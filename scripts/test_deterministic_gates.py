#!/usr/bin/env python3
"""A judge failure must lose the judge's OPINION, not the checks below it.

prejudge has two ship-gates that need no model: a static scan for the agent
admitting its own chain has no working path, and structural validation of
chain.json. Both were written INSIDE the branch that handles a parseable LLM
verdict — so a judge that was blocked, timed out, or answered in prose skipped
them and the run shipped on a permissive default.

That is the wrong way round, and it matters most exactly when the hybrid work
makes a judge failure MORE likely: a cross-provider judge can be refused by a
classifier that has nothing to say about whether the exploit works.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.TemporaryDirectory(prefix="deterministic-gates-")
DATA = Path(_TMP.name)
(DATA / "jobs").mkdir()
SETTINGS = DATA / "settings.json"
PRESETS = DATA / "model_presets.json"
SETTINGS.write_text(json.dumps({"agent_provider": "claude"}))
PRESETS.write_text(json.dumps({"version": 2, "providers": {}}))
os.environ.update(
    DATA_DIR=str(DATA),
    SETTINGS_PATH=str(SETTINGS),
    MODEL_PRESETS_PATH=str(PRESETS),
    JOBS_DIR=str(DATA / "jobs"),
)
for _k in ("AGENT_PROVIDER", "CLAUDE_MODEL", "GROK_MODEL", "GPT_MODEL"):
    os.environ.pop(_k, None)


def _missing(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is None
    except (ImportError, ValueError):
        return True


STUBBED = [n for n in ("claude_agent_sdk",) if _missing(n)]
if _missing("claude_agent_sdk"):
    _sdk = types.ModuleType("claude_agent_sdk")
    for _n in ("AssistantMessage", "ClaudeAgentOptions", "ResultMessage",
               "SystemMessage", "TextBlock", "ClaudeSDKClient", "UserMessage"):
        setattr(_sdk, _n, type(_n, (), {}))

    async def _query(*a, **k):  # pragma: no cover
        if False:
            yield None

    _sdk.query = _query
    _sdk.HookMatcher = type("HookMatcher", (), {"__init__": lambda s, **k: None})
    _sdk.AgentDefinition = type("AgentDefinition", (), {"__init__": lambda s, **k: None})
    _sdk.create_sdk_mcp_server = lambda *a, **k: None
    _sdk.tool = lambda *a, **k: (lambda fn: fn)
    _sdk.project_key_for_directory = lambda *a, **k: ""
    sys.modules["claude_agent_sdk"] = _sdk

import modules._judge as J  # noqa: E402
from modules import usage_ledger as UL  # noqa: E402

PASSED = 0
FAILED = 0
LOGS: list[str] = []


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


def log(msg):
    LOGS.append(str(msg))


# Wording taken from _SELF_DEFEAT_PATTERNS, which exists because real jobs
# shipped with these admissions in their own artifacts.
SELF_DEFEAT = "The chain is incomplete; unable to leak the libc base.\n"


def make_job(job_id: str, *, self_defeat: bool = False, chain: dict | None = None) -> Path:
    jd = DATA / "jobs" / job_id
    (jd / "work").mkdir(parents=True, exist_ok=True)
    (jd / "meta.json").write_text(json.dumps({"id": job_id, "agent_provider": "claude"}))
    (jd / "exploit.py").write_text(
        "# solver\n" + (f'"""{SELF_DEFEAT}"""\n' if self_defeat else "print(1)\n")
    )
    if chain is not None:
        (jd / "work" / "chain.json").write_text(json.dumps(chain))
    J._forget_sid(job_id)
    return jd


def prejudge(jd, **kw) -> dict:
    """Call prejudge and turn any escape into a REPORTABLE result.

    prejudge is documented as never fatal, so an exception escaping it is
    itself a failure — and a test that dies on it hides which contract broke
    instead of naming it. Third time in this work that an unguarded call
    turned a caught mutation into a stack trace.
    """
    try:
        return J.prejudge_script(jd, "exploit.py", None, log, job_id=jd.name, **kw)
    except Exception as exc:
        return {"ok": "RAISED", "severity": f"{type(exc).__name__}: {exc}",
                "issues": [], "raw": ""}


# ---------------------------------------------------------------------------
# 1. The gates stand alone.
# ---------------------------------------------------------------------------
clean = make_job("g-clean")
out = J.deterministic_prejudge(clean, clean / "exploit.py", log)
check("a clean job passes the static gates", out["ok"], True)
check("...at low severity", out["severity"], "low")

sd = make_job("g-selfdefeat", self_defeat=True)
out = J.deterministic_prejudge(sd, sd / "exploit.py", log)
check("a self-defeat admission blocks", out["ok"], False)
check("...at high severity", out["severity"], "high")
check("...and says why", any("self-defeat" in i for i in out["issues"]), True)

# ---------------------------------------------------------------------------
# 2. THE POINT: they run when the judge does not answer.
# ---------------------------------------------------------------------------
_orig_turn = J.judge_turn


def judge_returns(text: str, **kw):
    def _fake(user_prompt, *, cwd, job_id, stage, resume, model=None):
        return J.JudgeTurnResult(text=text, provider="claude", **kw)

    J.judge_turn = _fake


# An unparseable answer is exactly what a refused / timed-out judge produces.
for label, answer in (
    ("empty", ""),
    ("prose", "I was unable to complete this review."),
    ("truncated json", '{"ok": tr'),
):
    jd = make_job(f"g-noparse-{label.replace(' ', '-')}", self_defeat=True)
    judge_returns(answer)
    v = prejudge(jd)
    check(f"{label}: the static gate still blocks", v["ok"], False)
    check(f"{label}: at high severity", v["severity"], "high")
    check(f"{label}: with the reason", any("self-defeat" in i for i in v["issues"]), True)

# And a CLEAN job with an unparseable answer still ships — the fallback is
# permissive about opinion, not about evidence.
jd = make_job("g-noparse-clean")
judge_returns("")
v = prejudge(jd)
check("a clean job with no verdict still ships", v["ok"], True)
check("...at low severity", v["severity"], "low")

# A refused judge is the case the hybrid work makes more likely, and it must
# behave identically — the refusal says nothing about the exploit.
jd = make_job("g-refused", self_defeat=True)
judge_returns("", error_kind="policy_refusal", error_detail="violates our usage policy")
v = prejudge(jd)
check("a REFUSED judge still runs the static gates", v["ok"], False)
check("...and blocks", v["severity"], "high")

# ---------------------------------------------------------------------------
# 3. Escalation only. A static gate may overrule "ok"; never the reverse.
# ---------------------------------------------------------------------------
jd = make_job("g-llm-ok-static-bad", self_defeat=True)
judge_returns('{"ok": true, "severity": "low", "flag_likelihood": 0.9}')
v = prejudge(jd)
check("an 'ok' verdict is overruled by the static gate", v["ok"], False)
check("...and severity is raised", v["severity"], "high")

jd = make_job("g-llm-bad-static-ok")
judge_returns('{"ok": false, "severity": "high", "flag_likelihood": 0.9}')
v = prejudge(jd)
check("a clean static gate does NOT rescue a blocking verdict", v["ok"], False)
check("...severity stays high", v["severity"], "high")

# The LLM's own issues survive alongside the static ones.
jd = make_job("g-both-issues", self_defeat=True)
judge_returns('{"ok": true, "severity": "low", "flag_likelihood": 0.9, '
              '"issues": ["llm noticed something"]}')
v = prejudge(jd)
check("the model's own issue survives", any("llm noticed" in i for i in v["issues"]), True)
check("...beside the static one", any("self-defeat" in i for i in v["issues"]), True)

# ---------------------------------------------------------------------------
# 3b. turn 0040 D1 — the gates run BEFORE the judge call. "Whether or not the
#     judge answered" was only true for a judge that RETURNED: a wrapper that
#     raised escaped past them, and the runner turns that into ok/low, so a
#     run whose own artifact admits an incomplete chain went to the sandbox
#     because a network call failed.
# ---------------------------------------------------------------------------
def judge_raises(exc):
    def _fake(user_prompt, *, cwd, job_id, stage, resume, model=None):
        raise exc

    J.judge_turn = _fake


for exc in (RuntimeError("transport wrapper failure"), ValueError("bug")):
    jd = make_job(f"g-raise-{type(exc).__name__}", self_defeat=True)
    judge_raises(exc)
    v = prejudge(jd)
    check(f"{type(exc).__name__}: prejudge does not propagate", v["ok"] != "RAISED", True)
    check(f"{type(exc).__name__}: the static gate still blocks", v["ok"], False)
    check(f"{type(exc).__name__}: at high severity", v["severity"], "high")

# turn 0042 D3: the static verdict survives, and so must the CAUSE. Swallowing
# the exception re-opened the hole stage 3 closed — `error_kind` exists to tell
# "ran and said nothing" from "never ran", and a wrapper that raised is
# emphatically the second. It also has to reach the ledger, or a judge that
# burned tokens before dying bills nothing.
jd = make_job("g-raise-observable", self_defeat=True)
judge_raises(RuntimeError("connection reset by peer"))
v = prejudge(jd)
check("D3 the failure reason is returned, not just logged",
      "connection reset" in str(v.get("error") or ""), True)
check("D3 ...classified", v.get("error_kind"), "transport_error")
check("D3 the static verdict still stands", (v["ok"], v["severity"]), (False, "high"))
rrows = UL.read_usage(jd.name)
check("D3 the dead turn is billed", len(rrows), 1)
check("D3 ...with its kind on the row",
      rrows[0].get("error_kind") if rrows else None, "transport_error")
check("D3 ...under the prejudge stage",
      rrows[0].get("stage") if rrows else None, "prejudge")

# A timeout is classified as a timeout, not lumped into transport.
jd = make_job("g-raise-timeout", self_defeat=True)
judge_raises(RuntimeError("request timed out after 600s"))
v = prejudge(jd)
check("D3 a timeout keeps its own kind", v.get("error_kind"), "timeout")

# A clean job whose judge raised still ships.
jd = make_job("g-raise-clean")
judge_raises(RuntimeError("boom"))
v = prejudge(jd)
check("a clean job whose judge raised still ships", v["ok"], True)

# ---------------------------------------------------------------------------
# 3c. turn 0040 D2 — no gate's CAUSE is lost to another gate's volume. A
#     single trailing cap let twelve self-defeat matches erase chain.critical
#     from the verdict, so the operator would read "self-defeat" and never
#     learn the chain was also invalid.
# ---------------------------------------------------------------------------
many_sd = [f"self-defeat in report: \"admission {i}\"" for i in range(12)]
crit = [f"chain.critical: step {i} depends on a blocked primitive" for i in range(2)]
llm6 = [f"llm issue {i}" for i in range(6)]
merged = J._merge_prejudge_issues(llm6, many_sd + crit)
check("the cap still holds", len(merged), 12)
check("chain.critical survives a flood of self-defeat",
      sum(1 for i in merged if i.startswith("chain.critical")), 2)
check("self-defeat is represented", any(i.startswith("self-defeat") for i in merged), True)
check("the model's own issues are represented",
      any(i.startswith("llm issue") for i in merged), True)
check(
    "every cause present in the input is present in the output",
    {i.split(":")[0].split(" in ")[0] for i in merged}
    >= {"self-defeat", "chain.critical"},
    True,
)

# Advisory families never crowd out a blocking one.
notes = [f"chain.note: n{i}" for i in range(20)]
merged2 = J._merge_prejudge_issues([], crit + notes)
check("chain.critical survives a flood of notes",
      sum(1 for i in merged2 if i.startswith("chain.critical")), 2)

J.judge_turn = _orig_turn

# ---------------------------------------------------------------------------
# 4. The other stages' deterministic fallbacks, per the agreed table.
# ---------------------------------------------------------------------------
_orig_turn2 = J.judge_turn
judge_returns("")   # nothing parseable from any stage

sup = make_job("g-supervise")
sv = J.supervise_run_once(sup, "exploit.py", 60, "", "", log, job_id=sup.name)
check("supervise with no verdict CONTINUES", sv["action"], "continue")
check("...it never kills on a judge failure", sv["action"] == "kill", False)

post = make_job("g-postjudge")
pv = J.postjudge_run(post, "exploit.py", 1, "", "", log, job_id=post.name)
check("postjudge with no verdict is 'unknown'", pv["verdict"], "unknown")
check("...continues rather than stopping", pv["next_action"], "continue")
check("...and offers no retry hint it does not have", pv["retry_hint"], "")

J.judge_turn = _orig_turn2

print(
    f"== summary: {PASSED} passed, {FAILED} failed =="
    + (f"  [stubbed: {', '.join(STUBBED)}]" if STUBBED else "  [all real deps]")
)
_TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
