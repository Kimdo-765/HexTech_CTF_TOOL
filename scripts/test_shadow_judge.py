#!/usr/bin/env python3
"""Shadow mode must not change the thing it is measuring.

Two ways it would, and both are contracts rather than intentions:

  * Latency. The three judge stages sit inside the auto_run cycle, so a model
    call added there lengthens every run and leaves a shadow job incomparable
    with the control. Shadow records INPUTS during the run and produces
    verdicts afterwards.

  * The flag scanner. Judge prose has been scraped as a job's flag before
    (a15ff70a6ed5). `_NARRATIVE_FLAG_SOURCES` is an explicit allowlist and
    run.log was removed from it in 2026-07, so a new file is safe BY
    CONSTRUCTION — but only while nobody adds it, which is what this pins.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.TemporaryDirectory(prefix="shadow-judge-")
DATA = Path(_TMP.name)
(DATA / "jobs").mkdir()
SETTINGS = DATA / "settings.json"
SETTINGS.write_text("{}")
os.environ.update(
    DATA_DIR=str(DATA),
    SETTINGS_PATH=str(SETTINGS),
    JOBS_DIR=str(DATA / "jobs"),
)
for _k in ("JUDGE_MODE", "ENABLE_JUDGE"):
    os.environ.pop(_k, None)

import importlib.util  # noqa: E402
import types  # noqa: E402


def _missing(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is None
    except (ImportError, ValueError):
        return True


STUBBED = [n for n in ("docker", "claude_agent_sdk") if _missing(n)]
if _missing("docker"):
    # _runner talks to Docker at module scope. The mode helpers under test do
    # not, and stubbing only what is absent keeps this runnable in the worker
    # image where the real client exists.
    _d = types.ModuleType("docker")
    _d.from_env = lambda *a, **k: None
    _d.DockerClient = type("DockerClient", (), {})
    _errors = types.ModuleType("docker.errors")
    for _n in ("APIError", "NotFound", "ImageNotFound", "DockerException", "NullResource"):
        setattr(_errors, _n, type(_n, (Exception,), {}))
    _d.errors = _errors
    _types_mod = types.ModuleType("docker.types")
    _types_mod.Mount = type("Mount", (), {"__init__": lambda s, **k: None})
    _d.types = _types_mod
    sys.modules["docker"] = _d
    sys.modules["docker.errors"] = _errors
    sys.modules["docker.types"] = _types_mod

if _missing("claude_agent_sdk"):
    _sdk = types.ModuleType("claude_agent_sdk")
    for _n in ("AssistantMessage", "ClaudeAgentOptions", "ResultMessage",
               "SystemMessage", "TextBlock", "ClaudeSDKClient", "UserMessage"):
        # kwargs-accepting: the real ClaudeAgentOptions is built with keywords,
        # and a stub that rejects them fails BEFORE the seam under test.
        setattr(_sdk, _n, type(_n, (), {"__init__": lambda s, **k: None}))

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

import modules.settings_io as SI  # noqa: E402
from modules import judge_shadow as SH  # noqa: E402

PASSED = 0
FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


def set_settings(**kw) -> None:
    SETTINGS.write_text(json.dumps(kw))


# ---------------------------------------------------------------------------
# 1. The mode is tri-state, and `shadow` is never reached by inference.
# ---------------------------------------------------------------------------
for cfg, want in (
    ({}, "enforce"),
    ({"enable_judge": True}, "enforce"),
    ({"enable_judge": False}, "off"),
    ({"enable_judge": False, "judge_mode": "shadow"}, "shadow"),
    ({"enable_judge": True, "judge_mode": "off"}, "off"),
    ({"enable_judge": True, "judge_mode": "shadow"}, "shadow"),
    ({"judge_mode": "bogus"}, "enforce"),
    ({"enable_judge": False, "judge_mode": "bogus"}, "off"),
    ({"enable_judge": False, "judge_mode": ""}, "off"),
):
    set_settings(**cfg)
    check(f"judge_mode({cfg})", SI.get_judge_mode(), want)

check(
    "shadow is not derivable from the legacy boolean alone",
    "shadow" in {SI.get_judge_mode() for cfg in ({}, {"enable_judge": True},
                                                 {"enable_judge": False})
                 for _ in [set_settings(**cfg)]},
    False,
)

# ---------------------------------------------------------------------------
# 2. Shadow gates NOTHING. The runner's enable flag stays False.
# ---------------------------------------------------------------------------
import modules._runner as R  # noqa: E402
from modules import _judge as _judge_mod  # noqa: E402

for cfg, mode, gates in (
    ({"enable_judge": False}, "off", False),
    ({"enable_judge": False, "judge_mode": "shadow"}, "shadow", False),
    ({"enable_judge": True}, "enforce", True),
):
    set_settings(**cfg)
    check(f"{mode}: mode", R._judge_mode(), mode)
    check(f"{mode}: gates the run", R._judge_enabled(), gates)

check(
    "shadow gates exactly as much as off",
    (set_settings(enable_judge=False, judge_mode="shadow"), R._judge_enabled())[1],
    (set_settings(enable_judge=False), R._judge_enabled())[1],
)

# ---------------------------------------------------------------------------
# 3. Recording is inputs-only during the run. No model is involved.
# ---------------------------------------------------------------------------
jid = "sh1"
(DATA / "jobs" / jid).mkdir(parents=True, exist_ok=True)
rec = SH.record_input(jid, "prejudge", {"script_rel": "exploit.py", "target": None})
check("an input record is written", rec["kind"] if rec else None, "input")
check("...tagged with its stage", rec["stage"] if rec else None, "prejudge")
check("...and carries no verdict", "verdict" in (rec or {}), False)

# Oversized fields are clipped: this file is written during a live run.
big = SH.record_input(jid, "postjudge", {"stdout": "x" * 50_000})
check("a huge field is clipped", len(big["inputs"]["stdout"]) < 20_000, True)
check("...and says it was", "clipped" in big["inputs"]["stdout"], True)

# ---------------------------------------------------------------------------
# 4. Evaluation happens afterwards, once per RECORDING — supervise fires more
#    than once, so matching by stage alone would evaluate it once.
# ---------------------------------------------------------------------------
jid2 = "sh2"
(DATA / "jobs" / jid2).mkdir(parents=True, exist_ok=True)
for stall in (30, 60, 90):
    SH.record_input(jid2, "supervise", {"stall_seconds": stall})
SH.record_input(jid2, "postjudge", {"exit_code": 1})
check("four inputs recorded", len(SH.pending_inputs(jid2)), 4)

seen: list[tuple[str, dict]] = []


def fake_runner(stage, inputs):
    seen.append((stage, inputs))
    return {"action": "continue"} if stage == "supervise" else {"verdict": "unknown"}


n = SH.evaluate(jid2, DATA / "jobs" / jid2, runner=fake_runner)
check("every recording is evaluated", n, 4)
check("...including each supervise firing",
      [s for s, _ in seen].count("supervise"), 3)
check("nothing is left pending", SH.pending_inputs(jid2), [])
check("a second pass re-evaluates nothing",
      SH.evaluate(jid2, DATA / "jobs" / jid2, runner=fake_runner), 0)

# PARTIAL evaluation is the case stage-only matching gets wrong: with one
# supervise verdict already on file, the other two firings are still pending.
jid2b = "sh2b"
(DATA / "jobs" / jid2b).mkdir(parents=True, exist_ok=True)
for stall in (30, 60, 90):
    SH.record_input(jid2b, "supervise", {"stall_seconds": stall})
SH.record_verdict(jid2b, "supervise", {"action": "continue"})
check("one verdict does not clear three firings",
      len(SH.pending_inputs(jid2b)), 2)
check("...and the ones left are the LATER firings",
      [r["inputs"]["stall_seconds"] for r in SH.pending_inputs(jid2b)], [60, 90])
seen2: list[int] = []
SH.evaluate(jid2b, DATA / "jobs" / jid2b,
            runner=lambda st, inp: seen2.append(inp.get("stall_seconds")) or {"action": "continue"})
check("evaluation resumes where it left off", seen2, [60, 90])

# A runner that raises records the failure rather than losing the entry.
jid3 = "sh3"
(DATA / "jobs" / jid3).mkdir(parents=True, exist_ok=True)
SH.record_input(jid3, "prejudge", {})


def boom(stage, inputs):
    raise RuntimeError("evaluator exploded")


check("an exploding evaluator still consumes the entry",
      SH.evaluate(jid3, DATA / "jobs" / jid3, runner=boom), 1)
check("...and records why",
      "exploded" in json.dumps(SH.read_shadow(jid3)[-1].get("verdict") or {}), True)
check("...leaving nothing pending", SH.pending_inputs(jid3), [])

# ---------------------------------------------------------------------------
# 5. The rollup answers the question shadow exists to ask.
# ---------------------------------------------------------------------------
jid4 = "sh4"
(DATA / "jobs" / jid4).mkdir(parents=True, exist_ok=True)
SH.record_input(jid4, "prejudge", {})
SH.record_verdict(jid4, "prejudge", {"ok": False, "severity": "high"})
SH.record_input(jid4, "supervise", {})
SH.record_verdict(jid4, "supervise", {"action": "kill"})
s = SH.summary(jid4)
check("the rollup counts what was seen", (s["inputs"], s["evaluated"]), (2, 2))
check("...and says it WOULD have blocked", s["would_have_blocked"], True)
check("...and WOULD have killed", s["would_have_killed"], True)
check("...but did neither", s["would_have_retried"], False)

# ---------------------------------------------------------------------------
# 6. THE ONE THAT MATTERS: shadow prose must never reach the flag scanner.
# ---------------------------------------------------------------------------
from modules._common import _NARRATIVE_FLAG_SOURCES, _TRUSTED_FLAG_SOURCES  # noqa: E402

check(
    "the shadow file is not a NARRATIVE flag source",
    SH.SHADOW_FILENAME in _NARRATIVE_FLAG_SOURCES,
    False,
)
check(
    "...nor a TRUSTED one",
    SH.SHADOW_FILENAME in _TRUSTED_FLAG_SOURCES,
    False,
)
check(
    "run.log is still out of the narrative tier",
    "run.log" in _NARRATIVE_FLAG_SOURCES,
    False,
)
# The allowlist is what makes a new file safe by construction. If it ever
# becomes a glob, this assertion is the thing that notices.
check(
    "the narrative tier is an explicit allowlist, not a pattern",
    all(isinstance(x, str) and "*" not in x for x in _NARRATIVE_FLAG_SOURCES),
    True,
)

# End to end: a shadow file full of flag-shaped prose changes no scan result.
from modules._common import scan_job_for_flags  # noqa: E402

jid5 = "sh5"
jd5 = DATA / "jobs" / jid5
(jd5 / "work").mkdir(parents=True, exist_ok=True)
(jd5 / "meta.json").write_text(json.dumps({"id": jid5}))
before = scan_job_for_flags(jid5)
SH.record_verdict(
    jid5, "prejudge",
    {"ok": False, "issues": ["the agent claims it captured DH{shadow_prose_flag}"]},
)
after = scan_job_for_flags(jid5)
check("a shadow verdict full of flag-shaped prose adds no flags", after, before)
check("...and specifically not that one",
      any("shadow_prose_flag" in f for f in after), False)

# ---------------------------------------------------------------------------
# 7. The runner WIRING — structurally.
#
#    This section used to be the ONLY thing standing between the shadow branch
#    and deletion, and it was labelled "weaker than execution" while being
#    trusted like execution. It missed a fatal defect: the postjudge shadow
#    block sat inside `if enable_judge:`, which is False in shadow, so the live
#    path recorded one prejudge input and then nothing, forever. Every check
#    above passed because they call judge_shadow directly.
#
#    So the structural checks are now BOUNDS on the branch (what may enclose
#    it, what it may call) and section 8 drives the real function.
# ---------------------------------------------------------------------------
import ast  # noqa: E402

_runner_src = (ROOT / "modules" / "_runner.py").read_text()
_runner_ast = ast.parse(_runner_src)


def _is_shadow_test(node) -> bool:
    """`judge_mode == "shadow"` — the real test, not the substring.

    Requiring ast.Eq also rejects an inverted guard; `if False:` leaves the
    text in the file but produces no Compare at all.
    """
    for sub in ast.walk(node):
        if not (isinstance(sub, ast.Compare) and isinstance(sub.left, ast.Name)):
            continue
        if sub.left.id != "judge_mode":
            continue
        for op, c in zip(sub.ops, sub.comparators):
            if isinstance(op, ast.Eq) and isinstance(c, ast.Constant) and c.value == "shadow":
                return True
    return False


def _names_in(node) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _callee(func) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        base = _callee(func.value)
        return f"{base}.{func.attr}" if base else func.attr
    return "<expr>"


# Parent links, so a block can be asked what encloses it.
_parent = {}
for _n in ast.walk(_runner_ast):
    for _c in ast.iter_child_nodes(_n):
        _parent[id(_c)] = _n


def _enclosing_if_tests(node) -> list[ast.expr]:
    out, cur = [], _parent.get(id(node))
    while cur is not None:
        if isinstance(cur, ast.If):
            out.append(cur.test)
        cur = _parent.get(id(cur))
    return out


_shadow_blocks = [n for n in ast.walk(_runner_ast)
                  if isinstance(n, ast.If) and _is_shadow_test(n.test)]
_shadow_blocks.sort(key=lambda n: n.lineno)

check("the runner has exactly two shadow blocks", len(_shadow_blocks), 2)

# THE D1 CLASS. `enable_judge` is False in shadow, so a shadow block nested
# under it — or guarded by it — is dead code that a "is the guard live?" check
# reads as healthy.
_enclosed_by_gate = [
    any("enable_judge" in _names_in(t) for t in _enclosing_if_tests(b))
    or "enable_judge" in _names_in(b.test)
    for b in _shadow_blocks
]
check("no shadow block sits under the enforce gate", _enclosed_by_gate,
      [False] * len(_shadow_blocks))

# What a shadow block may call. Recording is a file append; anything else here
# runs in the auto_run cycle, which is the wall-clock change §8.2 forbids.
# `evaluate` is deliberately absent: the run path never evaluates.
_ALLOWED_IN_BLOCK = {"judge_shadow.record_input"}
_block_callees = [{_callee(c.func) for s in b.body for c in ast.walk(s)
                   if isinstance(c, ast.Call)} for b in _shadow_blocks]
check("every shadow block only records", _block_callees,
      [_ALLOWED_IN_BLOCK] * len(_shadow_blocks))
check("nothing in the run path evaluates",
      any("judge_shadow.evaluate" in c for c in _block_callees), False)
check("...anywhere in _runner.py, guarded or not",
      "judge_shadow.evaluate" in {_callee(c.func) for c in ast.walk(_runner_ast)
                                  if isinstance(c, ast.Call)},
      False)

# The mode snapshot must be taken ONCE. Two reads let a settings change land
# between them and yield a pair that never existed as a configuration.
check("the mode is read once per attempt",
      _runner_src.count("judge_mode = _judge_mode()"), 1)
check("...and the gate is derived from that snapshot, not re-read",
      _runner_src.count("enable_judge = _judge_gates(judge_mode)"), 1)
check("...with no second _judge_enabled() read in the run path",
      "enable_judge = _judge_enabled()" in _runner_src, False)

# ---------------------------------------------------------------------------
# 8. THE PATH. Everything above tests judge_shadow, or the shape of _runner.py.
#    Neither noticed that the live path recorded nothing. So drive the public
#    `attempt_sandbox_run()` with doubles and read what actually landed.
#
#    Three doubles, each load-bearing:
#      * the sandbox, so no container is needed;
#      * `Path`, because the job dir is hardcoded to /data;
#      * every model-client seam, which RAISES — that is the review gate
#        "shadow 라이브 구간에서 클라이언트 생성 시 raise 하는 test double",
#        and it is proved non-vacuous below rather than assumed.
# ---------------------------------------------------------------------------
_real_Path = R.Path


def _tmp_path(p="", *a):
    s = str(p)
    if s.startswith("/data/jobs/"):
        s = str(DATA / "jobs" / s[len("/data/jobs/"):])
    return _real_Path(s, *a)


class ModelCallInLiveWindow(RuntimeError):
    """Raised the instant anything builds a model client."""


def _poison(*a, **k):
    raise ModelCallInLiveWindow("the live window built a model client")


_SEAMS = [("modules._judge", "query"), ("modules.gpt_agent", "GptAgentClient"),
          ("modules.grok_acp", "GrokACPClient")]
_seam_saved = []
for _mn, _at in _SEAMS:
    try:
        _m = __import__(_mn, fromlist=["_"])
    except Exception:
        continue
    if hasattr(_m, _at):
        _seam_saved.append((_m, _at, getattr(_m, _at)))
        setattr(_m, _at, _poison)
check("every model-client seam is poisoned", len(_seam_saved), 3)

# NON-VACUITY: if a judge turn can complete without tripping the poison, the
# clean live window below proves nothing at all.
_probe_dir = DATA / "jobs" / "seamprobe"
_probe_dir.mkdir(parents=True, exist_ok=True)
_tripped = []
for _prov in ("claude", "gpt", "grok"):
    try:
        _r = _judge_mod._run_async(_judge_mod._run_judge_turn(
            "probe", cwd=_probe_dir, resume_sid=None, provider_override=_prov))
        _tripped.append("ModelCallInLiveWindow" in str(getattr(_r, "error_detail", "") or ""))
    except ModelCallInLiveWindow:
        _tripped.append(True)
    except Exception:
        _tripped.append(False)
check("...and the poison is on all three provider paths", _tripped, [True] * 3)


def _drive(job_id: str, *, mode: str, exit_code: int = 0):
    """Run the real attempt_sandbox_run() and report what it produced."""
    jd = DATA / "jobs" / job_id
    (jd / "work").mkdir(parents=True, exist_ok=True)
    (jd / "work" / "exploit.py").write_text("print('x')\n")
    (jd / "meta.json").write_text(json.dumps({"id": job_id}))
    set_settings(enable_judge=(mode == "enforce"), judge_mode=mode)
    logged: list[str] = []
    sandbox_calls: list[tuple] = []

    def _fake_sandbox(*a, **k):
        sandbox_calls.append((a, k))
        return {"exit_code": exit_code, "stdout": "sandbox stdout",
                "stderr": "", "timeout": False, "killed_by_supervise": False}

    _saved = (R.run_in_sandbox, R.Path)
    R.run_in_sandbox, R.Path = _fake_sandbox, _tmp_path
    try:
        res = R.attempt_sandbox_run(job_id, "exploit.py", None, logged.append)
        err = None
    except BaseException as exc:            # noqa: BLE001 — reported, not raised
        res, err = None, f"{type(exc).__name__}: {exc}"
    finally:
        R.run_in_sandbox, R.Path = _saved
    kinds = [(r.get("kind"), r.get("stage")) for r in SH.read_shadow(job_id)]
    return {"res": res, "err": err, "log": logged, "records": kinds,
            "pending": len(SH.pending_inputs(job_id)),
            "sandbox_ran": len(sandbox_calls)}


_sh = _drive("pathshadow", mode="shadow")
check("shadow: the run completes", (_sh["err"], _sh["sandbox_ran"]), (None, 1))
check("shadow: BOTH stages are recorded on the live path",
      _sh["records"], [("input", "prejudge"), ("input", "postjudge")])
check("...and both are still pending — the run path never evaluates",
      _sh["pending"], 2)
check("...and no model client was built", "ModelCallInLiveWindow" in
      " ".join(_sh["log"]), False)
check("...and the judge did not gate the run",
      (_sh["res"] or {}).get("judge_aborted"), None)

# Identity: with the judge OFF the same drive must produce no shadow file at
# all. That equality is the basis for comparing a shadow job to a control.
_off = _drive("pathoff", mode="off")
check("off: nothing is recorded", _off["records"], [])
check("off: the run is otherwise identical",
      (_off["err"], _off["sandbox_ran"], (_off["res"] or {}).get("judge")),
      (_sh["err"], _sh["sandbox_ran"], (_sh["res"] or {}).get("judge")))

for _m, _at, _orig in _seam_saved:
    setattr(_m, _at, _orig)

# ---------------------------------------------------------------------------
# 9. The default evaluator must not write judge prose into the run's log.
#    §8.1: the judge writes issues/summary/retry_hint to whatever callback it
#    is handed, and in production that callback appends to run.log.
# ---------------------------------------------------------------------------
_leak_job = "shleak"
(DATA / "jobs" / _leak_job).mkdir(parents=True, exist_ok=True)
SH.record_input(_leak_job, "prejudge", {"script_rel": "exploit.py"})
_run_log: list[str] = []
_saved_pre = _judge_mod.prejudge_script


def _prose_judge(job_dir, script_rel, target, log_fn, **kw):
    log_fn("[judge] prejudge issue: the agent claims DH{shadow_prose_leak}")
    return {"ok": False, "severity": "high",
            "issues": ["DH{shadow_prose_leak}"]}


_judge_mod.prejudge_script = _prose_judge
try:
    SH.evaluate(_leak_job, DATA / "jobs" / _leak_job, log_fn=_run_log.append)
finally:
    _judge_mod.prejudge_script = _saved_pre

check("the judge's prose never reaches the caller's logger",
      any("shadow_prose_leak" in line for line in _run_log), False)
check("...it lands in the shadow file instead",
      any(r.get("kind") == "log" and "shadow_prose_leak" in str(r.get("line"))
          for r in SH.read_shadow(_leak_job)), True)
check("...and the caller still learns the evaluation happened",
      any("evaluated 1 recorded stage" in line for line in _run_log), True)
check("...while the verdict itself is recorded",
      any(r.get("kind") == "verdict" for r in SH.read_shadow(_leak_job)), True)
# And the API gives a caller no way to hand the judge a production logger.
import inspect  # noqa: E402

_sig = inspect.signature(SH.evaluate)
check("evaluate() takes log_fn keyword-only, so it cannot be passed by habit",
      _sig.parameters["log_fn"].kind, inspect.Parameter.KEYWORD_ONLY)
check("...and defaults to writing nowhere",
      _sig.parameters["log_fn"].default, None)

print(
    f"== summary: {PASSED} passed, {FAILED} failed =="
    + (f"  [stubbed: {', '.join(STUBBED)}]" if STUBBED else "  [all real deps]")
)
_TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
