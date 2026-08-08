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


n = SH.evaluate(jid2, DATA / "jobs" / jid2, lambda *_: None, runner=fake_runner)
check("every recording is evaluated", n, 4)
check("...including each supervise firing",
      [s for s, _ in seen].count("supervise"), 3)
check("nothing is left pending", SH.pending_inputs(jid2), [])
check("a second pass re-evaluates nothing",
      SH.evaluate(jid2, DATA / "jobs" / jid2, lambda *_: None, runner=fake_runner), 0)

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
SH.evaluate(jid2b, DATA / "jobs" / jid2b, lambda *_: None,
            runner=lambda st, inp: seen2.append(inp.get("stall_seconds")) or {"action": "continue"})
check("evaluation resumes where it left off", seen2, [60, 90])

# A runner that raises records the failure rather than losing the entry.
jid3 = "sh3"
(DATA / "jobs" / jid3).mkdir(parents=True, exist_ok=True)
SH.record_input(jid3, "prejudge", {})


def boom(stage, inputs):
    raise RuntimeError("evaluator exploded")


check("an exploding evaluator still consumes the entry",
      SH.evaluate(jid3, DATA / "jobs" / jid3, lambda *_: None, runner=boom), 1)
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
# 7. The runner WIRING. Driving auto_run needs a live Docker daemon, so this
#    is a structural assertion — weaker than execution, and labelled as such.
#    Without it the whole shadow branch could be deleted and every test above
#    would still pass, because they exercise judge_shadow directly.
# ---------------------------------------------------------------------------
import ast  # noqa: E402

_runner_src = (ROOT / "modules" / "_runner.py").read_text()
_runner_ast = ast.parse(_runner_src)


def _calls_in(tree, dotted: str) -> list[int]:
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            if n.func.attr == dotted.split(".")[-1] and isinstance(n.func.value, ast.Name):
                if n.func.value.id == dotted.split(".")[0]:
                    out.append(n.lineno)
    return out


_records = _calls_in(_runner_ast, "judge_shadow.record_input")
_evals = _calls_in(_runner_ast, "judge_shadow.evaluate")
check("the runner records shadow inputs", len(_records) >= 2, True)
check("the runner evaluates out of band", len(_evals), 1)
check(
    "evaluation comes AFTER the last input is recorded",
    _evals[0] > max(_records) if _evals and _records else False,
    True,
)
# Substring checks cannot tell a live branch from a dead one: replacing the
# guard with `if False:` leaves the string in the file. Walk the tree and
# require each call to sit under a test that actually compares judge_mode.
def _guarded_by_shadow_mode(tree, attr: str) -> list[bool]:
    """One entry per `judge_shadow.<attr>(...)` call: does SOME enclosing `if`
    actually test `judge_mode == "shadow"`?

    Per call site, not per (If, call) pair — a call sits inside several nested
    conditionals, and an unrelated outer one (`if enable_judge:`) says nothing
    about whether the shadow guard is live.
    """

    def _is_shadow_test(node) -> bool:
        for sub in ast.walk(node):
            if not (isinstance(sub, ast.Compare) and isinstance(sub.left, ast.Name)):
                continue
            if sub.left.id != "judge_mode":
                continue
            for op, c in zip(sub.ops, sub.comparators):
                if (isinstance(op, ast.Eq)
                        and isinstance(c, ast.Constant) and c.value == "shadow"):
                    return True
        return False

    def _calls(nodes) -> list:
        out = []
        for node in nodes:
            for sub in ast.walk(node):
                if (isinstance(sub, ast.Call)
                        and isinstance(sub.func, ast.Attribute)
                        and sub.func.attr == attr
                        and isinstance(sub.func.value, ast.Name)
                        and sub.func.value.id == "judge_shadow"):
                    out.append(sub)
        return out

    guarded = set()
    for node in ast.walk(tree):
        # `node.body` only: the same call in an `else` runs when NOT shadow.
        if isinstance(node, ast.If) and _is_shadow_test(node.test):
            guarded.update(id(c) for c in _calls(node.body))
    return [id(c) in guarded for c in _calls([tree])]


_guards = _guarded_by_shadow_mode(_runner_ast, "record_input")
check("every shadow recording is guarded", len(_guards) >= 2, True)
check("...by a live judge_mode == 'shadow' test, not a dead branch",
      all(_guards), True)
check("the evaluation call is guarded the same way",
      all(_guarded_by_shadow_mode(_runner_ast, "evaluate")), True)

print(
    f"== summary: {PASSED} passed, {FAILED} failed =="
    + (f"  [stubbed: {', '.join(STUBBED)}]" if STUBBED else "  [all real deps]")
)
_TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
