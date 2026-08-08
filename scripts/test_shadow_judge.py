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

def _seed_cycle(job_id: str, job_dir: Path, cycle: str = "c1") -> str:
    """Record a prejudge for `cycle` and measure it, so dependents can run.

    A postjudge with no prejudge in its cycle is refused now — it would have
    no session to resume. Fixtures that only care about a LATER stage still
    have to establish the prerequisite, exactly as a real run does.
    """
    job_dir.mkdir(parents=True, exist_ok=True)
    rec = SH.record_input(job_id, "prejudge",
                          {"cycle_id": cycle, "script_rel": "exploit.py"})
    SH.record_verdict(job_id, "prejudge", {"ok": True, "severity": "low"},
                      answers=rec["id"])
    return cycle


# ---------------------------------------------------------------------------
# 4. Evaluation happens afterwards, once per RECORDING — supervise fires more
#    than once, so matching by stage alone would evaluate it once.
# ---------------------------------------------------------------------------
jid2 = "sh2"
(DATA / "jobs" / jid2).mkdir(parents=True, exist_ok=True)
_c2 = _seed_cycle(jid2, DATA / "jobs" / jid2)
for stall in (30, 60, 90):
    SH.record_input(jid2, "supervise", {"cycle_id": _c2, "stall_seconds": stall})
SH.record_input(jid2, "postjudge", {"cycle_id": _c2, "exit_code": 1})
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
_c2b = _seed_cycle(jid2b, DATA / "jobs" / jid2b)
for stall in (30, 60, 90):
    SH.record_input(jid2b, "supervise", {"cycle_id": _c2b, "stall_seconds": stall})
_first = SH.pending_inputs(jid2b)[0]
SH.record_verdict(jid2b, "supervise", {"action": "continue"},
                  answers=_first.get("id"))
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


check("an exploding evaluator counts as no measurement",
      SH.evaluate(jid3, DATA / "jobs" / jid3, runner=boom), 0)
check("...but the entry is consumed, not lost",
      any(r.get("kind") == "verdict" for r in SH.read_shadow(jid3)), True)
check("...and records why",
      any("exploded" in json.dumps(r.get("verdict") or {})
          for r in SH.read_shadow(jid3) if r.get("kind") == "verdict"), True)
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

# Every "would have" must answer with the rule the REAL path uses. The runner
# blocks only on severity=high; low/med are advisory and the run proceeds. A
# rollup that counts any ok=False turns advisory findings into false blocks,
# and a confusion matrix built on it is wrong in the direction that matters.
for _sev, _blocks in (("high", True), ("med", False), ("low", False),
                      ("HIGH", True), (None, False), ("", False)):
    _j = f"shsev{_sev!r}"
    (DATA / "jobs" / _j).mkdir(parents=True, exist_ok=True)
    SH.record_verdict(_j, "prejudge", {"ok": False, "severity": _sev})
    check(f"severity={_sev!r} blocks? (runner's own rule)",
          SH.summary(_j)["would_have_blocked"], _blocks)

check("an ok=True verdict never blocks, whatever its severity",
      _judge_mod.prejudge_blocks_ship({"ok": True, "severity": "high"}), False)
check("...and the runner asks the SAME predicate",
      "_judge.prejudge_blocks_ship(prejudge)" in
      (ROOT / "modules" / "_runner.py").read_text(), True)
check("...so no inline severity test is left behind in the runner",
      'prejudge.get("severity") == "high"' in
      (ROOT / "modules" / "_runner.py").read_text(), False)

# next_action is read by the retry loop as `(x or "continue").lower()`.
for _na, _retries in (("retry", True), ("RETRY", True), ("stop", False),
                      (None, False), ("continue", False)):
    _j = f"shna{_na!r}"
    (DATA / "jobs" / _j).mkdir(parents=True, exist_ok=True)
    SH.record_verdict(_j, "postjudge", {"next_action": _na})
    check(f"next_action={_na!r} counts as a retry?",
          SH.summary(_j)["would_have_retried"], _retries)

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
# `_postjudge_extra` is allowed in the postjudge block only, and only because
# it is pure — pinned immediately below, so widening the allowlist did not
# quietly widen what a shadow block may DO.
_block_callees = [{_callee(c.func) for s in b.body for c in ast.walk(s)
                   if isinstance(c, ast.Call)} for b in _shadow_blocks]
check("every shadow block only records (+ the pinned derivations)",
      _block_callees,
      [{"judge_shadow.record_input", "judge_shadow.prejudge_fingerprint"},
       {"judge_shadow.record_input", "_postjudge_extra",
        "_judge.postjudge_inputs", "judge_shadow.postjudge_fingerprint"}])

_extra_fn = next((n for n in ast.walk(_runner_ast)
                  if isinstance(n, ast.FunctionDef) and n.name == "_postjudge_extra"),
                 None)
check("the shared context builder exists", _extra_fn is not None, True)
check("...and is pure — dict reads and builtins, no I/O, no model, no state",
      sorted({_callee(c.func) for c in ast.walk(_extra_fn)
              if isinstance(c, ast.Call)}) if _extra_fn else None,
      ["enumerate", "len", "res.get"])

# The other two derivations are allowed in a shadow block only because of what
# they do, so pin that rather than trusting the name. `postjudge_inputs` is
# pure; `script_snapshot` reads ONE local file the runner has just written —
# bounded, no model, no network — which is the price of recording the artifact
# rather than a path to it.
_judge_src_ast = ast.parse((ROOT / "modules" / "_judge.py").read_text())
_pin = next((n for n in ast.walk(_judge_src_ast)
             if isinstance(n, ast.FunctionDef) and n.name == "postjudge_inputs"), None)
check("postjudge_inputs exists", _pin is not None, True)
check("...and only reduces strings — no model, no I/O",
      sorted({_callee(c.func) for c in ast.walk(_pin) if isinstance(c, ast.Call)})
      if _pin else None,
      ["<expr>.encode", "FLAG_RE.findall", "_truncate_tail", "len",
       "set", "sorted"])

_shadow_src_ast = ast.parse((ROOT / "modules" / "judge_shadow.py").read_text())
_snap = next((n for n in ast.walk(_shadow_src_ast)
              if isinstance(n, ast.FunctionDef) and n.name == "prejudge_fingerprint"),
             None)
check("prejudge_fingerprint exists", _snap is not None, True)
check("...and only hashes local files",
      sorted({_callee(c.func) for c in ast.walk(_snap) if isinstance(c, ast.Call)})
      if _snap else None,
      ["<expr>.is_dir", "_digest", "len", "raw.decode", "script.read_bytes"])
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
# 8b. Shadow must judge the SAME PROMPT the gate would. The runner assembles
#     `extra_context` — target reachability, timeout/kill, prior retry hints —
#     and postjudge is judged with it. If shadow records only the four raw
#     fields, the replay scores a prompt the gate never saw.
# ---------------------------------------------------------------------------
_HINTS = ["reuse the same failed idea", "and again"]


def _drive_ctx(job_id: str, *, mode: str, timeout: bool):
    """Drive the runner and capture the extra_context each mode produces."""
    jd = DATA / "jobs" / job_id
    (jd / "work").mkdir(parents=True, exist_ok=True)
    (jd / "work" / "exploit.py").write_text("print('x')\n")
    (jd / "meta.json").write_text(json.dumps({"id": job_id}))
    set_settings(enable_judge=(mode == "enforce"), judge_mode=mode)
    seen_ctx: list[str] = []

    def _fake_sandbox(*a, **k):
        return {"exit_code": 1, "stdout": "", "stderr": "boom",
                "timeout": timeout, "killed_by_supervise": False}

    def _fake_post(jd_, rel, code, out, err, log, *, extra_context="", **kw):
        seen_ctx.append(extra_context)
        return {"verdict": "fail", "next_action": "retry", "retry_hint": "",
                "summary": "", "raw": ""}

    _saved = (R.run_in_sandbox, R.Path, _judge_mod.postjudge_run)
    R.run_in_sandbox, R.Path = _fake_sandbox, _tmp_path
    _judge_mod.postjudge_run = _fake_post
    try:
        R.attempt_sandbox_run(job_id, "exploit.py", None, lambda *_: None,
                              prior_hints=_HINTS)
    finally:
        R.run_in_sandbox, R.Path, _judge_mod.postjudge_run = _saved
    return seen_ctx


_enf_ctx = _drive_ctx("ctxenf", mode="enforce", timeout=True)
check("enforce judges with an assembled context", len(_enf_ctx), 1)
check("...that carries the timeout note",
      "runner timeout fired" in (_enf_ctx[0] if _enf_ctx else ""), True)
check("...and the prior-hint history",
      "same failed idea" in (_enf_ctx[0] if _enf_ctx else ""), True)

_drive_ctx("ctxsh", mode="shadow", timeout=True)
_sh_rec = [r for r in SH.read_shadow("ctxsh")
           if r.get("kind") == "input" and r.get("stage") == "postjudge"]
check("shadow records the postjudge context too", len(_sh_rec), 1)
check("...and it is BYTE-IDENTICAL to what enforce judged",
      _sh_rec[0]["inputs"].get("extra_context") if _sh_rec else None,
      _enf_ctx[0] if _enf_ctx else "<no enforce run>")

# ...and the evaluator actually forwards it, rather than recording it unused.
_fwd: list[str] = []


def _capture_post(jd_, rel, code, out, err, log, *, extra_context="", **kw):
    _fwd.append(extra_context)
    return {"verdict": "fail"}


_saved_post = _judge_mod.postjudge_run
_judge_mod.postjudge_run = _capture_post
try:
    SH.evaluate("ctxsh", DATA / "jobs" / "ctxsh")
finally:
    _judge_mod.postjudge_run = _saved_post
check("the evaluator forwards the recorded context to postjudge",
      _fwd, [_enf_ctx[0] if _enf_ctx else "<no enforce run>"])

# ---------------------------------------------------------------------------
# 9. The default evaluator must not write judge prose into the run's log.
#    §8.1: the judge writes issues/summary/retry_hint to whatever callback it
#    is handed, and in production that callback appends to run.log.
# ---------------------------------------------------------------------------
_leak_job = "shleak"
(DATA / "jobs" / _leak_job).mkdir(parents=True, exist_ok=True)
(DATA / "jobs" / _leak_job / "exploit.py").write_text("print('leak probe')\n")
SH.record_input(_leak_job, "prejudge", {
    "script_rel": "exploit.py",
    **SH.prejudge_fingerprint(DATA / "jobs" / _leak_job, "exploit.py"),
})
_run_log: list[str] = []
_saved_pre = _judge_mod.prejudge_script


def _prose_judge(job_dir, script_rel, target, log_fn, **kw):
    log_fn("[judge] prejudge issue: the agent claims DH{shadow_prose_leak}")
    return {"ok": False, "severity": "high",
            "issues": ["DH{shadow_prose_leak}"]}


_judge_mod.prejudge_script = _prose_judge
try:
    SH.evaluate(_leak_job, DATA / "jobs" / _leak_job)
finally:
    _judge_mod.prejudge_script = _saved_pre

check("the judge's prose never reaches the caller's logger",
      any("shadow_prose_leak" in line for line in _run_log), False)
check("...it lands in the shadow file instead",
      any(r.get("kind") == "log" and "shadow_prose_leak" in str(r.get("line"))
          for r in SH.read_shadow(_leak_job)), True)
check("...and the caller is told nothing at all — there is no route to run.log",
      _run_log, [])
check("...the summary goes to the shadow file",
      any(r.get("kind") == "log" and "evaluated 1 recorded stage" in str(r.get("line"))
          for r in SH.read_shadow(_leak_job)), True)
check("...while the verdict itself is recorded",
      any(r.get("kind") == "verdict" for r in SH.read_shadow(_leak_job)), True)
# And the API gives a caller no way to hand the judge a production logger.
import inspect  # noqa: E402

_sig = inspect.signature(SH.evaluate)
check("evaluate() has no log_fn at all — production hands around log_line(), "
      "which appends to run.log",
      "log_fn" in _sig.parameters, False)
check("...and every remaining parameter is keyword-only except the job",
      [k for k, v in _sig.parameters.items()
       if v.kind is inspect.Parameter.KEYWORD_ONLY], ["runner"])

# ---------------------------------------------------------------------------
# 10. Long output: shadow must keep the END, because that is what postjudge
#     reads — and the placeholder override reads the WHOLE thing. Keeping a
#     head-clipped prefix hands the judge the start of a long run and drops the
#     capture, then re-derives the override's input from the wrong string.
# ---------------------------------------------------------------------------
_FAKE = "DH{fake_flag}"                       # near the START, survives a head clip
_REAL = "DH{" + "r" * 24 + "}"                # near the END, only a tail keeps it
_LONG = _FAKE + ("x" * 40_000) + _REAL + "\n"

_pi = _judge_mod.postjudge_inputs(_LONG, "")
check("the recorded stdout is the TAIL the prompt uses",
      _pi["stdout_tail"],
      _judge_mod._truncate_tail(_LONG, max_bytes=_judge_mod.POSTJUDGE_STDOUT_BYTES))
check("...so the real flag survives", _REAL in _pi["stdout_tail"], True)
check("...and the head-clipped prefix would have lost it",
      _REAL in _LONG[:8000], False)
check("the override's input is scanned from the FULL output",
      (_FAKE in _pi["flag_shapes"], _REAL in _pi["flag_shapes"]), (True, True))
check("...which the tail alone would not give",
      _FAKE in set(_judge_mod.postjudge_inputs(_pi["stdout_tail"], "")["flag_shapes"]),
      False)
check("the record says how much was elided",
      _pi["stdout_bytes"], len(_LONG.encode()))

# Recording it must not re-clip: the generic cap counts CHARACTERS and would
# cut a byte-exact tail into a different string.
_long_job = "shlong"
_cl = _seed_cycle(_long_job, DATA / "jobs" / _long_job)
_rec_long = SH.record_input(_long_job, "postjudge",
                            {"cycle_id": _cl, "exit_code": 0, **_pi})
check("the recorded tail is byte-identical to the derived one",
      _rec_long["inputs"]["stdout_tail"] if _rec_long else None, _pi["stdout_tail"])

# End to end: the same run judged directly and through shadow must reach the
# SAME verdict. The override downgrades success->partial only when every shape
# is a placeholder, so the real flag in the tail is what keeps it `success`.
_seen_prompts: list[tuple[str, str, tuple]] = []


def _echo_success(prompt, **kw):
    # The REAL result type. A hand-rolled stand-in was missing fields the
    # failover wrapper reads, and a double that cannot survive the code under
    # test is not evidence about the code under test.
    return _judge_mod.JudgeTurnResult(
        provider="claude", model="m",
        text=json.dumps({"verdict": "success", "next_action": "stop",
                         "summary": "", "retry_hint": "", "failure_code": ""}))


_saved_turn = _judge_mod.judge_turn
_judge_mod.judge_turn = _echo_success
try:
    _direct = _judge_mod.postjudge_run(
        DATA / "jobs" / _long_job, "exploit.py", 0, _LONG, "", lambda *_: None)
    # through the real default evaluator — no injected runner
    SH.evaluate(_long_job, DATA / "jobs" / _long_job)
    _shadow_v = [r["verdict"] for r in SH.read_shadow(_long_job)
                 if r.get("kind") == "verdict" and r.get("stage") == "postjudge"]
finally:
    _judge_mod.judge_turn = _saved_turn

check("judged directly, the run is a success", _direct.get("verdict"), "success")
check("judged through shadow, it is the SAME verdict",
      [v.get("verdict") for v in _shadow_v], ["success"])

# The DISCRIMINATING case for the override. Put the real capture at the START
# and a placeholder at the END: the tail alone shows only a placeholder, and
# the override downgrades success->partial when EVERY shape is one. Enforce
# scans the full output and keeps `success`; a shadow that re-derives shapes
# from the tail flips the verdict. The previous fixture could not tell the two
# apart, because the real flag was in the tail either way.
_LONG2 = _REAL + ("y" * 40_000) + _FAKE + "\n"
_pi2 = _judge_mod.postjudge_inputs(_LONG2, "")
check("the tail alone shows only the placeholder",
      (_REAL in _pi2["stdout_tail"], _FAKE in _pi2["stdout_tail"]), (False, True))
check("...but the recorded shapes still carry the real one",
      _REAL in _pi2["flag_shapes"], True)

_long2 = "shlong2"
_cl2 = _seed_cycle(_long2, DATA / "jobs" / _long2)
SH.record_input(_long2, "postjudge", {"cycle_id": _cl2, "exit_code": 0, **_pi2})
_judge_mod.judge_turn = _echo_success
try:
    _direct2 = _judge_mod.postjudge_run(
        DATA / "jobs" / _long2, "exploit.py", 0, _LONG2, "", lambda *_: None)
    SH.evaluate(_long2, DATA / "jobs" / _long2)
    _shadow2 = [r["verdict"] for r in SH.read_shadow(_long2)
                if r.get("kind") == "verdict" and r.get("stage") == "postjudge"]
finally:
    _judge_mod.judge_turn = _saved_turn
check("a capture at the START is still a success directly",
      _direct2.get("verdict"), "success")
check("...and shadow does not downgrade it to partial",
      [v.get("verdict") for v in _shadow2], ["success"])

# The unclipped-field rule needs a value that actually EXCEEDS the generic cap
# in CHARACTERS. A byte-bounded tail never can; a script and a long prior-hint
# history can.
_big_ctx = "hint\n" * 4_000
_big_src = "# " + ("s" * 30_000) + "\nprint(1)\n"
_uncl = "shuncl"
(DATA / "jobs" / _uncl).mkdir(parents=True, exist_ok=True)
(DATA / "jobs" / _uncl / "big.py").write_text(_big_src)
_rec_u = SH.record_input(_uncl, "postjudge", {"extra_context": _big_ctx})
_rec_s = SH.record_input(_uncl, "prejudge", {
    "script_rel": "big.py", **SH.prejudge_fingerprint(DATA / "jobs" / _uncl, "big.py")})
check("a long extra_context is recorded whole, not clipped",
      _rec_u["inputs"]["extra_context"] if _rec_u else None, _big_ctx)
check("a long script snapshot is recorded whole",
      _rec_s["inputs"]["script_text"] if _rec_s else None, _big_src)
check("...while an unlisted field is still capped",
      len(SH.record_input(_uncl, "postjudge", {"stdout": "z" * 50_000})
          ["inputs"]["stdout"]) < 20_000, True)

# ---------------------------------------------------------------------------
# 11. Evaluate the same inputs or none. The retry loop rewrites exploit.py
#     between attempts, and report.md / chain.json move too — prejudge reads
#     all three, and returns a silent ok=True when the script is simply gone.
#     Restoring a recorded copy was tried and dropped: the prompt embeds the
#     script's PATH, so a copy under any other name is a different prompt, and
#     the companions cannot be put back at all without rewriting the job.
# ---------------------------------------------------------------------------
_saved_pre2 = _judge_mod.prejudge_script


def _mk_job(name, *, script="print('one')\n", report=None, chain=None):
    jd = DATA / "jobs" / name
    (jd / "work").mkdir(parents=True, exist_ok=True)
    (jd / "exploit.py").write_text(script)
    if report is not None:
        (jd / "work" / "report.md").write_text(report)
    if chain is not None:
        (jd / "work" / "chain.json").write_text(chain)
    (jd / "meta.json").write_text(json.dumps({"id": name}))
    return jd


def _evaluate_with_stub(name, jd):
    """Run the real default evaluator, capturing what prejudge was handed."""
    seen: list[str] = []

    def _stub(j, rel, target, log_fn, **kw):
        seen.append((j / rel).read_text())
        return {"ok": True, "severity": "low", "issues": [], "raw": ""}

    _judge_mod.prejudge_script = _stub
    try:
        SH.evaluate(name, jd)
    finally:
        _judge_mod.prejudge_script = _saved_pre2
    verdicts = [r["verdict"] for r in SH.read_shadow(name)
                if r.get("kind") == "verdict"]
    return seen, verdicts


# Unchanged: judge it, in place, at the recorded path.
_same = "shsame"
_same_dir = _mk_job(_same, report="all good\n", chain='{"steps": []}')
SH.record_input(_same, "prejudge", {
    "script_rel": "exploit.py", **SH.prejudge_fingerprint(_same_dir, "exploit.py")})
_seen, _v = _evaluate_with_stub(_same, _same_dir)
check("an unchanged artifact is judged in place", _seen, ["print('one')\n"])
check("...and yields a real verdict", [x.get("ok") for x in _v], [True])

# The SCRIPT moved.
_chg = "shchg"
_chg_dir = _mk_job(_chg, report="all good\n")
SH.record_input(_chg, "prejudge", {
    "script_rel": "exploit.py", **SH.prejudge_fingerprint(_chg_dir, "exploit.py")})
(_chg_dir / "exploit.py").write_text("print('attempt three')\n")
_seen, _v = _evaluate_with_stub(_chg, _chg_dir)
check("a changed script is NOT judged", _seen, [])
check("...it is recorded as unevaluable, naming the artifact",
      (bool(_v[0].get("unevaluable")), "exploit.py" in json.dumps(_v)),
      (True, True))
check("...rather than reporting a clean review", _v[0].get("ok"), None)
check("...and the rollup does not count it as a measurement",
      (SH.summary(_chg)["evaluated"], SH.summary(_chg)["unevaluable"]), (0, 1))

# A COMPANION moved. Same script, same hash — and prejudge's deterministic
# gates read report.md for self-defeat admissions, so this alone flips a
# verdict. Fingerprinting the script only would have missed it.
_comp = "shcomp"
_comp_dir = _mk_job(_comp, report="a working write primitive\n")
SH.record_input(_comp, "prejudge", {
    "script_rel": "exploit.py", **SH.prejudge_fingerprint(_comp_dir, "exploit.py")})
(_comp_dir / "work" / "report.md").write_text("No write identified\n")
_seen, _v = _evaluate_with_stub(_comp, _comp_dir)
check("a changed report.md is caught even with the script untouched", _seen, [])
check("...and named", "report.md" in json.dumps(_v), True)

# chain.json appearing where there was none is also a changed input.
_ch2 = "shchain"
_ch2_dir = _mk_job(_ch2, report="fine\n")
SH.record_input(_ch2, "prejudge", {
    "script_rel": "exploit.py", **SH.prejudge_fingerprint(_ch2_dir, "exploit.py")})
(_ch2_dir / "work" / "chain.json").write_text('{"steps": [{"id": 1}]}')
_seen, _v = _evaluate_with_stub(_ch2, _ch2_dir)
check("chain.json appearing is a changed input", _seen, [])
check("...and named", "chain.json" in json.dumps(_v), True)

# Bytes that are not UTF-8 must not be laundered into text. A replacement
# decode would produce a different file wearing the recorded hash.
_lat = "shlatin"
_lat_dir = DATA / "jobs" / _lat
_lat_dir.mkdir(parents=True, exist_ok=True)
(_lat_dir / "exploit.py").write_bytes(b"# -*- coding: latin-1 -*-\ns = '\xe9'\n")
_fp = SH.prejudge_fingerprint(_lat_dir, "exploit.py")
check("a non-UTF-8 script still gets a hash", bool(_fp["script_sha256"]), True)
check("...but no text, because the round-trip would not be the same bytes",
      _fp["script_text"], None)
check("...and the hash is over the RAW bytes",
      _fp["script_sha256"],
      __import__("hashlib").sha256((_lat_dir / "exploit.py").read_bytes()).hexdigest())

# ---------------------------------------------------------------------------
# 12. Two evaluators must not make an input disappear. Completion is matched
#     by the input's own id: a duplicate verdict is redundant, never a silent
#     cancellation of some LATER input.
# ---------------------------------------------------------------------------
_conc = "shconc"
_conc_dir = DATA / "jobs" / _conc
_conc_dir.mkdir(parents=True, exist_ok=True)
_cc = _seed_cycle(_conc, _conc_dir)
_in1 = SH.record_input(_conc, "supervise", {"cycle_id": _cc, "stall_seconds": 30})
check("an input carries an identity", bool(_in1 and _in1.get("id")), True)

# Two evaluators both answer the first input — the concurrency Codex hit.
SH.evaluate(_conc, _conc_dir, runner=lambda st, i: {"action": "continue"})
SH.record_verdict(_conc, "supervise", {"action": "continue"},
                  answers=_in1["id"])          # the duplicate
_in2 = SH.record_input(_conc, "supervise", {"cycle_id": _cc, "stall_seconds": 60})
check("a later input is still pending after a duplicate verdict",
      [r["id"] for r in SH.pending_inputs(_conc)], [_in2["id"]])
_seen2: list[int] = []
SH.evaluate(_conc, _conc_dir,
            runner=lambda st, i: (_seen2.append(i.get("stall_seconds")),
                                  {"action": "continue"})[1])
check("...and it does get evaluated", _seen2, [60])

# Legacy records — written before ids existed — still read correctly.
_leg = "shlegacy"
_leg_dir = DATA / "jobs" / _leg
_leg_dir.mkdir(parents=True, exist_ok=True)
_lp = SH.shadow_path(_leg)
_lp.parent.mkdir(parents=True, exist_ok=True)
_lp.write_text("\n".join(json.dumps(r) for r in [
    {"ts": "t0", "kind": "input", "stage": "supervise", "inputs": {"stall_seconds": 30}},
    {"ts": "t1", "kind": "verdict", "stage": "supervise", "verdict": {"action": "continue"}},
    {"ts": "t2", "kind": "input", "stage": "supervise", "inputs": {"stall_seconds": 60}},
]) + "\n")
check("an id-less file falls back to positional matching",
      [r["inputs"]["stall_seconds"] for r in SH.pending_inputs(_leg)], [60])

# ---------------------------------------------------------------------------
# 13. The delayed postjudge can READ. Its prompt says so: "You may Read the
#     script + std{out,err} files under `{cwd}`". Those live at fixed names
#     the next attempt overwrites, so an evaluation that happens later can
#     answer about attempt 3's crash while holding attempt 1's tail.
# ---------------------------------------------------------------------------
_pj = "shpjart"
_pj_dir = DATA / "jobs" / _pj
(_pj_dir / "work").mkdir(parents=True, exist_ok=True)
(_pj_dir / "exploit.py").write_text("print('one')\n")
(_pj_dir / "exploit.py.stdout").write_text("FIRST_ATTEMPT_GOOD\n")
(_pj_dir / "exploit.py.stderr").write_text("")
_pjfp = SH.postjudge_fingerprint(_pj_dir, "exploit.py")
check("the postjudge fingerprint covers the readable artifacts",
      sorted(_pjfp), ["script_sha256", "stderr_file_sha256", "stdout_file_sha256"])
_cpj = _seed_cycle(_pj, _pj_dir)
SH.record_input(_pj, "postjudge", {
    "cycle_id": _cpj, "script_rel": "exploit.py", "exit_code": 0,
    **_pjfp, **_judge_mod.postjudge_inputs("FIRST_ATTEMPT_GOOD\n", "")})

# The next attempt overwrites the fixed-name file.
(_pj_dir / "exploit.py.stdout").write_text("SECOND_ATTEMPT_CRASH\n")
_pj_called: list[str] = []
_saved_post2 = _judge_mod.postjudge_run
_judge_mod.postjudge_run = lambda *a, **k: (
    _pj_called.append("x"), {"verdict": "crash"})[1]
try:
    SH.evaluate(_pj, _pj_dir)
finally:
    _judge_mod.postjudge_run = _saved_post2
_pjv = [r["verdict"] for r in SH.read_shadow(_pj) if r.get("kind") == "verdict"]
check("an overwritten stdout file stops the delayed postjudge", _pj_called, [])
check("...naming the file that moved",
      "exploit.py.stdout" in json.dumps(_pjv), True)

# ---------------------------------------------------------------------------
# 14. pre -> post share ONE judge session. A postjudge evaluated without its
#     prejudge has none of the context the gate's postjudge had, so it is not
#     a measurement of the gate — and must not be counted as one.
# ---------------------------------------------------------------------------
_dep = "shdep"
_dep_dir = DATA / "jobs" / _dep
(_dep_dir / "work").mkdir(parents=True, exist_ok=True)
(_dep_dir / "exploit.py").write_text("print('one')\n")
(_dep_dir / "exploit.py.stdout").write_text("out\n")
(_dep_dir / "exploit.py.stderr").write_text("")
SH.record_input(_dep, "prejudge", {
    "script_rel": "exploit.py", **SH.prejudge_fingerprint(_dep_dir, "exploit.py")})
SH.record_input(_dep, "postjudge", {
    "script_rel": "exploit.py", "exit_code": 0,
    **SH.postjudge_fingerprint(_dep_dir, "exploit.py"),
    **_judge_mod.postjudge_inputs("out\n", "")})
# Only the SCRIPT moves — postjudge's own artifacts are untouched, so nothing
# but the prejudge dependency can stop it.
(_dep_dir / "exploit.py").write_text("print('three')\n")
(_dep_dir / "exploit.py.stdout").write_text("out\n")

_pre_calls, _post_calls = [], []
_judge_mod.prejudge_script = lambda *a, **k: (
    _pre_calls.append("x"), {"ok": True, "severity": "low"})[1]
_judge_mod.postjudge_run = lambda *a, **k: (
    _post_calls.append("x"), {"verdict": "success"})[1]
try:
    _n_dep = SH.evaluate(_dep, _dep_dir)
finally:
    _judge_mod.prejudge_script = _saved_pre2
    _judge_mod.postjudge_run = _saved_post2

check("an unevaluable prejudge is not judged", _pre_calls, [])
check("...and its postjudge is not judged either", _post_calls, [])
_depv = [r["verdict"] for r in SH.read_shadow(_dep) if r.get("kind") == "verdict"]
check("both stages are recorded, both unevaluable",
      [bool(v.get("unevaluable")) for v in _depv], [True, True])
check("...and the postjudge says WHY it was blocked",
      "prejudge for this cycle was unevaluable"
      in str(_depv[1].get("unevaluable")), True)
check("evaluate() reports no measurements", _n_dep, 0)

# The rollup must not report this job as fully evaluated.
_ds = SH.summary(_dep)
check("the rollup counts the inputs", _ds["inputs"], 2)
check("...but zero measurements", _ds["evaluated"], 0)
check("...and two refusals", _ds["unevaluable"], 2)
check("...split by stage",
      _ds["unevaluable_by_stage"], {"prejudge": 1, "postjudge": 1})
check("...with by_stage empty, since nothing was measured", _ds["by_stage"], {})

# The block survives a RESUMED evaluation: a later call must reach the same
# conclusion, which is why it is derived from the file and not a local.
SH.record_input(_dep, "postjudge", {
    "script_rel": "exploit.py", "exit_code": 0,
    **SH.postjudge_fingerprint(_dep_dir, "exploit.py"),
    **_judge_mod.postjudge_inputs("out\n", "")})
_post2: list[str] = []
_judge_mod.postjudge_run = lambda *a, **k: (
    _post2.append("x"), {"verdict": "success"})[1]
try:
    SH.evaluate(_dep, _dep_dir)
finally:
    _judge_mod.postjudge_run = _saved_post2
check("a resumed evaluation is still blocked", _post2, [])

# ---------------------------------------------------------------------------
# 15. A refusal belongs to its CYCLE. A job retries; each attempt opens its own
#     judge session. Keyed job-wide, attempt 1's refusal silenced attempt 2's
#     perfectly healthy postjudge — and the rollup called both unevaluable.
# ---------------------------------------------------------------------------
_ret = "shretry"
_ret_dir = DATA / "jobs" / _ret
(_ret_dir / "work").mkdir(parents=True, exist_ok=True)


def _record_cycle(job, jd, cyc):
    SH.record_input(job, "prejudge", {
        "cycle_id": cyc, "script_rel": "exploit.py",
        **SH.prejudge_fingerprint(jd, "exploit.py")})
    SH.record_input(job, "postjudge", {
        "cycle_id": cyc, "script_rel": "exploit.py", "exit_code": 0,
        **SH.postjudge_fingerprint(jd, "exploit.py"),
        **_judge_mod.postjudge_inputs("out\n", "")})


(_ret_dir / "exploit.py").write_text("print('one')\n")
(_ret_dir / "exploit.py.stdout").write_text("out\n")
(_ret_dir / "exploit.py.stderr").write_text("")
_record_cycle(_ret, _ret_dir, "cycA")          # attempt 1
(_ret_dir / "exploit.py").write_text("print('two')\n")   # the retry rewrites it
_record_cycle(_ret, _ret_dir, "cycB")          # attempt 2 — matches disk NOW

_rpre, _rpost = [], []
_judge_mod.prejudge_script = lambda *a, **k: (
    _rpre.append("x"), {"ok": True, "severity": "low"})[1]
_judge_mod.postjudge_run = lambda *a, **k: (
    _rpost.append("x"), {"verdict": "success"})[1]
try:
    _rn = SH.evaluate(_ret, _ret_dir)
finally:
    _judge_mod.prejudge_script = _saved_pre2
    _judge_mod.postjudge_run = _saved_post2

check("attempt 1 is refused — its artifacts moved", len(_rpre), 1)
check("...and attempt 2 IS measured, both stages", len(_rpost), 1)
check("...so the run yields two measurements, not zero", _rn, 2)
_rs = SH.summary(_ret)
check("the rollup splits them by cycle, not by job",
      (_rs["evaluated"], _rs["unevaluable"]), (2, 2))
_rpost_v = [r["verdict"] for r in SH.read_shadow(_ret)
            if r.get("kind") == "verdict" and r.get("stage") == "postjudge"]
check("attempt 1's postjudge is refused, attempt 2's is measured",
      [bool(v.get("unevaluable")) for v in _rpost_v], [True, False])
check("...and attempt 2's verdict is the real one", _rpost_v[1].get("verdict"),
      "success")

# The cycle id has to come from the RUNNER, one per attempt. The fixtures
# above mint their own, so they cannot tell whether the live path emits one at
# all — the same blind spot that let the whole shadow branch sit dead in round
# 1. Drive the real function twice and read what it wrote.
_cyc_job = "shcycrun"
_cyc_dir = DATA / "jobs" / _cyc_job
(_cyc_dir / "work").mkdir(parents=True, exist_ok=True)
(_cyc_dir / "work" / "exploit.py").write_text("print('x')\n")
(_cyc_dir / "exploit.py").write_text("print('x')\n")
(_cyc_dir / "meta.json").write_text(json.dumps({"id": _cyc_job}))
set_settings(enable_judge=False, judge_mode="shadow")
_saved_run = (R.run_in_sandbox, R.Path)
R.run_in_sandbox = lambda *a, **k: {"exit_code": 0, "stdout": "o", "stderr": "",
                                    "timeout": False, "killed_by_supervise": False}
R.Path = _tmp_path
try:
    R.attempt_sandbox_run(_cyc_job, "exploit.py", None, lambda *_: None)
    R.attempt_sandbox_run(_cyc_job, "exploit.py", None, lambda *_: None)
finally:
    R.run_in_sandbox, R.Path = _saved_run

_cyc_rows = [(r["stage"], (r["inputs"] or {}).get("cycle_id"))
             for r in SH.read_shadow(_cyc_job) if r.get("kind") == "input"]
check("two attempts record four rows", len(_cyc_rows), 4)
check("...one prejudge and one postjudge each",
      sorted(st for st, _ in _cyc_rows),
      ["postjudge", "postjudge", "prejudge", "prejudge"])
_cyc_ids = [c for _st, c in _cyc_rows]
check("...every row carries a cycle id", all(bool(c) for c in _cyc_ids), True)
check("...the two stages of one attempt SHARE it, and the attempts differ",
      (_cyc_ids[0] == _cyc_ids[1], _cyc_ids[2] == _cyc_ids[3],
       _cyc_ids[0] == _cyc_ids[2]),
      (True, True, False))

# ---------------------------------------------------------------------------
# 16. A stage whose model never answered is not a measurement. Every stage
#     normalises a failed turn into a permissive default so the RUN is not
#     blocked; that default is indistinguishable from an opinion unless
#     `error_kind` survives to the public verdict.
# ---------------------------------------------------------------------------
check("_with_failover carries error_kind out to the verdict",
      _judge_mod._with_failover(
          {"verdict": "unknown"},
          _judge_mod.JudgeTurnResult(provider="claude", model="m",
                                     error_kind="auth_error",
                                     error_detail="no creds")),
      {"verdict": "unknown", "error_kind": "auth_error",
       "error_detail": "no creds"})
check("...and adds nothing when the turn was fine",
      _judge_mod._with_failover(
          {"verdict": "success"},
          _judge_mod.JudgeTurnResult(provider="claude", model="m", text="{}")),
      {"verdict": "success"})

_ek = "shek"
_ek_dir = DATA / "jobs" / _ek
_ek_dir.mkdir(parents=True, exist_ok=True)
_cek = _seed_cycle(_ek, _ek_dir)
SH.record_input(_ek, "postjudge", {"cycle_id": _cek, "exit_code": 0})
_nek = SH.evaluate(_ek, _ek_dir,
                   runner=lambda st, i: {"verdict": "unknown",
                                         "error_kind": "auth_error"})
check("a verdict carrying error_kind counts as no measurement", _nek, 0)
_eks = SH.summary(_ek)
check("...and lands in the unevaluable column",
      (_eks["evaluated"], _eks["unevaluable_by_stage"].get("postjudge")), (1, 1))
check("...saying the judge never answered",
      any("never answered" in str((r["verdict"] or {}).get("unevaluable") or "")
          for r in SH.read_shadow(_ek) if r.get("kind") == "verdict"), True)

# ---------------------------------------------------------------------------
# 17. One measurement per INPUT. `pending_inputs` already folds duplicate
#     answers; the rollup was appending every row, so `evaluated` could exceed
#     `inputs` — a number that cannot be true.
# ---------------------------------------------------------------------------
_dup = "shdup"
_dup_dir = DATA / "jobs" / _dup
_dup_dir.mkdir(parents=True, exist_ok=True)
_cdup = _seed_cycle(_dup, _dup_dir)
_di = SH.record_input(_dup, "supervise", {"cycle_id": _cdup, "stall_seconds": 30})
SH.evaluate(_dup, _dup_dir, runner=lambda st, i: {"action": "continue"})
SH.record_verdict(_dup, "supervise", {"action": "continue"}, answers=_di["id"])
_dsum = SH.summary(_dup)
check("a duplicate verdict does not inflate the rollup",
      _dsum["by_stage"].get("supervise"), 1)
check("...and evaluated never exceeds inputs",
      _dsum["evaluated"] <= _dsum["inputs"], True)
check("...with nothing left pending", SH.pending_inputs(_dup), [])

# ---------------------------------------------------------------------------
# 18. An orphan postjudge has no session to resume. Recording is best-effort
#     per stage, so a lost prejudge append leaves exactly this shape — and the
#     old check looked for a REFUSED prejudge, which reads the same as "fine".
# ---------------------------------------------------------------------------
_orp = "shorphan"
_orp_dir = DATA / "jobs" / _orp
_orp_dir.mkdir(parents=True, exist_ok=True)
SH.record_input(_orp, "postjudge", {"cycle_id": "cycZ", "exit_code": 0})
_ocalls = []
_norp = SH.evaluate(_orp, _orp_dir,
                    runner=lambda st, i: (_ocalls.append(st), {"verdict": "x"})[1])
check("an orphan postjudge is not judged", _ocalls, [])
check("...and counts as no measurement", _norp, 0)
check("...saying the prerequisite is missing, not that it failed",
      any("no prejudge was recorded" in str((r["verdict"] or {}).get("unevaluable") or "")
          for r in SH.read_shadow(_orp) if r.get("kind") == "verdict"), True)

print(
    f"== summary: {PASSED} passed, {FAILED} failed =="
    + (f"  [stubbed: {', '.join(STUBBED)}]" if STUBBED else "  [all real deps]")
)
_TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
