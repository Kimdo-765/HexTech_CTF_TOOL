#!/usr/bin/env python3
"""`enforce` gates pwn and web. On every other module it must record, not gate.

Stage 8, operator decision 2026-08-09. The stage-7 stratified table could only
measure discriminating power where both outcome classes exist — pwn (8/8) and
web (3/3). rev (13/1) and crypto (6/0) have effectively no negative class, so a
judge answering "success" every time scores full marks there; that is a
measurement nobody took, not a result worth gating on.

The property this pins is not "the constant says pwn and web". It is that the
SAME global `enforce` produces a different gate answer for a pwn job than for a
rev job, and that every path which cannot determine the module lands on shadow
rather than enforce. A suite that only asserted the constant would pass against
an implementation that ignored the module entirely.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.TemporaryDirectory(prefix="judge-scope-")
DATA = Path(_TMP.name)
(DATA / "jobs").mkdir()
SETTINGS = DATA / "settings.json"
SETTINGS.write_text("{}")
os.environ.update(DATA_DIR=str(DATA), SETTINGS_PATH=str(SETTINGS),
                  JOBS_DIR=str(DATA / "jobs"))
for _k in ("JUDGE_MODE", "ENABLE_JUDGE"):
    os.environ.pop(_k, None)

import ast  # noqa: E402
import importlib.util  # noqa: E402
import types  # noqa: E402


def _missing(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is None
    except (ImportError, ValueError):
        return True


STUBBED = [n for n in ("docker", "claude_agent_sdk") if _missing(n)]
if _missing("docker"):
    # `_runner` builds a Docker client at import. The helpers under test never
    # touch it; stub only what is absent so this still runs in the worker image
    # against the real client.
    _d = types.ModuleType("docker")
    _d.from_env = lambda *a, **k: None
    _d.DockerClient = type("DockerClient", (), {})
    _e = types.ModuleType("docker.errors")
    for _n in ("APIError", "NotFound", "ImageNotFound", "DockerException",
               "NullResource"):
        setattr(_e, _n, type(_n, (Exception,), {}))
    _d.errors = _e
    _t = types.ModuleType("docker.types")
    _t.Mount = type("Mount", (), {"__init__": lambda s, **k: None})
    _d.types = _t
    sys.modules.update({"docker": _d, "docker.errors": _e, "docker.types": _t})

if _missing("claude_agent_sdk"):
    _sdk = types.ModuleType("claude_agent_sdk")
    for _n in ("AssistantMessage", "ClaudeAgentOptions", "ResultMessage",
               "SystemMessage", "TextBlock", "ClaudeSDKClient", "UserMessage"):
        setattr(_sdk, _n, type(_n, (), {"__init__": lambda s, **k: None}))

    async def _q(*a, **k):  # pragma: no cover
        if False:
            yield None

    _sdk.query = _q
    for _n in ("HookMatcher", "AgentDefinition"):
        setattr(_sdk, _n, type(_n, (), {"__init__": lambda s, **k: None}))
    _sdk.create_sdk_mcp_server = lambda *a, **k: None
    _sdk.tool = lambda *a, **k: (lambda fn: fn)
    _sdk.project_key_for_directory = lambda *a, **k: ""
    sys.modules["claude_agent_sdk"] = _sdk

from modules import _runner as R  # noqa: E402
from modules import settings_io as S  # noqa: E402

PASSED = FAILED = 0


def check(label, got, want):
    global PASSED, FAILED
    if got == want:
        PASSED += 1
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


def set_settings(**kw) -> None:
    SETTINGS.write_text(json.dumps(kw))


def make_job(job_id: str, **meta) -> str:
    d = DATA / "jobs" / job_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "meta.json").write_text(json.dumps({"id": job_id, **meta}))
    return job_id


# ---------------------------------------------------------------------------
# 1. The rule itself.
# ---------------------------------------------------------------------------
for module, want in (
    ("pwn", "enforce"),
    ("web", "enforce"),
    ("rev", "shadow"),
    ("crypto", "shadow"),
    ("web3", "shadow"),
    ("misc", "shadow"),
    ("forensic", "shadow"),
):
    check(f"enforce x {module}", S.effective_judge_mode("enforce", module), want)

check("an unknown module never reaches enforce",
      S.effective_judge_mode("enforce", "quantum"), "shadow")
check("...nor does an empty one", S.effective_judge_mode("enforce", ""), "shadow")
check("...nor None", S.effective_judge_mode("enforce", None), "shadow")

check("case and padding do not decide a gate",
      (S.effective_judge_mode("enforce", " PWN "),
       S.effective_judge_mode("ENFORCE", "Web")),
      ("enforce", "enforce"))

# Only the GATING is scoped. shadow and off are module-blind: an out-of-scope
# module still records, which is how rev/crypto eventually grow the negative
# class they are missing.
for module in ("pwn", "rev", "quantum", ""):
    check(f"shadow is module-blind ({module or 'empty'})",
          S.effective_judge_mode("shadow", module), "shadow")
    check(f"off is module-blind ({module or 'empty'})",
          S.effective_judge_mode("off", module), "off")

check("a mode outside the tri-state fails to off, not enforce",
      S.effective_judge_mode("ENFORCE_ALL", "pwn"), "off")

# ---------------------------------------------------------------------------
# 2. The job-level resolver — the one the run path actually calls.
# ---------------------------------------------------------------------------
set_settings(judge_mode="enforce")
pwn_job = make_job("j-pwn", module="pwn")
rev_job = make_job("j-rev", module="rev")
bare_job = make_job("j-bare")

check("a pwn job under global enforce gates",
      R._judge_mode_for_job(pwn_job), "enforce")
check("a rev job under the SAME global enforce does not",
      R._judge_mode_for_job(rev_job), "shadow")
check("a job whose meta has no module does not gate",
      R._judge_mode_for_job(bare_job), "shadow")
check("a job with no meta at all does not gate",
      R._judge_mode_for_job("j-does-not-exist"), "shadow")

# THE discriminating assertion. One global setting, two answers — an
# implementation that ignored `module` would pass everything above this line
# that only reads the constant, and fail here.
check("one global enforce, two different gate answers",
      (R._judge_gates(R._judge_mode_for_job(pwn_job)),
       R._judge_gates(R._judge_mode_for_job(rev_job))),
      (True, False))

set_settings(judge_mode="shadow")
check("global shadow gates nothing, pwn included",
      (R._judge_mode_for_job(pwn_job), R._judge_gates(R._judge_mode_for_job(pwn_job))),
      ("shadow", False))
set_settings(judge_mode="off")
check("global off stays off for pwn", R._judge_mode_for_job(pwn_job), "off")
check("...and the module is not consulted at all when off",
      R._judge_mode_for_job("j-does-not-exist"), "off")

# Fail CLOSED. `_judge_mode()` returns "enforce" when settings blow up — a
# defensible fail-open while the mode was global, and no longer defensible now
# that it could hand gating to a module the operator excluded.
set_settings(judge_mode="enforce")
_orig_read = None
try:
    from modules import _common as _C
    _orig_read = _C.read_meta

    def _boom(*a, **k):
        raise OSError("meta unreadable")

    _C.read_meta = _boom
    check("an unreadable meta resolves to shadow, never enforce",
          R._judge_mode_for_job(pwn_job), "shadow")
finally:
    if _orig_read is not None:
        _C.read_meta = _orig_read

check("...and the resolver recovers once meta is readable again",
      R._judge_mode_for_job(pwn_job), "enforce")

# The OTHER failure, and the one that actually shipped broken: a settings read
# that blows up. `_judge_mode()` swallows it and answers "enforce", so the
# resolver used to receive a value it could not tell apart from an operator's
# explicit choice — and with a readable pwn meta it opened a real gate out of a
# filesystem error. Mutating `read_meta` alone never touched this path, which
# is why the suite was 38/0 while it was broken.
_orig_mode = S.get_judge_mode
try:
    def _mode_boom():
        raise OSError("settings unreadable")

    S.get_judge_mode = _mode_boom
    check("a settings failure does not become an operator's enforce",
          R._judge_mode_for_job(pwn_job), "shadow")
    check("...and the gate stays shut for an in-scope module",
          R._judge_gates(R._judge_mode_for_job(pwn_job)), False)
    check("...for an out-of-scope module too", R._judge_mode_for_job(rev_job), "shadow")
finally:
    S.get_judge_mode = _orig_mode

check("...and enforce returns once settings are readable again",
      R._judge_mode_for_job(pwn_job), "enforce")

# The wrapper's fail-open must not be on the path at all. Reading it and THEN
# guarding is not enough: the information needed to tell a failure from a
# choice is already gone by then.
_runner_src = (ROOT / "modules" / "_runner.py").read_text()
_resolver_fn = next(n for n in ast.walk(ast.parse(_runner_src))
                    if isinstance(n, ast.FunctionDef) and n.name == "_judge_mode_for_job")
# Asked of the CALLS, not of the text. The docstring necessarily names
# `_judge_mode()` to explain why it is avoided, and a substring check on the
# source segment therefore reports the very thing it is meant to forbid — the
# first version of this check did exactly that and failed on its own prose.
_resolver_calls = {c.func.id for c in ast.walk(_resolver_fn)
                   if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
check("the resolver reads settings directly, not through the fail-open wrapper",
      ("get_judge_mode" in _resolver_calls, "_judge_mode" in _resolver_calls),
      (True, False))

# ---------------------------------------------------------------------------
# 3. The run path must read the EFFECTIVE mode, not the global one.
#
#    `cycle_id` is the reason this matters beyond gating: it is set only when
#    the mode is "shadow", and an out-of-scope job that recorded with
#    cycle_id="" would collapse into `_cycle_state`'s legacy job-wide bucket,
#    where one attempt's refusal silences the next attempt's healthy postjudge
#    (turn 0073, D21). A single surviving comparison against the raw setting
#    reintroduces that, and it would not show up as a failing gate assertion.
# ---------------------------------------------------------------------------
src = (ROOT / "modules" / "_runner.py").read_text()
tree = ast.parse(src)
fn = next(n for n in ast.walk(tree)
          if isinstance(n, ast.FunctionDef) and n.name == "attempt_sandbox_run")
body = ast.get_source_segment(src, fn) or ""

check("the run path resolves the mode per JOB",
      "_judge_mode_for_job(job_id)" in body, True)
check("...and never calls the global resolver directly",
      "_judge_mode()" in body, False)
check("...assigning judge_mode exactly once, so both answers share a snapshot",
      body.count("judge_mode = "), 1)

# Every downstream consumer must read that one local. Counted by call site so
# a new shadow-recording block added later against the global is caught.
check("both shadow recording sites key off the resolved mode",
      body.count('if judge_mode == "shadow":'), 2)
check("the gate is derived from the resolved mode",
      "enable_judge = _judge_gates(judge_mode)" in body, True)
check("the cycle id is derived from it too",
      'judge_mode == "shadow" else ""' in body, True)

# The scope lives in settings_io, not scattered through the runner.
check("the runner does not restate the enforce set",
      "JUDGE_ENFORCE_MODULES" in src.replace(
          "settings_io.JUDGE_ENFORCE_MODULES", ""), False)
check("the scope is a documented constant", S.JUDGE_ENFORCE_MODULES, ("pwn", "web"))

# ---------------------------------------------------------------------------
# 4. supervise is excluded from v1 enforce, and turning the gate on must not
#    turn it on. Two grounds, both still true: its evidence is a LIVE
#    container's stalled output, which no post-hoc shadow can reconstruct — so
#    it is the one stage stage-7 never measured — and it is the only gate that
#    KILLS. Hardest to verify, largest blast radius.
#
#    It used to ride the same `enable_judge` flag as prejudge/postjudge, so
#    flipping Settings to enforce handed container lifetime to an unevaluated
#    gate. Driven here rather than read, because the wiring is what broke.
# ---------------------------------------------------------------------------
set_settings(judge_mode="enforce")
_sandbox_kw: list[dict] = []


def _spy_sandbox(*a, **kw):
    _sandbox_kw.append(kw)
    return {"exit_code": 0, "stdout": "", "stderr": "", "timeout": False,
            "killed_by_supervise": False}


_pre_calls, _post_calls = [], []
from modules import _judge as _J  # noqa: E402

_saved = (R.run_in_sandbox, R.Path, _J.prejudge_script, _J.postjudge_run)
_jd = DATA / "jobs" / "j-pwn"
(_jd / "work").mkdir(parents=True, exist_ok=True)
(_jd / "work" / "exploit.py").write_text("print('x')\n")


class _P(type(Path())):  # a Path that maps /data/jobs/<id> onto the fixture
    pass


def _tmp_path(p="", *a):
    p = str(p)
    return Path(str(DATA / "jobs") + p[len("/data/jobs"):]) if p.startswith("/data/jobs") else Path(p, *a)


try:
    R.run_in_sandbox = _spy_sandbox
    R.Path = _tmp_path
    _J.prejudge_script = lambda *a, **k: (_pre_calls.append(1),
                                          {"ok": True, "severity": "low"})[1]
    _J.postjudge_run = lambda *a, **k: (_post_calls.append(1),
                                        {"verdict": "success",
                                         "next_action": "stop"})[1]
    R.attempt_sandbox_run("j-pwn", "exploit.py", None, lambda *_: None)
finally:
    R.run_in_sandbox, R.Path, _J.prejudge_script, _J.postjudge_run = _saved

check("an in-scope job under enforce still runs prejudge and postjudge",
      (bool(_pre_calls), bool(_post_calls)), (True, True))
check("...and hands the sandbox the supervise flag OFF",
      [kw.get("enable_supervise") for kw in _sandbox_kw], [False])
check("...never passing the pre/post gate through as the supervise flag",
      any("enable_judge" in kw for kw in _sandbox_kw), False)

# The wait loop itself must honour it: a stalled container with the flag off
# gets no supervise call and no kill, no matter how long it sits.
class _StalledContainer:
    """Alive, never exits, never changes its output — a permanent stall."""

    status = "running"
    id = "deadbeef"

    def __init__(self, kills):
        self._kills = kills

    def reload(self):
        pass

    def logs(self, **kw):
        return b"stuck"

    def wait(self, **kw):
        return {"StatusCode": -1}

    def kill(self, *a, **k):
        self._kills.append(1)


def _drive_wait(enable: bool):
    calls, kills = [], []
    saved = (_J.supervise_run_once, R.SUPERVISE_STALL_S, R._POLL_INTERVAL_S)
    try:
        _J.supervise_run_once = lambda *a, **k: (
            calls.append(1), {"action": "kill", "reason": "hung"})[1]
        R.SUPERVISE_STALL_S = -1      # every poll counts as a stall
        # The real interval is 2s and the first poll only records the log size
        # — the stall branch cannot be reached until the second. At the default
        # interval a short `timeout_s` times out first, which is how the
        # positive control below caught this driver being unable to trigger the
        # path it was asserting about.
        R._POLL_INTERVAL_S = 0.01
        res = R._wait_with_supervise(
            _StalledContainer(kills), timeout_s=1, job_dir_path=_jd,
            script_rel="exploit.py", log_fn=lambda *_: None,
            enable_supervise=enable)
    finally:
        _J.supervise_run_once, R.SUPERVISE_STALL_S, R._POLL_INTERVAL_S = saved
    return calls, kills, res


# POSITIVE CONTROL FIRST. "supervise was called 0 times" is worth nothing if
# this fixture could never have triggered it — the flag would look honoured by
# a container that simply never stalls.
_on_calls, _on_kills, _on_res = _drive_wait(True)
check("control: with supervise ON this fixture does reach the judge",
      (bool(_on_calls), bool(_on_kills)), (True, True))
check("...and reports the kill as supervise's",
      _on_res.get("killed_by_supervise"), True)

_off_calls, _off_kills, _off_res = _drive_wait(False)
check("a stalled container is not judged when supervise is off", _off_calls, [])
check("...and nothing is attributed to supervise",
      (_off_res.get("killed_by_supervise"), _off_res.get("supervise")), (None, None))
# The container IS killed here — by the hard timeout, which is not a judge
# decision and must keep working. Asserting "no kill at all" would have pinned
# the wrong thing; the first draft of this check did exactly that and failed on
# the timeout path.
check("...while the hard timeout still kills, judge or no judge",
      (_off_kills, _off_res.get("timeout")), ([1], True))

# ---------------------------------------------------------------------------
# 5. What the OPERATOR is told has to match what the code does.
#
#    The runtime boundary was fixed while the Settings control still promised
#    "supervise fires under the enforce gate" and titled the mode with a stall
#    watchdog. Every runtime check above passed against that build: the code
#    was right and the contract shown to the person flipping the switch was
#    backwards. A gate the operator believes is live and is not is the exact
#    failure `get_judge_mode`'s docstring exists to prevent — it just happened
#    in prose instead of in code.
# ---------------------------------------------------------------------------
_html = (ROOT / "web-ui" / "index.html").read_text()
_i = _html.index('<select name="judge_mode">')
_block = _html[_html.rindex("<label>", 0, _i):_html.index("</label>", _i)]

check("the mode control does not advertise supervise as one of its stages",
      ("stall watchdog" in _block.split("<select")[0]), False)
check("...and does not promise that supervise fires under enforce",
      "supervise fires under" in _block, False)
check("...it states the opposite, where the operator will read it",
      "does not run in any mode" in _block, True)

# The same contract, in the two internal places that also stated it wrongly.
check("judge_shadow no longer ties supervise to the pre/post gate",
      "under the same `enable_judge` gate" in
      (ROOT / "modules" / "judge_shadow.py").read_text(), False)
_settings_src = (ROOT / "modules" / "settings_io.py").read_text()
check("the settings schema no longer sells hang detection as part of the judge",
      "stall supervisor →" in _settings_src, False)

# ---------------------------------------------------------------------------
# 6. Bind the runtime boundary to what the MODELS are told, in one check.
#
#    Section 5 pinned the operator-facing copy and still missed this: the judge
#    system prompt taught the judge that the orchestrator drives it through a
#    supervise stage, and the deterministic heap hints injected into main
#    asserted that a watchdog kills a hung run. Those go to a model, not to a
#    reader — a judge reasoning about a post-mortem under a false lifecycle,
#    and a retry hint steering main around a mechanism that does not exist.
#
#    Written as an implication rather than as two independent assertions: the
#    claims are only wrong BECAUSE the boundary is False. If supervise is ever
#    driven again, this check should stop demanding their absence rather than
#    silently keep failing.
# ---------------------------------------------------------------------------
_attempt = next(n for n in ast.walk(ast.parse(_runner_src))
                if isinstance(n, ast.FunctionDef) and n.name == "attempt_sandbox_run")
_supervise_args = [kw.value.value
                   for c in ast.walk(_attempt) if isinstance(c, ast.Call)
                   for kw in c.keywords
                   if kw.arg == "enable_supervise" and isinstance(kw.value, ast.Constant)]
check("the production attempt drives supervise nowhere", _supervise_args, [False])

if _supervise_args == [False]:
    from modules._prompts import JUDGE_AGENT_PROMPT  # noqa: E402
    from modules._common import HEAP_FIX_HINTS  # noqa: E402

    check("...so the judge's own prompt does not teach it a supervise stage",
          ("three stages" in JUDGE_AGENT_PROMPT,
           "supervise watchdog" in JUDGE_AGENT_PROMPT),
          (False, False))
    check("...and does say what actually ends a hung run",
          "hard timeout" in JUDGE_AGENT_PROMPT, True)
    _hint_blob = " ".join(str(v) for v in HEAP_FIX_HINTS.values())
    check("...and no retry hint sends main around a watchdog that never runs",
          "supervise watchdog" in _hint_blob, False)
    check("...they name the hard timeout instead",
          "hard timeout" in _hint_blob, True)

    # ------------------------------------------------------------------
    # One decision — "supervise does not run" — turned out to be written
    # down in six places: the runner, the Settings control, the shadow
    # module, the settings schema, the judge's system prompt, main's retry
    # hints, and the README. Each was found separately, one review round
    # each. Enumerating files here would just start that again for the
    # next surface, so this sweeps the whole tree for the VOCABULARY the
    # old contract used. It cannot prove a rewording is honest; it does
    # stop the old wording coming back, and catches a new file adopting it.
    # ------------------------------------------------------------------
    _FORBIDDEN = ("3-stage", "three stages", "stall-supervise",
                  "supervise watchdog", "stall supervisor",
                  "supervise fires under")
    # The plan doc is the record of the decision itself and argues about
    # supervise by name; the suites quote the old strings to test for them.
    _ALLOW = ("docs/hybrid-agent-plan.md", "scripts/test_")
    # SOURCE surfaces only. The first version walked the whole tree and, in the
    # deployment checkout where `data/` exists, flagged agent-written solvers
    # and subagent logs from finished jobs. Those are records of what an agent
    # once said, not contracts anyone can fix, and a check that demands they be
    # edited is a check that gets disabled. It passed in the worktree purely
    # because no `data/` is there — the merge is what exposed it.
    _SURFACES = ("modules", "web-ui", "api", "worker", "docs", "scripts")
    _roots = [ROOT / d for d in _SURFACES] + [ROOT]
    _seen: set = set()
    _offenders = []
    _files = [f for f in sorted(ROOT.glob("*.md")) if f.is_file()]
    for _d in (ROOT / d for d in _SURFACES):
        if _d.is_dir():
            _files += sorted(f for f in _d.rglob("*") if f.is_file())
    for _f in _files:
        if _f.suffix not in (".md", ".py", ".html", ".js", ".sh"):
            continue
        _rel = str(_f.relative_to(ROOT))
        if _rel in _seen:
            continue
        _seen.add(_rel)
        if any(a in _rel for a in _ALLOW):
            continue
        try:
            _txt = _f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for _bad in _FORBIDDEN:
            if _bad in _txt:
                _offenders.append(f"{_rel}: {_bad!r}")
    check("no surface still speaks the pre-stage-8 lifecycle", _offenders, [])

print(f"== summary: {PASSED} passed, {FAILED} failed =="
      + (f"  [stubbed: {', '.join(STUBBED)}]" if STUBBED else "  [all real deps]"))
_TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
