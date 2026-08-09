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

print(f"== summary: {PASSED} passed, {FAILED} failed =="
      + (f"  [stubbed: {', '.join(STUBBED)}]" if STUBBED else "  [all real deps]"))
_TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
