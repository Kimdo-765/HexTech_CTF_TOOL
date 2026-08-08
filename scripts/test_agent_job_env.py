#!/usr/bin/env python3
"""Every agent process gets the same per-job scratch environment.

The one that did NOT was GPT pre-recon, and the consequence was not cosmetic:
with no per-job TMPDIR it unpacked an archive into the container-global /tmp
and analysed a `prob.ko` an earlier job had left there, while the initramfs it
was handed contained only `serendipity.ko` (job 6685e3e65add). An entire recon
pass answered about the wrong binary, confidently.

Three call sites had built this independently and a fourth had not built it at
all — the same "one rule in several places" shape that has produced defects
throughout this branch. It is one function now, and these checks pin both the
function and that every call site actually uses it.
"""

from __future__ import annotations

import ast
import importlib.util
import os
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.TemporaryDirectory(prefix="agentenv-")
DATA = Path(_TMP.name)
(DATA / "jobs").mkdir()
(DATA / "settings.json").write_text("{}")
os.environ.update(DATA_DIR=str(DATA), JOBS_DIR=str(DATA / "jobs"),
                  SETTINGS_PATH=str(DATA / "settings.json"))


def _missing(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is None
    except (ImportError, ValueError):
        return True


STUBBED = [n for n in ("docker", "claude_agent_sdk") if _missing(n)]
if _missing("docker"):
    _d = types.ModuleType("docker")
    _d.from_env = lambda *a, **k: None
    _d.DockerClient = type("DockerClient", (), {})
    _e = types.ModuleType("docker.errors")
    for _n in ("APIError", "NotFound", "ImageNotFound", "DockerException", "NullResource"):
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
    _sdk.HookMatcher = type("HookMatcher", (), {"__init__": lambda s, **k: None})
    _sdk.AgentDefinition = type("AgentDefinition", (), {"__init__": lambda s, **k: None})
    _sdk.create_sdk_mcp_server = lambda *a, **k: None
    _sdk.tool = lambda *a, **k: (lambda fn: fn)
    _sdk.project_key_for_directory = lambda *a, **k: ""
    sys.modules["claude_agent_sdk"] = _sdk

from modules._common import agent_job_env  # noqa: E402

PASSED = FAILED = 0


def check(label, got, want):
    global PASSED, FAILED
    if got == want:
        PASSED += 1
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


# ---------------------------------------------------------------------------
# 1. The scratch dir is per JOB and actually created.
# ---------------------------------------------------------------------------
w1 = DATA / "jobs" / "j1" / "work"
env1 = agent_job_env("j1", "recon", w1)
check("TMPDIR points inside the job's work tree",
      env1["TMPDIR"], str(w1 / "tmp"))
check("...and TMP / TEMP agree with it",
      (env1["TMP"], env1["TEMP"]), (env1["TMPDIR"], env1["TMPDIR"]))
check("...and the directory exists, not just the variable",
      (w1 / "tmp").is_dir(), True)

w2 = DATA / "jobs" / "j2" / "work"
env2 = agent_job_env("j2", "recon", w2)
check("two jobs never share a scratch dir", env1["TMPDIR"] == env2["TMPDIR"], False)

check("the job id travels with it", env1["JOB_ID"], "j1")
check("the role does too", env1["AGENT_ROLE"], "recon")
check("...and an empty role adds no AGENT_ROLE at all — main never had one",
      "AGENT_ROLE" in agent_job_env("j1", "", w1), False)

check("terminfo noise is silenced",
      (env1["TERM"], env1["PWNLIB_NOTERM"]), ("xterm", "1"))
check("a caller may override those",
      agent_job_env("j1", "r", w1, {"TERM": "dumb"})["TERM"], "dumb")
check("extras are stringified",
      agent_job_env("j1", "r", w1, {"N": 7})["N"], "7")

# An unwritable work dir must not fail the run: the agent falls back to the
# container default exactly as it did before this helper existed.
env_ro = agent_job_env("j3", "r", Path("/proc/self/nonexistent-dir"))
check("an uncreatable scratch dir still returns an env", isinstance(env_ro, dict), True)
check("...and still names the intended path", "TMPDIR" in env_ro, True)

# ---------------------------------------------------------------------------
# 2. EVERY call site uses it. This is the half that matters: the defect was a
#    call site that built its own env, not a broken helper.
# ---------------------------------------------------------------------------
src = (ROOT / "modules" / "_common.py").read_text()
tree = ast.parse(src)


def _calls_named(name: str) -> int:
    n = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == name:
                n += 1
    return n


check("main, sub-agents and both pre-recon branches all call it",
      _calls_named("agent_job_env"), 4)

# The literal that used to start each hand-rolled copy must be gone, or a
# fifth call site can quietly reappear built the old way.
check("no call site still hand-builds the env dict",
      '{"JOB_ID": job_id, "AGENT_ROLE"' in src, False)
check("...and no site assigns TMPDIR outside the helper",
      src.count('env["TMPDIR"]'), 1)
check("...nor TMP / TEMP", (src.count('env["TMP"]'), src.count('env["TEMP"]')), (1, 1))

# pre-recon is the site that was missing entirely; pin it by name so a future
# refactor that drops it fails here rather than in a job's recon output.
prerecon = src[src.index("async def run_pre_recon("):]
prerecon = prerecon[:prerecon.index("\ndef ", 1) if "\ndef " in prerecon else len(prerecon)]
check("pre-recon passes the job's work_dir, not a global temp",
      prerecon.count('env=agent_job_env(job_id, "recon", work_dir)'), 2)

print(f"== summary: {PASSED} passed, {FAILED} failed =="
      + (f"  [stubbed: {', '.join(STUBBED)}]" if STUBBED else "  [all real deps]"))
_TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
