#!/usr/bin/env python3
"""pwn can opt into building the bundled Dockerfile, and detection can find it.

Job b914889c1f9c shipped `work/chal/Dockerfile` (a pinned ubuntu:22.04 running
`prob` under socat) and the agent never built it. Three separate things had to
be true for that, and this pins all three:

  * pwn had no 🐳 box in the UI, and `docker_challenge_block` was never wired
    into its prompt — both on the belief, written into that function's own
    docstring, that "web and pwn already build+run challenge Dockerfiles
    unconditionally". True of web. False of pwn, whose prompts say to READ a
    Dockerfile for sysctl/deploy context.

  * detection pruned `work/`, which is exactly where pwn's autoboot unpacks the
    operator archive. So even a ticked box would have answered "found NOTHING"
    about a bundle that shipped one — worse than silence.

  * nothing told the agent that the staged-libc setup reproduces the challenge's
    glibc VERSION but not its MAPPING. Measured on that job: libc 2 MiB-aligned
    5/5 under staged libs, not aligned 5/5 in the challenge image. The exploit's
    whole 1/2048 probability model rested on the alignment it measured in the
    wrong place.

The opt-in stays additive: unticked must remain a byte-for-byte no-op.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.TemporaryDirectory(prefix="dcpwn-")
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


STUBBED = [n for n in ("docker",) if _missing(n)]
if _missing("docker"):
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

from modules._common import docker_challenge_block  # noqa: E402

PASSED = FAILED = 0


def check(label, got, want):
    global PASSED, FAILED
    if got == want:
        PASSED += 1
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


def make_job(job_id: str, *, dockerfile_at: str | None, **meta) -> str:
    d = DATA / "jobs" / job_id
    (d / "bin").mkdir(parents=True, exist_ok=True)
    if dockerfile_at:
        f = d / dockerfile_at
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("FROM ubuntu:22.04\nCMD socat TCP-LISTEN:8080,fork EXEC:./prob\n")
    (d / "meta.json").write_text(json.dumps({"id": job_id, "module": "pwn", **meta}))
    return job_id


# ---------------------------------------------------------------------------
# 1. Detection reaches where pwn's bundle actually lands.
# ---------------------------------------------------------------------------
j = make_job("j-workchal", dockerfile_at="work/chal/Dockerfile", docker_challenge=True)
blk = docker_challenge_block(j)
check("a Dockerfile under work/chal/ is found", "work/chal/Dockerfile" in blk, True)
check("...and the build context is that directory, not the job root",
      '"/data/jobs/$JOB_ID/work/chal"' in blk, True)
# Telling the agent to RUN a container without telling it how to REACH one is
# most of the value thrown away: the worker is not the host, so 127.0.0.1, the
# container's bridge IP and `docker top`'s host pids all fail in different ways.
# Job 1ede2b4d8ac3 spent several turns rediscovering that.
check("...and says how to reach it from the worker",
      ("REACHING IT" in blk and "/proc/net/route" in blk), True)
check("...naming the routes that do NOT work, not just the one that does",
      all(k in blk for k in ("127.0.0.1", "bridge IP", "docker top")), True)

# The pruning that hid it exists for a reason and must still hold: the rest of
# `work/` is agent scratch, and on a forensic job it holds carved evidence.
# Only the operator's own unpack target is exempt.
j2 = make_job("j-scratch", dockerfile_at="work/.scratch/Dockerfile", docker_challenge=True)
check("a Dockerfile in agent scratch under work/ is still ignored",
      "found NO Dockerfile" in docker_challenge_block(j2), True)
# `.scratch` is in the noise set, so the check above passes even for an
# implementation that scans ALL of work/ — a mutation to `_extra_roots =
# [work]` slipped through it. This one does not: `work/carved/` is an ordinary
# directory name, exactly what a forensic collector writing into the job root
# produces, and only `work/chal` may be exempt from the pruning.
j2b = make_job("j-carved", dockerfile_at="work/carved/Dockerfile", docker_challenge=True)
check("...and so is any other work/ subdir — only work/chal is exempt",
      "found NO Dockerfile" in docker_challenge_block(j2b), True)

for where in ("bin/Dockerfile", "src/Dockerfile", "Dockerfile"):
    jn = make_job(f"j-{where.replace('/', '-')}", dockerfile_at=where,
                  docker_challenge=True)
    check(f"the pre-existing root still works: {where}",
          where in docker_challenge_block(jn), True)

# ---------------------------------------------------------------------------
# 2. The opt-in is additive — unticked changes nothing at all.
# ---------------------------------------------------------------------------
j3 = make_job("j-unticked", dockerfile_at="work/chal/Dockerfile")
check("unticked returns the empty string, not advice",
      docker_challenge_block(j3), "")
j4 = make_job("j-explicit-false", dockerfile_at="work/chal/Dockerfile",
              docker_challenge=False)
check("...and an explicit False is the same", docker_challenge_block(j4), "")

# ---------------------------------------------------------------------------
# 3. pwn is wired — prompt injection AND container reaping.
#
#    The reap is the half that bites: `_dc` is bound in `run_job`, and a first
#    draft put the reap in `_run_agent`'s finally, where it raises NameError on
#    every docker-challenge job — in the path that only runs when something has
#    already gone wrong. Asked of the AST so scope is actually checked.
# ---------------------------------------------------------------------------
src = (ROOT / "modules" / "pwn" / "analyzer.py").read_text()
tree = ast.parse(src)
check("pwn injects the docker block into its prompt",
      "docker_challenge_block(job_id)" in src, True)
check("...and sweeps stale containers at start", 'reason="startup sweep"' in src, True)
check("...and reaps them at the end", 'reason="job complete"' in src, True)

_owner = None
for n in ast.walk(tree):
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
        seg = ast.get_source_segment(src, n) or ""
        if all(m in seg for m in ('_dc = bool(', 'reason="startup sweep"',
                                  'reason="job complete"')):
            _owner = n.name
check("the sweep, the reap and the flag they read all live in ONE function",
      _owner is not None, True)

# ---------------------------------------------------------------------------
# 4. The contract the operator and the agent are shown.
# ---------------------------------------------------------------------------
html = (ROOT / "web-ui" / "index.html").read_text()
i = html.index('<section id="panel-pwn"')
pwn_panel = html[i:html.find('<section id="panel-', i + 1)]
check("the pwn form offers the box", 'name="docker_challenge"' in pwn_panel, True)
check("no tooltip still claims pwn does this by default",
      "Pwn already do this by default" in html, False)

common = (ROOT / "modules" / "_common.py").read_text()
# Asked of the ASSERTION, not the phrase. The corrected docstring necessarily
# QUOTES the old claim to explain why it was wrong, so a bare substring check
# matches its own correction — the same trap the supervise vocabulary sweep hit.
check("the block's docstring no longer asserts pwn builds unconditionally",
      "in their own prompts — this does NOT touch" in common, False)
check("...it says outright that the claim was false for pwn",
      "FALSE of\n        pwn" in common or "FALSE of pwn" in common, True)
check("the not-found message names every root it actually searched",
      "./work/chal/" in common, True)

pwn_prompt = (ROOT / "modules" / "pwn" / "analyzer.py").read_text()
check("pwn is told that reading a Dockerfile is not running it",
      "READING the Dockerfile is not the same as RUNNING it" in pwn_prompt, True)
check("...with the measurement behind it, not just an assertion",
      bool(re.search(r"2 MiB-aligned 5/5", pwn_prompt)), True)

# ---------------------------------------------------------------------------
# 5. Form ↔ route parity, for EVERY module — not just pwn.
#
#    The box was added to the pwn form while `api/routes/pwn_module.py` had no
#    `docker_challenge` parameter. FastAPI silently drops form fields a
#    signature does not declare, so ticking it set nothing and the block stayed
#    a no-op: a checkbox that does nothing, which is exactly the "the UI says
#    one thing and the code does another" defect this whole change was about.
#    Checked across all modules so the next one to grow a box cannot repeat it.
# ---------------------------------------------------------------------------
import re as _re2

_html = (ROOT / "web-ui" / "index.html").read_text()
_with_box = set()
for _m in _re2.finditer(r'<section id="panel-(\w+)"', _html):
    _n = _m.group(1)
    _i = _m.start()
    _j = _html.find('<section id="panel-', _i + 1)
    if "docker_challenge" in _html[_i:_j if _j > 0 else len(_html)]:
        _with_box.add(_n)

_accepts = set()
for _p in sorted((ROOT / "api" / "routes").glob("*_module.py")):
    _src = _p.read_text()
    if "docker_challenge: bool = Form(" in _src and '"docker_challenge": docker_challenge' in _src:
        _accepts.add(_p.stem.replace("_module", ""))

check("every form offering the box has a route that accepts AND persists it",
      sorted(_with_box - _accepts), [])
check("...and pwn is one of them", "pwn" in _with_box and "pwn" in _accepts, True)

print(f"== summary: {PASSED} passed, {FAILED} failed =="
      + (f"  [stubbed: {', '.join(STUBBED)}]" if STUBBED else "  [all real deps]"))
_TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
