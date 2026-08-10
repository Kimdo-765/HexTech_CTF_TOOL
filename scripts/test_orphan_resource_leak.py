#!/usr/bin/env python3
"""Container removal takes its anonymous volumes with it, and a failed reap says so.

TWO LEAKS, MEASURED 2026-08-10.

`docker rm` keeps a container's anonymous volumes unless told otherwise, and
every removal site in this repo said `remove(force=True)`. 393 dangling
anonymous volumes had accumulated, 383 of them that same day. Named volumes and
bind mounts are unaffected by `v=True` — docker removes only volumes it created
for that container — so this is not a data-loss knob.

Separately, `_hard_stop_job` wrapped its whole container sweep in a bare
`except: pass`. A sweep that removed nothing because the daemon was unreachable
was indistinguishable from one that had nothing to remove. Container
609f3504b4d2 (runner, labelled job 9b8168b0ee29) outlived the deletion of its
own job, and nothing anywhere recorded that the reap had not happened.

Run:  python3 scripts/test_orphan_resource_leak.py [--mutate NAME]
"""

from __future__ import annotations

import argparse
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=(
    "none",
    "volume-leak",        # a removal site goes back to dropping its volumes
    "silent-daemon",      # docker unreachable stops being recorded
    "silent-container",   # a per-container remove failure stops being recorded
    "network-v",          # v=True wrongly applied to a network removal
), default="none")
args = parser.parse_args()

passed = failed = 0


def check(label, got, want=True):
    global passed, failed
    if got == want:
        passed += 1
    else:
        failed += 1
        print(f"FAIL  {label}\n      got  = {got!r}\n      want = {want!r}")


# ------------------------------------------------ ① every removal takes volumes
#
# Enumerated rather than spot-checked: the leak was uniform, so one site left
# behind keeps leaking at whatever rate that path runs.
SITES = [
    "api/routes/terminal.py",
    "api/routes/tunnel.py",
    "api/routes/containers.py",
    "api/routes/jobs.py",
    "modules/_runner.py",
    "modules/pwn/decompile.py",
    "modules/misc/orchestrator.py",
    "modules/forensic/orchestrator.py",
    "worker/misc_recarve.py",
    "modules/_common.py",
]
sources = {p: (ROOT / p).read_text(encoding="utf-8") for p in SITES}

if args.mutate == "volume-leak":
    sources["modules/_runner.py"] = sources["modules/_runner.py"].replace(
        "remove(force=True, v=True)", "remove(force=True)", 1)
elif args.mutate == "network-v":
    sources["modules/_common.py"] = sources["modules/_common.py"].replace(
        "n.remove()", "n.remove(v=True)", 1)

bare = []
for path, src in sources.items():
    for m in re.finditer(r"\.remove\(force=True(?P<rest>[^)]*)\)", src):
        if "v=True" not in m.group("rest"):
            bare.append(path)
check("no container removal drops its anonymous volumes", sorted(set(bare)), [])

total = sum(len(re.findall(r"\.remove\(force=True, v=True\)", s))
            for s in sources.values())
check("every known removal site is covered", total >= 13, True)

# A network has no anonymous volumes; `v=True` there is a TypeError at runtime,
# i.e. a cleanup that raises inside the sweep it was meant to complete.
net_bad = re.findall(r"\bn\.remove\(v=", sources["modules/_common.py"])
check("network removal is left alone", net_bad, [])


# ------------------------------------------------- ② a failed reap is recorded
#
# The function is exercised, not grepped: the failure mode was behavioural — it
# returned a plausible-looking dict while having done nothing.
if "fastapi" not in sys.modules:
    fastapi = types.ModuleType("fastapi")
    fastapi.APIRouter = lambda *a, **k: types.SimpleNamespace(
        get=lambda *a, **k: (lambda fn: fn),
        post=lambda *a, **k: (lambda fn: fn),
        delete=lambda *a, **k: (lambda fn: fn),
        put=lambda *a, **k: (lambda fn: fn),
        websocket=lambda *a, **k: (lambda fn: fn),
    )
    fastapi.HTTPException = type("HTTPException", (Exception,), {})
    fastapi.Query = lambda default=None, **k: default
    fastapi.Body = lambda default=None, **k: default
    fastapi.Request = object
    fastapi.UploadFile = object
    fastapi.File = lambda default=None: default
    fastapi.Form = lambda default=None: default
    sys.modules["fastapi"] = fastapi

src = (ROOT / "api" / "routes" / "jobs.py").read_text(encoding="utf-8")
if args.mutate == "silent-daemon":
    src = src.replace('info["docker_error"] = f"{type(e).__name__}: {e}"', "pass")
elif args.mutate == "silent-container":
    src = src.replace(
        'info["containers_failed"].append(f"{name}: {type(e).__name__}")', "pass")

# Only the reaper is needed; importing the whole route module would drag in the
# storage/queue stack for no benefit.
ns: dict = {}
start = src.index("def _hard_stop_job")
end = src.index("\n@router.get", start)
exec(compile(
    "def get_redis():\n    return None\n"
    "def _rq_id_candidates(j):\n    return [j]\n" + src[start:end],
    "jobs_reaper", "exec"), ns)
_hard_stop_job = ns["_hard_stop_job"]


class FakeContainer:
    def __init__(self, name, *, remove_raises=None):
        self.name = name
        self.id = name + "0" * 12
        self._raises = remove_raises
        self.removed_with_volumes = None

    def kill(self):
        raise RuntimeError("already exited")     # the normal case

    def remove(self, force=False, v=False):
        if self._raises:
            raise self._raises
        self.removed_with_volumes = v


def run_with(containers=None, list_raises=None):
    class _Containers:
        @staticmethod
        def list(all=False, filters=None):
            if list_raises:
                raise list_raises
            return containers or []

    fake_docker = types.ModuleType("docker")
    fake_docker.from_env = lambda: types.SimpleNamespace(containers=_Containers())
    sys.modules["docker"] = fake_docker
    try:
        return _hard_stop_job("abc123abc123")
    finally:
        sys.modules.pop("docker", None)


ok = FakeContainer("runner_ok")
r = run_with([ok])
check("a clean sweep reports what it removed", r["containers_killed"], 1)
check("...and how many it found", r["containers_found"], 1)
check("...and removes the container's anonymous volumes", ok.removed_with_volumes, True)
check("...with nothing recorded as failed", r["containers_failed"], [])
check("...and no daemon error", r["docker_error"], None)

bad = FakeContainer("runner_stuck", remove_raises=PermissionError("device busy"))
r = run_with([ok := FakeContainer("runner_ok2"), bad])
check("a container that will not go names itself",
      any("runner_stuck" in s for s in r["containers_failed"]), True)
check("...with the reason", any("PermissionError" in s for s in r["containers_failed"]), True)
check("...while its neighbours are still removed", r["containers_killed"], 1)
check("...and found still counts both", r["containers_found"], 2)

# The 609f3504b4d2 shape: the daemon was unreachable, so the sweep did nothing
# at all. Previously this returned containers_killed=0 with no way to tell it
# apart from "there was nothing to reap".
r = run_with(list_raises=ConnectionError("docker socket gone"))
check("an unreachable daemon is recorded, not swallowed",
      "ConnectionError" in (r["docker_error"] or ""), True)
check("...and is distinguishable from an empty sweep",
      (r["containers_killed"], r["containers_found"]), (0, 0))

r = run_with([])
check("an empty sweep says so without inventing an error",
      (r["containers_killed"], r["containers_found"], r["docker_error"]), (0, 0, None))

# Best-effort is the whole contract: this runs inside DELETE, and a cleanup that
# raises would take the deletion down with it.
try:
    run_with(list_raises=ConnectionError("x"))
    raised = False
except Exception:
    raised = True
check("the reaper still never raises", raised, False)

print(f"== summary: {passed} passed, {failed} failed; mutation={args.mutate} ==")
raise SystemExit(1 if failed else 0)
