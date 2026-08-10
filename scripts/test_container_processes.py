#!/usr/bin/env python3
"""Per-container process list: source selection, CPU semantics, and UI wiring.

The load-bearing property here is NOT "does it list processes" — it is WHICH
SOURCE is used for which container. `docker top` is answered by the daemon and
nothing inside the container participates. Reading /proc needs `exec`, which
runs a process inside an image we may not own and then parses whatever bytes
that image hands back. So the source is chosen by TRUST, and the mutations
below exist to make a future edit that widens exec fail loudly.

The second property is that the CPU column means what its label says. ps'
%CPU is a lifetime average — measured 2026-08-10, a process pinned at one full
core reported 34.4% because it had been idle earlier — so whenever that is the
source, the payload has to say so.

Run:  python3 scripts/test_container_processes.py [--mutate NAME]
"""

from __future__ import annotations

import argparse
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# The route module imports fastapi and api.storage at import time; neither is
# needed for the logic under test and neither is guaranteed on the host.
if "fastapi" not in sys.modules:
    fastapi = types.ModuleType("fastapi")

    class _HTTPException(Exception):
        def __init__(self, status_code, detail):
            self.status_code = status_code
            self.detail = detail
            super().__init__(detail)

    class _APIRouter:
        def get(self, *a, **k):
            return lambda fn: fn

        def delete(self, *a, **k):
            return lambda fn: fn

    fastapi.APIRouter = _APIRouter
    fastapi.HTTPException = _HTTPException
    fastapi.Query = lambda default=None, **k: default
    sys.modules["fastapi"] = fastapi

    concurrency = types.ModuleType("starlette.concurrency")

    async def _run_in_threadpool(fn, *a):
        return fn(*a)

    concurrency.run_in_threadpool = _run_in_threadpool
    starlette = types.ModuleType("starlette")
    starlette.concurrency = concurrency
    sys.modules.setdefault("starlette", starlette)
    sys.modules["starlette.concurrency"] = concurrency

if "api.storage" not in sys.modules:
    api_pkg = types.ModuleType("api")
    api_pkg.__path__ = []
    routes_pkg = types.ModuleType("api.routes")
    routes_pkg.__path__ = []
    storage = types.ModuleType("api.storage")
    storage.JOBS_DIR = Path("/data/jobs")
    sys.modules.setdefault("api", api_pkg)
    sys.modules.setdefault("api.routes", routes_pkg)
    sys.modules["api.storage"] = storage

import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "containers_mod", ROOT / "api" / "routes" / "containers.py")
cont = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cont)


parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=(
    "none",
    "exec-everything",     # trust boundary removed: exec into any container
    "avg-unlabelled",      # ps source stops declaring its CPU is a lifetime avg
    "new-proc-spike",      # a process with no baseline reports lifetime as now
    "no-fallback",         # exec failure propagates instead of degrading to ps
    "rss-sum-silent",      # per-process RSS sum no longer surfaced
    "always-clickable",    # UI offers a process panel on stopped containers
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


# --------------------------------------------------------------- mutations
if args.mutate == "exec-everything":
    _real_cat = cont._category
    cont._category = lambda c: "core"
elif args.mutate == "avg-unlabelled":
    _real_top = cont._procs_via_top
    def _unlabelled(c):
        out = _real_top(c)
        out["cpu_is_lifetime_avg"] = False
        return out
    cont._procs_via_top = _unlabelled
elif args.mutate == "new-proc-spike":
    _real_exec = cont._procs_via_exec
    def _spike(c, window):
        out = _real_exec(c, window)
        for p in out["processes"]:
            if p["new"]:
                p["cpu_pct"] = 999.0
        return out
    cont._procs_via_exec = _spike
elif args.mutate == "no-fallback":
    # Sever the degrade path at its seam: a core container whose exec fails has
    # nowhere to fall back to. Non-core containers still reach `top` normally,
    # so the failure points at the fallback rather than at the whole module.
    _real_top = cont._procs_via_top
    def _no_fallback(c):
        if cont._category(c) == "core":
            raise RuntimeError("fallback removed")
        return _real_top(c)
    cont._procs_via_top = _no_fallback
elif args.mutate == "rss-sum-silent":
    pass          # applied after _processes_sync runs, below


# ------------------------------------------------------------- fake daemon
#
# /proc/<pid>/stat with a comm that contains BOTH a space and a ")", which is
# legal and is the reason the parser splits on the LAST ")" rather than the
# first.
def stat_line(pid, ppid, utime, stime, rss_pages, threads=1, comm="python3"):
    tail = " ".join(str(x) for x in (
        ppid, 1, 1, 0, -1, 4194560, 0, 0, 0, 0,      # ppid..cmajflt
        utime, stime, 0, 0, 20, 0, threads, 0,        # utime..itrealvalue
        56398271, 91697152, rss_pages,                # starttime, vsize, rss
    ))
    return f"{pid}\t\t{pid} ({comm}) S {tail}"


def dump(rows, hz=100, page=4096):
    return "\n".join([str(hz), str(page)] + rows)


class FakeExecResult:
    def __init__(self, out, code=0):
        self.output = out.encode()
        self.exit_code = code


class FakeContainer:
    """Two /proc dumps served in order, plus a `docker top` table."""

    def __init__(self, name, *, status="running", labels=None, dumps=None,
                 top=None, exec_raises=None):
        self.name = name
        self.id = name + "0123456789abcdef"
        self.status = status
        # The SDK exposes labels as a property; `_labels()` reads exactly that,
        # and `_svc()` additionally requires the compose PROJECT label to match.
        self.labels = dict(labels or {})
        self.attrs = {"Config": {"Labels": self.labels},
                      "Created": "2026-08-10T00:00:00Z",
                      "Image": "sha256:deadbeef"}
        self._dumps = list(dumps or [])
        self._top = top
        self._exec_raises = exec_raises
        self.exec_calls = 0

    def exec_run(self, cmd):
        self.exec_calls += 1
        if self._exec_raises:
            raise self._exec_raises
        return FakeExecResult(self._dumps.pop(0) if self._dumps else "")

    def top(self, ps_args=""):
        return self._top

    def stats(self, stream=False):
        return {"memory_stats": {"usage": 67702784, "limit": 4294967296,
                                 "stats": {"anon": 50000000, "slab": 1000000}},
                "cpu_stats": {}, "precpu_stats": {}}


CORE_LABELS = {"com.docker.compose.service": "worker-1",
               "com.docker.compose.project": "hextech_ctf_tool"}
SANDBOX_LABELS = {"com.docker.compose.service": "decompiler",
                  "com.docker.compose.project": "hextech_ctf_tool",
                  "hextech_ctf_tool_job_id": "abc123abc123"}

TOP_TABLE = {
    "Titles": ["PID", "PPID", "USER", "%CPU", "%MEM", "RSS", "ELAPSED", "COMMAND"],
    "Processes": [
        ["411318", "411290", "root", "34.4", "0.1", "1928", "00:02", "sleep 600"],
        ["411400", "411318", "nobody", "0.3", "0.0", "512", "00:01", "./chal"],
    ],
}

# One 30%-of-a-core process (30 ticks of cpu across a 1.00 s window at 100 Hz)
# and one that only appears in the SECOND sample.
D1 = dump([stat_line(1, 0, 1000, 200, 2988, threads=2)])
D2 = dump([stat_line(1, 0, 1030, 200, 2988, threads=2),
           stat_line(9, 1, 5000, 0, 100, comm="new proc) x")])


_REGISTRY: dict = {}


class _FakeClient:
    class containers:
        @staticmethod
        def get(cid):
            if cid not in _REGISTRY:
                raise KeyError(cid)
            return _REGISTRY[cid]


# The route resolves a container by id through docker.from_env(); stubbing the
# client keeps `_processes_sync`'s real signature under test instead of adding
# a seam to production for the suite's convenience.
cont._client = lambda: _FakeClient()


def register(c):
    _REGISTRY[c.name] = c
    return c.name


def patched_clock():
    """time.time() advancing exactly 1.00 s per sample pair."""
    seq = iter([100.0, 101.0, 200.0, 201.0, 300.0, 301.0, 400.0, 401.0])
    return lambda: next(seq)


_real_time = cont.time.time
_real_sleep = cont.time.sleep
cont.time.sleep = lambda s: None
cont.time.time = patched_clock()

core = FakeContainer("worker-1", labels=CORE_LABELS, dumps=[D1, D2], top=TOP_TABLE)
r_core = cont._processes_sync(register(core), 1.0)

cont.time.time = patched_clock()
chal = FakeContainer("chal_x", labels={}, top=TOP_TABLE)
r_chal = cont._processes_sync(register(chal), 1.0)

cont.time.time = patched_clock()
sandbox = FakeContainer("dec_x", labels=SANDBOX_LABELS, top=TOP_TABLE)
r_sandbox = cont._processes_sync(register(sandbox), 1.0)

cont.time.time = patched_clock()
broken = FakeContainer("worker-2", labels=CORE_LABELS, top=TOP_TABLE,
                       exec_raises=OSError("no shell in image"))
try:
    r_broken = cont._processes_sync(register(broken), 1.0)
except Exception as exc:          # only reachable under --mutate no-fallback
    r_broken = {"_raised": f"{type(exc).__name__}: {exc}"}

cont.time.time = patched_clock()
stopped = FakeContainer("dead", status="exited", labels=CORE_LABELS)
r_stopped = cont._processes_sync(register(stopped), 1.0)

cont.time.time = _real_time
cont.time.sleep = _real_sleep

if args.mutate == "rss-sum-silent":
    for r in (r_core, r_chal, r_sandbox):
        r.pop("rss_sum", None)


# ------------------------------------------------- ① trust boundary (source)
check("core container is sampled from /proc", r_core.get("source"), "proc")
check("core container was exec'd exactly twice", core.exec_calls, 2)

check("challenge container uses docker top", r_chal.get("source"), "ps")
check("challenge container is NEVER exec'd", chal.exec_calls, 0)
check("sandbox container uses docker top", r_sandbox.get("source"), "ps")
# Our image, but the agent has root inside and runs challenge binaries there,
# so /bin/sh is not ours by the time we would call it.
check("sandbox container is NEVER exec'd", sandbox.exec_calls, 0)
check("the untrusted note names the category",
      "sandbox" in (r_sandbox.get("source_note") or ""), True)

# ------------------------------------------------------- ② CPU means its label
check("proc source does not claim a lifetime average",
      r_core.get("cpu_is_lifetime_avg"), False)
check("ps source DECLARES its CPU is a lifetime average",
      r_chal.get("cpu_is_lifetime_avg"), True)
check("ps source says so in words too",
      "WHOLE LIFE" in (r_chal.get("source_note") or ""), True)

by_pid = {p["pid"]: p for p in r_core["processes"]}
by_pid.setdefault(1, {})
by_pid.setdefault(9, {})
# 30 ticks / 100 Hz over 1.00 s = 30.0%.
check("delta CPU is computed from clock ticks over the window",
      by_pid[1].get("cpu_pct"), 30.0)
check("window is reported so the number can be read", r_core.get("window_s"), 1.0)
check("clk_tck comes from the container, not a constant",
      r_core.get("clk_tck"), 100)

# ------------------------------------- ③ a process with no baseline is unknown
check("a process that appeared mid-window is flagged new", by_pid[9].get("new"), True)
check("...and its CPU is unknown, not its lifetime total",
      by_pid[9].get("cpu_pct"), None)
check("an established process is not flagged new", by_pid[1].get("new"), False)

# ------------------------------------------------------------- ④ parsing
check("comm containing a space and ')' is parsed",
      by_pid[9].get("cmd"), "[new proc) x]")
check("rss is converted from pages to bytes", by_pid[1].get("rss"), 2988 * 4096)
check("thread count survives", by_pid[1].get("threads"), 2)
check("ppid survives", by_pid[1].get("ppid"), 0)

# ---------------------------------------------------------- ⑤ ps row shape
# A mutation must leave the suite RUNNABLE, so a row the mutation removed
# reads as a failed check rather than a KeyError that hides everything after it.
chal_pids = {p["pid"]: p for p in r_chal["processes"]}
_ps_a, _ps_b = chal_pids.get(411400, {}), chal_pids.get(411318, {})
check("ps rows carry the user column", _ps_a.get("user"), "nobody")
check("ps RSS is converted from KiB to bytes", _ps_b.get("rss"), 1928 * 1024)
check("ps rows have no thread count to invent", _ps_b.get("threads"), None)

# --------------------------------------------------- ⑥ degrade, never explode
check("a core container whose exec fails still answers",
      r_broken.get("source"), "ps")
check("...and records WHY it degraded",
      "no shell in image" in (r_broken.get("source_fallback") or ""), True)

# ------------------------------------------------------- ⑦ stopped container
check("a stopped container reports no processes", r_stopped.get("processes"), [])
check("...with a reason rather than an error",
      "not running" in (r_stopped.get("note") or ""), True)
check("...and is not exec'd", stopped.exec_calls, 0)

# ------------------------------- ⑧ the two memory numbers are both surfaced
check("per-process RSS is summed", r_core.get("rss_sum"), 2988 * 4096 + 100 * 4096)
check("the cgroup figure is carried alongside it", r_core.get("mem_usage"), 67702784)
check("the memory cap is carried so a share can be computed",
      r_core.get("mem_limit"), 4294967296)
# Two numbers that disagree and no reason is how a real measurement gets read
# as a bug — see the worker OOM that was chased on the wrong denominator.
check("the sum carries the reason it can exceed the cgroup",
      "shared" in (r_core.get("rss_sum_note") or ""), True)


# --------------------------------------------------------------------- UI
APP = (ROOT / "web-ui" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "web-ui" / "style.css").read_text(encoding="utf-8")
HTML = (ROOT / "web-ui" / "index.html").read_text(encoding="utf-8")

if args.mutate == "always-clickable":
    APP = APP.replace("const expandable = running;", "const expandable = true;")

check("the row is clickable only when the container is running",
      "const expandable = running;" in APP, True)
check("a detail row is emitted for an open container",
      'class="proc-detail"' in APP, True)
check("the detail row spans the whole table", 'colspan="9"' in APP, True)
check("the panel is fetched from the new endpoint",
      "/processes`" in APP, True)
check("clicking delete does not also toggle the panel",
      'ev.target.closest("button")' in APP, True)

# One-shot by design: the list poll already spends ~2 s on stats calls.
check("the detail is NOT wired into the 15s container poll",
      re.search(r"_containersPoll\s*=\s*setInterval[\s\S]{0,400}?loadProcesses", APP) is None, True)
check("the panel has its own refresh instead", "proc-refresh" in APP, True)
check("open panels survive a list re-render from cache",
      "_procOpen.forEach((id) => _paintProcPanel(id))" in APP, True)
check("CSS.escape is guarded like the other four call sites",
      APP.count("(window.CSS && CSS.escape)") >= 5, True)
check("the source badge is rendered", "proc-src--live" in APP and "proc-src--avg" in APP, True)
check("a lifetime-average source is styled as a caveat, not as normal",
      ".proc-src--avg" in CSS, True)
check("a long argv cannot push the numeric columns off screen",
      ".proc-cmd" in CSS and "text-overflow: ellipsis" in CSS, True)

# The buster is what makes a redeploy's app.js actually reach the browser.
import hashlib  # noqa: E402
_h = hashlib.sha256()
_h.update((ROOT / "web-ui" / "app.js").read_bytes())
_h.update((ROOT / "web-ui" / "style.css").read_bytes())
check("index.html's cache buster tracks the assets it ships",
      f"?v=a{_h.hexdigest()[:8]}" in HTML, True)

print(f"== summary: {passed} passed, {failed} failed; mutation={args.mutate} ==")
raise SystemExit(1 if failed else 0)
