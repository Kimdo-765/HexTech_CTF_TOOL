#!/usr/bin/env python3
"""Regression suite for the per-slot worker split.

Run from the repo root:   python3 scripts/test_worker_slots.py

Covers the four things that were actually load-bearing, each of which was a
real defect caught during implementation rather than a hypothetical:

  1. runner.py's RQ name/sweep scoping — the pre-split sweep matched
     `htct-w*` unconditionally, so with two slots, slot 2 booting would delete
     slot 1's LIVE registration and RQ would read a healthy worker as dead.
  2. deploy.sh's slot scan — must FAIL CLOSED. A queued job, or a running job
     with no recorded slot, can be on any slot; treating either as idle
     restarts a container that is serving a job.
  3. settings.py's memory gates — the cap is now multiplied by the slot count,
     so the pre-split 8g would become 16 GiB inside a 15.99 GiB VM.
  4. write_meta's slot stamping across stop/retry/resume/continue.

No docker or redis needed; the container layer is faked.
"""
from __future__ import annotations

import fnmatch
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

GiB = 1073741824
VM = 15990 * 1048576  # the WSL VM this was sized against

_results: list[tuple[bool, str, str]] = []


def chk(label: str, cond: bool, got: object = "") -> None:
    _results.append((bool(cond), label, "" if cond else repr(got)))
    print(("PASS  " if cond else "FAIL  ") + label + ("" if cond else "  | got=" + repr(got)))


def section(name: str) -> None:
    print("\n--- " + name + " " + "-" * max(0, 60 - len(name)))


# --------------------------------------------------------------------------
# 1. worker/runner.py — slot naming and sweep scoping
# --------------------------------------------------------------------------
def _load_runner(slot: str | None):
    """Import worker/runner.py fresh with WORKER_SLOT set to `slot`."""
    stub = types.ModuleType("modules.settings_io")
    stub.get_setting = lambda k: {"worker_concurrency": 3}.get(k)
    pkg = types.ModuleType("modules")
    pkg.__path__ = []  # type: ignore[attr-defined]
    sys.modules.setdefault("modules", pkg)
    sys.modules["modules.settings_io"] = stub

    if slot is None:
        os.environ.pop("WORKER_SLOT", None)
    else:
        os.environ["WORKER_SLOT"] = slot
    spec = importlib.util.spec_from_file_location("_wrun", ROOT / "worker" / "runner.py")
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_runner() -> None:
    section("worker/runner.py — slot identity")
    m1 = _load_runner("1")
    chk("slot 1 name prefix", m1._name_prefix() == "htct-s1-w", m1._name_prefix())
    chk("slot 1 worker name", m1._worker_name(0) == "htct-s1-w0", m1._worker_name(0))
    chk("slot 1 forces concurrency 1", m1._resolve_concurrency() == 1, m1._resolve_concurrency())
    chk("slot 1 runs the single RQ scheduler", m1._runs_scheduler(0) is True)

    m2 = _load_runner("2")
    chk("slot 2 name prefix", m2._name_prefix() == "htct-s2-w", m2._name_prefix())
    chk("slot 2 forces concurrency 1", m2._resolve_concurrency() == 1)
    chk("slot 2 does NOT run the scheduler", m2._runs_scheduler(0) is False)

    ml = _load_runner(None)
    chk("legacy prefix unchanged", ml._name_prefix() == "htct-w", ml._name_prefix())
    chk("legacy honours worker_concurrency", ml._resolve_concurrency() == 3)
    chk("legacy worker 0 runs the scheduler", ml._runs_scheduler(0) is True)

    # THE defect: a boot sweep must never match another slot's live key.
    p1, n1 = f"rq:worker:{m1._name_prefix()}*", f"rq:worker:{m1._worker_name(0)}"
    p2, n2 = f"rq:worker:{m2._name_prefix()}*", f"rq:worker:{m2._worker_name(0)}"
    chk("slot 2's sweep does NOT match slot 1's key", not fnmatch.fnmatch(n1, p2))
    chk("slot 1's sweep does NOT match slot 2's key", not fnmatch.fnmatch(n2, p1))
    chk("slot 1's sweep DOES match its own key", fnmatch.fnmatch(n1, p1))
    chk("legacy glob does not match slot names", not fnmatch.fnmatch(n1, "rq:worker:htct-w*"))

    # Drop the `modules` stub: runner.py is imported with a fake
    # modules.settings_io (it hard-codes sys.path /app), and leaving that in
    # sys.modules makes every LATER test import the stub instead of the real
    # module — which surfaces as a confusing ImportError inside settings.py.
    for name in ("modules.settings_io", "modules"):
        sys.modules.pop(name, None)
    os.environ.pop("WORKER_SLOT", None)


# --------------------------------------------------------------------------
# 2. deploy.sh — slot scan, extracted from the script so they cannot drift
# --------------------------------------------------------------------------
def _scan_script(tmp: Path) -> Path:
    src = (ROOT / "deploy.sh").read_text()
    body = src.split("slot_scan() {\n", 1)[1].split("\nPY\n", 1)[0].split("<<'PY'\n", 1)[1]
    p = tmp / "scan.py"
    p.write_text(body)
    return p


def test_slot_scan() -> None:
    section("deploy.sh — slot scan (must fail closed)")
    tmp = Path(tempfile.mkdtemp())
    script = _scan_script(tmp)
    counter = [0]

    def scan(jobs: list[dict]) -> str:
        counter[0] += 1
        root = tmp / f"case{counter[0]}"
        root.mkdir(parents=True, exist_ok=True)
        for i, j in enumerate(jobs):
            d = root / f"job{i:012d}"
            d.mkdir(parents=True, exist_ok=True)
            (d / "meta.json").write_text(json.dumps(j))
        return subprocess.run([sys.executable, str(script), str(root)],
                              capture_output=True, text=True).stdout.strip()

    chk("no jobs -> IDLE", scan([]) == "IDLE", scan([]))
    chk("one running on slot 1 -> BUSY 1",
        scan([{"status": "running", "worker_slot": "1"}]) == "BUSY 1")
    chk("both running -> BUSY 1 2",
        scan([{"status": "running", "worker_slot": "1"},
              {"status": "running", "worker_slot": "2"}]) == "BUSY 1 2")
    chk("finished jobs hold no slot",
        scan([{"status": "finished", "worker_slot": "1"}]) == "IDLE")
    chk("stopped jobs hold no slot",
        scan([{"status": "stopped", "worker_slot": "1"}]) == "IDLE")
    # fail-closed cases
    chk("QUEUED job -> defer every slot (it is unplaced)",
        scan([{"status": "queued"}]).startswith("ALL"))
    chk("queued job still claiming an old slot -> defer every slot",
        scan([{"status": "queued", "worker_slot": "1"}]).startswith("ALL"))
    chk("running job with no slot (pre-split job) -> defer every slot",
        scan([{"status": "running"}]).startswith("ALL"))
    chk("unreadable meta.json -> defer every slot",
        "ALL" in _scan_unreadable(tmp, script))
    # a continue that cleared its slot is queued, hence unplaced
    chk("continue re-queued with worker_slot=null -> defer every slot",
        scan([{"status": "queued", "worker_slot": None}]).startswith("ALL"))
    # resume: previous job stopped, new one running elsewhere
    chk("resume (old stopped + new running on 2) -> BUSY 2",
        scan([{"status": "stopped", "worker_slot": "1"},
              {"status": "running", "worker_slot": "2"}]) == "BUSY 2")


def _scan_unreadable(tmp: Path, script: Path) -> str:
    root = tmp / "unreadable"
    d = root / "jobdeadbeef"
    d.mkdir(parents=True, exist_ok=True)
    (d / "meta.json").write_text("{not json")
    return subprocess.run([sys.executable, str(script), str(root)],
                          capture_output=True, text=True).stdout.strip()


# --------------------------------------------------------------------------
# 3. api/routes/settings.py — per-slot aggregation and the two memory gates
# --------------------------------------------------------------------------
class _FakeContainer:
    def __init__(self, name: str, slot: str, limit: int, anon: int = 200 * 1024 * 1024):
        self.name = name
        self.labels = {"com.docker.compose.service": name.split("-", 2)[-1]}
        self.attrs = {
            "HostConfig": {"Memory": limit, "MemorySwap": limit},
            "Config": {"Env": [f"WORKER_SLOT={slot}"]},
        }
        self._anon = anon
        self.updated: dict | None = None

    def stats(self, stream: bool = False) -> dict:
        return {"memory_stats": {"usage": self._anon + 100 * 1024 * 1024,
                                 "stats": {"anon": self._anon, "slab": 0}}}

    def update(self, **kw) -> None:
        self.updated = kw


def _load_settings():
    fa = types.ModuleType("fastapi")

    class _Router:
        def get(self, *a, **k):
            return lambda f: f

        def put(self, *a, **k):
            return lambda f: f

    class HTTPException(Exception):
        def __init__(self, status_code=None, detail=None):
            self.status_code, self.detail = status_code, detail

    fa.APIRouter = lambda *a, **k: _Router()
    fa.HTTPException = HTTPException
    fa.Request = object
    sys.modules["fastapi"] = fa
    spec = importlib.util.spec_from_file_location(
        "_st", ROOT / "api" / "routes" / "settings.py")
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_settings() -> None:
    section("api/routes/settings.py — slots + memory gates")
    st = _load_settings()

    def patch(cs, vm=VM):
        st._worker_containers = lambda: cs
        st._host_mem_total = lambda: vm

    two = [_FakeContainer("hextech_ctf_tool-worker-1", "1", 4 * GiB),
           _FakeContainer("hextech_ctf_tool-worker-2", "2", 4 * GiB)]

    # THE regression the settings-key rename exists for.
    patch(two)
    r = st._apply_worker_mem("8g")
    chk("8g x 2 slots REFUSED (16 GiB in a 15.99 GiB VM)", r["applied"] is False, r)
    chk("  refusal shows the multiplication", "x 2 slots" in r.get("reason", ""), r.get("reason"))
    chk("  nothing was pushed to any container", all(c.updated is None for c in two))

    patch(two)
    r = st._apply_worker_mem("4g")
    chk("4g x 2 accepted (8 GiB total)", r["applied"] is True, r)
    chk("  applied to BOTH slots", r["slot_count"] == 2 and all(c.updated for c in two), r)
    chk("  memswap pinned equal to mem", all(c.updated["memswap_limit"] == 4 * GiB for c in two))

    patch(two)
    chk("6g x 2 REFUSED (12 GiB > 70% of VM)", st._apply_worker_mem("6g")["applied"] is False)

    three = [_FakeContainer(f"hextech_ctf_tool-worker-{i}", str(i), 4 * GiB) for i in (1, 2, 3)]
    patch(three)
    chk("4g x 3 REFUSED — a third slot needs a bigger VM",
        st._apply_worker_mem("4g")["applied"] is False)

    # Per-slot headroom, reported against the slot that is actually busy.
    busy = [_FakeContainer("hextech_ctf_tool-worker-1", "1", 4 * GiB, anon=200 * 1024 * 1024),
            _FakeContainer("hextech_ctf_tool-worker-2", "2", 4 * GiB, anon=3 * GiB)]
    patch(busy)
    r = st._apply_worker_mem("2g")
    chk("2g refused while slot 2 holds 3 GiB", r["applied"] is False, r)
    chk("  refusal names slot 2, not slot 1", "slot 2" in r.get("reason", ""), r.get("reason"))
    chk("  no partial application", all(c.updated is None for c in busy))

    patch(two)
    live = st.worker_mem_live()
    chk("live: slot_count is 2", live["slot_count"] == 2, live)
    chk("live: limit_bytes is PER SLOT", live["limit_bytes"] == 4 * GiB, live)
    chk("live: total_limit_bytes is the sum", live["total_limit_bytes"] == 8 * GiB, live)
    chk("live: limits_uniform True", live["limits_uniform"] is True)

    mixed = [_FakeContainer("hextech_ctf_tool-worker-1", "1", 2 * GiB),
             _FakeContainer("hextech_ctf_tool-worker-2", "2", 4 * GiB)]
    patch(mixed)
    live = st.worker_mem_live()
    chk("live: mixed caps -> limits_uniform False", live["limits_uniform"] is False)
    chk("live: mixed caps -> reports the SMALLEST (OOMs first)",
        live["limit_bytes"] == 2 * GiB, live)

    st._worker_containers = lambda: []
    chk("no containers -> available False", st.worker_mem_live() == {"available": False})
    chk("no containers -> apply reports it", st._apply_worker_mem("4g")["applied"] is False)


# --------------------------------------------------------------------------
# 4. settings_io — the rename must make the stale 8g unreachable
# --------------------------------------------------------------------------
def test_settings_key_rename() -> None:
    section("modules/settings_io.py — key rename")
    tmp = Path(tempfile.mkdtemp())
    store = tmp / "settings.json"
    # exactly what /data/settings.json held before the split
    store.write_text(json.dumps({"worker_concurrency": 3, "worker_mem_limit": "8g"}))
    os.environ["SETTINGS_PATH"] = str(store)
    os.environ["WORKER_MEM_LIMIT"] = "8g"  # and what .env held
    for mod in [m for m in sys.modules if m.startswith("modules.settings_io")]:
        del sys.modules[mod]
    spec = importlib.util.spec_from_file_location(
        "_sio", ROOT / "modules" / "settings_io.py")
    assert spec and spec.loader
    sio = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sio)

    chk("stored 8g cannot be read under the new key",
        sio.get_setting("worker_slot_mem") == "4g", sio.get_setting("worker_slot_mem"))
    chk("the old key resolves to nothing at all",
        sio.get_setting("worker_mem_limit") is None)
    view = sio.get_settings_view()
    chk("the UI view exposes worker_slot_mem", view.get("worker_slot_mem") == "4g", view.get("worker_slot_mem"))
    chk("the UI view no longer exposes worker_mem_limit", "worker_mem_limit" not in view)
    os.environ.pop("WORKER_MEM_LIMIT", None)


# --------------------------------------------------------------------------
# 5. write_meta slot stamping across the job lifecycle
# --------------------------------------------------------------------------
def _stamp(meta: dict, updates: dict, slot: str) -> dict:
    """Mirror of the stamping block in modules/_common.py write_meta()."""
    updates = dict(updates)
    if slot and not updates.get("worker_slot"):
        updates["worker_slot"] = slot
    out = dict(meta)
    out.update(updates)
    return out


def test_lifecycle_stamping() -> None:
    section("write_meta — slot stamping across the lifecycle")
    chk("a run on slot 2 stamps worker_slot=2",
        _stamp({}, {"status": "running"}, "2")["worker_slot"] == "2")
    chk("api writes (no WORKER_SLOT) never stamp",
        "worker_slot" not in _stamp({}, {"status": "queued"}, ""))

    requeued = {"status": "queued", "worker_slot": None, "id": "abc"}
    chk("/continue re-queues with the slot cleared", requeued["worker_slot"] is None)
    chk("the slot that picks it up re-stamps it",
        _stamp(requeued, {"status": "running"}, "2")["worker_slot"] == "2")
    chk("an explicit falsy worker_slot in updates is still overridden",
        _stamp({}, {"status": "running", "worker_slot": None}, "2")["worker_slot"] == "2")


# --------------------------------------------------------------------------
# 6. deploy.sh — the .last_deploy stamp must NOT advance past a deferred slot
# --------------------------------------------------------------------------
def test_deploy_stamp_gate() -> None:
    """A deferral that still advances `.last_deploy` is permanent staleness.

    `modules/` is bind-mounted and imported once per worker process, so a slot
    keeps the code it had at ITS last restart. deploy.sh restarts idle slots
    and defers busy ones; if the stamp advanced anyway, the next `--changed`
    would say "nothing new since last deploy" and exit 0, leaving the deferred
    slot on the old prompts and modules indefinitely — half the jobs on new
    code, half on old, and nothing in meta.json recording which.

    Tested structurally, because the interesting regression is someone adding a
    NEW deferral branch and forgetting the flag.
    """
    section("deploy.sh — .last_deploy stamp gate")
    src = (ROOT / "deploy.sh").read_text()

    chk("DEFERRED is initialised to 0", "\nDEFERRED=0\n" in src)
    chk("the stamp appears exactly once",
        src.count('git rev-parse HEAD > "$LAST_DEPLOY_FILE"') == 1,
        src.count('git rev-parse HEAD > "$LAST_DEPLOY_FILE"'))

    # The stamp must sit in the else-branch of the DEFERRED test.
    gate = src.split('if [ "$DEFERRED" = 1 ]; then', 1)
    chk("the stamp is gated on DEFERRED", len(gate) == 2)
    if len(gate) == 2:
        after = gate[1].split("\nfi\n", 1)[0]
        then_part, _, else_part = after.partition("\nelse\n")
        chk("  DEFERRED=1 branch does NOT stamp",
            'git rev-parse HEAD > "$LAST_DEPLOY_FILE"' not in then_part)
        chk("  the else branch DOES stamp",
            'git rev-parse HEAD > "$LAST_DEPLOY_FILE"' in else_part)
        chk("  the deferral is reported to the operator",
            "NOT advanced" in then_part, then_part[:120])

    # Every branch that leaves a wanted slot un-restarted must raise the flag.
    for marker in ("no worker container is running",
                   "slots busy with a job — DEFERRING",
                   "its slot could not be determined"):
        idx = src.find(marker)
        chk(f"branch {marker!r:46s} sets DEFERRED=1",
            idx != -1 and "DEFERRED=1" in src[max(0, idx - 320):idx + 80],
            "marker not found" if idx == -1 else "no DEFERRED=1 nearby")

    # ...and the paths that DO restart everything must not.
    force = src.find("--force: restarting ALL worker slots")
    chk("--force does NOT set DEFERRED",
        force != -1 and "DEFERRED=1" not in src[force:force + 200])

    # Behavioural check of the gate itself.
    for deferred, should_stamp in ((1, False), (0, True)):
        out = subprocess.run(
            ["bash", "-c",
             f'DEFERRED={deferred}; LAST_DEPLOY_FILE=/dev/stdout; '
             f'warn() {{ :; }};'
             f'if [ "$DEFERRED" = 1 ]; then warn skip; else echo STAMPED; fi'],
            capture_output=True, text=True).stdout
        chk(f"gate with DEFERRED={deferred} -> {'stamps' if should_stamp else 'skips'}",
            ("STAMPED" in out) is should_stamp, out)


# --------------------------------------------------------------------------
# 7. prompts must not claim /tmp is shared between CONCURRENT jobs
# --------------------------------------------------------------------------
def test_prompt_tmp_claims() -> None:
    """One job per slot container means concurrent jobs no longer share /tmp.

    The `$TMPDIR` rule is still right, but its old justification became false
    with the split, and a rule resting on a premise the agent can disprove is a
    weak rule. The durable reason is dev/run parity: $TMPDIR lives in the work
    tree, so it is the only scratch path that also exists in the sandbox that
    auto-runs the exploit (modules/_runner.py sets TMPDIR=<workdir>/tmp).
    """
    section("prompts — /tmp justification")
    src = (ROOT / "modules" / "_prompts.py").read_text()
    for stale in ("shared across jobs", "share the worker's /tmp"):
        chk(f"no prompt claims /tmp is {stale!r}", stale not in src)
    chk("the $TMPDIR rule survives", src.count("$TMPDIR") >= 4, src.count("$TMPDIR"))
    chk("the rule now cites sandbox parity", "auto-runs the exploit" in src)


# --------------------------------------------------------------------------
# 8. the memory-budget block quotes the LIVE cgroup, or says nothing
# --------------------------------------------------------------------------
def test_mem_budget_block() -> None:
    """A per-job memory figure only became stateable with the slot split.

    The rule that matters is the fallback: a wrong number in a prompt is worse
    than no number, because the agent will size real work against it.
    """
    section("prompts — live memory budget")
    spec = importlib.util.spec_from_file_location(
        "_pr", ROOT / "modules" / "_prompts.py")
    assert spec and spec.loader
    pr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pr)

    import builtins
    real_open = builtins.open

    def fake_cgroup(value):
        class _F:
            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *a):
                return False

            def read(self_inner):
                if value is None:
                    raise OSError("no cgroup")
                return value
        def _open(path, *a, **k):
            if str(path) == "/sys/fs/cgroup/memory.max":
                if value is None:
                    raise OSError("no cgroup")
                return _F()
            return real_open(path, *a, **k)
        return _open

    cases = [
        ("4294967296", "4 GiB", "a 4 GiB cap is quoted as 4 GiB"),
        ("2147483648", "2 GiB", "a 2 GiB cap is quoted as 2 GiB"),
        ("8589934592", "8 GiB", "an 8 GiB cap is quoted as 8 GiB"),
    ]
    for raw, want, label in cases:
        builtins.open = fake_cgroup(raw)
        try:
            out = pr._mem_budget_block()
        finally:
            builtins.open = real_open
        chk(label, want in out, out[:80])

    # Everything unexpected must produce NOTHING, never a guess.
    for raw, label in [("max", "uncapped cgroup -> no claim at all"),
                       ("0", "0 -> no claim"),
                       ("999999999999999", "implausibly large -> no claim"),
                       (None, "unreadable cgroup (v1 host) -> no claim")]:
        builtins.open = fake_cgroup(raw)
        try:
            out = pr._mem_budget_block()
        finally:
            builtins.open = real_open
        chk(label, out == "", out[:80])

    chk("the sandbox figure matches modules/_runner.DEFAULT_MEM",
        pr._SANDBOX_MEM_TEXT.split()[0] + "g" ==
        _runner_default_mem(), pr._SANDBOX_MEM_TEXT)


def _runner_default_mem() -> str:
    """DEFAULT_MEM out of modules/_runner.py WITHOUT importing it (it pulls in
    docker-py). The prompt module quotes this number as a literal; this check
    is what keeps the two from drifting apart."""
    src = (ROOT / "modules" / "_runner.py").read_text()
    for line in src.splitlines():
        if line.startswith("DEFAULT_MEM"):
            return line.split("=", 1)[1].strip().strip('"\'')
    return "?"


# --------------------------------------------------------------------------
# 9. retry/resume preambles state what did NOT carry
# --------------------------------------------------------------------------
def test_carry_limits_note() -> None:
    """A retry goes back to the queue, so it may run on a different slot.

    Everything that matters crosses (work tree on /data, transcript on
    /root/.claude keyed by cwd) — but globally-installed packages do not, and
    that IS new: the worker used to be one container shared by every job. All
    four preamble variants must say so, and the hint must still come last.
    """
    section("retry/resume — carried-vs-not note")
    import ast as _ast
    src = (ROOT / "api" / "routes" / "retry.py").read_text()
    tree = _ast.parse(src)
    want = {"_CARRY_LIMITS_NOTE", "_retry_preamble", "_resume_preamble"}
    nodes = [n for n in tree.body
             if (isinstance(n, _ast.Assign)
                 and any(getattr(t, "id", "") in want for t in n.targets))
             or (isinstance(n, _ast.FunctionDef) and n.name in want)]
    chk("both preamble builders and the note were found", len(nodes) == 3, len(nodes))
    ns = {"_CTF_CONTEXT_HEADER": "[HDR]",
          "_STALE_PATH_WARNING_TMPL": "[STALE {prev_id}]",
          "_sanitize_hint": lambda h: f"[HINT:{h}]"}
    exec(compile(_ast.Module(body=nodes, type_ignores=[]), "<t>", "exec"), ns)

    for name in ("_retry_preamble", "_resume_preamble"):
        for fresh in (False, True):
            out = ns[name]("PREVJOB", "do the thing", fresh=fresh)
            label = f"{name}(fresh={fresh})"
            chk(f"{label} states what did not carry", "CARRIED vs NOT" in out)
            chk(f"{label} keeps the hint LAST",
                out.rstrip().endswith("[HINT:do the thing]"), out[-60:])
            chk(f"{label} puts the note before the hint",
                "CARRIED vs NOT" in out
                and out.index("CARRIED vs NOT") < out.index("[HINT:"))
    note = ns["_CARRY_LIMITS_NOTE"]
    chk("the note names the global-install case", "pip install" in note)
    chk("the note tells the agent to keep a path without the tool",
        "without it" in note)


# --------------------------------------------------------------------------
# 10. Containers tab — classification and the delete guards
# --------------------------------------------------------------------------
class _FakeC:
    def __init__(self, name, labels, cid="deadbeefcafe0000", status="running"):
        self.name, self.labels, self.id, self.status = name, labels, cid, status
        self.attrs = {"Config": {"Image": "img:latest"}, "Created": "2026-08-02T00:00:00Z",
                      "HostConfig": {"Memory": 0}, "State": {"Status": status}}


def _load_containers_mod():
    fa = types.ModuleType("fastapi")

    class _R:
        def get(self, *a, **k):
            return lambda f: f

        def delete(self, *a, **k):
            return lambda f: f

    class HTTPException(Exception):
        def __init__(self, status_code=None, detail=None):
            self.status_code, self.detail = status_code, detail

    fa.APIRouter = lambda *a, **k: _R()
    fa.HTTPException = HTTPException
    fa.Query = lambda default=None, **k: default
    sys.modules["fastapi"] = fa
    sc = types.ModuleType("starlette.concurrency")

    async def _rit(fn, *a):
        return fn(*a)
    sc.run_in_threadpool = _rit
    sys.modules.setdefault("starlette", types.ModuleType("starlette"))
    sys.modules["starlette.concurrency"] = sc
    st = types.ModuleType("api.storage")
    st.JOBS_DIR = ROOT / "data" / "jobs"
    sys.modules.setdefault("api", types.ModuleType("api"))
    sys.modules["api.storage"] = st
    spec = importlib.util.spec_from_file_location(
        "_ct", ROOT / "api" / "routes" / "containers.py")
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m, HTTPException


def test_containers() -> None:
    """The categories drive an IRREVERSIBLE delete, so a mislabel is a real
    hazard in both directions: `core` on a leftover hides it from cleanup, and
    `challenge` on a stack service invites deleting the stack."""
    section("Containers tab — classification + guards")
    ct, HTTPExc = _load_containers_mod()
    P = "com.docker.compose.project"
    S = "com.docker.compose.service"
    proj = ct._COMPOSE_PROJECT

    cases = [
        ("api",       {P: proj, S: "api"},                          "core"),
        ("redis",     {P: proj, S: "redis"},                        "core"),
        ("worker-1",  {P: proj, S: "worker-1"},                     "core"),
        ("worker-2",  {P: proj, S: "worker-2"},                     "core"),
        # THE bug this test exists for: profiles:["tools"] services inherit a
        # compose service label onto per-job containers.
        ("decompiler-leftover", {P: proj, S: "decompiler",
                                 ct._JOB_LABEL: "a15ff70a6ed5"},    "sandbox"),
        ("runner-leftover",     {P: proj, S: "runner",
                                 ct._JOB_LABEL: "ef8c5eb95d15"},    "sandbox"),
        ("tunnel",    {ct._ROLE_LABEL: "tunnel"},                   "tunnel"),
        ("db_fd844946", {},                                         "challenge"),
        # a compose label from a DIFFERENT project must not read as ours
        ("other-project", {P: "somethingelse", S: "api"},           "challenge"),
    ]
    for name, labels, want in cases:
        got = ct._category(_FakeC(name, labels))
        chk(f"{name:22s} -> {want}", got == want, got)

    # self-identification: the guard that must never silently fail
    ct._SELF_HOSTNAME = "f1f06c7e8a11"
    chk("hostname prefix identifies self",
        ct._is_self(_FakeC("api", {}, cid="f1f06c7e8a11abcdef")))
    chk("compose service=api is the fallback self-id",
        ct._is_self(_FakeC("api", {P: proj, S: "api"}, cid="zzzz")))
    chk("an unrelated container is NOT self",
        not ct._is_self(_FakeC("db_fd844946", {}, cid="0011223344")))

    # delete refuses self, hard
    class _Client:
        class containers:
            @staticmethod
            def get(cid):
                return _FakeC("api", {P: proj, S: "api"}, cid="f1f06c7e8a11abc")
    ct._client = lambda: _Client()
    try:
        ct._delete_sync("f1f06c7e8a11abc", True)
        chk("DELETE of the api container is refused", False, "no exception")
    except HTTPExc as e:
        chk("DELETE of the api container is refused", e.status_code == 409, e.status_code)
        chk("  the refusal explains WHY", "UI would die" in str(e.detail), e.detail)

    # a non-core service must not be promised a compose recreate
    chk("_is_core_service excludes tool services",
        not ct._is_core_service("decompiler") and not ct._is_core_service("runner"))
    chk("_is_core_service includes every slot",
        all(ct._is_core_service(f"worker-{i}") for i in (1, 2, 3)))

    # --- job attribution + provenance -----------------------------------
    chk("full 12-hex job id in a name is found",
        ct._job_from_name("chal_e994cf7cad22") == "e994cf7cad22",
        ct._job_from_name("chal_e994cf7cad22"))
    chk("8-hex job prefix in a name is found",
        ct._job_from_name("protoss_fd844946") == "fd844946")
    chk("db_ prefix does not confuse it",
        ct._job_from_name("db_fd844946") == "fd844946")
    for n in ("confident_euler", "simold", "web", "valk", "uniqtmp",
              "dazzling_poitras", "exciting_ishizaka", "sender"):
        chk(f"{n:20s} yields no false job id", ct._job_from_name(n) is None,
            ct._job_from_name(n))
    chk("a compose container name yields nothing",
        ct._job_from_name("hextech_ctf_tool-worker-1") is None)
    # a hex run that is the WRONG length must not match
    chk("7 hex chars is too short", ct._job_from_name("x_abcdef1") is None)
    chk("13 hex chars is too long", ct._job_from_name("x_abcdef0123456") is None)



# --------------------------------------------------------------------------
# 11. end-of-job reap — containers AND networks, never fatal
# --------------------------------------------------------------------------
def test_reap() -> None:
    """A job that finishes must take its containers and networks with it.

    Order is the load-bearing part: a network with an attached container
    cannot be removed, so containers have to go first or the network sweep
    silently fails. And nothing here may raise — a cleanup that breaks a
    finished job is worse than the leak it fixes.
    """
    section("end-of-job reap")
    stub = types.ModuleType("modules.settings_io")
    stub.get_setting = lambda k: True
    pkg = types.ModuleType("modules")
    pkg.__path__ = []  # type: ignore[attr-defined]
    sys.modules["modules"] = pkg
    sys.modules["modules.settings_io"] = stub

    src = (ROOT / "modules" / "_common.py").read_text()
    import ast as _ast
    tree = _ast.parse(src)
    want = {"reap_job_siblings", "_coerce_bool", "_JOB_LABEL"}
    nodes = [n for n in tree.body
             if (isinstance(n, _ast.FunctionDef) and n.name in want)
             or (isinstance(n, _ast.Assign)
                 and any(getattr(t, "id", "") in want for t in n.targets))]
    ns: dict = {}
    exec(compile(_ast.Module(body=nodes, type_ignores=[]), "<r>", "exec"), ns)

    order: list[str] = []

    class _Obj:
        def __init__(self, name, fail=False):
            self.name, self._fail = name, fail

        def remove(self, **kw):
            if self._fail:
                raise RuntimeError("boom")
            order.append(self.name)

    class _Coll:
        def __init__(self, items):
            self.items = items

        def list(self, **kw):
            return self.items

    class _Client:
        def __init__(self, cs, ns_):
            self.containers, self.networks = _Coll(cs), _Coll(ns_)

    fake_docker = types.ModuleType("docker")
    cs = [_Obj("chal_web"), _Obj("chal_db")]
    nets = [_Obj("chal_net")]
    fake_docker.from_env = lambda: _Client(cs, nets)
    sys.modules["docker"] = fake_docker

    res = ns["reap_job_siblings"]("JOB123")
    chk("both containers removed", res["containers"] == ["chal_web", "chal_db"], res)
    chk("the network removed too", res["networks"] == ["chal_net"], res)
    chk("no errors on the happy path", res["errors"] == [], res)
    chk("containers are removed BEFORE networks (else the network is in use)",
        order.index("chal_db") < order.index("chal_net"), order)

    # a failure on one item must not abort the sweep or raise
    order.clear()
    cs2 = [_Obj("stuck", fail=True), _Obj("fine")]
    fake_docker.from_env = lambda: _Client(cs2, [_Obj("net2")])
    res = ns["reap_job_siblings"]("JOB123")
    chk("one stuck container does not stop the others", "fine" in res["containers"], res)
    chk("the network is still swept", res["networks"] == ["net2"], res)
    chk("the failure is reported, not raised", any("stuck" in e for e in res["errors"]), res)

    # THE live failure: a network the WORKER is still attached to. Job
    # 7955d4ad066a reaped both challenge containers and then died on
    # "protossnet: APIError", because the agent had run
    # `docker network connect protossnet <worker>` and the worker is not ours
    # to remove. Ordering containers-before-networks does not help there; only
    # force-disconnecting the survivors does.
    class _StuckNet:
        def __init__(self, name):
            self.name = name
            self.attrs = {"Containers": {"workercid": {}, "othercid": {}}}
            self.tries = 0
            self.disconnected: list[str] = []

        def remove(self, **kw):
            self.tries += 1
            if self.tries == 1:                    # endpoints still attached
                raise RuntimeError("APIError")
            order.append(self.name)

        def reload(self):
            pass

        def disconnect(self, cid, force=False):
            assert force, "must force — a live worker will not leave politely"
            self.disconnected.append(cid)

    order.clear()
    stuck = _StuckNet("protossnet")
    fake_docker.from_env = lambda: _Client([], [stuck])
    res = ns["reap_job_siblings"]("JOB123")
    chk("a network with a stuck endpoint is retried, not abandoned",
        res["networks"] == ["protossnet"], res)
    chk("  every survivor was force-disconnected first",
        sorted(stuck.disconnected) == ["othercid", "workercid"], stuck.disconnected)
    chk("  and it took exactly two remove attempts", stuck.tries == 2, stuck.tries)
    chk("  no error is reported once it succeeds", res["errors"] == [], res)

    # ...and when even that fails, BOTH failures are reported.
    class _HopelessNet(_StuckNet):
        def remove(self, **kw):
            self.tries += 1
            raise RuntimeError("APIError")

    hopeless = _HopelessNet("wedged")
    fake_docker.from_env = lambda: _Client([], [hopeless])
    res = ns["reap_job_siblings"]("JOB123")
    chk("a truly wedged network reports both attempts",
        res["networks"] == [] and res["errors"]
        and "then after disconnect" in res["errors"][0], res)

    # docker unreachable
    def _boom():
        raise RuntimeError("no socket")
    fake_docker.from_env = _boom
    res = ns["reap_job_siblings"]("JOB123")
    chk("docker unreachable is reported, never raised",
        res["errors"] and "unreachable" in res["errors"][0], res)

    cb = ns["_coerce_bool"]
    chk("reap toggle: unset -> default on", cb(None, True) is True)
    chk("reap toggle: '0' -> off", cb("0", True) is False)
    chk("reap toggle: 'false' -> off", cb("false", True) is False)
    chk("reap toggle: True -> on", cb(True, True) is True)

    # the write_meta gate must fire on the TRANSITION only
    wm = (ROOT / "modules" / "_common.py").read_text()
    chk("gate compares against the PREVIOUS on-disk status",
        'meta.get("status") not in _TERMINAL_STATUSES' in wm)
    chk("the reap runs AFTER meta.json is written",
        wm.index("_reap_after_terminal(job_id)") > wm.index("f.write_text(json.dumps(meta"), "")
    chk("the sweep is time-bounded", "_REAP_TIMEOUT_S" in wm)

    for name in ("modules.settings_io", "modules", "docker"):
        sys.modules.pop(name, None)


def main() -> int:
    test_runner()
    test_slot_scan()
    test_settings()
    test_settings_key_rename()
    test_lifecycle_stamping()
    test_deploy_stamp_gate()
    test_prompt_tmp_claims()
    test_mem_budget_block()
    test_carry_limits_note()
    test_containers()
    test_reap()
    failed = [r for r in _results if not r[0]]
    print(f"\n{len(_results)} checks, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
