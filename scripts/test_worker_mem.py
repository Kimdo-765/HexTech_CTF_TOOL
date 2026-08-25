#!/usr/bin/env python3
"""Regression tests for per-slot memory sampling and the dynamic cap flag.

Run: python3 scripts/test_worker_mem.py

These are deliberately behavioural. The first version of the worker wiring
compiled cleanly and passed a py_compile check while having moved the queue
setup after a `return`, i.e. the workers would have started nothing at all. A
test that only imports would not have caught it; the ordering test below would.
"""

import json
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.worker_mem as wm  # noqa: E402

GiB = 1024 ** 3
fails = 0
checks = 0


def chk(label, cond, got=None):
    global fails, checks
    checks += 1
    if cond:
        print("PASS  %s" % label)
    else:
        fails += 1
        print("FAIL  %s   got=%r" % (label, got))


# ---------------------------------------------------------------- parse_mem
chk("parse 4g", wm.parse_mem("4g") == 4 * GiB, wm.parse_mem("4g"))
chk("parse 4096m", wm.parse_mem("4096m") == 4 * GiB, wm.parse_mem("4096m"))
chk("parse bytes", wm.parse_mem("1048576") == 1048576, wm.parse_mem("1048576"))
chk("parse junk -> None", wm.parse_mem("4 gigs") is None, wm.parse_mem("4 gigs"))
chk("parse empty -> None", wm.parse_mem("") is None, wm.parse_mem(""))
chk("parse None -> None", wm.parse_mem(None) is None, wm.parse_mem(None))
chk("parse 0 -> None (a zero cap is 'unlimited', never a target)",
    wm.parse_mem("0") is None, wm.parse_mem("0"))


# ------------------------------------------------------------------- policy
class _Settings:
    """Stand in for settings_io without touching /data/settings.json."""

    def __init__(self, **vals):
        self.vals = vals

    def get_setting(self, key, *a, **k):
        return self.vals.get(key)


def _with_settings(**vals):
    import modules.settings_io as sio

    stub = _Settings(**vals)
    real = sio.get_setting
    sio.get_setting = stub.get_setting
    return real, sio


def _restore(real, sio):
    sio.get_setting = real


real, sio = _with_settings(worker_slot_mem="4g", dynamic_worker_mem=False)
try:
    chk("flag OFF: base is the setting", wm.base_cap_bytes() == 4 * GiB,
        wm.base_cap_bytes())
    chk("flag OFF: dynamic_enabled() is False", wm.dynamic_enabled() is False)
    for mod in ("rev", "crypto", "web", "pwn", "misc", "forensic", None):
        chk("flag OFF: %s gets the base, not an expansion" % mod,
            wm.desired_cap_bytes(mod) == 4 * GiB, wm.desired_cap_bytes(mod))
finally:
    _restore(real, sio)

real, sio = _with_settings(worker_slot_mem="4g", dynamic_worker_mem=True)
try:
    chk("flag ON: dynamic_enabled() is True", wm.dynamic_enabled() is True)
    # Pin the FACTOR to a literal. An earlier version asserted "expands to
    # 8 GiB" against a 4g base — true by coincidence, since 4 x 2 = 8, so it
    # would have survived a change to the factor. Replacing that with
    # `base * wm.EXPANSION_FACTOR` was no better: comparing the code against
    # itself passes for ANY value the constant takes. The constant is the thing
    # under test, so it has to face a number nobody derived from it.
    chk("EXPANSION_FACTOR is 2", wm.EXPANSION_FACTOR == 2, wm.EXPANSION_FACTOR)
    for mod in sorted(wm.EXPANSION_MODULES):
        chk("flag ON: %s expands from a 4g base to exactly 8 GiB" % mod,
            wm.desired_cap_bytes(mod) == 8 * GiB, wm.desired_cap_bytes(mod))
    # web left EXPANSION_MODULES on 2026-08-25. It is listed explicitly here,
    # not just absent from the set, so removing it from the frozenset without
    # meaning to would fail rather than silently widen the expansion again.
    chk("web is NOT an expansion module", "web" not in wm.EXPANSION_MODULES)
    for mod in ("web", "pwn", "misc", "forensic", "web3", None):
        chk("flag ON: %s still gets the base" % mod,
            wm.desired_cap_bytes(mod) == 4 * GiB, wm.desired_cap_bytes(mod))
    # pwn is excluded on evidence, not oversight: every pwn OOM in the 88-job
    # census was the QEMU guest or the target binary, neither of which is in
    # the slot's cgroup, so raising the slot cap would change nothing.
    chk("pwn is NOT an expansion module", "pwn" not in wm.EXPANSION_MODULES)
finally:
    _restore(real, sio)

real, sio = _with_settings(worker_slot_mem="8g", dynamic_worker_mem=True)
try:
    # The expansion is a MULTIPLE now, not a fixed 8 GiB floor, so it scales
    # with the base instead of being swallowed by it. Under the old floor an 8g
    # base made the expansion a no-op — rev asked for exactly what every other
    # module got — which is the case that motivated the change.
    chk("the expansion scales with the base rather than flattening at 8 GiB",
        wm.desired_cap_bytes("rev") == 8 * GiB * wm.EXPANSION_FACTOR,
        wm.desired_cap_bytes("rev"))
    chk("...and it never LOWERS the base",
        wm.desired_cap_bytes("rev") > 8 * GiB, wm.desired_cap_bytes("rev"))
    # A want this large will not survive `apply_cap`'s total-budget gate on a
    # small VM. That is deliberate and is asserted where the gate lives: this
    # function reports desire, not permission.
finally:
    _restore(real, sio)

# A small base must still produce a small expansion — the property the fixed
# 8 GiB floor did not have. This is the operator's actual configuration on
# 2026-08-25 (base 2g), where the old code gave rev 8 GiB regardless.
real, sio = _with_settings(worker_slot_mem="2g", dynamic_worker_mem=True)
try:
    chk("base 2g: rev expands to 4 GiB, not 8",
        wm.desired_cap_bytes("rev") == 4 * GiB, wm.desired_cap_bytes("rev"))
    chk("base 2g: crypto expands to 4 GiB",
        wm.desired_cap_bytes("crypto") == 4 * GiB, wm.desired_cap_bytes("crypto"))
    chk("base 2g: web stays at 2 GiB",
        wm.desired_cap_bytes("web") == 2 * GiB, wm.desired_cap_bytes("web"))
    chk("base 2g: pwn stays at 2 GiB",
        wm.desired_cap_bytes("pwn") == 2 * GiB, wm.desired_cap_bytes("pwn"))
finally:
    _restore(real, sio)

real, sio = _with_settings(worker_slot_mem=None, dynamic_worker_mem=True)
try:
    chk("no base configured -> no desired cap (never invent one)",
        wm.desired_cap_bytes("rev") is None, wm.desired_cap_bytes("rev"))
finally:
    _restore(real, sio)


# ------------------------------------------------------------------ sampler
tmp = pathlib.Path(tempfile.mkdtemp())
sample_file = tmp / "worker_mem.jsonl"
meta_file = tmp / "meta.json"
meta_file.write_text(json.dumps({"status": "running", "keep": "me"}))

seq = [
    {"ts": 1.0, "current": 100, "max": 4096, "peak": 100, "oom_kill": 7, "oom": 0},
    {"ts": 2.0, "current": 900, "max": 4096, "peak": 900, "oom_kill": 7, "oom": 0},
    {"ts": 3.0, "current": 400, "max": 4096, "peak": 900, "oom_kill": 9, "oom": 1},
]
calls = {"n": 0}


def fake_sample():
    i = min(calls["n"], len(seq) - 1)
    calls["n"] += 1
    return dict(seq[i])


real_sample = wm.sample
wm.sample = fake_sample
try:
    seen_oom = []
    s = wm.JobSampler("testjob", sample_file, on_oom=seen_oom.append,
                      interval_s=0.01)
    s.start()
    for _ in range(200):
        if s.oom_delta:
            break
        import time

        time.sleep(0.01)
    summary = s.stop()
finally:
    wm.sample = real_sample

chk("sampler tracked the peak, not the last value",
    summary["peak_bytes"] == 900, summary["peak_bytes"])
chk("sampler reported the oom_kill DELTA, not the absolute counter",
    summary["oom_kill_delta"] == 2, summary["oom_kill_delta"])
chk("on_oom fired", seen_oom == [2] or 2 in seen_oom, seen_oom)
chk("sampler wrote its own file", sample_file.exists())
rows = [json.loads(l) for l in sample_file.read_text().splitlines() if l.strip()]
chk("every sampled row is valid json", len(rows) >= 2, len(rows))
chk("first row marks the start", rows[0].get("event") == "start", rows[0].get("event"))
chk("last row marks the stop", rows[-1].get("event") == "stop", rows[-1].get("event"))

# The point of the dedicated file: write_meta is a read-modify-write with no
# lock (modules/_common.py), so a background thread must never be the one
# calling it.
chk("sampler NEVER touched meta.json",
    json.loads(meta_file.read_text()) == {"status": "running", "keep": "me"},
    meta_file.read_text())



# ---------------------------------------------------------------- escalator
# The operator's step 2: on a real OOM, raise this slot by 1.5x. These shipped
# as constants with no caller for one revision - defined, documented, and dead.
# The first assertion is the one that matters: with the flag OFF the escalator
# must not move a cgroup at all, because a feature that is "off" and still
# changes a cap is not off.
_applied: list = []


def _fake_apply(want, log=None):
    _applied.append(want)
    return {"applied": True}


_real_apply = wm.apply_cap
_real_readint = wm._read_int
wm.apply_cap = _fake_apply
wm._read_int = lambda name: (4 * GiB if name == "memory.max" else 0)

real, sio = _with_settings(worker_slot_mem="4g", dynamic_worker_mem=False)
try:
    _applied.clear()
    esc = wm.OomEscalator()
    esc(1)
    chk("flag OFF: an OOM does NOT escalate", _applied == [], _applied)
    chk("flag OFF: the escalation count stays 0", esc.count == 0, esc.count)
finally:
    _restore(real, sio)

real, sio = _with_settings(worker_slot_mem="4g", dynamic_worker_mem=True)
try:
    _applied.clear()
    esc = wm.OomEscalator()
    esc(1)
    chk("flag ON: the first OOM escalates by exactly 1.5x",
        _applied == [int(4 * GiB * 1.5)], _applied)
    esc(2)
    chk("flag ON: a second OOM escalates again", len(_applied) == 2, _applied)
    esc(3)
    esc(4)
    chk("flag ON: escalation stops at MAX_ESCALATIONS",
        len(_applied) == wm.MAX_ESCALATIONS, _applied)

    # a refused escalation must not be counted as one
    _applied.clear()
    wm.apply_cap = lambda want, log=None: {"applied": False, "reason": "refused"}
    esc2 = wm.OomEscalator()
    esc2(1)
    chk("a REFUSED escalation does not consume the budget of attempts",
        esc2.count == 0, esc2.count)
    wm.apply_cap = _fake_apply

    # no readable cap -> never guess one
    _applied.clear()
    wm._read_int = lambda name: None
    esc3 = wm.OomEscalator()
    esc3(1)
    chk("no readable memory.max -> no escalation, no invented number",
        _applied == [], _applied)
finally:
    _restore(real, sio)
    wm.apply_cap = _real_apply
    wm._read_int = _real_readint

# ----------------------------------------------- the absolute ceiling (base x4)
# MAX_ESCALATIONS does NOT bound the reachable maximum on its own: the ladder
# starts from the slot's CURRENT cap, and an expansion module already starts at
# base x EXPANSION_FACTOR. At base 2g that runs 4 -> 6 -> 9 GiB (base x 4.5),
# bounded only by the step count. These pin the ceiling against the BASE, so it
# stays true if the factor or the step count changes.
wm.apply_cap = _fake_apply
_real_readint = wm._read_int
try:
    real, sio = _with_settings(worker_slot_mem="2g", dynamic_worker_mem=True)
    try:
        # rev's second OOM: 6 GiB x 1.5 = 9 GiB, over the 8 GiB ceiling.
        _applied.clear()
        wm._read_int = lambda name: (6 * GiB if name == "memory.max" else 0)
        wm.OomEscalator()(1)
        # Literal, not `2 * GiB * wm.MAX_CAP_FACTOR` — the constant is what is
        # under test, and comparing it against itself would pass at any value.
        chk("MAX_CAP_FACTOR is 4", wm.MAX_CAP_FACTOR == 4, wm.MAX_CAP_FACTOR)
        chk("6 GiB x 1.5 = 9 GiB is CLAMPED to the 8 GiB ceiling",
            _applied == [8 * GiB], _applied)

        # already at the ceiling: do not escalate, and above all do not SHRINK
        # the slot that just ran out of memory.
        _applied.clear()
        wm._read_int = lambda name: (8 * GiB if name == "memory.max" else 0)
        esc = wm.OomEscalator()
        esc(1)
        chk("at the ceiling: no escalation at all", _applied == [], _applied)
        esc(2)
        chk("...and the ladder stays stopped on a repeat OOM",
            _applied == [], _applied)

        # a non-expansion module never reaches the ceiling, so it must be
        # untouched by it: 2 -> 3 GiB is a plain 1.5x.
        _applied.clear()
        wm._read_int = lambda name: (2 * GiB if name == "memory.max" else 0)
        wm.OomEscalator()(1)
        chk("below the ceiling the step is still a plain 1.5x",
            _applied == [int(2 * GiB * 1.5)], _applied)

        # the ceiling scales with the base, it is not a fixed byte count
        _applied.clear()
        wm._read_int = lambda name: (6 * GiB if name == "memory.max" else 0)
        real2, sio2 = _with_settings(worker_slot_mem="4g", dynamic_worker_mem=True)
        try:
            wm.OomEscalator()(1)
            chk("a 4g base lifts the ceiling to 16 GiB, so 9 GiB is unclamped",
                _applied == [int(6 * GiB * 1.5)], _applied)
        finally:
            _restore(real2, sio2)
    finally:
        _restore(real, sio)
finally:
    wm.apply_cap = _real_apply
    wm._read_int = _real_readint

# --------------------------------------- the runner matches its parent slot
# The runner is a SIBLING container: the daemon creates it outside the slot's
# cgroup, so its memory is charged to the VM and never to the slot. A fixed
# DEFAULT_MEM therefore drifted from the slot in both directions — slots at 8g
# still OOM'd a solver at 2g, and slots at 2g held a runner that outweighed its
# parent. Sliced from source: importing modules._runner drags in the docker SDK
# and the whole module tree.
import ast as _ast

_runner_src = (ROOT / "modules/_runner.py").read_text()
_rt = _ast.parse(_runner_src)
_fn = next((n for n in _rt.body
            if isinstance(n, _ast.FunctionDef) and n.name == "_parent_slot_mem"), None)
chk("_parent_slot_mem exists in modules/_runner.py", _fn is not None)
if _fn is not None:
    import typing as _typing
    _ns: dict = {"Optional": _typing.Optional}
    exec(compile(_ast.Module(body=[_fn], type_ignores=[]), "<s>", "exec"), _ns)
    _psm = _ns["_parent_slot_mem"]

    _real_readint = wm._read_int
    try:
        wm._read_int = lambda name: (3 * GiB if name == "memory.max" else 0)
        chk("the runner reads the slot's LIVE cap, not the setting",
            _psm() == 3 * GiB, _psm())
        # `memory.max` is the literal string `max` on an uncapped cgroup, which
        # _read_int cannot int() — the caller must fall back, never hand docker
        # an unlimited runner.
        wm._read_int = lambda name: None
        chk("an unreadable or uncapped cgroup yields None (caller falls back)",
            _psm() is None, _psm())
        wm._read_int = lambda name: 0
        chk("a zero cap is not treated as a real limit", _psm() is None, _psm())
    finally:
        wm._read_int = _real_readint

# and the wiring: the default must be None so the resolution above can happen,
# while explicit callers keep their own number.
chk("run_in_sandbox defaults mem_limit to None",
    "mem_limit: str | int | None = None" in _runner_src)
chk("...and resolves it from the parent slot when unset",
    "_parent = _parent_slot_mem()" in _runner_src
    and "mem_limit = _parent if _parent else DEFAULT_MEM" in _runner_src)
for _mod, _const in (("forensic/orchestrator.py", "FORENSIC_MEM"),
                     ("misc/orchestrator.py", "MISC_MEM"),
                     ("pwn/decompile.py", "DECOMPILER_MEM")):
    _src = (ROOT / "modules" / _mod).read_text()
    chk("%s still sizes its own runner (%s)" % (_mod, _const),
        "mem_limit=%s" % _const in _src)

# ------------------------------------------------- lifecycle ordering (fake)
# Prove the wrapper applies a cap BEFORE the job body and restores AFTER it,
# and that the restore still happens when the body raises - the SIGKILL case
# is precisely why the restore lives in the parent process.
class _FakeJob:
    args = ("job-abc",)
    func_name = "modules.rev.analyzer.run_job"


class _Base:
    def __init__(self):
        self.ran = False

    def execute_job(self, job, queue):
        _trace.append("body")
        self.ran = True
        return "done"


class _BaseRaises(_Base):
    def execute_job(self, job, queue):
        _trace.append("body")
        raise RuntimeError("boom")


import worker.runner as runner  # noqa: E402

_trace: list = []


def _install_fakes():
    _trace.clear()
    wm.base_cap_bytes = lambda: 4 * GiB
    wm.desired_cap_bytes = lambda m: (8 * GiB if m == "rev" else 4 * GiB)
    wm.apply_cap = lambda want, log=None: (_trace.append("apply:%d" % want)
                                           or {"applied": True})

    class _NoopSampler:
        def __init__(self, *a, **k):
            pass

        def start(self):
            _trace.append("sample:start")
            return self

        def stop(self):
            _trace.append("sample:stop")
            return {"peak_bytes": 1}

    wm.JobSampler = _NoopSampler


_real = (wm.base_cap_bytes, wm.desired_cap_bytes, wm.apply_cap, wm.JobSampler)
try:
    _install_fakes()
    K = runner._mem_aware_worker(_Base)
    out = K().execute_job(_FakeJob(), None)
    chk("the job body still runs and its return value is passed through",
        out == "done", out)
    chk("order: expand -> sample -> body -> sample stop -> restore",
        _trace == ["apply:%d" % (8 * GiB), "sample:start", "body",
                   "sample:stop", "apply:%d" % (4 * GiB)], _trace)

    _install_fakes()
    K = runner._mem_aware_worker(_BaseRaises)
    try:
        K().execute_job(_FakeJob(), None)
        chk("a raising body propagates", False, "no exception")
    except RuntimeError:
        chk("a raising body propagates", True)
    chk("restore still runs when the body raises",
        _trace[-1] == "apply:%d" % (4 * GiB), _trace)
finally:
    (wm.base_cap_bytes, wm.desired_cap_bytes, wm.apply_cap, wm.JobSampler) = _real

print("")
# Counted, never hardcoded. A literal total keeps printing the same
# number after a check is deleted, so the suite reports full coverage
# of checks it no longer runs.
print("%d checks, %d failed" % (checks, fails))
sys.exit(1 if fails else 0)
