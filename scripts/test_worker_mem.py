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


def chk(label, cond, got=None):
    global fails
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
    for mod in sorted(wm.EXPANSION_MODULES):
        chk("flag ON: %s expands to 8 GiB" % mod,
            wm.desired_cap_bytes(mod) == 8 * GiB, wm.desired_cap_bytes(mod))
    for mod in ("pwn", "misc", "forensic", "web3", None):
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
    chk("flag ON never LOWERS a base that is already above the expansion",
        wm.desired_cap_bytes("rev") == 8 * GiB, wm.desired_cap_bytes("rev"))
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
print("%d checks, %d failed" % (44 + len(wm.EXPANSION_MODULES), fails))
sys.exit(1 if fails else 0)
