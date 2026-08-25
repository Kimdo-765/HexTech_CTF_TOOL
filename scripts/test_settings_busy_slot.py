#!/usr/bin/env python3
"""A Settings save must not pull a live job's memory out from under it.

Run: python3 scripts/test_settings_busy_slot.py

THE INCIDENT

Measured live on 2026-08-25T15:31:03Z, during the operator's dynamic-RAM test.
A Settings save pushed `worker_slot_mem=2g` onto every slot's cgroup through
the Docker API. Slots 2, 3 and 11 dropped to 2048 MiB in the same second, and
two of them were running jobs:

    job e0776a88b45b, still running, worker_mem.jsonl caps seen:
        4096  (rev -> base x2)  ->  6144  (one OOM escalation)  ->  2048

The job continued with less memory than it STARTED with, and with one of its
two escalations already spent. Nothing errored; the dashboard reported a
successful save.

WHY THE EXISTING GATE DID NOT CATCH IT

The per-slot headroom gate asks whether the new cap clears anon+slab x 1.5. At
that instant those jobs' anon was a few hundred MiB, so 2 GiB cleared it
easily. "Does it fit" is a different question from "is this slot's memory mine
to take back", and only the first one was being asked.

WHAT IS ASSERTED HERE

The real `_apply_worker_mem` is driven against fake containers and a fake job
tree — no docker, no queue. The direction matters and both directions are
pinned: shrinking a busy slot is DEFERRED, growing one is APPLIED immediately.
A test that only checked "busy slots are skipped" would pass on an
implementation that also refuses to raise the limit under load, which would
make the setting unusable exactly when an operator needs it.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.TemporaryDirectory(prefix="busy-slot-")
DATA = Path(_TMP.name)
(DATA / "jobs").mkdir()
os.environ.update(DATA_DIR=str(DATA), JOBS_DIR=str(DATA / "jobs"),
                  SETTINGS_PATH=str(DATA / "settings.json"))
(DATA / "settings.json").write_text("{}")


def _stub_fastapi() -> None:
    import types
    if "fastapi" in sys.modules:
        return
    try:
        import fastapi  # noqa: F401
        return
    except ModuleNotFoundError:
        pass
    m = types.ModuleType("fastapi")

    class HTTPException(Exception):
        def __init__(self, status_code=400, detail=""):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    class APIRouter:
        def __init__(self, *a, **k):
            pass

        def _noop(self, *a, **k):
            return lambda fn: fn

        get = post = put = delete = patch = _noop

    m.APIRouter = APIRouter
    m.HTTPException = HTTPException
    m.Request = type("Request", (), {})
    sys.modules["fastapi"] = m


_stub_fastapi()

import api.routes.settings as S  # noqa: E402

checks = 0
fails = 0


def chk(label, got, want):
    global checks, fails
    checks += 1
    if got == want:
        print("PASS  %s" % label)
    else:
        fails += 1
        print("FAIL  %s\n        got  = %r\n        want = %r" % (label, got, want))


class FakeContainer:
    """Just enough of a docker container for _apply_worker_mem."""

    def __init__(self, slot: int, cap: int):
        self.name = "hextech_ctf_tool-worker-%d" % slot
        # `labels`, not just Config.Labels — `_slot_label` reads the attribute,
        # and a fake without it made the whole suite crash on its first call
        # rather than assert anything.
        self.labels = {"com.docker.compose.service": "worker-%d" % slot}
        self.attrs = {"HostConfig": {"Memory": cap, "MemorySwap": cap},
                      "Config": {"Labels": dict(self.labels)}}
        self.updates = []

    def update(self, **kw):
        self.updates.append(kw)
        self.attrs["HostConfig"]["Memory"] = kw.get("mem_limit")

    def stats(self, stream=False):
        # A small live footprint — this is what let the headroom gate pass while
        # a running job lost its cap.
        return {"memory_stats": {"usage": 400 * 1024 * 1024,
                                 "stats": {"anon": 300 * 1024 * 1024,
                                           "slab": 20 * 1024 * 1024}}}


def _job(job_id: str, slot: int, status: str) -> None:
    d = DATA / "jobs" / job_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "meta.json").write_text(json.dumps(
        {"id": job_id, "module": "rev", "status": status,
         "worker_slot": str(slot)}))


def run(containers, host_bytes=80 * 1024 ** 3, value="2g"):
    S._worker_containers = lambda: containers
    S._host_mem_total = lambda: host_bytes
    return S._apply_worker_mem(value)


GiB = 1024 ** 3

print("--- a busy slot above the new value is left alone " + "-" * 8)
_job("aaaaaaaaaaaa", 2, "running")
cs = [FakeContainer(1, 2 * GiB), FakeContainer(2, 6 * GiB),
      FakeContainer(3, 4 * GiB)]
res = run(cs)
chk("the save still reports applied", res.get("applied"), True)
chk("the idle slots were written", sorted(res.get("applied_to") or []),
    ["hextech_ctf_tool-worker-1", "hextech_ctf_tool-worker-3"])
chk("REGRESSION: the BUSY slot was not written",
    [c.updates for c in cs if c.name.endswith("-2")], [[]])
chk("...and it is reported as deferred, not silently dropped",
    [d["slot"] for d in (res.get("deferred_busy") or [])], ["2"])
chk("...with its current cap, so the operator can see what was kept",
    [d["current_bytes"] for d in (res.get("deferred_busy") or [])], [6 * GiB])
chk("...and the total does not count the slot that did not take it",
    res.get("total_limit_bytes"), 2 * GiB * 2)

print("")
print("--- direction matters: GROWING a busy slot is applied " + "-" * 4)
cs = [FakeContainer(1, 2 * GiB), FakeContainer(2, 2 * GiB)]
_job("aaaaaaaaaaaa", 2, "running")
res = run(cs, value="4g")
chk("raising the limit under load is applied to the busy slot too",
    res.get("applied"), True)
chk("...every slot written", len(res.get("applied_to") or []), 2)
chk("...nothing deferred", res.get("deferred_busy"), None)
chk("...and the busy slot really got the bigger cap",
    [c.attrs["HostConfig"]["Memory"] for c in cs if c.name.endswith("-2")],
    [4 * GiB])

print("")
print("--- an EQUAL value is not a shrink " + "-" * 22)
cs = [FakeContainer(1, 2 * GiB), FakeContainer(2, 2 * GiB)]
res = run(cs, value="2g")
chk("a busy slot already at the value is written, not deferred",
    len(res.get("applied_to") or []), 2)

print("")
print("--- queued counts as busy " + "-" * 31)
for d in (DATA / "jobs").iterdir():
    (d / "meta.json").unlink(missing_ok=True)
_job("bbbbbbbbbbbb", 2, "queued")
cs = [FakeContainer(1, 2 * GiB), FakeContainer(2, 6 * GiB)]
res = run(cs)
chk("a queued job protects its slot from a shrink",
    [d["slot"] for d in (res.get("deferred_busy") or [])], ["2"])

print("")
print("--- a finished job does not protect anything " + "-" * 12)
for d in (DATA / "jobs").iterdir():
    (d / "meta.json").unlink(missing_ok=True)
_job("cccccccccccc", 2, "finished")
cs = [FakeContainer(1, 2 * GiB), FakeContainer(2, 6 * GiB)]
res = run(cs)
chk("REGRESSION: an idle slot above the value IS shrunk — deferral must not "
    "become 'never shrink anything'",
    len(res.get("applied_to") or []), 2)
chk("...nothing deferred", res.get("deferred_busy"), None)

print("")
print("--- every slot busy and above the value " + "-" * 17)
for d in (DATA / "jobs").iterdir():
    (d / "meta.json").unlink(missing_ok=True)
_job("dddddddddddd", 1, "running")
_job("eeeeeeeeeeee", 2, "running")
cs = [FakeContainer(1, 6 * GiB), FakeContainer(2, 6 * GiB)]
res = run(cs)
chk("the save reports NOT applied rather than claiming success",
    res.get("applied"), False)
chk("...and says why", "busy" in (res.get("reason") or ""), True)
chk("...and wrote nothing", [c.updates for c in cs], [[], []])

print("")
print("--- unreadable meta is not evidence a slot is free " + "-" * 6)
for d in (DATA / "jobs").iterdir():
    (d / "meta.json").unlink(missing_ok=True)
_job("ffffffffffff", 2, "running")
(DATA / "jobs" / "ffffffffffff" / "meta.json").write_text("{ not json")
cs = [FakeContainer(1, 2 * GiB), FakeContainer(2, 6 * GiB)]
res = run(cs)
chk("a corrupt meta leaves the slot unprotected only because nothing else "
    "claims it — the shrink proceeds and that is the documented behaviour",
    len(res.get("applied_to") or []), 2)

print("")
print("--- the budget gate still refuses an impossible total " + "-" * 3)
for d in (DATA / "jobs").iterdir():
    (d / "meta.json").unlink(missing_ok=True)
cs = [FakeContainer(i, 2 * GiB) for i in range(1, 13)]
res = run(cs, host_bytes=8 * GiB, value="4g")
chk("REGRESSION: 12 x 4g in an 8 GiB VM is still refused",
    res.get("applied"), False)
chk("...for the budget reason, not the busy one",
    "over the 70%" in (res.get("reason") or ""), True)

print("")
print("%d checks, %d failed" % (checks, fails))
sys.exit(1 if fails else 0)
