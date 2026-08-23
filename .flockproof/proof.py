"""Prove the park-inside-_worker_containers mechanism, standalone.

Mimics apply_cap's exact structure: flock -> _worker_containers -> caps read ->
budget decision -> write. State lives in a JSON file, standing in for the
authoritative dockerd state that `containers.list(all=True)` inspects fresh.
"""
import fcntl
import json
import os
import sys
from pathlib import Path

D = Path(os.environ["PROOF_DIR"])
LOCK = D / "lock"
STATE = D / "state.json"
BUDGET = 11_737_192_857          # the live 70% budget, measured
USE_LOCK = os.environ["USE_LOCK"] == "1"


def _worker_containers():        # <- the injection point (module global)
    return json.loads(STATE.read_text())


def apply_cap(me, want):
    with open(LOCK, "a+b") as lk:
        if USE_LOCK:
            fcntl.flock(lk.fileno(), fcntl.LOCK_EX)
        try:
            caps = _worker_containers()      # fresh read INSIDE the lock
            others = sum(v for k, v in caps.items() if k != me)
            if others + want > BUDGET:
                return {"applied": False, "others": others, "want": want}
            caps[me] = want
            STATE.write_text(json.dumps(caps))
            return {"applied": True, "others": others, "want": want}
        finally:
            if USE_LOCK:
                fcntl.flock(lk.fileno(), fcntl.LOCK_UN)


who, want = sys.argv[1], int(sys.argv[2])
if who == "A":                               # A parks after its snapshot
    _real = _worker_containers

    def _parking(_r=_real):
        slots = _r()
        (D / "A_READ").write_text("1")
        open(D / "go").read()                # unbounded blocking park on a FIFO
        return slots

    _worker_containers = _parking

res = apply_cap(who, want)
(D / ("res_%s" % who)).write_text(json.dumps(res))
