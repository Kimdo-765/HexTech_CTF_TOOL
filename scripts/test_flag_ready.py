#!/usr/bin/env python3
"""`flag_ready` — the status that asks the operator instead of guessing.

A run that recorded flag candidates but promoted none is not the same event as
a run that found nothing, and both used to be filed as `no_flag`. Job
f24519394073 is the case that forced this: the remote returned a real flag with
exit 0, the reproduction run was blocked, the candidate was recorded, and the
job read as a plain miss until a human went looking. `flag_ready` holds that
job open for a verdict.

Two halves have to stay in step and neither is enforced by types:

  * `flag_ready` is TERMINAL for the worker — monitor stops, finished_at is
    stamped, the SSE stream closes, usage counts. Nine sets say so separately.
  * `flag_ready` is NOT terminal for the operator — bulk-delete's safe
    defaults must leave it alone, or a job awaiting a verdict is swept away
    before anyone can give one.

Get one of those wrong and the failure is silent in both directions: a poll
that never stops, or a reaped job. The first section below pins every site.

The verdict endpoint is driven directly rather than through a TestClient: the
route is an async function taking (job_id, Request), and a duck-typed Request
exercises the real body-parsing and error paths without a server.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.TemporaryDirectory(prefix="flag-ready-")
DATA = Path(_TMP.name)
(DATA / "jobs").mkdir()
SETTINGS = DATA / "settings.json"
SETTINGS.write_text(json.dumps({"agent_provider": "claude"}))
os.environ.update(
    DATA_DIR=str(DATA),
    SETTINGS_PATH=str(SETTINGS),
    JOBS_DIR=str(DATA / "jobs"),
)

def _stub_fastapi() -> None:
    """Let this file run on a host without the API's serving dependencies.

    `api/routes/jobs.py` is the module under test; fastapi is only its
    transport. Stubbing the three names it imports keeps the REAL route body —
    validation, status transitions, meta writes — on the code path, which is
    the part with the defects. `HTTPException` must be a real exception class
    carrying `status_code`, because the adversarial section asserts on those
    codes and a lenient stub would turn every refusal into a silent pass.
    """
    import types

    if "fastapi" in sys.modules:
        return
    try:
        import fastapi  # noqa: F401
        return
    except ModuleNotFoundError:
        pass

    mod = types.ModuleType("fastapi")

    class HTTPException(Exception):
        def __init__(self, status_code: int, detail: str = ""):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    class APIRouter:
        def __init__(self, *a, **k):
            pass

        def _noop(self, *a, **k):
            def deco(fn):
                return fn
            return deco

        get = post = put = delete = patch = _noop

    class Request:  # only ever duck-typed by the tests
        pass

    class UploadFile:
        pass

    def File(*a, **k):
        return None

    def Form(*a, **k):
        return None

    def Query(*a, **k):
        return None

    def Body(*a, **k):
        return None

    def Depends(*a, **k):
        return None

    mod.APIRouter = APIRouter
    mod.HTTPException = HTTPException
    mod.Request = Request
    mod.UploadFile = UploadFile
    mod.File = File
    mod.Form = Form
    mod.Query = Query
    mod.Body = Body
    mod.Depends = Depends
    sys.modules["fastapi"] = mod

    resp = types.ModuleType("fastapi.responses")

    class _Resp:
        def __init__(self, *a, **k):
            pass

    resp.PlainTextResponse = _Resp
    resp.JSONResponse = _Resp
    resp.StreamingResponse = _Resp
    resp.FileResponse = _Resp
    resp.HTMLResponse = _Resp
    resp.Response = _Resp
    sys.modules["fastapi.responses"] = resp
    mod.responses = resp


def _stub_queue() -> None:
    """`api.queue` reaches for redis/rq at import. The verdict route touches
    neither — it reads meta and writes meta — so a stub keeps the import graph
    satisfiable without pretending to test the queue."""
    import types

    for name in ("redis", "rq"):
        if name in sys.modules:
            continue
        try:
            __import__(name)
            continue
        except ModuleNotFoundError:
            pass
        m = types.ModuleType(name)

        class _AnyMeta(type):
            # Class-level attribute access has to answer too: api/queue.py
            # calls `Redis.from_url(...)` at import, on the CLASS.
            def __getattr__(cls, _n):
                return lambda *a, **k: cls()

        class _Any(metaclass=_AnyMeta):
            def __init__(self, *a, **k):
                pass

            def __getattr__(self, _n):
                return _Any()

            def __call__(self, *a, **k):
                return _Any()

        m.Redis = _Any
        m.Queue = _Any
        m.from_url = lambda *a, **k: _Any()
        sys.modules[name] = m
        if name == "rq":
            jm = types.ModuleType("rq.job")
            jm.Job = _Any
            sys.modules["rq.job"] = jm
            m.job = jm


_stub_fastapi()
_stub_queue()

PASSED = 0
FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


# ---------------------------------------------------------------------------
# 1. The terminal split. Every set that means "the run is over" must include
#    flag_ready; the one that means "safe to bulk delete" must not.
# ---------------------------------------------------------------------------
print("--- the terminal split -------------------------------------")

import modules._common as C  # noqa: E402
import modules._monitor as MON  # noqa: E402
import api.storage as ST  # noqa: E402
from modules.hybrid import coordinator as HC  # noqa: E402
import api.routes.jobs as JR  # noqa: E402

TERMINAL_SETS = [
    ("modules._common._TERMINAL_STATUSES", C._TERMINAL_STATUSES),
    ("modules._monitor._TERMINAL", MON._TERMINAL),
    ("api.storage._TERMINAL_STATUSES", ST._TERMINAL_STATUSES),
    ("api.routes.jobs._USAGE_TERMINAL_STATUSES", JR._USAGE_TERMINAL_STATUSES),
    ("api.routes.jobs._TERMINAL_META_STATUSES", JR._TERMINAL_META_STATUSES),
    ("hybrid.coordinator.TERMINAL_STATUSES", HC.TERMINAL_STATUSES),
]
for name, s in TERMINAL_SETS:
    check(f"REGRESSION: {name} treats flag_ready as run-over", "flag_ready" in s, True)

# forensic/misc pull in `anyio`, which the host running this file need not
# have. Read their literal instead of importing them — a source read still
# catches the drift this section exists to catch, and a skipped check would
# not. Asserting the line was FOUND is what stops a rename from turning this
# into a silent pass.
for _mod in ("forensic", "misc"):
    _src = (ROOT / "modules" / _mod / "orchestrator.py").read_text()
    _l = next(
        (l for l in _src.splitlines() if l.startswith("_TERMINAL_STATUSES")), ""
    )
    check(f"  ...{_mod}.orchestrator too", "flag_ready" in _l, True)
    check(f"  ...and {_mod}'s set was actually located", bool(_l), True)

# The counter-half. Read the literal out of the source rather than importing a
# local — it is defined inside the bulk-delete handler, and a test that cannot
# see it is a test that cannot notice it drifting.
_bulk = (ROOT / "api" / "routes" / "jobs.py").read_text()
_line = next(
    (l for l in _bulk.splitlines() if "safe_default_statuses" in l and "{" in l), ""
)
check(
    "REGRESSION: bulk-delete's safe defaults do NOT sweep a job awaiting a verdict",
    "flag_ready" in _line,
    False,
)
check("  ...and that line was actually found", bool(_line), True)

# ---------------------------------------------------------------------------
# 2. no_flag_status — the only place that decides which of the two it is.
# ---------------------------------------------------------------------------
print("\n--- choosing between flag_ready and no_flag ----------------")


def make_job(label: str, **meta) -> str:
    """Create a job under a REAL id shape.

    `_validate_job_id` requires 12 hex chars and rejects anything else — a
    guard added after a path-traversal audit. Feeding it readable labels would
    make every route call 400 before reaching the code under test, so derive a
    stable id from the label instead of weakening the guard.
    """
    import hashlib

    job_id = hashlib.md5(label.encode()).hexdigest()[:12]
    d = DATA / "jobs" / job_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "meta.json").write_text(json.dumps({"id": job_id, **meta}))
    return job_id


check(
    "candidates recorded -> flag_ready",
    C.no_flag_status(make_job("fr1", flag_candidates=["DH{x}"])),
    "flag_ready",
)
check(
    "nothing to adjudicate -> no_flag",
    C.no_flag_status(make_job("fr2", flag_candidates=[])),
    "no_flag",
)
check(
    "the key absent entirely -> no_flag",
    C.no_flag_status(make_job("fr3")),
    "no_flag",
)
check(
    "null candidates -> no_flag",
    C.no_flag_status(make_job("fr4", flag_candidates=None)),
    "no_flag",
)
check(
    "REGRESSION: a list of empty strings is not something to ask about",
    C.no_flag_status(make_job("fr5", flag_candidates=["", None])),
    "no_flag",
)
check(
    "an unreadable job falls back to no_flag, never to a stuck verdict",
    C.no_flag_status("does-not-exist-at-all"),
    "no_flag",
)

# ---------------------------------------------------------------------------
# 3. The verdict endpoint.
# ---------------------------------------------------------------------------
print("\n--- the operator's verdict ---------------------------------")

from fastapi import HTTPException  # noqa: E402


class Req:
    """Duck-typed Request: the route only ever awaits .json()."""

    def __init__(self, body, raise_on_parse=False):
        self._body = body
        self._raise = raise_on_parse

    async def json(self):
        if self._raise:
            raise ValueError("not json")
        return self._body


def verdict(job_id, body, raise_on_parse=False):
    return asyncio.run(JR.flag_verdict(job_id, Req(body, raise_on_parse)))


def verdict_err(job_id, body, raise_on_parse=False):
    try:
        verdict(job_id, body, raise_on_parse)
    except HTTPException as e:
        return e.status_code
    return None


j = make_job("v1", status="flag_ready", flag_candidates=["DH{real}"], flags=[])
out = verdict(j, {"verdict": "ok"})
check("ok promotes the candidate", out["flags"], ["DH{real}"])
check("...and finishes the job", out["status"], "finished")
check("...and meta agrees", (C.read_meta(j) or {}).get("status"), "finished")
check("...and does not ask for a retry", out["retry_suggested"], False)

j = make_job("v2", status="flag_ready", flag_candidates=["DH{decoy}"], flags=[])
out = verdict(j, {"verdict": "wrong"})
check("wrong files it as a miss", out["status"], "no_flag")
check("...promotes nothing", out["flags"], [])
check("...remembers the refused value", out["rejected"], ["DH{decoy}"])
check("...and asks for a retry", out["retry_suggested"], True)

# The A3 half: a job that finished on its own, ruled wrong afterwards.
j = make_job("v3", status="finished", flags=["DH{wrong_answer}"])
out = verdict(j, {"verdict": "wrong"})
check("REGRESSION: a finished job can be demoted by a later verdict", out["status"], "no_flag")
check("  ...the flag is taken back out", (C.read_meta(j) or {}).get("flags"), [])
check("  ...and recorded as refused", out["rejected"], ["DH{wrong_answer}"])

# ---------------------------------------------------------------------------
# 4. Adversarial. Every one of these is a way the operator's click could put
#    the job into a state nobody intended.
# ---------------------------------------------------------------------------
print("\n--- adversarial --------------------------------------------")

check(
    "a verdict on a job that does not exist is 404, not a written meta",
    verdict_err("beefbeefbeef", {"verdict": "ok"}),
    404,
)
check(
    "a garbage verdict is refused",
    verdict_err(make_job("a1", status="flag_ready", flag_candidates=["x"]),
                {"verdict": "maybe"}),
    400,
)
check(
    "an empty body is refused, not defaulted to ok",
    verdict_err(make_job("a2", status="flag_ready", flag_candidates=["x"]), {}),
    400,
)
check(
    "a body that is not JSON at all is refused",
    verdict_err(make_job("a3", status="flag_ready", flag_candidates=["x"]),
                None, raise_on_parse=True),
    400,
)
check(
    "REGRESSION: a RUNNING job cannot be adjudicated out from under the worker",
    verdict_err(make_job("a4", status="running", flag_candidates=["x"]),
                {"verdict": "ok"}),
    409,
)
check(
    "  ...queued likewise",
    verdict_err(make_job("a5", status="queued"), {"verdict": "wrong"}),
    409,
)
check(
    "REGRESSION: ok with nothing to confirm cannot invent a flag",
    verdict_err(make_job("a6", status="flag_ready", flag_candidates=[], flags=[]),
                {"verdict": "ok"}),
    409,
)

# A double click. The second must not duplicate the flag list or resurrect a
# rejected value — the UI can and does fire twice on a slow network.
j = make_job("a7", status="flag_ready", flag_candidates=["DH{once}"], flags=[])
verdict(j, {"verdict": "ok"})
out = verdict(j, {"verdict": "ok"})
check("REGRESSION: clicking ok twice is idempotent", out["flags"], ["DH{once}"])
check("  ...and meta holds one copy", (C.read_meta(j) or {}).get("flags"), ["DH{once}"])

j = make_job("a8", status="flag_ready", flag_candidates=["DH{no}"], flags=[])
verdict(j, {"verdict": "wrong"})
out = verdict(j, {"verdict": "wrong"})
check("REGRESSION: clicking wrong twice does not duplicate the rejection",
      out["rejected"], ["DH{no}"])

# Changing one's mind: wrong, then ok. The candidate is still on disk, so ok
# has something to promote — but the refusal must not be forgotten, or the
# record stops showing that this value was once ruled out.
j = make_job("a9", status="flag_ready", flag_candidates=["DH{maybe}"], flags=[])
verdict(j, {"verdict": "wrong"})
out = verdict(j, {"verdict": "ok"})
check("wrong then ok promotes the candidate", out["flags"], ["DH{maybe}"])
check("  ...and the earlier refusal is still on the record",
      (C.read_meta(j) or {}).get("flag_rejected"), ["DH{maybe}"])

# result.json must not be able to resurrect a demoted flag.
j = make_job("a10", status="finished", flags=["DH{gone}"])
(DATA / "jobs" / j / "result.json").write_text(json.dumps({"flags": ["DH{gone}"]}))
verdict(j, {"verdict": "wrong"})
_rj = json.loads((DATA / "jobs" / j / "result.json").read_text())
check("REGRESSION: result.json is demoted in step with meta", _rj["flags"], [])

# A malformed result.json must not cost the operator their verdict.
j = make_job("a11", status="flag_ready", flag_candidates=["DH{ok}"], flags=[])
(DATA / "jobs" / j / "result.json").write_text("{ this is not json")
out = verdict(j, {"verdict": "ok"})
check("REGRESSION: a broken result.json does not lose the verdict",
      (C.read_meta(j) or {}).get("status"), "finished")

# A verdict on a plain no_flag job (no candidates) — reachable from the UI if
# the operator opens an old job. ok must refuse; wrong is a no-op that still
# records the judgement.
check(
    "ok on a plain no_flag job has nothing to promote",
    verdict_err(make_job("a12", status="no_flag"), {"verdict": "ok"}),
    409,
)

print(f"\n== summary: {PASSED} passed, {FAILED} failed ==")
raise SystemExit(1 if FAILED else 0)
