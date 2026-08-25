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

    The surface below is installed unconditionally — an installed FastAPI is
    never preferred. It used to be, and that made the file's outcome depend on
    what pip had done to the host rather than on what the code says: the routes
    this suite execs declare `Form(...)`, so a FastAPI without python-multipart
    raises at import and the whole file aborts before the first check, while a
    host with no FastAPI at all passes 90/0 on the same bytes. Nothing here
    asserts real FastAPI semantics — the verdict endpoint is driven by a
    duck-typed Request, never a TestClient — so the installed package decided
    whether the file ran without contributing to what it proved.
    """
    import types

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
    class _Streaming(_Resp):
        """Keeps the body generator so the SSE endpoints can be driven."""

        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.body_iterator = a[0] if a else None

    resp.StreamingResponse = _Streaming
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


def _stub_pydantic() -> None:
    """exploits.py declares request models with pydantic; the gate under test
    uses none of them. Stub just enough for the import to land."""
    import types

    if "pydantic" in sys.modules:
        return
    try:
        import pydantic  # noqa: F401
        return
    except ModuleNotFoundError:
        pass
    m = types.ModuleType("pydantic")

    class BaseModel:
        def __init__(self, **kw):
            for k, v in kw.items():
                setattr(self, k, v)

    def Field(*a, **k):
        return None

    m.BaseModel = BaseModel
    m.Field = Field
    m.ValidationError = type("ValidationError", (Exception,), {})
    sys.modules["pydantic"] = m


def _stub_sdk() -> None:
    """Stub claude_agent_sdk only when it is genuinely absent.

    Borrowed from scripts/test_retry_provider_snapshot.py, including the part
    that matters: `find_spec`, not `name not in sys.modules`. The latter is
    true at startup even in a container that HAS the library, so it would
    install a stub over a working install and this suite would never once
    exercise the real import path.

    `api.routes.retry` binds the SDK at module scope for the reviewer turn.
    That path is not under test here; the child-meta builder is. Treating the
    import as a wall was wrong — a harness for exactly this already existed in
    this repo and I did not look for it.
    """
    import importlib.util
    import types

    try:
        if importlib.util.find_spec("claude_agent_sdk") is not None:
            return
    except (ImportError, ValueError):
        pass
    if "claude_agent_sdk" in sys.modules:
        return

    sdk = types.ModuleType("claude_agent_sdk")
    for name in ("AssistantMessage", "ClaudeAgentOptions", "ResultMessage",
                 "TextBlock"):
        setattr(sdk, name, type(name, (), {}))
    sdk.project_key_for_directory = lambda *a, **k: ""

    async def _query(*a, **k):  # pragma: no cover — never called here
        if False:
            yield None

    sdk.query = _query
    sys.modules["claude_agent_sdk"] = sdk


_stub_fastapi()
_stub_queue()
_stub_pydantic()
_stub_sdk()

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
check("wrong then ok promotes the value — a mis-click is undoable",
      out["flags"], ["DH{maybe}"])
check(
    "REGRESSION: and it LEAVES the rejected list — a value in both would make "
    "the exploit-library gate refuse a flag the operator just confirmed",
    (C.read_meta(j) or {}).get("flag_rejected"), [])

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

# ---------------------------------------------------------------------------
# 5. Retryable modules. The UI gate and the route gate answered the same
#    question from two hand-written lists, and they disagreed: web3 was
#    supported by the backend and hidden by the UI, forensic was refused by
#    both. A completed forensic job therefore offered the operator nothing.
# ---------------------------------------------------------------------------
print("\n--- which modules can be retried ---------------------------")

# This used to read the tuple out of the source text, with a comment saying
# retry.py imports claude_agent_sdk and the host might not have it. That was
# true when written and is not now — the SDK stub above makes the module
# importable, and a later section already does `import api.routes.retry`.
#
# Reading the text cost far more than it saved. `_validate_retry` carries its
# OWN hardcoded module list, and it disagreed with _RETRYABLE_MODULES about
# forensic while this check happily reported "forensic can be retried" — it was
# asking the constant, not the gate an HTTP request actually reaches. The UI
# rendered Retry / Retry-with-my-hint / Continue on finished forensic jobs and
# all three returned 400. Ask the gate.
import api.routes.retry as _RT  # noqa: E402
from fastapi import HTTPException as _HX  # noqa: E402

RETRYABLE = _RT._RETRYABLE_MODULES
check("the retryable-module list is importable, not scraped", bool(RETRYABLE), True)
check("forensic is in the list", "forensic" in RETRYABLE, True)
check("web3 too", "web3" in RETRYABLE, True)
# misc used to be pinned OUT here, with the reason spelled out: its run_job
# needs a passphrase only the operator has, the passphrase reached it only as
# an RQ argument, and a rebuilt job would therefore have failed in a way that
# reads as the module's fault. That was a true statement about the plumbing,
# not a permanent property of misc, and the plumbing changed — so this check
# is inverted rather than deleted, and the three below assert the mechanism
# that made the inversion legitimate. Deleting it would have left "misc can be
# retried" resting on nothing.
check("misc is in the list now that its passphrase outlives the first run",
      "misc" in RETRYABLE, True)

from modules.job_secrets import (  # noqa: E402
    read_misc_passphrase, store_misc_passphrase, prepare_job_secret,
)

_PARENT, _CHILD = "aaaaaaaaaaaa", "bbbbbbbbbbbb"
# Seven characters on purpose: the operator-facing key/value ingress requires
# 8..8192, which is a sensible floor for an API token and the wrong one for a
# passphrase. A misc passphrase that the store silently rejected would fail the
# retry in exactly the way this whole change exists to prevent.
store_misc_passphrase(_PARENT, "hunter2")
check("a short passphrase is storable — the 8-char token floor does not apply",
      read_misc_passphrase(_PARENT), "hunter2")
prepare_job_secret(_CHILD, "some description", copy_from=_PARENT)
check("REGRESSION: the retry child inherits it through the SAME call the "
      "route already makes, so the retry route needs no passphrase code",
      read_misc_passphrase(_CHILD), "hunter2")
check("a job with no stored passphrase reads back None, not an empty string",
      read_misc_passphrase("cccccccccccc"), None)
# The recovery has to happen where the argument is empty. Asserting the list
# and the store without this would pass while run_job still ignored the store.
_MISC_SRC = (ROOT / "modules/misc/orchestrator.py").read_text()
check("...and run_job actually reads it back",
      "read_misc_passphrase" in _MISC_SRC, True)
check("...only when its own argument is empty, so the first run still wins",
      "if not passphrase:" in _MISC_SRC, True)

# Redaction is a plain substring replace, and admitting an unbounded-length
# value to the secret store points that replace at ordinary English. A
# passphrase of `cat` must not turn "concatenate" into a redaction marker in
# every log line this job writes, nor shred the description it appears in.
from modules.job_secrets import redact_job_value  # noqa: E402

store_misc_passphrase("dddddddddddd", "cat")
check("a sub-8 passphrase is still STORED — the retry needs it",
      read_misc_passphrase("dddddddddddd"), "cat")
check("...but is NOT used as a redaction needle on log payloads",
      redact_job_value("dddddddddddd", "please concatenate the categories"),
      "please concatenate the categories")
_desc = prepare_job_secret("dddddddddddd", "the cat sat on the mat")
check("...nor on the description", _desc, "the cat sat on the mat")

# The floor must not weaken what was already being redacted. A CTFd token is 69
# characters, so nothing that was masked before stops being masked.
_LONG = "ctfd_" + "a" * 64
store_misc_passphrase("eeeeeeeeeeee", _LONG)
check("REGRESSION: a long secret is still redacted from log payloads",
      redact_job_value("eeeeeeeeeeee", "token is " + _LONG),
      "token is [REDACTED_JOB_SECRET]")


def gate_status(module):
    """Run the REAL gate that every retry-family endpoint calls first.

    Returns None when it admits the job, or the HTTP status when it refuses.
    """
    jid = make_job(f"gate-{module}", module=module, status="no_flag",
                   filename="disk.raw", description="d")
    try:
        _RT._validate_retry(jid, require_claude_auth=False)
        return None
    except _HX as exc:
        return exc.status_code


# The invariant the old check could not see: the gate and the list must agree.
_refused = [m for m in RETRYABLE if gate_status(m) is not None]
check(
    "REGRESSION: the gate admits EVERY module in _RETRYABLE_MODULES — it used "
    "to keep its own literal, and forensic fell in the gap between them",
    _refused,
    [],
)
# The negative case used to be `misc`, which is now retryable. Derived rather
# than swapped for another literal: whatever is NOT in the list must still be
# refused, and naming one module here is how this check quietly stops testing
# anything the next time that module is admitted.
_NOT_RETRYABLE = [m for m in ("hybrid", "live_fire", "__not_a_module__")
                  if m not in RETRYABLE]
check(
    "  ...and still refuses every module that is not in the list",
    [gate_status(m) for m in _NOT_RETRYABLE],
    [400] * len(_NOT_RETRYABLE),
)
check("  ...and that negative set is not empty, or the check above is vacuous",
      bool(_NOT_RETRYABLE), True)


def continue_dispatch(module):
    """What would /continue enqueue for this module — or how does it refuse?"""
    jid = make_job(f"cont-{module}", module=module, status="no_flag",
                   filename="disk.raw", description="d", target_url="t:1")

    class _Q:
        def __init__(self):
            self.seen = []

        def enqueue(self, *a, **k):
            self.seen.append(a[0] if a else None)
            return None

    q = _Q()
    real = _RT.get_queue
    _RT.get_queue = lambda: q
    try:
        _RT._continue_in_place(C.read_meta(jid), "note")
        return ("enqueued", q.seen)
    except _HX as exc:
        return ("refused", exc.status_code)
    finally:
        _RT.get_queue = real


# Opening the gate without this is worse than leaving it shut: _continue_in_place
# had no forensic branch and its else is rev, so a Continue on a finished
# forensic job would have run Ghidra over a raw disk image.
check(
    "REGRESSION: /continue REFUSES forensic rather than falling through to rev",
    continue_dispatch("forensic"),
    ("refused", 400),
)
check(
    "  ...while a module it does support still dispatches to its own analyzer",
    continue_dispatch("pwn"),
    ("enqueued", ["modules.pwn.analyzer.run_job"]),
)


# --- capability <-> dispatch parity ----------------------------------------
# _CONTINUABLE_MODULES is a written-out list, not "retryable minus forensic".
# The derivation defaulted new modules to ALLOWED, which is how an unreviewed
# module would have reached the dispatch table's fallback. A literal defaults
# them to refused; these two checks are what stops the literal from drifting
# out of step with the table, which is the failure the derivation was meant to
# prevent. The invariant belongs in a test, not in a subtraction.
_no_branch = [m for m in _RT._CONTINUABLE_MODULES
              if continue_dispatch(m)[0] != "enqueued"]
check("REGRESSION: every continuable module has its own dispatch branch",
      _no_branch, [])

def _enqueued_for(m):
    out = continue_dispatch(m)
    return out[1] if out[0] == "enqueued" else []


_wrong_branch = [m for m in _RT._CONTINUABLE_MODULES
                 if not any(f"modules.{m}." in str(x) for x in _enqueued_for(m))]
check("  ...and it dispatches to that module, not to whichever branch is last",
      _wrong_branch, [])

# A module that is retryable but not continuable must be REFUSED, never routed.
# forensic is today's instance; the check is written over the difference of the
# two lists so a future retryable-only module is covered the day it is added.
_leaky = [m for m in _RT._RETRYABLE_MODULES
          if m not in _RT._CONTINUABLE_MODULES
          and continue_dispatch(m) != ("refused", 400)]
check("REGRESSION: a retryable-but-not-continuable module is refused, not routed",
      _leaky, [])
check("  ...and continuable is a subset of retryable",
      [m for m in _RT._CONTINUABLE_MODULES if m not in _RT._RETRYABLE_MODULES], [])


# ---------------------------------------------------------------------------
# 5b. The five rebuild endpoints, driven end to end for forensic.
#
#     The checks above stop at the gate and the dispatch table. That was not
#     enough: a refusal can be correct in what it returns and wrong in what it
#     leaves behind, and that is exactly what happened — the forensic branch
#     used to sit at the dispatch site, so /continue answered 400 after
#     write_job_meta had already flipped the job to queued with nothing
#     enqueued. Every check here reads state back AFTER the call.
# ---------------------------------------------------------------------------
print("\n--- the five rebuild endpoints, for a module that has an image ---")

import asyncio as _aio  # noqa: E402


class _Body:
    """Duck-typed Request — the real ones only ever call .json()."""

    def __init__(self, payload):
        self._payload = payload

    async def json(self):
        return self._payload


class _Recorder:
    def __init__(self):
        self.calls = []

    def enqueue(self, *a, **k):
        self.calls.append(a[0] if a else None)
        return None


def _parent(tag, module="forensic"):
    jid = make_job(f"ep-{tag}", module=module, status="no_flag",
                   filename="disk.raw", image_type="raw", target_os="linux",
                   description="inspect the disk", target_url="fx:8080")
    (DATA / "jobs" / jid / "disk.raw").write_bytes(b"\x00" * 32)
    return jid


def _drive(endpoint, tag, payload, module="forensic"):
    """Call a real route function; return (outcome, enqueued, meta_before, meta_after)."""
    jid = _parent(tag, module)
    before = dict(C.read_meta(jid) or {})
    rec = _Recorder()
    real = _RT.get_queue
    _RT.get_queue = lambda: rec
    try:
        res = _aio.run(endpoint(jid, _Body(payload)))
        gen = getattr(res, "body_iterator", None)
        if gen is not None:                      # SSE: drain it
            async def _drain():
                out = []
                async for chunk in gen:
                    out.append(chunk.decode() if isinstance(chunk, bytes) else str(chunk))
                return "".join(out)
            res = _aio.run(_drain())
        outcome = ("ok", res)
    except _HX as exc:
        outcome = ("http", exc.status_code)
    finally:
        _RT.get_queue = real
    return outcome, rec.calls, before, dict(C.read_meta(jid) or {})


# ---- the four that rebuild: forensic must go all the way through ----------
for _tag, _fn, _label in (
    ("retry", _RT.retry_with_hint, "POST /retry"),
    ("retrystream", _RT.retry_with_hint_stream, "POST /retry/stream"),
    ("resume", _RT.stop_and_resume, "POST /resume"),
    ("resumestream", _RT.stop_and_resume_stream, "POST /resume/stream"),
):
    _out, _q, _before, _after = _drive(_fn, _tag, {"hint": "look again"})
    check(f"{_label}: a forensic job is rebuilt, not refused",
          _out[0], "ok")
    check(f"  ...and it reaches forensic's own orchestrator",
          _q, ["modules.forensic.orchestrator.run_job"])


# ---- the fifth refuses, and must leave the job exactly as it was ----------
_out, _q, _before, _after = _drive(_RT.continue_with_comment, "cont",
                                   {"comment": "instance is back"})
check("POST /continue: forensic is refused", _out, ("http", 400))
check("  ...with nothing enqueued", _q, [])
# The postcondition the previous round did not ask for. A refusal that has
# already rewritten status/description/markers leaves a queued job no worker
# will ever pick up, and the operator sees a job that looks alive.
# EXACT equality — no key is excused. The previous version excused updated_at
# on the assumption that including it would make the check permanently red.
# That assumption was never tested and is false: the normal path leaves the
# whole dict untouched. The excuse only hid updated_at-only side effects.
_changed = {k: (_before.get(k), _after.get(k))
            for k in set(_before) | set(_after)
            if _before.get(k) != _after.get(k)}
check("  ...and REGRESSION: the job it refused is untouched", _changed, {})

# The same endpoint on a module it supports still works, so the check above is
# about forensic and not about /continue being broken for everyone.
_out2, _q2, _b2, _a2 = _drive(_RT.continue_with_comment, "contpwn",
                              {"comment": "instance is back"}, module="pwn")
check("  ...(control) a supported module is still continued",
      _out2[0] != "http", True)

# The UI side of this — that a finished forensic job offers Retry but NOT
# change-target, that a flag_ready web3 job still offers Retry, that misc offers
# neither — is asserted behaviourally in scripts/test_dashboard_ui.js, which
# executes the real renderJob() affordance block. The source version that lived
# here read the FIRST `const hasTarget` line, which is the job-CREATE form's
# variable (app.js ~865), not the render gate; three render-gate mutants passed
# against it. The check moved to where it can run the code instead of grepping
# it. The backend list (_RETRYABLE_MODULES, above) still asserts here — it is
# the source of truth the card is checked against.

# ---------------------------------------------------------------------------
# 6. The verdict-authority boundary. Codex reproduced four defects here that
#    all follow from the same oversight: a verdict was written in one place
#    and four other places kept reading the pre-verdict evidence.
# ---------------------------------------------------------------------------
print("\n--- a verdict has to outrank the evidence it overrules ------")

# F1. `wrong` used to leave the candidates in place, so the next thing that
# recomputed the status asked the operator a question they had just answered.
j = make_job("f1", status="flag_ready", flag_candidates=["DH{dead}"], flags=[])
verdict(j, {"verdict": "wrong"})
check(
    "REGRESSION: a refused job does not bounce back to flag_ready",
    C.no_flag_status(j),
    "no_flag",
)
check(
    "  ...the candidate is cleared, not just demoted",
    (C.read_meta(j) or {}).get("flag_candidates"),
    [],
)
check(
    "  ...and it survives as a refusal",
    (C.read_meta(j) or {}).get("flag_rejected"),
    ["DH{dead}"],
)

# F2. The retry child is the run most likely to re-derive the dead end, so it
# is the one that most needs to know. retry.py imports claude_agent_sdk, so
# assert on the source; the found-the-line check keeps a rename honest.
# Source slices broke here once already — a comment pushed the asserted line
# out of the window and it passed for the wrong reason. Ask the builder. The
# SDK stub above (borrowed from test_retry_provider_snapshot.py) is what makes
# api.routes.retry importable; treating that import as a wall was wrong.
import api.routes.retry as RT  # noqa: E402
import inspect as _inspect  # noqa: E402



def _child_inherits(parent_rejected):
    """Run the REAL _resubmit and read the child's PERSISTED meta.

    The previous version pulled one line out of _resubmit's source and eval'd
    its right-hand side — a source check wearing a function call. It cannot
    notice a later statement deleting the key, and Codex's mutant did exactly
    that and passed. What landed on disk is the only version of this check
    that means anything.

    The enqueue is stubbed because a queue is not under test; the meta write
    is left alone because it is.
    """
    parent = make_job("retry-parent-" + str(parent_rejected), module="rev",
                      status="no_flag", flag_rejected=parent_rejected,
                      description="d")
    pj = DATA / "jobs" / parent
    (pj / "bin").mkdir(exist_ok=True)
    (pj / "bin" / "chal").write_bytes(b"\x7fELF")

    class _Q:
        def enqueue(self, *a, **k):
            return None

    _real = RT.get_queue
    RT.get_queue = lambda: _Q()
    try:
        new_id = RT._resubmit(C.read_meta(parent), "hint", pj)
    finally:
        RT.get_queue = _real
    return (C.read_meta(new_id) or {}).get("flag_rejected")


check(
    "REGRESSION: the retry child inherits the parent's refusals",
    _child_inherits(["DH{dead}"]),
    ["DH{dead}"],
)
check(
    "  ...empty values are not carried as noise",
    _child_inherits(["DH{a}", "", None]),
    ["DH{a}"],
)
check(
    "  ...a parent with none gives the child an empty list, not None",
    _child_inherits(None),
    [],
)

# F3. A hybrid parent that ends with unverified candidates is exactly the
# situation flag_ready exists for.
check(
    "REGRESSION: a hybrid parent with unverified candidates asks for a verdict",
    HC._terminal_parent_status([{"disposition": "unverified", "value": "DH{x}"}]),
    "flag_ready",
)
check(
    "  ...a confirmed one still finishes",
    HC._terminal_parent_status([{"disposition": "confirmed", "value": "DH{x}"}]),
    "finished",
)
check(
    "  ...and nothing at all is still a miss",
    HC._terminal_parent_status([]),
    "no_flag",
)

# F4. The library's fallback rescan reads trusted stdout, which still holds
# the refused value. Saving it files a rejected answer as a known-good
# exploit — the opposite of what the operator said. The old version of this
# check read exploits.py's source for the word "flag_rejected" near the
# refusal; a mutant that disables the filter (`if False and rejected`) leaves
# that word in the file and passed. Call the real route on a real job instead.
import api.routes.exploits as EX  # noqa: E402


def _scalar_save(reject):
    """Run the REAL save_exploit scalar branch on a job whose trusted stdout
    holds a flag the operator may have ruled wrong. Returns (status, detail)
    on refusal, or "saved" if the gate let it through."""
    jid = make_job("scalar-save-" + str(bool(reject)), module="pwn",
                   status="finished", flags=[],
                   flag_rejected=(["DH{c0ffeec0ffee9a1f}"] if reject else []))
    (DATA / "jobs" / jid / "exploit.py.stdout").write_text(
        "solver ran\nDH{c0ffeec0ffee9a1f}\nexit 0\n"
    )
    try:
        EX.save_exploit(EX.SaveBody(job_id=jid, tags=[], notes="", overwrite=True))
        return "saved"
    except HTTPException as e:
        return (e.status_code, str(getattr(e, "detail", "")))


_rej = _scalar_save(reject=True)
check(
    "REGRESSION: an explicit wrong verdict outranks the library rescan",
    _rej[0] if isinstance(_rej, tuple) else _rej,
    400,
)
check(
    "  ...and the refusal says why — the operator ruled it wrong",
    isinstance(_rej, tuple) and "ruled wrong by the operator" in _rej[1],
    True,
)
# Positive control: WITHOUT the refusal the same stdout flag passes the flag
# gate (it fails later on the absent script). This is what proves the refusal
# above did the filtering — the gate is not simply seeing an empty scan.
_ok = _scalar_save(reject=False)
check(
    "  ...proving the rescan really found it (it clears the flag gate and only "
    "fails on the missing script)",
    isinstance(_ok, tuple) and _ok[0] == 400 and "no captured flag" not in _ok[1],
    True,
)

# ---------------------------------------------------------------------------
# 7. The library gate is a TWO-WAY authority question, and fixing only one
#    direction is what left the other broken. Codex found the second half:
#    after an operator ok on a hybrid parent, the save still 400'd because the
#    canonical evidence was the machine's old `unverified` disposition.
#
#    All three directions are pinned together. The third — no verdict at all —
#    is the one that keeps the next change from quietly moving the baseline
#    while the two interesting cases still pass.
# ---------------------------------------------------------------------------
print("\n--- the library gate answers to the operator, both ways -----")

# Codex mutated production six ways that break the meaning of this gate and
# every source-string check here still returned green. A string that appears
# in a file proves the string is in the file; it proves nothing about what the
# code does with it. `_hybrid_save_source` is a plain function taking a meta
# dict, so ask IT.
import api.routes.exploits as EX  # noqa: E402


def gate(meta):
    """Did the hybrid save gate ALLOW this meta? Refusal is an HTTPException.

    Anything else raised means the gate was passed and a later step failed on
    the missing filesystem — which is the answer we want, so it counts as
    allowed rather than being swallowed into a false refusal.
    """
    try:
        EX._hybrid_save_source("a" * 12, meta)
        return True
    except HTTPException as e:
        # Only the AUTHORITY refusal counts as a refusal. The same function
        # later raises for a missing child artifact, and on this fixture that
        # always happens — treating it as "refused" would make every case look
        # refused and the oracle would be vacuous in the other direction.
        return "canonical confirmed evidence" not in str(getattr(e, "detail", ""))
    except Exception:
        return True


def hyb(disposition, value):
    return {"hybrid": {"stage_flag_evidence": [
        {"disposition": disposition, "value": value}]}}


_m = hyb("unverified", "DH{v}")
_m.update(flags=["DH{v}"], flag_verdict="ok")
check("REGRESSION: an explicit ok authorises what the machine could not", gate(_m), True)

_m = hyb("unverified", "DH{v}")
_m.update(flags=["DH{v}"])
check(
    "REGRESSION: with NO verdict the same meta is still refused — the gate did "
    "not simply get looser",
    gate(_m),
    False,
)

_m = hyb("unverified", "DH{v}")
_m.update(flags=["DH{other}"], flag_verdict="ok")
check(
    "REGRESSION: ok on ONE value does not drag an unrelated unverified stage in",
    gate(_m),
    False,
)

_m = hyb("confirmed", "DH{v}")
_m.update(flags=["DH{v}"])
check("a machine-confirmed record still authorises on its own", gate(_m), True)

_m = hyb("unverified", "DH{v}")
_m.update(flags=["DH{v}"], flag_verdict="wrong")
check("REGRESSION: an explicit wrong is not authority to save", gate(_m), False)

_m = hyb("unverified", "DH{v}")
_m.update(flags=[], flag_verdict="ok")
check("  ...and ok with nothing promoted authorises nothing", gate(_m), False)

# ---------------------------------------------------------------------------
# 8. Two things that look identical in the data and must not be: a verdict
#    being asked again, and a NEW run genuinely finding something new.
#    F1 fixed the first by clearing the candidates. That makes the second
#    work — but nothing proved it, and "the bug is gone" is not the same
#    claim as "the feature still works".
# ---------------------------------------------------------------------------
print("\n--- asked again vs genuinely new ---------------------------")

j = make_job("g1", status="flag_ready", flag_candidates=["DH{old}"], flags=[])
verdict(j, {"verdict": "wrong"})
check(
    "REGRESSION: nothing new -> stays a miss (the verdict is not re-asked)",
    C.no_flag_status(j),
    "no_flag",
)
# A later run writes a candidate the operator has never seen. That job SHOULD
# reopen — this is the feature, not the bug.
_m = json.loads((DATA / "jobs" / j / "meta.json").read_text())
_m["flag_candidates"] = ["DH{brand_new}"]
(DATA / "jobs" / j / "meta.json").write_text(json.dumps(_m))
check(
    "REGRESSION: a NEW candidate from a later run reopens the verdict",
    C.no_flag_status(j),
    "flag_ready",
)
# And the refusal is still on the record while that happens — the new question
# does not erase the old answer.
check(
    "  ...without forgetting what was already ruled out",
    (C.read_meta(j) or {}).get("flag_rejected"),
    ["DH{old}"],
)

# The operator changing their mind is an UNDO, not a reopen: same value, and
# it leaves the rejected list so the library gate can still save it.
j = make_job("g2", status="flag_ready", flag_candidates=["DH{mind}"], flags=[])
verdict(j, {"verdict": "wrong"})
out = verdict(j, {"verdict": "ok"})
check("change-of-mind promotes the same value", out["flags"], ["DH{mind}"])
check("  ...and is an undo, not a second question",
      (C.read_meta(j) or {}).get("status"), "finished")

# ---------------------------------------------------------------------------
# 9. One builder, four callers. retry / resume / stop-resume all fork a child
#    through _resubmit, so the rejection inheritance had to land there rather
#    than in whichever path someone remembered.
# ---------------------------------------------------------------------------
print("\n--- the child inherits on every path ------------------------")

# Read here rather than at module scope: the retryable-module section above
# no longer scrapes this file, so this is the only remaining reader.
_retry_src = (ROOT / "api" / "routes" / "retry.py").read_text()
_calls = _retry_src.count("_resubmit(")
check("every fork path shares one child-meta builder", _calls >= 5, True)
check(
    "REGRESSION: and the inheritance lives IN that builder, not in one caller",
    _child_inherits(["DH{x}"]),
    ["DH{x}"],
)

# Three generations, with the youngest re-refusing something an ancestor
# already refused. The list must not grow a duplicate.
def _inherit(parent):
    return [r for r in (parent.get("flag_rejected") or []) if r]


def _refuse(meta, values):
    seen = [r for r in (meta.get("flag_rejected") or []) if r]
    return seen + [v for v in values if v not in seen]


_g0 = {"flag_rejected": []}
_g0["flag_rejected"] = _refuse(_g0, ["DH{a}"])
_g1 = {"flag_rejected": _inherit(_g0)}
_g1["flag_rejected"] = _refuse(_g1, ["DH{b}"])
_g2 = {"flag_rejected": _inherit(_g1)}
_g2["flag_rejected"] = _refuse(_g2, ["DH{a}"])
check(
    "REGRESSION: a re-refused ancestor value does not duplicate down the chain",
    _g2["flag_rejected"],
    ["DH{a}", "DH{b}"],
)

# ---------------------------------------------------------------------------
# 10. The hybrid parent through the real verdict route, not the status helper
#     alone — including the bulk-delete asymmetry, which is the half that
#     silently destroys the thing being asked about.
# ---------------------------------------------------------------------------
print("\n--- hybrid through the production route --------------------")

j = make_job("h1", status="flag_ready", flag_candidates=["DH{hy}"], flags=[],
             hybrid={"stage_flag_evidence": [
                 {"disposition": "unverified", "value": "DH{hy}"}]})
out = verdict(j, {"verdict": "ok"})
check("a hybrid parent takes ok through the same route", out["status"], "finished")
check("  ...and the flag is promoted", (C.read_meta(j) or {}).get("flags"), ["DH{hy}"])

j = make_job("h2", status="flag_ready", flag_candidates=["DH{hy2}"], flags=[],
             hybrid={"stage_flag_evidence": [
                 {"disposition": "unverified", "value": "DH{hy2}"}]})
out = verdict(j, {"verdict": "wrong"})
check("  ...and wrong likewise", out["status"], "no_flag")
check("  ...refusal recorded", out["rejected"], ["DH{hy2}"])

check(
    "REGRESSION: bulk-delete's safe defaults still exclude flag_ready — a job "
    "waiting for a verdict must not be swept away before it gets one",
    "flag_ready" in _line,
    False,
)

# ---------------------------------------------------------------------------
# 11. bulk-delete, through the real route. This lived in section 1 as a
#     source check until Codex showed such checks pass against a broken
#     product; it moved here because it needs make_job.
# ---------------------------------------------------------------------------
print("\n--- bulk-delete leaves a job awaiting a verdict -------------")

def _bulk_survives(status):
    """Create a job, run the REAL bulk delete, report whether it survived.

    Two things were wrong with the first version of this and both made it
    weaker than the source check it replaced:

      * it wrapped a SYNCHRONOUS route in `asyncio.run`, so the call raised
        TypeError and fell through to a second attempt — the thing under test
        was never the thing being called;
      * it ended in `except Exception: pass`, so a route that raised 500
        after deleting still read as a pass.

    That second one was written in the same commit that narrowed a too-broad
    `except OSError` in production, for exactly the reason repeated here: a
    broad except does not remove a failure, it removes the evidence of one.

    Nothing is caught now. If the route raises, this test fails, which is what
    a test is for.
    """
    jid = make_job("bulk-" + status, status=status)
    resp = JR.bulk_delete_jobs()
    return (DATA / "jobs" / jid).exists(), jid, resp


_kept, _kept_id, _kept_resp = _bulk_survives("flag_ready")
_gone, _gone_id, _gone_resp = _bulk_survives("no_flag")

check(
    "REGRESSION: bulk-delete leaves a job that is awaiting a verdict",
    _kept,
    True,
)
check(
    "  ...while still sweeping a settled one — the default is protective, "
    "not simply broken",
    _gone,
    False,
)
# The response is part of the contract, not decoration: the UI reports these
# numbers back to the operator. Checking only the filesystem let a route that
# deleted correctly but reported wrongly pass — Codex's mutant did exactly
# that.
check(
    "REGRESSION: the response does not claim to have deleted the kept job",
    _kept_id in (_kept_resp.get("ids") or []),
    False,
)
check(
    "  ...and does name the one it did delete",
    _gone_id in (_gone_resp.get("ids") or []),
    True,
)
check(
    "  ...with deleted matching the ids it lists",
    _gone_resp.get("deleted"),
    len(_gone_resp.get("ids") or []),
)

# ---------------------------------------------------------------------------
# 12. The teardown guard, by errno. Narrowing the catch was verified by the
#     product behaving correctly, which says nothing about whether widening it
#     again would be noticed. Checking the present state and preventing the
#     regression are different jobs and only the first had been done.
#
#     ESRCH is the race the guard exists for and must be swallowed. EPERM and
#     EIO are real "could not clean up" results and must propagate — a broad
#     `except OSError` returns all three as success, which is the mutant this
#     section kills.
# ---------------------------------------------------------------------------
print("\n--- teardown: which errno may be swallowed -----------------")

import asyncio as _aio  # noqa: E402
import errno as _errno  # noqa: E402
import signal as _signal  # noqa: E402


def _teardown(err, fail_on):
    """Run the REAL _stop_process and report (outcome, call_sequence).

    os.killpg is forced to ProcessLookupError on BOTH signals so the FALLBACK —
    the branch under test — is the one exercised each time. `fail_on` selects
    which fallback raises `err`:

      "terminate"  the TERM fallback (proc.terminate), reached straight after
                   the first killpg.
      "kill"       the KILL fallback (proc.kill). Reaching it requires TERM to
                   succeed and the first wait to TIME OUT. The previous version
                   of this matrix had wait() return 0 immediately, so the KILL
                   fallback was never once exercised — and a mutant that widened
                   ONLY its catch to `except OSError` passed the whole suite.

    outcome is "returned" if teardown completed, else the errno name it let
    through. call_sequence records each killpg (with its signal), terminate,
    wait and kill in the order the production path actually touched them.
    """
    import modules.codex_cli as CC

    calls = []

    class _Proc:
        pid = 424242
        returncode = None

        def __init__(self):
            self._waits = 0

        def terminate(self):
            calls.append("terminate")
            if fail_on == "terminate" and err is not None:
                raise OSError(err, "injected")

        def kill(self):
            calls.append("kill")
            if fail_on == "kill" and err is not None:
                raise OSError(err, "injected")

        async def wait(self):
            self._waits += 1
            calls.append("wait")
            # Only the FIRST wait (the one between TERM and KILL) times out, and
            # only when steering toward the KILL fallback. Any post-KILL wait
            # must complete, or a genuinely-gone process would look like a hang.
            if self._waits == 1 and fail_on == "kill":
                raise _aio.TimeoutError
            return 0

    real_killpg = CC.os.killpg

    def fake_killpg(pid, sig):
        calls.append("killpg:" + ("TERM" if sig == _signal.SIGTERM
                                  else "KILL" if sig == _signal.SIGKILL
                                  else str(sig)))
        raise ProcessLookupError()

    CC.os.killpg = fake_killpg
    try:
        holder = CC.CodexCLIClient.__new__(CC.CodexCLIClient)
        holder._proc = _Proc()
        try:
            _aio.run(CC.CodexCLIClient._stop_process(holder))
            return "returned", calls
        except OSError as e:
            return _errno.errorcode.get(e.errno, str(e.errno)), calls
    finally:
        CC.os.killpg = real_killpg


try:
    # --- TERM fallback: killpg(TERM) fails, proc.terminate() is the branch. ---
    _out, _seq = _teardown(_errno.ESRCH, "terminate")
    check("REGRESSION: ESRCH at the TERM fallback is swallowed — that IS the race",
          _out, "returned")
    check("  ...and it stopped at TERM, never reaching KILL",
          _seq, ["killpg:TERM", "terminate"])
    check("REGRESSION: EPERM at TERM propagates — a broad except OSError would hide it",
          _teardown(_errno.EPERM, "terminate")[0], "EPERM")
    check("REGRESSION: EIO at TERM propagates too",
          _teardown(_errno.EIO, "terminate")[0], "EIO")

    # --- KILL fallback: TERM succeeds, the first wait TIMES OUT, killpg(KILL) --
    # --- fails, and proc.kill() is the branch. This path used to be dead code --
    # --- from the test's point of view — nothing here ever entered it.        --
    _out, _seq = _teardown(_errno.ESRCH, "kill")
    check("REGRESSION: ESRCH at the KILL fallback is swallowed too", _out, "returned")
    check("  ...having actually walked TERM -> wait-timeout -> KILL",
          _seq, ["killpg:TERM", "terminate", "wait", "killpg:KILL", "kill"])
    check("REGRESSION: EPERM at the KILL fallback propagates — the mutant this "
          "second half exists to kill",
          _teardown(_errno.EPERM, "kill")[0], "EPERM")
    check("REGRESSION: EIO at the KILL fallback propagates too",
          _teardown(_errno.EIO, "kill")[0], "EIO")
except AttributeError as _e:
    check(f"teardown matrix could not run ({_e})", False, True)

print(f"\n== retry-gate summary: {PASSED} passed, {FAILED} failed ==")
raise SystemExit(1 if FAILED else 0)
