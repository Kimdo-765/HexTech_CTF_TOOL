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

# retry.py imports claude_agent_sdk, which a host running this file need not
# have. Read the tuple out of the source. Asserting the line was FOUND is what
# keeps a rename from turning every check below into a silent pass.
_retry_src = (ROOT / "api" / "routes" / "retry.py").read_text()
_rmline = next(
    (l for l in _retry_src.splitlines() if l.startswith("_RETRYABLE_MODULES")), ""
)
check("the retryable-module list was located", bool(_rmline), True)
RETRYABLE = tuple(
    m.strip().strip("\"'") for m in
    _rmline.split("(", 1)[-1].rsplit(")", 1)[0].split(",") if m.strip()
)

check("forensic can be retried", "forensic" in RETRYABLE, True)
check("web3 too", "web3" in RETRYABLE, True)
check(
    "REGRESSION: misc stays out — its run_job needs a passphrase only the "
    "operator has, so a rebuilt job would fail in a way that looks like the "
    "module's fault",
    "misc" in RETRYABLE,
    False,
)

_app = (ROOT / "web-ui" / "app.js").read_text()
_canretry = next(
    (l for l in _app.splitlines() if "const canRetry" in l), ""
)
_hastarget = next((l for l in _app.splitlines() if "const hasTarget" in l), "")
check("the UI has a separate can-retry gate", bool(_canretry), True)
check("  ...and a separate has-target gate", bool(_hastarget), True)
check(
    "REGRESSION: the UI's retry gate covers every module the route accepts",
    all(m in _app[_app.index("const canRetry"):_app.index("const canRetry") + 200]
        for m in RETRYABLE),
    True,
)
check(
    "REGRESSION: forensic is NOT offered 'change target' — it takes none",
    "forensic" in _hastarget,
    False,
)

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

_resub_src = _inspect.getsource(RT._resubmit)
_rej_line = next(
    (l for l in _resub_src.splitlines() if '"flag_rejected":' in l), ""
)


def _child_inherits(parent_rejected):
    """Evaluate the builder's own expression for the child's flag_rejected.

    Only that expression: the rest of _resubmit enqueues work and copies
    artifacts, which needs a queue and a job tree. The inheritance either
    happens in this line or nowhere.
    """
    if not _rej_line:
        return "MISSING"
    expr = _rej_line.strip().split(":", 1)[1].rstrip(",")
    return eval(expr, {}, {"prev_meta": {"flag_rejected": parent_rejected}})


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
# exploit — the opposite of what the operator said.
_expl = (ROOT / "api" / "routes" / "exploits.py").read_text()
_gate = _expl[_expl.index("refusing to save into exploit library") - 900:
              _expl.index("refusing to save into exploit library")]
check(
    "REGRESSION: an explicit wrong verdict outranks the library rescan",
    "flag_rejected" in _gate,
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
    JR.bulk_delete_jobs()
    return (DATA / "jobs" / jid).exists()


check(
    "REGRESSION: bulk-delete leaves a job that is awaiting a verdict",
    _bulk_survives("flag_ready"),
    True,
)
check(
    "  ...while still sweeping a settled one — the default is protective, "
    "not simply broken",
    _bulk_survives("no_flag"),
    False,
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


class _FakeProc:
    """Duck-typed asyncio process whose signal calls raise a chosen errno."""

    def __init__(self, err):
        self.pid = 424242
        self.returncode = None
        self._err = err
        self.calls = []

    def _boom(self, name):
        self.calls.append(name)
        if self._err is None:
            return
        raise OSError(self._err, "injected")

    def terminate(self):
        self._boom("terminate")

    def kill(self):
        self._boom("kill")

    async def wait(self):
        return 0


def _teardown(err):
    """Run the REAL _stop_process against a process whose signals fail.

    Returns "returned" if teardown completed, or the errno name it let
    through. os.killpg is forced to ProcessLookupError so the fallback — the
    branch under test — is always the one exercised.
    """
    import modules.codex_cli as CC


    proc = _FakeProc(err)

    real_killpg = CC.os.killpg

    def fake_killpg(pid, sig):
        raise ProcessLookupError()

    CC.os.killpg = fake_killpg
    try:
        holder = CC.CodexCLIClient.__new__(CC.CodexCLIClient)
        holder._proc = proc
        try:
            _aio.run(CC.CodexCLIClient._stop_process(holder))
            return "returned"
        except OSError as e:
            return _errno.errorcode.get(e.errno, str(e.errno))
    finally:
        CC.os.killpg = real_killpg


try:
    check(
        "REGRESSION: ESRCH (already gone) is swallowed — that IS the race",
        _teardown(_errno.ESRCH),
        "returned",
    )
    check(
        "REGRESSION: EPERM propagates — a broad except OSError would hide it",
        _teardown(_errno.EPERM),
        "EPERM",
    )
    check(
        "REGRESSION: EIO propagates too",
        _teardown(_errno.EIO),
        "EIO",
    )
except AttributeError as _e:
    check(f"teardown matrix could not run ({_e})", False, True)

print(f"\n== retry-gate summary: {PASSED} passed, {FAILED} failed ==")
raise SystemExit(1 if FAILED else 0)
