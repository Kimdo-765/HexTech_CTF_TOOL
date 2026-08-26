#!/usr/bin/env python3
"""A retry should know which mechanisms its lineage has already named.

Run: python3 scripts/test_lineage_technique_carry.py

WHY THIS EXISTS, AND WHY THE OBVIOUS RULE IS WRONG

Measured on the 2026-08-25 corpus by reading every attempt's findings.json,
solver and report — not their technique strings:

    instagram.exe   7 attempts · 6 distinct technique strings · 2 mechanisms
    r.0.0.mca       5 attempts · 3 distinct technique strings · 1 mechanism
    across 5 lineages: of 29 pairs whose strings DIFFER, 23 (79%) name the
    same mechanism

So the strings overstate conceptual variety by about four to one, and nothing
in the retry loop noticed instagram circling.

The obvious fix — "do not repeat a technique" — is REFUTED by the same corpus.
r.0.0.mca is one mechanism across all five attempts and it went

    no_flag → no_flag → finished → finished → finished

Repeating the mechanism is how that challenge was solved. The first attempt had
the mechanism right and failed to execute it. What must be prevented is not
repetition; it is reading an execution failure as a hypothesis failure. So the
carried block asks the agent to DECLARE re-executing vs refuting, and never
tells it to avoid a name.

THE THIRD PART. An attempt cut off by a timeout, an OOM or a policy refusal did
not test its hypothesis. Three jobs died that way on 2026-08-25 with the
operator's job_timeout set to 9,999,999. Such an entry is carried as NOT TESTED
and must never read as a dead end.

WHY THIS IS NOT A TAUTOLOGY

Everything here drives the real functions from api/routes/retry.py against real
temp job trees. Asserting that the source contains a string would pass on a
carry that drops the field two statements later — which is exactly how the
`flag_rejected` carry was once broken.
"""
from __future__ import annotations

import ast
import json
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.TemporaryDirectory(prefix="lineage-carry-")
DATA = Path(_TMP.name)
(DATA / "jobs").mkdir()
os.environ.update(DATA_DIR=str(DATA), JOBS_DIR=str(DATA / "jobs"),
                  SETTINGS_PATH=str(DATA / "settings.json"))
(DATA / "settings.json").write_text("{}")


def _stub_fastapi() -> None:
    import types
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
    m.UploadFile = type("UploadFile", (), {})
    for n in ("File", "Form", "Query", "Body", "Depends"):
        setattr(m, n, lambda *a, **k: None)
    sys.modules["fastapi"] = m
    resp = types.ModuleType("fastapi.responses")
    for n in ("PlainTextResponse", "JSONResponse", "StreamingResponse",
              "FileResponse", "HTMLResponse", "Response"):
        setattr(resp, n, type(n, (), {"__init__": lambda self, *a, **k: None}))
    sys.modules["fastapi.responses"] = resp
    m.responses = resp



def _stub_queue() -> None:
    """`api.queue` reaches for redis/rq at import; neither is under test."""
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

    m.BaseModel = BaseModel
    m.Field = lambda *a, **k: None
    m.ValidationError = type("ValidationError", (Exception,), {})
    sys.modules["pydantic"] = m


def _stub_sdk() -> None:
    """Stub claude_agent_sdk ONLY when genuinely absent.

    `find_spec`, not `name not in sys.modules` — the latter is true at startup
    even where the library exists, so it would install a stub over a working
    install and this suite would never exercise the real import path. Borrowed
    from scripts/test_flag_ready.py, which borrowed it in turn.
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


try:
    import api.routes.retry as RT
except Exception as e:  # pragma: no cover
    # Not a silent exit 0. Every dependency this module reaches for is stubbed
    # above, so an import failure here means the stubs stopped matching the
    # code — which is a finding, not a reason to report success.
    print("FAIL  api.routes.retry did not import even with stubs: %s" % e)
    raise SystemExit(1)


def make_job(jid, *, technique=None, status="no_flag", kind=None, history=None):
    d = DATA / "jobs" / jid
    d.mkdir(parents=True, exist_ok=True)
    meta = {"id": jid, "module": "rev", "status": status}
    if kind:
        # `error_kind`, NOT `agent_error_kind`. This suite originally wrote the
        # latter — the same name the production read used — so every K1-c check
        # passed against a key that meta.json has never held. A fixture that
        # mirrors the code's mistake tests nothing.
        meta["error_kind"] = kind
    if history is not None:
        meta["technique_history"] = history
    (d / "meta.json").write_text(json.dumps(meta))
    if technique is not None:
        (d / "findings.json").write_text(json.dumps(
            {"solver_strategy": {"technique_name": technique,
                                 "approach": "static-emit"}}))
    return meta, d


print("--- the mechanism is read from the artifact " + "-" * 14)
m, d = make_job("aaaaaaaaaaaa", technique="minecraft-region-nbt-redstone-linear-system")
chk("technique comes from solver_strategy.technique_name",
    RT._technique_of(d), "minecraft-region-nbt-redstone-linear-system")

d2 = DATA / "jobs" / "bbbbbbbbbbbb"
d2.mkdir(parents=True, exist_ok=True)
(d2 / "findings.json").write_text(json.dumps(
    {"chain": {"technique_name": "house_of_einherjar"},
     "solver_strategy": {"technique_name": "ignored"}}))
chk("chain.technique_name wins for pwn/web/crypto shapes",
    RT._technique_of(d2), "house_of_einherjar")

d3 = DATA / "jobs" / "cccccccccccc"
d3.mkdir(parents=True, exist_ok=True)
chk("a job with no findings.json yields None", RT._technique_of(d3), None)
(d3 / "findings.json").write_text("{ not json")
chk("unparseable findings.json yields None, not a crash",
    RT._technique_of(d3), None)
(d3 / "findings.json").write_text(json.dumps(
    {"solver_strategy": {"approach": "static-emit"}}))
chk("REGRESSION: `approach` is NOT used as a technique — it was static-emit "
    "in 16 of 18 findings and carries no information",
    RT._technique_of(d3), None)

print("")
print("--- the carry accumulates, like flag_rejected " + "-" * 12)
m1, d1 = make_job("111111111111", technique="alpha")
h1 = RT._carry_technique_history(m1, d1)
chk("first retry carries the parent's own mechanism",
    [x["technique"] for x in h1], ["alpha"])
chk("...with the parent's outcome", [x["status"] for x in h1], ["no_flag"])

m2, d2b = make_job("222222222222", technique="beta", history=h1)
h2 = RT._carry_technique_history(m2, d2b)
chk("REGRESSION: a grandchild sees the grandparent without walking the tree",
    [x["technique"] for x in h2], ["alpha", "beta"])

m3, d3b = make_job("333333333333", technique="alpha", history=h2)
h3 = RT._carry_technique_history(m3, d3b)
chk("a repeated mechanism is carried again, not deduped — r.0.0.mca repeated "
    "one mechanism and solved on the third try",
    [x["technique"] for x in h3], ["alpha", "beta", "alpha"])

m4, d4 = make_job("444444444444", technique=None, history=h3)
chk("an attempt that ran and named nothing adds nothing but loses nothing",
    [x["technique"] for x in RT._carry_technique_history(m4, d4)],
    ["alpha", "beta", "alpha"])

long_hist = [{"job_id": str(i), "technique": "t%d" % i, "status": "no_flag",
              "looked": True} for i in range(20)]
m5, d5 = make_job("555555555555", technique="last", history=long_hist)
chk("the window is bounded so a long lineage cannot grow the prompt without end",
    len(RT._carry_technique_history(m5, d5)), 12)

print("")
print("--- K1-c: a truncated attempt did not test anything " + "-" * 6)
for n, kind in enumerate(sorted(RT._TRUNCATED_KINDS)):
    mk, dk = make_job("kkkkkkkkkk%02d" % n, technique="gamma", status="failed",
                      kind=kind)
    got = RT._carry_technique_history(mk, dk)
    chk("stopped by %-21s -> looked=False" % kind, got[-1]["looked"], False)

mo, do = make_job("999999999999", technique="delta", status="no_flag")
chk("a job that ran to a verdict is looked=True",
    RT._carry_technique_history(mo, do)[-1]["looked"], True)

for n, kind in enumerate(sorted(RT._RAN_KINDS)):
    mr, dr = make_job("rrrrrrrrrr%02d" % n, technique="eps", status="failed",
                      kind=kind)
    chk("REGRESSION: %-16s is NOT a truncation — it did run" % kind,
        RT._carry_technique_history(mr, dr)[-1]["looked"], True)

# The defect this pins: production read `agent_error_kind`, a key meta.json has
# never held, so `looked` was unconditionally True and K1-c was inert while its
# own suite went green. A permissive dual-key read would re-hide it, so the
# WRONG key must stay inert.
mw, dw = make_job("wwwwwwwwwwww", technique="gamma", status="failed")
mw["agent_error_kind"] = "timeout"
(dw / "meta.json").write_text(json.dumps(mw))
chk("REGRESSION: `agent_error_kind` is the RESPONSE/result key and must NOT "
    "drive the carry — meta.json holds `error_kind`",
    RT._carry_technique_history(mw, dw)[-1]["looked"], True)

print("")
print("--- K1-c: a truncated attempt that named nothing still enters " + "-" * 0)
# Both forensic attempts K2 had to exclude are this shape: cut off with no
# findings.json at all. Dropping them makes the child's history say the attempt
# never happened.
mn, dn = make_job("nnnnnnnnnnnn", technique=None, status="failed",
                  kind="timeout")
_got = RT._carry_technique_history(mn, dn)
# Report the drop as a FAIL rather than dying on [-1] of an empty list: the
# regression that matters is "the entry vanished", and a traceback reads as a
# broken suite instead of a broken carry.
tail = _got[-1] if _got else {"technique": "<NO ENTRY AT ALL>",
                              "looked": None, "stopped_by": None}
chk("a truncated attempt with no mechanism still gets an entry",
    (tail["technique"], tail["looked"], tail["stopped_by"]),
    (None, False, "timeout"))
chk("...and it survives the NEXT hop rather than being filtered out",
    [(x["technique"], x["looked"])
     for x in RT._carry_technique_history(
         {"id": "oooooooooooo", "technique_history": [tail]},
         DATA / "jobs" / "does-not-exist")],
    [(None, False)])
chk("...and renders as a spent attempt, not as the string None",
    "(no mechanism recorded)" in RT._technique_history_block([tail])
    and "None" not in RT._technique_history_block([tail]), True)

print("")
print("--- what the agent is actually told " + "-" * 22)
chk("an empty history renders nothing at all",
    RT._technique_history_block([]), "")

block = RT._technique_history_block([
    {"job_id": "111111111111", "technique": "alpha", "status": "no_flag",
     "looked": True},
    {"job_id": "222222222222", "technique": "beta", "status": "failed",
     "looked": False, "stopped_by": "timeout"},
])
chk("the mechanism names appear", "alpha" in block and "beta" in block, True)
chk("a tested attempt shows its outcome", "no_flag" in block, True)
chk("REGRESSION: a truncated attempt is marked NOT TESTED",
    "NOT TESTED" in block and "timeout" in block, True)
chk("...and is explicitly not a dead end",
    "not evidence against" in block, True)
chk("REGRESSION: the block never tells the agent to avoid a name — "
    "r.0.0.mca was solved by repeating one",
    ("do not repeat" in block.lower() or "avoid" in block.lower()), False)
chk("it demands a declaration instead",
    "RE-EXECUTING" in block and "REFUTING" in block, True)

print("")
print("--- it reaches the prompt " + "-" * 32)
hist = [{"job_id": "111111111111", "technique": "alpha", "status": "no_flag",
         "looked": True}]
# Both builders, not just retry. `/resume` mints a new job id through
# _resubmit exactly as `/retry` does, so its child accumulates the same carry;
# leaving the block out of _resume_preamble meant nobody ever read it. (The
# same-job-id path is _continue_in_place, which has no child and is untouched.)
for name in ("_retry_preamble", "_resume_preamble"):
    build = getattr(RT, name)
    for fresh in (False, True):
        pre = build("111111111111", "some hint", fresh=fresh,
                    operator_text=True, history=hist)
        chk("%s fresh=%-5s the history is in the preamble" % (name, fresh),
            "alpha" in pre, True)
        chk("%s fresh=%-5s ...and the hint still is too" % (name, fresh),
            "some hint" in pre, True)
        bare = build("111111111111", "some hint", fresh=fresh,
                     operator_text=True)
        chk("%s fresh=%-5s no history -> preamble unchanged in shape"
            % (name, fresh),
            "what this lineage has already named" in bare, False)

print("")
print("--- the child meta really carries it " + "-" * 21)
parent, pj = make_job("777777777777", technique="zeta")


class _Q:
    def enqueue(self, *a, **k):
        return None


_real = RT.get_queue
RT.get_queue = lambda: _Q()
try:
    child_id = RT._resubmit(parent, "hint", pj)
finally:
    RT.get_queue = _real
child = json.loads((DATA / "jobs" / child_id / "meta.json").read_text())
chk("REGRESSION: _resubmit persists technique_history to the child's meta — "
    "a source check would pass on a carry that a later statement drops",
    [x["technique"] for x in (child.get("technique_history") or [])], ["zeta"])
chk("...and flag_rejected still rides alongside it",
    "flag_rejected" in child, True)

print("")
print("--- the vocabulary is the producers', not this file's " + "-" * 4)
# Why a census and not a hand-written list: the shipped set contained "budget",
# which NO producer writes (`modules/_common.py` writes "budget_fallback"). A
# dead member rates a real truncation as `looked: true` — the exact misreading
# K1-c exists to prevent — and no fixture-based check can see it, because a
# fixture writes whatever token the test author already believes in. So both
# directions are asserted against the source tree itself.
_ROOT = Path(__file__).resolve().parent.parent
_ASSIGN = re.compile(r'(?:agent_error_kind|error_kind)"?\]?\s*(?:=|:)\s*"([a-z_]+)"')


def _producible_kinds():
    """Every error_kind literal production code can put on a job."""
    kinds, where = set(), {}
    for base in ("modules", "api", "worker"):
        root = _ROOT / base
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.py")):
            rel = path.relative_to(_ROOT).as_posix()
            for i, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
                for m in _ASSIGN.finditer(line):
                    kinds.add(m.group(1))
                    where.setdefault(m.group(1), "%s:%d" % (rel, i))
    # classify_agent_error's own return literals, read from source rather than
    # imported: modules/_common.py is not importable in this stubbed process.
    common = (_ROOT / "modules" / "_common.py").read_text(errors="replace")
    fn = ast.parse(common)
    for node in ast.walk(fn):
        if isinstance(node, ast.FunctionDef) and node.name == "classify_agent_error":
            for sub in ast.walk(node):
                if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Constant) \
                        and isinstance(sub.value.value, str):
                    kinds.add(sub.value.value)
                    where.setdefault(sub.value.value, "modules/_common.py:classify_agent_error")
    # _STOP_REASON_KIND's VALUES are the kinds an adapter stop_reason becomes.
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "_STOP_REASON_KIND"
                for t in node.targets) and isinstance(node.value, ast.Dict):
            for v in node.value.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    kinds.add(v.value)
                    where.setdefault(v.value, "modules/_common.py:_STOP_REASON_KIND")
    return kinds, where


producible, origin = _producible_kinds()
chk("the census actually found the producers (a zero here means the scan "
    "broke, not that the code is clean)", len(producible) >= 10, True)

dead = sorted(RT._TRUNCATED_KINDS - producible)
chk("REGRESSION: every truncation kind is one a producer really writes — "
    "`budget` was not, and shipped a truncation as looked=True",
    dead, [])

unclassified = sorted(producible - RT._TRUNCATED_KINDS - RT._RAN_KINDS)
chk("REGRESSION: every producible kind is classified in exactly one set, so a "
    "NEW kind cannot silently default to looked=True (unclassified: %s)"
    % ", ".join("%s @ %s" % (k, origin.get(k, "?")) for k in unclassified),
    unclassified, [])

chk("the two sets do not overlap",
    sorted(RT._TRUNCATED_KINDS & RT._RAN_KINDS), [])

print("")
print("--- against the real job trees, not fixtures " + "-" * 13)
# A fixture check cannot see a key mismatch between this file and the live
# writer. These read meta.json as it is actually written on disk.
def _live_jobs_dir() -> Path | None:
    """The first candidate that actually holds job metadata.

    Not just the first that exists: this host has a stale `/data/jobs` with six
    empty directories in it, and picking that one turned the whole section into
    zero assertions that still printed as a section. Candidates are derived, not
    hardcoded to one operator's home — from inside a worker container the corpus
    is at /data/jobs; from a worktree it is under the MAIN checkout, which is the
    parent of the shared git dir.
    """
    cands = []
    env = os.environ.get("HEXTECH_LIVE_JOBS")
    if env:
        cands.append(Path(env))
    cands.append(Path("/data/jobs"))
    cands.append(ROOT / "data" / "jobs")
    common = ROOT / ".git"
    if common.is_file():  # worktree: .git is a file pointing at the real dir
        try:
            line = common.read_text().strip()
            if line.startswith("gitdir:"):
                gd = Path(line.split(":", 1)[1].strip())
                # <main>/.git/worktrees/<name> -> <main>
                for anc in gd.parents:
                    if anc.name == ".git":
                        cands.append(anc.parent / "data" / "jobs")
                        break
        except OSError:
            pass
    for c in cands:
        try:
            if c.is_dir() and any(c.glob("*/meta.json")):
                return c
        except OSError:
            continue
    return None


_LIVE = _live_jobs_dir()
if _LIVE is not None:
    live_kinds, scanned = {}, 0
    for jdir in sorted(_LIVE.iterdir()):
        mfile = jdir / "meta.json"
        if not mfile.is_file():
            continue
        try:
            lm = json.loads(mfile.read_text())
        except (OSError, ValueError):
            continue
        scanned += 1
        chk_key = "agent_error_kind" in lm
        if chk_key:
            live_kinds.setdefault("__wrong_key_present__", []).append(jdir.name)
        k = str(lm.get("error_kind") or "")
        if k:
            live_kinds.setdefault(k, []).append(jdir.name)
    chk("the live corpus was actually read (%d job trees)" % scanned,
        scanned > 0, True)
    chk("REGRESSION: no live meta.json carries `agent_error_kind` — the read "
        "this suite once fabricated does not exist on disk",
        live_kinds.get("__wrong_key_present__", []), [])
    live_unclassified = sorted(
        k for k in live_kinds
        if k != "__wrong_key_present__"
        and k not in RT._TRUNCATED_KINDS and k not in RT._RAN_KINDS)
    chk("every error_kind observed on disk is classified (%s)"
        % ", ".join(sorted(k for k in live_kinds if k != "__wrong_key_present__")),
        live_unclassified, [])
    # 6a3a84822b07: web, error_kind=timeout, findings.solver_strategy names
    # chromedriver-rce. The end-to-end case D1 broke.
    real = _LIVE / "6a3a84822b07"
    if (real / "meta.json").is_file():
        rmeta = json.loads((real / "meta.json").read_text())
        entry = RT._carry_technique_history(rmeta, real)[-1]
        chk("END-TO-END on real job 6a3a84822b07: a timed-out attempt reads as "
            "NOT TESTED", (entry["looked"], entry["stopped_by"]),
            (False, "timeout"))
        chk("...and its real mechanism is carried, not invented",
            entry["technique"], "chromedriver-rce")
    else:
        print("NOTE  6a3a84822b07 is not on this host — end-to-end pair skipped")
else:
    print("NOTE  no live job corpus on this host — 4 disk-backed checks skipped")

print("")
print("%d checks, %d failed" % (checks, fails))
sys.exit(1 if fails else 0)
