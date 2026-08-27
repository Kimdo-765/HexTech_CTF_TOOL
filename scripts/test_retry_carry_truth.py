#!/usr/bin/env python3
"""A retry preamble must not promise files the carry did not copy.

Run: python3 scripts/test_retry_carry_truth.py [--mutate <name>]

WHAT WENT WRONG

`_resubmit` carries the prior attempt's tree with

    prev_work = prev_jd / "work"
    if prev_work.is_dir():
        shutil.copytree(prev_work, new_jd / "work", ...)

Every module whose agent runs in `<job>/work/` satisfies that. **misc and
forensic do not**: their orchestrators set `work_dir = _job_dir(job_id)` — the
job root itself — so no `work/` directory is ever created and the guard skips
in silence. Observed on the one real forensic retry in the corpus,
b7c25bb93d13 -> 56b4d47d5b4c: neither job has a `work/`, so the child inherited
nothing.

The preamble did not know that. It told the child:

    "...have been COPIED into your cwd at `./`"
    "Your current working directory IS the new job's work tree"

and, worst of all, in the MANDATORY FIRST CALL:

    "If pwd doesn't match `/data/jobs/$JOB_ID/work`, stop and re-orient
     before any further tool call."

A misc/forensic child's pwd is `/data/jobs/$JOB_ID` with no `/work`, so that
condition is ALWAYS true and the agent's opening instruction is to halt.

WHY THE FIX IS WORDING AND NOT COPYING

The tempting fix — carry the job root when there is no `work/` — would move the
parent's `report.md` / `findings.json` into the child. Those two files are the
NARRATIVE tier of `scan_job_for_flags`, and for misc there is no sandbox, so
the narrative tier is effectively the only tier it has. Carrying them would
hand the child its parent's flag text as if the child had found it — the
stale-artifact false success this repository has already been bitten by. So
the carry is left alone and the preamble is made to tell the truth instead.

WHY THIS IS NOT A TAUTOLOGY

The wording checks drive the real `_retry_preamble` / `_resume_preamble` from
`api/routes/retry.py`. The premise underneath them — that the carry really does
copy nothing when there is no `work/` — is established by running the real
`_resubmit` against real temp job trees, both with and without one. And the
call sites are checked by AST, because a builder that accepts `carried` proves
nothing if no caller ever passes it.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

MUTATIONS = (
    "none",
    "always-carried",     # builders ignore carried= and act as if True
    "hardcode-work-pwd",  # stale-path block asserts /work unconditionally
    "drop-callsite",      # one call site stops passing carried=
    "invert-streaming",   # the UI's own retry route reports the opposite
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS, default="none")
args = parser.parse_args()

passed = 0
failed = 0


def check(label: str, got, want=True, *, detail=None) -> None:
    """Compare got to want. Diagnostics go in `detail`, never in `want`."""
    global passed, failed
    if got == want:
        passed += 1
        print(f"PASS  {label}")
    else:
        failed += 1
        print(f"FAIL  {label}\n      got  = {got!r}\n      want = {want!r}"
              + (f"\n      detail = {detail!r}" if detail is not None else ""))


def replace_once(source: str, old: str, new: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(
            f"mutation anchor count is {count}, expected 1: {old[:60]!r}")
    return source.replace(old, new, 1)


# --------------------------------------------------------------- environment
_TMP = tempfile.TemporaryDirectory(prefix="carry-truth-")
DATA = Path(_TMP.name)
(DATA / "jobs").mkdir()
os.environ.update(DATA_DIR=str(DATA), JOBS_DIR=str(DATA / "jobs"),
                  SETTINGS_PATH=str(DATA / "settings.json"))
(DATA / "settings.json").write_text("{}")


def _stub_fastapi() -> None:
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
    """`api.queue` reaches for redis/rq at import; neither is under test.

    A bare empty module is not enough: `api/queue.py` does
    `from redis import Redis`, so the stub has to answer attribute access.
    Same _Any stand-in as scripts/test_lineage_technique_carry.py.
    """
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
    import importlib.util
    try:
        if importlib.util.find_spec("pydantic") is not None:
            return
    except (ImportError, ValueError):
        pass
    if "pydantic" in sys.modules:
        return
    m = types.ModuleType("pydantic")

    class BaseModel:
        def __init__(self, **kw):
            for k, v in kw.items():
                setattr(self, k, v)

    m.BaseModel = BaseModel
    m.Field = lambda *a, **k: (k.get("default_factory") or (lambda: None))()
    sys.modules["pydantic"] = m


def _stub_sdk() -> None:
    """Stub claude_agent_sdk ONLY when genuinely absent.

    `find_spec`, not `name not in sys.modules`: the latter is true at startup
    even where the library exists, so it would install a stub over a working
    install and this suite would never exercise the real import path. Same
    rule as scripts/test_lineage_technique_carry.py.
    """
    import importlib.util
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

    async def _query(*a, **k):  # pragma: no cover - never called here
        if False:
            yield None

    sdk.query = _query
    sys.modules["claude_agent_sdk"] = sdk


_stub_fastapi()
_stub_queue()
_stub_pydantic()
_stub_sdk()

import api.routes.retry as RT  # noqa: E402

RETRY_SRC_PATH = ROOT / "api" / "routes" / "retry.py"
RETRY_SRC = RETRY_SRC_PATH.read_text()

# ------------------------------------------------------------------ mutation
_mutated_src = RETRY_SRC
if args.mutate == "always-carried":
    _mutated_src = replace_once(
        _mutated_src,
        '    _cwd_desc = "work tree" if carried else "job directory"\n'
        '    _carry_note = (',
        '    carried = True  # MUTATION\n'
        '    _cwd_desc = "work tree" if carried else "job directory"\n'
        '    _carry_note = (',
    )
elif args.mutate == "hardcode-work-pwd":
    _mutated_src = replace_once(
        _mutated_src,
        '    return _STALE_PATH_WARNING_TMPL.format(\n'
        '        prev_id=prev_id,\n'
        '        pwd_expect="/data/jobs/$JOB_ID",',
        '    return _STALE_PATH_WARNING_TMPL.format(\n'
        '        prev_id=prev_id,\n'
        '        pwd_expect="/data/jobs/$JOB_ID/work",  # MUTATION',
    )

if _mutated_src is not RETRY_SRC:
    exec(compile(_mutated_src, str(RETRY_SRC_PATH), "exec"), RT.__dict__)

# The AST wiring check reads this text, so the call-site mutations edit it.
_wiring_src = RETRY_SRC
if args.mutate == "invert-streaming":
    # The streaming route, not the direct one: retry.py:1120 records that the
    # UI's manual retry lands there. An audit inverted exactly this site and
    # the suite stayed 45/0, which is why the wiring check now evaluates the
    # expression instead of reading it.
    # The anchor has to name _retry_preamble: the streaming retry and the
    # streaming resume sites are otherwise byte-identical, and a two-match
    # anchor aborts the run instead of testing the property.
    _wiring_src = replace_once(
        _wiring_src,
        '        augmented = _retry_preamble(\n'
        '            safe, hint, fresh=fresh_session,\n'
        '            operator_text=manual_hint is not None,\n'
        '            history=_carry_technique_history(prev_meta, jd),\n'
        '            carried=(jd / "work").is_dir())',
        '        augmented = _retry_preamble(\n'
        '            safe, hint, fresh=fresh_session,\n'
        '            operator_text=manual_hint is not None,\n'
        '            history=_carry_technique_history(prev_meta, jd),\n'
        '            carried=not (jd / "work").is_dir())  # MUTATION',
    )
elif args.mutate == "drop-callsite":
    _wiring_src = replace_once(
        _wiring_src,
        '        history=_carry_technique_history(prev_meta, jd),\n'
        '        carried=(jd / "work").is_dir())',
        '        history=_carry_technique_history(prev_meta, jd))  # MUTATION',
    )


# ---------------------------------------------------------------- the premise
print("--- the carry really does copy nothing without work/ " + "-" * 12)


def make_job(job_id: str, *, with_work: bool):
    jd = Path(os.environ["JOBS_DIR"]) / job_id
    jd.mkdir(parents=True, exist_ok=True)
    meta = {"id": job_id, "module": "misc", "status": "no_flag",
            "description": "d", "filename": "f.zip"}
    (jd / "meta.json").write_text(json.dumps(meta))
    # An artifact the agent authored, in whichever place this module puts it.
    if with_work:
        (jd / "work").mkdir(exist_ok=True)
        (jd / "work" / "notes.txt").write_text("prior")
    else:
        (jd / "notes.txt").write_text("prior")
    return meta, jd


class _Q:
    def enqueue(self, *a, **k):
        return None


_real_queue = RT.get_queue
RT.get_queue = lambda: _Q()
try:
    pm_no, pj_no = make_job("aaaaaaaaaaaa", with_work=False)
    child_no = RT._resubmit(pm_no, "hint", pj_no, carry_work=True)
    child_no_jd = Path(os.environ["JOBS_DIR"]) / child_no

    pm_yes, pj_yes = make_job("bbbbbbbbbbbb", with_work=True)
    child_yes = RT._resubmit(pm_yes, "hint", pj_yes, carry_work=True)
    child_yes_jd = Path(os.environ["JOBS_DIR"]) / child_yes
finally:
    RT.get_queue = _real_queue

check("a parent WITH work/ carries it to the child",
      (child_yes_jd / "work" / "notes.txt").is_file())
check("a parent WITHOUT work/ carries NOTHING - the guard skips in silence",
      (child_no_jd / "work").exists(), False)
check("...and the artifact really was there to miss",
      (pj_no / "notes.txt").is_file())
check("the carry does not fall back to the job root either",
      (child_no_jd / "notes.txt").exists(), False)


# ------------------------------------------------------------- the wording
print("")
print("--- the preamble tells the truth about what it carried " + "-" * 10)

_COPIED = "COPIED into"
_WORK_PWD = "If pwd doesn't match `/data/jobs/$JOB_ID/work`"
_ROOT_PWD = "If pwd doesn't match `/data/jobs/$JOB_ID`"

for builder_name in ("_retry_preamble", "_resume_preamble"):
    builder = getattr(RT, builder_name)
    for fresh in (False, True):
        tag = f"{builder_name}(fresh={fresh})"

        carried_txt = builder("pppppppppppp", "HINT", fresh=fresh, carried=True)
        bare_txt = builder("pppppppppppp", "HINT", fresh=fresh, carried=False)

        check(f"{tag} carried=True still says the tree was copied",
              _COPIED in carried_txt)
        check(f"{tag} carried=True still anchors pwd on the work tree",
              _WORK_PWD in carried_txt)
        check(f"{tag} carried=False never claims files were copied",
              _COPIED in bare_txt, False)
        check(f"{tag} carried=False says so in words",
              "NOT carried" in bare_txt or "NOTHING" in bare_txt)
        # The instruction-to-halt. `_WORK_PWD` is `_ROOT_PWD` plus "/work`",
        # so assert the exact /work form is absent.
        check(f"{tag} carried=False does NOT order the agent to stop on pwd",
              _WORK_PWD in bare_txt, False)
        check(f"{tag} carried=False anchors pwd on the job dir instead",
              _ROOT_PWD in bare_txt)
        check(f"{tag} carried=False tells it there is no ./work/",
              "NO `./work/` subdirectory" in bare_txt)
        check(f"{tag} carried=False keeps the hint", "HINT" in bare_txt)
        check(f"{tag} carried=False keeps the stale-path rules",
              "bare names" in bare_txt)


# ------------------------------------------------------------------- wiring
print("")
print("--- every caller actually computes it from disk " + "-" * 17)

_tree = ast.parse(_wiring_src)
_calls = [n for n in ast.walk(_tree)
          if isinstance(n, ast.Call)
          and getattr(n.func, "id", "") in ("_retry_preamble", "_resume_preamble")]
check("all four preamble call sites are present", len(_calls), 4)

_with_carried = [c for c in _calls
                 if any(k.arg == "carried" for k in c.keywords)]
check("every call site passes carried=", len(_with_carried), 4)

# EVALUATE the expression, do not pattern-match it. The previous version of
# this check asked whether ast.unparse(...) contained "is_dir()" and "work",
# which `not (jd / "work").is_dir()` also satisfies - so an inverted call site
# reproduced the exact bug this file guards and still scored 45/0. It also
# slipped the literal check, because ast.UnaryOp is not ast.Constant.
#
# A truth table cannot be talked around: with a work/ present the expression
# must say True, without one it must say False. Inversion fails the first,
# constants fail one or the other, and anything reading a different path fails
# both.
_probe = Path(_TMP.name) / "wiring"
_with_work = _probe / "haswork"
(_with_work / "work").mkdir(parents=True, exist_ok=True)
_no_work = _probe / "nowork"
_no_work.mkdir(parents=True, exist_ok=True)

_correct = 0
_wrong = []
for c in _with_carried:
    kw = next(k for k in c.keywords if k.arg == "carried")
    txt = ast.unparse(kw.value)
    try:
        got_yes = bool(eval(txt, {"Path": Path}, {"jd": _with_work}))
        got_no = bool(eval(txt, {"Path": Path}, {"jd": _no_work}))
    except Exception as exc:  # noqa: BLE001
        _wrong.append((c.lineno, txt, f"raised {type(exc).__name__}"))
        continue
    if got_yes is True and got_no is False:
        _correct += 1
    else:
        _wrong.append((c.lineno, txt, f"work/->{got_yes} none->{got_no}"))

check("every carried= actually reports whether the prior job has a work/ "
      "- evaluated, not pattern-matched",
      _correct, 4, detail=_wrong)
check("no call site's expression has the wrong truth table", _wrong, [])

_literal = [c for c in _with_carried
            if isinstance(next(k for k in c.keywords if k.arg == "carried").value,
                          ast.Constant)]
check("no call site hardcodes carried=", len(_literal), 0)

print("")
print(f"retry-carry-truth: {passed} passed, {failed} failed; mutation={args.mutate}")
sys.exit(1 if failed else 0)
