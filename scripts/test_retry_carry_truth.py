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

WHAT `carried` HAS TO MEAN

Not "a work/ directory exists" — "the carry will deliver files". Those come
apart in two ways, both reachable and both reproduced here against the real
`_resubmit`:

  * The carry drops every name in `_CARRY_WORK_IGNORE_NAMES`, and `work/tmp`
    is created eagerly when the agent environment is built. A job that wrote
    nothing else leaves a work/ that exists and carries nothing.
  * `_resubmit` plants `_STALE_DO_NOT_WRITE_HERE.md` in the PARENT's work/ on
    its way out. Retry the same parent a second time and an unfiltered count
    sees that marker as a file worth carrying — while the same `_resubmit`
    deletes it from the child. Measured before the exclusion was written:
    round 1 said False and delivered nothing; round 2 said True and delivered
    nothing.

So the wiring check is a three-column truth table (real file / only ignored
names / no work/ at all), and the premise block additionally asserts that
`_carry_will_deliver` agrees with what the real copytree actually left behind.

WHAT THE MUTATIONS COVER

Twelve, each of which must produce a NAMED check failure rather than an
aborted run: the four original wiring/wording reversals, plus
`existence-only` (the helper reverts to `is_dir()`), `name-filter-only` (it
re-derives the rule from names instead of calling `_carry_work_ignore`, and
so misses the FIFO/device-node half), `count-sentinel` (the marker counts as
cargo), `promise-marker` (a marker is promised where none is ever written),
`jsonl-work-key` (the transcript is keyed on a cwd the agent never had), and
`false-cwd-desc` / `false-carry-limits`, which restore the sentences 7655809
left standing — the block that called the job root a work tree, cited
`<prev>/work/exploit.py` as the predecessor's write, said the cwd came along,
and pointed installs at a work tree that does not exist.

The marker one is the same shape as the rest. `_drop_stale_sentinel` runs
inside the copytree branch, so a prior job with no `work/` never gets one,
and after a real job-root retry the parent holds findings.json, meta.json and
report.md — nothing else. An agent told to expect a marker, that `ls`es and
finds none, reads the directory as still live.
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
    "existence-only",     # carried= goes back to "a work/ dir exists"
    "false-cwd-desc",     # stale-path block calls the job root a work tree
    "false-carry-limits", # CARRIED-vs-NOT says the cwd came along
    "count-sentinel",     # the stale marker counts as a file worth carrying
    "promise-marker",     # a marker is promised where none is ever written
    "jsonl-work-key",     # transcript keyed on a cwd the agent never had
    "name-filter-only",   # the rule is re-derived from names, not called
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
        '    _cwd_desc = "work tree" if carried else "directory"\n'
        '    _carry_note = (',
        '    carried = True  # MUTATION\n'
        '    _cwd_desc = "work tree" if carried else "directory"\n'
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

elif args.mutate == "existence-only":
    # The defect this replaced: `carried` was a directory-existence test while
    # the carry filters its contents, so a work/ holding only tmp/ promised
    # files the child never received.
    _mutated_src = replace_once(
        _mutated_src,
        '    prev_work = prev_jd / "work"\n'
        '    if not prev_work.is_dir():\n'
        '        return False\n'
        '    try:\n'
        '        names = [p.name for p in prev_work.iterdir()]\n'
        '    except OSError:\n'
        '        return False\n'
        '    dropped = set(_carry_work_ignore(str(prev_work), names))\n'
        '    dropped.add(_STALE_SENTINEL_NAME)\n'
        '    return any(n not in dropped for n in names)\n',
        '    return (prev_jd / "work").is_dir()  # MUTATION\n',
    )
elif args.mutate == "name-filter-only":
    # _carry_work_ignore also lstats and drops device nodes, FIFOs and
    # sockets. A name-set reimplementation calls a work/ holding one FIFO a
    # delivery, and goes on being wrong every time that filter grows.
    _mutated_src = replace_once(
        _mutated_src,
        '    dropped = set(_carry_work_ignore(str(prev_work), names))\n',
        '    dropped = set(_CARRY_WORK_IGNORE_NAMES)  # MUTATION\n',
    )
elif args.mutate == "jsonl-work-key":
    # The transcript is indexed by project_key_for_directory(cwd). Keying a
    # job-root module on <job>/work looks under a key nothing was ever
    # written to, so the copy no-ops and fork_session finds nothing.
    _mutated_src = replace_once(
        _mutated_src,
        '            if prev_work.is_dir():\n'
        '                _carry_session_jsonl(prev_sid, prev_work, new_jd / "work")\n'
        '            else:\n'
        '                _carry_session_jsonl(prev_sid, prev_jd, new_jd)',
        '            _carry_session_jsonl(prev_sid, prev_work,  # MUTATION\n'
        '                                 new_jd / "work")',
    )
elif args.mutate == "promise-marker":
    # _drop_stale_sentinel runs inside the copytree branch, so a prior job
    # with no work/ never gets a marker. Promising one makes the agent read
    # an unmarked directory as still live.
    _mutated_src = replace_once(
        _mutated_src,
        '        stale_marker_note="",',
        '        stale_marker_note=("; you\'ll find a "  # MUTATION\n'
        '                           "`_STALE_DO_NOT_WRITE_HERE.md` marker if "\n'
        '                           "you `ls` it"),',
    )
elif args.mutate == "count-sentinel":
    # The first retry plants the sentinel in the parent's work/; counting it
    # makes the SECOND retry of that parent promise a carry that arrives
    # empty, since _resubmit deletes the sentinel from the child.
    _mutated_src = replace_once(
        _mutated_src,
        '    dropped.add(_STALE_SENTINEL_NAME)\n',
        '    pass  # MUTATION - sentinel counts as cargo\n',
    )
elif args.mutate == "false-cwd-desc":
    _mutated_src = replace_once(
        _mutated_src,
        '        cwd_desc="the new job\'s directory",',
        '        cwd_desc="the new job\'s work tree",  # MUTATION',
    )
    _mutated_src = replace_once(
        _mutated_src,
        '        stale_example="/data/jobs/%s/report.md" % prev_id,',
        '        stale_example="/data/jobs/%s/work/exploit.py" % prev_id,  # MUT',
    )
elif args.mutate == "false-carry-limits":
    _mutated_src = replace_once(
        _mutated_src,
        '    return _CARRY_LIMITS_NOTE_TMPL.format(\n'
        '        what_came=("the prior conversation came with you (unless stated "\n'
        '                   "otherwise above); your cwd did NOT — no files were "\n'
        '                   "carried, as said above"),\n'
        '        install_target="your cwd",\n'
        '    )',
        '    return _CARRY_LIMITS_NOTE_TMPL.format(  # MUTATION\n'
        '        what_came=("your cwd and (unless stated otherwise above) the "\n'
        '                   "prior conversation came with you"),\n'
        '        install_target="the work tree",\n'
        '    )',
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
        '            carried=_carry_will_deliver(jd))',
        '        augmented = _retry_preamble(\n'
        '            safe, hint, fresh=fresh_session,\n'
        '            operator_text=manual_hint is not None,\n'
        '            history=_carry_technique_history(prev_meta, jd),\n'
        '            carried=not _carry_will_deliver(jd))  # MUTATION',
    )
elif args.mutate == "drop-callsite":
    _wiring_src = replace_once(
        _wiring_src,
        '        history=_carry_technique_history(prev_meta, jd),\n'
        '        carried=_carry_will_deliver(jd))',
        '        history=_carry_technique_history(prev_meta, jd))  # MUTATION',
    )


# ---------------------------------------------------------------- the premise
print("--- the carry really does copy nothing without work/ " + "-" * 12)


def make_job(job_id: str, *, with_work: bool, only_ignored: bool = False):
    jd = Path(os.environ["JOBS_DIR"]) / job_id
    jd.mkdir(parents=True, exist_ok=True)
    meta = {"id": job_id, "module": "misc", "status": "no_flag",
            "description": "d", "filename": "f.zip"}
    (jd / "meta.json").write_text(json.dumps(meta))
    # An artifact the agent authored, in whichever place this module puts it.
    if with_work and only_ignored:
        # Reachable, not hypothetical: `work/tmp` is created eagerly when the
        # agent environment is built, so a job that wrote nothing else leaves
        # a work/ that exists and carries nothing.
        (jd / "work").mkdir(exist_ok=True)
        for _name in sorted(RT._CARRY_WORK_IGNORE_NAMES):
            _p = jd / "work" / _name
            if _name.startswith("."):
                _p.write_text("x")
            else:
                _p.mkdir(exist_ok=True)
                (_p / "junk.txt").write_text("junk")
    elif with_work:
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

    pm_ign, pj_ign = make_job("cccccccccccc", with_work=True, only_ignored=True)
    # _resubmit plants the stale sentinel in the PARENT's work/, so the parent
    # listing has to be taken before the call, not after.
    pre_ign = sorted(p.name for p in (pj_ign / "work").iterdir())
    child_ign = RT._resubmit(pm_ign, "hint", pj_ign, carry_work=True)
    child_ign_jd = Path(os.environ["JOBS_DIR"]) / child_ign

    # Retry the SAME parent a second time. This is the ordinary case - the
    # operator retries a job, it fails again, they retry it again - and the
    # sentinel the first retry left behind is sitting in the parent's work/
    # when the second one computes `carried`.
    pm_two, pj_two = make_job("dddddddddddd", with_work=True, only_ignored=True)
    two_rounds = []
    for _round in (1, 2):
        _said = RT._carry_will_deliver(pj_two)
        _c = RT._resubmit(dict(pm_two), "hint", pj_two, carry_work=True)
        _cw = Path(os.environ["JOBS_DIR"]) / _c / "work"
        two_rounds.append((_said, _cw.is_dir() and any(_cw.iterdir())))
    sentinel_in_parent = (pj_two / "work" / RT._STALE_SENTINEL_NAME).is_file()
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
check("a parent whose work/ holds only ignored names delivers an empty tree",
      sorted(p.name for p in (child_ign_jd / "work").iterdir())
      if (child_ign_jd / "work").is_dir() else [], [])
check("...and that parent's work/ really did exist and hold entries",
      pre_ign, sorted(RT._CARRY_WORK_IGNORE_NAMES))

# Reproduced live before this was written: round 1 answered False and
# delivered nothing; round 2 answered True and still delivered nothing,
# because round 1 had dropped _STALE_DO_NOT_WRITE_HERE.md into the parent and
# round 2 counted it as a file worth carrying. _resubmit deletes that file
# from the child (retry.py:465), so it is never something the child receives.
check("the first retry really does leave the stale sentinel in the parent",
      sentinel_in_parent)

# The transcript is looked up by project_key_for_directory(cwd), and BOTH key
# shapes exist side by side in the live ~/.claude/projects (the worker's
# /root/.claude bind mount) — `-data-jobs-<id>` for a job-root agent and
# `-data-jobs-<id>-work` for a work-tree one. So the pair of directories
# handed to _carry_session_jsonl has to be the pair the agents actually ran
# in, or the source lookup misses, the copy no-ops in silence, and
# fork_session=True has nothing to find. 760a011 proved the field is READ;
# it did not prove the transcript is FINDABLE.
_spy: list = []
_real_jsonl = RT._carry_session_jsonl
RT._carry_session_jsonl = lambda sid, p, n: _spy.append((str(p), str(n)))
RT.get_queue = lambda: _Q()
try:
    _pm_r, _pj_r = make_job("111111111111", with_work=False)
    _pm_r["agent_provider"] = "claude"
    _pm_r["claude_session_id"] = "sid-root"
    _c_r = Path(os.environ["JOBS_DIR"]) / RT._resubmit(
        _pm_r, "hint", _pj_r, carry_work=True)

    _pm_w, _pj_w = make_job("222222222222", with_work=True)
    _pm_w["agent_provider"] = "claude"
    _pm_w["claude_session_id"] = "sid-work"
    _c_w = Path(os.environ["JOBS_DIR"]) / RT._resubmit(
        _pm_w, "hint", _pj_w, carry_work=True)
finally:
    RT._carry_session_jsonl = _real_jsonl
    RT.get_queue = _real_queue

check("both retries tried to carry the transcript", len(_spy), 2)
check("a job-root module keys the transcript on the job dirs it ran in",
      _spy[0] if _spy else None, (str(_pj_r), str(_c_r)))
check("a work-tree module still keys it on the work trees",
      _spy[1] if len(_spy) > 1 else None,
      (str(_pj_w / "work"), str(_c_w / "work")))
check("retrying the SAME parent twice tells the truth both times - "
      "the sentinel is not a delivered file",
      two_rounds, [(False, False), (False, False)])

# The point of the helper is to answer the question the copytree above just
# answered in fact. Pin it to the observed delivery, not to a description of
# the filter: an existence test agrees on the outer two rows and only parts
# company on the middle one.
for _label, _pjd, _cjd in (("no work/", pj_no, child_no_jd),
                           ("work/ with a real file", pj_yes, child_yes_jd),
                           ("work/ with only ignored names", pj_ign,
                            child_ign_jd)):
    _cw = _cjd / "work"
    _delivered = _cw.is_dir() and any(_cw.iterdir())
    check(f"_carry_will_deliver agrees with the real carry - {_label}",
          RT._carry_will_deliver(_pjd), _delivered)


# ------------------------------------------------------------- the wording
print("")
print("--- the preamble tells the truth about what it carried " + "-" * 10)

_COPIED = "COPIED into"
_CWD_IS_WORK = "your cwd is already the new job's work tree"
_INSTALL_WORK = "prefer installing into the work tree"
_CWD_CAME = "your cwd and (unless stated otherwise above)"
_CONV_CAME = "the prior conversation came with you"
_MARKER_PROMISE = "_STALE_DO_NOT_WRITE_HERE.md` marker if you `ls` it"
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

        # 7655809 fixed the sentences it was written for and left four more
        # standing. Each of these was rendered, verbatim, to a job-root agent
        # in the same message that told it nothing had been carried.
        check(f"{tag} carried=False does not call the job root a work tree",
              _CWD_IS_WORK in bare_txt, False)
        check(f"{tag} carried=False does not send installs to a work tree",
              _INSTALL_WORK in bare_txt, False)
        check(f"{tag} carried=False does not claim the cwd came along",
              _CWD_CAME in bare_txt, False)
        check(f"{tag} carried=False cites no work/ path as the stale example",
              "/work/exploit.py" in bare_txt, False)
        # Verified against the real _resubmit: after a job-root retry the
        # parent holds findings.json, meta.json and report.md - and no
        # marker, because _drop_stale_sentinel sits inside the copytree
        # branch. An agent told to expect one, that `ls`es and finds none,
        # concludes the directory is still live.
        check(f"{tag} carried=False promises no stale marker",
              _MARKER_PROMISE in bare_txt, False)
        check(f"{tag} carried=True still promises the marker it does write",
              _MARKER_PROMISE in carried_txt)
        # ...and the half that IS true has to survive: 760a011 wired
        # resume/fork_session into misc and forensic, so every module really
        # does inherit the conversation. Deleting this sentence would be a
        # second lie in the other direction.
        check(f"{tag} carried=False still says the conversation came with it",
              _CONV_CAME in bare_txt)
        check(f"{tag} carried=True keeps the work-tree cwd sentence",
              _CWD_IS_WORK in carried_txt)
        check(f"{tag} carried=True keeps the work-tree install advice",
              _INSTALL_WORK in carried_txt)


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
# Three columns, not two. `carried` has to mean "the carry will deliver
# files", not "a directory exists": the carry drops every name in
# _CARRY_WORK_IGNORE_NAMES, and `work/tmp` is created eagerly when the agent
# environment is built — so a work/ whose only entries are ignored is
# reachable, and under an existence test the child was promised a tree that
# arrived empty. The middle column is the one an `is_dir()` fails.
_probe = Path(_TMP.name) / "wiring"
_with_work = _probe / "haswork"
(_with_work / "work").mkdir(parents=True, exist_ok=True)
(_with_work / "work" / "exploit.py").write_text("# carried\n")
_ignored_only = _probe / "ignoredonly"
for _n in sorted(RT._CARRY_WORK_IGNORE_NAMES):
    (_ignored_only / "work" / _n).mkdir(parents=True, exist_ok=True)
# A fourth column for the half of the filter that is not a name set: the
# copy lstats each entry and drops FIFOs, sockets and device nodes — the
# class that once blocked copytree's open() and froze uvicorn's event loop.
_fifo_only = _probe / "fifoonly"
(_fifo_only / "work").mkdir(parents=True, exist_ok=True)
_have_fifo = True
try:
    os.mkfifo(str(_fifo_only / "work" / "pipe"))
except (OSError, AttributeError):
    _have_fifo = False

_no_work = _probe / "nowork"
_no_work.mkdir(parents=True, exist_ok=True)

_EVAL_GLOBALS = {**RT.__dict__, "Path": Path}
_COLUMNS = [("work/ with a real file", _with_work, True),
            ("work/ with only ignored names", _ignored_only, False),
            ("no work/ at all", _no_work, False)]
if _have_fifo:
    _COLUMNS.insert(2, ("work/ with only a FIFO", _fifo_only, False))
_COLUMNS = tuple(_COLUMNS)
check("the FIFO column is actually exercised", _have_fifo)

_correct = 0
_wrong = []
for c in _with_carried:
    kw = next(k for k in c.keywords if k.arg == "carried")
    txt = ast.unparse(kw.value)
    try:
        got = [bool(eval(txt, dict(_EVAL_GLOBALS), {"jd": d}))
               for _lbl, d, _want in _COLUMNS]
    except Exception as exc:  # noqa: BLE001
        _wrong.append((c.lineno, txt, f"raised {type(exc).__name__}"))
        continue
    if got == [w for _lbl, _d, w in _COLUMNS]:
        _correct += 1
    else:
        _wrong.append((c.lineno, txt, "; ".join(
            f"{lbl}->{g}(want {w})"
            for (lbl, _d, w), g in zip(_COLUMNS, got) if g is not w)))

check("every carried= actually reports whether the carry will deliver files "
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
