#!/usr/bin/env python3
"""Every module that can take a remote target actually consumes one.

misc and forensic were the last two modules with no target field at all. Adding
the form field is the easy half; the half that has gone wrong before (the web
`docker_challenge` round) is wiring a value into meta that nothing downstream
reads, so the box writes `true` and the agent behaves identically.

So the oracles here CALL things:

  * `build_target_directive` is invoked, not grepped — including a byte-for-byte
    comparison of the default path against the text the five pre-existing
    modules were already getting, because that default is shared and a
    regression there is silent.
  * The two route handlers are invoked with a duck-typed upload, and the meta
    they write is read back off disk.
  * The prompt assembly is invoked: the real statements of `_claude_summary`
    are lifted out of the orchestrator source and EXECUTED with the module's
    own `build_target_directive`, so the assertion is on the string a job would
    actually receive. Deleting the append, reading the wrong meta key, or
    passing script_driven=True all turn that string wrong.
  * The Change-target gate is evaluated by node against the real declarations
    lifted out of app.js, per module.

`--mutate` applies one semantic break so the suite can be shown to fail; a
green run with every mutant red is the only evidence these checks bite.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
import traceback
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

MUTATIONS = (
    "none",
    "drop-misc-route-field",        # route stops accepting the form field
    "drop-forensic-persistence",    # accepted but never written to meta
    "shadow-forensic-image-path",   # the old local name clobbers the target
    "shadow-misc-image-path",       # same shadow, misc side
    "drop-misc-injection",          # meta has it, prompt never gets it
    "script-driven-forensic",       # wrong directive variant for a runner-less module
    "read-wrong-meta-key",          # injection present but pointed at nothing
    "drop-retry-target-carry",      # child meta loses the target on rebuild
    "clobber-forensic-retry-target",# module branch patches meta after the literal
    "typo-misc-data-field",         # form points at a param the route lacks
    "drop-form-extraction",         # typed target never reaches FormData
    "ungate-change-target",         # inert Change Target button returns for misc
    "keep-rejected-job-dir",        # 400 leaves an orphan data/jobs/<id>/
    "pwn-data-field-description",   # bound to another VALID param, not `target`
    "misc-primary-off-by-one",      # early IndexError in primary selection (CRASH)
    "drop-forensic-injection",      # forensic meta has it, prompt never gets it
    "prefer-description-when-both",  # both file+description: precedence flip in _prompts
    "composite-crash-mask",         # early crash + downstream defect together
    "break-prompts-compile",        # section-1 compile fails: HARNESS ABORT, not red
)
# The last six extend the original twelve. The first four are ordinary
# assertion-red mutants; `composite-crash-mask` combines an early crash with a
# downstream defect (F1's masking case); `break-prompts-compile` is the
# deliberate HARNESS-ABORT case that keeps the sweep's crash/red discriminator
# from being vacuous. See _run_sweep.
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS, default="none")
ap.add_argument("--sweep", action="store_true",
                help="run every mutant and verify each is caught via "
                     "assertion-red (summary reached), not a bare crash")
ARGS = ap.parse_args()


def _run_sweep() -> int:
    """The mutation runner.

    Every mutant must end ASSERTION-RED VIA THE SUMMARY — exit 1 with an
    ``N checks, M>0 failed`` line — never a bare harness crash (no summary).
    A sweep that equated any non-zero exit with "caught" would be fooled by a
    mutation that merely CRASHED before the downstream oracles ran: that is the
    exact false success F1 is about. So the runner keys off the SUMMARY LINE,
    not the exit code, and one deliberate compile-break mutant proves the
    crash/red discriminator is not vacuous.
    """
    summary_re = re.compile(r"(\d+) checks, (\d+) failed")
    # node-less environments SKIP the app.js gate/extract oracles, so the two
    # mutations only those oracles catch cannot be swept here. Detect once.
    try:
        _n = subprocess.run(["node", "-e", ""], capture_output=True)
        have_node = _n.returncode == 0
    except (FileNotFoundError, OSError):
        have_node = False
    node_only = {"drop-form-extraction", "ungate-change-target"}

    abort = {"break-prompts-compile"}
    red = [m for m in MUTATIONS if m != "none" and m not in abort]
    expect = {"none": "green"}
    expect.update({m: "assertion-red" for m in red})
    expect.update({m: "aborted" for m in abort})

    ok = True
    order = ["none", *red, *sorted(abort)]
    for mut in order:
        if not have_node and mut in node_only:
            print(f"SKIP  sweep[{mut}] — node unavailable for its only oracle")
            continue
        res = subprocess.run([sys.executable, __file__, "--mutate", mut],
                             capture_output=True, text=True)
        out = res.stdout + res.stderr
        m = summary_re.search(out)
        if m is None:
            kind = "aborted" if "HARNESS ABORT" in out else "no-summary"
        else:
            failed = int(m.group(2))
            if res.returncode == 0 and failed == 0:
                kind = "green"
            elif res.returncode == 1 and failed > 0:
                kind = "assertion-red"
            else:
                kind = f"inconsistent(exit={res.returncode},failed={failed})"
        want = expect[mut]
        good = kind == want
        detail = ""
        # The composite mutant must report BOTH defects AND reach the summary:
        # the early misc crash (now a named failure) and the downstream forensic
        # prompt loss, proving neither masks the other any more.
        if mut == "composite-crash-mask" and good:
            crash = "IndexError" in out
            downstream = ("forensic: a targeted job's prompt names the target"
                          in out)
            summary = m is not None
            if not (crash and downstream and summary):
                good = False
                detail = (f" [crash={crash} downstream={downstream} "
                          f"summary={summary}]")
        ok = ok and good
        print(f"{'PASS' if good else 'FAIL'}  sweep[{mut}] -> {kind} "
              f"(want {want}){detail}")
    print(f"\nsweep: {'every mutant classified as expected' if ok else 'MISCLASSIFICATION — a mutant did not bite'}")
    return 0 if ok else 1


if ARGS.sweep:
    sys.exit(_run_sweep())


_TMP = tempfile.TemporaryDirectory(prefix="target-all-")
DATA = Path(_TMP.name)
(DATA / "jobs").mkdir()
SETTINGS = DATA / "settings.json"
SETTINGS.write_text(json.dumps({"agent_provider": "claude"}))
os.environ.update(
    DATA_DIR=str(DATA),
    SETTINGS_PATH=str(SETTINGS),
    JOBS_DIR=str(DATA / "jobs"),
)

PASSED = FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


class guard:
    """Absorb an exception from ONE scenario as a named FAILURE and keep going.

    Without this, a mutation (or a real bug) that RAISES mid-suite aborts every
    later check AND the final summary. A crash and an assertion miss then look
    identical to an exit-code-only mutation sweep — the false success F1 exists
    to prevent. A guarded scenario that raises is counted as a failed check, so
    execution continues to the next scenario and the summary is still printed.

    Only `Exception` is caught — SystemExit / KeyboardInterrupt propagate, and a
    crash OUTSIDE any guard (e.g. section-1 compile of the module under test) is
    an unguarded HARNESS ABORT that _harness_excepthook turns into exit 2 with
    no summary, which is exactly what the sweep must NOT count as caught.
    """

    def __init__(self, label: str):
        self.label = label

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        global FAILED
        if exc_type is None or not issubclass(exc_type, Exception):
            return False
        FAILED += 1
        first = "".join(traceback.format_exception_only(exc_type, exc)).strip()
        print(f"FAIL  {self.label} — raised {first}")
        return True


def _harness_excepthook(exc_type, exc, tb):
    """Any UNGUARDED exception is a harness abort, not an assertion failure.

    It prints a distinct marker and exits 2 with NO summary line, so the sweep's
    summary-keyed oracle classifies it as `aborted` rather than a caught red.
    """
    sys.stdout.flush()
    print(f"HARNESS ABORT — {exc_type.__name__}: {exc}")
    traceback.print_exception(exc_type, exc, tb)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(2)


sys.excepthook = _harness_excepthook


# --------------------------------------------------------------------------
# Sources. Mutations are applied to the TEXT before anything is imported or
# executed, so a mutant exercises a genuinely different program.
# --------------------------------------------------------------------------
SRC = {
    "misc_route": ROOT / "api" / "routes" / "misc_module.py",
    "forensic_route": ROOT / "api" / "routes" / "forensic_module.py",
    "misc_orch": ROOT / "modules" / "misc" / "orchestrator.py",
    "forensic_orch": ROOT / "modules" / "forensic" / "orchestrator.py",
    "prompts": ROOT / "modules" / "_prompts.py",
    "retry": ROOT / "api" / "routes" / "retry.py",
    "pwn_route": ROOT / "api" / "routes" / "pwn_module.py",
    "rev_route": ROOT / "api" / "routes" / "rev_module.py",
    "app_js": ROOT / "web-ui" / "app.js",
    "index_html": ROOT / "web-ui" / "index.html",
}
TEXT = {k: p.read_text() for k, p in SRC.items()}
_ORIG_TEXT = dict(TEXT)

M = ARGS.mutate
if M == "drop-misc-route-field":
    TEXT["misc_route"] = TEXT["misc_route"].replace(
        "    target: Optional[str] = Form(None),\n", "", 1)
    TEXT["misc_route"] = TEXT["misc_route"].replace(
        "    targets = parse_targets(target)\n"
        "    target = targets[0] if targets else None\n",
        "    targets = []\n    target = None\n", 1)
elif M == "drop-forensic-persistence":
    TEXT["forensic_route"] = TEXT["forensic_route"].replace(
        '        "target_url": target,\n'
        '        "target_urls": targets if len(targets) >= 2 else None,\n', "", 1)
elif M == "shadow-forensic-image-path":
    TEXT["forensic_route"] = TEXT["forensic_route"].replace(
        "    image_path = job_dir(job_id) / image_name\n"
        "    size = _stream_to(image_path, file)",
        "    target = job_dir(job_id) / image_name\n"
        "    size = _stream_to(target, file)", 1)
elif M == "shadow-misc-image-path":
    TEXT["misc_route"] = TEXT["misc_route"].replace(
        "        dest = job_dir(job_id) / fname\n"
        "        size = _stream_to(dest, file)",
        "        target = job_dir(job_id) / fname\n"
        "        size = _stream_to(target, file)", 1)
elif M == "drop-misc-injection":
    TEXT["misc_orch"] = TEXT["misc_orch"].replace(
        '    if _tgt_block:\n        prompt = prompt + "\\n\\n" + _tgt_block\n',
        "    if False:\n        pass\n", 1)
elif M == "script-driven-forensic":
    TEXT["forensic_orch"] = TEXT["forensic_orch"].replace(
        "        script_driven=False,\n", "        script_driven=True,\n", 1)
elif M == "read-wrong-meta-key":
    TEXT["misc_orch"] = TEXT["misc_orch"].replace(
        '(_meta_now.get("target_url") or "").strip() or None',
        '(_meta_now.get("target_os") or "").strip() or None', 1)
elif M == "drop-retry-target-carry":
    TEXT["retry"] = TEXT["retry"].replace(
        '        "target_url": target,\n', '        "target_url": None,\n', 1)
elif M == "clobber-forensic-retry-target":
    TEXT["retry"] = TEXT["retry"].replace(
        '        meta["image_type"] = prev_meta.get("image_type")\n',
        '        meta["image_type"] = prev_meta.get("image_type")\n'
        '        meta["target_url"] = None\n', 1)
elif M == "typo-misc-data-field":
    TEXT["index_html"] = TEXT["index_html"].replace(
        '<div class="target-list" data-field="target" '
        'data-placeholder="ctf.example.com:1337">',
        '<div class="target-list" data-field="target_url" '
        'data-placeholder="ctf.example.com:1337">', 1)
elif M == "drop-form-extraction":
    TEXT["app_js"] = TEXT["app_js"].replace(
        "fd.set(tlist.dataset.field, vals.join(\"\\n\"));",
        "fd.set(tlist.dataset.field, \"\");", 1)
elif M == "keep-rejected-job-dir":
    for _k in ("misc_route", "forensic_route", "pwn_route", "rev_route"):
        TEXT[_k] = TEXT[_k].replace(
            "reject_job(job_id, 400,", "_keep_and_raise(job_id, 400,")
elif M == "ungate-change-target":
    TEXT["app_js"] = TEXT["app_js"].replace(
        "const showChangeTarget = hasTarget && canRetry;",
        "const showChangeTarget = hasTarget;", 1)
elif M == "pwn-data-field-description":
    # Codex's semantic mutation: bind the target list to another VALID Form
    # param (`description`). The AST "is it a real Form param" check accepts it;
    # only the exact-field oracle ("bound to `target`") rejects it. The first
    # `data-field="target"` with this placeholder is pwn's panel.
    TEXT["index_html"] = TEXT["index_html"].replace(
        '<div class="target-list" data-field="target" '
        'data-placeholder="ctf.example.com:1337">',
        '<div class="target-list" data-field="description" '
        'data-placeholder="ctf.example.com:1337">', 1)
elif M == "misc-primary-off-by-one":
    # A plausible off-by-one in primary selection. For any non-empty target
    # list it raises IndexError INSIDE analyze_misc — a CRASH, not an assertion
    # miss. Per-scenario guards turn it into a named failure so the summary is
    # still reached (the F1 fix); an exit-code-only sweep would have called the
    # pre-fix crash "caught" while the later oracles never ran.
    TEXT["misc_route"] = TEXT["misc_route"].replace(
        "    target = targets[0] if targets else None\n",
        "    target = targets[len(targets)] if targets else None\n", 1)
elif M == "drop-forensic-injection":
    # forensic keeps the target in meta but never appends the directive to the
    # prompt — a downstream (section-3) defect, caught by the forensic slice.
    TEXT["forensic_orch"] = TEXT["forensic_orch"].replace(
        '    if _tgt_block:\n        prompt = prompt + "\\n\\n" + _tgt_block\n',
        '    if False and _tgt_block:\n        prompt = prompt + "\\n\\n" + _tgt_block\n',
        1)
elif M == "prefer-description-when-both":
    # Precedence flip in the runner-less primary-input directive. The sealed
    # helper evaluates `if has_artifact:` FIRST, so a misc job carrying BOTH an
    # uploaded artifact AND a description keeps the artifact-primary wording.
    # Guarding that branch with `and not has_description` diverts ONLY the
    # both-present cell to the description branch; file-only, description-only,
    # and target-only keep their original branch. Attacks precedence alone, so
    # only the file+description+target pin in section 3 catches it.
    TEXT["prompts"] = TEXT["prompts"].replace(
        "        if has_artifact:\n",
        "        if has_artifact and not has_description:\n", 1)
elif M == "composite-crash-mask":
    # The masking case: an EARLY crash (misc off-by-one) plus a DOWNSTREAM
    # defect (forensic prompt loss). Pre-fix the crash aborted the run, the
    # forensic defect never executed, and no summary printed — so the composite
    # looked "caught" to an exit-code sweep. Post-fix both surface as named
    # failures and the summary is reached.
    TEXT["misc_route"] = TEXT["misc_route"].replace(
        "    target = targets[0] if targets else None\n",
        "    target = targets[len(targets)] if targets else None\n", 1)
    TEXT["forensic_orch"] = TEXT["forensic_orch"].replace(
        '    if _tgt_block:\n        prompt = prompt + "\\n\\n" + _tgt_block\n',
        '    if False and _tgt_block:\n        prompt = prompt + "\\n\\n" + _tgt_block\n',
        1)
elif M == "break-prompts-compile":
    # DELIBERATE harness abort: a syntax break in the module under test makes
    # section 1's compile() raise before any check runs. The sweep must classify
    # this as `aborted`, NOT as a caught assertion-red — that is what proves the
    # crash/red discriminator is real and not vacuous.
    TEXT["prompts"] = TEXT["prompts"] + "\nthis is not valid python\n"

# A mutation uses `.replace(old, new, 1)`, which SILENTLY no-ops if `old`
# drifted out of the source. An inert mutant would pass the suite green — and a
# sweep would then read "green (want assertion-red)" as a miss with no clue why.
# Fail loudly at the source instead: if a non-`none` mutant changed nothing, its
# anchor is stale.
if M != "none" and TEXT == _ORIG_TEXT:
    raise RuntimeError(
        f"mutation {M!r} matched no anchor (source drifted?) — the mutant is "
        f"inert, so it proves nothing")


# ==========================================================================
# 1 — build_target_directive, called for real
# ==========================================================================
_prompts = types.ModuleType("_prompts_under_test")
exec(compile(TEXT["prompts"], str(SRC["prompts"]), "exec"), _prompts.__dict__)
btd = _prompts.build_target_directive

# The default path is shared with web/pwn/crypto/rev/web3, which pass no
# keyword at all. Pin it against the exact text those five were getting before
# misc/forensic existed, so widening the signature cannot quietly reword it.
LEGACY = "\n".join([
    "TARGET DIRECTIVE — the remote target for THIS run is `chal.example.com:1337`.",
    "• AUTHORITATIVE: if you are resuming / retrying a prior attempt, the "
    "target may have CHANGED since then (the operator can update it between "
    "runs). Trust THIS value — discard any different host:port in your "
    "conversation history AND in any carried exploit.py / solver.py, and "
    "re-point every remote() / connection at it before you test.",
    "• DRIVE OFF sys.argv[1] (and the `TARGETS` env var if it is set), "
    "NEVER a hardcoded host:port literal. The orchestrator re-reads the "
    "live target and rewrites argv[1] on every SANDBOX run, so an "
    "argv-driven exploit picks up a target change with NO code edit — a "
    "hardcoded one silently keeps hitting the old host. (Your own ad-hoc "
    "remote() Bash smoke tests are NOT auto-refreshed — use the value "
    "above for those.)",
])
check("the five pre-existing modules' directive text is unchanged",
      btd("chal.example.com:1337"), LEGACY)
check("no target still yields an empty block (script-driven)", btd(None), "")
check("no target still yields an empty block (runner-less)",
      btd(None, None, script_driven=False), "")
check("a blank string is treated as no target",
      btd("   ", [], script_driven=False), "")
check("target_urls alone can supply the primary",
      btd(None, ["a:1", "b:2"]).splitlines()[0].endswith("`a:1`."), True)

runnerless = btd("chal.example.com:1337", None, script_driven=False)
check("runner-less directive still names the target",
      "chal.example.com:1337" in runnerless, True)
check("runner-less directive drops the argv[1] mandate",
      "argv[1]" in runnerless or "sys.argv" in runnerless, False)
check("runner-less directive drops the TARGETS env reference",
      "TARGETS" in runnerless, False)
check("runner-less directive does not order an exploit.py re-point",
      "exploit.py" in runnerless or "solver.py" in runnerless, False)
check("runner-less directive tells the agent to reach it from Bash",
      "REACH IT YOURSELF" in runnerless, True)
check("runner-less directive keeps the authoritative-on-retry half",
      "AUTHORITATIVE" in runnerless, True)
check("runner-less directive says an unreachable target is not fatal",
      "does not make the job unsolvable" in runnerless, True)

multi_rl = btd("a:1", ["a:1", "b:2"], script_driven=False)
check("runner-less multi-target lists every target inline",
      ("1) a:1" in multi_rl and "2) b:2" in multi_rl), True)
check("runner-less multi-target does not promise a TARGETS env var",
      "`TARGETS` env var" in multi_rl, False)
multi_sd = btd("a:1", ["a:1", "b:2"])
check("script-driven multi-target still points at the TARGETS env var",
      "`TARGETS` env var" in multi_sd, True)


# ==========================================================================
# 2 — the route handlers, invoked
# ==========================================================================
def _stub_fastapi() -> None:
    """Always install the local FastAPI surface — never the installed one.

    This used to return early when `fastapi` was importable, on the theory that
    a real install is closer to production. It is not, for this file: the
    surface below (`APIRouter`, `HTTPException`, `UploadFile`, `Form`, `File`,
    `responses`) is a hand-written minimum, none of the checks assert real
    FastAPI semantics, and the route bodies are exec'd directly rather than
    served. So the real package bought nothing — and it cost determinism.

    `Form(...)`/`File(...)` make FastAPI demand `python-multipart` at import
    time. A host with fastapi but not python-multipart therefore aborted this
    suite before a single check ran, while the same commit passed 102/0 on a
    host with neither. Same bytes, opposite outcome, decided by what happened
    to be installed. Choosing the local surface unconditionally removes that
    fork: no-fastapi, partial-install and full-install hosts now run the
    identical program.

    Real-FastAPI integration is the API image's job (api/requirements.txt pins
    fastapi AND python-multipart together) and belongs in a test that actually
    serves a request, not in this source-contract harness.
    """
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

    class UploadFile:
        pass

    mod.APIRouter = APIRouter
    mod.HTTPException = HTTPException
    mod.UploadFile = UploadFile
    mod.Request = type("Request", (), {})
    for _n in ("File", "Form", "Query", "Body", "Depends"):
        setattr(mod, _n, lambda *a, **k: (a[0] if a else None))
    sys.modules["fastapi"] = mod

    # `from fastapi.responses import ...` would otherwise try to walk into a
    # module that is not a package. Pre-seeding the submodule is what makes
    # api.routes.retry importable in section 5.
    resp = types.ModuleType("fastapi.responses")

    class _Resp:
        def __init__(self, *a, **k):
            pass

    for _r in ("PlainTextResponse", "JSONResponse", "StreamingResponse",
               "FileResponse", "HTMLResponse", "Response", "RedirectResponse"):
        setattr(resp, _r, _Resp)
    sys.modules["fastapi.responses"] = resp
    mod.responses = resp


def _stub_queue_deps() -> None:
    for name in ("redis", "rq"):
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

        m.Redis = m.Queue = _Any
        m.from_url = lambda *a, **k: _Any()
        sys.modules[name] = m
        if name == "rq":
            jm = types.ModuleType("rq.job")
            jm.Job = _Any
            sys.modules["rq.job"] = jm


_stub_fastapi()
_stub_queue_deps()

from fastapi import HTTPException as _HTTPExc  # noqa: E402


class _Upload:
    """forensic reads the upload via `.file.read(n)` (sync, chunked)."""

    def __init__(self, filename: str, data: bytes = b"payload"):
        self.filename = filename
        self._data = data
        self._pos = 0
        self.file = self

    def read(self, n=-1):
        chunk = self._data[self._pos:]
        self._pos = len(self._data)
        return chunk


class _AsyncUpload:
    """misc awaits `file.read()` on the UploadFile itself."""

    def __init__(self, filename: str, data: bytes = b"payload"):
        self.filename = filename
        self._data = data
        self._pos = 0
        self.file = _Upload(filename, data)

    async def read(self, n=-1):
        return self._data


class _Recorder:
    def __init__(self):
        self.calls = []

    def enqueue(self, *a, **k):
        self.calls.append((a, k))
        return types.SimpleNamespace(id=k.get("job_id"))


def _load_route(key: str, mod_name: str):
    m = types.ModuleType(mod_name)
    m.__file__ = str(SRC[key])
    m.__package__ = "api.routes"
    sys.modules[mod_name] = m
    exec(compile(TEXT[key], str(SRC[key]), "exec"), m.__dict__)
    return m


misc_route = _load_route("misc_route", "misc_module_under_test")
forensic_route = _load_route("forensic_route", "forensic_module_under_test")


def _meta_of(job_id: str) -> dict:
    return json.loads((DATA / "jobs" / job_id / "meta.json").read_text())


# --- misc ------------------------------------------------------------------
# Each scenario is isolated: an exception (e.g. the misc-primary-off-by-one
# mutant's IndexError) becomes a named failure, so the NEXT scenario and the
# final summary still run instead of the whole suite aborting silently.
misc_route.get_queue = lambda: _Recorder()
with guard("misc multi-target persistence scenario"):
    res = asyncio.run(misc_route.analyze_misc(
        file=_AsyncUpload("blob.png"),
        target="a.example.com:1337 , b.example.com:1338",
        passphrase=None, description="d", skip_claude=False, docker_challenge=False,
        job_timeout=None, model=None, effort=None, flag_format=None,
    ))
    mm = _meta_of(res["job_id"])
    check("misc persists the primary target", mm.get("target_url"), "a.example.com:1337")
    check("misc persists the full multi-target list",
          mm.get("target_urls"), ["a.example.com:1337", "b.example.com:1338"])
    check("misc still records the uploaded filename", mm.get("filename"), "blob.png")
    # misc had the same local `target` holding the on-disk path. Shadowed, meta
    # carries a PosixPath and write_job_meta raises before the job is ever queued.
    check("misc writes the upload under the job dir, not shadowed by the target",
          (DATA / "jobs" / res["job_id"] / "blob.png").is_file(), True)
    check("misc's target_url is the operator's string, not a filesystem path",
          isinstance(mm.get("target_url"), str) and "/jobs/" not in str(mm.get("target_url")),
          True)

with guard("misc description-only scenario"):
    res = asyncio.run(misc_route.analyze_misc(
        file=None, target=None, passphrase=None, description="desc only",
        skip_claude=False, docker_challenge=False, job_timeout=None, model=None,
        effort=None, flag_format=None,
    ))
    mm2 = _meta_of(res["job_id"])
    check("misc without a target writes an explicit null", mm2.get("target_url"), None)
    check("misc without several targets omits the list", mm2.get("target_urls"), None)
    check("misc keeps its description-only mode (no file, no target)",
          mm2.get("filename"), None)

with guard("misc target-only scenario"):
    res = asyncio.run(misc_route.analyze_misc(
        file=None, target="only.example.com:9999", passphrase=None, description=None,
        skip_claude=False, docker_challenge=False, job_timeout=None, model=None,
        effort=None, flag_format=None,
    ))
    check("misc accepts a target with no file at all",
          _meta_of(res["job_id"]).get("target_url"), "only.example.com:9999")

# --- forensic --------------------------------------------------------------
forensic_route.get_queue = lambda: _Recorder()
with guard("forensic persistence scenario"):
    res = asyncio.run(forensic_route.collect_forensic(
        file=_Upload("disk.raw", b"\x00" * 64), target="fx.example.com:8080",
        image_type="raw", target_os="linux", description=None, bulk_extractor=False,
        skip_claude=False, docker_challenge=False, job_timeout=None, model=None,
        effort=None, flag_format=None,
    ))
    fm = _meta_of(res["job_id"])
    check("forensic persists the remote target", fm.get("target_url"), "fx.example.com:8080")
    check("forensic keeps target_os separate from the remote target",
          fm.get("target_os"), "linux")
    # The route had a local `target` holding the on-disk image path. If the remote
    # target reuses that name the image write and the meta value fight each other,
    # and the symptom is a meta whose target_url is a Path under /data/jobs.
    check("the image is written under the job dir, not shadowed by the target",
          (DATA / "jobs" / res["job_id"] / "disk.raw").is_file(), True)
    check("forensic's target_url is the operator's string, not a filesystem path",
          isinstance(fm.get("target_url"), str) and "/jobs/" not in str(fm.get("target_url")),
          True)
    check("forensic still records the image size", fm.get("size_bytes"), 64)

with guard("forensic requires-an-image scenario"):
    raised = None
    try:
        asyncio.run(forensic_route.collect_forensic(
            file=_Upload("", b""), target="fx.example.com:8080", image_type="auto",
            target_os="auto", description=None, bulk_extractor=False,
            skip_claude=False, docker_challenge=False, job_timeout=None, model=None,
            effort=None, flag_format=None,
        ))
    except _HTTPExc as exc:
        raised = exc.status_code
    check("forensic still REQUIRES an image — a target alone is rejected", raised, 400)

with guard("forensic no-target scenario"):
    res = asyncio.run(forensic_route.collect_forensic(
        file=_Upload("mem.dmp", b"\x01" * 8), target=None, image_type="memory",
        target_os="auto", description=None, bulk_extractor=False, skip_claude=False,
        docker_challenge=False, job_timeout=None, model=None, effort=None,
        flag_format=None,
    ))
    check("a forensic job with no target is unchanged",
          _meta_of(res["job_id"]).get("target_url"), None)


# ==========================================================================
# 3 — the prompt the agent would actually receive
# ==========================================================================
def _prompt_slice(src_key: str, meta: dict, fake_base: str = "BASE-PROMPT",
                  *, filename="blob.png", description=None) -> str:
    """Execute the real prologue of `_claude_summary` and return its `prompt`.

    Everything the prologue reaches for is stubbed EXCEPT `_prompts`, which is
    the code under test. The slice ends where the provider branch begins, so
    what comes back is the exact string handed to whichever backend runs.
    """
    tree = ast.parse(TEXT[src_key])
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "_claude_summary")
    cut = next(i for i, st in enumerate(fn.body)
               if isinstance(st, ast.Assign)
               and getattr(st.targets[0], "id", None) == "provider")
    body = [st for st in fn.body[:cut]
            if not (isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant))]
    body.append(ast.Return(value=ast.Name(id="prompt", ctx=ast.Load())))
    wrapper = ast.FunctionDef(
        name="_slice",
        args=ast.arguments(posonlyargs=[], args=[], vararg=None, kwonlyargs=[],
                           kw_defaults=[], kwarg=None, defaults=[]),
        body=body, decorator_list=[], returns=None, type_comment=None,
    )
    mod = ast.Module(body=[wrapper], type_ignores=[])
    ast.fix_missing_locations(mod)

    common = types.ModuleType("modules._common")
    common.build_exploit_library_hint = lambda *a, **k: ""
    common.docker_challenge_block = lambda *a, **k: ""
    prompts_mod = types.ModuleType("modules._prompts")
    prompts_mod.build_target_directive = btd
    saved = {k: sys.modules.get(k) for k in ("modules._common", "modules._prompts")}
    sys.modules["modules._common"] = common
    sys.modules["modules._prompts"] = prompts_mod

    slice_dir = DATA / "jobs" / "prompt-slice"
    slice_dir.mkdir(parents=True, exist_ok=True)
    g = {
        "job_id": "JOB", "filename": filename, "description": description,
        "model_override": None, "target_os": "linux", "kind": "raw",
        "Path": Path,
        "_job_dir": lambda _j: slice_dir,
        "coerce_model_for_provider": lambda m: m,
        "resolve_main_model": lambda m: "model",
        "read_meta": lambda _j: dict(meta),
        "build_user_prompt": lambda *a, **k: fake_base,
    }
    try:
        exec(compile(mod, "<slice>", "exec"), g)
        return g["_slice"]()
    finally:
        for k, v in saved.items():
            if v is not None:
                sys.modules[k] = v
            else:
                sys.modules.pop(k, None)


# Guard the loop BODY per module, not the loop: a misc-side raise inside
# _prompt_slice must not also kill the forensic iteration (composite masking).
for label, key in (("misc", "misc_orch"), ("forensic", "forensic_orch")):
    with guard(f"{label} prompt-slice scenario"):
        with_t = _prompt_slice(key, {"target_url": "t.example.com:4444"})
        without = _prompt_slice(key, {})
        check(f"{label}: a targeted job's prompt names the target",
              "t.example.com:4444" in with_t, True)
        check(f"{label}: the directive is appended, not substituted",
              with_t.startswith("BASE-PROMPT"), True)
        check(f"{label}: an untargeted job's prompt is byte-identical to before",
              without, "BASE-PROMPT")
        check(f"{label}: the prompt uses the runner-less directive variant",
              ("argv[1]" in with_t or "TARGETS" in with_t), False)
        check(f"{label}: the prompt keeps the authoritative-on-retry clause",
              "AUTHORITATIVE" in with_t, True)
        multi = _prompt_slice(key, {"target_url": "p:1", "target_urls": ["p:1", "q:2"]})
        check(f"{label}: extra targets survive into the prompt",
              ("1) p:1" in multi and "2) q:2" in multi), True)
        blank = _prompt_slice(key, {"target_url": "   "})
        check(f"{label}: a whitespace-only target adds nothing", blank, "BASE-PROMPT")

# The runner-less directive's "what is the PRIMARY input" line must match the
# job the operator actually created. misc's file is OPTIONAL, so the orchestrator
# passes has_artifact/has_description off the real job state; a hardcoded
# "the uploaded artifact is the main input" is a lie for a description-only or
# target-only misc job. Run the real misc prologue for each shape.
with guard("misc primary-input directive scenarios"):
    misc_file_t = _prompt_slice("misc_orch", {"target_url": "t.example.com:4444"},
                                filename="blob.png", description=None)
    check("misc file+target keeps the artifact-primary wording",
          "the uploaded artifact is still the job's main input" in misc_file_t, True)

    misc_desc_t = _prompt_slice("misc_orch", {"target_url": "t.example.com:4444"},
                                filename=None, description="a captured handshake")
    check("misc description+target names the description as the primary input",
          "the description above is still the job's main input" in misc_desc_t, True)
    check("misc description+target invents no uploaded artifact",
          "the uploaded artifact is still the job's main input" in misc_desc_t, False)

    misc_only_t = _prompt_slice("misc_orch", {"target_url": "only.example.com:9999"},
                                filename=None, description=None)
    check("misc target-only does not invent an uploaded artifact",
          "the uploaded artifact is still the job's main input" in misc_only_t, False)
    check("misc target-only does not call the sole target supplementary",
          "SUPPLEMENTARY, NOT PRIMARY" in misc_only_t, False)
    check("misc target-only names the target as the job's primary subject",
          ("only.example.com:9999" in misc_only_t and "PRIMARY INPUT" in misc_only_t), True)

    # BOTH an artifact AND a description: the sealed helper resolves this by
    # PRECEDENCE (has_artifact evaluated first), not by presence. A hardcoded
    # or description-first ordering would mislabel a file-bearing misc job.
    # Pin that the both-present cell keeps artifact-primary and does NOT switch
    # to the description wording.
    misc_both_t = _prompt_slice("misc_orch", {"target_url": "t.example.com:4444"},
                                filename="blob.png", description="a captured handshake")
    check("misc file+description+target keeps artifact-primary over the description",
          ("the uploaded artifact is still the job's main input" in misc_both_t
           and "the description above is still the job's main input" not in misc_both_t),
          True)

# forensic's file is REQUIRED, so it always has an artifact and keeps the
# original wording (its orchestrator passes no override — the default holds).
with guard("forensic primary-input directive scenario"):
    forensic_file_t = _prompt_slice("forensic_orch", {"target_url": "fz.example.com:22"})
    check("forensic keeps the artifact-primary wording (its file is required)",
          "the uploaded artifact is still the job's main input" in forensic_file_t, True)


# ==========================================================================
# 4 — the UI: the field exists where it is claimed, and the button is gated
# ==========================================================================
html = TEXT["index_html"]


def _panel(name: str) -> str:
    start = html.index(f'<section id="panel-{name}"')
    end = html.index('<section id="panel-', start + 1)
    return html[start:end]


for mod_name, field in (("misc", "target"), ("forensic", "target"),
                        ("pwn", "target"), ("web", "target_url")):
    with guard(f"{mod_name} panel target-field scenario"):
        panel = _panel(mod_name)
        check(f"{mod_name} form offers a target list bound to `{field}`",
              bool(re.search(r'class="target-list" data-field="%s"' % field, panel)), True)

check("forensic's file input is still marked required",
      bool(re.search(r'<input type="file" name="file" required', _panel("forensic"))),
      True)

# The gate is EVALUATED, not grepped: the real declarations are lifted out of
# app.js and run for each module. A revert to `showChangeTarget = hasTarget`
# turns misc true and this red.
js = TEXT["app_js"]
# Start at isExploitableModule so the slice is self-contained: `job` ends up
# the only free name, and showRetry/showStopResume/showStop come along and
# have to keep evaluating too.
_gs = js.index("  const isExploitableModule = [")
_ge = js.index("\n", js.index("const showChangeTarget", _gs))
GATE_SRC = re.sub(r"^\s*//.*$", "", js[_gs:_ge], flags=re.M)


def _gate(module: str) -> dict:
    prog = (
        "const job = {module: %s};\n" % json.dumps(module)
        + GATE_SRC
        + "\nconsole.log(JSON.stringify({canRetry, hasTarget, showChangeTarget}));"
    )
    out = subprocess.run(["node", "-e", prog], capture_output=True, text=True)
    if out.returncode != 0:
        raise AssertionError(f"gate eval failed: {out.stderr.strip()}")
    return json.loads(out.stdout)


try:
    _gate("web")
    have_node = True
except (FileNotFoundError, AssertionError, OSError) as exc:
    have_node = False
    print(f"SKIP  node unavailable for the gate evaluation ({exc})")

if have_node:
    with guard("Change-target gate evaluation scenario"):
        for _m in ("web", "pwn", "crypto", "rev", "web3"):
            check(f"{_m}: Change target still shown (no regression)",
                  _gate(_m)["showChangeTarget"], True)
        check("forensic: Change target shown — it is retryable, so the value is read",
              _gate("forensic")["showChangeTarget"], True)
        check("misc: target accepted at create time",
              _gate("misc")["hasTarget"], True)
        check("misc: Change target HIDDEN — no retry/resume/run would ever read it",
              _gate("misc")["showChangeTarget"], False)
        check("live-fire: no target affordance at all",
              _gate("live-fire")["hasTarget"], False)
        check("hybrid: targets live on its per-stage inputs, not the job panel",
              _gate("hybrid")["showChangeTarget"], False)


# ==========================================================================
# 6 — the wire between the form and the route
# ==========================================================================
# Sections 2 and 4 test opposite banks of the same river: section 4 says the
# HTML declares `data-field="target"`, section 2 calls the handler with a
# `target=` kwarg by hand. Neither notices if those two names disagree — a
# data-field typo, or a form pointed at a param the route does not take, makes
# the create succeed with `target_url: null` and looks like the operator simply
# did not type anything. So: cross the river.
_ROUTE_OF_PANEL = {
    "web": ("web_module.py", "analyze_web"),
    "pwn": ("pwn_module.py", "analyze_pwn"),
    "crypto": ("crypto_module.py", "analyze_crypto"),
    "rev": ("rev_module.py", "analyze_rev"),
    "web3": ("web3_module.py", "analyze_web3"),
    "misc": ("misc_module.py", "analyze_misc"),
    "forensic": ("forensic_module.py", "collect_forensic"),
}


def _form_params(route_file: str) -> set:
    """Parameter names the route declares with `Form(...)`. AST, so a comment
    mentioning the name does not count and a renamed parameter does."""
    src = (ROOT / "api" / "routes" / route_file).read_text()
    tree = ast.parse(src)
    out = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        a = node.args
        names = [*a.args, *a.kwonlyargs]
        defaults = [*([None] * (len(a.args) - len(a.defaults))), *a.defaults,
                    *a.kw_defaults]
        for arg, dflt in zip(names, defaults):
            fn = getattr(getattr(dflt, "func", None), "id", None)
            if fn in ("Form", "File"):
                out.add(arg.arg)
    return out


_panel_fields = {}
for _p, (_f, _fn) in _ROUTE_OF_PANEL.items():
    with guard(f"{_p} form-to-route wire scenario"):
        _decl = re.findall(r'class="target-list" data-field="([a-z_]+)"', _panel(_p))
        check(f"{_p}: exactly one target list in the panel (querySelector is singular)",
              _panel(_p).count('class="target-list"'), 1)
        check(f"{_p}: the list declares a data-field", len(_decl), 1)
        if _decl:
            _panel_fields[_p] = _decl[0]
            check(f"{_p}: `{_decl[0]}` is a Form parameter the route actually accepts",
                  _decl[0] in _form_params(_f), True)

# And the extraction itself, executed. The row inputs carry no `name`, so the
# ONLY thing that puts the operator's text into the request is this block.
_es = js.index('const tlist = form.querySelector(".target-list");')
_ee = js.index("}", js.index('fd.set(tlist.dataset.field', _es)) + 1
EXTRACT_SRC = js[_es:_ee]


def _extract(field: str, values, rows=None) -> dict:
    """Run the real block against a DOM stub shaped like the rendered panel."""
    rows = len(values) if rows is None else rows
    prog = """
const values = %s, field = %s, rows = %d;
const inputs = [];
for (let i = 0; i < rows; i++) inputs.push({ value: values[i] === undefined ? "" : values[i] });
const _tl = { dataset: { field }, querySelectorAll: (s) => (s === ".target-input" ? inputs : []) };
const form = { querySelector: (s) => (s === ".target-list" ? _tl : null) };
const store = {};
const fd = { set: (k, v) => { store[k] = v; }, get: (k) => (k in store ? store[k] : null) };
%s
console.log(JSON.stringify(store));
""" % (json.dumps(values), json.dumps(field), rows, EXTRACT_SRC)
    out = subprocess.run(["node", "-e", prog], capture_output=True, text=True)
    if out.returncode != 0:
        raise AssertionError(f"extract eval failed: {out.stderr.strip()}")
    return json.loads(out.stdout)


if have_node:
    with guard("form extraction scenario"):
        for _p in ("misc", "forensic"):
            _fld = _panel_fields.get(_p)
            got = _extract(_fld, ["h.example.com:1"])
            check(f"{_p}: what the operator types lands under `{_fld}`",
                  got.get(_fld), "h.example.com:1")
            got = _extract(_fld, [" a:1 ", "", "b:2"])
            check(f"{_p}: several rows are newline-joined and blanks dropped",
                  got.get(_fld), "a:1\nb:2")
            got = _extract(_fld, ["   "])
            check(f"{_p}: an untouched row sends an empty value, not whitespace",
                  got.get(_fld), "")
        # The same block serves the modules that already had a list; if it stopped
        # working there this would be a regression, not a new-module problem.
        check("web: the shared extraction still writes target_url",
              _extract("target_url", ["http://x:1"]).get("target_url"), "http://x:1")


# ==========================================================================
# 5 — the retry path: forensic's target survives a rebuild
# ==========================================================================
# forensic is in _RETRYABLE_MODULES, so the Change-target button on a forensic
# card promises that the value reaches the NEXT run. `_resubmit` writes
# target_url from one shared meta literal and then each module branch patches a
# few keys on top; a branch that reassigned meta after the literal would drop
# it silently. Run the real function and read what landed on disk.
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
            self.__dict__.update(kw)

    m.BaseModel = BaseModel
    m.Field = lambda *a, **k: None
    m.ValidationError = type("ValidationError", (Exception,), {})
    sys.modules["pydantic"] = m


def _stub_sdk() -> None:
    """find_spec, not `name not in sys.modules` — the latter installs a stub
    over a working install and the real import path never runs (the note on
    this in test_flag_ready.py is the reason it is spelled out again)."""
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
                 "TextBlock", "ThinkingBlock", "ToolResultBlock", "ToolUseBlock",
                 "UserMessage", "HookMatcher"):
        setattr(sdk, name, type(name, (), {}))
    sdk.project_key_for_directory = lambda *a, **k: ""

    async def _query(*a, **k):
        if False:
            yield None

    sdk.query = _query
    sys.modules["claude_agent_sdk"] = sdk


_stub_pydantic()
_stub_sdk()

# Loaded from TEXT, not imported, so a mutation can reach _resubmit the same
# way it reaches the routes. retry.py has no relative imports, so executing its
# source under a private name is equivalent to importing it.
_retry_ok = True
try:
    RT = _load_route("retry", "retry_module_under_test")
    from modules._common import read_meta as _read_meta  # noqa: E402
except Exception as _exc:  # pragma: no cover — dependency-shaped, not logic
    _retry_ok = False
    print(f"SKIP  api.routes.retry not loadable here ({type(_exc).__name__}: {_exc})")

if _retry_ok:
    def _forensic_child(parent_target, parent_urls=None, override=None):
        pid = f"fparent-{abs(hash((parent_target, override))) % 10**8}"
        pj = DATA / "jobs" / pid
        pj.mkdir(parents=True, exist_ok=True)
        pmeta = {
            "id": pid, "module": "forensic", "status": "no_flag",
            "filename": "disk.raw", "image_type": "raw", "target_os": "linux",
            "target_url": parent_target, "target_urls": parent_urls,
            "description": "d", "bulk_extractor": False,
        }
        (pj / "meta.json").write_text(json.dumps(pmeta))
        (pj / "disk.raw").write_bytes(b"\x00" * 16)

        class _Q:
            def enqueue(self, *a, **k):
                return None

        real = RT.get_queue
        RT.get_queue = lambda: _Q()
        try:
            kw = {} if override is None else {"target_override": override}
            new_id = RT._resubmit(_read_meta(pid), "hint", pj, **kw)
        finally:
            RT.get_queue = real
        return _read_meta(new_id) or {}

    with guard("forensic retry carry scenario"):
        child = _forensic_child("keep.example.com:7000")
        check("a forensic retry carries the parent's target into the child",
              child.get("target_url"), "keep.example.com:7000")
        check("  ...and still carries the image forward",
              child.get("filename"), "disk.raw")
        check("  ...and does not confuse target_os with the remote target",
              child.get("target_os"), "linux")

    with guard("forensic retry override scenario"):
        child = _forensic_child("old.example.com:1", override="new.example.com:2")
        check("a Change-target override reaches the forensic retry",
              child.get("target_url"), "new.example.com:2")

    with guard("forensic retry clear-override scenario"):
        child = _forensic_child("old.example.com:1", override="(none)")
        check("  ...and \"(none)\" clears it rather than re-using the old value",
              child.get("target_url"), None)

    with guard("forensic retry multi-target scenario"):
        child = _forensic_child("p:1", parent_urls=["p:1", "q:2"])
        check("a multi-target forensic retry keeps the extras",
              child.get("target_urls"), ["p:1", "q:2"])


# The summary line is printed ONLY here, on the normal completion path. A crash
# in an UNGUARDED region (e.g. section 1's compile of the module under test)


# ==========================================================================
# 7 — a rejected create leaves nothing behind
# ==========================================================================
# job_dir() mkdirs, and a create route has to call it before it can judge a
# streamed upload. Every 400 therefore used to leave one data/jobs/<id>/ that
# nothing ever swept. Same shape as the /continue defect: the side effect
# preceded the verdict.
pwn_route = _load_route("pwn_route", "pwn_module_under_test")
rev_route = _load_route("rev_route", "rev_module_under_test")
for _m in (pwn_route, rev_route):
    _m.get_queue = lambda: _Recorder()
    _m._keep_and_raise = lambda _j, code, detail: (_ for _ in ()).throw(
        _HTTPExc(status_code=code, detail=detail))
misc_route._keep_and_raise = forensic_route._keep_and_raise = pwn_route._keep_and_raise


def _jobdirs():
    return {p.name for p in (DATA / "jobs").iterdir() if p.is_dir()}


def _rejects(fn, **kw):
    """Call a create route expected to 400; return (status, new job dirs)."""
    before = _jobdirs()
    status = None
    try:
        asyncio.run(fn(**kw))
    except _HTTPExc as exc:
        status = exc.status_code
    return status, sorted(_jobdirs() - before)


# pwn and rev do not take skip_claude; misc and forensic do. Passing the union
# would make every call a TypeError, which the harness reports as a failure
# rather than a skip — signature drift must not read as a passing check.
_EMPTY = dict(description=None, docker_challenge=False,
              job_timeout=None, model=None, effort=None, flag_format=None)
_SWEEP = dict(_EMPTY, skip_claude=False)

for _label, _call in (
    ("pwn", lambda: _rejects(
        pwn_route.analyze_pwn, file=_AsyncUpload("x.bin", b""), target=None,
        auto_run=False, **_EMPTY)),
    ("rev (empty file)", lambda: _rejects(
        rev_route.analyze_rev, file=_AsyncUpload("x.bin", b""), target=None,
        auto_run=False, **_EMPTY)),
    ("rev (invalid zip)", lambda: _rejects(
        rev_route.analyze_rev, file=_AsyncUpload("x.zip", b"not a zip"),
        target=None, auto_run=False, **_EMPTY)),
    ("misc", lambda: _rejects(
        misc_route.analyze_misc, file=_AsyncUpload("x.png", b""), target=None,
        passphrase=None, **_SWEEP)),
    ("forensic", lambda: _rejects(
        forensic_route.collect_forensic, file=_Upload("x.raw", b""), target=None,
        image_type="auto", target_os="auto", bulk_extractor=False, **_SWEEP)),
):
    try:
        _st, _new = _call()
    except TypeError as exc:            # signature drift is a failure, not a skip
        _st, _new = f"TypeError: {exc}", []
    check(f"{_label}: a rejected upload still returns 400", _st, 400)
    check(f"  ...and leaves no job directory behind", _new, [])


# ==========================================================================
# 8 — when the cleanup cannot run, the refusal is still a refusal AND it says so
# ==========================================================================
# reject_job removes the directory a create route already made. If that removal
# fails, three things must hold at once: the caller still gets the original 400,
# the orphan is honestly still there, and somebody is told. The first version
# used ignore_errors=True and satisfied only the first two — a surviving
# directory was indistinguishable from a cleaned one, and the 7-day TTL reaper
# is configurable to 0.
import logging as _logging  # noqa: E402

import api.storage as _storage  # noqa: E402


class _Capture(_logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        # Keep the RECORD, not its rendering. Asserting on rendered text made
        # the check hostage to wording: a substring matched a path inside a
        # cause, a lookahead matched the rmdir cause, and a delimiter split
        # stopped working the moment the delimiter changed. The structured
        # field cannot be reworded away.
        self.records.append(record)


def _reject_under(job_id, *, make_undeletable):
    """Call reject_job and report (status, dir survived, diagnostics).

    The failure is injected by making os.unlink refuse for paths under this one
    job directory. An earlier version chmod'd the directory instead, which is
    not deterministic: the mode is advisory to root, so the whole contract went
    unexercised on any host that runs the suite as root. A patched unlink fails
    the same way for everyone, and is restored in `finally` whatever happens.
    """
    import os as _os

    jd = DATA / "jobs" / job_id
    jd.mkdir(parents=True, exist_ok=True)
    (jd / "payload.bin").write_bytes(b"x")

    real_unlink = _os.unlink

    def _refuse(path, *a, **k):
        # dir_fd-relative names arrive as bare strings; refuse by name too.
        name = path if isinstance(path, str) else str(path)
        if "payload.bin" in name:
            raise PermissionError(13, "Permission denied", name)
        return real_unlink(path, *a, **k)

    cap = _Capture()
    log = _logging.getLogger(_storage.__name__)
    log.addHandler(cap)
    prev = log.level
    log.setLevel(_logging.WARNING)
    status = None
    try:
        if make_undeletable:
            _os.unlink = _refuse
        _storage.reject_job(job_id, 400, "empty file")
    except _HTTPExc as exc:
        status = (exc.status_code, exc.detail)
    finally:
        _os.unlink = real_unlink          # always, even on an unexpected raise
        log.removeHandler(cap)
        log.setLevel(prev)
    survived = jd.exists()
    if survived:
        import shutil as _sh
        _sh.rmtree(jd, ignore_errors=True)
    return status, survived, cap.records


# --- the failure path -------------------------------------------------------
_st, _survived, _logs = _reject_under("rj-blocked", make_undeletable=True)
if not _survived:
    # Running as root (or on a filesystem that ignores the mode) defeats the
    # injection. Say so as a NAMED failure — a silent skip here would read as
    # a passing contract.
    check("cleanup-failure injection actually blocked the removal", _survived, True)
else:
    check("a blocked cleanup still returns the original 400",
          _st, (400, "empty file"))
    check("  ...and does not pretend the directory is gone", _survived, True)
    _joined = " ".join(r.getMessage() for r in _logs)
    _dirs = [getattr(r, "reject_job_dir", None) for r in _logs]
    # Three separate things, asserted separately. The previous version wrote
    # the same condition twice and so never checked the second one at all.
    check("  ...and REGRESSION: names the job", "rj-blocked" in _joined, True)
    # Structural, not textual. Three earlier versions of this check parsed the
    # rendered message and each was defeated by a different rewording — the last
    # one turned a pathless diagnostic GREEN as soon as the delimiter changed.
    check("  ...and REGRESSION: carries the directory as a structured field",
          _dirs, [str(DATA / "jobs" / "rj-blocked")])
    check("  ...and the cause, not just the fact",
          "PermissionError" in _joined or "Permission denied" in _joined, True)

# --- the two quiet paths ----------------------------------------------------
_st, _survived, _logs = _reject_under("rj-clean", make_undeletable=False)
check("a successful cleanup returns the 400", _st, (400, "empty file"))
check("  ...removes the directory", _survived, False)
check("  ...and logs nothing — a warning on the normal path is unread",
      _logs, [])

_missing = DATA / "jobs" / "rj-absent"
if _missing.exists():
    import shutil as _sh2
    _sh2.rmtree(_missing)
_cap = _Capture()
_log = _logging.getLogger(_storage.__name__)
_log.addHandler(_cap)
try:
    _storage.reject_job("rj-absent", 400, "empty file")
except _HTTPExc as _e:
    _st = (_e.status_code, _e.detail)
finally:
    _log.removeHandler(_cap)
check("a refusal with nothing to clean still returns the 400", _st, (400, "empty file"))
check("  ...and logs nothing", _cap.records, [])
# never reaches this line — _harness_excepthook prints HARNESS ABORT and exits 2
# instead — so the sweep can tell a caught assertion-red from a harness abort.
print(f"\n{PASSED + FAILED} checks, {FAILED} failed  (mutate={ARGS.mutate})")
sys.exit(1 if FAILED else 0)
