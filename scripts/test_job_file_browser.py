#!/usr/bin/env python3
"""Job file browser: containment, one-level listing, and the UI wiring.

WHY THIS REPLACED A LINK LIST
The job panel hard-coded one artifact link per module — `exploit.py.stdout`
for pwn/web, `solver.py.stdout` for crypto/rev. The runner names artifacts
after the script it actually ran, so a crypto Sage job writes
`solver.sage.stdout`, a name no list contained. Measured 2026-08-11 on job
606175dde9d6: the file existed and served 200, while the link the UI rendered
(`solver.py.stdout`) returned 404. Listing the directory removes the guess.

THE LOAD-BEARING PROPERTY IS CONTAINMENT, not listing. `work/` is written by
the agent and by challenge code running as root in the sandbox, so a symlink
such as `work/x -> /` is something this has to survive rather than assume
away. The guard is realpath ancestry, and the mutations below exist to make a
future edit that weakens it fail loudly.

Run:  python3 scripts/test_job_file_browser.py [--mutate NAME]
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=(
    "none",
    "no-containment",     # the realpath ancestry check is dropped
    "follow-symlink",     # escaping symlinks are resolved instead of refused
    "no-cap",             # a huge directory is returned whole
    "hardcoded-links",    # the UI goes back to guessing artifact filenames
    "browser-unmounted",  # the browser is not re-mounted after a re-render
    "no-adoption",        # the live browser node is discarded on every re-render
    "loading-in-template",  # the placeholder ships in the rebuilt markup again
    "adopt-any-job",      # the adoption stops checking which job the node is for
), default="none")
args = parser.parse_args()

passed = failed = 0


def check(label, got, want=True):
    global passed, failed
    if got == want:
        passed += 1
    else:
        failed += 1
        print(f"FAIL  {label}\n      got  = {got!r}\n      want = {want!r}")


# ------------------------------------------------------------- import route
TMP = tempfile.TemporaryDirectory(prefix="jobfiles-")
JOBS = Path(TMP.name) / "jobs"
JOBS.mkdir(parents=True)

if "fastapi" not in sys.modules:
    fastapi = types.ModuleType("fastapi")

    class _HTTPException(Exception):
        def __init__(self, status_code, detail=""):
            self.status_code = status_code
            self.detail = detail
            super().__init__(detail)

    class _APIRouter:
        def __getattr__(self, _name):
            return lambda *a, **k: (lambda fn: fn)

    fastapi.APIRouter = _APIRouter
    fastapi.HTTPException = _HTTPException
    fastapi.Request = object
    sys.modules["fastapi"] = fastapi

    responses = types.ModuleType("fastapi.responses")
    responses.FileResponse = lambda path, filename=None: {"file": str(path)}
    responses.PlainTextResponse = lambda *a, **k: None
    responses.StreamingResponse = lambda *a, **k: None
    sys.modules["fastapi.responses"] = responses

for name, attrs in (
    ("api", {}),
    ("api.routes", {}),
    ("api.queue", {"get_queue": lambda: None, "get_redis": lambda: None}),
    ("api.storage", {"JOBS_DIR": JOBS, "parse_targets": lambda *a: [],
                     "read_job_meta": lambda *a: None,
                     "write_job_meta": lambda *a, **k: None}),
):
    if name not in sys.modules:
        mod = types.ModuleType(name)
        if name in ("api", "api.routes"):
            mod.__path__ = []
        for k, v in attrs.items():
            setattr(mod, k, v)
        sys.modules[name] = mod

import importlib.util  # noqa: E402

_src = (ROOT / "api" / "routes" / "jobs.py").read_text(encoding="utf-8")
if args.mutate == "no-containment":
    _src = _src.replace(
        "if target != root and root not in target.parents:",
        "if False:")
elif args.mutate == "follow-symlink":
    _src = _src.replace("target = (root / (rel or \"\")).resolve()",
                        "target = root / (rel or \"\")")
elif args.mutate == "no-cap":
    _src = _src.replace("if len(entries) >= _FILE_LIST_CAP:", "if False:")

ns: dict = {}
# Only the browser needs to run; executing the whole module would pull in the
# queue/agent stack for no benefit.
_start = _src.index("_FILE_LIST_CAP")
_end = _src.index("@router.get(\"/{job_id}/result\")")
exec(compile(
    "import os\nfrom pathlib import Path\n"
    "from datetime import datetime, timezone\n"
    "from fastapi import HTTPException\n"
    "from fastapi.responses import FileResponse\n"
    "from api.storage import JOBS_DIR\n"
    "def router_get(*a, **k):\n    return lambda fn: fn\n"
    + _src[_start:_end].replace("@router.get(", "@router_get("),
    "jobs_browser", "exec"), ns)
list_job_files = ns["list_job_files"]
get_job_blob = ns["get_job_blob"]
HTTPException = sys.modules["fastapi"].HTTPException


# ------------------------------------------------------------ the fixture
J = "abc123abc123"
jd = JOBS / J
(jd / "work" / "deep").mkdir(parents=True)
(jd / "src").mkdir()
(jd / "solver.sage.stdout").write_text("FLAG_CANDIDATE: DH{x}\n")
(jd / "meta.json").write_text("{}")
(jd / "work" / "solver.sage").write_text("print(1)\n")
(jd / "work" / "deep" / "nested.txt").write_text("deep\n")
# Exactly the shapes agent/challenge code can leave behind.
os.symlink("/etc/passwd", jd / "work" / "escape_file")
os.symlink("/etc", jd / "work" / "escape_dir")
os.symlink("../../..", jd / "work" / "up")
os.symlink("/nonexistent", jd / "work" / "broken")

OUTSIDE = Path(TMP.name) / "secret.txt"
OUTSIDE.write_text("do not serve me\n")


def status_of(fn, **kw):
    """HTTP status the call would produce, or a marker for anything else.

    A mutation must leave the suite RUNNABLE so the failure names the severed
    defence. Dropping the containment check makes `relative_to` raise
    ValueError on an escaped path — without catching that, the whole run dies
    at the first traversal case and every later check goes unreported.
    """
    try:
        fn(**kw)
        return 200
    except HTTPException as e:
        return e.status_code
    except Exception as e:                       # noqa: BLE001
        return f"raised:{type(e).__name__}"


# ------------------------------------------------- ① containment (the point)
for bad in ("..", "../..", "/etc/passwd", "work/../..", "work/up", "work/up/jobs"):
    check(f"listing refuses to escape via {bad!r}",
          status_of(list_job_files, job_id=J, path=bad) in (403, 404), True)
for bad in ("../secret.txt", "/etc/passwd", "work/escape_file", "work/up/secret.txt"):
    check(f"blob refuses to escape via {bad!r}",
          status_of(get_job_blob, job_id=J, path=bad) in (403, 404), True)
# A traversal that lands back inside is legitimate and must still work — the
# guard is ancestry, not a ban on "..".
check("a '..' that stays inside still resolves",
      status_of(get_job_blob, job_id=J, path="work/../solver.sage.stdout"), 200)

# ------------------------------------------------------- ② listing contract
root = list_job_files(J)
names = [e["name"] for e in root["entries"]]
check("directories sort before files",
      names.index("src") < names.index("solver.sage.stdout"), True)
check("the runner's real artifact name is listed",
      "solver.sage.stdout" in names, True)
check("sizes are reported for files",
      next(e["size"] for e in root["entries"] if e["name"] == "solver.sage.stdout"), 22)
check("directories report no size",
      next(e["size"] for e in root["entries"] if e["name"] == "work"), None)
check("path is relative to the job root", root["path"], "")

work = list_job_files(J, path="work")
check("one level only — nested content is not inlined",
      "nested.txt" not in [e["name"] for e in work["entries"]], True)
check("the child directory is offered instead",
      "deep" in [e["name"] for e in work["entries"]], True)
check("parent is derivable for the crumb trail", work["parent"], "")
check("nested paths are fetchable",
      status_of(get_job_blob, job_id=J, path="work/deep/nested.txt"), 200)

# A symlink is SHOWN (so "empty" and "points somewhere we won't go" do not
# look alike) but never followed.
links = {e["name"]: e for e in work["entries"]}
check("an escaping symlink is still listed", "escape_file" in links, True)
check("...and flagged as a link", links["escape_file"]["is_link"], True)
check("a broken symlink does not break the listing", "broken" in links, True)

check("an unknown job is 404", status_of(list_job_files, job_id="nope", path=""), 404)
check("a file path given to the lister is 404",
      status_of(list_job_files, job_id=J, path="solver.sage.stdout"), 404)

# ------------------------------------------------------------------ ③ cap
big = JOBS / "bigjob"
big.mkdir()
for i in range(2100):
    (big / f"f{i:05d}").write_text("x")
listed = list_job_files("bigjob")
check("a huge directory is capped", listed["truncated"], True)
check("...at the documented cap", len(listed["entries"]), listed["cap"])
check("...and the cap is surfaced, not silent", listed["cap"] >= 1, True)

# --------------------------------------------------------------------- UI
APP = (ROOT / "web-ui" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "web-ui" / "style.css").read_text(encoding="utf-8")
HTML = (ROOT / "web-ui" / "index.html").read_text(encoding="utf-8")

if args.mutate == "hardcoded-links":
    APP += '\nlinks.push(fileLink("stdout", `${API}/jobs/${id}/file/solver.py.stdout`));\n'
elif args.mutate == "browser-unmounted":
    APP = APP.replace("  mountJobFiles(id);", "")
elif args.mutate == "no-adoption":
    APP = APP.replace("    if (_fresh) _fresh.replaceWith(_keptFiles);", "")
elif args.mutate == "loading-in-template":
    APP = APP.replace('<div class="job-files-list"></div>',
                      '<div class="job-files-list"><span class="c-dim">Loading…</span></div>')
elif args.mutate == "adopt-any-job":
    APP = APP.replace(
        'const _keptFiles = detail.querySelector(`.job-files[data-job="'
        '${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`);',
        "const _keptFiles = detail.querySelector('.job-files');")

# The regression this feature exists to end: a filename the UI guessed.
check("the UI no longer guesses artifact filenames",
      re.search(r"file/(exploit|solver)\.py\.(stdout|stderr)", APP) is None, True)
check("the browser container is rendered", 'class="job-files"' in APP, True)
check("entries are fetched from the listing endpoint", "/files?path=" in APP, True)
check("files open through the blob endpoint", "/blob?path=" in APP, True)
check("files reuse the existing preview modal",
      "file-preview-link" in APP and "jf-file" in APP, True)
# Rebuilt on every poll — without a re-mount the browser resets to the job
# root every couple of seconds, which is the SDK panel's old bug.
check("the browser is re-mounted after a detail re-render",
      "mountJobFiles(id);" in APP, True)
check("...and restores the directory the operator was in",
      "_jobFilesPath" in APP, True)
check("CSS.escape is guarded like every other call site",
      APP.count("(window.CSS && CSS.escape)") >= 6, True)
check("the terminal link survived the replacement", "job-files-terminal" in APP, True)
check("a large directory scrolls inside its own box, not the page",
      ".job-files-list" in CSS and "overflow-y: auto" in CSS, True)
check("a long filename cannot push the size column away",
      "text-overflow: ellipsis" in CSS, True)

# ------------------------------------------------- ④ the poll must be invisible
# Reported 2026-08-11: the browser blinked `Loading…` every couple of seconds
# and lost the scroll position of a directory being read, because the detail
# panel is rebuilt on every poll and took the browser down with it. The listing
# was correct and unreadable. Behaviour is pinned in
# scripts/test_job_files_quiet_poll.js (jsdom, node identity across polls);
# what is checked HERE is the part that lives outside that slice.
check("the rebuilt markup ships an empty list, not a placeholder",
      '<div class="job-files-list"></div>' in APP, True)
# Scoped to the browser's own spinner class — `Loading…` appears elsewhere in
# app.js for unrelated panels, so a bare count would measure the wrong thing.
check("...so the browser writes its spinner in exactly one place",
      APP.count('class="c-dim jf-loading"'), 1)
check("...and that one write is reachable only from a first paint",
      "if (firstPaint) list.innerHTML = '<span class=\"c-dim jf-loading\">Loading…</span>'"
      in APP, True)
check("...with the spinner cleared before the listing is patched",
      'const spinner = list.querySelector(".jf-loading");' in APP, True)

check("the live browser node is adopted across a re-render",
      "_fresh.replaceWith(_keptFiles)" in APP, True)
# There is a separate `detail.innerHTML = ""` for job switches; an unguarded
# adoption would carry job A's directory into job B's panel.
check("...only when the node belongs to THIS job",
      'const _keptFiles = detail.querySelector(`.job-files[data-job='
      '"${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`);' in APP, True)
# An adopted list is taller than the empty placeholder. Restoring the outer
# scroll against the shorter document would clamp it — the trap the SDK panel
# comment already records.
# `.index` raises when a mutation removes the needle, which would kill the run
# and hide every check below it. A severed defence has to REPORT, not crash.
def _before(a: str, b: str) -> bool:
    ia, ib = APP.find(a), APP.find(b)
    return ia != -1 and ib != -1 and ia < ib


check("...before anything measures the document for a scroll restore",
      _before("_fresh.replaceWith(_keptFiles)",
              "detail.scrollTop = prevModalScrollTop"), True)

check("the listing is patched towards the new entries, not rewritten",
      "function _jfReconcile(" in APP, True)
check("...keyed so an unchanged row is left alone", 'row.dataset.key' in APP, True)
check("...and reconciled over rows only, so the unkeyed siblings do not churn",
      'list.querySelectorAll(":scope > .jf-row")' in APP, True)
check("...placed in the API's order rather than appended",
      "list.insertBefore(row, next)" in APP, True)
check("a row whose dir/link shape changed is rebuilt, not patched",
      "row.dataset.shape !== _jfShape(e)" in APP, True)
check("a dropped background poll cannot erase a good listing",
      "if (firstPaint) {\n      list.innerHTML = `<span style=\"color:var(--red)\">" in APP,
      True)
check("handlers are delegated once per box, not re-attached per row",
      'box.dataset.wired === "1"' in APP, True)
check("...so Refresh is no longer a one-shot on a node that now survives",
      "{ once: true }" not in APP.split("function _jfWire")[-1].split("async function loadJobFiles")[0],
      True)

check("only arriving rows are marked for animation",
      "row.classList.add(\"jf-new\")" in APP, True)
check("...and a first paint is exempt, so opening does not shimmer",
      "if (!opts.firstPaint) {" in APP, True)
check("the arrival animation exists", "@keyframes jf-fade-in" in CSS, True)
check("...and is dropped for reduced-motion",
      "prefers-reduced-motion" in CSS and ".jf-row.jf-new { animation: none; }" in CSS,
      True)

import hashlib  # noqa: E402
_h = hashlib.sha256()
_h.update((ROOT / "web-ui" / "app.js").read_bytes())
_h.update((ROOT / "web-ui" / "style.css").read_bytes())
check("index.html's cache buster tracks the assets it ships",
      f"?v=a{_h.hexdigest()[:8]}" in HTML, True)

TMP.cleanup()
print(f"== summary: {passed} passed, {failed} failed; mutation={args.mutate} ==")
raise SystemExit(1 if failed else 0)
