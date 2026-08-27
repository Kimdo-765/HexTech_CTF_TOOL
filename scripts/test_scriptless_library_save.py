#!/usr/bin/env python3
"""A module that never writes a script must still be able to save its work.

Run: python3 scripts/test_scriptless_library_save.py [--mutate <name>]

WHY THIS EXISTS

`POST /api/exploits/save` required one of exploit.py / solver.py / solver.sage
in the job directory. misc and forensic are `orchestrator.py` modules with no
sandbox runner - both files say so in as many words, "no sandbox runner: ...
an exploit.py it never writes" - so they solve by running tools and analysing
artefacts and produce no such file, ever.

The consequence was measured, not guessed: the library held 229 entries -
rev 90, pwn 65, web 59, crypto 15 - and ZERO from misc or forensic. Saving one
was impossible by construction. The operator hit it as
`400 job has no script (exploit.py, solver.py, solver.sage)`.

report.md stays REQUIRED. `build_exploit_library_hint` points a later agent at
`/data/exploits/<id>/report.md` and never mentions the script, so the report is
the artefact that actually transfers; an entry without one is an empty shell.

THE UI HALF

app.js rendered the script link as `m.script_filename || "exploit.py"`. For a
script-less entry that fallback produces a link to a file that does not exist,
so the save would succeed and the card would still be broken. The link is now
conditional, and this file pins that - a server fix with a broken card is not
a fix.

WHY THIS IS NOT A TAUTOLOGY

The save path is driven for real: temp job trees shaped like misc (no script)
and like web (with one) go through the actual `save_exploit`, and the resulting
library directory is inspected on disk. The mutation battery restores each
half of the old behaviour and requires the suite to go red.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

MUTATIONS = (
    "none",
    "require-script",       # bring back the 400
    "copy-missing-script",  # bring back the unconditional copy2
    "ui-fallback",          # bring back `|| "exploit.py"` in app.js
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS, default="none")
args = parser.parse_args()

passed = 0
failed = 0


def check(label: str, got, want=True) -> None:
    global passed, failed
    if got == want:
        passed += 1
        print(f"PASS  {label}")
    else:
        failed += 1
        print(f"FAIL  {label}\n      got  = {got!r}\n      want = {want!r}")


def replace_once(source: str, old: str, new: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(
            f"mutation anchor count is {count}, expected 1: {old[:60]!r}")
    return source.replace(old, new, 1)


# --------------------------------------------------------------- environment
_TMP = tempfile.TemporaryDirectory(prefix="scriptless-save-")
DATA = Path(_TMP.name)
(DATA / "jobs").mkdir()
(DATA / "exploits").mkdir()
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

    def _field(*a, **k):
        f = k.get("default_factory")
        return f() if f else k.get("default")

    m.Field = _field
    sys.modules["pydantic"] = m


_stub_fastapi()
_stub_pydantic()

import api.routes.exploits as EX  # noqa: E402

SRC_PATH = ROOT / "api" / "routes" / "exploits.py"
SRC = SRC_PATH.read_text()

# ------------------------------------------------------------------ mutation
_mut = SRC
if args.mutate == "require-script":
    _mut = replace_once(
        _mut,
        "    report_src = artifact_jd / \"report.md\"\n"
        "    if not report_src.is_file():",
        "    if script_name is None:  # MUTATION\n"
        "        raise HTTPException(status_code=400, detail=\"job has no script\")\n"
        "    report_src = artifact_jd / \"report.md\"\n"
        "    if not report_src.is_file():",
    )
elif args.mutate == "copy-missing-script":
    _mut = replace_once(
        _mut,
        "    if script_name:\n"
        "        shutil.copy2(artifact_jd / script_name, dest / script_name)",
        "    shutil.copy2(artifact_jd / script_name, dest / script_name)  # MUTATION",
    )

if _mut is not SRC:
    exec(compile(_mut, str(SRC_PATH), "exec"), EX.__dict__)


# ------------------------------------------------------------------- helpers
def make_job(job_id: str, module: str, *, script: str | None,
             report: bool = True) -> None:
    jd = Path(os.environ["JOBS_DIR"]) / job_id
    jd.mkdir(parents=True, exist_ok=True)
    (jd / "meta.json").write_text(json.dumps(
        # A captured flag is a separate precondition of the route
        # (exploits.py:388) and is NOT what this file is about: the library
        # rightly refuses to store an unsolved attempt. Every fixture here
        # carries one so the only variable under test is the script.
        {"id": job_id, "module": module, "status": "finished",
         "filename": f"{module}-chal.zip",
         "flags": [f"FLAG{{{module}-solved}}"]}))
    if report:
        (jd / "report.md").write_text(f"# {module} report\nhow it was solved\n")
    (jd / "findings.json").write_text(json.dumps({"strings": {}}))
    if script:
        (jd / script).write_text("print('x')\n")


def save(job_id: str):
    body = EX.SaveBody(job_id=job_id, tags=[], notes="", overwrite=True)
    return EX.save_exploit(body)


# ------------------------------------------------------ the module that can't
print("--- a script-less module can save its report " + "-" * 14)
make_job("m0000000misc", "misc", script=None)

err = None
meta = None
try:
    meta = save("m0000000misc")
except Exception as exc:  # noqa: BLE001
    err = exc

check("a misc job with no script SAVES", err is None)
if err is not None:
    print("      raised:", repr(err))
if meta is not None:
    check("...and records that there is no script",
          meta.get("script_filename") is None)
    check("...and keeps the module", meta.get("module"), "misc")
    dest = Path(os.environ["DATA_DIR"]) / "exploits" / meta["id"]
    check("...and the report really landed on disk",
          (dest / "report.md").is_file())
    check("...and no phantom script file was created",
          sorted(p.name for p in dest.iterdir()), ["meta.json", "report.md"])
else:
    for lbl in ("...and records that there is no script", "...and keeps the module",
                "...and the report really landed on disk",
                "...and no phantom script file was created"):
        check(lbl, False)

# ----------------------------------------------------------- the regression
print("")
print("--- a module that DOES write one still stores it " + "-" * 11)
make_job("w0000000web0", "web", script="exploit.py")
meta_w = save("w0000000web0")
check("a web job still saves", isinstance(meta_w, dict))
check("...with its script recorded", meta_w.get("script_filename"), "exploit.py")
dest_w = Path(os.environ["DATA_DIR"]) / "exploits" / meta_w["id"]
check("...and the script really landed on disk",
      (dest_w / "exploit.py").is_file())

# --------------------------------------------------------- report is required
print("")
print("--- report.md is still the floor " + "-" * 26)
make_job("n0000000norp", "misc", script=None, report=False)
raised = None
try:
    save("n0000000norp")
except Exception as exc:  # noqa: BLE001
    raised = exc
check("a job with no report.md is still refused", raised is not None)
check("...for the stated reason",
      "report.md" in str(raised) if raised else False)

# ------------------------------------------------------------------- the UI
print("")
print("--- the card does not link a file that isn't there " + "-" * 8)
_appjs = (ROOT / "web-ui" / "app.js").read_text()
if args.mutate == "ui-fallback":
    _appjs = replace_once(
        _appjs,
        '${m.script_filename ? `<a class="file-preview-link" '
        'data-name="${escapeHtml(id)}/${escapeHtml(m.script_filename)}"',
        '${true ? `<a class="file-preview-link" '
        'data-name="${escapeHtml(id)}/${escapeHtml(m.script_filename || "exploit.py")}"',
    )
check("the script link is rendered conditionally",
      "${m.script_filename ? `<a class=\"file-preview-link\"" in _appjs)
check("the exploit.py fallback that linked a missing file is gone",
      'm.script_filename || "exploit.py"' in _appjs, False)

check("test_mutation_suite_reaches_final_named_check", True, True)

print("")
print(f"scriptless-library-save: {passed} passed, {failed} failed; "
      f"mutation={args.mutate}")
sys.exit(1 if failed else 0)
