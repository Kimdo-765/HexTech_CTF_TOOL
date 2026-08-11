#!/usr/bin/env python3
"""The runner records what it wrote; consumers read it instead of guessing.

THE BUG THIS CLOSES, MEASURED 2026-08-11 ON JOB 606175dde9d6.
The runner names artifacts after the script it actually ran, so a crypto Sage
job writes `solver.sage.stdout`. Every consumer instead carried its own fixed
list of names. `_TRUSTED_FLAG_SOURCES` held the `.py` spellings only, so the
solver printed `FLAG_CANDIDATE: DH{Not_bad!_10.8+_is_ezpz}`, the file sat on
disk at 791 bytes, and the job finished `no_flag`. Reproduced under the
scan-time conditions (`result.json` is written AFTER the scan, so it cannot
rescue the first pass) and confirmed fixed once the names are recorded.

WHY UNION AND NOT REPLACEMENT. Jobs that ran before the recording existed have
no `meta.artifacts` at all, and re-scanning them has to keep working — the
legacy tuple is the fallback, not the truth. Both directions are pinned below.

Run:  python3 scripts/test_artifact_name_truth.py [--mutate NAME]
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=(
    "none",
    "no-record",        # the runner stops recording what it wrote
    "replace-legacy",   # recorded names REPLACE the tuple instead of joining it
    "trust-path",       # a recorded value keeps its directory component
    "record-not-read",  # meta carries the names but the scanner ignores them
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


# --------------------------------------------------------------- environment
TMP = tempfile.TemporaryDirectory(prefix="artifacts-")
JOBS = Path(TMP.name) / "jobs"
JOBS.mkdir(parents=True)

# Import the REAL module. An earlier draft sliced the two functions out of the
# source and exec'd them; that broke on the first module-level name they touch
# (`FLAG_RE`), and a harness that can only run part of the function proves
# nothing about the function.
from modules import _common as C  # noqa: E402

C.JOBS_DIR = JOBS
C.job_dir = lambda j: JOBS / Path(j).name

if args.mutate == "replace-legacy":
    _orig_rec = C._recorded_artifact_names
    C._TRUSTED_FLAG_SOURCES = ()          # recorded names REPLACE the tuple
elif args.mutate == "trust-path":
    _orig_rec = C._recorded_artifact_names
    C._recorded_artifact_names = lambda j: [
        (C.read_meta(j) or {}).get("artifacts", {}).get(k)
        for k in ("stdout", "stderr")
        if isinstance((C.read_meta(j) or {}).get("artifacts", {}).get(k), str)
    ]
elif args.mutate == "record-not-read":
    C._recorded_artifact_names = lambda j: []

scan_job_for_flags = C.scan_job_for_flags
_recorded = C._recorded_artifact_names

FLAG = "DH{Not_bad!_10.8+_is_ezpz}"
STDOUT = f"[*] stage 6/6: submitting seed\nseed: {FLAG}\nFLAG_CANDIDATE: {FLAG}\n"


def make_job(job_id: str, *, artifacts: dict | None, script="solver.sage",
             with_result_json=False) -> str:
    jd = JOBS / job_id
    jd.mkdir(parents=True, exist_ok=True)
    (jd / f"{script}.stdout").write_text(STDOUT)
    (jd / f"{script}.stderr").write_text("")
    meta = {"id": job_id, "module": "crypto"}
    if artifacts is not None:
        meta["artifacts"] = artifacts
    (jd / "meta.json").write_text(json.dumps(meta))
    # result.json is written AFTER the scan by the analyzer, so the scan-time
    # view does not have it. Only the explicit case gets one.
    if with_result_json:
        (jd / "result.json").write_text(json.dumps({"sandbox": {"stdout": STDOUT}}))
    return job_id


RECORDED = {"script": "solver.sage",
            "stdout": "solver.sage.stdout",
            "stderr": "solver.sage.stderr"}

# ------------------------------------- ① the reported failure, and its fix
old = make_job("oldjob", artifacts=None)
new = make_job("newjob", artifacts=RECORDED)

prov: dict = {}
check("a recorded sage artifact is trusted at scan time",
      scan_job_for_flags(new, provenance_out=prov), [FLAG])
check("...and it is the solver's own MARKER, not prose", prov.get("tier"), "marker")

# The pre-fix behaviour, kept as the contrast that makes the fix legible.
check("without a record, the sage artifact is still invisible",
      scan_job_for_flags(old), [])

# ------------------------------------------ ② union, not replacement
legacy = make_job("legacyjob", artifacts=None, script="solver.py")
check("a legacy .py artifact still works with no record at all",
      scan_job_for_flags(legacy), [FLAG])
legacy_recorded = make_job("legacymix", artifacts=RECORDED, script="solver.py")
check("...and still works when a DIFFERENT name is recorded",
      scan_job_for_flags(legacy_recorded), [FLAG])

# ------------------------------------------------- ③ the recorded value
check("recorded names are surfaced as basenames",
      _recorded(new), ["solver.sage.stdout", "solver.sage.stderr"])
pathy = make_job("pathyjob", artifacts={"stdout": "../../etc/passwd",
                                        "stderr": "work/x.stderr"})
# The trusted tier joins these onto the job directory, so a directory
# component in a recorded value would read outside it.
check("a recorded value cannot carry a path out of the job dir",
      all("/" not in n and ".." not in n for n in _recorded(pathy)), True)
check("an absent artifacts block yields nothing rather than raising",
      _recorded(old), [])
check("a malformed artifacts block yields nothing",
      _recorded(make_job("badmeta", artifacts={"stdout": 42})), [])
check("an unknown job yields nothing", _recorded("no-such-job"), [])

# ------------------------------------------------- ④ the runner records
RUNNER = (ROOT / "modules" / "_runner.py").read_text(encoding="utf-8")
if args.mutate == "no-record":
    RUNNER = RUNNER.replace('_wm(job_id, artifacts=_arts)', "pass")

check("the runner records the artifact names it wrote",
      "_wm(job_id, artifacts=_arts)" in RUNNER, True)
check("...derived from the script it actually ran",
      '"stdout": f"{script_filename}.stdout"' in RUNNER, True)
check("...including the script name itself",
      '"script": script_filename' in RUNNER, True)
# Bookkeeping must never lose a finished run.
check("a failure to record cannot fail the run",
      "artifact name record failed" in RUNNER, True)
check("...and it merges rather than clobbering an existing block",
      "_arts.update(" in RUNNER, True)

TMP.cleanup()
print(f"== summary: {passed} passed, {failed} failed; mutation={args.mutate} ==")
raise SystemExit(1 if failed else 0)
