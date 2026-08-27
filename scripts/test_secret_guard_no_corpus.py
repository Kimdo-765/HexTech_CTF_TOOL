#!/usr/bin/env python3
"""The secrets guard must not go green where it cannot check.

Run: python3 scripts/test_secret_guard_no_corpus.py [--mutate <name>]

WHAT WAS OPEN

`data/` is never tracked — `git rev-list --objects origin/main | awk '$2 ~
/^data\\//'` returns nothing — so no clone, and no CI runner, has a job corpus.
`_live_jobs_dir()` returned None there, the accepted-flag oracle printed SKIP,
and the run exited 0.

An adversarial audit measured what that let through: planting each of the 28
distinct accepted flags from the live corpus, one at a time, into a TRACKED
artefact of a fresh clone left the guard green for 17 of them. The credential
PATTERNS carry no flag shape; the only ones caught were those whose payload
happened to be 40+ hex characters. And a shape is the wrong instrument anyway,
because the same artefacts legitimately carry REJECTED candidates that are
indistinguishable from real flags.

WHY THE FIX IS A DIGEST AND NOT AN ORACLE

The values cannot be committed to give a clone its own oracle — that would be
the leak the guard exists to prevent. What can be committed is the digest of
each generated artefact as it stood when the oracle last ran and passed.
Unchanged bytes carry that verification with them. Changed bytes do not, and
are refused rather than skipped.

So a corpus-less run has exactly two honest outcomes, and this file pins both:
green when the artefacts are byte-identical to a verified state, red when any
of them moved.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MUTATIONS = (
    "none",
    "silent-skip",   # restore the old print-and-continue
    "no-pin",        # delete the committed digest pin
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


GUARD = "scripts/test_no_committed_secrets.py"
PIN = "scripts/generated_artifact_digests.json"
ARTEFACT = "scripts/lineage_equivalence_labelled.json"

_TMP = tempfile.TemporaryDirectory(prefix="guard-no-corpus-")
CLONE = Path(_TMP.name) / "clone"


def build_clone() -> None:
    """A tracked-files-only copy: exactly what a clone gets, minus data/."""
    CLONE.mkdir(parents=True)
    files = subprocess.run(["git", "ls-files"], cwd=str(ROOT),
                           capture_output=True, text=True).stdout.split("\n")
    for rel in files:
        if not rel.strip():
            continue
        src = ROOT / rel
        if not src.is_file():
            continue
        dst = CLONE / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    # The pin is written by --refresh-digests and may not be committed yet in
    # the tree under test; copy it if it exists so the clone matches reality.
    if (ROOT / PIN).is_file():
        shutil.copy2(ROOT / PIN, CLONE / PIN)
    if args.mutate == "silent-skip":
        p = CLONE / GUARD
        s = p.read_text()
        i = s.find('    print("NO CORPUS')
        j = s.find("\nelse:", i)
        if i < 0 or j < 0:
            raise RuntimeError("mutation anchor not found in the guard")
        s = s[:i] + '    print("SKIP  live jobs corpus is unavailable")\n' + s[j + 1:]
        p.write_text(s)
    if args.mutate == "no-pin":
        (CLONE / PIN).unlink(missing_ok=True)
    for cmd in (["git", "init", "-q", "."],
                ["git", "add", "-A"],
                ["git", "-c", "user.email=t@t", "-c", "user.name=t",
                 "commit", "-qm", "base"]):
        subprocess.run(cmd, cwd=str(CLONE), capture_output=True)


def run_guard():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1")
    # Point the resolver at a path that cannot exist so the fallback chain has
    # nowhere left to go — the clone has no .git worktree file and no data/.
    env["HEXTECH_LIVE_JOBS"] = "/nonexistent-corpus-for-this-test"
    r = subprocess.run([sys.executable, GUARD], cwd=str(CLONE),
                       capture_output=True, text=True, env=env, timeout=900)
    return r.returncode, r.stdout + r.stderr


build_clone()

print("--- the clone really has no corpus " + "-" * 24)
check("data/ is not part of a checkout", (CLONE / "data").exists(), False)
check("the guard came along", (CLONE / GUARD).is_file())

print("")
print("--- untouched artefacts: green, and it says why " + "-" * 12)
rc0, out0 = run_guard()
check("a corpus-less run of an unmodified tree passes", rc0, 0, detail=out0[-400:])
check("...and states that the oracle could not run",
      "NO CORPUS" in out0 or "SKIP" in out0)
check("...and says the digest pin is what carried the verification",
      "byte-identical" in out0, detail=out0[-300:])

print("")
print("--- anything planted in a generated artefact: red " + "-" * 10)
p = CLONE / ARTEFACT
before = p.read_text()
# Deliberately NOT a flag-shaped or credential-shaped string. The point of the
# digest is that it is value-agnostic: if an inert edit is caught, so is a
# planted flag, and the test does not have to write a real flag to disk.
p.write_text(before + '\n{"planted": "inert"}\n')
rc1, out1 = run_guard()
check("a corpus-less run REFUSES a changed generated artefact", rc1 != 0)
check("...naming the artefact that moved",
      ARTEFACT.split("/")[-1] in out1, detail=out1[-400:])
p.write_text(before)

rc2, _ = run_guard()
check("restoring the bytes restores the pass", rc2, 0)

print("")
print(f"secret-guard-no-corpus: {passed} passed, {failed} failed; "
      f"mutation={args.mutate}")
sys.exit(1 if failed else 0)
