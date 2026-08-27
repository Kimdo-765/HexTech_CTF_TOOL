#!/usr/bin/env python3
"""No committed file may carry a credential.

Run: python3 scripts/test_no_committed_secrets.py

THE INCIDENT

scripts/concept_benchmark.json is built from live job data, and job
descriptions are free text an operator types. One of them contained a live
CTFd API token. The builder copied descriptions verbatim, so the token was
committed and pushed before review caught it.

`modules.job_secrets.redact_job_value` already existed and did not help: it
replaces secrets that were REGISTERED for a job through the upload form. A
credential the operator merely typed into the description was never registered,
so there was nothing to match against.

The builder now runs both layers -- registered-secret redaction and a broad
pattern scrub. This file is the thing that would have caught it: it reads the
committed artefacts as bytes and fails on anything credential-shaped,
regardless of which layer was supposed to have removed it.

Deliberately broad. A false positive costs one line in a fixture; a false
negative costs a credential, and this repository has a remote.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

_REFRESH = "--refresh-digests" in sys.argv

# Scan EVERY tracked text file, not a list of the ones I happened to think of.
# The leak was in a file built from live job data, and naming that file would
# only protect the case already known. A sweep of all 237 tracked files found
# no other real credential -- the six other matches are digests and test
# placeholders, listed below by exact value so a NEW one cannot hide behind a
# path-level exemption.
# Artefacts BUILT FROM LIVE JOB DATA and committed. Add a file here the moment
# anything generated from data/jobs becomes tracked.
#
# THE SECOND INCIDENT, 2026-08-26. `fafa7a1` tracked the two files below. They
# are written by reading every attempt of every retry lineage — findings,
# solvers, reports, run.log — so they inherit whatever those artefacts say. The
# labelled one carried three ACCEPTED flags (verified present in `meta.flags` of
# finished jobs 90bd949f3c34 / d12c1e2f9a3e, f52c4049fec9, 9d2e4099d5ba) and one
# rejected candidate of the same shape. The commit was made without running this
# file; a read-only eyeball scan ran instead and searched only for `DH{`, so it
# reported "no real flags" while two `pokactf2024{...}` captures sat in the same
# artefact. That is the same lesson as the first incident in a new costume: the
# sweep below is what catches it, and it only runs if someone runs it.
GENERATED: list[str] = [
    "scripts/lineage_equivalence_seed.json",
    "scripts/lineage_equivalence_labelled.json",
]

# Byte digests of the GENERATED artefacts, recorded the last time the live
# accepted-flag oracle actually ran and passed. Refresh with
#
#     python3 scripts/test_no_committed_secrets.py --refresh-digests
#
# which only writes when the corpus is present AND the oracle passes.
DIGESTS_PATH = "scripts/generated_artifact_digests.json"

# Known-benign, allowlisted by VALUE rather than by file. A commit SHA and a
# hash of the empty string are credential-shaped and are not credentials.
ALLOWED_SUBSTRINGS = {
    # docs/hardening-s1-baseline.json — provenance digests, each verified by
    # reading the JSON key it sits under: base_commit, base_tree, two
    # `sha256:`-prefixed file hashes, and manifest_sha256.
    "b172d6d13461beb0d603ca170ae84822ab",
    "6f952dfa5cd11f576f0ec0268d787395fc",
    "59f979038dbc4a67f4625e6203e3ac937e",
    "e52da33a2f8cd33901982baed5274179d2",
    "ce8590edf720994c0a899298d163ef173c",
    "e3b0c44298fc1c149afbf4c8996fb924",            # sha256 of the empty string
    "da39a3ee5e6b4b0d3255bfef95601890",            # sha1 of the empty string
    "sk-test-secret-value-123456789",              # explicit test placeholder
    "0123456789abcdef",                            # synthetic fixture
    "bb3cd526550f28ebc618d59e4bebcb6e",            # DH{...} flag fixture in a test
    "bcdaad21d4635931d1bd3b54",                    # synthetic fixture
}


def _tracked_text_files():
    import subprocess
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files"],
                         capture_output=True, text=True)
    for rel in out.stdout.split():
        p = ROOT / rel
        if not p.is_file():
            continue
        try:
            yield rel, p.read_text(errors="strict")
        except (UnicodeDecodeError, OSError):
            continue                               # binary


def _live_jobs_dir():
    """Find live metadata without assuming this checkout owns data/jobs."""
    candidates = []
    if os.environ.get("HEXTECH_LIVE_JOBS"):
        candidates.append(pathlib.Path(os.environ["HEXTECH_LIVE_JOBS"]))
    candidates.extend((pathlib.Path("/data/jobs"), ROOT / "data" / "jobs"))

    common = ROOT / ".git"
    if common.is_file():
        try:
            line = common.read_text().strip()
            if line.startswith("gitdir:"):
                git_dir = pathlib.Path(line.split(":", 1)[1].strip())
                for ancestor in git_dir.parents:
                    if ancestor.name == ".git":
                        candidates.append(ancestor.parent / "data" / "jobs")
                        break
        except OSError:
            pass

    for candidate in candidates:
        try:
            if candidate.is_dir() and any(candidate.glob("*/meta.json")):
                return candidate
        except OSError:
            continue
    return None


# 32 hex characters, not 64. The credential sweep in this same file flags any
# `\b[A-Fa-f0-9]{40,}\b` as a "long hex blob", so a full sha256 in a TRACKED
# file trips the guard against itself — which is what happened the first time
# this pin was written. Exempting the pin by path was the other option and is
# exactly what this file's header refuses ("listed below by exact value so a
# NEW one cannot hide behind a path-level exemption"), and an exact-value
# allowlist would need editing on every refresh. 128 bits is far more than a
# content-change detector needs, and a truncated content digest genuinely is
# not a credential, so the honest fix is to stop it looking like one.
_DIGEST_HEX = 32


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:_DIGEST_HEX]


def _read_pinned_digests() -> dict:
    p = ROOT / DIGESTS_PATH
    if not p.is_file():
        return {}
    try:
        return dict((json.loads(p.read_text()) or {}).get("digests") or {})
    except (OSError, ValueError):
        return {}


def _write_pinned_digests(digests: dict) -> None:
    (ROOT / DIGESTS_PATH).write_text(json.dumps({
        "why": (
            "sha256 of each GENERATED artefact as it stood the last time the "
            "live accepted-flag oracle ran and passed. A clone has no "
            "data/jobs corpus, so it cannot run that oracle; matching these "
            "digests is how a corpus-less run establishes that the artefacts "
            "are the ones already verified. Refresh with "
            "`python3 scripts/test_no_committed_secrets.py --refresh-digests` "
            "on a host that has the corpus."
        ),
        "digests": dict(sorted(digests.items())),
    }, indent=2) + "\n")


def _accepted_flag_oracle(jobs_dir):
    """Exact accepted values; no prefix or flag-shape assumption."""
    accepted = set()
    scanned = 0
    for job_dir in sorted(jobs_dir.iterdir()):
        meta_path = job_dir / "meta.json"
        if not meta_path.is_file():
            continue
        scanned += 1
        for path in (meta_path, job_dir / "result.json"):
            try:
                payload = json.loads(path.read_text())
            except (OSError, ValueError):
                continue
            for value in payload.get("flags") or []:
                if isinstance(value, str) and value:
                    accepted.add(value)
    return accepted, scanned

PATTERNS = [
    ("vendor token", re.compile(
        r"\b(?:ctfd|ghp|gho|ghu|ghs|ghr|glpat|xox[baprs])_[A-Za-z0-9_\-]{10,}")),
    ("openai-style key", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}")),
    ("aws access key", re.compile(r"\bAKIA[0-9A-Z]{12,}")),
    ("jwt", re.compile(
        r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("labelled credential", re.compile(
        r"(?i)\b(?:token|api[_-]?key|apikey|secret|passwd|password|bearer)"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{20,}")),
    ("long hex blob", re.compile(r"\b[A-Fa-f0-9]{40,}\b")),
]

checks = 0
fails = 0


def chk(label, cond, got=None):
    global checks, fails
    checks += 1
    if cond:
        print("PASS  %s" % label)
    else:
        fails += 1
        print("FAIL  %s\n        got=%r" % (label, got))


print("--- generated artefacts must not carry credentials " + "-" * 8)
for rel in GENERATED:
    p = ROOT / rel
    chk("%s exists" % rel, p.is_file())
    if not p.is_file():
        continue
    raw = p.read_text(errors="replace")
    for name, pat in PATTERNS:
        found = pat.findall(raw)
        chk("%s carries no %s" % (rel, name), not found,
            [f[:12] + "..." for f in found[:3]])

print("")
print("--- and NO tracked file carries an unrecognised one " + "-" * 7)
unknown = []
scanned = 0
for rel, raw in _tracked_text_files():
    scanned += 1
    for name, pat in PATTERNS:
        for m in pat.finditer(raw):
            hit = m.group(0)
            if any(a in hit for a in ALLOWED_SUBSTRINGS):
                continue
            unknown.append((rel, name, hit[:28]))
chk("scanned a plausible number of tracked files", scanned > 100, scanned)
chk("no unrecognised credential-shaped string in any tracked file",
    not unknown, unknown[:5])

print("")
print("--- live accepted flags are an exact-value oracle " + "-" * 12)
# `data/` is never tracked, so a clone has no corpus and this oracle cannot
# run there. It used to print SKIP and let the run exit 0, which is where the
# hole was: an adversarial audit planted each of the 28 distinct accepted flags
# into a TRACKED artefact of a fresh clone one at a time, and 17 of them left
# the guard green. The credential PATTERNS carry no flag shape — the only ones
# caught were those whose payload happened to be >=40 hex characters — and a
# shape is the wrong oracle anyway, since the same artefacts legitimately hold
# REJECTED candidates that look identical to real flags.
#
# The values cannot be committed to give a clone an oracle; that would be the
# leak. What can be committed is the digest of each artefact as it stood when
# the oracle last ran and passed. Unchanged bytes carry that verification with
# them; changed bytes do not, and are refused here rather than skipped.
_gen_digests = {rel: _sha256_bytes((ROOT / rel).read_bytes())
                for rel in GENERATED if (ROOT / rel).is_file()}
_pinned = _read_pinned_digests()

live_jobs = _live_jobs_dir()
if live_jobs is None:
    print("NO CORPUS  the accepted-flag oracle cannot run here "
          "(data/ is untracked, so no clone has one)")
    if not _pinned:
        chk("a digest pin exists so a corpus-less run can still be sound "
            "(regenerate with --refresh-digests on the operator host)",
            False, DIGESTS_PATH)
    else:
        _drift = sorted(
            rel for rel in set(_gen_digests) | set(_pinned)
            if _gen_digests.get(rel) != _pinned.get(rel)
        )
        chk("every generated artefact is byte-identical to the state the "
            "oracle last verified — without the corpus that is the only thing "
            "that can be established here",
            not _drift, _drift)
        chk("the pin covers every listed generated artefact",
            sorted(_pinned) == sorted(GENERATED),
            {"pinned": sorted(_pinned), "listed": sorted(GENERATED)})
else:
    accepted, live_scanned = _accepted_flag_oracle(live_jobs)
    chk("the live flag oracle actually read job metadata (%d trees)"
        % live_scanned, live_scanned > 0, live_scanned)
    accepted_hits = []
    for rel, raw in _tracked_text_files():
        for value in accepted:
            if value in raw:
                accepted_hits.append((
                    rel,
                    "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:16],
                ))
    _oracle_clean = not accepted_hits
    chk("no exact accepted flag from meta.json or result.json is tracked — "
        "this is prefix-agnostic and also covers brace-less flags",
        _oracle_clean, accepted_hits[:8])
    if _REFRESH:
        if _oracle_clean:
            _write_pinned_digests(_gen_digests)
            print("      refreshed %s" % DIGESTS_PATH)
        else:
            print("      NOT refreshing the pin: the oracle did not pass")
    else:
        _drift = sorted(
            rel for rel in set(_gen_digests) | set(_pinned)
            if _gen_digests.get(rel) != _pinned.get(rel)
        )
        chk("the digest pin still matches — a generated artefact changed "
            "without the pin being refreshed would let a corpus-less run "
            "inherit a verification that no longer applies "
            "(refresh: --refresh-digests)",
            not _drift, _drift)

print("")
print("--- the generated-artefact list has not gone stale " + "-" * 6)
# This half used to exercise scripts/build_concept_benchmark.py's `_scrub`.
# That builder was the ONLY producer of a committed artefact made from live job
# data, and it was deleted with the ranker its benchmark scored — so the
# scrubber it defined has no subject and no caller. Reading it anyway is not a
# stricter test; it is a FileNotFoundError that killed this file before it
# printed a verdict, which is exactly how a security guard stops guarding
# without anyone noticing.
#
# The sweep above is the part that would have caught the original incident, and
# it does not depend on knowing which file was generated: it reads every
# tracked file as bytes. What is left to assert is that GENERATED describes
# reality, so that adding a new job-data-derived artefact cannot skip the
# targeted checks by simply not being listed.
for rel in GENERATED:
    chk("listed generated artefact %s exists" % rel, (ROOT / rel).is_file())
chk("no generated artefact is listed that does not exist",
    all((ROOT / rel).is_file() for rel in GENERATED), GENERATED)
_gone = [rel for rel in ("scripts/concept_benchmark.json",
                         "scripts/build_concept_benchmark.py",
                         "scripts/run_concept_benchmark.py")
         if (ROOT / rel).exists()]
chk("the deleted concept-benchmark files stayed deleted — if one returns it "
    "is job-derived again and needs a GENERATED entry plus a scrubber",
    not _gone, _gone)

print("")
print("%d checks, %d failed" % (checks, fails))
sys.exit(1 if fails else 0)
