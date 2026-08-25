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

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Files built from live job data, i.e. the ones that can inherit operator text.
GENERATED = [
    "scripts/concept_benchmark.json",
]

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
print("--- the builder scrubs, and is wired to do so " + "-" * 12)
builder = (ROOT / "scripts/build_concept_benchmark.py").read_text()
chk("the builder defines a scrubber", "def _scrub(" in builder)
chk("...and applies it to the description it commits",
    "_scrub((rm.get(\"description\")" in builder)
chk("...and also asks job_secrets for registered secrets",
    "redact_job_value" in builder)

# behavioural: the scrubber actually removes a token of the shape that leaked
sys.path.insert(0, str(ROOT / "scripts"))
import importlib.util
spec = importlib.util.spec_from_file_location(
    "_bcb", ROOT / "scripts/build_concept_benchmark.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

LEAKED_SHAPE = "ctfd_" + "a" * 60
sample = "use the api, token : %s and then post" % LEAKED_SHAPE
out = mod._scrub(sample)
chk("the scrubber removes a ctfd-style token", LEAKED_SHAPE not in out, out)
chk("...and leaves the surrounding sentence readable",
    "use the api" in out and "and then post" in out, out)
chk("a description with no credential is untouched",
    mod._scrub("decode the region file and print the flag")
    == "decode the region file and print the flag")
for shape in ("sk-" + "b" * 30, "AKIA" + "C" * 16, "d" * 44):
    chk("the scrubber removes %r" % (shape[:8] + "..."),
        shape not in mod._scrub("key: " + shape))

print("")
print("%d checks, %d failed" % (checks, fails))
sys.exit(1 if fails else 0)
