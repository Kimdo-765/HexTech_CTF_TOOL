#!/usr/bin/env python3
"""rev must record WHAT the challenge is, not only HOW it was solved.

Run: python3 scripts/test_rev_technique_identity.py

The library indexer had one field for "technique" and, for rev, filled it from
`solver_strategy.approach`. That field enumerates solver METHODS -- static-emit,
constraint-solver, dynamic-trace -- so the 87 stored rev entries collapse onto
10 values. The median entry shares its technique with 13 others, which is MORE
than the twelve the library hint can display, so matching on it narrows
nothing. pwn, whose field is a specific attack name, has 52 distinct values
across 65 entries and a median share of 1.

That is not a shortage of concepts in rev challenges. It is a schema recording
a different kind of label, and the fallback in the indexer quietly presented
one as the other.

REPORT_SCHEMA_REV now asks for `solver_strategy.technique_name` -- the specific
mechanism -- next to `approach`. The indexer prefers it and keeps the old path
for entries saved before the change, so nothing already in the library moves.

Sliced from source: importing api.routes.exploits drags in fastapi.
"""
from __future__ import annotations

import ast
import json
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPLOITS_SRC = (ROOT / "api/routes/exploits.py").read_text()
COMMON_SRC = (ROOT / "modules/_common.py").read_text()

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


def section(name):
    print("\n--- %s %s" % (name, "-" * max(0, 56 - len(name))))


# ------------------------------------------------------------------ schema
section("the rev schema asks for an identity, separately from the method")
start = COMMON_SRC.index("REPORT_SCHEMA_REV")
rev_schema = COMMON_SRC[start:start + 1800]
chk("rev still asks for the solver method", '"approach":' in rev_schema)
chk("rev now also asks for a technique identity",
    '"technique_name":' in rev_schema)
chk("...and says it is not the solver method",
    "not how you solved it" in rev_schema)
chk("...and tells the model not to reuse an approach value",
    "do NOT reuse an `approach` value" in rev_schema)
# the two must be distinct keys inside solver_strategy, not one renamed
chk("both keys live in solver_strategy",
    rev_schema.index('"approach":') < rev_schema.index('"technique_name":')
    < rev_schema.index('"libs":'))

# ----------------------------------------------------------------- indexer
section("the indexer prefers identity, and keeps the old path working")
tree = ast.parse(EXPLOITS_SRC)
fn = next((n for n in ast.walk(tree)
           if isinstance(n, ast.FunctionDef) and "findings" in n.name.lower()
           and "technique" in (ast.get_source_segment(EXPLOITS_SRC, n) or "")),
          None)
chk("found the indexer", fn is not None)
body = ast.get_source_segment(EXPLOITS_SRC, fn) or ""
chk("it reads solver_strategy.technique_name",
    '_solver.get("technique_name")' in body)
chk("it still falls back to approach",
    '_solver.get("approach")' in body)
chk("chain.technique_name is still first for pwn/web/crypto",
    body.index('chain.get("technique_name")') < body.index('_solver.get("technique_name")'))

# exec just the indexer against fixture findings, so this is behaviour and not
# a reading of the source
ns: dict = {"_read_json": None}
exec(compile(ast.Module(body=[fn], type_ignores=[]), "<s>", "exec"), ns)
indexer = ns[fn.name]


def run(findings: dict):
    tmp = pathlib.Path(tempfile.mkdtemp())
    (tmp / "findings.json").write_text(json.dumps(findings))
    ns["_read_json"] = lambda p: json.loads(p.read_text()) if p.is_file() else None
    return indexer(tmp)


section("behavioural: which label reaches the library")
rev_new = {
    "chal_name": "r.0.0.mca",
    "solver_strategy": {"approach": "static-emit",
                        "technique_name": "minecraft-region-nbt"},
    "key_facts": [{"fact_class": "algorithm"}],
}
got = run(rev_new)
chk("a current rev save indexes the specific mechanism",
    got.get("technique_name") == "minecraft-region-nbt", got)
chk("...not the solver method", got.get("technique_name") != "static-emit", got)

rev_old = {
    "chal_name": "zrq",
    "solver_strategy": {"approach": "constraint-solver"},
    "key_facts": [{"fact_class": "algorithm"}],
}
got_old = run(rev_old)
chk("an entry saved before the change still resolves",
    got_old.get("technique_name") == "constraint-solver", got_old)

pwn_like = {
    "chal_name": "protoss",
    "chain": {"technique_name": "fsop_wfile"},
    "solver_strategy": {"approach": "static-emit",
                        "technique_name": "should-not-win"},
    "vulns": [{"bug_class": "oob-write"}],
}
got_pwn = run(pwn_like)
chk("chain.technique_name still wins where it exists",
    got_pwn.get("technique_name") == "fsop_wfile", got_pwn)
chk("...and bug classes still come from vulns",
    got_pwn.get("bug_classes") == ["oob-write"], got_pwn)

empty = run({"chal_name": "x"})
chk("nothing to index yields no technique",
    empty.get("technique_name") is None, empty)

section("the fallback is documented as a fallback, not a synonym")
chk("the code explains why approach is the wrong identity",
    "enumerates SOLVER METHODS" in EXPLOITS_SRC)
chk("...with the number that makes it concrete",
    "collapse onto 10 values" in EXPLOITS_SRC)
chk("...and states that existing entries do not move",
    "nothing" in EXPLOITS_SRC and "already in the library changes" in EXPLOITS_SRC)

print("")
print("%d checks, %d failed" % (checks, fails))
sys.exit(1 if fails else 0)
