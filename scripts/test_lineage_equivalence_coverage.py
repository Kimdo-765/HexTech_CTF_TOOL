#!/usr/bin/env python3
"""The K2 corpus must state what it did NOT judge.

Run: python3 scripts/test_lineage_equivalence_coverage.py

WHY THIS EXISTS

`totals` used to read `pairs: 33, undecided: 0`. The possible pairs are 34 —
sum of C(n,2) over the five lineages — so one pair was missing from the
denominator with nothing in the file to say so. `33/undecided 0` therefore read
as "34 of 34 judged, none ambiguous". The missing pair is the forensic lineage
b7c25bb93d13 <-> 56b4d47d5b4c: BOTH attempts were cut off before naming a
mechanism, so the same/different question had no input on either side.

That pair must NOT become `undecided`. Undecided means the question was asked
of real observations and could not be answered; this pair was never in the
population. It is recorded as its own unit, `excluded_unobserved`.

WHY THESE CHECKS RECOMPUTE INSTEAD OF COMPARING TO 34

A literal 34 in the artifact is a second number to keep in sync, and it rots
the first time a lineage is added. Every count here is derived from the seed's
own `lineages` block, and the coverage line is asserted as an INVARIANT
(possible == eligible + excluded) rather than as a remembered value.
"""
from __future__ import annotations

import json
import os
import sys
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "scripts" / "lineage_equivalence_seed.json"
LABELLED = ROOT / "scripts" / "lineage_equivalence_labelled.json"

checks = 0
fails = 0


def chk(label, got, want):
    global checks, fails
    checks += 1
    if got == want:
        print("PASS  %s" % label)
    else:
        fails += 1
        print("FAIL  %s\n        got  = %r\n        want = %r" % (label, got, want))


seed = json.loads(SEED.read_text())
lab = json.loads(LABELLED.read_text())
totals = lab["totals"]


def _live_jobs_dir() -> Path | None:
    """Find the real corpus from either the main checkout or a worker."""
    candidates = []
    if os.environ.get("HEXTECH_LIVE_JOBS"):
        candidates.append(Path(os.environ["HEXTECH_LIVE_JOBS"]))
    candidates.extend((Path("/data/jobs"), ROOT / "data" / "jobs"))

    common = ROOT / ".git"
    if common.is_file():
        try:
            line = common.read_text().strip()
            if line.startswith("gitdir:"):
                git_dir = Path(line.split(":", 1)[1].strip())
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


def _live_retry_graph(jobs_dir: Path, scope_date: str):
    """Rebuild all multi-attempt lineages started on the seed's date."""
    metas = {}
    for meta_path in sorted(jobs_dir.glob("*/meta.json")):
        try:
            metas[meta_path.parent.name] = json.loads(meta_path.read_text())
        except (OSError, ValueError):
            continue

    def parent(job_id):
        meta = metas.get(job_id) or {}
        return meta.get("retry_of") or meta.get("resumed_from")

    def root_of(job_id):
        seen = set()
        while parent(job_id) in metas and parent(job_id) not in seen:
            seen.add(job_id)
            job_id = parent(job_id)
        return job_id

    grouped = {}
    for job_id, meta in metas.items():
        if str(meta.get("started_at") or "")[:10] != scope_date:
            continue
        grouped.setdefault(root_of(job_id), []).append(job_id)

    graph = {}
    for root, job_ids in grouped.items():
        if len(job_ids) < 2:
            continue
        graph[root] = sorted(
            job_ids,
            key=lambda job_id: (str(metas[job_id].get("started_at") or ""),
                                job_id),
        )
    return graph, len(metas)


print("--- the seed is bound to the live retry graph " + "-" * 12)
live_jobs = _live_jobs_dir()
if live_jobs is None:
    print("SKIP  live jobs corpus is unavailable")
else:
    live_graph, live_meta_count = _live_retry_graph(live_jobs, seed["built"])
    seed_graph = {
        lineage["root"]: [attempt["job_id"] for attempt in lineage["attempts"]]
        for lineage in seed["lineages"]
    }
    chk("the live corpus was actually read (%d job trees)" % live_meta_count,
        live_meta_count > 0, True)
    chk("REGRESSION: seed roots and ordered attempts equal every multi-attempt "
        "lineage in the live corpus for %s" % seed["built"],
        seed_graph, live_graph)

print("--- the denominator is derived from the seed " + "-" * 13)
lineages = seed["lineages"]
chk("the seed actually has lineages to count (a zero here means the file "
    "changed shape, not that coverage is complete)", len(lineages) > 0, True)

possible = sum(len(L.get("attempts") or []) * (len(L.get("attempts") or []) - 1) // 2
               for L in lineages)
chk("possible_pairs == sum of C(n,2) recomputed from the seed",
    totals["possible_pairs"], possible)

eligible = len(seed["pairs"])
chk("eligible_pairs == the number of pairs the seed actually carries",
    totals["eligible_pairs"], eligible)

print("")
print("--- the coverage line is an invariant, not three numbers " + "-" * 1)
chk("REGRESSION: possible == eligible + excluded_unobserved, so a pair cannot "
    "leave the denominator silently again",
    totals["possible_pairs"],
    totals["eligible_pairs"] + totals["excluded_unobserved"])
chk("the itemised exclusions match the count",
    len(totals["excluded"]), totals["excluded_unobserved"])

print("")
print("--- the excluded pair is the one measured, and is real " + "-" * 3)
seed_pairs = {(p["a_job"], p["b_job"]) for p in seed["pairs"]}
computed_excluded = set()
for L in lineages:
    for a, b in combinations(L.get("attempts") or [], 2):
        if (a["job_id"], b["job_id"]) not in seed_pairs:
            computed_excluded.add((a["job_id"], b["job_id"]))
chk("the exclusion list is exactly the set the seed implies",
    sorted(computed_excluded),
    sorted((e["a_job"], e["b_job"]) for e in totals["excluded"]))

by_job = {a["job_id"]: a
          for L in lineages for a in (L.get("attempts") or [])}
for e in totals["excluded"]:
    for side in ("a", "b"):
        att = by_job.get(e["%s_job" % side])
        chk("excluded %s side %s: the seed agrees it named no mechanism"
            % (e["%s_job" % side], side),
            (att or {}).get("technique_name"), None)
        chk("excluded %s side %s: the recorded technique matches the seed"
            % (e["%s_job" % side], side),
            e["%s_technique" % side], (att or {}).get("technique_name"))
    chk("...and it is booked as unobserved, NOT as undecided",
        e["reason"], "unobserved")

print("")
print("--- the 33 labels are untouched " + "-" * 26)
chk("REGRESSION: the labelled verdicts did not move — coverage is a separate "
    "unit from the judgments",
    (totals["pairs"], totals["same"], totals["different"],
     totals["undecided"], totals["disputed"]),
    (33, 27, 6, 0, 0))
chk("same + different + undecided still accounts for every label",
    totals["same"] + totals["different"] + totals["undecided"],
    totals["pairs"])
chk("`pairs` counts labels and equals the eligible population",
    totals["pairs"], totals["eligible_pairs"])

labelled_pairs = sum(len(L.get("pairs") or []) for L in lab["labels"])
chk("the per-lineage label blocks sum to the same number",
    labelled_pairs, totals["pairs"])

decided = [p for L in lab["labels"] for p in (L.get("pairs") or [])]
chk("every labelled pair carries a same_concept verdict",
    sorted({str(p.get("same_concept")) for p in decided}), ["False", "True"])
chk("the `same` tally is the real count of True verdicts, not a remembered one",
    sum(1 for p in decided if p.get("same_concept") is True), totals["same"])
chk("...and `different` likewise",
    sum(1 for p in decided if p.get("same_concept") is False),
    totals["different"])

print("")
print("--- the excluded pair keeps a lineage that produced no labels " + "-" * 0)
excluded_roots = {e["lineage_root"] for e in totals["excluded"]}
for L in lab["labels"]:
    if L["lineage_root"] in excluded_roots:
        chk("the excluded lineage's label block is empty, and that emptiness "
            "is now explained rather than merely absent",
            len(L.get("pairs") or []), 0)

print("")
print("%d checks, %d failed" % (checks, fails))
sys.exit(1 if fails else 0)
