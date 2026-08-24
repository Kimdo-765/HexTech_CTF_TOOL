#!/usr/bin/env python3
"""Freeze the labeled corpus for the concept-ranker question. NOT a ranker.

Run: python3 scripts/build_concept_benchmark.py [--write]

WHY THIS EXISTS, AND WHY IT IS NOT A RANKER

The name ranker cannot help a challenge whose name resembles nothing stored.
Eleven real rev calls across four retry lineages are in that position, and the
proposal was to rank them by concept instead. Before building that, two things
had to be measured, and both came back negative for the obvious approach:

  * Joining library entries to those lineages and applying
    `saved_at < query started_at`, the number of related entries that actually
    EXISTED when the query ran is zero. So "recall" has no denominator here.
    The honest statement is verified retrieval opportunity 0, not recall 0.

  * The fields a meta-only ranker would use cannot separate rev entries anyway.
    87 rev entries carry 10 distinct `technique_name` values; the median entry
    shares its value with 13 others, which is MORE than the 12 the hint can
    show. `bug_classes` returns 60 of 87. The cause is in the schema: rev's
    field is `approach` and enumerates solver METHODS (`static-emit`,
    `constraint-solver`, `dynamic-trace`), while pwn/web/crypto record a
    specific attack name — pwn has 52 distinct values across 65 entries, median
    share 1.

So the question is open, and the way to answer it is an offline benchmark with
labels fixed in advance, not a production reorder. This script freezes that
benchmark. Nothing here changes what any agent sees.

THE TWO RULES THAT MAKE IT HONEST

1. The query side carries only what existed when ranking happened: the
   description and the filename from job meta. A report written after the
   challenge was solved describes the answer, so scoring a query built from it
   measures hindsight, not retrieval.

2. Every row records `available_at_query`. A candidate produced after its query
   ran can be scored for semantic similarity offline, but it must never enter a
   live recall denominator. On this corpus that flag is false for every
   positive, which is exactly why live recall is reported as N/A.
"""
from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIVE = pathlib.Path("/home/yadohyun/HexTech_CTF_TOOL/data")
JOBS = LIVE / "jobs"
OUT = ROOT / "scripts/concept_benchmark.json"

# The four retry lineages whose rev calls the name ranker cannot reach.
ROOTS = {
    "d5bd07ce0865": "minecraft-region",
    "1f681ea2b8e6": "zrq",
    "5d4ba07beba7": "windows-pdf-driver",
    "f94c35eb16a2": "maze-client",
}


def _load_metas() -> dict:
    metas = {}
    for d in sorted(JOBS.iterdir()):
        p = d / "meta.json"
        if not p.is_file():
            continue
        try:
            metas[d.name] = json.loads(p.read_text())
        except Exception:
            continue
    return metas


def _root_of(job: str, metas: dict) -> str:
    seen: set[str] = set()
    while job and job not in seen:
        seen.add(job)
        parent = (metas.get(job) or {}).get("retry_of")
        if not parent or parent not in metas:
            return job
        job = parent
    return job


def _ts(value):
    if not value:
        return None
    try:
        return datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def build() -> dict:
    metas = _load_metas()
    chains = {r: sorted(j for j in metas if _root_of(j, metas) == r) for r in ROOTS}

    # ONE candidate document per lineage: the largest findings/report in the
    # chain. One per root keeps the matrix at 4 positives and 12 negatives.
    candidates = {}
    for root, members in chains.items():
        best = None
        for job in members:
            for rel in ("work/findings.json", "findings.json", "work/report.md"):
                p = JOBS / job / rel
                if not p.is_file() or p.stat().st_size <= 200:
                    continue
                cand = {
                    "job": job,
                    "path": str(p.relative_to(LIVE.parent)),
                    "bytes": p.stat().st_size,
                    "produced_at": (metas.get(job) or {}).get("updated_at"),
                }
                if best is None or cand["bytes"] > best["bytes"]:
                    best = cand
        candidates[root] = best

    missing = [r for r, c in candidates.items() if c is None]
    if missing:
        raise SystemExit("no candidate document for lineage(s): %s" % missing)

    rows = []
    for q_root, q_label in ROOTS.items():
        qm = metas[q_root]
        q_started = _ts(qm.get("started_at"))
        query = {
            "root": q_root,
            "label": q_label,
            "filename": qm.get("filename"),
            "description": (qm.get("description") or "").strip(),
            "started_at": qm.get("started_at"),
            "source": "data/jobs/%s/meta.json" % q_root,
            "fields_used": ["description", "filename"],
            "leakage_guard": (
                "pre-solve fields only — no report, findings or solver text on "
                "the query side"
            ),
        }
        for c_root, c_label in ROOTS.items():
            cand = candidates[c_root]
            produced = _ts(cand["produced_at"])
            rows.append({
                "query_root": q_root,
                "query_label": q_label,
                "candidate_root": c_root,
                "candidate_label": c_label,
                "candidate_job": cand["job"],
                "candidate_path": cand["path"],
                "candidate_bytes": cand["bytes"],
                "candidate_produced_at": cand["produced_at"],
                "label": "positive" if c_root == q_root else "negative",
                "label_basis": (
                    "same retry lineage, root %s" % q_root if c_root == q_root
                    else "different lineage: %s vs %s" % (q_label, c_label)
                ),
                "available_at_query": bool(
                    q_started and produced and produced < q_started),
                "query": query,
            })

    positives = [r for r in rows if r["label"] == "positive"]
    live_denominator = sum(1 for r in positives if r["available_at_query"])
    return {
        "schema_version": 1,
        "purpose": "offline labeled corpus for the concept-ranker question",
        "production_use": "FORBIDDEN — this never reorders a live hint",
        "roots": ROOTS,
        "counts": {
            "rows": len(rows),
            "positives": len(positives),
            "negatives": len(rows) - len(positives),
            "positives_available_at_query": live_denominator,
        },
        "live_recall": "N/A" if live_denominator == 0 else None,
        "live_recall_basis": (
            "no positive candidate existed when its query ran, so a live recall "
            "denominator cannot be formed; offline semantic scoring is still "
            "valid on these rows"
        ),
        "rows": rows,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true",
                    help="write scripts/concept_benchmark.json")
    args = ap.parse_args()

    manifest = build()
    c = manifest["counts"]
    print("rows=%(rows)d positives=%(positives)d negatives=%(negatives)d"
          % c)
    print("positives available at query time: %d  -> live recall %s"
          % (c["positives_available_at_query"], manifest["live_recall"]))
    for root, label in ROOTS.items():
        row = next(r for r in manifest["rows"]
                   if r["query_root"] == root and r["label"] == "positive")
        print("   %-14s %-20s candidate=%s (%d bytes, available=%s)"
              % (root, label, row["candidate_job"], row["candidate_bytes"],
                 row["available_at_query"]))

    if args.write:
        OUT.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        print("wrote %s" % OUT.relative_to(ROOT))
    else:
        print("(dry run — pass --write to freeze)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
