#!/usr/bin/env python3
"""Freeze the labeled corpus for the concept-ranker question. NOT a ranker.

Run: python3 scripts/build_concept_benchmark.py [--write] [--rev-only]

WHY THIS EXISTS, AND WHY IT IS NOT A RANKER

The name ranker cannot help a challenge whose name resembles nothing stored.
Real rev calls across four retry lineages are in that position, and the
proposal was to rank them by concept instead. Before building that, two things
had to be measured, and both came back negative for the obvious approach:

  * Joining library entries to those lineages and applying
    `saved_at < query started_at`, the number of related entries that actually
    EXISTED when the query ran is zero. So "recall" has no denominator there.
    The honest statement is verified retrieval opportunity 0, not recall 0.

  * The fields a meta-only ranker would use could not separate rev entries.
    87 rev entries carried 10 distinct technique values; the median entry
    shared its value with 13 others, MORE than the 12 the hint can show. The
    cause was in the schema -- rev's field enumerated solver METHODS -- and is
    now fixed forward: REPORT_SCHEMA_REV asks for a specific mechanism next to
    `approach`. Existing entries keep the old label, so this corpus still sees
    the old vocabulary and will keep seeing it until new saves accumulate.

So the question is open, and the way to answer it is an offline benchmark with
labels fixed in advance, not a production reorder. Nothing here changes what
any agent sees.

THE THREE RULES THAT MAKE IT HONEST

1. The query side carries only what existed when ranking happened: the
   description and the filename from job meta. A report written after the
   challenge was solved describes the answer, so scoring a query built from it
   measures hindsight, not retrieval.

2. Negatives are drawn from the SAME MODULE. A rev report against a web report
   is trivially separable by vocabulary, and a benchmark full of those reports
   a high score that means nothing about the decision at hand.

3. Every row records `available_at_query`. A candidate produced after its query
   ran can be scored for semantic similarity offline, but it must never enter a
   live recall denominator.
"""
from __future__ import annotations

import argparse
import collections
import datetime
import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIVE = pathlib.Path("/home/yadohyun/HexTech_CTF_TOOL/data")
JOBS = LIVE / "jobs"
OUT = ROOT / "scripts/concept_benchmark.json"

# The four rev lineages the name ranker cannot reach. Kept as a named subset so
# the original four-root result stays reproducible after the corpus grew.
REV_SEED_ROOTS = {
    "d5bd07ce0865": "minecraft-region",
    "1f681ea2b8e6": "zrq",
    "5d4ba07beba7": "windows-pdf-driver",
    "f94c35eb16a2": "maze-client",
}

CANDIDATE_FILES = ("work/findings.json", "findings.json", "work/report.md")
MIN_DOC_BYTES = 400


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


# Job descriptions are free text an operator typed, and this file is committed.
# One of them contained a live CTFd API token, which reached the repository and
# was pushed before review caught it. Registered job secrets are handled by
# modules.job_secrets.redact_job_value; a credential the operator merely TYPED
# into the description was never registered, so nothing scrubbed it.
#
# Both layers now run. The pattern layer is deliberately broad: a false
# redaction costs a few tokens of benchmark vocabulary, a missed one costs a
# credential.
_SECRET_PATTERNS = (
    re.compile(r"\b(?:ctfd|ghp|gho|ghu|ghs|ghr|glpat|xox[baprs])_[A-Za-z0-9_\-]{10,}"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\bAKIA[0-9A-Z]{12,}"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    # generic "<word that means credential> <sep> <long opaque blob>"
    re.compile(r"(?i)\b(?:token|api[_-]?key|apikey|secret|passwd|password|bearer)"
               r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{20,})"),
    re.compile(r"\b[A-Fa-f0-9]{40,}\b"),          # long hex blobs
)


def _scrub(text: str, job_id: str = "") -> str:
    """Remove credentials from operator-authored text before it is committed."""
    if not text:
        return text
    if job_id:
        try:
            from modules.job_secrets import redact_job_value
            text = redact_job_value(job_id, text)
        except Exception:
            pass
    for pat in _SECRET_PATTERNS:
        text = pat.sub(lambda m: (m.group(0)[: m.start(1) - m.start(0)]
                                  + "[REDACTED]") if m.groups() else "[REDACTED]",
                       text)
    return text


def _norm_name(s: str) -> str:
    s = (s or "").strip().lower().rsplit("/", 1)[-1]
    for e in (".tar.gz", ".tgz", ".tar", ".zip", ".gz", ".elf", ".bin", ".exe"):
        if s.endswith(e):
            s = s[: -len(e)]
            break
    return re.sub(r"[^a-z0-9]+", "", s)


def _name_relation(query_name: str, candidate_name: str) -> str:
    q, c = _norm_name(query_name), _norm_name(candidate_name)
    if not q or not c:
        return "no-name"
    if q == c:
        return "exact"
    return "contain" if (q in c or c in q) else "unrelated"


def _identity_for(root: str, metas: dict) -> str:
    """What the NAME signal would see for this lineage: its real filename.

    This used to return a hand-written alias for three of the four seed roots
    (`CVE-2015-2291.exe` -> `windows-pdf-driver`, `r.0.0.mca` ->
    `minecraft-region`, `client_old` -> `maze-client`) and the real filename for
    the other 31. Those three substitutions WERE the "3 queries where the name
    says nothing" subset -- the previous headline result. Renaming a candidate
    and then observing that its name no longer matches measures the rename.

    Names used for scoring are now always the real ones. A human-readable alias
    is kept separately, for reading the manifest, and never reaches a scorer.
    """
    name = ((metas.get(root) or {}).get("filename") or root).strip()
    return name.rsplit("/", 1)[-1][:60] or root


def _display_for(root: str, metas: dict) -> str:
    """A readable name for humans skimming the manifest. Never scored."""
    return REV_SEED_ROOTS.get(root) or _identity_for(root, metas)


def build(rev_only: bool = False) -> dict:
    metas = _load_metas()
    chains: dict[str, list[str]] = collections.defaultdict(list)
    for job in metas:
        chains[_root_of(job, metas)].append(job)

    # A lineage is usable when its root has a description to query with and
    # some job in the chain produced a document to retrieve.
    lineages = {}
    for root, members in chains.items():
        rm = metas.get(root) or {}
        module = (rm.get("module") or "?").lower()
        if rev_only and module != "rev":
            continue
        if not (rm.get("description") or "").strip():
            continue
        best = None
        for job in sorted(members):
            for rel in CANDIDATE_FILES:
                p = JOBS / job / rel
                if not p.is_file() or p.stat().st_size <= MIN_DOC_BYTES:
                    continue
                cand = {
                    "job": job,
                    "path": str(p.relative_to(LIVE.parent)),
                    "bytes": p.stat().st_size,
                    "produced_at": (metas.get(job) or {}).get("updated_at"),
                }
                if best is None or cand["bytes"] > best["bytes"]:
                    best = cand
        if best is None:
            continue
        lineages[root] = {
            "module": module,
            "identity": _identity_for(root, metas),
            "label": _display_for(root, metas),
            "chain_len": len(members),
            "candidate": best,
            "query": {
                "root": root,
                "module": module,
                "label": _display_for(root, metas),
                "filename": rm.get("filename"),
                "description": _scrub((rm.get("description") or "").strip(), root),
                "started_at": rm.get("started_at"),
                "source": "data/jobs/%s/meta.json" % root,
                "fields_used": ["description", "filename"],
                "leakage_guard": (
                    "pre-solve fields only — no report, findings or solver text "
                    "on the query side"
                ),
            },
        }

    by_module: dict[str, list[str]] = collections.defaultdict(list)
    for root, info in lineages.items():
        by_module[info["module"]].append(root)

    rows = []
    for q_root, q in sorted(lineages.items()):
        # Rule 2: negatives come from the same module only.
        peers = [r for r in by_module[q["module"]] if r != q_root]
        if not peers:
            continue                     # a lone lineage cannot be scored
        q_started = _ts(q["query"]["started_at"])
        # Order candidates by a hash of the pair, not positive-first. Listing
        # the positive first let a scorer that TIES with a negative still win
        # on stable-sort order -- the name scorer scored a perfect 1.000 that
        # way. Position must carry no signal.
        ordered = sorted([q_root] + peers,
                         key=lambda r: hashlib.sha256(
                             (q_root + "|" + r).encode()).hexdigest())
        for c_root in ordered:
            cand = lineages[c_root]["candidate"]
            produced = _ts(cand["produced_at"])
            rows.append({
                "module": q["module"],
                "query_root": q_root,
                "query_label": q["label"],
                "candidate_root": c_root,
                "candidate_label": lineages[c_root]["label"],
                "candidate_identity": lineages[c_root]["identity"],
                "candidate_job": cand["job"],
                "candidate_path": cand["path"],
                "candidate_bytes": cand["bytes"],
                "candidate_produced_at": cand["produced_at"],
                "label": "positive" if c_root == q_root else "negative",
                "label_basis": (
                    "same retry lineage, root %s" % q_root if c_root == q_root
                    else "different lineage in the same module: %s vs %s"
                         % (q["label"], lineages[c_root]["label"])
                ),
                "available_at_query": bool(
                    q_started and produced and produced < q_started),
                # How the NAME signal already relates this pair. The concept
                # question only exists where the name says nothing, so a row
                # whose positive is name-exact cannot test it: the shipped
                # ranker would already have retrieved that candidate.
                "name_relation": _name_relation(
                    q["query"].get("filename"), lineages[c_root]["identity"]),
                "query": q["query"],
            })

    positives = [r for r in rows if r["label"] == "positive"]
    live_den = sum(1 for r in positives if r["available_at_query"])
    mods = collections.Counter(r["module"] for r in rows)
    return {
        "schema_version": 2,
        "purpose": "offline labeled corpus for the concept-ranker question",
        "production_use": "FORBIDDEN — this never reorders a live hint",
        "negatives_policy": "same module only; cross-module pairs are trivially separable",
        "query_policy": "description + filename as of rank time; no post-solve text",
        "rev_seed_roots": REV_SEED_ROOTS,
        "counts": {
            "rows": len(rows),
            "queries": len({r["query_root"] for r in rows}),
            "positives": len(positives),
            "negatives": len(rows) - len(positives),
            "positives_available_at_query": live_den,
            "rows_by_module": dict(mods),
        },
        # Always N/A, and structurally so rather than by luck: a positive's
        # candidate is drawn from the query root's OWN chain, and api/storage
        # stamps meta.updated_at at or after started_at, so produced_at can
        # never precede the query. The old `else None` branch was unreachable,
        # and a None here would have printed a caveat claiming a denominator
        # that does not exist. If the construction ever changes so that a
        # positive predates its query, this must become a real number and the
        # caveat must be rewritten -- it does not fall out correctly on its own.
        "live_recall": "N/A",
        "live_recall_unreachable_by_construction": True,
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
    ap.add_argument("--rev-only", action="store_true",
                    help="restrict to rev lineages (11 queries / 121 rows). "
                         "This does NOT reproduce the first four-root corpus: "
                         "that had 16 rows and no longer exists in this tree.")
    args = ap.parse_args()

    manifest = build(rev_only=args.rev_only)
    c = manifest["counts"]
    print("queries=%(queries)d rows=%(rows)d positives=%(positives)d "
          "negatives=%(negatives)d" % c)
    print("by module: %s" % c["rows_by_module"])
    print("positives available at query time: %d  -> live recall %s"
          % (c["positives_available_at_query"], manifest["live_recall"]))
    seeds = [r for r in manifest["rows"]
             if r["query_root"] in REV_SEED_ROOTS and r["label"] == "positive"]
    print("the four seed rev lineages are still present: %d/4" % len(seeds))

    if args.write:
        OUT.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        print("wrote %s" % OUT.relative_to(ROOT))
    else:
        print("(dry run — pass --write to freeze)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
