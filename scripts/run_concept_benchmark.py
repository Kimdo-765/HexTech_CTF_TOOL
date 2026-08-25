#!/usr/bin/env python3
"""Score a candidate ranking idea against the frozen corpus. Offline only.

Run: python3 scripts/run_concept_benchmark.py

Reads scripts/concept_benchmark.json and reports, for each scorer, where the
one correct candidate lands among the four. It writes nothing, imports nothing
from the live hint path, and cannot change what an agent sees. The gate it
serves is simple: no production reordering until a scorer beats the baseline
here.

ON THE METRIC

recall@12 is meaningless on this corpus and is not reported. Each query has
four candidates and the hint shows twelve, so every scorer would score 1.0.
What discriminates is WHERE the positive lands, so this reports MRR and
precision@1, plus false promotions — negatives ranked above the positive,
which is the failure mode that actually costs an agent turns.

ON WHAT A GOOD RESULT WOULD AND WOULD NOT MEAN

Sixteen rows over four lineages is a smoke test, not evidence of general
retrieval quality. A scorer that wins here has cleared the first bar; it has
not earned a production reorder on its own. And every positive in this corpus
has `available_at_query: false`, so a win is a statement about semantic
similarity, never about recall that was achievable live.
"""
from __future__ import annotations

import collections
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIVE = pathlib.Path("/home/yadohyun/HexTech_CTF_TOOL")
MANIFEST = ROOT / "scripts/concept_benchmark.json"

_WORD = re.compile(r"[a-z0-9]{4,}")
_STOP = {
    "with", "this", "that", "from", "into", "when", "have", "will", "your",
    "flag", "challenge", "file", "files", "using", "used", "which", "then",
    "there", "their", "http", "https", "https", "code", "data", "does",
}


def _tokens(text: str) -> set[str]:
    return {w for w in _WORD.findall((text or "").lower()) if w not in _STOP}


def _norm_name(s: str) -> str:
    s = (s or "").strip().lower().rsplit("/", 1)[-1]
    for e in (".tar.gz", ".tgz", ".tar", ".zip", ".gz", ".elf", ".bin", ".exe"):
        if s.endswith(e):
            s = s[: -len(e)]
            break
    return re.sub(r"[^a-z0-9]+", "", s)


# ----------------------------------------------------------------- scorers
def score_name(row: dict, _cache: dict) -> float:
    """The shipped signal: normalized challenge-name relation."""
    q = _norm_name(row["query"].get("filename"))
    c = _norm_name(row["candidate_label"])
    if not q or not c:
        return 0.0
    if q == c:
        return 2.0
    return 1.0 if (q in c or c in q) else 0.0


def score_recency(row: dict, _cache: dict) -> float:
    """The shipped fallback: newer candidate wins, name ignored.

    Must rank by the actual timestamp. An earlier version returned a constant,
    which left `sorted` in input order and quietly measured nothing.
    """
    raw = str(row.get("candidate_produced_at") or "")
    if not raw:
        return float("-inf")
    try:
        return __import__("datetime").datetime.fromisoformat(
            raw.replace("Z", "+00:00")).timestamp()
    except Exception:
        return float("-inf")


def score_description_overlap(row: dict, cache: dict) -> float:
    """The cheapest concept idea: shared vocabulary between the pre-solve
    description and the candidate document."""
    path = LIVE / row["candidate_path"]
    if path not in cache:
        try:
            cache[path] = _tokens(path.read_text(errors="replace"))
        except OSError:
            cache[path] = set()
    q = _tokens(row["query"].get("description"))
    c = cache[path]
    if not q or not c:
        return 0.0
    return len(q & c) / float(len(q | c))


SCORERS = {
    "name (shipped)": score_name,
    "recency only": score_recency,
    "description-overlap": score_description_overlap,
}


def main() -> int:
    if not MANIFEST.is_file():
        print("no manifest — run scripts/build_concept_benchmark.py --write")
        return 1
    man = json.loads(MANIFEST.read_text())
    rows = man["rows"]

    print("corpus: %(rows)d rows, %(positives)d positive, %(negatives)d negative"
          % man["counts"])
    print("live recall: %s — %s" % (man["live_recall"], man["live_recall_basis"]))
    print()

    by_query = collections.defaultdict(list)
    for r in rows:
        by_query[r["query_root"]].append(r)

    def measure(fn, groups):
        cache: dict = {}
        rr, hits, promoted, n = [], 0, 0, 0
        for _q, group in sorted(groups):
            pos = [r for r in group if r["label"] == "positive"]
            if not pos:
                continue
            n += 1
            scored = sorted(group, key=lambda r: -fn(r, cache))
            rank = next(i for i, r in enumerate(scored, 1)
                        if r["label"] == "positive")
            rr.append(1.0 / rank)
            hits += 1 if rank == 1 else 0
            pos_score = fn(pos[0], cache)
            promoted += sum(1 for r in group if r["label"] == "negative"
                            and fn(r, cache) > pos_score)
        if not n:
            return None
        return sum(rr) / n, hits / float(n), promoted, n

    print("%-22s %6s %6s %10s %7s" %
          ("scorer", "MRR", "P@1", "false-promo", "queries"))
    for name, fn in SCORERS.items():
        got = measure(fn, by_query.items())
        if got:
            print("%-22s %6.3f %6.3f %10d %7d" % ((name,) + got))

    # Per module, because the whole finding is that the answer differs by
    # module: rev stores a solver METHOD where pwn stores an attack name.
    by_module = collections.defaultdict(lambda: collections.defaultdict(list))
    for r in rows:
        by_module[r["module"]][r["query_root"]].append(r)
    print()
    print("per module (%s):" % ", ".join(sorted(by_module)))
    print("%-10s %-22s %6s %6s %10s %7s" %
          ("module", "scorer", "MRR", "P@1", "false-promo", "queries"))
    for mod in sorted(by_module):
        for name, fn in SCORERS.items():
            got = measure(fn, by_module[mod].items())
            if got:
                print("%-10s %-22s %6.3f %6.3f %10d %7d" % ((mod, name) + got))

    # THE SUBSET THAT ACTUALLY ASKS THE QUESTION.
    #
    # A concept ranker exists to help when the NAME says nothing. If a query's
    # positive is already an exact name match, the shipped ranker retrieves it
    # and there is nothing for concepts to add — scoring those rows measures
    # the name signal wearing a different hat. Split them out.
    hard = {q: g for q, g in by_query.items()
            if not any(r["label"] == "positive"
                       and r.get("name_relation") == "exact" for r in g)}
    easy = len(by_query) - len(hard)
    print()
    print("queries whose positive the NAME already retrieves: %d/%d"
          % (easy, len(by_query)))
    print("queries where the name says nothing — the concept question: %d"
          % len(hard))
    if hard:
        print("%-22s %6s %6s %10s %7s" %
              ("scorer", "MRR", "P@1", "false-promo", "queries"))
        for name, fn in SCORERS.items():
            got = measure(fn, hard.items())
            if got:
                print("%-22s %6.3f %6.3f %10d %7d" % ((name,) + got))
    else:
        print("  (none — this corpus cannot answer the concept question)")
    print()
    print("Read the split before the totals. The ground truth available here is")
    print("'same retry lineage', and a lineage keeps its filename, so the name")
    print("signal reproduces the labels almost exactly. That is a property of")
    print("the LABELS, not evidence that names are sufficient in general.")

    print()
    print("Beating the baseline here is the first bar, not a licence to")
    print("reorder the production hint. Every positive in this corpus has")
    print("available_at_query=false, so a win is a statement about semantic")
    print("similarity and never about recall that was achievable live.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
