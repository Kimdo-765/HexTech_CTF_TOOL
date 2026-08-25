#!/usr/bin/env python3
"""Score a candidate ranking idea against the frozen corpus. Offline only.

Run: python3 scripts/run_concept_benchmark.py

Reads scripts/concept_benchmark.json and reports, for each scorer, where the
one correct candidate lands among its module's lineages. It writes nothing,
imports nothing into the live hint path, and cannot change what an agent sees.

WHAT THIS CORPUS TURNED OUT TO SHOW

Run it and the last section says: queries where the name says nothing — 0.

That is the result. The only ground truth available here is "same retry
lineage", and a lineage keeps its filename, so a positive is a name match by
construction. There is no subset left over for a concept signal to win. An
earlier version appeared to have three such queries; those three came from a
table in the builder that renamed the candidate (`CVE-2015-2291.exe` ->
`windows-pdf-driver` and two more). Renaming a candidate and then observing
that its name no longer matches measures the rename.

So this benchmark cannot decide whether a concept ranker is worth building.
Deciding it needs ground truth of a different kind — pairs of DIFFERENT
challenges a person has labelled as conceptually related. That is a bigger
ask than more of this data, and pretending otherwise was the error.

ON THE METRICS

recall@12 is not reported: a query has at most a dozen same-module candidates
and the hint shows twelve, so every scorer would read 1.0.

Ties count against a scorer in both MRR and false-promotions. A negative that
merely MATCHES the positive's score is just as likely to be displayed, and
ranking the positive first out of a tie is list order, not retrieval. Counting
only strictly-higher negatives reported 0 false promotions for the name
baseline when 40 negatives tied above it, and gave a constant scorer a perfect
zero.

The name baseline is SLICED from modules/_common.py rather than re-typed here.
A local reimplementation called itself "the shipped signal" while omitting the
stoplist and the containment floor, which inflated the very baseline every
other scorer was being judged against.
"""
from __future__ import annotations

import ast
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
def _shipped_score():
    """Slice the REAL scorer out of modules/_common.py.

    A reimplementation here called itself "the shipped signal" and was not one:
    it omitted `_LIBRARY_STOP_NAMES` and `_MIN_CONTAINMENT_CHARS`. Eleven of the
    34 queries normalize to a stop word (`foruser` x7, `main` x3, `prob`), and
    for all eleven the reimplementation awarded the positive 2.0 where the
    shipped scorer awards 0.0 -- so the baseline the whole benchmark is judged
    against was inflated by exactly the suppression this branch added.
    """
    src = (ROOT / "modules/_common.py").read_text()
    tree = ast.parse(src)
    want = {"_norm_chal", "_LIBRARY_STOP_NAMES", "_MIN_CONTAINMENT_CHARS"}
    nodes = [n for n in tree.body
             if (isinstance(n, ast.FunctionDef) and n.name in want)
             or (isinstance(n, ast.Assign)
                 and any(getattr(t, "id", "") in want for t in n.targets))]
    ns: dict = {"re": re}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<s>", "exec"), ns)
    norm, stop, floor = (ns["_norm_chal"], ns["_LIBRARY_STOP_NAMES"],
                         ns["_MIN_CONTAINMENT_CHARS"])

    def score(query_name: str, candidate_name: str) -> float:
        want_n = norm(query_name)
        if not want_n or want_n in stop:
            return 0.0
        got = norm(candidate_name)
        if not got or got in stop:
            return 0.0
        if got == want_n:
            return 2.0
        if not (got in want_n or want_n in got):
            return 0.0
        return 1.0 if min(len(got), len(want_n)) >= floor else 0.0

    return score


_SHIPPED = _shipped_score()


def score_name(row: dict, _cache: dict) -> float:
    """The shipped signal, sliced from production rather than re-typed.

    Compares against `candidate_identity` -- the lineage's REAL filename. The
    manifest also carries a human-readable `candidate_label`, and scoring that
    instead would have measured a rename.
    """
    return _SHIPPED(row["query"].get("filename"),
                    row.get("candidate_identity") or row["candidate_label"])


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
            # Ties count against the scorer, on both metrics. Ranking the
            # positive by list position after a tie is not retrieval, and a
            # negative that MATCHES the positive's score is just as likely to
            # be shown. Counting only strictly-higher negatives reported 0
            # false promotions for the name baseline when 40 negatives
            # actually tied above it, and gave a constant scorer a perfect 0.
            pos_score = fn(pos[0], cache)
            better = sum(1 for r in group if r["label"] == "negative"
                         and fn(r, cache) > pos_score)
            tied = sum(1 for r in group if r["label"] == "negative"
                       and fn(r, cache) == pos_score)
            rank = better + 1                       # optimistic within the tie
            worst_rank = better + tied + 1          # pessimistic within it
            rr.append(1.0 / ((rank + worst_rank) / 2.0))   # expected position
            hits += 1 if (better == 0 and tied == 0) else 0
            promoted += better + tied
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
