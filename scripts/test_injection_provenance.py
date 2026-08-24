#!/usr/bin/env python3
"""What the orchestrator injects into main must be recoverable afterwards.

Run: python3 scripts/test_injection_provenance.py

Four producers reach `_format_postjudge_user_turn` and one of them fired live
in `579a216ed747`. The run.log proves a redirect was injected and
`result.json` already carries `reviewer_redirects` / `reviewer_hint_chars` —
but nothing recorded WHICH TEXT reached main, so the rendered bytes were
unrecoverable after the fact and the retry-hint audit could not be closed on
evidence.

The audit goal is ORIGIN, and that is now recorded outright: the formatter
hands back the `hint_source` / `hint_origin` it chose, so the label is stored
rather than re-derived from `verdict` against a second copy of a table that is
deliberately local to that function.

The digest is a COMMITMENT to the bytes, not a way to recover them. An earlier
version of this file claimed the record let a later run "re-render the same
inputs and compare"; it does not. The rendered body depends on
`sandbox_result`, and the caller only keeps the LAST run's, so two injections
can share attempt, verdict and length and still differ. `sha256` answers "was
it this text?" and never "what was the text?" — the exact-bytes question stays
open, by decision, rather than being claimed closed.

Two things have to hold, and the SECOND is the one that actually bit:

  1. the injection site records the digest at all
  2. the `summary` dict it records into is persisted to disk

(2) is not obvious. `summary` is a PARAMETER of `run_main_agent_session`; the
function never writes it to meta, and `meta["summary"]` is None in all 78 jobs
in the corpus. The caller persists it — to `result.json` under `"agent"`, not
to meta. Reading meta and concluding "the feature is unmeasurable" is a mistake
this file exists to prevent: the counters were in `result.json` the whole time.

Sliced from source: importing modules._common drags in the agent SDK.
"""
import ast
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
COMMON = (ROOT / "modules/_common.py").read_text()

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


tree = ast.parse(COMMON)


def func(name):
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


section("the injection site records what it injected")
loop = func("run_main_agent_session")
chk("run_main_agent_session exists", loop is not None)
body = ast.get_source_segment(COMMON, loop) or ""

chk("it records into summary['injected_turns']",
    "injected_turns" in body)
# the record must sit BEFORE the query that consumes the text, or a crash in
# query() loses the only evidence of what was sent
idx_rec = body.find("injected_turns")
idx_qry = body.find("await client.query(feedback)")
chk("the record is written before client.query(feedback)",
    idx_rec != -1 and idx_qry != -1 and idx_rec < idx_qry, (idx_rec, idx_qry))

# every field the closure condition needs
for field in ("attempt", "verdict", "chars", "sha256"):
    chk("the record carries %r" % field,
        ("\"%s\":" % field) in body[idx_rec:idx_rec + 700])

chk("it stores a digest, not the whole feedback body",
    "hashlib.sha256(feedback.encode())" in body
    and '"text": feedback' not in body)

section("the recorded dict actually reaches disk")
# summary is a parameter; run_main_agent_session never persists it itself.
params = [a.arg for a in loop.args.args + loop.args.kwonlyargs]
chk("summary is a parameter, so the CALLER owns persistence",
    "summary" in params, params)

# Every module that runs this loop must write its summary dict into
# result.json, or the record is silently dropped for that module.
CALLERS = ("pwn", "rev", "web", "crypto", "web3")
for mod in CALLERS:
    p = ROOT / ("modules/%s/analyzer.py" % mod)
    if not p.is_file():
        chk("%s analyzer exists" % mod, False, str(p))
        continue
    src = p.read_text()
    uses_loop = "run_main_agent_session" in src
    chk("%s runs the orchestrator loop" % mod, uses_loop)
    if not uses_loop:
        continue
    chk("%s persists its summary dict into result.json" % mod,
        '"agent": agent_summary' in src and "result.json" in src)

# ...and the modules that do NOT run the loop cannot produce the record,
# so their absence from the list above is correct rather than a gap.
for mod in ("misc", "forensic"):
    p = ROOT / ("modules/%s/orchestrator.py" % mod)
    if p.is_file():
        chk("%s does not run the orchestrator loop (so nothing to persist)"
            % mod, "run_main_agent_session" not in p.read_text())

section("the recorded label comes from the formatter, not a second copy")
# The provenance table is deliberately local to _format_postjudge_user_turn
# (the anti-overfit suite execs that function with almost nothing in scope), so
# a caller that re-derived the label from `verdict` would be maintaining a
# duplicate of it. The formatter hands the label out instead.
chk("the formatter accepts a record out-dict",
    "record: dict | None = None" in COMMON)
fmt = ast.get_source_segment(COMMON, func("_format_postjudge_user_turn")) or ""
chk("...and writes the label it actually chose into it",
    'record["hint_source"] = hint_source' in fmt
    and 'record["hint_origin"] = hint_origin' in fmt)
chk("the injection site passes the record in", "record=_inject_record" in body)
for field in ("hint_source", "hint_origin"):
    chk("the persisted record carries %r" % field,
        ('"%s": _inject_record.get' % field) in body)
chk("the loop does not keep its own copy of the provenance table",
    body.count("_hint_provenance") == 0)

section("the digest is a commitment, not a reconstruction")
# Codex's defect: two injections can share attempt, verdict AND length and
# still be different text, because the rendered body depends on
# `sandbox_result` and the caller only retains the last one. A record that
# cannot regenerate the expected bytes cannot close an exact-text audit, and
# the earlier docstring claimed it could.
import hashlib as _h
same_len_a = "verdict=reviewer_redirect\nrebuild the chain from the leak"
same_len_b = "verdict=reviewer_redirect\nrebuild the chain from the heap"
chk("the two fixtures really are the same length",
    len(same_len_a) == len(same_len_b), (len(same_len_a), len(same_len_b)))
rec_a = {"attempt": 1, "verdict": "reviewer_redirect", "chars": len(same_len_a),
         "sha256": _h.sha256(same_len_a.encode()).hexdigest()[:16]}
rec_b = {"attempt": 1, "verdict": "reviewer_redirect", "chars": len(same_len_b),
         "sha256": _h.sha256(same_len_b.encode()).hexdigest()[:16]}
chk("same attempt/verdict/chars, different digest",
    (rec_a["attempt"], rec_a["verdict"], rec_a["chars"])
    == (rec_b["attempt"], rec_b["verdict"], rec_b["chars"])
    and rec_a["sha256"] != rec_b["sha256"], (rec_a, rec_b))
chk("the record does NOT carry the inputs needed to re-render",
    not any(k in rec_a for k in ("sandbox_result", "script_filename",
                                 "max_attempts", "text")))
# and the code must not claim otherwise
chk("no comment claims the digest lets a later run re-render and compare",
    "re-render the same inputs and compare" not in COMMON)
# Comments wrap, so compare on text with comment markers and runs of
# whitespace collapsed rather than on an exact substring.
_flat = " ".join(COMMON.replace("#", " ").split())
chk("the code says plainly what the digest can and cannot answer",
    'it answers "was it this text?", never "what was the text?"' in _flat,
    [s for s in _flat.split(". ") if "was it this text" in s][:1])

section("behavioural: the digest identifies the text")
# Re-rendering the same inputs must reproduce the stored digest; a different
# producer's text must not. This is what makes the audit closable without
# storing the body.
def record(feedback, attempt, verdict):
    return {"attempt": attempt, "verdict": verdict, "chars": len(feedback),
            "sha256": hashlib.sha256(feedback.encode()).hexdigest()[:16]}


a = "=== retry hint (from the one-shot auto-reviewer) ===\nrebuild the chain"
b = "=== retry hint (from prejudge) ===\nrebuild the chain"
ra, rb = record(a, 1, "reviewer_redirect"), record(b, 1, "prejudge_blocked")
chk("re-rendering identical text reproduces the digest",
    record(a, 1, "reviewer_redirect") == ra)
chk("a different producer's text yields a different digest",
    ra["sha256"] != rb["sha256"], (ra["sha256"], rb["sha256"]))
chk("chars is the real length, not a placeholder",
    ra["chars"] == len(a) and ra["chars"] > 0, ra["chars"])
chk("verdict is retained so origin stays derivable",
    ra["verdict"] == "reviewer_redirect" and rb["verdict"] == "prejudge_blocked")

print("")
print("%d checks, %d failed" % (checks, fails))
sys.exit(1 if fails else 0)
