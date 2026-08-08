#!/usr/bin/env python3
"""The per-role usage ledger, and the two rules that make it worth having.

Both rules exist because a hybrid job has spend in two units that cannot be
added: Claude reports dollars, Codex ChatGPT OAuth reports none and is metered
against 5h / weekly windows.

  1. a missing dollar figure is not zero
  2. a partial sum is not a total

Neither is checkable by reading the code — an aggregator that quietly treats
None as 0.0 looks identical to a correct one until a hybrid job runs.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.TemporaryDirectory(prefix="usage-ledger-")
DATA = Path(_TMP.name)
(DATA / "jobs").mkdir()
os.environ["DATA_DIR"] = str(DATA)

from modules import usage_ledger as UL  # noqa: E402

PASSED = 0
FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


TOK = {
    "input_tokens": 100,
    "output_tokens": 20,
    "cache_read_input_tokens": 5,
    "bogus_key": 999,
}

# ---------------------------------------------------------------------------
# 1. Rule one: a missing dollar figure is NOT zero.
# ---------------------------------------------------------------------------
rec = UL.record_usage(
    "j1", role="main", stage="main", provider="gpt", model="gpt-5.6-sol", tokens=TOK
)
check("no cost reported -> cost_usd stays null", rec["cost_usd"], None)
check("no cost reported -> basis says so", rec["cost_basis"], "none")

# 0.0 is a real value and must survive as one — a call that genuinely cost
# nothing is not the same observation as a provider that does not price calls.
zero = UL.record_usage(
    "j1", role="judge", stage="prejudge", provider="claude",
    cost_usd=0.0, cost_basis="reported",
)
check("an explicit 0.0 is preserved", zero["cost_usd"], 0.0)
check("an explicit 0.0 keeps its basis", zero["cost_basis"], "reported")

# A caller that passes a cost of None cannot claim a basis for it.
bogus = UL.record_usage(
    "j1", role="judge", stage="postjudge", provider="claude",
    cost_usd=None, cost_basis="reported",
)
check("null cost cannot carry a 'reported' basis", bogus["cost_basis"], "none")
check("an unknown basis string degrades to none", UL.record_usage(
    "j1", role="report", stage="report", provider="gpt", cost_basis="invented",
)["cost_basis"], "none")

check("unknown token keys are dropped", "bogus_key" in rec["tokens"], False)
check(
    "known token keys survive",
    rec["tokens"],
    {"input_tokens": 100, "output_tokens": 20, "cache_read_input_tokens": 5},
)

# ---------------------------------------------------------------------------
# 2. Rule two: a partial sum is not a total.
# ---------------------------------------------------------------------------
UL.record_usage(
    "j2", role="main", stage="main", provider="gpt", model="gpt-5.6-sol",
    tokens={"input_tokens": 1000, "output_tokens": 200},
)
UL.record_usage(
    "j2", role="judge", stage="prejudge", provider="claude",
    model="claude-opus-4-8", tokens={"input_tokens": 10, "output_tokens": 2},
    cost_usd=0.31, cost_basis="reported",
)
UL.record_usage(
    "j2", role="reviewer", stage="reviewer", provider="claude",
    model="claude-opus-4-8", cost_usd=0.18, cost_basis="reported",
)
agg = UL.aggregate_usage("j2")
prov = agg["providers"]

check("providers are bucketed separately", sorted(prov), ["claude", "gpt"])
check("claude dollars are summed", prov["claude"]["usd"], 0.49)
check("claude bucket is complete", prov["claude"]["usd_complete"], True)
check("gpt reported no dollars -> usd stays null", prov["gpt"]["usd"], None)
check("gpt bucket is flagged incomplete", prov["gpt"]["usd_complete"], False)
check(
    "there is NO cross-provider total key",
    [k for k in agg if "total" in k.lower()],
    [],
)
check(
    "gpt tokens are not folded into claude's",
    prov["gpt"]["tokens"],
    {"input_tokens": 1000, "output_tokens": 200},
)
check("per-role breakdown exists", sorted(prov["claude"]["by_role"]), ["judge", "reviewer"])
check(
    "per-stage breakdown under the role",
    sorted(prov["claude"]["by_role"]["judge"]["by_role"]),
    ["prejudge"],
)

# A claude bucket where ONE call reported nothing must not read as complete.
UL.record_usage("j2", role="report", stage="report", provider="claude")
prov2 = UL.aggregate_usage("j2")["providers"]
check("one silent claude call flips the bucket to incomplete", prov2["claude"]["usd_complete"], False)
check("...but the known dollars are still reported", prov2["claude"]["usd"], 0.49)

# ---------------------------------------------------------------------------
# 3. attempt counter: per (role, stage), and survives a process restart.
# ---------------------------------------------------------------------------
for expected in (1, 2, 3):
    got = UL.record_usage("j3", role="judge", stage="supervise", provider="claude")
    check(f"supervise attempt {expected}", got["attempt"], expected)
check(
    "a different stage has its own counter",
    UL.record_usage("j3", role="judge", stage="postjudge", provider="claude")["attempt"],
    1,
)
UL._attempts.clear()  # simulate a worker restart mid-job
check(
    "the counter is re-seeded from the file, not reset to 1",
    UL.record_usage("j3", role="judge", stage="supervise", provider="claude")["attempt"],
    4,
)

# ---------------------------------------------------------------------------
# 3b. dedupe_key: main's cost is cumulative-per-session, so a re-emitted
#     ResultMessage must not add a second row for the same session.
# ---------------------------------------------------------------------------
first = UL.record_usage(
    "j7", role="main", stage="main", provider="claude",
    cost_usd=5.0, cost_basis="reported", dedupe_key="sess-A",
)
again = UL.record_usage(
    "j7", role="main", stage="main", provider="claude",
    cost_usd=5.0, cost_basis="reported", dedupe_key="sess-A",
)
check("the first row is written", bool(first), True)
check("the same session key is refused", again, None)
check("only one row on disk", len(UL.read_usage("j7")), 1)
check("so the total is the session cost, not double", UL.aggregate_usage("j7")["providers"]["claude"]["usd"], 5.0)

# A genuine stop -> continue is a NEW session and must contribute its own row.
UL.record_usage(
    "j7", role="main", stage="main", provider="claude",
    cost_usd=3.0, cost_basis="reported", dedupe_key="sess-B",
)
check("a second session adds its own row", len(UL.read_usage("j7")), 2)
check("and the rows sum to the job total", UL.aggregate_usage("j7")["providers"]["claude"]["usd"], 8.0)

# Roles whose every call is discrete omit the key and always append.
for _ in range(3):
    UL.record_usage("j8", role="judge", stage="supervise", provider="claude")
check("no dedupe key -> every call appends", len(UL.read_usage("j8")), 3)

# ---------------------------------------------------------------------------
# 4. Best-effort: nothing here may raise into the run being measured.
# ---------------------------------------------------------------------------
path = UL.ledger_path("j4")
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text('{"role":"main","provider":"claude","cost_usd":1.0}\n'
                'not json at all\n'
                '{"role":"judge","provider":"claude","cost_usd":2.0}\n'
                '{"role":"truncated","provider":"cla')
recs = UL.read_usage("j4")
check("malformed and truncated lines are skipped, not fatal", len(recs), 2)
check("the surviving records still aggregate", UL.aggregate_usage("j4")["providers"]["claude"]["usd"], 3.0)

# An unwritable ledger returns None instead of exploding.
blocked = DATA / "jobs" / "j5"
blocked.mkdir(parents=True, exist_ok=True)
(blocked / UL.LEDGER_FILENAME).mkdir()  # a directory where the file should be
check(
    "an unwritable ledger returns None rather than raising",
    UL.record_usage("j5", role="main", stage="main", provider="claude"),
    None,
)
check("reading an unwritable ledger yields nothing", UL.read_usage("j5"), [])
check("aggregating an absent ledger is empty, not an error",
      UL.aggregate_usage("does-not-exist"), {"providers": {}, "records": 0})

# ---------------------------------------------------------------------------
# 5. The window snapshot records absence as absence.
# ---------------------------------------------------------------------------
import modules.codex_rate_limit as CRL  # noqa: E402

_orig = CRL.read_codex_rate_limit
CRL.read_codex_rate_limit = lambda: None
check("no window reading -> None, never 100%", UL.codex_window_snapshot(), None)
CRL.read_codex_rate_limit = lambda: {
    "remaining_pct": 68.0,
    "resets_at": "2026-08-14T17:39:12+09:00",
    "windows": [
        {"rate_limit_type": "weekly", "remaining_pct": 68.0},
        {"rate_limit_type": "5h", "remaining_pct": 91.5},
    ],
}
snap = UL.codex_window_snapshot()
check("weekly remaining is captured", snap.get("weekly_remaining_pct"), 68.0)
check("5h remaining is captured", snap.get("5h_remaining_pct"), 91.5)
CRL.read_codex_rate_limit = _orig

# The window rides on the record, and never becomes a dollar figure.
UL.record_usage(
    "j6", role="main", stage="main", provider="gpt",
    window={"weekly_remaining_pct": 68.0},
)
b = UL.aggregate_usage("j6")["providers"]["gpt"]
check("window is surfaced on the bucket", b["window"], {"weekly_remaining_pct": 68.0})
check("a window reading does not become dollars", b["usd"], None)

# Ledger files are per job.
check("j1 and j2 have separate ledgers",
      UL.ledger_path("j1") != UL.ledger_path("j2"), True)
check("a job id cannot escape the jobs dir",
      UL.ledger_path("../../etc/passwd").parent.name, "passwd")

print(f"== summary: {PASSED} passed, {FAILED} failed ==")
_TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
