#!/usr/bin/env python3
"""`agent_heartbeat` must write main's usage row, and write it once per session.

The subtle part is not that a row appears — it is WHICH dollar figure lands in
it. `meta.cost_usd` is the JOB total (this session plus every earlier one, for
a stop->continue). Putting that number in a per-session ledger row would count
every earlier session again on the next session, so the ledger has to carry the
un-summed per-session figure and dedupe on the session id.

Driven through the real `agent_heartbeat` with duck-typed SDK messages: it
dispatches on `type(msg).__name__`, so a local class of the right name is the
real code path, not a mock of it.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.TemporaryDirectory(prefix="main-usage-row-")
DATA = Path(_TMP.name)
(DATA / "jobs").mkdir()
SETTINGS = DATA / "settings.json"
PRESETS = DATA / "model_presets.json"
SETTINGS.write_text(json.dumps({"agent_provider": "claude"}))
PRESETS.write_text(json.dumps({"version": 2, "providers": {}}))
os.environ.update(
    DATA_DIR=str(DATA),
    SETTINGS_PATH=str(SETTINGS),
    MODEL_PRESETS_PATH=str(PRESETS),
    JOBS_DIR=str(DATA / "jobs"),
)
for _k in ("AGENT_PROVIDER", "CLAUDE_MODEL", "GROK_MODEL", "GPT_MODEL"):
    os.environ.pop(_k, None)

import modules._common as C  # noqa: E402
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


class ResultMessage:
    """Duck-typed: agent_heartbeat dispatches on the class NAME."""

    def __init__(self, cost=None, session_id=None, usage=None, model_usage=None):
        self.total_cost_usd = cost
        self.session_id = session_id
        self.usage = usage
        self.model_usage = model_usage


class AssistantMessage:
    """The turn message that actually carries usage.

    Sending only an EMPTY Result — which the first version of this file did —
    never populates the token accumulator, so the cost-estimate branch is never
    reached and a whole class of defect passes underneath. The Codex adapter
    emits usage here and then a Result with total_cost_usd=None.
    """

    def __init__(self, usage, message_id):
        self.usage = usage
        self.message_id = message_id
        self.content = []


def make_job(job_id: str, **meta) -> str:
    d = DATA / "jobs" / job_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "meta.json").write_text(json.dumps({"id": job_id, **meta}))
    return job_id


def reset(job_id: str) -> None:
    C._heartbeat_state.pop(job_id, None)
    C._token_state.pop(job_id, None)
    C._token_seen_ids.pop(job_id, None)


# ---------------------------------------------------------------------------
# 1. Claude main — a reported dollar figure, un-summed.
# ---------------------------------------------------------------------------
j = make_job("mu1", agent_provider="claude", model="claude-opus-4-8")
reset(j)
C.agent_heartbeat(j, ResultMessage(cost=1.25, session_id="s1"))
rows = UL.read_usage(j)
check("one row after the first Result", len(rows), 1)
check("role is main", rows[0].get("role"), "main")
check("provider comes from the job", rows[0].get("provider"), "claude")
check("the reported session cost lands in the row", rows[0].get("cost_usd"), 1.25)
check("basis says reported", rows[0].get("cost_basis"), "reported")

# A re-emitted Result for the SAME session must not add a row.
C.agent_heartbeat(j, ResultMessage(cost=1.25, session_id="s1"))
check("a repeated session adds nothing", len(UL.read_usage(j)), 1)

# A stop -> continue is a new session. The real continue path banks the spend
# so far into `cost_usd_prior_sessions` at session start (_common.py:8197,
# api/routes/jobs.py:207); mirror that so meta.cost_usd means what it means in
# production.
C.write_meta(j, cost_usd_prior_sessions=1.25)
C._heartbeat_state.pop(j, None)
C.agent_heartbeat(j, ResultMessage(cost=0.75, session_id="s2"))
rows = UL.read_usage(j)
check("the second session adds its own row", len(rows), 2)
check("the row holds the SESSION figure, not the job total", rows[1].get("cost_usd"), 0.75)
check(
    "the rows sum to the job total",
    UL.aggregate_usage(j)["providers"]["claude"]["usd"],
    2.0,
)
check(
    "and that matches what meta reports as the job total",
    round(float((C.read_meta(j) or {}).get("cost_usd") or 0), 6),
    2.0,
)

# The ledger reaches that total by ADDING per-session rows, so it does not
# depend on `cost_usd_prior_sessions` having been stamped. meta.cost_usd does:
# a continue path that forgets the stamp under-reports the job (which is the
# failure prior_session_cost was introduced to fix — job c552faf18d31 lost
# nearly half its spend that way). Same job, stamp deliberately cleared:
j_nostamp = make_job("mu1b", agent_provider="claude", model="claude-opus-4-8")
reset(j_nostamp)
C.agent_heartbeat(j_nostamp, ResultMessage(cost=1.25, session_id="s1"))
C._heartbeat_state.pop(j_nostamp, None)
C.agent_heartbeat(j_nostamp, ResultMessage(cost=0.75, session_id="s2"))
check(
    "the ledger totals correctly with no prior-session stamp",
    UL.aggregate_usage(j_nostamp)["providers"]["claude"]["usd"],
    2.0,
)
check(
    "meta, by contrast, keeps only the last session without it",
    round(float((C.read_meta(j_nostamp) or {}).get("cost_usd") or 0), 6),
    0.75,
)

# ---------------------------------------------------------------------------
# 2. Codex main — no dollar figure at all. Null, never 0.0.
# ---------------------------------------------------------------------------
SETTINGS.write_text(json.dumps({"agent_provider": "gpt"}))
j2 = make_job("mu2", agent_provider="gpt", model="gpt-5.6-sol")
reset(j2)
C.agent_heartbeat(j2, ResultMessage(cost=None, session_id="g1"))
rows2 = UL.read_usage(j2)
check("codex main still gets a row", len(rows2), 1)
check("codex reports no dollars -> null", rows2[0].get("cost_usd"), None)
check("...and it is NOT recorded as 0.0", rows2[0].get("cost_usd") == 0.0, False)
check("basis says none", rows2[0].get("cost_basis"), "none")
check("provider is gpt", rows2[0].get("provider"), "gpt")

agg = UL.aggregate_usage(j2)["providers"]["gpt"]
check("the gpt bucket has no dollar total", agg["usd"], None)
check("and is flagged incomplete", agg["usd_complete"], False)

# ---------------------------------------------------------------------------
# 2b. turn 0010 D1 — the REAL Codex message order: usage arrives on an
#     Assistant turn, then a Result with total_cost_usd=None. That fills the
#     token accumulator, so the estimate branch fires. Pricing GPT tokens
#     through the Claude rate table produced $0.049 of money that never
#     existed. The contract says Codex OAuth is null / none / window-metered.
# ---------------------------------------------------------------------------
SETTINGS.write_text(json.dumps({"agent_provider": "gpt", "gpt_runtime": "codex"}))
j2b = make_job("mu2b", agent_provider="gpt", model="gpt-5.6-sol")
reset(j2b)
C.agent_heartbeat(j2b, AssistantMessage({"input_tokens": 5000, "output_tokens": 800}, "m1"))
C._heartbeat_state.pop(j2b, None)
C.agent_heartbeat(
    j2b,
    ResultMessage(
        cost=None,
        session_id="gs1",
        model_usage={"gpt-5.6-sol": {"input_tokens": 5000, "output_tokens": 800}},
    ),
)
row = UL.read_usage(j2b)[-1]
check("D1 tokens WERE accumulated (the branch is really reached)", bool(row.get("tokens")), True)
check("D1 codex OAuth records no dollars", row.get("cost_usd"), None)
check("D1 basis is none, not estimated", row.get("cost_basis"), "none")
check("D1 the runtime is on the row", row.get("runtime"), "codex")

# ---------------------------------------------------------------------------
# 2c. turn 0010 D2 — the Responses runtime is API-key billed and its
#     total_cost_usd is the ADAPTER's own estimate. So: dollars, but
#     "estimated", and no Codex OAuth window (that window belongs to the
#     subscription, not to an API key).
# ---------------------------------------------------------------------------
SETTINGS.write_text(json.dumps({"agent_provider": "gpt", "gpt_runtime": "responses"}))
j2c = make_job("mu2c", agent_provider="gpt", model="gpt-5.6-sol")
reset(j2c)
_orig_snap = UL.codex_window_snapshot
UL.codex_window_snapshot = lambda **k: {"weekly_remaining_pct": 77.0}
try:
    C.agent_heartbeat(j2c, ResultMessage(cost=0.008, session_id="rs1"))
finally:
    UL.codex_window_snapshot = _orig_snap
row_r = UL.read_usage(j2c)[-1]
check("D2 responses reports dollars", row_r.get("cost_usd"), 0.008)
check("D2 but labelled estimated, not reported", row_r.get("cost_basis"), "estimated")
check("D2 and carries NO Codex OAuth window", "window" in row_r, False)
check("D2 the runtime is on the row", row_r.get("runtime"), "responses")

# ---------------------------------------------------------------------------
# 3. A ledger failure must not break the heartbeat.
# ---------------------------------------------------------------------------
SETTINGS.write_text(json.dumps({"agent_provider": "claude"}))
j3 = make_job("mu3", agent_provider="claude")
reset(j3)
_orig = UL.record_usage
UL.record_usage = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("ledger down"))
try:
    C.agent_heartbeat(j3, ResultMessage(cost=0.5, session_id="s9"))
    check("a raising ledger does not propagate", True, True)
except Exception as exc:  # pragma: no cover
    check(f"a raising ledger does not propagate ({exc})", False, True)
finally:
    UL.record_usage = _orig
check(
    "and meta was still written",
    round(float((C.read_meta(j3) or {}).get("cost_usd") or 0), 6),
    0.5,
)

print(f"== summary: {PASSED} passed, {FAILED} failed ==")
_TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
