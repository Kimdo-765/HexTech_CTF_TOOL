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
# 1b. The guard must not suppress a LEGITIMATE estimate. Claude can end a
#     session without a total_cost_usd (see prior_session_cost's history), and
#     claude-opus-4-8 IS in the rate table — so the estimate is real money and
#     must still be recorded, marked "estimated".
# ---------------------------------------------------------------------------
j1b = make_job("mu1c", agent_provider="claude", model="claude-opus-4-8")
reset(j1b)
C.agent_heartbeat(j1b, AssistantMessage({"input_tokens": 100000, "output_tokens": 5000}, "cm1"))
C._heartbeat_state.pop(j1b, None)
C.agent_heartbeat(j1b, ResultMessage(cost=None, session_id="cs1"))
row_c = UL.read_usage(j1b)[-1]
check("a priced claude model still gets its estimate", isinstance(row_c.get("cost_usd"), float), True)
check("...above zero", (row_c.get("cost_usd") or 0) > 0, True)
check("...labelled estimated", row_c.get("cost_basis"), "estimated")

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
# 2d. turn 0012 D1 — Grok through the REAL heartbeat. `grok-build` has no row
#     in the rate table, so its estimate was Opus-5 pricing applied to Grok
#     tokens. A reported ACP figure is still preserved.
# ---------------------------------------------------------------------------
SETTINGS.write_text(json.dumps({"agent_provider": "grok", "grok_model": "grok-build"}))
j2d = make_job("mu2d", agent_provider="grok", model="grok-build")
reset(j2d)
C.agent_heartbeat(j2d, AssistantMessage({"input_tokens": 1000, "output_tokens": 100}, "gm1"))
C._heartbeat_state.pop(j2d, None)
C.agent_heartbeat(j2d, ResultMessage(cost=None, session_id="ks1"))
row_g = UL.read_usage(j2d)[-1]
check("D1 grok tokens were accumulated (branch reached)", bool(row_g.get("tokens")), True)
check("D1 an unpriced grok model books NO dollars", row_g.get("cost_usd"), None)
check("D1 basis is none, not estimated", row_g.get("cost_basis"), "none")
check("D1 the bucket says so out loud",
      UL.aggregate_usage(j2d)["providers"]["grok"]["usd_complete"], False)

# The reported branch was correct and must stay correct.
j2e = make_job("mu2e", agent_provider="grok", model="grok-build")
reset(j2e)
C.agent_heartbeat(j2e, ResultMessage(cost=0.2, session_id="ks2"))
row_g2 = UL.read_usage(j2e)[-1]
check("a reported ACP figure is preserved", row_g2.get("cost_usd"), 0.2)
check("...as reported", row_g2.get("cost_basis"), "reported")

# ---------------------------------------------------------------------------
# 2f. turn 0014 D1 — the row's model and its dollar figure must be the SAME
#     resolution. The estimate omitted the provider, so it fell through to
#     whatever Settings says NOW, while the row used the job's create-time
#     snapshot: a job stamped `claude` with no model override, running while
#     Settings said `gpt`, produced model=claude-opus-4-8 priced at
#     gpt-5.6-luna rates ($0.13 against $0.625 for the model it names).
#
#     A job with `model: null` is the COMMON case — that key is the per-job
#     override and is null whenever the operator did not pick one in the form.
# ---------------------------------------------------------------------------
SETTINGS.write_text(
    json.dumps(
        {
            "agent_provider": "gpt",          # live Settings says gpt...
            "gpt_model": "gpt-5.6-luna",
            "claude_model": "claude-opus-4-8",
        }
    )
)
j2f = make_job("mu2f", agent_provider="claude", model=None)   # ...job says claude
reset(j2f)
TOKENS = {"input_tokens": 100000, "output_tokens": 5000}
C.agent_heartbeat(j2f, AssistantMessage(TOKENS, "xm1"))
C._heartbeat_state.pop(j2f, None)
C.agent_heartbeat(j2f, ResultMessage(cost=None, session_id="xs1"))
row_x = UL.read_usage(j2f)[-1]
check("D1 the row follows the job snapshot, not live Settings", row_x.get("provider"), "claude")
check("D1 and names the job provider's model", row_x.get("model"), "claude-opus-4-8")
check(
    "D1 the dollar figure is priced with the model the row NAMES",
    round(row_x.get("cost_usd") or 0, 4),
    round(C.estimate_cost_from_tokens(TOKENS, row_x.get("model")), 4),
)
check(
    "D1 and is NOT the live-Settings model's price",
    round(row_x.get("cost_usd") or 0, 4)
    == round(C.estimate_cost_from_tokens(TOKENS, "gpt-5.6-luna"), 4),
    False,
)
check(
    "D1 meta's in-flight estimate agrees with the row",
    round(float((C.read_meta(j2f) or {}).get("cost_usd_estimate") or 0), 4),
    round(row_x.get("cost_usd") or 0, 4),
)

# ---------------------------------------------------------------------------
# 2g. turn 0026 D5 — main spans several models too. The Responses adapter
#     merges every subagent's usage into the parent map and the preset can
#     pin a subagent to a different model, so folding them into one row loses
#     the ledger's `model` axis and prices the cheaper model's tokens at the
#     expensive one's rate. Same defect as the judge's, found separately
#     because the splitting logic lived in neither place; it now lives in
#     usage_ledger.record_usage_by_model, shared by both.
# ---------------------------------------------------------------------------
SETTINGS.write_text(json.dumps({"agent_provider": "claude"}))
MULTI = {
    "claude-opus-4-8": {"input_tokens": 1000, "output_tokens": 100},
    "claude-sonnet-4-6": {"input_tokens": 2000, "output_tokens": 200},
}
jmm = make_job("mu-multi", agent_provider="claude", model="claude-opus-4-8")
reset(jmm)
C.agent_heartbeat(jmm, ResultMessage(cost=None, session_id="ms1", model_usage=MULTI))
mrows = UL.read_usage(jmm)
check("D5 one row PER MODEL", len(mrows), 2)
check("D5 both models named", sorted(r["model"] for r in mrows),
      ["claude-opus-4-8", "claude-sonnet-4-6"])
check("D5 each row holds only its own tokens",
      {r["model"]: r["tokens"] for r in mrows}, MULTI)
_want = round(sum(C.estimate_cost_from_tokens(v, m) for m, v in MULTI.items()), 6)
_flat = round(C.estimate_cost_from_tokens(
    {"input_tokens": 3000, "output_tokens": 300}, "claude-opus-4-8"), 6)
check("D5 dollars are the PER-MODEL sum", round(sum(r["cost_usd"] or 0 for r in mrows), 6), _want)
check("D5 ...not the flattened single-rate figure", _want == _flat, False)

# A reported session cost cannot be split: whole on the primary row, absent
# on the others, so the bucket sums to the reported total.
jmr = make_job("mu-multi-reported", agent_provider="claude", model="claude-opus-4-8")
reset(jmr)
C.agent_heartbeat(jmr, ResultMessage(cost=0.42, session_id="ms2", model_usage=MULTI))
rrows = UL.read_usage(jmr)
check("D5 reported: still one row per model", len(rrows), 2)
check("D5 reported: whole on the primary row",
      rrows[0]["cost_usd"] if rrows else None, 0.42)
check("D5 reported: not duplicated onto the other",
      rrows[1]["cost_usd"] if len(rrows) > 1 else "MISSING ROW", None)
check("D5 reported: bucket sums to the reported total",
      UL.aggregate_usage(jmr)["providers"]["claude"]["usd"], 0.42)

# The per-model dedupe key must not let one model claim the whole session.
reset(jmr)
C.agent_heartbeat(jmr, ResultMessage(cost=0.42, session_id="ms2", model_usage=MULTI))
check("D5 a re-emitted Result adds no rows for any model",
      len(UL.read_usage(jmr)), 2)

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
