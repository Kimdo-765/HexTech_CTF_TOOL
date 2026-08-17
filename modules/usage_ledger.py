"""Per-role usage ledger — provider × model × role × stage × attempt.

Why this is separate from `meta.agent_tokens`
---------------------------------------------
The existing ledger answers "what did this JOB cost", and only for the main
session. Once roles can run on different backends that question stops having a
single answer: Claude reports dollars, Codex ChatGPT OAuth reports none at all
and is metered against 5-hour / weekly windows instead. A hybrid job therefore
has spend in TWO units that must never be added together.

Two rules are load-bearing here, and both are encoded as contracts rather than
conventions because no unit test on the old ledger would have caught either:

  1. **A missing dollar figure is not zero.** `codex_cli.py` returns
     `total_cost_usd=None` because the subscription does not price a call.
     Folding that into a sum as 0.0 makes a hybrid job look cheaper than a
     pure-Claude one, which is exactly backwards. `cost_usd` stays None and
     `cost_basis` says why.
  2. **A partial sum is not a total.** If the Claude judge reports $0.31 and
     Codex main reports nothing, "$0.31" read as the job total is wrong by
     however much the Codex half cost. Aggregation marks the bucket
     `usd_complete: False` rather than quietly under-reporting.

Storage is an append-only `<job>/usage.jsonl` rather than a meta key: meta has
several concurrent writers (agent_heartbeat, the monitor, the orchestrator) and
appending a record per role invocation there would invite both write races and
unbounded growth of a file that is re-read on every UI poll.

Everything is best-effort. Observability must never break the pipeline it
observes — the same posture `_monitor.py` states for itself.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LEDGER_FILENAME = "usage.jsonl"

# Mirrors modules._common._TOKEN_KEYS. Duplicated rather than imported: this
# module is imported from api/ where pulling in _common (thousands of lines,
# SDK-adjacent) for four strings would be a poor trade.
TOKEN_KEYS = (
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)

# The SDK hands `model_usage` over the wire in camelCase, and all three
# callers (main, judge, reviewer) pass their provider object straight through.
# Normalising HERE rather than at each call site is the same decision the
# record_usage_by_model docstring already argues for: the per-model splitting
# defect was found twice because the logic lived in neither place. Mirrors
# modules._common._MODEL_USAGE_KEYMAP, duplicated for the same reason
# TOKEN_KEYS is.
_WIRE_TOKEN_KEYS = {
    "inputTokens": "input_tokens",
    "outputTokens": "output_tokens",
    "cacheCreationInputTokens": "cache_creation_input_tokens",
    "cacheReadInputTokens": "cache_read_input_tokens",
}


def normalize_tokens(tokens: Any) -> dict[str, int]:
    """Accept either the wire's camelCase or our snake_case token schema.

    Applied before the row is priced, not just before it is written: the cost
    estimator reads snake_case too, so a camelCase dict that only got cleaned
    on the way to disk would still be estimated at $0 (live evidence: 42/42
    main rows and 24/24 reviewer rows carried `tokens: {}` while the same
    jobs' meta held millions of tokens).
    """
    if not isinstance(tokens, dict):
        return {}
    out: dict[str, int] = {}
    for k, v in tokens.items():
        dest = _WIRE_TOKEN_KEYS.get(k, k if k in TOKEN_KEYS else None)
        if dest is None:
            continue
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            continue
        out[dest] = out.get(dest, 0) + int(v)
    return out

# How a dollar figure was arrived at. The distinction matters when deciding
# whether a cap may fire: an estimate must not silently stop a job.
COST_BASIS = ("reported", "estimated", "none")

_lock = threading.Lock()


def cost_contract(
    provider: str,
    *,
    reported_cost: Any = None,
    estimated_cost: Any = None,
    gpt_runtime: str | None = None,
    estimate_priced: bool = False,
) -> tuple[float | None, str, bool]:
    """Decide (cost_usd, cost_basis, attach_oauth_window) for one invocation.

    The rules differ per BACKEND, not per provider name, and getting that
    wrong invents money:

    * ``gpt`` + ``codex`` runtime — ChatGPT OAuth does not price a call, so
      there is no dollar figure to have. Pricing its tokens instead runs GPT
      usage through the Claude rate table and produces a number that is not
      an estimate of anything (measured: a 5.8k-token Codex turn priced at
      $0.049). Null, basis "none", metered by the OAuth window.
    * ``gpt`` + ``responses`` runtime — API-key billed, and the adapter's
      ``total_cost_usd`` is its OWN estimate (gpt_responses.py). So it is a
      dollar figure, but "estimated", and the OAuth window does not apply to
      it at all — that window belongs to the subscription, not the API key.
    * ``claude`` / ``grok`` — the SDK's figure when there is one. Grok's ACP
      adapter reports a real one whenever the transport carries it, and that
      is preserved. When there is none, an estimate is only accepted if the
      rate table actually prices this model.

    ``estimate_priced`` is the guard for that last clause and defaults to
    **False**. `_rates_for_model` falls back to the Opus row for any model it
    does not recognise, so `grok-build` — which has no row — priced out at
    Opus-5 rates and booked $0.0075 of Grok spend that no one was charged.
    A caller that cannot say whether its estimate is priced should not have it
    believed: the row then reads null / "none" and the bucket says
    `usd_complete: False`, which is visibly missing rather than quietly wrong.
    """
    p = str(provider or "").strip().lower()
    runtime = str(gpt_runtime or "").strip().lower()

    def _num(v: Any) -> float | None:
        return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None

    est = _num(estimated_cost) if estimate_priced else None

    if p == "gpt" and runtime != "responses":
        return None, "none", True
    if p == "gpt":  # responses — API-key billed; its figure is its own estimate
        cost = _num(reported_cost)
        if cost is None:
            cost = est
        return (cost, "estimated", False) if cost is not None else (None, "none", False)

    cost = _num(reported_cost)
    if cost is not None:
        return cost, "reported", False
    return (est, "estimated", False) if est is not None else (None, "none", False)


def _jobs_dir() -> Path:
    return Path(os.environ.get("DATA_DIR", "/data")) / "jobs"


def ledger_path(job_id: str) -> Path:
    return _jobs_dir() / Path(job_id).name / LEDGER_FILENAME


def _clean_tokens(tokens: Any) -> dict[str, int]:
    if not isinstance(tokens, dict):
        return {}
    out: dict[str, int] = {}
    for k in TOKEN_KEYS:
        v = tokens.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and v:
            out[k] = int(v)
    return out


class _ledger_lock:
    """Cross-PROCESS exclusion around the whole read-decide-append cycle.

    The attempt number and the dedupe check are both derived from the file's
    current contents, so deriving them outside the lock that guards the append
    is a read-modify-write race: two workers seeded from the same empty
    snapshot both allocate attempt 1 (verified with a multiprocessing barrier).
    A thread lock cannot fix that — the api container and the worker are
    different PROCESSES, and stage 3 gives the ledger writers in both.

    flock is advisory and Linux-only; on a platform without it this degrades
    to the in-process lock, which is still correct for the single-process case.
    """

    def __init__(self, path: Path):
        self.path = path
        self._fh = None

    def __enter__(self):
        _lock.acquire()
        try:
            import fcntl

            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self.path.parent.joinpath(
                self.path.name + ".lock"
            ).open("a+")
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
        except Exception:
            self._close()
        return self

    def _close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None

    def __exit__(self, *exc) -> None:
        # flock is released by the close; do it before dropping the thread lock
        # so the two are never held in an inconsistent order.
        self._close()
        _lock.release()


def next_attempt(job_id: str, role: str, stage: str) -> int:
    """1-based counter for this (job, role, stage), derived from the file.

    Read-only: the value is only trustworthy while the ledger lock is held, so
    `record_usage` calls this INSIDE that lock. Exposed for tests/inspection.
    """
    seen = 0
    for rec in read_usage(job_id):
        if rec.get("role") == role and rec.get("stage") == stage:
            seen += 1
    return seen + 1


def record_usage(
    job_id: str,
    *,
    role: str,
    stage: str,
    provider: str,
    model: str | None = None,
    tokens: dict | None = None,
    cost_usd: float | None = None,
    cost_basis: str = "none",
    runtime: str | None = None,
    window: dict | None = None,
    error_kind: str | None = None,
    dedupe_key: str | None = None,
    extra: dict | None = None,
) -> dict[str, Any] | None:
    """Append one role invocation to the job's ledger.

    ``extra`` merges caller-specific scalars onto the row (the judge uses it
    for its failover diagnosis). Kept generic so the ledger does not grow a
    field per caller, and merged UNDER the reserved keys so a caller cannot
    overwrite provider/model/cost by accident.

    ``cost_usd=None`` is preserved as null. Callers must NOT pass 0.0 to mean
    "the provider did not tell us" — that is what ``cost_basis="none"`` is for,
    and 0.0 is a legitimate value for a call that really did cost nothing.

    ``dedupe_key`` makes a row idempotent. Main needs it: its cost arrives on a
    ResultMessage whose figure is cumulative for that SDK session, and the same
    session can emit more than one. Keyed by session id, a repeat replaces
    nothing and adds nothing, while a genuine stop->continue (a second session)
    still contributes its own row — so the rows sum to the true total either
    way. Roles whose every invocation is discrete simply omit it.

    Returns the written record, None if it could not be written, and None when
    ``dedupe_key`` was already recorded for this job.
    """
    try:
        if cost_basis not in COST_BASIS:
            cost_basis = "none"
        if not isinstance(cost_usd, (int, float)) or isinstance(cost_usd, bool):
            cost_usd = None
        if cost_usd is None:
            cost_basis = "none"

        rec: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "role": str(role),
            "stage": str(stage),
            "provider": str(provider),
            "model": str(model) if model else None,
            "tokens": _clean_tokens(tokens),
            "cost_usd": cost_usd,
            "cost_basis": cost_basis,
        }
        if runtime:
            # `gpt` alone does not say which billing model applied. An auditor
            # reading a row needs to know whether "no dollars" meant a
            # subscription or a failure to record one.
            rec["runtime"] = str(runtime)
        if dedupe_key:
            rec["dedupe_key"] = str(dedupe_key)
        if isinstance(window, dict) and window:
            rec["window"] = {
                k: v
                for k, v in window.items()
                if isinstance(v, (int, float, str)) and v is not None
            }
        if error_kind:
            rec["error_kind"] = str(error_kind)
        for k, v in (extra or {}).items():
            if k in rec or v is None:
                continue
            if isinstance(v, (str, int, float, bool)):
                rec[str(k)] = v

        path = ledger_path(job_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        # The dedupe check and the attempt number are BOTH derived from the
        # file's current contents, so they have to be inside the same lock as
        # the append or two writers seeded from one snapshot allocate the same
        # attempt (and both pass a dedupe check the other was about to fail).
        with _ledger_lock(path):
            if dedupe_key:
                for prior in read_usage(job_id):
                    if prior.get("dedupe_key") == dedupe_key:
                        return None
            rec["attempt"] = next_attempt(job_id, role, stage)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        return rec
    except Exception:
        # Never let accounting break the run it is accounting for.
        return None


def record_usage_by_model(
    job_id: str,
    *,
    role: str,
    stage: str,
    provider: str,
    primary_model: str | None,
    model_usage: dict[str, dict] | None,
    tokens: dict | None,
    reported_cost: float | None,
    estimate_for,
    rates_known,
    gpt_runtime: str | None = None,
    window_for=None,
    error_kind: str | None = None,
    dedupe_key: str | None = None,
    extra: dict | None = None,
) -> list[dict[str, Any]]:
    """One row PER MODEL for a turn that may have spanned several.

    A single turn is not necessarily single-model: a judge registers a recon
    subagent, main's Responses adapter merges every child's usage into the
    parent map, and either can be pinned to a different model by the active
    preset. Folding that into one row loses the ledger's own `model` axis and
    prices the cheaper model's tokens at the expensive one's rate — measured
    $0.0225 booked where the per-model sum was $0.0165.

    Shared by the judge and main wirings deliberately. This defect was found
    twice — once in each — because the same splitting logic lived in neither
    place and had to be written from scratch the second time.

    A REPORTED cost is a SESSION figure and cannot be split across models
    without inventing the split, so it stays whole on the primary model's row
    and the others carry tokens with no dollars. The bucket then sums to the
    reported total rather than a fabricated one, and `usd_complete` says out
    loud that not every row could be priced.

    `dedupe_key`, when given, is suffixed per model — otherwise the first row
    would claim the key and every other model would be silently refused.
    """
    # normalize_tokens before the map is consulted, so an all-camelCase entry
    # is not mistaken for an empty one and silently demoted to the `tokens`
    # fallback row.
    breakdown = {
        str(m): n
        for m, t in (model_usage or {}).items()
        if isinstance(t, dict) and t
        for n in (normalize_tokens(t),)
        if n
    }
    if breakdown:
        # Whenever the SDK gave a per-model map, use it — even for one model.
        # `_common.agent_heartbeat` already treats model_usage as the
        # authoritative field ("pricing these totals reproduces the reported
        # cost to the cent"), and taking the streamed `usage` for one model
        # while taking the map for two made the two paths disagree about which
        # number is real.
        rows = sorted(breakdown.items(), key=lambda kv: kv[0] != (primary_model or ""))
    else:
        rows = [(primary_model, normalize_tokens(tokens))]

    written: list[dict[str, Any]] = []
    window = None
    for index, (model, model_tokens) in enumerate(rows):
        is_primary = index == 0
        reported = reported_cost if is_primary else None
        est = None
        if model_tokens and reported_cost is None:
            try:
                est = estimate_for(model_tokens, model) or None
            except Exception:
                est = None
        cost, basis, wants_window = cost_contract(
            provider,
            reported_cost=reported,
            estimated_cost=est,
            gpt_runtime=gpt_runtime,
            estimate_priced=bool(rates_known(model)),
        )
        if wants_window and window is None and window_for is not None:
            try:
                window = window_for()
            except Exception:
                window = None
        rec = record_usage(
            job_id,
            role=role,
            stage=stage,
            provider=provider,
            model=model,
            tokens=model_tokens,
            cost_usd=cost,
            cost_basis=basis,
            runtime=gpt_runtime,
            window=window if wants_window else None,
            error_kind=error_kind,
            extra=extra,
            dedupe_key=(
                f"{dedupe_key}:{model or ''}" if dedupe_key and len(rows) > 1
                else dedupe_key
            ),
        )
        if rec:
            written.append(rec)
    return written


def read_usage(job_id: str) -> list[dict[str, Any]]:
    """All ledger records for a job, oldest first. Malformed lines are skipped.

    A truncated final line (the process died mid-append) must not make the
    whole ledger unreadable — that would turn a cosmetic loss into a total one.
    """
    out: list[dict[str, Any]] = []
    try:
        text = ledger_path(job_id).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def aggregate_usage(job_id: str) -> dict[str, Any]:
    """Per-provider buckets. Deliberately returns NO cross-provider total.

    Each bucket carries:
      tokens        summed per token key
      usd           sum of the entries that reported dollars, or None when
                    none did — never 0.0 as a stand-in for "unknown"
      usd_complete  False when any entry in the bucket has no dollar figure,
                    so a partial sum is never mistaken for the bucket total
      calls         invocation count
      by_role       {role: {stage: {...}}} at the same granularity
      window        the most recent window reading seen for this provider

    There is no `total_usd` key across providers, and that absence is the
    point: Claude dollars and a Codex subscription window are different units
    and adding them produces a number that means nothing.
    """
    records = read_usage(job_id)
    providers: dict[str, Any] = {}

    def _bucket() -> dict[str, Any]:
        return {
            "tokens": {},
            "usd": None,
            "usd_complete": True,
            "calls": 0,
            "by_role": {},
        }

    def _fold(dst: dict[str, Any], rec: dict[str, Any]) -> None:
        dst["calls"] += 1
        for k, v in (rec.get("tokens") or {}).items():
            if isinstance(v, (int, float)):
                dst["tokens"][k] = dst["tokens"].get(k, 0) + int(v)
        cost = rec.get("cost_usd")
        if isinstance(cost, (int, float)) and not isinstance(cost, bool):
            dst["usd"] = round((dst["usd"] or 0.0) + float(cost), 6)
        else:
            dst["usd_complete"] = False

    for rec in records:
        provider = str(rec.get("provider") or "unknown")
        role = str(rec.get("role") or "unknown")
        stage = str(rec.get("stage") or "unknown")
        bucket = providers.setdefault(provider, _bucket())
        _fold(bucket, rec)
        role_b = bucket["by_role"].setdefault(role, _bucket())
        _fold(role_b, rec)
        stage_b = role_b["by_role"].setdefault(stage, _bucket())
        _fold(stage_b, rec)
        window = rec.get("window")
        if isinstance(window, dict) and window:
            bucket["window"] = window

    return {"providers": providers, "records": len(records)}


def codex_window_snapshot(*, cached_only: bool = False) -> dict[str, Any] | None:
    """Current Codex window remaining, shaped for a ledger record.

    Returns None when Codex is not the provider in play or the reading is
    unavailable — a missing reading is recorded as absent, never as 100%.

    ``cached_only=True`` never spawns the Codex CLI. Use it from anything on a
    job's critical path: ``read_codex_rate_limit()`` falls through to an
    app-server round trip with a 10-second timeout when its 60-second cache is
    stale, and the natural place to record main's usage is the FINAL heartbeat
    of the run — where a ten-second stall is a ten-second stall in finishing
    the job. A slightly old percentage is worth more than a fast one that
    delays the artifact write.
    """
    try:
        if cached_only:
            from modules.codex_rate_limit import _read_cache

            data = _read_cache(fresh_only=False)
        else:
            from modules.codex_rate_limit import read_codex_rate_limit

            data = read_codex_rate_limit()
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    out: dict[str, Any] = {}
    for w in data.get("windows") or []:
        if not isinstance(w, dict):
            continue
        kind = w.get("rate_limit_type")
        remaining = w.get("remaining_pct")
        if kind and isinstance(remaining, (int, float)):
            out[f"{kind}_remaining_pct"] = float(remaining)
    if isinstance(data.get("remaining_pct"), (int, float)):
        out["display_remaining_pct"] = float(data["remaining_pct"])
    if data.get("resets_at"):
        out["resets_at"] = data["resets_at"]
    if data.get("stale") or cached_only:
        # Say so rather than presenting an old percentage as current — the
        # same reason read_codex_rate_limit stamps `stale` on its fallback.
        out["stale"] = True
    return out or None
