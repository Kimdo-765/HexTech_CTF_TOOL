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

# How a dollar figure was arrived at. The distinction matters when deciding
# whether a cap may fire: an estimate must not silently stop a job.
COST_BASIS = ("reported", "estimated", "none")

_lock = threading.Lock()
_attempts: dict[tuple[str, str, str], int] = {}


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


def next_attempt(job_id: str, role: str, stage: str) -> int:
    """1-based counter for this (job, role, stage).

    In-process, and seeded from the file so a worker restart mid-job does not
    reset supervise back to attempt 1 and make two different calls look like
    the same one.
    """
    key = (str(job_id), str(role), str(stage))
    with _lock:
        if key not in _attempts:
            seen = 0
            for rec in read_usage(job_id):
                if rec.get("role") == role and rec.get("stage") == stage:
                    seen += 1
            _attempts[key] = seen
        _attempts[key] += 1
        return _attempts[key]


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
    window: dict | None = None,
    error_kind: str | None = None,
    dedupe_key: str | None = None,
) -> dict[str, Any] | None:
    """Append one role invocation to the job's ledger.

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
        if dedupe_key:
            for prior in read_usage(job_id):
                if prior.get("dedupe_key") == dedupe_key:
                    return None
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
            "attempt": next_attempt(job_id, role, stage),
            "provider": str(provider),
            "model": str(model) if model else None,
            "tokens": _clean_tokens(tokens),
            "cost_usd": cost_usd,
            "cost_basis": cost_basis,
        }
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

        path = ledger_path(job_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with _lock:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec
    except Exception:
        # Never let accounting break the run it is accounting for.
        return None


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
