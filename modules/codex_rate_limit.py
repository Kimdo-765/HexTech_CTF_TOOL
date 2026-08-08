"""Best-effort Codex ChatGPT OAuth rate-limit data for the top-bar UI.

Codex owns its OAuth tokens and refresh flow.  This module deliberately does
not parse tokens or call an inferred private HTTP endpoint; it asks the
installed CLI's app-server for ``account/rateLimits/read`` and keeps the
sanitized result in a short-lived cache so the UI's polling interval does not
spawn a Codex process on every request.
"""

from __future__ import annotations

import json
import os
import selectors
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from modules.codex_cli import resolve_codex_bin
from modules.settings_io import has_codex_oauth


CODEX_RATE_LIMIT_CACHE = (
    Path(os.environ.get("DATA_DIR", "/data")) / "codex_rate_limit.json"
)
CODEX_RATE_LIMIT_TTL_S = 60.0
CODEX_RATE_LIMIT_TIMEOUT_S = 10.0

_cache_lock = threading.Lock()


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _epoch(value: Any) -> int | None:
    number = _number(value)
    return int(number) if number is not None and number > 0 else None


def _percent(value: Any) -> float | None:
    number = _number(value)
    if number is None:
        return None
    return round(max(0.0, min(100.0, number)), 1)


def _window_type(duration_mins: Any) -> str | None:
    duration = _number(duration_mins)
    if duration is None:
        return None
    duration = int(duration)
    if duration == 300:
        return "five_hour"
    if duration == 10_080:
        return "seven_day"
    return f"{duration}_minute"


def _normalize_window(
    limit_id: str,
    limit_name: str | None,
    window_name: str,
    raw: Any,
) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    used = _percent(raw.get("usedPercent"))
    if used is None:
        return None
    duration = _number(raw.get("windowDurationMins"))
    return {
        "limit_id": limit_id,
        "limit_name": limit_name,
        "window": window_name,
        "window_duration_mins": int(duration) if duration is not None else None,
        "rate_limit_type": _window_type(duration),
        "used_pct": used,
        "remaining_pct": round(100.0 - used, 1),
        "resets_at": _epoch(raw.get("resetsAt")),
    }


def _normalize_rate_limits(
    response: dict[str, Any], *, now: datetime | None = None
) -> dict[str, Any] | None:
    """Convert Codex app-server's account response to the shared UI shape."""
    root = response.get("rateLimits")
    if not isinstance(root, dict):
        return None

    root_id = str(root.get("limitId") or "codex")
    raw_buckets = response.get("rateLimitsByLimitId")
    buckets = dict(raw_buckets) if isinstance(raw_buckets, dict) else {}
    # The root is the account's ordinary Codex pool. Some CLI versions omit it
    # from the per-model mapping; others repeat it there.
    buckets.setdefault(root_id, root)

    windows: list[dict[str, Any]] = []
    main_windows: list[dict[str, Any]] = []
    ordered_buckets = [(root_id, buckets[root_id])]
    ordered_buckets.extend(
        (bucket_key, bucket)
        for bucket_key, bucket in buckets.items()
        if bucket_key != root_id
    )
    seen_windows: set[tuple[str, str]] = set()
    for bucket_key, bucket in ordered_buckets:
        if not isinstance(bucket, dict):
            continue
        limit_id = str(bucket.get("limitId") or bucket_key)
        limit_name_raw = bucket.get("limitName")
        limit_name = str(limit_name_raw) if limit_name_raw else None
        for window_name in ("primary", "secondary"):
            window_key = (limit_id, window_name)
            if window_key in seen_windows:
                continue
            normalized = _normalize_window(
                limit_id, limit_name, window_name, bucket.get(window_name)
            )
            if normalized is None:
                continue
            seen_windows.add(window_key)
            windows.append(normalized)
            if limit_id == root_id:
                main_windows.append(normalized)

    # Display the most constrained window in the ordinary Codex pool. The
    # complete list remains available for the hover tooltip, including
    # separately named model pools such as Codex Spark.
    display = max(main_windows, key=lambda item: item["used_pct"], default=None)

    if display is None:
        individual = root.get("individualLimit")
        if isinstance(individual, dict):
            remaining = _percent(individual.get("remainingPercent"))
            if remaining is not None:
                display = {
                    "used_pct": round(100.0 - remaining, 1),
                    "remaining_pct": remaining,
                    "resets_at": _epoch(individual.get("resetsAt")),
                    "rate_limit_type": "individual",
                }
    if display is None:
        return None

    used = float(display["used_pct"])
    remaining = float(display["remaining_pct"])
    reached = bool(root.get("rateLimitReachedType")) or bool(
        root.get("spendControlReached")
    )
    if reached or remaining <= 0:
        status = "rejected"
    elif remaining <= 20:
        status = "allowed_warning"
    else:
        status = "allowed"

    credits = root.get("credits") if isinstance(root.get("credits"), dict) else {}
    observed_at = now or datetime.now(timezone.utc)
    return {
        "status": status,
        "rate_limit_type": display.get("rate_limit_type"),
        "used_pct": used,
        "remaining_pct": remaining,
        "resets_at": display.get("resets_at"),
        "updated_at": observed_at.isoformat(),
        "plan_type": root.get("planType"),
        "limit_id": root_id,
        "limit_name": root.get("limitName"),
        "windows": windows,
        "credits": {
            "has_credits": bool(credits.get("hasCredits")),
            "unlimited": bool(credits.get("unlimited")),
        },
    }


def _send(proc: subprocess.Popen[str], message: dict[str, Any]) -> None:
    if proc.stdin is None:
        raise RuntimeError("Codex app-server stdin is unavailable")
    proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
    proc.stdin.flush()


def _read_response(
    proc: subprocess.Popen[str], request_id: int, deadline: float
) -> dict[str, Any]:
    if proc.stdout is None:
        raise RuntimeError("Codex app-server stdout is unavailable")
    with selectors.DefaultSelector() as selector:
        selector.register(proc.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise TimeoutError("Codex rate-limit request timed out")
            line = proc.stdout.readline()
            if not line:
                raise RuntimeError("Codex app-server exited before replying")
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get("id") != request_id:
                continue
            if message.get("error") is not None:
                raise RuntimeError("Codex app-server rejected the request")
            result = message.get("result")
            if not isinstance(result, dict):
                raise RuntimeError("Codex app-server returned no result")
            return result


def _query_codex_rate_limits() -> dict[str, Any]:
    env = os.environ.copy()
    # This widget specifically represents the mounted ChatGPT OAuth account,
    # even if an API fallback key is also configured in Settings.
    env.pop("OPENAI_API_KEY", None)
    env.pop("CODEX_API_KEY", None)
    timeout = _number(os.environ.get("CODEX_RATE_LIMIT_TIMEOUT_S"))
    timeout = (
        timeout if timeout is not None and timeout > 0 else CODEX_RATE_LIMIT_TIMEOUT_S
    )
    proc = subprocess.Popen(
        [resolve_codex_bin(), "app-server", "--stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
        env=env,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + timeout
        _send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "clientInfo": {"name": "hextech-ctf-tool", "version": "1"},
                    "capabilities": {"experimentalApi": True},
                },
            },
        )
        _read_response(proc, 1, deadline)
        _send(proc, {"jsonrpc": "2.0", "method": "initialized"})
        _send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "account/rateLimits/read",
                "params": None,
            },
        )
        return _read_response(proc, 2, deadline)
    finally:
        if proc.stdin is not None:
            proc.stdin.close()
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1)


def _read_cache(*, fresh_only: bool) -> dict[str, Any] | None:
    try:
        age = time.time() - CODEX_RATE_LIMIT_CACHE.stat().st_mtime
        if fresh_only and age > CODEX_RATE_LIMIT_TTL_S:
            return None
        data = json.loads(CODEX_RATE_LIMIT_CACHE.read_text())
        return data if isinstance(data, dict) else None
    except (OSError, ValueError, TypeError):
        return None


def _write_cache(payload: dict[str, Any]) -> None:
    CODEX_RATE_LIMIT_CACHE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CODEX_RATE_LIMIT_CACHE.with_name(CODEX_RATE_LIMIT_CACHE.name + ".tmp")
    tmp.write_text(json.dumps(payload, separators=(",", ":")))
    tmp.replace(CODEX_RATE_LIMIT_CACHE)


def read_codex_rate_limit() -> dict[str, Any] | None:
    """Return a sanitized OAuth quota snapshot, or ``None`` when unavailable."""
    if not has_codex_oauth():
        return None
    cached = _read_cache(fresh_only=True)
    if cached is not None:
        return cached

    with _cache_lock:
        cached = _read_cache(fresh_only=True)
        if cached is not None:
            return cached
        try:
            normalized = _normalize_rate_limits(_query_codex_rate_limits())
            if normalized is None:
                raise RuntimeError("Codex returned no rate-limit windows")
            _write_cache(normalized)
            return normalized
        except Exception:
            # A brief CLI/network failure should not make a known quota vanish.
            # Mark old data clearly so the tooltip never presents it as fresh.
            stale = _read_cache(fresh_only=False)
            if stale is not None:
                stale["stale"] = True
            return stale
