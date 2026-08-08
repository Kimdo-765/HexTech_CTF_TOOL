"""Best-effort Claude Code OAuth usage data for the top-bar UI.

Claude Agent SDK ``RateLimitEvent`` messages are useful while a job is
running, but they are a passive, single-window signal.  In particular, an old
event can remain in ``/data/rate_limit.json`` long after its reset.  Claude
Code's OAuth usage endpoint returns the current five-hour and weekly windows,
so subscription users get an actively refreshed snapshot here.  API-key-only
setups continue to use the SDK event cache written by ``modules._common``.

Only sanitized percentages, reset times, and account tier labels are cached;
OAuth credentials never leave the mounted credentials file.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CLAUDE_RATE_LIMIT_CACHE = (
    Path(os.environ.get("DATA_DIR", "/data")) / "rate_limit.json"
)
CLAUDE_RATE_LIMIT_TTL_S = 15.0
CLAUDE_RATE_LIMIT_TIMEOUT_S = 10.0
_CLAUDE_USAGE_URL = "https://api.anthropic.com/api/oauth/usage"
_CLAUDE_TOKEN_URL = "https://platform.claude.com/v1/oauth/token"
_CLAUDE_CODE_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
_CLAUDE_OAUTH_BETA = "oauth-2025-04-20"

_cache_lock = threading.Lock()
_refresh_lock = threading.Lock()


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _percent(value: Any) -> float | None:
    number = _number(value)
    if number is None:
        return None
    return round(max(0.0, min(100.0, number)), 1)


def _reset_epoch(value: Any) -> int | None:
    if value in (None, ""):
        return None
    number = _number(value)
    if number is not None:
        # Credential expiries use milliseconds, while usage resets generally
        # use ISO timestamps.  Supporting both keeps fixtures/version changes
        # harmless.
        if number > 10_000_000_000:
            number /= 1000.0
        return int(number) if number > 0 else None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp())
    except (TypeError, ValueError, OverflowError):
        return None


def _rate_limit_type(group: Any, kind: Any) -> str:
    group_s = str(group or "").lower()
    kind_s = str(kind or "").lower()
    if group_s == "session" or kind_s in {"session", "five_hour"}:
        return "five_hour"
    if group_s == "weekly" or "week" in kind_s:
        return "seven_day"
    return kind_s or group_s or "subscription"


def _scope_label(scope: Any) -> str | None:
    if not isinstance(scope, dict):
        return None
    model = scope.get("model")
    if isinstance(model, dict):
        label = model.get("display_name") or model.get("id")
        if label:
            return str(label)
    surface = scope.get("surface")
    return str(surface) if surface else None


def _normalize_window(
    *,
    kind: Any,
    group: Any,
    used_value: Any,
    resets_at: Any,
    scope: Any = None,
    severity: Any = None,
    is_active: Any = None,
) -> dict[str, Any] | None:
    used = _percent(used_value)
    if used is None:
        return None
    return {
        "kind": str(kind or group or "usage"),
        "group": str(group or ""),
        "label": _scope_label(scope),
        "rate_limit_type": _rate_limit_type(group, kind),
        "used_pct": used,
        "remaining_pct": round(100.0 - used, 1),
        "resets_at": _reset_epoch(resets_at),
        "severity": str(severity) if severity else None,
        "is_active": bool(is_active) if is_active is not None else None,
        "scoped": isinstance(scope, dict) and bool(scope),
    }


def _normalize_claude_usage(
    response: dict[str, Any],
    *,
    now: datetime | None = None,
    subscription_type: str | None = None,
    rate_limit_tier: str | None = None,
) -> dict[str, Any] | None:
    """Convert Claude's OAuth usage response to the shared UI shape."""
    if not isinstance(response, dict):
        return None

    windows: list[dict[str, Any]] = []
    limits = response.get("limits")
    if isinstance(limits, list):
        for limit in limits:
            if not isinstance(limit, dict):
                continue
            window = _normalize_window(
                kind=limit.get("kind"),
                group=limit.get("group"),
                used_value=limit.get("percent"),
                resets_at=limit.get("resets_at"),
                scope=limit.get("scope"),
                severity=limit.get("severity"),
                is_active=limit.get("is_active"),
            )
            if window is not None:
                windows.append(window)

    # Older responses do not contain ``limits``.  Preserve support for their
    # named top-level windows; these ``utilization`` values are percentages,
    # unlike the SDK RateLimitEvent's 0..1 fraction.
    if not windows:
        for key, group in (
            ("five_hour", "session"),
            ("seven_day", "weekly"),
            ("seven_day_opus", "weekly"),
            ("seven_day_sonnet", "weekly"),
            ("seven_day_oauth_apps", "weekly"),
        ):
            raw = response.get(key)
            if not isinstance(raw, dict):
                continue
            scope = None if key in {"five_hour", "seven_day"} else {
                "model": {"display_name": key.removeprefix("seven_day_").title()}
            }
            window = _normalize_window(
                kind=key,
                group=group,
                used_value=raw.get("utilization"),
                resets_at=raw.get("resets_at"),
                scope=scope,
            )
            if window is not None:
                windows.append(window)

    # The chip represents the ordinary account pool.  Model/surface-scoped
    # windows remain available in the tooltip but must not replace it.
    ordinary = [window for window in windows if not window["scoped"]]
    display = max(ordinary or windows, key=lambda item: item["used_pct"], default=None)
    if display is None:
        return None

    used = float(display["used_pct"])
    remaining = float(display["remaining_pct"])
    severity = str(display.get("severity") or "").lower()
    if remaining <= 0 or severity in {"blocked", "rejected", "exceeded"}:
        status = "rejected"
    elif remaining <= 20 or severity in {"warning", "critical"}:
        status = "allowed_warning"
    else:
        status = "allowed"

    observed_at = now or datetime.now(timezone.utc)
    return {
        "status": status,
        "rate_limit_type": display.get("rate_limit_type"),
        "utilization": round(used / 100.0, 3),
        "used_pct": used,
        "remaining_pct": remaining,
        "resets_at": display.get("resets_at"),
        "updated_at": observed_at.isoformat(),
        "subscription_type": subscription_type,
        "rate_limit_tier": rate_limit_tier,
        "windows": windows,
        "source": "claude_oauth_usage",
    }


def _credential_paths() -> list[Path]:
    claude_home = Path(os.environ.get("CLAUDE_CONFIG_DIR") or "/root/.claude")
    return [
        claude_home / ".credentials.json",
        claude_home / "credentials.json",
        Path.home() / ".claude" / ".credentials.json",
        Path.home() / ".claude" / "credentials.json",
    ]


def _load_oauth() -> tuple[Path | None, str | None, dict[str, Any]]:
    seen: set[Path] = set()
    for path in _credential_paths():
        try:
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            raw = json.loads(path.read_text())
            oauth = raw.get("claudeAiOauth") if isinstance(raw, dict) else None
            if not isinstance(oauth, dict) or not oauth.get("accessToken"):
                continue
            return path, str(oauth["accessToken"]), dict(oauth)
        except (OSError, ValueError, TypeError):
            continue
    return None, None, {}


def _query_claude_usage(access_token: str) -> dict[str, Any]:
    timeout = _number(os.environ.get("CLAUDE_RATE_LIMIT_TIMEOUT_S"))
    timeout = (
        timeout
        if timeout is not None and timeout > 0
        else CLAUDE_RATE_LIMIT_TIMEOUT_S
    )
    request = urllib.request.Request(
        _CLAUDE_USAGE_URL,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "anthropic-beta": _CLAUDE_OAUTH_BETA,
            "User-Agent": "HexTech_CTF_TOOL/claude-usage",
        },
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read())
    if not isinstance(payload, dict):
        raise RuntimeError("Claude returned a non-object usage response")
    return payload


def _replace_credentials_json(path: Path, payload: dict[str, Any]) -> None:
    """Atomically update a bind-mounted credential while retaining ownership."""
    original = path.stat()
    directory = path.parent.stat()
    tmp = path.with_name(f"{path.name}.hextech.{os.getpid()}.tmp")
    fd = -1
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.fchmod(fd, original.st_mode & 0o777)
        try:
            os.fchown(fd, directory.st_uid, directory.st_gid)
        except (AttributeError, PermissionError, OSError):
            pass
        with os.fdopen(fd, "w") as out:
            fd = -1
            json.dump(payload, out)
        tmp.replace(path)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def _refresh_claude_token(
    credential_path: Path, failed_access_token: str
) -> str | None:
    """Refresh an expired Claude Code token without invoking an inference turn."""
    with _refresh_lock:
        try:
            root = json.loads(credential_path.read_text())
        except (OSError, ValueError, TypeError):
            return None
        oauth = root.get("claudeAiOauth") if isinstance(root, dict) else None
        if not isinstance(oauth, dict):
            return None

        # A worker/CLI may have refreshed while the usage request was in
        # flight.  Prefer that token instead of rotating the same refresh token
        # twice.
        current_access = oauth.get("accessToken")
        if current_access and current_access != failed_access_token:
            return str(current_access)
        refresh_token = oauth.get("refreshToken")
        if not refresh_token:
            return None

        body = json.dumps({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": _CLAUDE_CODE_CLIENT_ID,
        }).encode()
        request = urllib.request.Request(
            _CLAUDE_TOKEN_URL,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "HexTech_CTF_TOOL/claude-usage",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=CLAUDE_RATE_LIMIT_TIMEOUT_S) as response:
            refreshed = json.loads(response.read())
        access = refreshed.get("access_token") if isinstance(refreshed, dict) else None
        if not access:
            return None
        oauth["accessToken"] = access
        if refreshed.get("refresh_token"):
            oauth["refreshToken"] = refreshed["refresh_token"]
        expires_in = _number(refreshed.get("expires_in"))
        if expires_in is not None and expires_in > 0:
            oauth["expiresAt"] = int((time.time() + expires_in) * 1000)
        root["claudeAiOauth"] = oauth
        _replace_credentials_json(credential_path, root)
        return str(access)


def _query_claude_usage_with_refresh(
    credential_path: Path, access_token: str
) -> dict[str, Any]:
    try:
        return _query_claude_usage(access_token)
    except urllib.error.HTTPError as exc:
        if exc.code != 401:
            raise
        refreshed = _refresh_claude_token(credential_path, access_token)
        if not refreshed:
            raise
        return _query_claude_usage(refreshed)


def _read_cache(*, fresh_only: bool, active_only: bool = False) -> dict[str, Any] | None:
    try:
        age = time.time() - CLAUDE_RATE_LIMIT_CACHE.stat().st_mtime
        if fresh_only and age > CLAUDE_RATE_LIMIT_TTL_S:
            return None
        data = json.loads(CLAUDE_RATE_LIMIT_CACHE.read_text())
        if not isinstance(data, dict):
            return None
        if active_only and data.get("source") != "claude_oauth_usage":
            return None
        return data
    except (OSError, ValueError, TypeError):
        return None


def _write_cache(payload: dict[str, Any]) -> None:
    CLAUDE_RATE_LIMIT_CACHE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CLAUDE_RATE_LIMIT_CACHE.with_name(
        f"{CLAUDE_RATE_LIMIT_CACHE.name}.oauth.{os.getpid()}.tmp"
    )
    tmp.write_text(json.dumps(payload, separators=(",", ":")))
    tmp.replace(CLAUDE_RATE_LIMIT_CACHE)


def _mark_stale(cached: dict[str, Any]) -> dict[str, Any]:
    result = dict(cached)
    result["stale"] = True
    try:
        result["stale_age_seconds"] = max(
            0, int(time.time() - CLAUDE_RATE_LIMIT_CACHE.stat().st_mtime)
        )
    except OSError:
        pass
    return result


def read_claude_rate_limit() -> dict[str, Any] | None:
    """Return a sanitized current OAuth quota snapshot when possible."""
    credential_path, token, oauth = _load_oauth()
    if not credential_path or not token:
        # API-key users have no subscription usage endpoint.  Their latest SDK
        # RateLimitEvent remains the best available signal.
        return _read_cache(fresh_only=False)

    cached = _read_cache(fresh_only=True, active_only=True)
    if cached is not None:
        return cached

    with _cache_lock:
        cached = _read_cache(fresh_only=True, active_only=True)
        if cached is not None:
            return cached
        try:
            normalized = _normalize_claude_usage(
                _query_claude_usage_with_refresh(credential_path, token),
                subscription_type=oauth.get("subscriptionType"),
                rate_limit_tier=oauth.get("rateLimitTier"),
            )
            if normalized is None:
                raise RuntimeError("Claude returned no usable rate-limit windows")
            _write_cache(normalized)
            return normalized
        except Exception:
            stale = _read_cache(fresh_only=False)
            return _mark_stale(stale) if stale is not None else None
