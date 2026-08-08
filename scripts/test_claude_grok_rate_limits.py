#!/usr/bin/env python3
"""Offline regression tests for Claude and Grok usage widgets."""

from __future__ import annotations

import json
import sys
import tempfile
import time
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules import claude_rate_limit  # noqa: E402
from modules import _common  # noqa: E402


PASS = 0
FAIL = 0


def check(name: str, condition: bool) -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"PASS  {name}")
    else:
        FAIL += 1
        print(f"FAIL  {name}")


NOW = datetime(2026, 8, 8, 16, 0, tzinfo=timezone.utc)
CLAUDE_RESPONSE = {
    "five_hour": {
        "utilization": 7.0,
        "resets_at": "2026-08-08T20:00:00.193050+00:00",
    },
    "seven_day": {
        "utilization": 14.0,
        "resets_at": "2026-08-14T20:00:00.193069+00:00",
    },
    "limits": [
        {
            "kind": "session",
            "group": "session",
            "percent": 7,
            "severity": "normal",
            "resets_at": "2026-08-08T20:00:00.193050+00:00",
            "scope": None,
            "is_active": False,
        },
        {
            "kind": "weekly_all",
            "group": "weekly",
            "percent": 14,
            "severity": "normal",
            "resets_at": "2026-08-14T20:00:00.193069+00:00",
            "scope": None,
            "is_active": True,
        },
        {
            "kind": "weekly_scoped",
            "group": "weekly",
            "percent": 91,
            "severity": "warning",
            "resets_at": "2026-08-14T20:00:00.193069+00:00",
            "scope": {"model": {"display_name": "Fable"}},
            "is_active": True,
        },
    ],
}


normalized = claude_rate_limit._normalize_claude_usage(
    CLAUDE_RESPONSE,
    now=NOW,
    subscription_type="max",
    rate_limit_tier="default_claude_max_20x",
)
check("Claude live response normalizes", normalized is not None)
check("Claude percentage is treated as used percent", normalized["used_pct"] == 14.0)
check("Claude remaining is derived correctly", normalized["remaining_pct"] == 86.0)
check("Claude most constrained ordinary window is displayed", normalized["rate_limit_type"] == "seven_day")
check("Claude scoped model pool stays out of headline", normalized["status"] == "allowed")
check("Claude tooltip retains all windows", len(normalized["windows"]) == 3)
check("Claude account label is sanitized through", normalized["subscription_type"] == "max")


legacy = dict(CLAUDE_RESPONSE)
legacy.pop("limits")
legacy_normalized = claude_rate_limit._normalize_claude_usage(legacy, now=NOW)
check("Claude legacy response normalizes", legacy_normalized is not None)
check("Claude legacy utilization is percent, not fraction", legacy_normalized["remaining_pct"] == 86.0)


unauthorized = urllib.error.HTTPError(
    claude_rate_limit._CLAUDE_USAGE_URL, 401, "expired", {}, None
)
with patch.object(
    claude_rate_limit,
    "_query_claude_usage",
    side_effect=[unauthorized, CLAUDE_RESPONSE],
) as query, patch.object(
    claude_rate_limit, "_refresh_claude_token", return_value="new-token"
) as refresh:
    refreshed_response = claude_rate_limit._query_claude_usage_with_refresh(
        Path("/credentials.json"), "old-token"
    )
check("Claude 401 refreshes once", refresh.call_count == 1 and query.call_count == 2)
check("Claude refresh retry returns usage", refreshed_response == CLAUDE_RESPONSE)


with tempfile.TemporaryDirectory(prefix="claude-rate-") as tmp_name:
    cache_path = Path(tmp_name) / "rate_limit.json"
    credential_path = Path(tmp_name) / ".credentials.json"
    credential_path.write_text(json.dumps({
        "claudeAiOauth": {
            "accessToken": "test-secret",
            "subscriptionType": "max",
            "rateLimitTier": "test-tier",
        }
    }))
    with patch.object(
        claude_rate_limit, "CLAUDE_RATE_LIMIT_CACHE", cache_path
    ), patch.object(
        claude_rate_limit, "_credential_paths", return_value=[credential_path]
    ), patch.object(
        claude_rate_limit, "_query_claude_usage_with_refresh", return_value=CLAUDE_RESPONSE
    ) as query:
        live = claude_rate_limit.read_claude_rate_limit()
        cached = claude_rate_limit.read_claude_rate_limit()
    check("Claude live read returns quota", live["remaining_pct"] == 86.0)
    check("Claude short cache avoids duplicate network reads", query.call_count == 1)
    check("Claude cache contains no OAuth token", "test-secret" not in cache_path.read_text())
    check("Claude cached read remains fresh", not cached.get("stale"))

    old_time = time.time() - 125
    cache_path.touch()
    cache_path.chmod(0o600)
    import os
    os.utime(cache_path, (old_time, old_time))
    with patch.object(
        claude_rate_limit, "CLAUDE_RATE_LIMIT_CACHE", cache_path
    ), patch.object(
        claude_rate_limit, "_credential_paths", return_value=[credential_path]
    ), patch.object(
        claude_rate_limit, "_query_claude_usage_with_refresh", side_effect=RuntimeError("offline")
    ):
        stale = claude_rate_limit.read_claude_rate_limit()
    check("Claude failed refresh is marked stale", stale.get("stale") is True)
    check("Claude stale age is exposed", stale.get("stale_age_seconds", 0) >= 120)


GROK_RESPONSE = {
    "config": {
        "currentPeriod": {
            "type": "USAGE_PERIOD_TYPE_WEEKLY",
            "end": "2026-08-11T09:33:14.043422+00:00",
        },
        "creditUsagePercent": 100.0,
        "productUsage": [
            {"product": "GrokBuild", "usagePercent": 94.0},
            {"product": "GrokChat", "usagePercent": 6.0},
        ],
    }
}
grok = _common._normalize_grok_billing(GROK_RESPONSE)
check("Grok aggregate pool is exhausted", grok["remaining_pct"] == 0.0)
check("Grok exhausted pool is rejected", grok["status"] == "rejected")
check("Grok product breakdown is retained", len(grok["product_usage"]) == 2)

with tempfile.TemporaryDirectory(prefix="grok-rate-") as tmp_name:
    cache_path = Path(tmp_name) / "grok_rate_limit.json"
    cache_path.write_text(json.dumps(grok))
    old_time = time.time() - 125
    os.utime(cache_path, (old_time, old_time))
    with patch.object(_common, "GROK_RATE_LIMIT_CACHE", cache_path):
        grok_stale = _common._read_stale_grok_cache()
    check("Grok failed refresh is marked stale", grok_stale.get("stale") is True)
    check("Grok stale age is exposed", grok_stale.get("stale_age_seconds", 0) >= 120)


with tempfile.TemporaryDirectory(prefix="auth-owner-") as tmp_name:
    auth_dir = Path(tmp_name)
    grok_auth = auth_dir / "auth.json"
    grok_auth.write_text("{}")
    grok_auth.chmod(0o600)
    _common._replace_auth_json(grok_auth, {"safe": True})
    check("Grok auth rewrite preserves private mode", (grok_auth.stat().st_mode & 0o777) == 0o600)
    check("Grok auth rewrite preserves directory owner", grok_auth.stat().st_uid == auth_dir.stat().st_uid)
    check("Grok auth rewrite keeps JSON intact", json.loads(grok_auth.read_text()) == {"safe": True})

    claude_auth = auth_dir / ".credentials.json"
    claude_auth.write_text("{}")
    claude_auth.chmod(0o600)
    claude_rate_limit._replace_credentials_json(claude_auth, {"safe": True})
    check("Claude auth rewrite preserves private mode", (claude_auth.stat().st_mode & 0o777) == 0o600)
    check("Claude auth rewrite preserves directory owner", claude_auth.stat().st_uid == auth_dir.stat().st_uid)
    check("Claude auth rewrite keeps JSON intact", json.loads(claude_auth.read_text()) == {"safe": True})


app_js = (ROOT / "web-ui" / "app.js").read_text()
index_html = (ROOT / "web-ui" / "index.html").read_text()
check(
    "Claude stale quota is visible in the chip",
    'const claudeUsageIcon = rl.stale ? "⚠" : "⏳"' in app_js
    and "_rlStaleSuffix(rl)" in app_js,
)
check(
    "Grok stale quota is visible in the chip",
    'const grokUsageIcon = gr.stale ? "⚠" : "⏳"' in app_js
    and "_rlStaleSuffix(gr)" in app_js,
)
check(
    "browser cache key includes provider quota update",
    "app.js?v=20260809-provider-quota" in index_html,
)


print(f"\n{PASS} checks, {FAIL} failed")
raise SystemExit(1 if FAIL else 0)
