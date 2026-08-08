#!/usr/bin/env python3
"""Offline normalization tests for the Codex OAuth usage widget."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules import codex_rate_limit  # noqa: E402


_normalize_rate_limits = codex_rate_limit._normalize_rate_limits


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


NOW = datetime(2026, 8, 7, 10, 0, tzinfo=timezone.utc)
ROOT_LIMIT = {
    "limitId": "codex",
    "limitName": None,
    "primary": {
        "usedPercent": 6,
        "windowDurationMins": 10_080,
        "resetsAt": 1_786_696_752,
    },
    "secondary": None,
    "credits": {"hasCredits": False, "unlimited": False, "balance": "0"},
    "individualLimit": None,
    "spendControlReached": False,
    "planType": "prolite",
    "rateLimitReachedType": None,
}
SPARK_LIMIT = {
    "limitId": "codex_bengalfox",
    "limitName": "GPT-5.3-Codex-Spark",
    "primary": {
        "usedPercent": 0,
        "windowDurationMins": 10_080,
        "resetsAt": 1_786_705_592,
    },
    "secondary": None,
}


actual_shape = _normalize_rate_limits(
    {
        "rateLimits": ROOT_LIMIT,
        "rateLimitsByLimitId": {
            "codex": ROOT_LIMIT,
            "codex_bengalfox": SPARK_LIMIT,
        },
        "rateLimitResetCredits": {"availableCount": 0, "credits": []},
    },
    now=NOW,
)
check("actual response normalizes", actual_shape is not None)
check("remaining is derived from used", actual_shape["remaining_pct"] == 94.0)
check("weekly window is named", actual_shape["rate_limit_type"] == "seven_day")
check("reset epoch is preserved", actual_shape["resets_at"] == 1_786_696_752)
check("plan is preserved", actual_shape["plan_type"] == "prolite")
check("healthy quota is green", actual_shape["status"] == "allowed")
check("named model pool reaches tooltip", len(actual_shape["windows"]) == 2)
check(
    "secrets and credit balance are omitted",
    "balance" not in actual_shape["credits"]
    and "rateLimitResetCredits" not in actual_shape,
)


constrained = dict(ROOT_LIMIT)
constrained["primary"] = {
    "usedPercent": 25,
    "windowDurationMins": 300,
    "resetsAt": 100,
}
constrained["secondary"] = {
    "usedPercent": 85,
    "windowDurationMins": 10_080,
    "resetsAt": 200,
}
constrained_shape = _normalize_rate_limits(
    {"rateLimits": constrained, "rateLimitsByLimitId": {"codex": constrained}},
    now=NOW,
)
check(
    "most constrained window is displayed", constrained_shape["remaining_pct"] == 15.0
)
check("low remaining quota warns", constrained_shape["status"] == "allowed_warning")
check(
    "displayed reset follows constrained window", constrained_shape["resets_at"] == 200
)


rejected = dict(ROOT_LIMIT)
rejected["rateLimitReachedType"] = "primary"
rejected_shape = _normalize_rate_limits({"rateLimits": rejected}, now=NOW)
check("server-declared limit is rejected", rejected_shape["status"] == "rejected")


check(
    "Codex cache bounds top-bar lag",
    codex_rate_limit.CODEX_RATE_LIMIT_TTL_S <= 15.0,
)


with tempfile.TemporaryDirectory(prefix="codex-rate-source-") as source_tmp:
    source_home = Path(source_tmp)
    source_auth = source_home / "auth.json"
    source_auth.write_text("{}")
    source_auth.chmod(0o600)
    isolated_seen: dict[str, object] = {}

    def isolated_query(*, codex_home=None):
        auth_link = Path(codex_home) / "auth.json"
        isolated_seen["home"] = codex_home
        isolated_seen["is_link"] = auth_link.is_symlink()
        isolated_seen["target"] = auth_link.resolve()
        return {"ok": True}

    with patch.dict(os.environ, {"CODEX_HOME": str(source_home)}), patch.object(
        codex_rate_limit, "_query_codex_rate_limits", isolated_query
    ):
        isolated_result = codex_rate_limit._query_codex_rate_limits_isolated()

    check("isolated query returns adapter result", isolated_result == {"ok": True})
    check("isolated query keeps auth as a symlink", isolated_seen.get("is_link") is True)
    check(
        "isolated query points at authoritative auth",
        isolated_seen.get("target") == source_auth.resolve(),
    )


with tempfile.TemporaryDirectory(prefix="codex-rate-fallback-") as fallback_tmp:
    fallback_root = Path(fallback_tmp)
    source_home = fallback_root / "source"
    source_home.mkdir()
    (source_home / "auth.json").write_text("{}")
    cache_path = fallback_root / "codex_rate_limit.json"
    query_homes: list[Path | None] = []

    def shared_then_isolated(*, codex_home=None):
        query_homes.append(codex_home)
        if codex_home is None:
            raise RuntimeError("busy shared runtime")
        return {
            "rateLimits": ROOT_LIMIT,
            "rateLimitsByLimitId": {"codex": ROOT_LIMIT},
        }

    with patch.dict(os.environ, {"CODEX_HOME": str(source_home)}), patch.object(
        codex_rate_limit, "CODEX_RATE_LIMIT_CACHE", cache_path
    ), patch.object(
        codex_rate_limit, "has_codex_oauth", return_value=True
    ), patch.object(
        codex_rate_limit, "_query_codex_rate_limits", shared_then_isolated
    ):
        fallback_result = codex_rate_limit.read_codex_rate_limit()

    check("shared runtime failure retries in isolation", len(query_homes) == 2)
    check("fallback first tries the configured runtime", query_homes[0] is None)
    check("fallback uses an ephemeral Codex home", query_homes[1] is not None)
    check("fallback returns fresh quota", fallback_result["remaining_pct"] == 94.0)
    check("fallback fresh quota is not marked stale", not fallback_result.get("stale"))


with tempfile.TemporaryDirectory(prefix="codex-rate-stale-") as stale_tmp:
    stale_root = Path(stale_tmp)
    stale_cache = stale_root / "codex_rate_limit.json"
    stale_cache.write_text(json.dumps(actual_shape))
    old_time = time.time() - 125
    os.utime(stale_cache, (old_time, old_time))

    with patch.object(
        codex_rate_limit, "CODEX_RATE_LIMIT_CACHE", stale_cache
    ), patch.object(
        codex_rate_limit, "has_codex_oauth", return_value=True
    ), patch.object(
        codex_rate_limit,
        "_query_codex_rate_limits",
        side_effect=RuntimeError("shared failed"),
    ), patch.object(
        codex_rate_limit,
        "_query_codex_rate_limits_isolated",
        side_effect=RuntimeError("isolated failed"),
    ):
        stale_result = codex_rate_limit.read_codex_rate_limit()

    check("failed refresh is marked stale", stale_result.get("stale") is True)
    check(
        "stale response exposes visible age",
        stale_result.get("stale_age_seconds", 0) >= 120,
    )


print(f"\n{PASS} checks, {FAIL} failed")
raise SystemExit(1 if FAIL else 0)
