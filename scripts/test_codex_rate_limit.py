#!/usr/bin/env python3
"""Offline normalization tests for the Codex OAuth usage widget."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules.codex_rate_limit import _normalize_rate_limits  # noqa: E402


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


print(f"\n{PASS} checks, {FAIL} failed")
raise SystemExit(1 if FAIL else 0)
