"""Serializable API contract for one live-fire verification job.

The HTTP route stores only JSON-compatible values in ``meta.json``.  The RQ
worker reconstructs the typed LF-2/LF-3 specifications from that snapshot so
settings edits cannot change an already queued job.
"""

from __future__ import annotations

import json
from dataclasses import fields
from typing import Any

from modules.live_fire_patch_loop import PatchLoopSpec
from modules.live_fire_verifier import (
    AttackExpectation,
    ContainerLimits,
    ProbeSpec,
    VerificationSpec,
)


class LiveFireContractError(ValueError):
    """The operator-supplied verification contract is malformed."""


_LIMIT_FIELDS = frozenset(field.name for field in fields(ContainerLimits))
_TOP_LEVEL_FIELDS = frozenset(
    {
        "mitigation_class",
        "start_command",
        "health_command",
        "probes",
        "limits",
        "verification_reserve_s",
        "packaging_reserve_s",
        "max_attempts",
    }
)


def _argv(value: Any, label: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if value is None and allow_empty:
        return ()
    if not isinstance(value, list):
        raise LiveFireContractError(f"{label} must be a JSON array of strings")
    if not value and not allow_empty:
        raise LiveFireContractError(f"{label} cannot be empty")
    if any(not isinstance(part, str) or not part or "\x00" in part for part in value):
        raise LiveFireContractError(
            f"{label} contains an empty or non-string argv value"
        )
    return tuple(value)


def _positive_number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise LiveFireContractError(f"{label} must be a positive number")
    return float(value)


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise LiveFireContractError(f"{label} must be a positive integer")
    return value


def _probe(raw: Any, index: int) -> ProbeSpec:
    label = f"probes[{index}]"
    if not isinstance(raw, dict):
        raise LiveFireContractError(f"{label} must be an object")
    allowed = {
        "name",
        "corpus",
        "command",
        "evidence_tier",
        "attack_expectation",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise LiveFireContractError(f"{label} has unknown fields: {', '.join(unknown)}")
    name = raw.get("name")
    corpus = raw.get("corpus")
    if not isinstance(name, str) or not name:
        raise LiveFireContractError(f"{label}.name must be non-empty text")
    if corpus not in {"benign", "attack"}:
        raise LiveFireContractError(f"{label}.corpus must be benign or attack")

    expectation = None
    if corpus == "attack":
        expectation_raw = raw.get("attack_expectation")
        if not isinstance(expectation_raw, dict):
            raise LiveFireContractError(f"{label}.attack_expectation must be an object")
        expectation_allowed = {"exit_code", "stdout_contains", "stderr_contains"}
        expectation_unknown = sorted(set(expectation_raw) - expectation_allowed)
        if expectation_unknown:
            raise LiveFireContractError(
                f"{label}.attack_expectation has unknown fields: "
                + ", ".join(expectation_unknown)
            )
        exit_code = expectation_raw.get("exit_code", 0)
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            raise LiveFireContractError(
                f"{label}.attack_expectation.exit_code must be an integer"
            )
        for field_name in ("stdout_contains", "stderr_contains"):
            field_value = expectation_raw.get(field_name)
            if field_value is not None and not isinstance(field_value, str):
                raise LiveFireContractError(
                    f"{label}.attack_expectation.{field_name} must be text or null"
                )
        expectation = AttackExpectation(
            exit_code=exit_code,
            stdout_contains=expectation_raw.get("stdout_contains"),
            stderr_contains=expectation_raw.get("stderr_contains"),
        )
    elif (
        raw.get("attack_expectation") is not None
        or raw.get("evidence_tier") is not None
    ):
        raise LiveFireContractError(
            f"{label}: benign probes cannot carry attack evidence fields"
        )

    try:
        return ProbeSpec(
            name=name,
            corpus=corpus,
            command=_argv(raw.get("command"), f"{label}.command", allow_empty=False),
            evidence_tier=raw.get("evidence_tier"),
            attack_expectation=expectation,
        )
    except ValueError as exc:
        raise LiveFireContractError(str(exc)) from exc


def parse_live_fire_contract(
    raw_json: str,
    *,
    job_id: str,
    job_timeout_s: int,
) -> tuple[dict[str, Any], PatchLoopSpec]:
    """Validate JSON and return its stable snapshot plus typed loop spec."""

    try:
        raw = json.loads(raw_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise LiveFireContractError(f"verification must be valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise LiveFireContractError("verification must be a JSON object")
    unknown = sorted(set(raw) - _TOP_LEVEL_FIELDS)
    if unknown:
        raise LiveFireContractError(
            "verification has unknown fields: " + ", ".join(unknown)
        )

    probes_raw = raw.get("probes")
    if not isinstance(probes_raw, list) or not probes_raw:
        raise LiveFireContractError("verification.probes must be a non-empty array")
    probes = tuple(_probe(item, index) for index, item in enumerate(probes_raw))

    limits_raw = raw.get("limits") or {}
    if not isinstance(limits_raw, dict):
        raise LiveFireContractError("verification.limits must be an object")
    limit_unknown = sorted(set(limits_raw) - _LIMIT_FIELDS)
    if limit_unknown:
        raise LiveFireContractError(
            "verification.limits has unknown fields: " + ", ".join(limit_unknown)
        )
    try:
        limits = ContainerLimits(**limits_raw)
        verification = VerificationSpec(
            job_id=job_id,
            probes=probes,
            mitigation_class=raw.get("mitigation_class"),
            start_command=_argv(raw.get("start_command"), "start_command"),
            health_command=_argv(raw.get("health_command"), "health_command"),
            limits=limits,
        )
        spec = PatchLoopSpec(
            verification=verification,
            job_timeout_s=_positive_number(job_timeout_s, "job_timeout"),
            verification_reserve_s=_positive_number(
                raw.get("verification_reserve_s"), "verification_reserve_s"
            ),
            packaging_reserve_s=_positive_number(
                raw.get("packaging_reserve_s"), "packaging_reserve_s"
            ),
            max_attempts=_positive_integer(raw.get("max_attempts", 3), "max_attempts"),
        )
    except (TypeError, ValueError) as exc:
        if isinstance(exc, LiveFireContractError):
            raise
        raise LiveFireContractError(str(exc)) from exc

    # Round-trip through JSON so the worker snapshot contains no caller-owned
    # mappings and has exactly the representation accepted above.
    snapshot = json.loads(json.dumps(raw, sort_keys=True))
    snapshot.setdefault("limits", {})
    snapshot.setdefault("start_command", [])
    snapshot.setdefault("health_command", [])
    snapshot.setdefault("max_attempts", 3)
    return snapshot, spec


def patch_spec_from_snapshot(
    snapshot: dict[str, Any], *, job_id: str, job_timeout_s: int
) -> PatchLoopSpec:
    """Rebuild the immutable typed contract in the RQ worker."""

    _, spec = parse_live_fire_contract(
        json.dumps(snapshot), job_id=job_id, job_timeout_s=job_timeout_s
    )
    return spec


__all__ = [
    "LiveFireContractError",
    "parse_live_fire_contract",
    "patch_spec_from_snapshot",
]
