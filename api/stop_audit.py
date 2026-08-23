"""Durable, non-secret operator-stop audit records."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


_MAX_STOP_AUDIT_RECORDS = 16


def append_operator_stop_audit(
    meta: dict[str, Any],
    *,
    action: str,
    previous_status: str | None,
    halt: dict[str, Any] | None,
    termination_acknowledged: bool | None,
    acknowledgement_wait_ms: int | None = None,
) -> dict[str, Any]:
    """Return ``meta`` with one bounded, non-empty stop audit record.

    Raw exception strings and request text are intentionally excluded.  This
    record says what lifecycle action occurred without becoming a second log
    or a credential-bearing description channel.
    """

    halt = halt if isinstance(halt, dict) else {}
    failed = halt.get("containers_failed")
    record: dict[str, Any] = {
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "action": str(action or "operator_stop"),
        "previous_status": str(previous_status or "unknown"),
        "sent_stop": bool(halt.get("sent_stop")),
        "rq_cancelled": bool(halt.get("rq_cancelled")),
        "containers_found": int(halt.get("containers_found") or 0),
        "containers_killed": int(halt.get("containers_killed") or 0),
        "containers_failed_count": len(failed) if isinstance(failed, list) else 0,
        "docker_error": bool(halt.get("docker_error")),
        "termination_acknowledged": termination_acknowledged,
    }
    if acknowledgement_wait_ms is not None:
        record["acknowledgement_wait_ms"] = max(0, int(acknowledgement_wait_ms))

    existing = meta.get("operator_stop_audit")
    records = list(existing) if isinstance(existing, list) else []
    records.append(record)
    return {**meta, "operator_stop_audit": records[-_MAX_STOP_AUDIT_RECORDS:]}
