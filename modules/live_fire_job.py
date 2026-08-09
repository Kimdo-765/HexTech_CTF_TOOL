"""RQ worker entry point for live-fire jobs.

LF-5 connects the API lifecycle and artifact boundary.  The provider transport
remains injectable: until LF-6 supplies a live transport, the default invoker
runs the complete machine pipeline fail-closed and emits diagnostic
``UNVERIFIED`` artifacts instead of inventing a successful patch.
"""

from __future__ import annotations

import json
import traceback
from pathlib import Path
from typing import Any

from modules._common import job_dir, log_line, read_meta, write_meta
from modules.live_fire_contract import patch_spec_from_snapshot
from modules.live_fire_patch_loop import ProviderResult, ReviewResult
from modules.live_fire_provider import (
    AgentInvocationResult,
    AgentUsage,
    run_routed_patch_loop,
)
from modules.live_fire_workspace import create_workspace


class DiagnosticInvoker:
    """Fail-closed placeholder used until a real provider transport is injected."""

    def invoke(self, call):
        if call.route.role == "main":
            value = ProviderResult(
                "failure",
                "live-fire provider transport is not configured; diagnostic run only",
            )
        elif call.route.role == "reviewer":
            value = ReviewResult(
                "provider transport unavailable; retain machine evidence and UNVERIFIED status"
            )
        else:
            # An invalid report is intentional: LF-3 replaces it with its
            # deterministic complete report and keeps report_gate/READY false.
            value = "provider transport unavailable"
        return AgentInvocationResult(
            value=value,
            usage=AgentUsage(
                model=call.route.model,
                error_kind="transport_unavailable",
            ),
        )


def _evidence_tiers(document: dict[str, Any]) -> list[str]:
    tiers = document.get("security_gate", {}).get("evidence_tiers", [])
    if not isinstance(tiers, list):
        return []
    return sorted({tier for tier in tiers if tier in {"A", "B"}})


def run_job(
    job_id: str,
    archive_path: str,
    *,
    invoker=None,
    runtime_factory=None,
    clock=None,
) -> dict[str, Any]:
    """Run ingest → routed patch loop → three root-level artifacts."""

    meta = read_meta(job_id)
    timeout = int(meta.get("job_timeout") or 0)
    contract = meta.get("live_fire_contract")
    if not isinstance(contract, dict):
        raise ValueError("live-fire job is missing its verification contract snapshot")

    root = job_dir(job_id)
    write_meta(job_id, status="running", stage="safe-ingest")
    try:
        spec = patch_spec_from_snapshot(
            contract,
            job_id=job_id,
            job_timeout_s=timeout,
        )
        workspace = create_workspace(Path(archive_path), root / "live-fire-workspace")
        write_meta(job_id, stage="patch-and-verify")
        result = run_routed_patch_loop(
            job_id,
            workspace,
            root,
            spec,
            invoker or DiagnosticInvoker(),
            requested_models={"main": meta.get("model")},
            runtime_factory=runtime_factory,
            clock=clock,
        )
        document = result.verification
        tiers = _evidence_tiers(document)
        payload = {
            "ready_to_deploy": document.get("ready_to_deploy") is True,
            "evidence_tiers": tiers,
            "verification": document,
            "artifacts": {
                "patched_zip": result.artifacts.patched_zip.name,
                "report": result.artifacts.report.name,
                "verification": result.artifacts.verification.name,
            },
        }
        (root / "result.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        write_meta(
            job_id,
            status="finished",
            stage="done",
            ready_to_deploy=payload["ready_to_deploy"],
            evidence_tiers=tiers,
            live_fire_artifacts=payload["artifacts"],
        )
        return payload
    except Exception as exc:
        log_line(job_id, f"LIVE_FIRE_ERROR: {exc}\n{traceback.format_exc()}")
        write_meta(job_id, status="failed", stage="failed", error=str(exc))
        raise


__all__ = ["DiagnosticInvoker", "run_job"]
