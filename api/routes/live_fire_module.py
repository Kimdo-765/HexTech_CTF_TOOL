"""HTTP submission boundary for the isolated live-fire patch pipeline."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from api.queue import get_queue, hard_timeout_for, normalize_effort, resolve_timeout
from api.storage import new_job_id, save_upload, write_job_meta
from modules.agent_provider import enrich_job_meta
from modules.live_fire_contract import LiveFireContractError, parse_live_fire_contract


router = APIRouter()


@router.post("/analyze")
async def analyze_live_fire(
    file: UploadFile = File(...),
    verification: str = Form(...),
    description: Optional[str] = Form(None),
    job_timeout: Optional[int] = Form(None),
    model: Optional[str] = Form(None),
    effort: Optional[str] = Form(None),
):
    filename = Path(file.filename or "").name
    if not filename or Path(filename).suffix.lower() != ".zip":
        raise HTTPException(status_code=400, detail="live-fire accepts one ZIP file")
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="empty ZIP file")
    if not zipfile.is_zipfile(io.BytesIO(content)):
        raise HTTPException(status_code=400, detail="invalid ZIP file")

    job_id = new_job_id()
    timeout = resolve_timeout(job_timeout)
    try:
        contract, _ = parse_live_fire_contract(
            verification,
            job_id=job_id,
            job_timeout_s=timeout,
        )
    except LiveFireContractError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    saved = save_upload(job_id, "input.zip", content)
    chosen_model = (model or "").strip() or None
    chosen_effort = normalize_effort(effort)
    meta = {
        "id": job_id,
        "module": "live-fire",
        "status": "queued",
        "stage": "queued",
        "filename": filename,
        "description": (description or "").strip() or None,
        "job_timeout": timeout,
        "model": chosen_model,
        "effort": chosen_effort,
        "src_archive": str(saved),
        "live_fire_contract": contract,
        "ready_to_deploy": None,
        "evidence_tiers": [],
    }
    enrich_job_meta(meta)
    write_job_meta(job_id, meta)

    get_queue().enqueue(
        "modules.live_fire_job.run_job",
        job_id,
        str(saved),
        job_id=job_id,
        job_timeout=hard_timeout_for(timeout),
    )
    return {
        "job_id": job_id,
        "status": "queued",
        "job_timeout": timeout,
        "model": chosen_model,
    }


__all__ = ["analyze_live_fire", "router"]
