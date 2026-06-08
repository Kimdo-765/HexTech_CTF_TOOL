from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from api.queue import get_queue, hard_timeout_for, normalize_effort, resolve_timeout
from api.storage import (
    extract_if_archive,
    new_job_id,
    save_upload,
    write_job_meta,
)

router = APIRouter()


@router.post("/analyze")
async def analyze_web(
    file: Optional[UploadFile] = File(None),
    target_url: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    auto_run: bool = Form(False),
    job_timeout: Optional[int] = Form(None),
    model: Optional[str] = Form(None),
    effort: Optional[str] = Form(None),
    flag_format: Optional[str] = Form(None),
):
    target_url = (target_url or "").strip() or None
    has_file = bool(file and file.filename)
    if not has_file and not target_url:
        raise HTTPException(
            status_code=400,
            detail="Provide either a source file/zip or a target URL (or both).",
        )

    job_id = new_job_id()
    src_root = None
    if has_file:
        content = await file.read()
        if not content:
            raise HTTPException(status_code=400, detail="empty file")
        saved = save_upload(job_id, file.filename, content)
        src_root = str(extract_if_archive(saved))

    timeout = resolve_timeout(job_timeout)
    chosen_model = (model or "").strip() or None
    chosen_effort = normalize_effort(effort)
    meta = {
        "id": job_id,
        "module": "web",
        "status": "queued",
        "filename": file.filename if has_file else None,
        "target_url": target_url,
        "description": description,
        "auto_run": auto_run,
        "job_timeout": timeout,
        "model": chosen_model,
        "effort": chosen_effort,
        "flag_format": (flag_format or "").strip() or None,
        "src_root": src_root,
        "remote_only": not has_file,
    }
    write_job_meta(job_id, meta)

    q = get_queue()
    q.enqueue(
        "modules.web.analyzer.run_job",
        job_id,
        src_root,
        target_url,
        description,
        auto_run,
        chosen_model,
        job_id=job_id,
        job_timeout=hard_timeout_for(timeout),
    )

    return {"job_id": job_id, "status": "queued", "job_timeout": timeout, "model": chosen_model}
