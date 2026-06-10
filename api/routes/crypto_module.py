from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from api.queue import get_queue, hard_timeout_for, normalize_effort, resolve_timeout
from api.storage import (
    extract_if_archive,
    new_job_id,
    parse_targets,
    save_upload,
    write_job_meta,
)

router = APIRouter()


@router.post("/analyze")
async def analyze_crypto(
    file: Optional[UploadFile] = File(None),
    target: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    auto_run: bool = Form(False),
    use_sage: bool = Form(False),
    job_timeout: Optional[int] = Form(None),
    model: Optional[str] = Form(None),
    effort: Optional[str] = Form(None),
    flag_format: Optional[str] = Form(None),
):
    targets = parse_targets(target)
    target = targets[0] if targets else None
    has_file = bool(file and file.filename)
    if not has_file and not target:
        raise HTTPException(
            status_code=400,
            detail="Provide either a challenge file/zip or a remote target (host:port).",
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
        "module": "crypto",
        "status": "queued",
        "filename": file.filename if has_file else None,
        "target_url": target,
        "target_urls": targets if len(targets) >= 2 else None,
        "description": description,
        "auto_run": auto_run,
        "use_sage": use_sage,
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
        "modules.crypto.analyzer.run_job",
        job_id,
        src_root,
        target,
        description,
        auto_run,
        use_sage,
        chosen_model,
        job_id=job_id,
        job_timeout=hard_timeout_for(timeout),
    )

    return {"job_id": job_id, "status": "queued", "job_timeout": timeout, "model": chosen_model}
