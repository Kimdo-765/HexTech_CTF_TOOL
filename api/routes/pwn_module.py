from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from api.queue import get_queue, hard_timeout_for, normalize_effort, resolve_timeout
from api.storage import job_dir, new_job_id, write_job_meta

router = APIRouter()


@router.post("/analyze")
async def analyze_pwn(
    file: Optional[UploadFile] = File(None),
    target: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    auto_run: bool = Form(False),
    job_timeout: Optional[int] = Form(None),
    model: Optional[str] = Form(None),
    effort: Optional[str] = Form(None),
    flag_format: Optional[str] = Form(None),
):
    target = (target or "").strip() or None
    has_file = bool(file and file.filename)
    if not has_file and not target:
        raise HTTPException(
            status_code=400,
            detail="Provide either a binary or a remote target (host:port).",
        )

    job_id = new_job_id()
    bin_dir = job_dir(job_id) / "bin"
    bin_dir.mkdir(exist_ok=True)

    binary_name = None
    if has_file:
        content = await file.read()
        if not content:
            raise HTTPException(status_code=400, detail="empty file")
        binary_name = Path(file.filename).name
        target_path = bin_dir / binary_name
        target_path.write_bytes(content)
        target_path.chmod(0o755)

    timeout = resolve_timeout(job_timeout)
    chosen_model = (model or "").strip() or None
    chosen_effort = normalize_effort(effort)
    meta = {
        "id": job_id,
        "module": "pwn",
        "status": "queued",
        "filename": binary_name,
        "target_url": target,
        "description": description,
        "auto_run": auto_run,
        "job_timeout": timeout,
        "model": chosen_model,
        "effort": chosen_effort,
        "flag_format": (flag_format or "").strip() or None,
        "remote_only": not has_file,
    }
    write_job_meta(job_id, meta)

    q = get_queue()
    q.enqueue(
        "modules.pwn.analyzer.run_job",
        job_id,
        binary_name,
        target,
        description,
        auto_run,
        chosen_model,
        job_id=job_id,
        job_timeout=hard_timeout_for(timeout),
    )

    return {"job_id": job_id, "status": "queued", "job_timeout": timeout, "model": chosen_model}
