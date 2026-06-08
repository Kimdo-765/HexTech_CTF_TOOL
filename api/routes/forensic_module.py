from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from api.queue import get_queue, hard_timeout_for, normalize_effort, resolve_timeout
from api.storage import job_dir, new_job_id, write_job_meta

router = APIRouter()

CHUNK = 4 * 1024 * 1024  # 4 MiB


def _stream_to(path: Path, upload: UploadFile) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with path.open("wb") as out:
        while True:
            chunk = upload.file.read(CHUNK)
            if not chunk:
                break
            out.write(chunk)
            total += len(chunk)
    return total


@router.post("/collect")
async def collect_forensic(
    file: UploadFile = File(...),
    image_type: str = Form("auto"),  # auto/raw/qcow2/vmdk/memory
    target_os: str = Form("auto"),  # auto/linux/windows
    description: Optional[str] = Form(None),
    bulk_extractor: bool = Form(False),
    skip_claude: bool = Form(False),
    job_timeout: Optional[int] = Form(None),
    model: Optional[str] = Form(None),
    effort: Optional[str] = Form(None),
    flag_format: Optional[str] = Form(None),
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="file required")

    job_id = new_job_id()
    image_name = Path(file.filename).name
    target = job_dir(job_id) / image_name
    size = _stream_to(target, file)
    if size == 0:
        raise HTTPException(status_code=400, detail="empty file")

    timeout = resolve_timeout(job_timeout)
    chosen_model = (model or "").strip() or None
    chosen_effort = normalize_effort(effort)
    meta = {
        "id": job_id,
        "module": "forensic",
        "status": "queued",
        "filename": image_name,
        "image_type": image_type,
        "target_os": target_os,
        "description": description,
        "bulk_extractor": bulk_extractor,
        "skip_claude": skip_claude,
        "size_bytes": size,
        "job_timeout": timeout,
        "model": chosen_model,
        "effort": chosen_effort,
        "flag_format": (flag_format or "").strip() or None,
    }
    write_job_meta(job_id, meta)

    q = get_queue()
    q.enqueue(
        "modules.forensic.orchestrator.run_job",
        job_id,
        image_name,
        image_type,
        target_os,
        description,
        bulk_extractor,
        skip_claude,
        chosen_model,
        job_id=job_id,
        job_timeout=hard_timeout_for(timeout),
    )

    return {"job_id": job_id, "status": "queued", "size_bytes": size, "job_timeout": timeout, "model": chosen_model}
