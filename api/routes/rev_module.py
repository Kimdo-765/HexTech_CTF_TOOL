import shutil
import zipfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from api.queue import get_queue, hard_timeout_for, normalize_effort, resolve_timeout
from api.storage import job_dir, new_job_id, write_job_meta

router = APIRouter()


def _first_binary_in(d: Path) -> Optional[Path]:
    """Find the first ELF / PE inside `d` (recursive). Prefers the
    largest match so a small auxiliary binary doesn't beat the real
    challenge. Used after unpacking a zip upload."""
    candidates: list[Path] = []
    for p in d.rglob("*"):
        if not p.is_file():
            continue
        try:
            magic = p.read_bytes()[:4]
        except OSError:
            continue
        if magic.startswith(b"\x7fELF") or magic[:2] == b"MZ":
            candidates.append(p)
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_size, reverse=True)
    return candidates[0]


@router.post("/analyze")
async def analyze_rev(
    file: UploadFile = File(...),
    description: Optional[str] = Form(None),
    auto_run: bool = Form(False),
    job_timeout: Optional[int] = Form(None),
    model: Optional[str] = Form(None),
    effort: Optional[str] = Form(None),
    flag_format: Optional[str] = Form(None),
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="file required")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="empty file")

    job_id = new_job_id()
    bin_dir = job_dir(job_id) / "bin"
    bin_dir.mkdir(exist_ok=True)

    binary_name = Path(file.filename).name
    target_path = bin_dir / binary_name
    target_path.write_bytes(content)
    target_path.chmod(0o755)

    # zip-preferred upload: unpack into bin/, then re-resolve binary_name
    # to the largest ELF/PE inside so the user prompt's `./bin/<name>`
    # points at the real challenge instead of the archive.
    if binary_name.lower().endswith(".zip"):
        try:
            with zipfile.ZipFile(target_path, "r") as zf:
                zf.extractall(bin_dir)
            target_path.unlink(missing_ok=True)
            elf = _first_binary_in(bin_dir)
            if elf is not None:
                # Move it up to bin/<elf.name> so the prompt path is flat.
                flat = bin_dir / elf.name
                if elf.resolve() != flat.resolve():
                    shutil.move(str(elf), str(flat))
                flat.chmod(0o755)
                binary_name = flat.name
            else:
                raise HTTPException(
                    status_code=400,
                    detail="zip contained no ELF / PE binary",
                )
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="invalid zip upload")

    timeout = resolve_timeout(job_timeout)
    chosen_model = (model or "").strip() or None
    chosen_effort = normalize_effort(effort)
    meta = {
        "id": job_id,
        "module": "rev",
        "status": "queued",
        "filename": binary_name,
        "description": description,
        "auto_run": auto_run,
        "job_timeout": timeout,
        "model": chosen_model,
        "effort": chosen_effort,
        "flag_format": (flag_format or "").strip() or None,
    }
    write_job_meta(job_id, meta)

    q = get_queue()
    q.enqueue(
        "modules.rev.analyzer.run_job",
        job_id,
        binary_name,
        description,
        auto_run,
        chosen_model,
        job_id=job_id,
        job_timeout=hard_timeout_for(timeout),
    )

    return {"job_id": job_id, "status": "queued", "job_timeout": timeout, "model": chosen_model}
