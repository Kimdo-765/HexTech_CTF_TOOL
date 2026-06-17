import shutil
import zipfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from api.queue import get_queue, hard_timeout_for, normalize_effort, resolve_timeout
from api.storage import job_dir, new_job_id, parse_targets, write_job_meta

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


_ARCHIVE_EXTS = (
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".7z", ".rar",
)


def _largest_non_archive(d: Path) -> Optional[Path]:
    """Largest regular file under `d` that is not itself an archive — the
    fallback challenge target when a zip carries NO ELF/PE (Java .class/.jar,
    Python .pyc, WASM, Android DEX, Lua bytecode, custom-VM blob, a script,
    …). Lets rev proceed on non-native artifacts instead of hard-rejecting."""
    candidates = [
        p for p in d.rglob("*")
        if p.is_file() and not p.name.lower().endswith(_ARCHIVE_EXTS)
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_size, reverse=True)
    return candidates[0]


@router.post("/analyze")
async def analyze_rev(
    file: Optional[UploadFile] = File(None),
    target: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    auto_run: bool = Form(False),
    job_timeout: Optional[int] = Form(None),
    model: Optional[str] = Form(None),
    effort: Optional[str] = Form(None),
    flag_format: Optional[str] = Form(None),
):
    # Optional remote target (host:port / URL) — a rev chal can hand you a
    # live service whose protocol/algorithm you reverse from the artifact and
    # then drive to capture the flag. File OR target must be present.
    targets = parse_targets(target)
    target = targets[0] if targets else None
    has_file = bool(file and file.filename)
    if not has_file and not target:
        raise HTTPException(
            status_code=400,
            detail="Provide a binary/artifact or a remote target (host:port).",
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

        # zip-preferred upload: unpack into bin/, then re-resolve binary_name
        # to the largest ELF/PE inside (or a fallback file) so the prompt's
        # `./bin/<name>` points at the real challenge instead of the archive.
        if binary_name.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(target_path, "r") as zf:
                    zf.extractall(bin_dir)
                target_path.unlink(missing_ok=True)
                # Prefer the largest ELF/PE; if the zip carries NONE (Java
                # .class/.jar, Python .pyc, WASM, DEX, Lua, custom-VM
                # bytecode, scripts …) fall back to the largest non-archive
                # file so rev still proceeds — no "must contain ELF/PE" gate.
                pick = _first_binary_in(bin_dir) or _largest_non_archive(bin_dir)
                if pick is not None:
                    # Flatten to bin/<name> so the ./bin/<name> path is valid
                    # (zips usually extract into a subfolder).
                    flat = bin_dir / pick.name
                    if pick.resolve() != flat.resolve():
                        shutil.move(str(pick), str(flat))
                    flat.chmod(0o755)
                    binary_name = flat.name
                else:
                    # Degenerate (empty zip / only nested archives) — proceed
                    # with no specific target; the agent explores ./bin/.
                    binary_name = None
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
        "target_url": target,
        "target_urls": targets if len(targets) >= 2 else None,
        "remote_only": not has_file,
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
