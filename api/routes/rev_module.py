import shutil
import zipfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from api.queue import get_queue, hard_timeout_for, normalize_effort, resolve_timeout
from api.storage import job_dir, new_job_id, parse_targets, prepare_job_description, write_job_meta, reject_job
from modules.agent_provider import enrich_job_meta

router = APIRouter()


def _first_binary_in(d: Path) -> Optional[Path]:
    """Delegate to the one picker every ingest path shares.

    This used to be a local implementation; the retry route and the hybrid
    worker each had their own. Adding a size-tie-break here made the scalar
    path disagree with hybrid on a real bundle, which is what a duplicated
    "policy" always eventually does. The canonical one lives in
    modules/_common.py because the worker container does not mount `api/`.
    """
    from modules._common import pick_challenge_binary
    return pick_challenge_binary(d)


def _largest_non_archive(d: Path) -> Optional[Path]:
    """Kept as a name for callers; the shared picker already falls back to the
    largest non-archive when a directory holds no ELF/PE."""
    from modules._common import pick_challenge_binary
    return pick_challenge_binary(d)


@router.post("/analyze")
async def analyze_rev(
    file: Optional[UploadFile] = File(None),
    target: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    challenge_secret_key: Optional[str] = Form(None),
    challenge_secret_value: Optional[str] = Form(None),
    auto_run: bool = Form(False),
    docker_challenge: bool = Form(False),
    job_timeout: Optional[int] = Form(None),
    model: Optional[str] = Form(None),
    effort: Optional[str] = Form(None),
    output_language: Optional[str] = Form(None),
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
            reject_job(job_id, 400, "empty file")
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
                reject_job(job_id, 400, "invalid zip upload")
    description = prepare_job_description(
        job_id, description, challenge_secret_key, challenge_secret_value
    )

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
        "docker_challenge": docker_challenge,
        "job_timeout": timeout,
        "model": chosen_model,
        "effort": chosen_effort,
        "flag_format": (flag_format or "").strip() or None,
    }
    enrich_job_meta(meta, output_language=output_language)
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
