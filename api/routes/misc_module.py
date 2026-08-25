from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from api.queue import get_queue, hard_timeout_for, normalize_effort, resolve_timeout
from api.storage import job_dir, new_job_id, parse_targets, prepare_job_description, write_job_meta, reject_job
from modules.agent_provider import enrich_job_meta

router = APIRouter()

CHUNK = 4 * 1024 * 1024


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


@router.post("/analyze")
async def analyze_misc(
    file: Optional[UploadFile] = File(None),
    target: Optional[str] = Form(None),
    passphrase: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    challenge_secret_key: Optional[str] = Form(None),
    challenge_secret_value: Optional[str] = Form(None),
    skip_claude: bool = Form(False),
    docker_challenge: bool = Form(False),
    job_timeout: Optional[int] = Form(None),
    model: Optional[str] = Form(None),
    effort: Optional[str] = Form(None),
    flag_format: Optional[str] = Form(None),
):
    # Optional remote target (host:port / URL). ADDITIVE for misc: the file (or
    # the description) is still the job's input, and a target alone is already a
    # legal misc job because the file was optional before this. It reaches the
    # agent as a prompt directive only — misc has no sandbox runner, so there is
    # no argv[1]/TARGETS plumbing behind it (see build_target_directive's
    # script_driven=False branch).
    targets = parse_targets(target)
    target = targets[0] if targets else None

    job_id = new_job_id()

    # File is OPTIONAL: with no file the misc tool sweep is skipped and the
    # job runs a description-only Claude analysis (the orchestrator guards on
    # a falsy filename). An uploaded-but-empty file is still rejected.
    has_file = bool(file and file.filename)
    fname = None
    size = 0
    if has_file:
        fname = Path(file.filename).name
        # NOT `target`: that name now holds the operator's remote target and
        # reusing it here would put a PosixPath into meta.target_url.
        dest = job_dir(job_id) / fname
        size = _stream_to(dest, file)
        if size == 0:
            reject_job(job_id, 400, "empty file")
    description = prepare_job_description(
        job_id, description, challenge_secret_key, challenge_secret_value
    )
    # Park the passphrase where a retry can find it. It is still passed to
    # enqueue below, so the first run is unchanged; this is what lets the
    # SECOND run exist at all. Before, the passphrase reached the orchestrator
    # only as an RQ argument and died with the job, which is why misc was the
    # one module with no retry.
    from modules.job_secrets import store_misc_passphrase
    store_misc_passphrase(job_id, passphrase)

    timeout = resolve_timeout(job_timeout)
    chosen_model = (model or "").strip() or None
    chosen_effort = normalize_effort(effort)
    meta = {
        "id": job_id,
        "module": "misc",
        "status": "queued",
        "filename": fname,
        "target_url": target,
        "target_urls": targets if len(targets) >= 2 else None,
        "description": description,
        "skip_claude": skip_claude,
        "docker_challenge": docker_challenge,
        "size_bytes": size,
        "job_timeout": timeout,
        "model": chosen_model,
        "effort": chosen_effort,
        "flag_format": (flag_format or "").strip() or None,
    }
    enrich_job_meta(meta)
    write_job_meta(job_id, meta)

    q = get_queue()
    q.enqueue(
        "modules.misc.orchestrator.run_job",
        job_id,
        fname,
        passphrase,
        description,
        skip_claude,
        chosen_model,
        job_id=job_id,
        job_timeout=hard_timeout_for(timeout),
    )

    return {"job_id": job_id, "status": "queued", "job_timeout": timeout, "model": chosen_model}
