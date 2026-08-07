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
from modules.agent_provider import enrich_job_meta

router = APIRouter()


@router.post("/analyze")
async def analyze_web3(
    file: Optional[UploadFile] = File(None),
    target: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    auto_run: bool = Form(False),
    docker_challenge: bool = Form(False),
    job_timeout: Optional[int] = Form(None),
    model: Optional[str] = Form(None),
    effort: Optional[str] = Form(None),
    flag_format: Optional[str] = Form(None),
):
    """Submit a Web3 / smart-contract challenge.

    `target` is the remote instance when the challenge is hosted — an RPC URL,
    or the `host:port` of the handout service. It is optional on purpose: a
    great many Web3 challenges ship only Solidity sources and are solved
    entirely on a local anvil chain, and requiring a target would block those.
    The RPC URL, private key and Setup address a hosted challenge hands out
    belong in `description`, where the prompt tells the agent to look for them.
    """
    targets = parse_targets(target)
    target = targets[0] if targets else None
    has_file = bool(file and file.filename)
    if not has_file and not target:
        raise HTTPException(
            status_code=400,
            detail=(
                "Provide either the contract sources (file/zip) or a remote "
                "instance. With neither there is nothing to analyse — a Web3 "
                "challenge is its Solidity, and without it the agent can only "
                "read bytecode off a chain it has no address for."
            ),
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
        "module": "web3",
        "status": "queued",
        "filename": file.filename if has_file else None,
        "target_url": target,
        "target_urls": targets if len(targets) >= 2 else None,
        "description": description,
        "auto_run": auto_run,
        "docker_challenge": docker_challenge,
        "job_timeout": timeout,
        "model": chosen_model,
        "effort": chosen_effort,
        "flag_format": (flag_format or "").strip() or None,
        "src_root": src_root,
        "remote_only": not has_file,
    }
    enrich_job_meta(meta)
    write_job_meta(job_id, meta)

    q = get_queue()
    q.enqueue(
        "modules.web3.analyzer.run_job",
        job_id,
        src_root,
        target,
        description,
        auto_run,
        chosen_model,
        job_id=job_id,
        job_timeout=hard_timeout_for(timeout),
    )

    return {"job_id": job_id, "status": "queued", "job_timeout": timeout, "model": chosen_model}
