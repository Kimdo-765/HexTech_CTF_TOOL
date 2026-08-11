"""HTTP ingest boundary for the bounded two-stage hybrid solver."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from api.queue import get_queue, hard_timeout_for, normalize_effort, resolve_timeout
from api.storage import JOBS_DIR, UPLOADS_DIR, new_job_id, parse_targets
from modules.agent_provider import enrich_job_meta
from modules.hybrid.coordinator import HybridCoordinator, HybridCoordinatorError


router = APIRouter()

_RECIPE_ALIASES = {
    "rev-pwn": "rev-pwn",
    "pwn-rev": "rev-pwn",
    "web-pwn": "web-pwn",
    "pwn-web": "web-pwn",
}


def _canonical_recipe(raw: Optional[str]) -> str:
    """Validate a two-stage recipe and return the server-owned order."""

    value = (raw or "").strip().lower()
    if not value:
        raise HTTPException(status_code=400, detail="hybrid recipe is required")
    value = value.replace("→", "-").replace("->", "-")
    for separator in (",", "+", "/", "|"):
        value = value.replace(separator, "-")
    value = "-".join(part.strip() for part in value.split("-") if part.strip())

    if "live-fire" in (raw or "").strip().lower() or "live-fire" in value:
        raise HTTPException(
            status_code=400,
            detail="live-fire is a separate patch workflow and cannot be a hybrid stage",
        )
    if value in _RECIPE_ALIASES:
        return _RECIPE_ALIASES[value]

    parts = value.split("-") if value else []
    if len(parts) != 2:
        raise HTTPException(
            status_code=400, detail="hybrid recipe must contain exactly two stages"
        )
    raise HTTPException(
        status_code=400,
        detail="unsupported hybrid recipe; allowed recipes are rev-pwn and web-pwn",
    )


def _stage_input(targets: list[str], *, target_field: str, docker: bool) -> dict:
    return {
        target_field: targets[0] if targets else None,
        f"{target_field}s": targets if len(targets) >= 2 else None,
        "docker_challenge": docker,
    }


def _safe_upload_name(raw: str) -> str:
    name = Path(raw).name
    if not name or name in {".", ".."} or name != raw or "\\" in raw:
        raise HTTPException(status_code=400, detail="invalid challenge bundle filename")
    return name


@router.post("/analyze")
async def analyze_hybrid(
    recipe: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    description: Optional[str] = Form(None),
    flag_format: Optional[str] = Form(None),
    model: Optional[str] = Form(None),
    effort: Optional[str] = Form(None),
    job_timeout: Optional[int] = Form(None),
    rev_target: Optional[str] = Form(None, alias="inputs.rev.target"),
    rev_docker: bool = Form(False, alias="inputs.rev.docker_challenge"),
    web_target_url: Optional[str] = Form(None, alias="inputs.web.target_url"),
    web_docker: bool = Form(False, alias="inputs.web.docker_challenge"),
    pwn_target: Optional[str] = Form(None, alias="inputs.pwn.target"),
    pwn_docker: bool = Form(False, alias="inputs.pwn.docker_challenge"),
):
    canonical = _canonical_recipe(recipe)
    modules = canonical.split("-")
    has_file = bool(file and file.filename)
    rev_targets = parse_targets(rev_target)
    web_targets = parse_targets(web_target_url)
    pwn_targets = parse_targets(pwn_target)

    first_module = modules[0]
    first_targets = rev_targets if first_module == "rev" else web_targets
    if not has_file and not first_targets:
        field = "inputs.rev.target" if first_module == "rev" else "inputs.web.target_url"
        raise HTTPException(
            status_code=400,
            detail=f"provide a challenge bundle or {field} for the first stage",
        )

    content: bytes | None = None
    filename: str | None = None
    if has_file:
        filename = _safe_upload_name(str(file.filename))
        content = await file.read()
        if not content:
            raise HTTPException(status_code=400, detail="empty challenge bundle")

    timeout = resolve_timeout(job_timeout)
    chosen_model = (model or "").strip() or None
    chosen_effort = normalize_effort(effort)
    inputs = {
        "pwn": _stage_input(pwn_targets, target_field="target", docker=pwn_docker),
    }
    if first_module == "rev":
        inputs["rev"] = _stage_input(
            rev_targets, target_field="target", docker=rev_docker
        )
    else:
        inputs["web"] = _stage_input(
            web_targets, target_field="target_url", docker=web_docker
        )
    inputs = {module: inputs[module] for module in modules}

    job_id = new_job_id()
    upload_dir = UPLOADS_DIR / job_id
    saved: Path | None = None
    if content is not None and filename is not None:
        upload_dir.mkdir(parents=True, exist_ok=False)
        saved = upload_dir / filename
        try:
            saved.write_bytes(content)
        except Exception:
            shutil.rmtree(upload_dir, ignore_errors=True)
            raise

    meta = {
        "filename": filename,
        "src_bundle": str(saved) if saved is not None else None,
        "description": (description or "").strip() or None,
        "flag_format": (flag_format or "").strip() or None,
        "model": chosen_model,
        "effort": chosen_effort,
        "job_timeout": timeout,
        "inputs": inputs,
    }
    try:
        enrich_job_meta(meta)
        parent = HybridCoordinator(JOBS_DIR).create_parent(job_id, canonical, meta=meta)
    except HybridCoordinatorError as exc:
        if saved is not None:
            shutil.rmtree(upload_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception:
        if saved is not None:
            shutil.rmtree(upload_dir, ignore_errors=True)
        raise

    queue = get_queue()
    queue.enqueue(
        "modules.hybrid.worker.run_job",
        job_id,
        job_id=job_id,
        job_timeout=hard_timeout_for(timeout),
    )

    return {
        "job_id": job_id,
        "status": parent["status"],
        "recipe": parent["hybrid"]["recipe"],
        "modules": parent["modules"],
        "job_timeout": timeout,
        "model": chosen_model,
    }


__all__ = ["analyze_hybrid", "router"]
