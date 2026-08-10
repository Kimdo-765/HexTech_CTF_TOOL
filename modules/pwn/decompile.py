"""Run the ghiant/Ghidra decompiler against a binary by spawning a sibling
container. The worker has docker.sock mounted, so volumes must reference
HOST paths (HOST_DATA_DIR), not the worker's internal mount points."""

import json
import os
import zipfile
from pathlib import Path

import docker

DECOMPILER_IMAGE = "hextech_ctf_tool-decompiler"
DECOMPILER_TIMEOUT_S = 900  # 15 min — Ghidra auto-analysis can be slow
DECOMPILER_XREFS_TIMEOUT_S = 300  # 5 min — xrefs reuses cached project
DECOMPILER_MEM = "4g"


def host_path_for(job_id: str) -> str:
    host_root = os.environ.get("HOST_DATA_DIR")
    if not host_root:
        raise RuntimeError(
            "HOST_DATA_DIR not set on worker — required to bind-mount into sibling containers"
        )
    return f"{host_root.rstrip('/')}/jobs/{job_id}"


def run_decompiler(job_id: str, binary_rel: str) -> tuple[Path, str]:
    """Decompile <jobdir>/<binary_rel> into <jobdir>/decomp/.
    Returns (decomp_dir, container_logs).
    """
    job_dir = Path(f"/data/jobs/{job_id}")
    decomp_zip = job_dir / "decomp.zip"
    decomp_dir = job_dir / "decomp"

    # Wipe any prior run
    if decomp_zip.exists():
        decomp_zip.unlink()
    if decomp_dir.exists():
        for p in decomp_dir.glob("*"):
            p.unlink()

    client = docker.from_env()
    host_job = host_path_for(job_id)

    container = client.containers.run(
        image=DECOMPILER_IMAGE,
        command=[f"/job/{binary_rel}", "-o", "/job/decomp.zip"],
        volumes={host_job: {"bind": "/job", "mode": "rw"}},
        mem_limit=DECOMPILER_MEM,
        network_mode="none",
        detach=True,
        labels={"hextech_ctf_tool_job_id": job_id, "hextech_ctf_tool_role": "decompiler"},
    )
    try:
        result = container.wait(timeout=DECOMPILER_TIMEOUT_S)
        logs = container.logs().decode("utf-8", errors="replace")
        if result.get("StatusCode", 1) != 0:
            raise RuntimeError(
                f"decompiler exited with code {result.get('StatusCode')}\n--- logs ---\n{logs[-4000:]}"
            )
    finally:
        try:
            container.remove(force=True, v=True)
        except Exception:
            pass

    if not decomp_zip.exists():
        raise RuntimeError(f"decompiler produced no decomp.zip\n--- logs ---\n{logs[-4000:]}")

    decomp_dir.mkdir(exist_ok=True)
    with zipfile.ZipFile(decomp_zip, "r") as zf:
        zf.extractall(decomp_dir)

    return decomp_dir, logs


def run_decompiler_xrefs(
    job_id: str, binary_rel: str, target: str, *, limit: int = 50,
) -> tuple[dict, str]:
    """Query Ghidra for cross-references to `target` (symbol name or hex
    address) inside <jobdir>/<binary_rel>. Spawns the decompiler image
    in xrefs mode, which auto-bootstraps a full analysis if no cached
    project exists yet, then reuses it on subsequent calls. Output JSON
    lands at <jobdir>/.ghidra_proj/xrefs.json (overwritten each call).

    Returns (parsed_json, container_logs).
    """
    job_dir = Path(f"/data/jobs/{job_id}")
    proj_dir = job_dir / ".ghidra_proj"
    proj_dir.mkdir(exist_ok=True)
    out_rel = ".ghidra_proj/xrefs.json"
    out_abs = job_dir / out_rel
    if out_abs.exists():
        out_abs.unlink()

    client = docker.from_env()
    host_job = host_path_for(job_id)

    container = client.containers.run(
        image=DECOMPILER_IMAGE,
        # The decompiler container's ENTRYPOINT is
        #   python3 /opt/ghiant/ghidra_decompile.py /opt/ghidra
        # so this command list is the tail of argv.
        command=[
            "xrefs",
            f"/job/{binary_rel}", target,
            "-o", f"/job/{out_rel}",
            "--limit", str(limit),
        ],
        volumes={host_job: {"bind": "/job", "mode": "rw"}},
        mem_limit=DECOMPILER_MEM,
        network_mode="none",
        detach=True,
        labels={"hextech_ctf_tool_job_id": job_id, "hextech_ctf_tool_role": "decompiler"},
    )
    try:
        result = container.wait(timeout=DECOMPILER_TIMEOUT_S)
        logs = container.logs().decode("utf-8", errors="replace")
        if result.get("StatusCode", 1) != 0:
            raise RuntimeError(
                f"xrefs decompiler exited with code {result.get('StatusCode')}\n--- logs ---\n{logs[-4000:]}"
            )
    finally:
        try:
            container.remove(force=True, v=True)
        except Exception:
            pass

    if not out_abs.exists():
        raise RuntimeError(
            f"xrefs query produced no output file at {out_abs}\n--- logs ---\n{logs[-4000:]}"
        )
    try:
        payload = json.loads(out_abs.read_text())
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"xrefs output not parseable as JSON ({e})\n--- file ---\n"
            f"{out_abs.read_text()[:1000]}"
        )
    return payload, logs
