import asyncio
import json
import os
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import anyio
import docker
from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    TextBlock,
    ThinkingBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
    query,
)

from modules._common import (
    capture_session_id,
    agent_heartbeat,
    extract_cost,
    format_tool_result,
    log_thinking,
    read_meta,
    resolve_effort,
    scan_job_for_flags,
    soft_timeout_watchdog,
    write_meta,
)
from modules.forensic.prompts import SYSTEM_PROMPT, build_user_prompt
from modules.settings_io import apply_to_env, get_setting, has_claude_auth

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
JOBS_DIR = DATA_DIR / "jobs"

FORENSIC_IMAGE = "hextech_ctf_tool-forensic"
FORENSIC_TIMEOUT_S = 1800  # 30 min — vol3 + tsk on big images can be slow
FORENSIC_MEM = "6g"


def _job_dir(job_id: str) -> Path:
    p = JOBS_DIR / job_id
    p.mkdir(parents=True, exist_ok=True)
    return p


def _log(job_id: str, line: str) -> None:
    f = _job_dir(job_id) / "run.log"
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    with f.open("a") as fp:
        fp.write(f"[{ts}] {line}\n")


_TERMINAL_STATUSES = {"finished", "failed", "no_flag", "stopped"}


def _write_meta(job_id: str, **updates) -> None:
    f = _job_dir(job_id) / "meta.json"
    meta = {}
    if f.exists():
        meta = json.loads(f.read_text())
    now_iso = datetime.now(timezone.utc).isoformat()
    new_status = updates.get("status")
    if new_status == "running" and not meta.get("started_at"):
        updates.setdefault("started_at", now_iso)
    if new_status in _TERMINAL_STATUSES and not meta.get("finished_at"):
        updates.setdefault("finished_at", now_iso)
    meta.update(updates)
    meta["updated_at"] = now_iso
    f.write_text(json.dumps(meta, indent=2))


def _host_path(job_id: str) -> str:
    host_root = os.environ.get("HOST_DATA_DIR")
    if not host_root:
        raise RuntimeError("HOST_DATA_DIR not set on worker")
    return f"{host_root.rstrip('/')}/jobs/{job_id}"


def _spawn_collector(
    job_id: str,
    image_rel: str,
    image_type: str,
    target_os: str,
    bulk_extractor: bool,
) -> str:
    client = docker.from_env()
    cmd = [f"/job/{image_rel}", "--type", image_type, "--os", target_os, "--out", "/job"]
    if bulk_extractor:
        cmd.append("--bulk-extractor")

    container = client.containers.run(
        image=FORENSIC_IMAGE,
        command=cmd,
        volumes={_host_path(job_id): {"bind": "/job", "mode": "rw"}},
        mem_limit=FORENSIC_MEM,
        # network=bridge by default — needed so volatility3 can fetch PDB
        # symbols from microsoft for unknown windows builds.
        detach=True,
        labels={"hextech_ctf_tool_job_id": job_id, "hextech_ctf_tool_role": "forensic"},
    )
    try:
        result = container.wait(timeout=FORENSIC_TIMEOUT_S)
        logs = container.logs().decode("utf-8", errors="replace")
        sc = result.get("StatusCode", 1)
        if sc != 0:
            raise RuntimeError(f"forensic collector exited with code {sc}\n{logs[-4000:]}")
    finally:
        try:
            container.remove(force=True)
        except Exception:
            pass
    return logs


async def _claude_summary(
    job_id: str,
    target_os: str,
    kind: str,
    description: Optional[str],
    model_override: Optional[str] = None,
) -> dict:
    work_dir = _job_dir(job_id)
    model = model_override or str(get_setting("claude_model") or "claude-opus-4-7")
    # Per-job scratch dir (see modules/_common.py make_main_session_options
    # for rationale). Cleanup is implicit via job DELETE rmtree.
    tmp_dir = Path(work_dir) / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    _tmp_str = str(tmp_dir)
    options = ClaudeAgentOptions(
        system_prompt=SYSTEM_PROMPT,
        model=model,
        cwd=str(work_dir),
        allowed_tools=["Read", "Bash", "Glob", "Grep", "Write"],
        permission_mode="bypassPermissions",
        env={
            "JOB_ID": job_id,
            "TMPDIR": _tmp_str,
            "TMP":    _tmp_str,
            "TEMP":   _tmp_str,
        },
        effort=resolve_effort(read_meta(job_id).get("effort")),
    )
    prompt = build_user_prompt(target_os, kind, description)
    from modules._common import build_exploit_library_hint
    _lib_hint = build_exploit_library_hint("forensic")
    if _lib_hint:
        prompt = _lib_hint + "\n\n" + prompt
    _log(job_id, f"Launching Claude summary agent (model={model})")
    summary: dict = {"messages": 0, "tool_calls": 0}

    soft_timeout = int(read_meta(job_id).get("job_timeout") or 0)
    watchdog = asyncio.create_task(soft_timeout_watchdog(job_id, soft_timeout))

    try:
        async for msg in query(prompt=prompt, options=options):
            capture_session_id(msg, job_id)
            agent_heartbeat(job_id, msg)
            if isinstance(msg, AssistantMessage):
                summary["messages"] += 1
                for block in msg.content:
                    if isinstance(block, TextBlock):
                        _log(job_id, f"AGENT: {block.text[:500]}")
                    elif isinstance(block, ToolUseBlock):
                        summary["tool_calls"] += 1
                        args_preview = json.dumps(block.input)[:200]
                        _log(job_id, f"TOOL {block.name}: {args_preview}")
                    elif isinstance(block, ThinkingBlock):
                        log_thinking(
                            lambda s: _log(job_id, s),
                            "THINK", block.thinking,
                        )
            elif isinstance(msg, UserMessage):
                content = msg.content if isinstance(msg.content, list) else []
                for block in content:
                    if isinstance(block, ToolResultBlock):
                        _log(
                            job_id,
                            format_tool_result(block.content, block.is_error),
                        )
            elif isinstance(msg, ResultMessage):
                summary["result"] = {
                    "duration_ms": msg.duration_ms,
                    "num_turns": msg.num_turns,
                    "total_cost_usd": msg.total_cost_usd,
                    "is_error": msg.is_error,
                }
    finally:
        watchdog.cancel()
        if read_meta(job_id).get("awaiting_decision"):
            write_meta(job_id, awaiting_decision=False)
    return summary


def run_job(
    job_id: str,
    image_rel: str,
    image_type: str,
    target_os: str,
    description: Optional[str],
    bulk_extractor: bool,
    skip_claude: bool = False,
    model_override: Optional[str] = None,
) -> dict:
    """RQ entrypoint."""
    apply_to_env()
    _write_meta(job_id, status="running", stage="collect")
    try:
        _log(job_id, f"Spawning forensic collector (image={image_rel}, type={image_type}, os={target_os}, BE={bulk_extractor})")
        logs = _spawn_collector(job_id, image_rel, image_type, target_os, bulk_extractor)
        (_job_dir(job_id) / "collector.log").write_text(logs)

        summary_path = _job_dir(job_id) / "summary.json"
        collected_summary = json.loads(summary_path.read_text()) if summary_path.exists() else {}

        result: dict = {"collected": collected_summary}
        kind = collected_summary.get("kind", image_type)

        if skip_claude or not has_claude_auth():
            _log(job_id, "Skipping Claude summary (no API key, no OAuth, or skip flag).")
            result["claude"] = None
        else:
            _write_meta(job_id, stage="summarize")
            claude_result = anyio.run(
                _claude_summary, job_id, target_os, kind, description,
                model_override,
            )
            result["claude"] = claude_result

        cost = extract_cost(result.get("claude"))
        result["cost_usd"] = cost
        flags = scan_job_for_flags(job_id)
        result["flags"] = flags

        # Surface log-miner stats so the UI can render counts without
        # re-reading log_findings.json.
        log_findings_path = _job_dir(job_id) / "log_findings.json"
        log_findings_counts = None
        if log_findings_path.exists():
            try:
                lf = json.loads(log_findings_path.read_text())
                log_findings_counts = lf.get("counts") or {
                    k: len(v) for k, v in lf.items() if isinstance(v, list)
                }
                result["log_findings_counts"] = log_findings_counts
            except Exception:
                pass

        (_job_dir(job_id) / "result.json").write_text(json.dumps(result, indent=2, default=str))
        _write_meta(
            job_id, status="finished", stage="done", cost_usd=cost,
            flags=flags,
            log_findings_counts=log_findings_counts,
            result={"kind": kind, "had_claude": bool(result.get("claude"))},
        )
        return result
    except Exception as e:
        _log(job_id, f"ERROR: {e}\n{traceback.format_exc()}")
        _write_meta(job_id, status="failed", error=str(e))
        raise
