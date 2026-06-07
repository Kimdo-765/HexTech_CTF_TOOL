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
from modules.misc.prompts import SYSTEM_PROMPT, build_user_prompt
from modules.settings_io import apply_to_env, get_setting, has_claude_auth

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
JOBS_DIR = DATA_DIR / "jobs"

MISC_IMAGE = "hextech_ctf_tool-misc"
MISC_TIMEOUT_S = 600
MISC_MEM = "2g"


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


def _spawn_misc(job_id: str, filename: str, passphrase: Optional[str]) -> str:
    client = docker.from_env()
    cmd = [f"/job/{filename}", "--out", "/job"]
    if passphrase:
        cmd += ["--passphrase", passphrase]
    container = client.containers.run(
        image=MISC_IMAGE,
        command=cmd,
        volumes={_host_path(job_id): {"bind": "/job", "mode": "rw"}},
        mem_limit=MISC_MEM,
        network_mode="none",
        detach=True,
        labels={"hextech_ctf_tool_job_id": job_id, "hextech_ctf_tool_role": "misc"},
    )
    try:
        result = container.wait(timeout=MISC_TIMEOUT_S)
        logs = container.logs().decode("utf-8", errors="replace")
        sc = result.get("StatusCode", 1)
        if sc != 0:
            raise RuntimeError(f"misc analyzer exited with code {sc}\n{logs[-4000:]}")
    finally:
        try:
            container.remove(force=True)
        except Exception:
            pass
    return logs


async def _claude_summary(
    job_id: str, filename: str, description: Optional[str],
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
    prompt = build_user_prompt(filename, description)
    from modules._common import build_exploit_library_hint
    _lib_hint = build_exploit_library_hint("misc")
    if _lib_hint:
        prompt = _lib_hint + "\n\n" + prompt
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
    filename: Optional[str],
    passphrase: Optional[str],
    description: Optional[str],
    skip_claude: bool = False,
    model_override: Optional[str] = None,
) -> dict:
    apply_to_env()
    _write_meta(job_id, status="running", stage="analyze")
    try:
        # File is optional. With no file, skip the misc tool sweep
        # (`_spawn_misc` would build `/job/None`) and fall through to the
        # description-only Claude analysis.
        if filename:
            _log(job_id, f"Spawning misc analyzer (file={filename})")
            logs = _spawn_misc(job_id, filename, passphrase)
            (_job_dir(job_id) / "analyzer.log").write_text(logs)
        else:
            _log(job_id, "No file provided — skipping misc tool sweep; "
                         "running description-only Claude analysis.")

        findings_path = _job_dir(job_id) / "findings.json"
        findings = json.loads(findings_path.read_text()) if findings_path.exists() else {}

        result: dict = {"findings": findings}

        if skip_claude or not has_claude_auth():
            _log(job_id, "Skipping Claude summary (no API key or skip flag).")
        else:
            _write_meta(job_id, stage="summarize")
            result["claude"] = anyio.run(_claude_summary, job_id, filename, description, model_override)

        # Combine flags from misc tool sweep + general scan of report.md etc.
        candidates = (findings.get("strings") or {}).get("flag_candidates", [])
        embedded = [h.get("flag") for h in (findings.get("embedded_flag_hits") or [])]
        scanned = scan_job_for_flags(job_id)
        flags = sorted(set([f for f in candidates + embedded + scanned if f]))
        result["flags"] = flags

        cost = extract_cost(result.get("claude"))
        result["cost_usd"] = cost

        final_status = "finished" if flags else "no_flag"
        (_job_dir(job_id) / "result.json").write_text(json.dumps(result, indent=2, default=str))
        _write_meta(job_id, status=final_status, stage="done", cost_usd=cost,
                    flags=flags)
        return result
    except Exception as e:
        _log(job_id, f"ERROR: {e}\n{traceback.format_exc()}")
        _write_meta(job_id, status="failed", error=str(e))
        raise
