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
    prior_session_cost,
    format_tool_result,
    kill_guard_hooks,
    log_thinking,
    read_meta,
    reap_chal_containers,
    resolve_effort,
    resolve_main_model,
    scan_job_for_flags,
    _is_placeholder_flag,
    write_meta,
)
from modules.misc.prompts import SYSTEM_PROMPT, build_user_prompt
from modules.settings_io import apply_to_env, get_setting, has_claude_auth
from modules.agent_provider import (
    active_provider,
    has_provider_auth,
    provider_display_name,
    coerce_model_for_provider,
)

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
    """Misc summary agent. Backend follows Settings ``agent_provider``."""
    work_dir = _job_dir(job_id)
    model = coerce_model_for_provider(resolve_main_model(model_override))
    # Per-job scratch dir (see modules/_common.py make_main_session_options
    # for rationale). Cleanup is implicit via job DELETE rmtree.
    tmp_dir = Path(work_dir) / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    _tmp_str = str(tmp_dir)
    prompt = build_user_prompt(
        filename, description, flag_format=read_meta(job_id).get("flag_format")
    )
    from modules._common import build_exploit_library_hint
    _lib_hint = build_exploit_library_hint("misc")
    if _lib_hint:
        prompt = _lib_hint + "\n\n" + prompt
    # 'Docker challenge' opt-in: detect a bundled Dockerfile/compose and instruct
    # the agent to build+run it. Returns "" (no-op) when the box is unticked.
    from modules._common import docker_challenge_block
    _docker_block = docker_challenge_block(job_id)
    if _docker_block:
        prompt = prompt + "\n\n" + _docker_block

    provider = active_provider()
    summary: dict = {"messages": 0, "tool_calls": 0, "agent_provider": provider}

    # ---- Grok path --------------------------------------------------------
    if provider == "grok":
        from modules.grok_acp import (
            GrokACPClient,
            GrokSessionOptions,
            AssistantMessage as GrokAM,
            ResultMessage as GrokRM,
            ToolUseBlock as GrokTUB,
        )
        from modules._prompts import adapt_system_prompt_for_grok
        _log(job_id, f"Launching {provider_display_name('grok')} summary agent (model={model})")
        opts = GrokSessionOptions(
            system_prompt=adapt_system_prompt_for_grok(SYSTEM_PROMPT),
            model=model,
            cwd=str(work_dir),
            effort=resolve_effort(read_meta(job_id).get("effort")),
            env={
                "JOB_ID": job_id,
                "TMPDIR": _tmp_str,
                "TMP": _tmp_str,
                "TEMP": _tmp_str,
            },
        )
        async with GrokACPClient(opts) as client:
            if client.session_id:
                try:
                    write_meta(job_id, agent_session_id=client.session_id)
                except Exception:
                    pass
            await client.query(prompt)
            async for msg in client.receive_response():
                agent_heartbeat(job_id, msg)
                if isinstance(msg, GrokAM):
                    summary["messages"] += 1
                    for block in (getattr(msg, "content", None) or []):
                        if type(block).__name__ == "TextBlock":
                            _log(job_id, f"AGENT: {(getattr(block, 'text', '') or '')[:500]}")
                        elif type(block).__name__ == "ToolUseBlock" or isinstance(block, GrokTUB):
                            summary["tool_calls"] += 1
                            inp = getattr(block, "input", None) or {}
                            try:
                                args_preview = json.dumps(inp)[:200]
                            except Exception:
                                args_preview = str(inp)[:200]
                            _log(job_id, f"TOOL {getattr(block, 'name', '?')}: {args_preview}")
                elif isinstance(msg, GrokRM):
                    summary["result"] = {
                        "duration_ms": getattr(msg, "duration_ms", None),
                        "num_turns": getattr(msg, "num_turns", None),
                        "total_cost_usd": getattr(msg, "total_cost_usd", None),
                        "is_error": bool(getattr(msg, "is_error", False)),
                    }
        return summary

    # ---- Claude path ------------------------------------------------------
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
        # Bash kill-guard (the anti-writeup web-research block was removed
        # 2026-07-22 — kill_guard_hooks no longer denies WebSearch/WebFetch).
        hooks=kill_guard_hooks(job_id),
    )
    summary["agent_provider"] = "claude"

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
    # 'Docker challenge' opt-in → the agent may `docker build`/`docker run` the
    # bundled Dockerfile. Sweep stale chal containers from a prior crashed run
    # of this id, then reap in finally so nothing orphans (hextech_job=<id>).
    _dc = bool(read_meta(job_id).get("docker_challenge"))
    if _dc:
        reap_chal_containers(job_id, lambda s: _log(job_id, s), reason="startup sweep")
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

        if skip_claude or not has_provider_auth():
            _log(
                job_id,
                f"Skipping agent summary (no {active_provider()} auth, or skip flag).",
            )
        else:
            _write_meta(job_id, stage="summarize")
            result["claude"] = anyio.run(_claude_summary, job_id, filename, description, model_override)

        # Combine flags from misc tool sweep + general scan of report.md etc.
        candidates = (findings.get("strings") or {}).get("flag_candidates", [])
        embedded = [h.get("flag") for h in (findings.get("embedded_flag_hits") or [])]
        # candidates + embedded are RAW analyzer output — filter placeholders
        # (CTF{example} / FLAG{your_flag_here} planted in the input) so a sample
        # flag can't false-"finished" the job. Do NOT re-filter `scanned`:
        # scan_job_for_flags already applied the trusted-tier filter, and
        # re-running the untrusted heuristic here could drop a real DH{<64hex>}
        # (see memory real_flag_dropped_as_placeholder).
        raw = [f for f in candidates + embedded if f and not _is_placeholder_flag(f)]
        scanned = scan_job_for_flags(job_id)
        flags = sorted(set(raw + scanned))
        result["flags"] = flags

        cost = extract_cost(result.get("claude"))
        # + earlier sessions (stop -> continue reuses the job id)
        cost += prior_session_cost(job_id)
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
    finally:
        # Reap any local challenge containers the agent spun up for the
        # docker-challenge opt-in (label hextech_job=<id>). Best-effort.
        if _dc:
            reap_chal_containers(job_id, lambda s: _log(job_id, s), reason="job complete")
