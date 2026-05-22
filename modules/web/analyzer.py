import asyncio
import json
import os
import traceback
from typing import Optional

import anyio

from modules._common import (
    cleanup_job_processes,
    collect_outputs,
    extract_cost,
    job_dir,
    log_line,
    make_main_session_options,
    REPORT_SCHEMA_WEB,
    load_cached_pre_recon,
    module_autoboot,
    prior_work_dirs,
    read_meta,
    run_main_agent_session,
    run_pre_recon,
    run_report_phase,
    scan_job_for_flags,
    soft_timeout_watchdog,
    store_pre_recon_cache,
    write_meta,
)
from modules._runner import attempt_sandbox_run
from modules.settings_io import apply_to_env, get_setting
from modules.web.prompts import SYSTEM_PROMPT, build_user_prompt


async def _run_agent(
    job_id: str,
    src_root: Optional[str],
    target_url: Optional[str],
    description: Optional[str],
    auto_run: bool,
    model_override: Optional[str] = None,
) -> dict:
    work_dir = job_dir(job_id) / "work"
    work_dir.mkdir(exist_ok=True)

    # Item 5 — autoboot breadcrumb for subagent baseline.
    module_autoboot(
        "web", work_dir, lambda s: log_line(job_id, s),
        extras={
            "src_root": src_root or "(remote-only)",
            "target_url": target_url or "(none)",
        },
    )

    model = model_override or str(get_setting("claude_model") or "claude-opus-4-7")
    add_dirs = [src_root] if src_root else []
    resume_sid = read_meta(job_id).get("resume_session_id")
    summary: dict = {"messages": 0, "tool_calls": 0, "model": model}
    options = make_main_session_options(
        job_id=job_id,
        work_dir=work_dir,
        model=model,
        system_prompt=SYSTEM_PROMPT,
        base_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
        summary=summary,
        add_dirs=add_dirs,
        resume_sid=resume_sid,
    )
    if resume_sid:
        log_line(job_id, f"Forking prior Claude session {resume_sid[:8]}…")

    user_prompt = build_user_prompt(src_root, target_url, description, auto_run)

    # Auto-pre-recon — recon maps the source tree (routes, sinks, auth)
    # before main's first turn so main starts with a route inventory
    # instead of `find . -type f` walking the codebase itself. Skipped
    # for remote-only jobs (no source to grep) and on retries.
    if src_root and not resume_sid:
        # See modules/pwn/analyzer.py for the carry_work=True rationale —
        # web/crypto/rev share the same retry plumbing.
        recon_reply = load_cached_pre_recon(
            work_dir, lambda s: log_line(job_id, s),
            retry_of=read_meta(job_id).get("retry_of"),
        )
        if not recon_reply:
            recon_question = (
                "STATIC TRIAGE REQUEST (pre-flight for the main exploit writer).\n\n"
                f"SOURCE ROOT: {src_root}   (read-only)\n"
                + (f"REMOTE TARGET: {target_url}\n" if target_url else "")
                + "\n"
                "REPLY in ≤2 KB, as compact bullets, with these sections:\n"
                "  STACK        — language + framework + DB (Flask, Express, "
                "Spring, …). Cite the entry-point file.\n"
                "  ROUTES       — list every HTTP route the app exposes. "
                "format: `METHOD /path  →  file:line  (handler_name)`. "
                "Group by file when tight.\n"
                "  AUTH         — login / session / token plumbing in one "
                "paragraph. Where are creds stored, what crypto is used, "
                "what's the session cookie name?\n"
                "  USER INPUT   — every reachable parameter sink (request "
                "args / JSON body / headers / file upload paths). file:line.\n"
                "  CANDIDATES   — ranked HIGH/MED/LOW with bug class + "
                "file:line. Bug classes: SQLi, XSS, SSRF, RCE, LFI, "
                "deserialization, JWT-misuse, path traversal, command "
                "injection. Quote the unsafe line.\n"
                "  FLAG PATH    — where does the flag get read / served? "
                "(env var? /flag.txt? hardcoded string?)\n\n"
                "DO NOT propose exploit code. Facts only. Cite file:line for "
                "every claim."
            )
            log_line(job_id, "[pre-recon] spawning static-triage recon subagent")
            recon_reply = await run_pre_recon(
                job_id=job_id,
                work_dir=work_dir,
                model=model,
                prompt=recon_question,
                log_fn=lambda s: log_line(job_id, s),
            )
            store_pre_recon_cache(
                work_dir, recon_reply, lambda s: log_line(job_id, s),
            )
        if recon_reply:
            user_prompt = (
                "PRE-RECON COMPLETED — the orchestrator already ran a "
                "recon subagent on your behalf. Its 2 KB summary is "
                "below. START from this; do not re-grep the tree "
                "yourself.\n\n"
                "==== RECON REPLY ===="
                f"\n{recon_reply}\n"
                "==== END RECON ====\n\n"
            ) + user_prompt
            log_line(
                job_id,
                f"[pre-recon] reply ready ({len(recon_reply)} chars)",
            )

    from modules._common import build_exploit_library_hint
    _lib_hint = build_exploit_library_hint("web")
    if _lib_hint:
        user_prompt = _lib_hint + "\n\n" + user_prompt

    log_line(job_id, f"Launching Claude agent (model={model})")
    log_line(job_id, f"Source root: {src_root or '(remote-only)'}")

    soft_timeout = int(read_meta(job_id).get("job_timeout") or 0)
    watchdog = asyncio.create_task(soft_timeout_watchdog(job_id, soft_timeout))

    sandbox_result: Optional[dict] = None

    def _sandbox_for(script_name: str) -> Optional[dict]:
        return attempt_sandbox_run(
            job_id, script_name, target_url, lambda s: log_line(job_id, s),
            prior_hints=list(summary.get("judge_hints", [])),
        )

    try:
        sandbox_result = await run_main_agent_session(
            job_id,
            options=options,
            initial_prompt=user_prompt,
            summary=summary,
            work_dir=work_dir,
            artifact_names=("exploit.py",),
            auto_run=auto_run,
            sandbox_runner=_sandbox_for,
            log_fn=lambda s: log_line(job_id, s),
        )
        # Terminal REPORT phase — same cookbook pattern as pwn module.
        # Stateless query() converts report.md + exploit.py prose into
        # the web-specific findings.json schema. Best-effort.
        try:
            await run_report_phase(
                job_id=job_id,
                work_dir=work_dir,
                log_fn=lambda s: log_line(job_id, s),
                schema_text=REPORT_SCHEMA_WEB,
            )
        except Exception as e:
            log_line(
                job_id,
                f"[report] phase raised {type(e).__name__}: {e} — "
                f"continuing without findings.json",
            )
    finally:
        watchdog.cancel()
        # Kill leftover background processes (qemu/gdbserver) from this job
        # so they don't leak into the next. See modules/_common.py.
        cleanup_job_processes(lambda s: log_line(job_id, s))
        # Clear the awaiting_decision flag if the watchdog already fired —
        # the job has finished and the user no longer needs to decide.
        if read_meta(job_id).get("awaiting_decision"):
            write_meta(job_id, awaiting_decision=False)
        # Carry artifacts up to the job dir. Runs in `finally` so any
        # abrupt exit (RQ stop / Stop&Resume / SIGTERM-with-grace) still
        # flushes exploit.py / report.md into <jobdir>/, where the API's
        # file links look. Wrapped in its own try/except so a copy
        # failure can't mask the real agent error in summary.
        try:
            jd = job_dir(job_id)
            # Prefer the agent's cwd, but also check /root/, the job root, and
            # any prior-attempt work dirs (for retry/resume — the forked SDK
            # session sometimes re-uses absolute paths from the prior tool
            # history and silently writes into the OLD job dir).
            fallback_dirs = prior_work_dirs(job_id)
            found = collect_outputs(
                work_dir,
                ["exploit.py", "report.md", "findings.json", "WHY_STOPPED.md"],
                fallback_dirs=fallback_dirs,
            )
            if "exploit.py" not in found and (jd / "exploit.py").is_file():
                found["exploit.py"] = jd / "exploit.py"
            if "report.md" not in found and (jd / "report.md").is_file():
                found["report.md"] = jd / "report.md"
            summary["exploit_present"] = "exploit.py" in found
            summary["report_present"] = "report.md" in found
            for name, src in found.items():
                target_path = jd / name
                if src.resolve() != target_path.resolve():
                    target_path.write_bytes(src.read_bytes())
                # Mirror into work_dir too — the next /retry uses
                # `<this_job>/work/` as its carry source via shutil.copytree,
                # so without this any fallback recovery (file actually written
                # to a stale absolute path) would be carried as a stale copy
                # AGAIN on the next retry.
                work_target = work_dir / name
                if src.resolve() != work_target.resolve():
                    work_target.write_bytes(src.read_bytes())
        except Exception as carry_err:
            log_line(job_id, f"CARRY_ERROR: {carry_err}")
    summary["sandbox"] = sandbox_result
    return summary


def run_job(
    job_id: str,
    src_root: Optional[str],
    target_url: Optional[str],
    description: Optional[str],
    auto_run: bool,
    model_override: Optional[str] = None,
) -> dict:
    apply_to_env()
    write_meta(job_id, status="running", stage="analyze")
    try:
        agent_summary = anyio.run(
            _run_agent, job_id, src_root, target_url, description, auto_run,
            model_override,
        )
        cost = extract_cost(agent_summary)

        sandbox_result = agent_summary.pop("sandbox", None)

        flags = scan_job_for_flags(job_id)
        agent_err = agent_summary.get("agent_error")
        agent_err_kind = agent_summary.get("agent_error_kind")
        if agent_err and not agent_summary.get("exploit_present"):
            final_status = "failed"
        elif not flags:
            final_status = "no_flag"
        else:
            final_status = "finished"
        result = {
            "agent": agent_summary,
            "cost_usd": cost,
            "sandbox": sandbox_result,
            "flags": flags,
            "agent_error": agent_err,
            "agent_error_kind": agent_err_kind,
        }
        (job_dir(job_id) / "result.json").write_text(json.dumps(result, indent=2))
        write_meta(job_id, status=final_status, stage="done", cost_usd=cost,
                   model=agent_summary.get("model"),
                   flags=flags,
                   error=agent_err,
                   error_kind=agent_err_kind,
                   exploit_present=agent_summary.get("exploit_present", False))
        return result
    except Exception as e:
        log_line(job_id, f"ERROR: {e}\n{traceback.format_exc()}")
        write_meta(job_id, status="failed", error=str(e))
        raise
