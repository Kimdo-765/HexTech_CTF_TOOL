import asyncio
import json
import shutil
import traceback
from pathlib import Path
from typing import Optional

import anyio

from modules._common import (
    cleanup_job_processes,
    collect_outputs,
    docker_challenge_block,
    extract_cost,
    prior_session_cost,
    job_dir,
    log_line,
    reap_chal_containers,
    REPORT_SCHEMA_REV,
    load_cached_pre_recon,
    make_main_session_options,
    module_autoboot,
    prior_work_dirs,
    read_meta,
    resolve_effort,
    resolve_main_model,
    run_main_agent_session,
    run_pre_recon,
    run_report_phase,
    scan_job_for_flags,
    store_pre_recon_cache,
    write_meta,
)
from modules._runner import attempt_sandbox_run, remote_target_start_gate
from modules.rev.prompts import SYSTEM_PROMPT, build_user_prompt
from modules.settings_io import apply_to_env, get_setting


async def _run_agent(
    job_id: str,
    binary_name: str | None,
    bin_dir: Path,
    description: Optional[str],
    auto_run: bool,
    model_override: Optional[str] = None,
) -> dict:
    target = (read_meta(job_id).get("target_url") or "").strip() or None
    gate_summary = remote_target_start_gate(
        job_id, "rev", target, lambda s: log_line(job_id, s),
    )
    if gate_summary is not None:
        return gate_summary

    work_dir = job_dir(job_id) / "work"
    work_dir.mkdir(exist_ok=True)

    staged_bin = work_dir / "bin"
    if staged_bin.exists():
        shutil.rmtree(staged_bin)
    shutil.copytree(bin_dir, staged_bin)
    for f in staged_bin.iterdir():
        try:
            f.chmod(0o755)
        except Exception:
            pass

    # Item 5 — autoboot breadcrumb for subagent baseline.
    module_autoboot(
        "rev", work_dir, lambda s: log_line(job_id, s),
        extras={
            "binary": binary_name or "(none)",
            "staged_count": str(len(list(staged_bin.iterdir()))),
        },
    )

    model = resolve_main_model(model_override)
    resume_sid = read_meta(job_id).get("resume_session_id")
    summary: dict = {"messages": 0, "tool_calls": 0, "model": model}
    options = make_main_session_options(
        job_id=job_id,
        work_dir=work_dir,
        model=model,
        system_prompt=SYSTEM_PROMPT,
        base_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
        summary=summary,
        resume_sid=resume_sid,
        effort=resolve_effort(read_meta(job_id).get("effort")),
    )
    user_prompt = build_user_prompt(binary_name, description, auto_run, target=target)
    from modules._prompts import build_target_directive
    _tgt_block = build_target_directive(target, read_meta(job_id).get("target_urls"))
    if _tgt_block:
        user_prompt = user_prompt + "\n\n" + _tgt_block
    # 'Docker challenge' opt-in: detect a bundled Dockerfile/compose under ./bin/
    # and instruct the agent to build+run it as the real runtime + dynamic
    # oracle. Returns "" (no-op) when the box is unticked.
    _docker_block = docker_challenge_block(job_id)
    if _docker_block:
        user_prompt = user_prompt + "\n\n" + _docker_block

    # ELF/PE detection — the static-triage pre-recon below runs ghiant
    # (Ghidra) + checksec, which only make sense for a NATIVE executable.
    # For a non-native artifact (Java .class/.jar, Python .pyc, WASM, DEX,
    # Lua, custom-VM bytecode, a script) skip it: main's format-aware prompt
    # does `file`-first routing instead of burning a Ghidra run that errors.
    is_native = False
    if binary_name:
        try:
            _magic = (staged_bin / binary_name).read_bytes()[:4]
            is_native = _magic.startswith(b"\x7fELF") or _magic[:2] == b"MZ"
        except OSError:
            pass

    # Auto-pre-recon — recon does the static triage before main's first
    # turn so main starts with the inventory in its prompt instead of
    # having to decide "should I delegate?". Skipped on retries (main
    # is resuming a prior session) and for non-native / no-binary jobs.
    if is_native and not resume_sid:
        # See modules/pwn/analyzer.py for the carry_work=True rationale —
        # web/crypto/rev share the same retry plumbing.
        recon_reply = load_cached_pre_recon(
            work_dir, lambda s: log_line(job_id, s),
            retry_of=read_meta(job_id).get("retry_of"),
        )
        if not recon_reply:
            recon_question = (
                "STATIC TRIAGE REQUEST (pre-flight for the main solver writer).\n\n"
                f"BINARY: ./bin/{binary_name}   (cwd = work dir)\n\n"
                f"If `./decomp/` is missing, run `ghiant ./bin/{binary_name}` "
                "ONCE to populate it (project cached under ./.ghidra_proj/).\n\n"
                "REPLY in ≤2 KB, as compact bullets, with these sections:\n"
                "  ARCH         — `file` summary in one line\n"
                "  PROTECTIONS  — checksec\n"
                "  LANGUAGE     — C/C++ vs Go vs Rust vs .NET vs packed?\n"
                "  FUNCTIONS    — names + sizes of the interesting funcs "
                "(main, check_password / verify / decrypt / serial routines, "
                "flag-derivation paths). Ignore stdlib stubs.\n"
                "  FLAG PATH    — where is the flag string built / read / "
                "printed? cite file:addr.\n"
                "  CONSTANTS    — XOR keys, AES keys, hashes, magic bytes "
                "embedded in .data/.rodata that the solver will need.\n"
                "  CANDIDATES   — ranked HIGH/MED/LOW with technique name + "
                "file:line (`HIGH brute-force serial via known constant @ 0x..`).\n\n"
                "DO NOT propose solver code. Facts only. Cite file:line "
                "for every claim."
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
                "below. START from this; do not re-run the same triage "
                "yourself.\n\n"
                "==== RECON REPLY ===="
                f"\n{recon_reply}\n"
                "==== END RECON ====\n\n"
            ) + user_prompt
            log_line(
                job_id,
                f"[pre-recon] reply ready ({len(recon_reply)} chars)",
            )
    elif binary_name and not resume_sid:
        log_line(
            job_id,
            f"[pre-recon] skipped — {binary_name!r} is not ELF/PE; main "
            "identifies the format with `file` and routes to the right "
            "decompiler / manual analysis itself.",
        )

    from modules._common import build_exploit_library_hint
    _lib_hint = build_exploit_library_hint("rev")
    if _lib_hint:
        user_prompt = _lib_hint + "\n\n" + user_prompt

    from modules.agent_provider import active_provider, provider_display_name
    log_line(
        job_id,
        f"Launching {provider_display_name(active_provider())} agent (model={model})",
    )
    if resume_sid:
        log_line(job_id, f"Forking prior Claude session {resume_sid[:8]}…")


    sandbox_result: Optional[dict] = None

    def _sandbox_for(script_name: str) -> Optional[dict]:
        # Pass the remote target (if any) so the auto-run hands solver.py the
        # service via sys.argv[1] — a rev chal can require connecting to the
        # live service to capture the flag, not just a local derivation.
        return attempt_sandbox_run(
            job_id, script_name, target, lambda s: log_line(job_id, s),
            prior_hints=list(summary.get("judge_hints", [])),
        )

    try:
        sandbox_result = await run_main_agent_session(
            job_id,
            options=options,
            initial_prompt=user_prompt,
            summary=summary,
            work_dir=work_dir,
            artifact_names=("solver.py",),
            auto_run=auto_run,
            sandbox_runner=_sandbox_for,
            log_fn=lambda s: log_line(job_id, s),
        )
        # Terminal REPORT phase — see pwn analyzer for the rationale.
        try:
            await run_report_phase(
                job_id=job_id,
                work_dir=work_dir,
                model=model,  # report follows main's model (per-job)
                log_fn=lambda s: log_line(job_id, s),
                chal_name_hint=(binary_name or ""),
                schema_text=REPORT_SCHEMA_REV,
            )
        except Exception as e:
            log_line(
                job_id,
                f"[report] phase raised {type(e).__name__}: {e} — "
                f"continuing without findings.json",
            )
    finally:
        # Kill leftover background processes from this job (qemu used in
        # rev for emulating foreign-arch binaries).
        cleanup_job_processes(lambda s: log_line(job_id, s))
        # Carry artifacts up to the job dir. Runs in `finally` so any
        # abrupt exit (RQ stop / Stop&Resume / SIGTERM-with-grace) still
        # flushes solver.py / report.md into <jobdir>/, where the API's
        # file links look. Wrapped in its own try/except so a copy
        # failure can't mask the real agent error in summary.
        try:
            fallback_dirs = prior_work_dirs(job_id)
            found = collect_outputs(
                work_dir,
                ["solver.py", "report.md", "findings.json"],
                fallback_dirs=fallback_dirs,
                log_fn=lambda s: log_line(job_id, s),
            )
            summary["solver_present"] = "solver.py" in found
            summary["report_present"] = "report.md" in found
            summary["decomp_used"] = (work_dir / "decomp").exists()
            if summary["decomp_used"]:
                try:
                    summary["decomp_function_count"] = len(list((work_dir / "decomp").glob("*.c")))
                except Exception:
                    pass
            jd = job_dir(job_id)
            for name, src in found.items():
                target = jd / name
                if src.resolve() != target.resolve():
                    target.write_bytes(src.read_bytes())
                work_target = work_dir / name
                if src.resolve() != work_target.resolve():
                    work_target.write_bytes(src.read_bytes())
        except Exception as carry_err:
            log_line(job_id, f"CARRY_ERROR: {carry_err}")
    summary["sandbox"] = sandbox_result
    return summary


def run_job(
    job_id: str,
    binary_rel: str | None,
    description: Optional[str],
    auto_run: bool,
    model_override: Optional[str] = None,
) -> dict:
    jd = job_dir(job_id)
    bin_dir = jd / "bin"
    # binary_rel may be None: a zip that carried no ELF/PE and no usable
    # fallback file (rev_module.py), or a remote-target-only rev job.
    binary_name = Path(binary_rel).name if binary_rel else None

    apply_to_env()
    # 'Docker challenge' opt-in → the agent may `docker build`/`docker run` the
    # bundled Dockerfile. Sweep stale chal containers a prior crashed run of
    # this id left behind (SIGKILL/OOM skips the finally), then reap in finally
    # so nothing orphans (label hextech_job=<id>; see reap_chal_containers).
    _dc = bool(read_meta(job_id).get("docker_challenge"))
    if _dc:
        reap_chal_containers(
            job_id, lambda s: log_line(job_id, s), reason="startup sweep",
        )
    write_meta(job_id, status="running", stage="analyze")
    try:
        agent_summary = anyio.run(
            _run_agent, job_id, binary_name, bin_dir, description, auto_run,
            model_override,
        )
        cost = extract_cost(agent_summary)
        # + earlier sessions (stop -> continue reuses the job id)
        cost += prior_session_cost(job_id)

        sandbox_result = agent_summary.pop("sandbox", None)

        flags = scan_job_for_flags(job_id, sandbox_result=sandbox_result)
        agent_err = agent_summary.get("agent_error")
        agent_err_kind = agent_summary.get("agent_error_kind")
        if agent_err and not agent_summary.get("solver_present"):
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
        (jd / "result.json").write_text(json.dumps(result, indent=2))
        write_meta(job_id, status=final_status, stage="done", cost_usd=cost,
                   model=agent_summary.get("model"),
                   flags=flags,
                   error=agent_err,
                   error_kind=agent_err_kind,
                   solver_present=agent_summary.get("solver_present", False),
                   decomp_used=agent_summary.get("decomp_used", False))
        return result
    except Exception as e:
        log_line(job_id, f"ERROR: {e}\n{traceback.format_exc()}")
        write_meta(job_id, status="failed", error=str(e))
        raise
    finally:
        # Reap any local challenge containers/networks the agent spun up for the
        # docker-challenge opt-in (label hextech_job=<id>). Best-effort; runs on
        # success, failure, and _Stop/agent-error paths without masking results.
        if _dc:
            reap_chal_containers(
                job_id, lambda s: log_line(job_id, s), reason="job complete",
            )
