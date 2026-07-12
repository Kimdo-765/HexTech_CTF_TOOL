import asyncio
import json
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
    REPORT_SCHEMA_CRYPTO,
    load_cached_pre_recon,
    module_autoboot,
    prior_work_dirs,
    read_meta,
    resolve_effort,
    run_main_agent_session,
    run_pre_recon,
    run_report_phase,
    scan_job_for_flags,
    soft_timeout_watchdog,
    store_pre_recon_cache,
    write_meta,
)
from modules._runner import attempt_sandbox_run
from modules.crypto.prompts import SYSTEM_PROMPT, build_user_prompt
from modules.settings_io import apply_to_env, get_setting


async def _run_agent(
    job_id: str,
    src_root: Optional[str],
    target: Optional[str],
    description: Optional[str],
    auto_run: bool,
    model_override: Optional[str] = None,
) -> dict:
    work_dir = job_dir(job_id) / "work"
    work_dir.mkdir(exist_ok=True)

    # Item 5 — autoboot breadcrumb for subagent baseline.
    module_autoboot(
        "crypto", work_dir, lambda s: log_line(job_id, s),
        extras={
            "src_root": src_root or "(remote-only)",
            "target": target or "(none)",
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
        effort=resolve_effort(read_meta(job_id).get("effort")),
    )
    user_prompt = build_user_prompt(src_root, target, description, auto_run)
    from modules._prompts import build_multi_target_block
    _mt_block = build_multi_target_block(read_meta(job_id).get("target_urls"))
    if _mt_block:
        user_prompt = user_prompt + "\n\n" + _mt_block

    # Deterministic remote-banner pre-probe (no LLM). When a remote oracle is
    # the target, capture the FIRST bytes it emits on connect and inject them so
    # main writes its I/O parser against the REAL wire format instead of
    # guessing a `recvuntil` delimiter (job e8d25067458e hung the entire 900s
    # run on a wrong `') > '` guess, never reaching the solve). Best-effort /
    # warn-not-fail: a dead target at probe time returns "" and the job runs
    # normally. Covers remote-only jobs too (runs regardless of src_root); gated
    # on `not resume_sid` so a forked/resumed session doesn't re-probe.
    if target and not resume_sid:
        from modules.crypto.pre_analysis import probe_remote_banner
        _banner = probe_remote_banner(target, lambda s: log_line(job_id, s))
        if _banner:
            user_prompt = (
                "==== REMOTE PROTOCOL PRE-PROBE (automated, no LLM) ====\n"
                f"{_banner}\n"
                "==== END REMOTE PRE-PROBE ====\n\n"
            ) + user_prompt

    # Auto-pre-recon — recon identifies the cipher + parameters before
    # main's first turn so main starts with the math already framed.
    if src_root and not resume_sid:
        # See modules/pwn/analyzer.py for the carry_work=True rationale —
        # web/crypto/rev share the same retry plumbing.
        recon_reply = load_cached_pre_recon(
            work_dir, lambda s: log_line(job_id, s),
            retry_of=read_meta(job_id).get("retry_of"),
        )
        if not recon_reply:
            recon_question = (
                "STATIC TRIAGE REQUEST (pre-flight for the main solver writer).\n\n"
                f"CHALLENGE FILES: {src_root}   (read-only)\n"
                + (f"REMOTE TARGET: {target}\n" if target else "")
                + "\n"
                "REPLY in ≤2 KB, as compact bullets, with these sections:\n"
                "  SOURCE FILES — every script/source in src_root, one line "
                "each (path · purpose). Ignore READMEs unless they carry "
                "challenge specifics.\n"
                "  CIPHER       — name the primitive (RSA / AES-CBC / "
                "ChaCha20 / ECDSA / custom LFSR / etc.) and the public "
                "parameters (modulus bit-size, key length, IV reuse?, "
                "PRG seed?). cite source file:line.\n"
                "  CIPHERTEXT   — exact path(s) + format (hex/b64/raw "
                "bytes). Provide the length and first few bytes.\n"
                "  KEY MATERIAL — what's known (public key, leaked nonce, "
                "partial bits, oracle endpoint)? What's secret?\n"
                "  CANDIDATES   — ranked HIGH/MED/LOW attack name with "
                "rationale (`HIGH coppersmith — high bits of p leaked at "
                "line 47`). Reference standard names: small-e, common "
                "modulus, partial-key, padding oracle, lattice/LLL, "
                "Coppersmith, NTRU, LWE.\n"
                "  SOLVER NOTES — should the solver use SageMath? List the "
                "libs needed (pycryptodome / gmpy2 / sympy / z3).\n\n"
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
                "below. START from this; do not re-grep the source "
                "yourself.\n\n"
                "==== RECON REPLY ===="
                f"\n{recon_reply}\n"
                "==== END RECON ====\n\n"
            ) + user_prompt
            log_line(
                job_id,
                f"[pre-recon] reply ready ({len(recon_reply)} chars)",
            )

        # Deterministic (no-LLM) crypto pre-analysis. Runs INDEPENDENTLY of the
        # recon subagent above: it is pure code, so (a) it still produces facts
        # even when the LLM recon AUP-refused and returned "" (see memory
        # crypto_aup_bytecaesar_falsepos), and (b) on a factorable modulus it
        # effectively hands main the solve. Injected above the recon reply so
        # the reliable facts sit first.
        from modules.crypto.pre_analysis import (
            run_crypto_pre_analysis,
            run_classical_autosolve,
        )
        pre_analysis = run_crypto_pre_analysis(
            src_root, lambda s: log_line(job_id, s)
        )
        if pre_analysis:
            user_prompt = (
                "==== DETERMINISTIC PRE-ANALYSIS (automated static pass, "
                "no LLM) ====\n"
                "The orchestrator extracted these facts before your turn. "
                "Lines marked ★ are near-solves — verify and use them "
                "directly rather than re-deriving.\n\n"
                f"{pre_analysis}\n"
                "==== END PRE-ANALYSIS ====\n\n"
            ) + user_prompt

        # Deterministic classical-cipher auto-solve. If the challenge is a
        # single-byte Caesar/XOR whose plaintext contains the flag, this
        # solves it in PURE CODE and writes a real ./solver.py NOW — before
        # main's first turn. Two payoffs: (a) if main solves normally it just
        # confirms + ships; (b) if main AUP-blocks the moment it reads the
        # files (a deterministic content-classifier hit on this whole chal
        # class — memory crypto_aup_bytecaesar_falsepos), the pre-written
        # solver.py survives the is_error path (fallback only fires when NO
        # artifact exists) and the auto-run sandbox executes it, capturing the
        # flag without the blocked main.
        autosolved = run_classical_autosolve(
            src_root, work_dir,
            read_meta(job_id).get("flag_format"),
            lambda s: log_line(job_id, s),
        )
        if autosolved:
            user_prompt = (
                "==== AUTO-SOLVED (deterministic, no LLM) ====\n"
                "The orchestrator already brute-forced this single-byte "
                "classical cipher and wrote a working ./solver.py that "
                f"recovers the flag {autosolved}. VERIFY it (run "
                "`python3 solver.py`), keep/clean it up, and write report.md. "
                "Do NOT re-derive from scratch.\n"
                "==== END AUTO-SOLVED ====\n\n"
            ) + user_prompt

    from modules._common import build_exploit_library_hint
    _lib_hint = build_exploit_library_hint("crypto")
    if _lib_hint:
        user_prompt = _lib_hint + "\n\n" + user_prompt

    log_line(job_id, f"Launching Claude agent (model={model})")
    if resume_sid:
        log_line(job_id, f"Forking prior Claude session {resume_sid[:8]}…")

    soft_timeout = int(read_meta(job_id).get("job_timeout") or 0)
    watchdog = asyncio.create_task(soft_timeout_watchdog(job_id, soft_timeout))

    sandbox_result: Optional[dict] = None

    def _sandbox_for(script_name: str) -> Optional[dict]:
        return attempt_sandbox_run(
            job_id, script_name, target, lambda s: log_line(job_id, s),
            use_sage=script_name.endswith(".sage"),
            prior_hints=list(summary.get("judge_hints", [])),
        )

    try:
        sandbox_result = await run_main_agent_session(
            job_id,
            options=options,
            initial_prompt=user_prompt,
            summary=summary,
            work_dir=work_dir,
            # solver.py first so a co-existent .sage doesn't take
            # priority unless the agent only produced .sage.
            artifact_names=("solver.py", "solver.sage"),
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
                schema_text=REPORT_SCHEMA_CRYPTO,
            )
        except Exception as e:
            log_line(
                job_id,
                f"[report] phase raised {type(e).__name__}: {e} — "
                f"continuing without findings.json",
            )
    finally:
        watchdog.cancel()
        # Kill leftover background processes from this job.
        cleanup_job_processes(lambda s: log_line(job_id, s))
        if read_meta(job_id).get("awaiting_decision"):
            write_meta(job_id, awaiting_decision=False)
        # Carry artifacts up to the job dir. Runs in `finally` so any
        # abrupt exit (RQ stop / Stop&Resume / SIGTERM-with-grace) still
        # flushes solver.{py,sage} / report.md into <jobdir>/. Wrapped
        # in its own try/except so a copy failure can't mask the real
        # agent error in summary.
        try:
            jd = job_dir(job_id)
            fallback_dirs = prior_work_dirs(job_id)
            found = collect_outputs(
                work_dir,
                ["solver.py", "solver.sage", "report.md",
                 "findings.json", "WHY_STOPPED.md"],
                fallback_dirs=fallback_dirs,
                log_fn=lambda s: log_line(job_id, s),
            )
            for name in ("solver.py", "solver.sage", "report.md"):
                if name not in found and (jd / name).is_file():
                    found[name] = jd / name
            summary["solver_present"] = ("solver.py" in found) or ("solver.sage" in found)
            summary["sage_solver"] = ("solver.sage" in found) and ("solver.py" not in found)
            summary["report_present"] = "report.md" in found
            for name, src in found.items():
                target_path = jd / name
                if src.resolve() != target_path.resolve():
                    target_path.write_bytes(src.read_bytes())
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
    target: Optional[str],
    description: Optional[str],
    auto_run: bool,
    use_sage: bool = False,
    model_override: Optional[str] = None,
) -> dict:
    apply_to_env()
    write_meta(job_id, status="running", stage="analyze")
    try:
        agent_summary = anyio.run(
            _run_agent, job_id, src_root, target, description, auto_run,
            model_override,
        )
        cost = extract_cost(agent_summary)

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
            "use_sage": use_sage,
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
                   solver_present=agent_summary.get("solver_present", False))
        return result
    except Exception as e:
        log_line(job_id, f"ERROR: {e}\n{traceback.format_exc()}")
        write_meta(job_id, status="failed", error=str(e))
        raise
