"""Web3 / smart-contract module.

Modelled on modules/crypto/analyzer.py — same phase order (autoboot ->
pre-recon -> main session -> auto-run -> report), same artifact-carry and
terminal-status contract. The differences are the ones the domain forces:

  * the deliverable is `exploit.py` (plus optional helper .sol files that a
    reentrancy or force-send attack needs, which are carried too);
  * "solved" is a PREDICATE on chain (`Setup.isSolved()`), not a string the
    program prints, so the prompt separates a local rehearsal from a remote
    capture and the report schema records the win condition verbatim;
  * pre-recon is asked for the win condition FIRST, because every other
    decision follows from it.

Deliberately NOT copied from crypto: the deterministic pre-analysis and the
classical auto-solve. Both are pure-code near-solves for a cipher family; there
is no equivalent one-shot for contract logic, and a stub that pretends
otherwise would be dead code with a maintenance cost.
"""
import json
import traceback
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
    make_main_session_options,
    REPORT_SCHEMA_WEB3,
    load_cached_pre_recon,
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
from modules._runner import attempt_sandbox_run
from modules.web3.prompts import SYSTEM_PROMPT, build_user_prompt
from modules.settings_io import apply_to_env


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

    module_autoboot(
        "web3", work_dir, lambda s: log_line(job_id, s),
        extras={
            "src_root": src_root or "(no source — bytecode-only)",
            "target": target or "(none — local anvil only)",
        },
    )

    model = resolve_main_model(model_override)
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

    from modules._prompts import build_target_directive
    _mt_block = build_target_directive(target, read_meta(job_id).get("target_urls"))
    if _mt_block:
        user_prompt = user_prompt + "\n\n" + _mt_block

    _docker_block = docker_challenge_block(job_id)
    if _docker_block:
        user_prompt = user_prompt + "\n\n" + _docker_block

    # Auto-pre-recon. The question leads with the win condition on purpose:
    # in a Web3 challenge `Setup.isSolved()` decides what "exploit" even
    # means, and an agent that starts from the vulnerability instead of the
    # predicate can build a perfectly good attack that satisfies nothing.
    if src_root and not resume_sid:
        recon_reply = load_cached_pre_recon(
            work_dir, lambda s: log_line(job_id, s),
            retry_of=read_meta(job_id).get("retry_of"),
        )
        if not recon_reply:
            recon_question = (
                "STATIC TRIAGE REQUEST (pre-flight for the main exploit "
                "writer).\n\n"
                f"CONTRACT SOURCES: {src_root}   (read-only)\n"
                + (f"REMOTE INSTANCE: {target}\n" if target else "")
                + "\n"
                "REPLY in <=2 KB, as compact bullets, with these sections:\n"
                "  WIN CONDITION — quote the body of `isSolved()` (or "
                "whatever predicate the challenge checks) VERBATIM, with "
                "file:line. If there is no Setup contract, say so and name "
                "what else looks like the goal. Put this FIRST; everything "
                "else depends on it.\n"
                "  CONTRACTS    — every .sol, one line each (path · contract "
                "name · what it is for). Note which one Setup deploys and "
                "which holds value.\n"
                "  SOLIDITY VER — the pragma(s). Flag anything <0.8.0 (no "
                "built-in overflow checks) and any `unchecked{}` block.\n"
                "  EXTERNAL SURFACE — public/external functions on the "
                "target, with modifiers. Mark the ones with no access "
                "control.\n"
                "  STATE        — storage variables that matter, including "
                "`private` ones (they are readable) and who can change "
                "them.\n"
                "  CANDIDATES   — ranked HIGH/MED/LOW bug-class with "
                "rationale and file:line, e.g. `HIGH reentrancy — balance "
                "zeroed AFTER call{value:} at Vault.sol:41`. Use standard "
                "names: reentrancy, access-control, delegatecall, "
                "uninitialized-proxy, oracle-manipulation, integer-overflow, "
                "signature-replay, weak-randomness, force-send.\n\n"
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
                "PRE-RECON COMPLETED — the orchestrator already ran a recon "
                "subagent on your behalf. Its 2 KB summary is below. START "
                "from this; do not re-read the whole tree yourself.\n\n"
                "==== RECON REPLY ===="
                f"\n{recon_reply}\n"
                "==== END RECON ====\n\n"
            ) + user_prompt
            log_line(
                job_id,
                f"[pre-recon] reply ready ({len(recon_reply)} chars)",
            )

    from modules._common import build_exploit_library_hint
    _lib_hint = build_exploit_library_hint(
        "web3", chal_name=read_meta(job_id).get("chal_name") or "",
    )
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
            artifact_names=("exploit.py",),
            auto_run=auto_run,
            sandbox_runner=_sandbox_for,
            log_fn=lambda s: log_line(job_id, s),
        )
        try:
            await run_report_phase(
                job_id=job_id,
                work_dir=work_dir,
                model=model,
                log_fn=lambda s: log_line(job_id, s),
                schema_text=REPORT_SCHEMA_WEB3,
            )
        except Exception as e:
            log_line(
                job_id,
                f"[report] phase raised {type(e).__name__}: {e} — "
                f"continuing without findings.json",
            )
    finally:
        cleanup_job_processes(lambda s: log_line(job_id, s))
        try:
            jd = job_dir(job_id)
            fallback_dirs = prior_work_dirs(job_id)
            # Helper contracts are part of the deliverable, not scratch: a
            # reentrancy or force-send exploit is a .sol plus the script that
            # deploys it, and carrying only the .py would file half an answer.
            names = ["exploit.py", "report.md", "findings.json"]
            try:
                names += sorted(
                    p.name for p in work_dir.glob("*.sol") if p.is_file()
                )[:10]
            except Exception:
                pass
            found = collect_outputs(
                work_dir, names,
                fallback_dirs=fallback_dirs,
                log_fn=lambda s: log_line(job_id, s),
            )
            for name in ("exploit.py", "report.md"):
                if name not in found and (jd / name).is_file():
                    found[name] = jd / name
            summary["exploit_present"] = "exploit.py" in found
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
    model_override: Optional[str] = None,
) -> dict:
    apply_to_env()
    _dc = bool(read_meta(job_id).get("docker_challenge"))
    if _dc:
        reap_chal_containers(
            job_id, lambda s: log_line(job_id, s), reason="startup sweep",
        )
    write_meta(job_id, status="running", stage="analyze")
    try:
        agent_summary = anyio.run(
            _run_agent, job_id, src_root, target, description, auto_run,
            model_override,
        )
        cost = extract_cost(agent_summary)
        cost += prior_session_cost(job_id)

        sandbox_result = agent_summary.pop("sandbox", None)

        flags = scan_job_for_flags(job_id, sandbox_result=sandbox_result)
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
    finally:
        if _dc:
            reap_chal_containers(
                job_id, lambda s: log_line(job_id, s), reason="job complete",
            )
