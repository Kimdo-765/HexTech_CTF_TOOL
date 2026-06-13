import asyncio
import importlib.metadata
import importlib.util
import json
import re
import subprocess
import sys
import traceback
from pathlib import Path
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
from modules.settings_io import apply_to_env, get_setting
from modules.web.prompts import SYSTEM_PROMPT, build_user_prompt


# ── Autoboot Layer-1: stage the pinned web-stack SOURCE ────────────────────
# Mirrors the pwn auto-decompile of a custom .so (modules/pwn/analyzer.py
# _autodecomp_custom_libs): in a web chal the decisive bug often lives in how
# the pinned SERVER/FRAMEWORK serializes / parses / validates — NOT in the
# chal's own code. Job 579f9243a401 (Fast XSS) was missed because the agent
# black-boxed uvicorn: it tested CRLF in a header VALUE (rejected → 0-byte),
# generalised "response splitting blocked", and never READ uvicorn's source —
# where the header-NAME validator regex is broken (an unescaped `]` closes the
# char-class early) so CRLF in a header NAME splits the response. Staging that
# exact-version source on disk + a REQUIRED pre-recon section that diffs
# name-vs-value validation turns the white-box path from a hope into a default.
#
# Packages worth staging = the response path: servers + frameworks + template /
# low-level HTTP parsers. App-logic deps (requests, sqlalchemy, pyjwt) are
# excluded — those bugs surface in app.py, which the agent already reads.
# Ordered by priority so the ≤N cap keeps the server + framework first.
_WEB_STACK_SOURCE_PKGS = (
    "uvicorn", "hypercorn", "gunicorn", "daphne", "waitress",     # servers
    "starlette", "fastapi", "flask", "werkzeug", "django",        # frameworks
    "quart", "aiohttp", "tornado", "sanic", "bottle", "falcon",
    "jinja2", "mako", "markupsafe", "itsdangerous",               # templating
    "httptools", "h11", "h2",                                     # http parsers
)
_WEB_STACK_PRIORITY = {n: i for i, n in enumerate(_WEB_STACK_SOURCE_PKGS)}
_PINNED_PKG_RE = re.compile(r"([A-Za-z][A-Za-z0-9._-]*)==([0-9][A-Za-z0-9.+!_-]*)")
_MAX_STAGE_PKGS = 4


def _stage_pinned_web_stack(src_root: Optional[str], work_dir: Path, job_id: str) -> dict:
    """Stage the chal's pinned web-stack SOURCE into ./work/libsrc/ so
    pre-recon + main read the framework's actual serialization/validation code
    at the EXACT pinned version instead of black-boxing it. Best-effort: any
    parse / pip / network failure logs a breadcrumb and falls back to today's
    behaviour (no staged source). Returns
        {"extras": {<AUTOBOOT.md keys>}, "staged": [(name, ver, path_str), ...]}.
    """
    log = lambda s: log_line(job_id, s)
    out: dict = {"extras": {}, "staged": []}
    if not src_root:
        return out
    src = Path(src_root)

    # 1. Gather manifest text (dead-simple per design: a name==ver token scan
    #    over requirements / Dockerfile / pyproject / Pipfile; node from JSON).
    texts: list[str] = []
    node_deps: list[str] = []
    try:
        for pat in ("requirements*.txt", "Dockerfile*", "pyproject.toml", "Pipfile"):
            for f in src.rglob(pat):
                if f.is_file() and f.stat().st_size < 256_000:
                    try:
                        texts.append(f.read_text(errors="replace"))
                    except OSError:
                        pass
        for pj in src.rglob("package.json"):
            if pj.is_file() and pj.stat().st_size < 256_000:
                try:
                    data = json.loads(pj.read_text(errors="replace"))
                    for sec in ("dependencies", "devDependencies"):
                        for k, v in (data.get(sec) or {}).items():
                            node_deps.append(f"{k}@{v}")
                except (OSError, ValueError):
                    pass
    except Exception as e:
        log(f"[autoboot] web-stack manifest scan error: {e}")

    # 2. Extract pinned name==ver (last pin wins) + record the full list cheaply.
    pinned: dict = {}
    for t in texts:
        for m in _PINNED_PKG_RE.finditer(t):
            pinned[m.group(1).lower()] = m.group(2)
    if pinned:
        out["extras"]["pinned_deps"] = ", ".join(
            f"{k}=={v}" for k, v in sorted(pinned.items())
        )
    if node_deps:
        nd = list(dict.fromkeys(node_deps))[:30]
        out["extras"]["node_deps"] = (
            ", ".join(nd) + "  (no source staged — read ./node_modules or `npm view`)"
        )

    # 3. Pick stage-worthy web-stack pkgs (priority-ordered, capped).
    matched = sorted(
        [(n, v) for n, v in pinned.items() if n in _WEB_STACK_PRIORITY],
        key=lambda nv: _WEB_STACK_PRIORITY[nv[0]],
    )[:_MAX_STAGE_PKGS]
    if not matched:
        if pinned or node_deps:
            log("[autoboot] no stage-worthy web-stack pkg pinned — "
                "app-logic bug likely lives in the chal's own code")
        return out

    libsrc = work_dir / "libsrc"
    staged_disp: list[str] = []
    for name, ver in matched:
        relpath = f"./libsrc/{name}-{ver}"
        target = libsrc / f"{name}-{ver}"
        # 3a. cache hit (retries re-stage, but a same-run repeat is cheap to skip)
        if target.is_dir() and any(target.rglob("*.py")):
            out["staged"].append((name, ver, relpath))
            staged_disp.append(f"{name}=={ver} → {relpath}")
            continue
        # 3b. already importable at the EXACT pinned version? point recon there,
        #     skip the pip cost (advisor: don't pay pip on the ~90% that match).
        try:
            if importlib.metadata.version(name) == ver:
                spec = importlib.util.find_spec(name)
                locs = list(getattr(spec, "submodule_search_locations", None) or [])
                if locs:
                    out["staged"].append((name, ver, locs[0]))
                    staged_disp.append(f"{name}=={ver} → {locs[0]} (worker site-packages)")
                    log(f"[autoboot] {name}=={ver} already present → recon reads {locs[0]}")
                    continue
        except (importlib.metadata.PackageNotFoundError, ValueError, ModuleNotFoundError):
            pass
        # 3c. pip install --no-deps --target into the WORK TREE — never global.
        #     (memory agent_libpollution: confine lib experiments to ./work/.)
        target.mkdir(parents=True, exist_ok=True)
        log(f"[autoboot] staging {name}=={ver} source → {relpath} "
            f"(pre-recon reads the framework's real validation code)")
        try:
            res = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--no-deps", "--quiet",
                 "--target", str(target), f"{name}=={ver}"],
                cwd=str(work_dir), capture_output=True, text=True, timeout=90,
            )
        except subprocess.TimeoutExpired:
            log(f"[autoboot] {name}=={ver} staging TIMEOUT (90s) — recon falls back to black-box")
            continue
        except Exception as e:
            log(f"[autoboot] {name}=={ver} staging ERROR: {e}")
            continue
        if res.returncode == 0 and any(target.rglob("*.py")):
            n_py = sum(1 for _ in target.rglob("*.py"))
            out["staged"].append((name, ver, relpath))
            staged_disp.append(f"{name}=={ver} → {relpath}")
            log(f"[autoboot] {name}=={ver}: staged {n_py} .py files at {relpath}")
        else:
            tail = (res.stderr or "")[-160:].replace("\n", " | ")
            log(f"[autoboot] {name}=={ver} staging FAILED rc={res.returncode}: {tail}")

    if staged_disp:
        out["extras"]["web_stack_src"] = "; ".join(staged_disp)
    return out


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

    # Autoboot Layer-1 — stage the pinned web-stack SOURCE so pre-recon reads
    # the framework's real serialization/validation code (the deterministic
    # white-box step; see _stage_pinned_web_stack). Best-effort.
    _fw = _stage_pinned_web_stack(src_root, work_dir, job_id)

    # Item 5 — autoboot breadcrumb for subagent baseline.
    module_autoboot(
        "web", work_dir, lambda s: log_line(job_id, s),
        extras={
            "src_root": src_root or "(remote-only)",
            "target_url": target_url or "(none)",
            **_fw["extras"],
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
    if resume_sid:
        log_line(job_id, f"Forking prior Claude session {resume_sid[:8]}…")

    user_prompt = build_user_prompt(src_root, target_url, description, auto_run)
    from modules._prompts import build_multi_target_block
    _mt_block = build_multi_target_block(read_meta(job_id).get("target_urls"))
    if _mt_block:
        user_prompt = user_prompt + "\n\n" + _mt_block

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
            # When the pinned framework/server source is staged (autoboot
            # Layer-1), force recon to OPEN it as a required output section —
            # a one-line pointer gets skipped exactly the way the uvicorn
            # header-NAME validator did (job 579f9243a401). Diffing what the
            # server validates in header NAMES vs VALUES (etc.) is where the
            # white-box determinism lives.
            _fw_recon_section = ""
            if _fw["staged"]:
                _fw_paths = ", ".join(str(s[2]) for s in _fw["staged"])
                _fw_recon_section = (
                    "  SERVER/FRAMEWORK VALIDATION — the pinned server/"
                    "framework SOURCE is staged read-only at: "
                    f"{_fw_paths}. READ it (do NOT black-box the framework). "
                    "Find how a RESPONSE is serialized and what each sink is "
                    "validated against — header NAMES, header VALUES, the "
                    "body, and redirect targets are usually checked SEPARATELY "
                    "(quote the encode loop + the regex/check it applies, "
                    "file:line). Then DECIDE NOTHING FROM READING: a "
                    "validator's verdict MUST be execution-backed. You have "
                    "Bash — EXECUTE the actual check against the exact bytes an "
                    "attacker would inject, each sink separately. e.g. import "
                    "the staged module or copy the REAL pattern and run "
                    "`re.compile(<real pattern>).search(b'x\\r\\nInjected: 1')` "
                    "for a header-NAME payload, then again for a header-VALUE "
                    "payload. This section is INVALID unless it SHOWS, per sink, "
                    "the exact command you ran and its RAW output (a Match "
                    "object or None) — an assertion without shown execution does "
                    "NOT count (in a broad triage it is tempting to skim this "
                    "and read-infer; don't). A regex that 'looks' strict "
                    "routinely ACCEPTS your payload (a mis-bracketed or "
                    "unanchored class, a check on the wrong field). If you "
                    "genuinely cannot execute a check, label it "
                    "`UNVERIFIED — main must execute` — NEVER hand back a "
                    "read-only guess as a fact (main is told to start from "
                    "your reply, so a wrong 'blocked' verdict poisons it).\n"
                )
            recon_question = (
                "STATIC TRIAGE REQUEST (pre-flight for the main exploit writer).\n\n"
                f"SOURCE ROOT: {src_root}   (read-only)\n"
                + (f"REMOTE TARGET: {target_url}\n" if target_url else "")
                + "\n"
                "REPLY in ≤3 KB, as compact bullets, with these sections:\n"
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
                + _fw_recon_section
                + "  CANDIDATES   — ranked HIGH/MED/LOW with bug class + "
                "file:line. Bug classes: SQLi, XSS, SSRF, RCE, LFI, "
                "deserialization, JWT-misuse, path traversal, command "
                "injection. Quote the unsafe line.\n"
                "  DEFENSES → BYPASS — for EVERY input filter / WAF / "
                "sanitizer / encoder / parser the app applies before a "
                "sink: quote it (file:line) with the EXACT restriction "
                "(banned chars/words, allowed range) and name the library "
                "+ its EXACT pinned version. Then — you have WebSearch — "
                "list DOCUMENTED bypass primitives for THAT defense+version, "
                "ranked by applicability, WITH sources (CVE / advisory / "
                "writeup), and the viable EXFIL channel for the resulting "
                "primitive. A charset/word ban limits what an attacker can "
                "REPRESENT, not what they can EXECUTE once a sink fires: "
                "enumerate alternate-syntax / encoded-literal / runtime-"
                "decode channels — do NOT conclude 'char C banned ⇒ this "
                "technique is dead'. Sources + facts only; main does the "
                "crafting. (Omit only if the app applies NO input filtering "
                "at all — say so explicitly.)\n"
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
                model=model,  # report follows main's model (per-job)
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
                log_fn=lambda s: log_line(job_id, s),
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
