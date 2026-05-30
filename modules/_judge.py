"""Quality-gate judge for auto-run exploit/solver execution.

The judge is a stateful agent that wraps every `attempt_sandbox_run`:

  pre       — review the just-written script BEFORE the runner
              container starts.
  supervise — decide kill/continue when the running container has
              been silent for SUPERVISE_STALL_S while still alive
              (one-shot per run; conservative cost mode).
  post      — categorize the final exit_code + stdout + stderr and
              produce a retry-ready hint.

Same-job continuity: prejudge captures a `session_id`; supervise +
postjudge `resume` that session via `fork_session=False` so the judge
remembers what it warned about earlier in the run. Each stage is a
fresh `query()` call but the SDK loads the prior conversation from
the project-key directory under `~/.claude/projects/`.

Tools: Read · Bash · Glob · Grep · Agent — judge can verify by
Reading the script directly, doing a quick `python3 -m py_compile`
or `objdump`-style probe via Bash, or delegating heavy investigation
to the recon subagent. NO Write / Edit. Cost-disciplined: each stage
typically resolves in 1–3 tool calls.

All judge calls are best-effort. Judge auth/rate/empty failures fall
back to permissive defaults (prejudge ok=True, supervise
action=continue, postjudge verdict=unknown) so the runner is never
harder to use because of a flaky judge.

Public surface:
  * `prejudge_script(jd, script_rel, target, log_fn) → dict`
  * `supervise_run_once(jd, script_rel, stall_s, out_tail, err_tail, log_fn) → dict`
  * `postjudge_run(jd, script_rel, exit_code, stdout, stderr, log_fn,
                   *, extra_context="") → dict`
  * Internal `_session_state` (per-job session_id) is shared across
    all three so back-to-back calls within the same auto_run land in
    the same Claude session.
"""
from __future__ import annotations

import asyncio
import json
import re
import threading
from pathlib import Path
from typing import Any, Callable

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    SystemMessage,
    TextBlock,
    query,
)

from modules._common import (
    LATEST_JUDGE_MODEL,
    build_judge_agents,
    resolve_judge_model,
)
from modules.pwn import chain_schema


# ---------------------------------------------------------------------------
# Stage prompts
# ---------------------------------------------------------------------------

_PREJUDGE_USER_TMPL = """\
STAGE: prejudge

The orchestrator is about to spawn the runner container that executes
this script. Review it for issues that historically cause hangs,
parse mismatches, or wrong-target failures. Use Read on the script
itself if you want full source; use Bash for a quick `python3 -m
py_compile` or syntax probe. Only delegate to recon if you need to
verify a binary's actual prompt, libc symbol, or other heavy fact.

After you finish investigating, reply with EXACTLY ONE compact JSON
object on the FIRST line, no markdown, no commentary:
{{"ok": true|false, "severity": "low"|"med"|"high",
 "flag_likelihood": 0.0-1.0,
 "issues": ["...", "..."]}}

* ok=true means the script is safe to run as-is.
* severity=high blocks the run (orchestrator aborts before container
  start). low / med are advisory; the run still proceeds.
* flag_likelihood is YOUR honest estimate that THIS script (as
  written, no further edits) will capture the chal flag on the
  declared target. Float in [0.0, 1.0]. Calibrate aggressively:
    1.0  — guaranteed: read-only flag print, no exploit needed
    0.7  — solid exploit, all primitives verified, target matches,
           no parse risk
    0.4  — plausible exploit but at least one unverified primitive
           or noticeable parse / timing risk
    0.2  — script self-describes as partial / leak-only / probe /
           best-effort, OR depends on an explicitly missing prereq
           (e.g. "no libc leak", "no canary leak"), OR docstring
           hedges with "appears genuinely hard / could not discover
           / unlikely to capture"
    0.0  — script admits no working chain (e.g. rce_target is
           "not achieved", chain.json all-primitives-verified-false)
  Threshold 0.2: when flag_likelihood < 0.2 the orchestrator escalates
  to severity=high regardless of your `severity` field — running a
  guaranteed-fail sandbox cycle is pure waste. Be honest; the
  operator reads your number to decide /retry strategy.
* issues is a short list (≤6) of one-line findings.

Inputs:
  target          : {target}
  script_filename : {script_rel}
  cwd             : {cwd}

The script lives at `{script_path}`. Read it directly.
"""

_SUPERVISE_USER_TMPL = """\
STAGE: supervise

The runner container is still alive but has emitted no new
stdout/stderr for {stall_s} seconds. Decide whether to keep waiting
or kill it. You may Read the script to refresh your memory; you may
Bash a quick check (e.g. `grep -n recvuntil {script_path}` to count
unbounded reads). Don't delegate to recon here — supervise must be
fast.

Reply with EXACTLY ONE compact JSON object on the FIRST line, no
markdown:
{{"action": "kill"|"continue", "reason": "<short>"}}

Choose "kill" if the script is clearly stuck on a recvuntil/parse
mismatch, infinite loop, or otherwise will never produce output.
Choose "continue" if the silence looks legitimate (slow crypto,
network round-trip, sleep, or pwntools is buffering before its first
prompt).

=== last stdout (tail) ===
{stdout_tail}

=== last stderr (tail) ===
{stderr_tail}
"""

_POSTJUDGE_USER_TMPL = """\
STAGE: postjudge

The runner container has finished. Categorize the result and produce
a tight retry hint. You may Read the script + std{{out,err}} files
under `{cwd}` if you need more than the tail below; you may Bash
short verifications (e.g. grep stdout for flag patterns).

Reply with EXACTLY ONE compact JSON object on the FIRST line, no
markdown:
{{"verdict": "success"|"partial"|"hung"|"parse_error"|"network_error"|"crash"|"timeout"|"unknown",
 "summary": "<=200 chars",
 "retry_hint": "<=600 chars; empty when verdict==success or next_action==stop",
 "next_action": "continue"|"stop",
 "stop_reason": "<=200 chars; required when next_action==stop, else empty>",
 "failure_code": "<one of the heap codes below; OMIT or null when verdict==success or no heap code applies>",
 "what_worked": ["<=80 chars each, up to 3 items: parts of the chain that demonstrably succeeded — libc leak got a non-zero address, fastbin alloc returned, etc.>"],
 "what_failed": ["<=80 chars each, up to 3 items: the specific step that failed, with the observed signal (SIGSEGV at addr X, recvuntil timeout on 'Size:', abort msg, etc.)>"],
 "specific_diagnosis": "<=300 chars; one sentence pinpointing the failed line + the observed signal (e.g. 'exploit.py:42 sendlineafter waited for b\"> \" but service emits b\"> \\x1b[0m\" with ANSI; recv blocks then SDK timeout')",
 "alternative_paths": ["<=120 chars each, up to 3: techniques NOT yet tried that the observed state evidences could work (e.g. 'unsorted-bin attack on _IO_list_all', 'House of Orange via FILE struct overflow'). Empty list if exhaustively tried."]}}

next_action — judge's call on whether to feed retry_hint back to
main or halt the job. STOP is the AGGRESSIVE default whenever the
same broad failure pattern would repeat — every continue you authorize
costs the operator ~$5-15 in a 50-turn main retry, so be ruthless:

  continue — keep iterating. Use ONLY when:
             1. you have a CONCRETE, NARROW fix that main can apply
                in <10 lines of script edits (one offset value, one
                alignment mask, one missing timeout=, one swapped
                tube), AND
             2. the failure was a tactical bug in the chain (not a
                strategic mistake about which vuln class to use), AND
             3. NO prior retry hint in this job's history has already
                said the same thing (check `prior_hints` if attached
                to your context — if you see your own earlier wording
                even once, the answer is stop).
  stop     — finalize the job. Use whenever ANY of the following holds:
             (a) verdict == success (flag captured),
             (b) the failure is structural — wrong vuln class chosen,
                 chal needs a totally different technique, binary
                 doesn't match the published challenge, target
                 unreachable for reasons unrelated to the script,
             (c) the retry_hint you're about to write rhymes with one
                 you (or a prior judge turn) ALREADY produced this job
                 — even ONE similar hint is enough to stop. The
                 operator's /retry button is the right place to push
                 main onto a new approach; you cannot make main
                 abandon a wrong strategy by repeating yourself,
             (d) the artifact's own docstring / comments admit it's
                 a probe / partial / give-up shim with no real exploit
                 chain (main itself has concluded — don't override),
                 EXCEPT when main rejected a prior retry-hint based
                 on EMPIRICAL DISPROOF — disasm citation with file
                 + offset, OR a dynamic probe script (e.g.
                 tmp/probe_*.py) whose output contradicts a hint
                 assertion. In that case treat the hint as WRONG,
                 NOT main as defeated: classify as 'partial', set
                 retry_hint to acknowledge the disproof and propose
                 a path that AVOIDS the disproven assertion, and
                 only stop if no alternative remains. Operator
                 hints are best-effort guesses, not ground truth;
                 disasm + dynamic probe IS ground truth. Marking
                 evidence-based hint refusal as self-defeat
                 (observed on job de15654c8f39) silently penalizes
                 the correct behavior we want main to do,
             (e) main has already done ≥2 sandbox runs in this job
                 with the same broad outcome (empty leaks, same
                 SIGSEGV, same parse_error). Diminishing returns.

  Default to STOP when unsure. The /retry button gives the operator a
  fresh, intentional restart; auto-retry is for tightening a working
  exploit, not for fishing.
  stop_reason is REQUIRED on stop; it surfaces in run.log + meta.json
  so the operator knows why the loop halted without a flag.

Verdict guide:
  success       — a flag was clearly captured (FLAG{{}}/HTB{{}}/
                  DH{{}}/picoCTF{{}} or otherwise unambiguous).
  partial       — leak / intermediate result, no flag.
  hung          — supervise killed it (negative exit_code or
                  killed_by_supervise).
  parse_error   — recvuntil / format mismatch / wrong prompt.
  network_error — connection refused / DNS / TLS failure.
  crash         — unhandled exception or non-zero exit + traceback.
  timeout       — runner's own timeout fired.
  unknown       — none of the above.

failure_code (optional — populate ONLY for heap/FSOP-class scripts
when the failure shape clearly matches one of the codes below. Leave
null/omit for non-heap chals or generic bugs. The orchestrator
prepends a prescriptive fix snippet per code on top of your
retry_hint, so picking the right code makes the next attempt much
more targeted):

  heap.libc_version_mismatch       — script used worker libc paths
                                     (`/lib/x86_64-linux-gnu/libc.so.6`)
                                     or skipped `chal-libc-fix` entirely.
  heap.unaligned_libc_base         — leaked address used as libc base
                                     without `& 0xfff` validation; offsets
                                     evidently mismatched.
  heap.safe_linking_missing        — glibc>=2.32 chain wrote raw target
                                     into a freed chunk's fd (no XOR).
  heap.safe_linking_misapplied     — glibc<=2.31 chain applied the XOR
                                     mask (no safe-linking on that version).
  heap.hook_on_modern_libc         — `__free_hook` / `__malloc_hook` used
                                     on glibc>=2.34 (removed in 2.34).
  heap.str_finish_patched          — `_IO_str_jumps` __finish chain on
                                     glibc>=2.37 (path patched).
  heap.vtable_write_order_violated — FSOP vtable written before
                                     `_wide_data` / `_wide_vtable` /
                                     payload landed → SIGSEGV on next stdio.
  heap.tcache_key_not_bypassed     — double-free into tcache on glibc>=2.35
                                     without zeroing the chunk key first
                                     (aborts with `double free detected in tcache 2`).
  heap.aslr_unstable               — chain depends on nibble matching
                                     (1/16 or worse), no reconnect retry.
  heap.unaligned_tcache_target     — tcache poison target not 0x10-aligned
                                     (`unaligned tcache chunk detected`).
  heap.whitespace_in_address       — critical address contains \\x09/\\x0a/
                                     \\x0b/\\x0c/\\x0d/\\x20 and input path
                                     uses cin>> / getline → truncates.
  heap.interactive_in_sandbox      — `p.interactive()` after RCE inside
                                     the runner sandbox (no TTY → supervise
                                     kills it).
  heap.unbounded_recv              — recvuntil / recv / recvline missing
                                     explicit `timeout=` → hung forever
                                     on prompt mismatch.

retry_hint MUST be a single paragraph the next agent can act on
without seeing this judgment. Empty string when verdict==success.

Inputs:
  exit_code : {exit_code}
{extra_context}

=== stdout (tail) ===
{stdout_tail}

=== stderr (tail) ===
{stderr_tail}
"""


# ---------------------------------------------------------------------------
# Session-id continuity (per job, per process)
# ---------------------------------------------------------------------------
#
# Each auto_run cycle goes pre → (optional) supervise → post. Pre
# captures a session_id; supervise + post resume that session via
# `fork_session=False` so the judge's context is shared. We key the
# session map by job_id since one worker process can interleave
# multiple jobs (shouldn't happen with current orchestrator, but the
# state is cheap and dictionary-keyed by job_id is more robust than
# a global).

_session_lock = threading.Lock()
_session_ids: dict[str, str] = {}


def _remember_sid(job_id: str, sid: str | None) -> None:
    if not sid:
        return
    with _session_lock:
        _session_ids[job_id] = sid


def _recall_sid(job_id: str) -> str | None:
    with _session_lock:
        return _session_ids.get(job_id)


def _forget_sid(job_id: str) -> None:
    with _session_lock:
        _session_ids.pop(job_id, None)


# ---------------------------------------------------------------------------
# Async core — single Claude turn that may use tools.
# ---------------------------------------------------------------------------


async def _run_judge_turn(
    user_prompt: str,
    *,
    cwd: Path,
    resume_sid: str | None,
    model: str | None = None,
) -> tuple[str, str | None]:
    """Run a single judge turn (which may internally do multiple tool
    calls). Returns (final_text, captured_session_id).

    `model` makes the judge (and its spawned recon) FOLLOW the job's main
    model; when None it falls back to LATEST_JUDGE_MODEL. The same model is
    used for the judge session AND build_judge_agents (judge-spawned recon),
    so judge-recon tracks main too.

    Empty string + None on failure — judge errors are NEVER fatal.
    """
    _jm = model or LATEST_JUDGE_MODEL
    options = ClaudeAgentOptions(
        system_prompt=None,  # judge AgentDefinition prompt is loaded by SDK
        model=_jm,
        cwd=str(cwd),
        allowed_tools=["Read", "Bash", "Glob", "Grep", "Agent"],
        permission_mode="bypassPermissions",
        agents=build_judge_agents(_jm),
        resume=resume_sid,
        fork_session=False if resume_sid else None,
    )
    parts: list[str] = []
    captured_sid: str | None = None
    try:
        async for msg in query(prompt=user_prompt, options=options):
            if isinstance(msg, SystemMessage):
                # The init SystemMessage carries the new session's id.
                # Subsequent messages also have session_id; first one wins.
                sid = getattr(msg, "session_id", None) or (
                    msg.data.get("session_id") if hasattr(msg, "data") else None
                )
                if sid and not captured_sid:
                    captured_sid = sid
            elif isinstance(msg, AssistantMessage):
                for blk in msg.content:
                    if isinstance(blk, TextBlock):
                        parts.append(blk.text)
            elif isinstance(msg, ResultMessage):
                # ResultMessage also carries session_id as a fallback
                sid = getattr(msg, "session_id", None)
                if sid and not captured_sid:
                    captured_sid = sid
                if getattr(msg, "is_error", False):
                    return "", captured_sid
                break
    except Exception:
        return "", captured_sid

    return "".join(parts).strip()[:8000], captured_sid


def _run_async(coro):
    """Run an async coroutine from sync code, even if a parent loop is alive.

    The runner code path is sync (docker-py is sync). Most of the time
    asyncio.run() works; if the worker is already inside a running loop
    (e.g. an analyzer that awaited us), we fall back to a thread-isolated
    new loop so we never deadlock.
    """
    try:
        return asyncio.run(coro)
    except RuntimeError:
        result: dict[str, Any] = {}

        def _run():
            loop = asyncio.new_event_loop()
            try:
                result["v"] = loop.run_until_complete(coro)
            finally:
                loop.close()

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        t.join()
        return result.get("v", ("", None))


# ---------------------------------------------------------------------------
# JSON parsing + tail helpers
# ---------------------------------------------------------------------------


def _parse_json(text: str) -> dict:
    """Best-effort JSON extraction from a judge reply.

    Tolerates:
      * a plain JSON object as the entire reply,
      * a JSON object on the first non-empty line,
      * a JSON object inside a ```json fenced block.
    Returns {} on failure.
    """
    s = (text or "").strip()
    if not s:
        return {}
    try:
        d = json.loads(s)
        if isinstance(d, dict):
            return d
    except json.JSONDecodeError:
        pass
    if s.startswith("```"):
        body = s.split("\n", 1)[-1]
        if body.endswith("```"):
            body = body[:-3]
        try:
            d = json.loads(body.strip())
            if isinstance(d, dict):
                return d
        except json.JSONDecodeError:
            pass
    for line in s.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
            if isinstance(d, dict):
                return d
        except json.JSONDecodeError:
            continue
    return {}


def _truncate_tail(text: str, *, max_bytes: int) -> str:
    if not text:
        return ""
    b = text.encode("utf-8", errors="replace")
    if len(b) > max_bytes:
        b = b[-max_bytes:]
    return b.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Self-defeat detection (Phase 9 ship gate)
# ---------------------------------------------------------------------------
#
# Static regex check on the exploit script and report.md. Even when the
# LLM-driven prejudge ranks the run as `ok severity=low` because the
# script merely executes without crashing, we block ship when the
# artifacts themselves admit the chain has no working RCE path. Without
# this gate the runner spends $0.50–$2 on a sandbox + postjudge cycle
# that we already know cannot end in a flag (observed on job
# 4a6bd25a0d1d: report.md said "fundamental missing piece is the
# libc-leak primitive" and exploit docstring said "No write primitive
# identified; we can't reach hooks. Exit gracefully." — yet sandbox
# was still spun up).
#
# Patterns are case-insensitive and word-boundary anchored to minimise
# false positives. Generic encouragement like "we never give up" does
# NOT match because the trigger phrases are specific admissions ("no
# write primitive identified", "exit gracefully", etc.).

_SELF_DEFEAT_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE) for p in (
        r"\bno\s+(?:write|leak|rce|hook|chain|primitive)s?\s+"
        r"(?:identified|available|found|reachable|present)\b",
        r"\bcan'?t\s+reach\s+(?:the\s+)?(?:hook|libc|chain|rce|flag)s?\b",
        r"\bexit(?:ing)?\s+gracefully\b",
        r"\bunable\s+to\s+(?:leak|achieve|reach|exploit|capture)\b",
        r"\bbest[- ]case\s+only\s+logs?\b",
        r"\bfundamental(?:ly)?\s+(?:missing|blocked|impossible|unreachable)\b",
        r"\bno\s+(?:viable|working|known)\s+(?:chain|path|exploit)\b",
        r"\bchain\s+(?:incomplete|unfinished|partial)\b",
        # Patterns added 2026-05-22 after jobs 42845856644b /
        # 59ab9dfe2d2a / de15654c8f39 shipped with these admissions
        # but the existing set missed every one.
        r"\bchain\s+(?:blocked|halted|terminated|stops?)\s+at\b",
        r"\bintentionally\s+(?:halted|stopped|terminated|aborted)\b",
        r"\bgive[- ]up\s+(?:shim|probe|exploit|script|run)\b",
        r"\b(?:partial|leak)[- ]only\s+(?:result|chain|exploit|probe|shim)\b",
        r"\bcannot\s+pivot\s+to\b",
        r"\bstructurally\s+(?:blocked|impossible|unreachable|dead)\b",
        r"\b(?:SEGV|crash|abort)\s+(?:is\s+)?expected\b",
        r"\bflag\s+capture\s+(?:is\s+)?unlikely\b",
        # Patterns added 2026-05-23 after job 7f903a8e152b shipped
        # with these new wordings that the prior 16 missed:
        #   docstring  : "does NOT achieve full RCE"
        #   rce_target : "PARTIAL — libc leak only; no arb-write ..."
        #   chain_name : "libsalloc int-overflow + ... (partial)"
        r"\bdoes\s+not\s+achieve\b",
        # "(partial)" parenthetical anywhere in artifact (common when
        # main labels a chain partial in its title)
        r"\(\s*partial(?:\s*[-—:]\s*[a-z ]+)?\s*\)",
        # "PARTIAL — libc leak only" / "PARTIAL: leak only" — em-dash
        # not covered by ASCII-only \bpartial[- ]only\b above
        r"\bpartial\b\s*[—–-]\s*\w+\s+(?:leak|only)",
        # "leak only" / "libc leak only" as a phrase (no dash). The
        # earlier `\b(?:partial|leak)[- ]only\s+(?:result|chain|...)\b`
        # required a trailing noun; this catches the bare phrase.
        r"\b(?:libc\s+leak|leak)\s+only\b(?!\s*\w)",
        # "no arb-write" / "no arbitrary write" — main's common shorthand
        r"\bno\s+(?:arb|arbitrary)[- ]?write\b",
        # "infeasible in (sandbox|timeout|budget)"
        r"\binfeasible\s+in\s+(?:sandbox|timeout|budget|the\s+\w+)\b",
    )
)


def _resolve_work_dir(jd: Path) -> Path:
    """Resolve to the agent's actual work tree.

    `_runner.py:430` sets ``work_dir = Path("/data/jobs/<id>")`` (the job
    ROOT, not the work tree) and passes it straight to
    ``prejudge_script`` as ``jd``. The agent's artifacts live under
    ``{jd}/work/`` (chain.json, report.md, exploit.py, decomp/, …). Code
    here that previously looked at ``jd / "chain.json"`` or
    ``jd / "report.md"`` always missed (the files exist, just one
    directory deeper). This helper picks the work subdir when present
    so Phase 8 chain validation and Phase 9 self-defeat scan actually
    see the real artifacts. Verified across jobs 59ab9dfe2d2a,
    de15654c8f39, 42845856644b: ROOT/chain.json never exists,
    ROOT/work/chain.json always does.
    """
    wt = jd / "work"
    return wt if wt.is_dir() else jd


def _scan_self_defeat_sources(
    jd: Path, script: Path
) -> list[tuple[str, str]]:
    """Scan exploit + report.md for self-defeat admissions.

    Returns list of (source_name, matched_snippet). Snippets are
    trimmed so the operator can see which phrase tripped each pattern.
    """
    sources: list[tuple[str, Path]] = []
    if script.is_file():
        sources.append(("exploit", script))
    report_md = _resolve_work_dir(jd) / "report.md"
    if report_md.is_file():
        sources.append(("report", report_md))

    hits: list[tuple[str, str]] = []
    for src_name, src_path in sources:
        try:
            text = src_path.read_text(errors="ignore")
        except Exception:
            continue
        for pat in _SELF_DEFEAT_PATTERNS:
            for m in pat.finditer(text):
                snippet = m.group(0).strip()
                if len(snippet) > 80:
                    snippet = snippet[:77] + "..."
                hits.append((src_name, snippet))
    return hits


# ---------------------------------------------------------------------------
# Stage 1 — prejudge (NEW session)
# ---------------------------------------------------------------------------


def prejudge_script(
    jd: Path,
    script_rel: str,
    target: str | None,
    log_fn: Callable[[str], None],
    *,
    job_id: str | None = None,
) -> dict:
    """Static review of the about-to-run script.

    Starts a NEW judge session and stashes its session_id under
    `_session_ids[job_id]` so supervise + postjudge can resume it.
    `job_id` defaults to the job dir name (last path segment).
    """
    job_id = job_id or jd.name
    script = jd / script_rel
    if not script.is_file():
        log_fn(f"[judge] prejudge skipped — {script_rel} missing")
        return {"ok": True, "severity": "low", "issues": [], "raw": ""}

    user_prompt = _PREJUDGE_USER_TMPL.format(
        target=target or "(none)",
        script_rel=script_rel,
        cwd=jd,
        script_path=script,
    )
    raw, sid = _run_async(
        _run_judge_turn(
            user_prompt, cwd=jd, resume_sid=None,
            model=resolve_judge_model(job_id),
        )
    )
    _remember_sid(job_id, sid)
    parsed = _parse_json(raw)

    if not parsed:
        log_fn(
            "[judge] prejudge: no parseable JSON returned — "
            "running anyway (permissive default)"
        )
        return {"ok": True, "severity": "low", "issues": [], "raw": raw}

    ok = bool(parsed.get("ok", True))
    sev = str(parsed.get("severity") or ("low" if ok else "med")).lower()
    if sev not in ("low", "med", "high"):
        sev = "med"

    # Numeric flag-likelihood gate (Tier 1.7). LLM evaluates the same
    # signal the regex set tries to chase, but as a calibrated number
    # — so a new phrasing of "appears genuinely hard" doesn't slip
    # through the way regex patterns kept doing on jobs 4a6bd25a0d1d
    # → 96cd1092b992. Threshold 0.2: anything ≤ 0.2 means LLM itself
    # called the flag unreachable from this script as written, so a
    # sandbox cycle is guaranteed waste.
    fl_raw = parsed.get("flag_likelihood")
    flag_likelihood: float | None
    try:
        flag_likelihood = (
            None if fl_raw is None else float(fl_raw)
        )
    except (TypeError, ValueError):
        flag_likelihood = None
    if flag_likelihood is not None:
        flag_likelihood = max(0.0, min(1.0, flag_likelihood))

    raw_issues = parsed.get("issues") or []
    if not isinstance(raw_issues, list):
        raw_issues = [str(raw_issues)]
    issues = [str(x)[:200] for x in raw_issues][:6]

    # Phase 9 — self-defeat ship gate. Static regex pass on exploit +
    # report.md catches cases where the agent admits the chain has no
    # working RCE path. LLM judge sometimes ranks such runs "ok low"
    # because the script merely runs — but it cannot produce a flag,
    # so ship is blocked here regardless of the LLM verdict.
    sd_hits = _scan_self_defeat_sources(jd, script)
    if sd_hits:
        for src_name, snippet in sd_hits:
            issues.append(
                f"self-defeat in {src_name}: \"{snippet}\" — "
                f"agent admits no working chain"
            )
        # Raise cap from 6 → 10 so original LLM issues survive when
        # self-defeat appends; still bounded so log lines stay readable.
        issues = issues[:10]
        sev = "high"
        ok = False
        log_fn(
            f"[judge] prejudge SELF-DEFEAT: escalated severity=high "
            f"({len(sd_hits)} pattern match(es) — exploit/report "
            f"admit chain incomplete)"
        )

    # Phase 8 — chain.json structural validation. The ship-gate that
    # catches "chain step depends on an empirically-blocked primitive"
    # without paying a sandbox cycle to confirm. chain.json is optional
    # (advisory `med` if missing); when present, `critical` issues
    # force severity=high + ok=False, `high` issues are recorded but
    # don't auto-escalate (LLM's own severity stands).
    _chain_data, chain_issues = chain_schema.load_chain(_resolve_work_dir(jd))
    crit = [m for s, m in chain_issues if s == "critical"]
    hi = [m for s, m in chain_issues if s == "high"]
    med = [m for s, m in chain_issues if s == "med"]
    if crit:
        for m in crit:
            issues.append(f"chain.critical: {m}")
        # cap 10 → 12 so chain issues land without dropping LLM/self-defeat
        issues = issues[:12]
        sev = "high"
        ok = False
        log_fn(
            f"[judge] prejudge CHAIN-INVALID: escalated severity=high "
            f"({len(crit)} critical chain issue(s) — step depends on "
            f"empirically-blocked primitive or broken DAG)"
        )
    if hi:
        for m in hi:
            issues.append(f"chain.high: {m}")
        issues = issues[:12]
    if med:
        for m in med[:2]:
            issues.append(f"chain.note: {m}")
        issues = issues[:12]

    # Tier 1.7 #1 — flag_likelihood threshold gate. Runs LAST so the
    # regex / chain.json checks above can also raise severity; this
    # is the final escalation pass before logging the verdict.
    if flag_likelihood is not None and flag_likelihood < 0.2:
        issues.append(
            f"flag_likelihood={flag_likelihood:.2f} < 0.2 — LLM itself "
            f"evaluates this script as unable to capture the flag; ship "
            f"blocked to avoid sandbox-cost on a guaranteed-fail run"
        )
        issues = issues[:12]
        sev = "high"
        ok = False
        log_fn(
            f"[judge] prejudge LOW-LIKELIHOOD: escalated severity=high "
            f"(flag_likelihood={flag_likelihood:.2f})"
        )

    fl_str = (
        f" flag_likelihood={flag_likelihood:.2f}"
        if flag_likelihood is not None else ""
    )
    log_fn(
        f"[judge] prejudge ok={ok} severity={sev}{fl_str} "
        f"issues={len(issues)}"
    )
    for it in issues:
        log_fn(f"[judge] prejudge issue: {it}")

    return {
        "ok": ok, "severity": sev, "issues": issues,
        "flag_likelihood": flag_likelihood, "raw": raw,
    }


# ---------------------------------------------------------------------------
# Stage 2 — supervise (resumes prejudge session)
# ---------------------------------------------------------------------------


def supervise_run_once(
    jd: Path,
    script_rel: str,
    stall_seconds: int,
    stdout_tail: str,
    stderr_tail: str,
    log_fn: Callable[[str], None],
    *,
    job_id: str | None = None,
) -> dict:
    """One-shot stall decision. Resumes the prejudge session so the judge
    sees its prior warnings while making the kill/continue call.
    """
    job_id = job_id or jd.name
    script = jd / script_rel
    user_prompt = _SUPERVISE_USER_TMPL.format(
        stall_s=stall_seconds,
        script_path=script,
        stdout_tail=_truncate_tail(stdout_tail, max_bytes=4096) or "(empty)",
        stderr_tail=_truncate_tail(stderr_tail, max_bytes=4096) or "(empty)",
    )
    raw, sid = _run_async(
        _run_judge_turn(
            user_prompt, cwd=jd, resume_sid=_recall_sid(job_id),
            model=resolve_judge_model(job_id),
        )
    )
    _remember_sid(job_id, sid)
    parsed = _parse_json(raw)

    action = str(parsed.get("action") or "continue").lower()
    if action not in ("kill", "continue"):
        action = "continue"
    reason = str(parsed.get("reason") or "")[:400]

    log_fn(f"[judge] supervise action={action} reason={reason[:200]}")
    return {"action": action, "reason": reason, "raw": raw}


# ---------------------------------------------------------------------------
# Stage 3 — postjudge (resumes the same session, then forgets)
# ---------------------------------------------------------------------------


_VALID_VERDICTS = {
    "success", "partial", "hung", "parse_error",
    "network_error", "crash", "timeout", "unknown",
}

# Heap-specific failure codes the postjudge may emit. The orchestrator
# uses these in `_format_postjudge_user_turn` to prepend a prescriptive
# fix snippet ahead of the model-authored retry_hint. Keep this in sync
# with HEAP_FIX_HINTS in modules._common.
_VALID_HEAP_FAILURE_CODES = {
    "heap.libc_version_mismatch",
    "heap.unaligned_libc_base",
    "heap.safe_linking_missing",
    "heap.safe_linking_misapplied",
    "heap.hook_on_modern_libc",
    "heap.str_finish_patched",
    "heap.vtable_write_order_violated",
    "heap.tcache_key_not_bypassed",
    "heap.aslr_unstable",
    "heap.unaligned_tcache_target",
    "heap.whitespace_in_address",
    "heap.interactive_in_sandbox",
    "heap.unbounded_recv",
}


def _normalize_verdict(parsed: dict) -> dict:
    """Single source of truth for the postjudge state machine.

    Maps a raw (model-authored, possibly malformed) judgment JSON to the
    normalized fields the orchestrator + retry pipeline rely on, enforcing
    every invariant in ONE place (previously these were scattered across
    three success-collapse sites in postjudge_run). See
    docs/judge_state_machine.md for the transition table.

    Invariants:
      verdict      — model value if ∈ _VALID_VERDICTS, else 'unknown'.
      next_action  — 'stop' iff verdict==success or model said 'stop';
                     else 'continue' (the default when omitted).
      stop_reason  — '' unless next_action=='stop'; auto 'flag captured'
                     when success and model left it empty.
      failure_code — model value if ∈ _VALID_HEAP_FAILURE_CODES, else None.
      success-collapse — verdict==success forces the failure-side fields
                     empty (retry_hint, failure_code, what_failed,
                     alternative_paths, specific_diagnosis).
    """
    def _coerce_list(key: str, max_items: int, item_cap: int) -> list[str]:
        raw_v = parsed.get(key)
        if not isinstance(raw_v, list):
            return []
        out: list[str] = []
        for item in raw_v[:max_items]:
            if isinstance(item, str):
                trimmed = item.strip()
                if trimmed:
                    out.append(trimmed[:item_cap])
        return out

    verdict = str(parsed.get("verdict") or "unknown").lower()
    if verdict not in _VALID_VERDICTS:
        verdict = "unknown"
    is_success = verdict == "success"

    summary = str(parsed.get("summary") or "")[:400]
    retry_hint = "" if is_success else str(parsed.get("retry_hint") or "")[:1200]

    # next_action — continue is the default when omitted (legacy / parse
    # failure), so existing behavior is preserved. success auto-implies stop.
    raw_next = parsed.get("next_action")
    candidate_next = raw_next.strip().lower() if isinstance(raw_next, str) else ""
    if is_success:
        next_action = "stop"
    elif candidate_next in ("continue", "stop"):
        next_action = candidate_next
    else:
        next_action = "continue"

    stop_reason = str(parsed.get("stop_reason") or "")[:400]
    if next_action != "stop":
        stop_reason = ""
    elif is_success and not stop_reason:
        stop_reason = "flag captured"

    # Heap failure code is optional. Reject anything outside the known set
    # so a model-typoed code can't leak into the prescriptive-hint lookup.
    raw_code = parsed.get("failure_code")
    failure_code: str | None = None
    if isinstance(raw_code, str):
        candidate = raw_code.strip().lower()
        if candidate in _VALID_HEAP_FAILURE_CODES:
            failure_code = candidate
    if is_success:
        failure_code = None

    what_worked = _coerce_list("what_worked", max_items=3, item_cap=120)
    what_failed = _coerce_list("what_failed", max_items=3, item_cap=120)
    alternative_paths = _coerce_list("alternative_paths", max_items=3, item_cap=200)
    raw_diag = parsed.get("specific_diagnosis")
    specific_diagnosis = (
        str(raw_diag).strip()[:400] if isinstance(raw_diag, str) else ""
    )
    if is_success:
        # Success collapses these — nothing failed, nothing alternative.
        what_failed = []
        alternative_paths = []
        specific_diagnosis = ""

    return {
        "verdict": verdict,
        "summary": summary,
        "retry_hint": retry_hint,
        "next_action": next_action,
        "stop_reason": stop_reason,
        "failure_code": failure_code,
        "what_worked": what_worked,
        "what_failed": what_failed,
        "specific_diagnosis": specific_diagnosis,
        "alternative_paths": alternative_paths,
    }


def postjudge_run(
    jd: Path,
    script_rel: str,
    exit_code: int,
    stdout: str,
    stderr: str,
    log_fn: Callable[[str], None],
    *,
    extra_context: str = "",
    job_id: str | None = None,
) -> dict:
    """Categorize a finished run and produce a retry hint.

    Resumes the session opened by prejudge so the verdict can reference
    the issues judge flagged earlier. Drops the session_id from the
    in-memory map after (post is the last stage).
    """
    job_id = job_id or jd.name
    out_t = _truncate_tail(stdout, max_bytes=8000)
    err_t = _truncate_tail(stderr, max_bytes=4000)

    user_prompt = _POSTJUDGE_USER_TMPL.format(
        exit_code=exit_code,
        extra_context=(extra_context or "").rstrip(),
        cwd=jd,
        stdout_tail=out_t or "(empty)",
        stderr_tail=err_t or "(empty)",
    )
    raw, sid = _run_async(
        _run_judge_turn(
            user_prompt, cwd=jd, resume_sid=_recall_sid(job_id),
            model=resolve_judge_model(job_id),
        )
    )
    _remember_sid(job_id, sid)
    parsed = _parse_json(raw)

    # All verdict/next_action/stop_reason/failure_code + success-collapse
    # invariants live in one place now. See docs/judge_state_machine.md.
    norm = _normalize_verdict(parsed)
    verdict = norm["verdict"]
    summary = norm["summary"]
    retry_hint = norm["retry_hint"]
    next_action = norm["next_action"]
    stop_reason = norm["stop_reason"]
    failure_code = norm["failure_code"]
    what_worked = norm["what_worked"]
    what_failed = norm["what_failed"]
    alternative_paths = norm["alternative_paths"]
    specific_diagnosis = norm["specific_diagnosis"]

    log_fn(
        f"[judge] postjudge verdict={verdict} next_action={next_action} "
        f"summary={summary[:160]}"
    )
    if next_action == "stop" and stop_reason:
        log_fn(f"[judge] postjudge stop_reason={stop_reason[:200]}")
    if failure_code:
        log_fn(f"[judge] postjudge failure_code={failure_code}")
    if specific_diagnosis:
        log_fn(f"[judge] postjudge diagnosis={specific_diagnosis[:200]}")
    if retry_hint:
        log_fn(f"[judge] postjudge retry_hint={retry_hint[:200]}")

    # Last stage — release session bookkeeping for this job_id.
    _forget_sid(job_id)

    return {
        "verdict": verdict,
        "summary": summary,
        "retry_hint": retry_hint,
        "next_action": next_action,
        "stop_reason": stop_reason,
        "failure_code": failure_code,
        "what_worked": what_worked,
        "what_failed": what_failed,
        "specific_diagnosis": specific_diagnosis,
        "alternative_paths": alternative_paths,
        "raw": raw,
    }
