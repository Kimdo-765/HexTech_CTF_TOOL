"""Quality-gate judge for auto-run exploit/solver execution.

The judge is a stateful agent that wraps `attempt_sandbox_run` when
this job's effective mode gates it (`_runner._judge_mode_for_job`):

  pre       — review the just-written script BEFORE the runner
              container starts.
  post      — categorize the final exit_code + stdout + stderr and
              produce a retry-ready hint.

  supervise — kill/continue on a container that has been silent for
              SUPERVISE_STALL_S while still alive. Implemented here,
              but NOT driven in this release: it is excluded from v1
              enforce and `attempt_sandbox_run` passes
              `enable_supervise=False` unconditionally. It is the one
              stage no replay can evaluate (its evidence is a live
              container's stalled output) and the only one that kills.

Same-job continuity: prejudge captures a `session_id`; the later
stage(s) `resume` that session via `fork_session=False` so the judge
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
from dataclasses import dataclass, field
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
    kill_guard_hooks,
    resolve_judge_model,
)
from modules.pwn import chain_schema


@dataclass
class JudgeTurnResult:
    """What one judge turn produced, including WHY it produced nothing.

    The previous return type was ``(text, session_id)``, and every failure
    path collapsed to ``("", sid)``. That is enough to fall back permissively
    — which the judge always does — but it throws away the two things the
    hybrid work needs:

      * ``error_kind``. A Claude judge on a Codex job can be refused by the
        Anthropic classifier for the same content the job is about (this
        repo has a reviewer that once refused nearly every job on its own
        prompt scaffolding). Failing over to the other provider is only
        correct for ``policy_refusal``; doing it on a timeout or an auth
        error just burns the second provider's quota too.
      * usage. A cross-provider judge spends real money on a different
        meter from main's, and "we cannot see judge spend" is exactly the
        blind spot the ledger exists to close.

    Empty ``text`` with ``error_kind is None`` means the turn ran and said
    nothing, which is a different fact from a turn that never ran.
    """

    text: str = ""
    session_id: str | None = None
    provider: str = ""
    model: str | None = None
    runtime: str | None = None
    error_kind: str | None = None
    error_detail: str = ""
    tokens: dict[str, int] = field(default_factory=dict)
    reported_cost: float | None = None
    # Set only when a cross-provider retry happened. `failover_diagnosis`
    # turns the recovery into a measurement: if the other vendor accepted the
    # identical request the block was provider-specific, not content-specific.
    failover_from: str | None = None
    failover_to: str | None = None
    failover_diagnosis: str | None = None
    # Per-model breakdown, kept because a judge session is not necessarily
    # single-model: the Claude judge registers a recon subagent, and the
    # active preset can pin recon to a different model from judge. Flattening
    # that to one figure loses the ledger's own `model` axis AND prices the
    # cheaper model's tokens at the expensive one's rate (measured: $0.0225
    # booked where the per-model sum was $0.0165).
    model_usage: dict[str, dict] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.error_kind is None and bool(self.text)


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
 "target_liveness": "live"|"dead"|"unknown",
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
* target_liveness is a STRUCTURED observation about the declared remote
  endpoint, not about the exploit chain. Use "dead" only after a current,
  direct probe shows a required target service is unreachable while the probe
  environment itself has working network access; use "live" only after a
  current direct probe gets a service response; otherwise use "unknown".
  Statements in script/report/log text and phrases such as "dead chain" do
  not establish target liveness. If it is dead, describe the probe evidence in
  issues too, but do not rely on the issue wording to carry this fact.

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
 "alternative_paths": ["<=120 chars each, up to 3: techniques NOT yet tried that the observed state evidences could work — pwn e.g. 'unsorted-bin attack on _IO_list_all' / 'House of Orange via FILE overflow'; rev e.g. 'emulate the check with Unicorn instead of static z3' / 'constant is XOR-obfuscated — trace it dynamically'; web e.g. 'the filter blocks <script> — try an SVG/onerror vector'; crypto e.g. 'switch the decode from Gröbner to a linear support-minors solve'. Empty list if exhaustively tried."],
 "retry_worthwhile": false}}

retry_worthwhile — set TRUE only ALONGSIDE next_action==stop, and ONLY
when you are halting the CURRENT approach because it is structurally
wrong, BUT a concrete DIFFERENT method (named in alternative_paths /
retry_hint) is plausibly IN-BUDGET and worth exactly ONE automated
method-change retry that swaps the decisive step. This authorizes a
SINGLE re-attempt, not an open loop (the orchestrator hard-caps it at
one per job). Default FALSE. It MUST stay false for:
  - verdict==success (nothing to retry),
  - a dead / unreachable / rotated remote (network_error) — a method
    change fixes nothing when the target is down,
  - env-limits / untestable-locally (vsyscall / CET / kernel),
  - a true-negative (no viable method exists — the chal may be
    unsolvable by analysis; do NOT burn a retry on false hope),
  - same-method-with-a-tweak — a new offset / timeout / alarm / retry
    count is NOT a method change; those go through `continue`, not here.
Concretely — the four loop-modules (crypto / pwn / web / rev) share this
ONE auto-retry (misc/forensic are one-shot and never reach postjudge):
  · crypto — a Sage Gröbner that blows the per-round budget where a
    linearization / support-minors / FGLM / reduced-variable model is the
    in-budget alternative.
  · pwn — a heap chain whose failure_code is heap.hook_on_modern_libc
    (__free_hook/__malloc_hook on glibc>=2.34 where they're removed) or
    heap.str_finish_patched (_IO_str vtable patched >=2.37), where the
    version-correct FSOP chain (_IO_wfile_jumps overflow -> _IO_wdoallocbuf)
    is the in-budget alternative. Rebuilding the fake FILE/_wide_data/vtable
    is a NEW decisive step, NOT a <10-line edit -> here, not continue.
  · web — an IDENTIFIED blocker (a named WAF rule, a framework-version
    patch, a charset/length filter you pinpointed) provably defeats the
    current injection / deserialization / SSRF class, but a different
    REACHABLE class evades it. ("maybe try another class" with NO identified
    blocker is a guess, not a method change — that stays a plain stop.)
  · rev — a NAMED anti-static feature (VM/handler dispatch, opaque
    predicates, self-modifying code, a packer) defeats the static /
    constraint-solving approach, so dynamic instrumentation / emulation is
    the viable decisive method (or vice-versa). ("static is just stuck" with
    no named cause is NOT this.)
GENERAL RULE: whenever a structured failure_code — or your own diagnosis —
NAMES a version-correct, in-budget alternative that needs a DIFFERENT
decisive step, that is the canonical retry_worthwhile=true case. If you are
only swapping a constant / offset / endianness / timeout, that is
`continue`, NOT this. When unsure, prefer FALSE — the one retry is a scarce
resource and a wrong method-change burns a full main turn + sandbox.

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
#
# The session id is stored WITH the provider that issued it, and recall only
# returns it to that same provider. A session id is a handle into one vendor's
# store; handing a Codex id to the Claude SDK resumes nothing and, worse,
# looks like it should. Once a stage fails over, the rest of the job's judge
# stages stay on the provider that answered — a run that alternates providers
# mid-cycle has no shared context at all, which is the one thing prejudge ->
# supervise -> postjudge continuity exists to provide.

_session_lock = threading.Lock()
_session_ids: dict[str, dict[str, str]] = {}


def _remember_sid(job_id: str, sid: str | None, provider: str | None = None) -> None:
    """Store this job's judge session id together with its provider.

    A missing sid still records the provider when one is given: that is how a
    failover pins the remaining stages even if the answering provider returned
    no resumable session.
    """
    p = str(provider or "").strip().lower()
    if not sid and not p:
        return
    with _session_lock:
        entry = dict(_session_ids.get(job_id) or {})
        if p:
            if entry.get("provider") and entry["provider"] != p:
                # Provider changed: the old id belongs to the old vendor.
                entry.pop("session_id", None)
            entry["provider"] = p
        if sid:
            entry["session_id"] = sid
        _session_ids[job_id] = entry


def _recall_sid(job_id: str, provider: str | None = None) -> str | None:
    """This job's judge session id, but only for the provider that issued it."""
    with _session_lock:
        entry = _session_ids.get(job_id) or {}
    if not entry:
        return None
    p = str(provider or "").strip().lower()
    if p and entry.get("provider") and entry["provider"] != p:
        return None
    return entry.get("session_id")


def _pinned_provider(job_id: str) -> str | None:
    """Provider this job's judge is pinned to, if a stage already answered."""
    with _session_lock:
        return (_session_ids.get(job_id) or {}).get("provider") or None


def _forget_sid(job_id: str) -> None:
    with _session_lock:
        _session_ids.pop(job_id, None)


# ---------------------------------------------------------------------------
# Async core — single Claude turn that may use tools.
# ---------------------------------------------------------------------------


def _usage_from_result(msg: Any) -> tuple[dict[str, int], float | None, dict[str, dict]]:
    """(tokens, reported_cost) from any provider's ResultMessage.

    All three adapters mirror the SDK shape, so one reader covers them. The
    SDK's own ``model_usage`` is preferred over the streamed ``usage`` for the
    same reason `agent_heartbeat` prefers it: pricing those totals reproduces
    the reported cost to the cent.
    """
    tokens: dict[str, int] = {}
    per_model: dict[str, dict] = {}
    try:
        from modules._common import _tokens_from_model_usage

        mu = getattr(msg, "model_usage", None)
        if isinstance(mu, dict):
            tokens = _tokens_from_model_usage(mu) or {}
            # Keep the split as well as the total. Same normalisation, one
            # model at a time, so the ledger can carry a row per model.
            for name, raw in mu.items():
                if not isinstance(raw, dict):
                    continue
                one = _tokens_from_model_usage({name: raw})
                if one:
                    per_model[str(name)] = one
        if not tokens:
            usage = getattr(msg, "usage", None)
            if isinstance(usage, dict):
                from modules._common import _TOKEN_KEYS

                tokens = {
                    k: int(usage[k])
                    for k in _TOKEN_KEYS
                    if isinstance(usage.get(k), (int, float))
                    and not isinstance(usage.get(k), bool)
                    and usage[k]
                }
    except Exception:
        tokens, per_model = {}, {}
    cost = getattr(msg, "total_cost_usd", None)
    if not isinstance(cost, (int, float)) or isinstance(cost, bool):
        cost = None
    return tokens, cost, per_model


# Stored detail cap. Classification NEVER runs on the truncated string — a
# real refusal arriving after 1000 characters of normal output was measured
# being cut away and misfiled as a generic agent_error.
_DETAIL_MAX_CHARS = 2000

# `stop_reason` values that name the failure CATEGORY themselves.
#
# ENUMERATED from all three adapters rather than added one at a time — adding
# them piecemeal is what produced the last defect here: `codex_cli`'s values
# were mapped, `grok_acp`'s `eof` and `max_tokens` were not, and both fell
# through to prose and were poisoned by an earlier analysis that happened to
# mention a usage policy. Sources:
#   codex_cli     completed process_error timeout unexpected_eof turn_failed error
#   grok_acp      eof error process_error timeout  (+ cancelled max_tokens in its
#                 own is_error set)
#   gpt_responses api_error completed max_tool_rounds refusal timeout
_STOP_REASON_KIND = {
    "timeout": "timeout",
    "process_error": "transport_error",
    "unexpected_eof": "transport_error",
    "eof": "transport_error",
    "cancelled": "killed",
    "canceled": "killed",
    # A budget ceiling is a limit, not a refusal and not a transport fault.
    "max_tokens": "agent_error",
    "max_tool_rounds": "agent_error",
}

# Failure fields across the three adapters. `errors` is a LIST on the Claude
# SDK ResultMessage and is where its parser puts the wire's error payload;
# reading only scalars dropped it entirely. `stop_reason` is what GPT and Grok
# carry — neither has `result` at all.
def _structured_failure_bits(msg: Any) -> list[str]:
    """Shared extraction — see modules._common.structured_failure_bits()."""
    from modules._common import structured_failure_bits

    return structured_failure_bits(msg)


def _error_detail(msg: Any, parts: list[str]) -> str:
    """Failure detail from wherever THIS adapter actually puts it.

    Reading only ``.result`` was wrong for two of the three backends: the GPT
    and Grok ``ResultMessage`` contracts have no such field at all
    (gpt_responses.py / grok_acp.py — both carry ``stop_reason``), so every
    failure arrived as an empty string and classified as the generic
    `agent_error`. A refusal and a timeout became indistinguishable, which is
    exactly the distinction stage 4's failover turns on.

    The cause is not lost, just carried elsewhere: the Codex CLI emits turn
    failure / process error / timeout detail as ASSISTANT text before the
    error Result, and Grok does the same for ACP errors — so the text already
    accumulated in `parts` is a first-class source, not a fallback.
    """
    bits = _structured_failure_bits(msg)
    text = "".join(parts).strip()
    if text:
        bits.append(text)
    return " | ".join(bits)[:_DETAIL_MAX_CHARS]


def _classify(detail: str, fallback: str) -> str:
    """Map an error string to an error_kind, defaulting to `fallback`.

    `policy_refusal` is the only kind stage 4 fails over on, so mislabelling
    a transport blip as one would send a healthy job to the other provider,
    and mislabelling a refusal as transport would leave the AUP class stuck
    exactly where it is today.
    """
    try:
        from modules._common import classify_agent_error

        kind = classify_agent_error(detail or "")
    except Exception:
        return fallback
    # `classify_agent_error` answers "unknown" rather than None when nothing
    # matched, so `or fallback` is dead code — every unrecognised transport
    # error came back tagged "unknown", which tells stage 4 nothing about
    # WHERE it happened. Treat it as "not classified" and keep the caller's
    # more specific tag.
    return fallback if kind in (None, "", "unknown") else kind


def classify_failure(msg: Any, parts: list[str], fallback: str) -> tuple[str, str]:
    """(error_kind, detail) for a failed turn, structured signal FIRST.

    Joining every source into one blob and classifying that was wrong in both
    directions at once, and the two failures share a cause: prose and
    structured fields were treated as interchangeable.

      * A real refusal was HIDDEN. The blob was truncated to a fixed length
        before classification, so a turn that produced 1000+ characters of
        normal output before the server's block pushed the block's own words
        past the cut — measured `agent_error` on text whose tail said
        "violates our usage policy". Failover would not fire for the exact
        case it exists for.
      * A generic failure was POISONED. A judge analysing a challenge that
        mentions a usage policy, followed by an unrelated `process_error`,
        classified as `policy_refusal` — a spurious failover on a broken pipe.

    So: structured sources are authoritative and are classified alone, before
    any prose is consulted. `stop_reason` then names the CATEGORY for adapter
    failures that carry no message of their own. Only the ambiguous kinds
    (`turn_failed`, `refusal` — where the body carries the reason) fall
    through to prose, and prose is read newest-first because the adapters emit
    the failure detail as the LAST assistant message before the error result.

    Classification always runs on the FULL text; truncation is for storage.
    """
    from modules._common import classify_result_failure

    return classify_result_failure(msg, parts, fallback)


def _record_judge_usage(job_id: str, stage: str, res: JudgeTurnResult) -> None:
    """Ledger rows for one judge turn — ONE PER MODEL, keyed by stage.

    Judge spend was invisible before this: `meta.cost_usd` is main's session
    and `summary["cost_usd"]` is subagents, so a cross-provider judge burned a
    second vendor's meter with nothing recording it. Best-effort — accounting
    must never break the gate it is accounting for, and the judge in
    particular is designed so that every failure falls back permissively.

    `stage` is prejudge / supervise / postjudge: supervise fires repeatedly
    within one run, so a role-only ledger would say "judge is expensive"
    without saying which part.

    A judge turn is not necessarily single-model. The Claude judge registers a
    recon subagent and the active preset can pin recon to a different model,
    so the SDK's `model_usage` can carry two. Folding that into one row lost
    the ledger's own `model` axis and priced the cheaper model's tokens at the
    expensive one's rate — measured $0.0225 booked where the per-model sum was
    $0.0165.

    A REPORTED cost is a session figure and cannot be split across models
    without inventing the split, so it stays whole on the primary model's row
    and the other rows carry tokens with no dollars. The bucket then sums to
    the reported total rather than to a fabricated one, and `usd_complete`
    says out loud that not every row could be priced.
    """
    try:
        from modules._common import estimate_cost_from_tokens, model_rates_are_known
        from modules.usage_ledger import codex_window_snapshot, record_usage_by_model

        record_usage_by_model(
            job_id,
            role="judge",
            stage=stage,
            provider=res.provider,
            primary_model=res.model,
            model_usage=res.model_usage,
            tokens=res.tokens,
            reported_cost=res.reported_cost,
            estimate_for=estimate_cost_from_tokens,
            rates_known=model_rates_are_known,
            gpt_runtime=res.runtime,
            window_for=lambda: codex_window_snapshot(cached_only=True),
            error_kind=res.error_kind,
            # The failover diagnosis is only worth producing if it survives
            # the process that produced it. In-memory it dies with the run.
            extra={
                "failover_from": res.failover_from,
                "failover_diagnosis": res.failover_diagnosis,
            },
        )
    except Exception:
        pass


def _with_failover(out: dict, turn: JudgeTurnResult) -> dict:
    """Attach the turn's transport facts to a stage's public verdict.

    The diagnosis is only worth producing if it outlives the call that made
    it. It goes on the ledger row for accounting and here for the caller —
    postjudge's dict is what the retry logic reads, so a failover that is
    invisible there is a failover nobody can act on.

    `error_kind` rides along for the same reason, and it is the more important
    of the two. Every stage normalises a missing answer into a permissive
    default — postjudge into `verdict="unknown"`, prejudge into `ok=True` —
    which is correct for the RUN (a judge failure must not block a job) and
    indistinguishable from a real verdict for anything trying to MEASURE the
    judge. Stage 3 put `error_kind` on `JudgeTurnResult` for exactly this and
    it stopped at the boundary; a shadow replay counted `auth_error` as an
    `unknown` opinion. Every stage returns through here, so it is one place.
    """
    if turn.error_kind:
        out["error_kind"] = turn.error_kind
        if turn.error_detail:
            out["error_detail"] = turn.error_detail
    if turn.failover_diagnosis:
        out["fallback_used"] = True
        out["failover_from"] = turn.failover_from
        # The TARGET that was tried, not the provider of whichever result we
        # ended up returning. When both blocked we return the original, and
        # reading its provider reported a failover to the place it came from.
        out["failover_to"] = turn.failover_to or turn.provider
        out["failover_diagnosis"] = turn.failover_diagnosis
    return out


def _judge_model_for(provider: str, requested: str | None) -> str:
    """Judge model for `provider`, honouring THAT provider's active preset.

    `resolve_judge_model()` runs before the provider is known, against the
    job's own backend — so a judge routed (or failed over) to another provider
    arrives holding a model from the wrong family. Coercing that to the
    target's *global default* is what the code did, and it silently ignored
    the target's active preset: a GPT preset pinning judge to `gpt-5.6-terra`
    was never consulted, on either the primary or the failover path.

    So: keep a same-family request as-is, and otherwise resolve the target's
    own role preset before falling back to its global default.
    """
    from modules.agent_provider import (
        coerce_model_for_provider,
        default_model_for,
        is_claude_model_id,
        is_gpt_model_id,
        is_grok_model_id,
    )

    p = str(provider or "").strip().lower()
    m = str(requested or "").strip()
    same_family = bool(m) and (
        (p == "gpt" and is_gpt_model_id(m))
        or (p == "grok" and is_grok_model_id(m))
        or (p == "claude" and is_claude_model_id(m))
    )
    if same_family:
        return m

    fallback = default_model_for(p) or (LATEST_JUDGE_MODEL if p == "claude" else "")
    try:
        from modules.model_presets import resolve_role_model

        resolved = resolve_role_model("judge", fallback, p)
    except Exception:
        resolved = fallback
    return coerce_model_for_provider(resolved or fallback, p)


def _failover_target(provider: str) -> str | None:
    """Shared provider policy — see agent_provider.failover_target()."""
    from modules.agent_provider import failover_target

    return failover_target(provider)


def _attempt(
    user_prompt: str,
    *,
    cwd: Path,
    resume_sid: str | None,
    model: str | None,
    provider: str,
) -> JudgeTurnResult:
    """One judge attempt that NEVER raises (bar KeyboardInterrupt / SystemExit).

    The exception boundary belongs HERE, at the attempt, not around the public
    stage function — for three reasons that only show up at this level:

      * Every stage function goes through it, so none of them propagates
        or leaves zero ledger rows. (That includes `supervise`, which is
        implemented but not driven — see the module header.)
      * The provider is already known. A catch further out has to re-guess it,
        and in a failover it guesses WRONG: an exception from the alternate
        was attributed to the provider the primary ran on.
      * The primary's row is written after the failover decision, so an
        alternate that raised took the primary's refusal row down with it.
        The primary's result now survives its partner's failure.
    """
    try:
        return _run_async(
            _run_judge_turn(
                user_prompt,
                cwd=cwd,
                resume_sid=resume_sid,
                model=model,
                provider_override=provider,
            )
        )
    except (Exception, asyncio.CancelledError) as exc:
        # CancelledError derives from BaseException, so `except Exception`
        # left the one failure most likely during a shutdown or a wall-clock
        # kill escaping a box whose whole contract is "never raises" — and
        # taking the ledger row with it. KeyboardInterrupt and SystemExit are
        # deliberately NOT caught: those mean the process is going away, and
        # a best-effort gate has no business detaining them.
        detail = f"{type(exc).__name__}: {exc}"
        return JudgeTurnResult(
            provider=provider,
            session_id=resume_sid,
            error_kind=_classify(detail, "cancelled"
                                 if isinstance(exc, asyncio.CancelledError)
                                 else "transport_error"),
            error_detail=detail[:500] or type(exc).__name__,
        )


def judge_turn(
    user_prompt: str,
    *,
    cwd: Path,
    job_id: str,
    stage: str,
    resume: bool,
    model: str | None = None,
) -> JudgeTurnResult:
    """One judge stage, with a single cross-provider retry on a policy block.

    This is the destination the AUP recovery ladder never had. The failure it
    cures is specific and documented in this repo: a server-side classifier
    blocks the call over the challenge's own content, and re-running the same
    request on the same vendor blocks again — a fresh session does not cure
    it. The other vendor's classifier is a different classifier.

    Deliberately narrow:

      * ONLY `policy_refusal` retries. A timeout or an auth failure means the
        second provider would be burned for nothing, and stage 3 exists to
        tell those apart.
      * ONE retry, never a loop.
      * The retry starts a FRESH session. A session id is a handle into one
        vendor's store; there is nothing to resume across the boundary.
      * On success the job's remaining judge stages are PINNED to the
        answering provider. Alternating mid-cycle would leave prejudge ->
        supervise -> postjudge with no shared context, which is the whole
        reason that continuity exists.

    Both turns are recorded to the ledger. The refused one still cost tokens,
    and hiding it would make a failover look free.
    """
    from modules.agent_provider import provider_for_role

    pinned = _pinned_provider(job_id)
    primary = pinned or provider_for_role(job_id, "judge")
    # Resolved HERE, against the provider actually about to run: a session id
    # only means something to the vendor that issued it.
    resume_sid = _recall_sid(job_id, primary) if resume else None

    res = _attempt(
        user_prompt, cwd=cwd, resume_sid=resume_sid,
        model=model, provider=primary,
    )

    # Ledger writes are deferred to AFTER the failover decision. The diagnosis
    # is a property of the whole event, and recording the first turn before
    # the second has run leaves a row that can never carry it — the two turns
    # are back to back, so nothing meaningful is at risk in the gap.
    if res.error_kind != "policy_refusal":
        _record_judge_usage(job_id, stage, res)
        _remember_sid(job_id, res.session_id, res.provider or primary)
        return res

    target = _failover_target(res.provider or primary)
    if not target:
        res.error_detail = (
            (res.error_detail or "") + " | no failover target configured"
        ).strip(" |")
        _record_judge_usage(job_id, stage, res)
        return res

    alt = _attempt(
        user_prompt, cwd=cwd,
        resume_sid=None,   # never resume across the provider boundary
        model=None,        # let the target's own default/preset decide
        provider=target,
    )
    # Turning the recovery into a measurement costs nothing and answers a
    # question this repo has had to guess at before: when the reviewer refused
    # nearly every job, the cause was its OWN prompt scaffolding rather than
    # the artifacts. If the other vendor accepts the identical request, the
    # block was provider-specific, not content-specific.
    diagnosis = (
        "provider_specific" if alt.error_kind is None else
        "content_or_prompt" if alt.error_kind == "policy_refusal" else
        "inconclusive"
    )
    origin = res.provider or primary
    res.failover_from = alt.failover_from = origin
    res.failover_to = alt.failover_to = target
    res.failover_diagnosis = alt.failover_diagnosis = diagnosis
    _record_judge_usage(job_id, stage, res)
    _record_judge_usage(job_id, stage, alt)

    if alt.error_kind is None:
        _remember_sid(job_id, alt.session_id, alt.provider or target)
        return alt

    # The second provider failed too. Keep the ORIGINAL result as the answer —
    # the callers' permissive fallbacks are written against it — but carry the
    # diagnosis so the operator can see both were tried.
    res.error_detail = (
        f"{res.error_detail} | failover to {target}: "
        f"{alt.error_kind}: {alt.error_detail}"
    )[:_DETAIL_MAX_CHARS]
    return res


async def _run_judge_turn(
    user_prompt: str,
    *,
    cwd: Path,
    resume_sid: str | None,
    model: str | None = None,
    provider_override: str | None = None,
) -> JudgeTurnResult:
    """Run a single judge turn (which may internally do multiple tool
    calls). Returns a `JudgeTurnResult` — text, session id, and WHY the turn
    produced nothing when it did.

    Backend follows the job's ``agent_provider`` (Settings / meta):
      * claude — Claude Agent SDK ``query()`` (historical path; session
        continuity via ``resume`` / project-key under ``~/.claude``)
      * grok   — ``GrokACPClient`` with ``JUDGE_AGENT_PROMPT`` so
        prejudge/supervise/postjudge never burn Claude quota on a Grok job
      * gpt    — Codex CLI OAuth (or explicit Responses API fallback)

    `model` follows the job's main model family via ``resolve_judge_model``;
    when None it falls back to LATEST_JUDGE_MODEL (Claude) or the Grok
    default. Judge errors are NEVER fatal — a failed turn returns an empty
    `text` and the callers fall back permissively, exactly as before.
    """
    from modules.agent_provider import (
        coerce_model_for_provider,
        default_model_for,
        normalize_provider,
        provider_for_role,
    )

    job_id = Path(cwd).name
    # The judge is the first role to actually consult the per-role map that
    # stage 1 added; before this it followed the job provider like everything
    # else. `provider_override` is the failover path handing us the other
    # backend for one retry.
    provider = (
        normalize_provider(provider_override)
        if provider_override
        else provider_for_role(job_id, "judge")
    )
    _jm = _judge_model_for(provider, model)
    res = JudgeTurnResult(provider=provider, model=_jm, session_id=resume_sid)

    # ---- OpenAI GPT path --------------------------------------------------
    if provider == "gpt":
        try:
            from modules.gpt_agent import (
                GptAgentClient,
                GptSessionOptions,
                AssistantMessage as GptAssistantMessage,
                ResultMessage as GptResultMessage,
            )
            from modules._prompts import JUDGE_AGENT_PROMPT
        except Exception as exc:
            res.error_kind = "import_error"
            res.error_detail = f"{type(exc).__name__}: {exc}"
            return res
        if not _jm or str(_jm).lower().startswith(("claude", "grok")):
            _jm = default_model_for("gpt")
        res.model = _jm
        try:
            from modules.agent_provider import get_gpt_runtime

            res.runtime = get_gpt_runtime()
        except Exception:
            pass
        opts = GptSessionOptions(
            system_prompt=JUDGE_AGENT_PROMPT,
            model=_jm,
            cwd=str(cwd),
            resume=resume_sid,
            effort="medium",
            env={"JOB_ID": job_id, "AGENT_ROLE": "judge"},
            enable_tools=True,
            enable_subagents=False,
        )
        parts: list[str] = []
        captured_sid: str | None = resume_sid
        try:
            async with GptAgentClient(opts) as client:
                await client.query(user_prompt)
                async for msg in client.receive_response():
                    if isinstance(msg, GptAssistantMessage):
                        for blk in (getattr(msg, "content", None) or []):
                            t = getattr(blk, "text", None)
                            if t:
                                parts.append(t)
                    elif isinstance(msg, GptResultMessage):
                        captured_sid = getattr(msg, "session_id", None) or captured_sid
                        res.session_id = captured_sid
                        res.tokens, res.reported_cost, res.model_usage = _usage_from_result(msg)
                        if getattr(msg, "is_error", False):
                            res.error_kind, res.error_detail = classify_failure(
                                msg, parts, "agent_error")
                            return res
                        break
        except Exception as exc:
            res.session_id = captured_sid
            res.error_detail = f"{type(exc).__name__}: {exc}"
            res.error_kind = _classify(res.error_detail, "transport_error")
            return res
        res.session_id = captured_sid
        res.text = "".join(parts).strip()[:8000]
        return res

    # ---- Grok path: full ACP session (tools available like Claude judge) --
    if provider == "grok":
        try:
            from modules.grok_acp import (
                GrokACPClient,
                GrokSessionOptions,
                AssistantMessage as GrokAssistantMessage,
                ResultMessage as GrokResultMessage,
            )
            from modules._prompts import JUDGE_AGENT_PROMPT
        except Exception as exc:
            res.error_kind = "import_error"
            res.error_detail = f"{type(exc).__name__}: {exc}"
            return res
        if not _jm or str(_jm).lower().startswith("claude"):
            _jm = default_model_for("grok")
        res.model = _jm
        opts = GrokSessionOptions(
            system_prompt=JUDGE_AGENT_PROMPT,
            model=_jm,
            cwd=str(cwd),
            resume=resume_sid,
            effort="medium",
            env={"JOB_ID": job_id, "AGENT_ROLE": "judge"},
        )
        parts: list[str] = []
        captured_sid: str | None = None
        try:
            async with GrokACPClient(opts) as client:
                captured_sid = client.session_id
                await client.query(user_prompt)
                async for msg in client.receive_response():
                    if isinstance(msg, GrokAssistantMessage):
                        for blk in (getattr(msg, "content", None) or []):
                            t = getattr(blk, "text", None)
                            if t:
                                parts.append(t)
                    elif isinstance(msg, GrokResultMessage):
                        sid = getattr(msg, "session_id", None)
                        if sid and not captured_sid:
                            captured_sid = sid
                        res.session_id = captured_sid
                        res.tokens, res.reported_cost, res.model_usage = _usage_from_result(msg)
                        if getattr(msg, "is_error", False):
                            res.error_kind, res.error_detail = classify_failure(
                                msg, parts, "agent_error")
                            return res
                        break
        except Exception as exc:
            res.session_id = captured_sid
            res.error_detail = f"{type(exc).__name__}: {exc}"
            res.error_kind = _classify(res.error_detail, "transport_error")
            return res
        res.session_id = captured_sid
        res.text = "".join(parts).strip()[:8000]
        return res

    # ---- Claude path (historical) ----------------------------------------
    options = ClaudeAgentOptions(
        system_prompt=None,  # judge AgentDefinition prompt is loaded by SDK
        model=_jm,
        cwd=str(cwd),
        allowed_tools=["Read", "Bash", "Glob", "Grep", "Agent"],
        permission_mode="bypassPermissions",
        agents=build_judge_agents(_jm),
        resume=resume_sid,
        fork_session=False if resume_sid else None,
        # Bash kill-guard only (the anti-writeup web-research block was removed
        # 2026-07-22 — kill_guard_hooks no longer denies WebSearch/WebFetch).
        hooks=kill_guard_hooks(),
    )
    parts = []
    captured_sid = None
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
                res.session_id = captured_sid
                res.tokens, res.reported_cost, res.model_usage = _usage_from_result(msg)
                if getattr(msg, "is_error", False):
                    res.error_kind, res.error_detail = classify_failure(
                        msg, parts, "agent_error")
                    return res
                break
    except Exception as exc:
        res.session_id = captured_sid
        res.error_detail = f"{type(exc).__name__}: {exc}"
        res.error_kind = _classify(res.error_detail, "transport_error")
        return res

    res.session_id = captured_sid
    res.text = "".join(parts).strip()[:8000]
    return res


def _run_async(coro):
    """Run an async coroutine from sync code, even if a parent loop is alive.

    The runner code path is sync (docker-py is sync). Most of the time
    asyncio.run() works; if the worker is already inside a running loop
    (e.g. an analyzer that awaited us), we fall back to a thread-isolated
    new loop so we never deadlock.
    """
    # Decide by ASKING, before running — not by reading the message of an
    # exception afterwards. Message matching had two failure modes and they
    # were mirror images: a coroutine whose own RuntimeError happened to say
    # "running event loop" was re-awaited (turning its real error into
    # "cannot reuse already awaited coroutine"), and any other RuntimeError
    # from the coroutine had been swallowed as a loop conflict. The question
    # "is a loop running in THIS thread" has a direct answer.
    try:
        asyncio.get_running_loop()
        loop_is_running = True
    except RuntimeError:
        loop_is_running = False

    if not loop_is_running:
        return asyncio.run(coro)

    result: dict[str, Any] = {}
    error: dict[str, BaseException] = {}

    def _run():
        loop = asyncio.new_event_loop()
        try:
            result["v"] = loop.run_until_complete(coro)
        except BaseException as inner:      # noqa: BLE001 — re-raised below
            error["e"] = inner
        finally:
            loop.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join()
    if "e" in error:
        # Surfacing it lets the attempt boundary classify and bill it;
        # swallowing it here produced a silent empty answer.
        raise error["e"]
    return result["v"]


# ---------------------------------------------------------------------------
# JSON parsing + tail helpers
# ---------------------------------------------------------------------------


def _parse_json(text: str, *, expected_keys: tuple[str, ...] = ()) -> dict:
    """Best-effort JSON extraction from a judge reply.

    Tolerates:
      * a plain JSON object as the entire reply,
      * a JSON object on the first non-empty line,
      * a JSON object inside a ```json fenced block.
      * a complete JSON object surrounded by prose.
    When ``expected_keys`` is provided, embedded objects without any
    stage-specific key are ignored and the last non-nested matching object in
    a boundary tier wins. Judge replies normally put schema examples and
    planning prose before the operative answer, so key-count scoring would let
    a verbose empty template beat a shorter real decision.
    Returns {} on failure.
    """
    s = (text or "").strip()
    if not s:
        return {}
    try:
        d = json.loads(s)
        if isinstance(d, dict) and (
            not expected_keys or any(key in d for key in expected_keys)
        ):
            return d
    except json.JSONDecodeError:
        pass
    if s.startswith("```"):
        body = s.split("\n", 1)[-1]
        if body.endswith("```"):
            body = body[:-3]
        try:
            d = json.loads(body.strip())
            if isinstance(d, dict) and (
                not expected_keys or any(key in d for key in expected_keys)
            ):
                return d
        except json.JSONDecodeError:
            pass
    decoder = json.JSONDecoder()

    def _best_at(starts) -> dict:
        best: dict = {}
        consumed_until = -1
        for start in starts:
            # A later opening brace can belong to the object already selected.
            # It is a child candidate, not a later top-level decision.
            if start < consumed_until:
                continue
            try:
                d, end = decoder.raw_decode(s, start)
            except json.JSONDecodeError:
                continue
            if not isinstance(d, dict):
                continue
            if not expected_keys:
                return d
            if any(key in d for key in expected_keys):
                best = d
                consumed_until = end
        return best

    # Preserve the original high-confidence boundary: a decision beginning at
    # the start of a line is more likely to be the requested answer than an
    # inline schema example. Rank *all* such objects, though — returning the
    # first one lets a line-boundary schema example beat the operative verdict
    # below. Within a tier, the last non-nested stage-shaped object is the
    # final answer.
    line_starts = (
        match.end() - 1 for match in re.finditer(r"(?m)^[ \t]*\{", s)
    )
    line_object = _best_at(line_starts)
    if line_object:
        return line_object

    # A tool-using judge can also put a multiline object in the middle of prose.
    # Decode every possible boundary and use the stage schema to reject
    # unrelated artifact objects. The last non-nested matching object wins for
    # the same schema-before-answer ordering used by the line-boundary tier.
    return _best_at(i for i, char in enumerate(s) if char == "{")


def _truncate_tail(text: str, *, max_bytes: int) -> str:
    if not text:
        return ""
    b = text.encode("utf-8", errors="replace")
    if len(b) > max_bytes:
        b = b[-max_bytes:]
    return b.decode("utf-8", errors="replace")


POSTJUDGE_STDOUT_BYTES = 8000
POSTJUDGE_STDERR_BYTES = 4000


def postjudge_inputs(stdout: str, stderr: str) -> dict:
    """Exactly what postjudge consumes from a run's output. Nothing more.

    Two different reductions happen inside `postjudge_run`, and a recorder
    that keeps "the output, shortened" reproduces neither:

      * the PROMPT gets the TAIL — the last 8000/4000 **bytes**. Keeping the
        head instead hands the judge the start of a long run and drops the
        end, which is where a capture appears.
      * the placeholder override scans the WHOLE output for flag shapes and
        can downgrade a `success` verdict on what it finds. Feed it a tail and
        it sees a different set.

    Returning both from one place is what keeps a recorder honest: it stores
    this dict, and `postjudge_run` accepts every field of it back.
    """
    from modules._common import FLAG_RE

    return {
        "stdout_tail": _truncate_tail(stdout, max_bytes=POSTJUDGE_STDOUT_BYTES),
        "stderr_tail": _truncate_tail(stderr, max_bytes=POSTJUDGE_STDERR_BYTES),
        "flag_shapes": sorted(set(FLAG_RE.findall(f"{stdout}\n{stderr}"))),
        "stdout_bytes": len((stdout or "").encode("utf-8", errors="replace")),
        "stderr_bytes": len((stderr or "").encode("utf-8", errors="replace")),
    }


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


_PREJUDGE_ISSUE_CAP = 12


def _merge_prejudge_issues(llm: list[str], static: list[str]) -> list[str]:
    """Merge issue lists so no GATE's cause is lost to another's volume.

    A single trailing cap looked simpler than the staged 6 -> 10 -> 12 caps it
    replaced, and silently changed behaviour: twelve self-defeat matches ate
    the whole budget and `chain.critical` — a different, independently
    blocking cause — vanished from the verdict entirely. The operator then
    reads "blocked: self-defeat" and never learns the chain was also invalid.

    So the budget is allocated by CAUSE, round-robin, before it is spent:
    every family that has something to say gets a line before any family gets
    a second one. Ordering within the result keeps the blocking causes first.
    """
    def family(issue: str) -> str:
        for prefix in ("self-defeat", "chain.critical", "chain.high", "chain.note"):
            if issue.startswith(prefix):
                return prefix
        return "llm"

    groups: dict[str, list[str]] = {}
    # Blocking causes are listed before advisory ones; `llm` sits between so a
    # model's own finding is not buried under chain notes.
    order = ["self-defeat", "chain.critical", "llm", "chain.high", "chain.note"]
    for issue in list(static) + list(llm):
        groups.setdefault(family(issue), []).append(str(issue)[:200])

    out: list[str] = []
    while len(out) < _PREJUDGE_ISSUE_CAP:
        took = False
        for name in order:
            bucket = groups.get(name)
            if not bucket:
                continue
            out.append(bucket.pop(0))
            took = True
            if len(out) >= _PREJUDGE_ISSUE_CAP:
                break
        if not took:
            break
    return out


def deterministic_prejudge(jd: Path, script: Path, log_fn) -> dict:
    """The prejudge gates that need NO model, run on their own.

    These are the ship-blockers that do not depend on a judge answering: a
    static scan for the agent admitting its own chain has no working path,
    and structural validation of chain.json. They were written INSIDE the
    branch that handles a parseable LLM verdict, so a judge that failed to
    answer — blocked, timed out, returned prose — skipped them entirely and
    the run shipped on a permissive default.

    That is backwards. A judge failure should lose the judge's OPINION, not
    the checks that never needed one.

    Returns the public verdict shape so the caller can merge, and escalates
    ONLY: a static gate can turn ok into not-ok, never the reverse.
    """
    issues: list[str] = []
    ok = True
    sev = "low"

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
    if med:
        for m in med[:2]:
            issues.append(f"chain.note: {m}")

    return {"ok": ok, "severity": sev, "issues": issues}


def prejudge_blocks_ship(prejudge: dict | None) -> bool:
    """Would THIS prejudge verdict stop the sandbox from starting?

    The contract this file hands the judge says severity=high blocks and
    low/med are advisory — the run proceeds. `ok=False` alone therefore does
    NOT block, and anything that counts it as a block (an operator rollup, a
    confusion matrix) turns advisory findings into false positives.

    It lives here, next to the prompt that defines it, because two callers
    need the same answer: the runner that acts on it and the shadow rollup
    that reports what the runner WOULD have done. Asked separately, those two
    drift — and a drifted shadow measures something the gate never did.
    """
    if not prejudge:
        return False
    return (not prejudge.get("ok")) and str(prejudge.get("severity") or "").lower() == "high"


def postjudge_would_retry(verdict: dict | None) -> bool:
    """Would THIS postjudge verdict have cost the job another attempt?

    `next_action` never takes the value "retry". `_normalize_verdict` clamps it
    to exactly {"continue", "stop"} — a model that answers "retry" is coerced
    to "continue" — so any rollup comparing against "retry" is a constant
    False, which is what `would_have_retried` was.

    The loop's real rule, read from `_common.py`:

      * "stop" halts, EXCEPT the one-shot method-change conversion: a STOP with
        `retry_worthwhile` and either a hint or `alternative_paths`, on a
        verdict that is not `network_error`, is turned into a continue and
        spends exactly one retry.
      * anything else re-queries the agent with the hint — but a verdict with
        no `retry_hint` is the loop's natural exit, so it costs nothing.

    Answered for a FRESH budget: the loop also caps method-change retries at
    one per job and has an overall attempt ceiling, and neither is a property
    of the verdict.
    """
    v = verdict or {}
    hint = str(v.get("retry_hint") or "").strip()
    if str(v.get("next_action") or "continue").lower() == "stop":
        return bool(
            v.get("retry_worthwhile")
            and (hint or (v.get("alternative_paths") or []))
            and v.get("verdict") != "network_error"
        )
    return bool(hint)


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
        return {
            "ok": True, "severity": "low", "issues": [], "raw": "",
            "target_liveness": "unknown",
        }

    user_prompt = _PREJUDGE_USER_TMPL.format(
        target=target or "(none)",
        script_rel=script_rel,
        cwd=jd,
        script_path=script,
    )
    # BEFORE the judge call, not after it. "Runs whether or not the judge
    # answered" was only true for a judge that RETURNED — a wrapper that
    # raised (transport, auth, a bug in the failover path) escaped past the
    # gates entirely, and the runner turns that exception into ok=True /
    # severity=low. A run whose own artifact admits the chain is incomplete
    # then went to the sandbox because a network call failed.
    static = deterministic_prejudge(jd, script, log_fn)

    try:
        turn = judge_turn(
            user_prompt, cwd=jd, job_id=job_id, stage="prejudge",
            resume=False, model=resolve_judge_model(job_id),
        )
    except Exception as exc:
        # The static verdict survives (that was the point of moving the gates
        # above this call) — but the CAUSE has to survive with it. Swallowing
        # the exception here re-opened the hole stage 3 closed: `error_kind`
        # exists to tell "ran and said nothing" from "never ran", and a
        # wrapper that raised is emphatically the second. It also has to reach
        # the ledger, or a judge that burned tokens before dying bills nothing.
        detail = f"{type(exc).__name__}: {exc}"
        kind = _classify(detail, "transport_error")
        try:
            from modules.agent_provider import provider_for_role

            _p = _pinned_provider(job_id) or provider_for_role(job_id, "judge")
        except Exception:
            _p = ""
        _record_judge_usage(
            job_id, "prejudge",
            JudgeTurnResult(provider=_p, error_kind=kind, error_detail=detail[:500]),
        )
        log_fn(
            f"[judge] prejudge: judge call raised ({detail}) — static gates "
            f"stand (ok={static['ok']} severity={static['severity']}), "
            f"error_kind={kind}"
        )
        return {
            **static,
            "issues": _merge_prejudge_issues([], static["issues"]),
            "target_liveness": "unknown",
            "raw": "",
            # The runner's own error-preservation branch is no longer reached
            # now that this catch exists, so the fields it looked for are
            # carried here instead of vanishing.
            "error": detail[:500],
            "error_kind": kind,
        }
    raw, sid = turn.text, turn.session_id

    parsed = _parse_json(
        raw,
        expected_keys=(
            "ok", "severity", "flag_likelihood", "target_liveness", "issues",
        ),
    )

    if not parsed:
        log_fn(
            "[judge] prejudge: no parseable JSON returned — "
            f"falling back to the static gates alone "
            f"(ok={static['ok']} severity={static['severity']} "
            f"issues={len(static['issues'])})"
        )
        return _with_failover(
            {**static,
             "issues": _merge_prejudge_issues([], static["issues"]),
             "target_liveness": "unknown",
             "raw": raw}, turn)

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

    # A8: keep remote liveness as a typed fact from the prejudge that made the
    # observation.  The orchestrator must never infer it later from prose in an
    # issue: real issue text also contains phrases such as "terminal links
    # dead" and "NOT a blocker", which describe the chain rather than the
    # endpoint and have produced both false positives and false negatives.
    target_liveness = str(parsed.get("target_liveness") or "unknown").lower()
    if target_liveness not in ("live", "dead", "unknown"):
        target_liveness = "unknown"

    raw_issues = parsed.get("issues") or []
    if not isinstance(raw_issues, list):
        raw_issues = [str(raw_issues)]
    issues = [str(x)[:200] for x in raw_issues][:6]

    # Merge the static gates. They ESCALATE only — a model that says "ok" can
    # be overruled by a regex that found the agent admitting no working chain,
    # never the other way round.
    if static["issues"]:
        issues = _merge_prejudge_issues(issues, static["issues"])
    if not static["ok"]:
        ok = False
    if static["severity"] == "high":
        sev = "high"

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

    return _with_failover({
        "ok": ok, "severity": sev, "issues": issues,
        "flag_likelihood": flag_likelihood,
        "target_liveness": target_liveness,
        "raw": raw,
    }, turn)


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
    turn = judge_turn(
        user_prompt, cwd=jd, job_id=job_id, stage="supervise",
        resume=True, model=resolve_judge_model(job_id),
    )
    raw, sid = turn.text, turn.session_id
    parsed = _parse_json(raw, expected_keys=("action", "reason"))

    action = str(parsed.get("action") or "continue").lower()
    if action not in ("kill", "continue"):
        action = "continue"
    reason = str(parsed.get("reason") or "")[:400]

    log_fn(f"[judge] supervise action={action} reason={reason[:200]}")
    return _with_failover({"action": action, "reason": reason, "raw": raw}, turn)


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

    # retry_worthwhile — judge opt-in for ONE automated method-change retry.
    # Meaningful ONLY alongside a non-success STOP: the judge is halting the
    # CURRENT approach as structurally doomed, but a concrete DIFFERENT method
    # (named in alternative_paths / retry_hint) is plausibly in-budget and
    # worth exactly one automated attempt that swaps the decisive step. Default
    # False so its ABSENCE == today's terminal-stop behavior (no regression);
    # forced False on success and on any next_action != stop. The orchestrator
    # caps this at one method-change retry per job (see the auto-retry loop).
    # Strict `is True` (not bool()): matches the membership-checked validation
    # of verdict / next_action / failure_code above, and fails SAFE — a
    # stringified-truthy model value ("false" / "no" / "0", which json.loads
    # leaves as a truthy str) must NOT flip this opt-in on. Only a real JSON
    # `true` qualifies.
    retry_worthwhile = (
        parsed.get("retry_worthwhile") is True
        and next_action == "stop"
        and not is_success
    )

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
        "retry_worthwhile": retry_worthwhile,
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
    flag_shapes: list[str] | None = None,
) -> dict:
    """Categorize a finished run and produce a retry hint.

    Resumes the session opened by prejudge so the verdict can reference
    the issues judge flagged earlier. Drops the session_id from the
    in-memory map after (post is the last stage).
    """
    job_id = job_id or jd.name
    out_t = _truncate_tail(stdout, max_bytes=POSTJUDGE_STDOUT_BYTES)
    err_t = _truncate_tail(stderr, max_bytes=POSTJUDGE_STDERR_BYTES)

    user_prompt = _POSTJUDGE_USER_TMPL.format(
        exit_code=exit_code,
        extra_context=(extra_context or "").rstrip(),
        cwd=jd,
        stdout_tail=out_t or "(empty)",
        stderr_tail=err_t or "(empty)",
    )
    turn = judge_turn(
        user_prompt, cwd=jd, job_id=job_id, stage="postjudge",
        resume=True, model=resolve_judge_model(job_id),
    )
    raw, sid = turn.text, turn.session_id
    parsed = _parse_json(
        raw,
        expected_keys=(
            "verdict", "next_action", "summary", "retry_hint", "stop_reason",
            "failure_code", "what_worked", "what_failed", "specific_diagnosis",
            "alternative_paths", "retry_worthwhile",
        ),
    )

    # All verdict/next_action/stop_reason/failure_code + success-collapse
    # invariants live in one place now. See docs/judge_state_machine.md.
    norm = _normalize_verdict(parsed)

    # Placeholder-only success guard — a deterministic override of the LLM
    # verdict (same philosophy as the prejudge self-defeat / flag_likelihood
    # gates). If postjudge called this a success but EVERY flag-shape in the
    # trusted run output is a placeholder (DH{fake_flag} / a local-test seed),
    # the "capture" is fake: job dc981a8c4741's postjudge stopped on the local
    # replica's DH{fake_flag} without ever grabbing the real remote flag.
    #
    # POSITIVE detection only — gated on there BEING a flag-shape whose entries
    # are ALL placeholders. A real odd-format flag the scanner would miss (no
    # shape, no marker) leaves _run_shapes empty → success stands, so this can
    # never turn a scan false-negative into a retry loop.
    #
    # Downgrade to a TERMINAL STOP (verdict!=success, next_action=stop, EMPTY
    # retry_hint), NOT a `continue`: re-running the same exploit against the
    # same target just re-reads the same placeholder, and with the cost-cap
    # backstop disabled a `continue`+hint could spin placeholder→continue→…
    # until the (loose) wall-clock. An empty retry_hint is the auto-retry
    # loop's "no actionable hint" natural exit (run_main_agent_session's
    # `if not retry_hint: return`), so this halts deterministically and routes
    # the operator to fix the target and /retry — exactly dc981's real fix.
    if norm["verdict"] == "success":
        from modules._common import FLAG_RE as _FRE, _is_placeholder_flag as _isph
        # `flag_shapes`, when given, is the set scanned from the FULL output
        # at the time it existed. A caller replaying a recorded run has only
        # the tails left, and re-deriving from those would consult a smaller
        # string than the live gate did — the verdict would differ for a
        # reason that has nothing to do with the judge.
        _run_shapes = (set(flag_shapes) if flag_shapes is not None
                       else set(_FRE.findall(f"{stdout}\n{stderr}")))
        if _run_shapes and not any(
            not _isph(s, trusted=True) for s in _run_shapes
        ):
            log_fn(
                "[judge] postjudge SUCCESS->stop: every flag-shape in the run "
                f"output is a placeholder ({sorted(_run_shapes)}) — not a real "
                "capture; halting (remote likely down / wrong target)"
            )
            norm["verdict"] = "partial"
            norm["next_action"] = "stop"
            norm["stop_reason"] = (
                "Only a PLACEHOLDER flag (e.g. DH{fake_flag}, a local-test "
                "seed) was reachable — not the real challenge flag. The remote "
                "is likely down or the target is wrong; fix the target and "
                "/retry."
            )
            norm["retry_hint"] = ""

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
    retry_worthwhile = norm["retry_worthwhile"]

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

    return _with_failover({
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
        "retry_worthwhile": retry_worthwhile,
        "raw": raw,
    }, turn)
