"""Retry-with-hint endpoint.

Given an existing job whose exploit/solver failed (or finished without a
flag), spin up a quick reviewer turn on the selected agent provider that:

1. Reads the original description, run.log, exploit.py / solver.py,
   their stdout/stderr, plus module-relevant source files.
2. Writes a compact, evidence-labelled retry plan that distinguishes a
   broken implementation from a broken strategy and requires novel,
   falsifiable hypotheses when the prior chain itself is unproven.

Then enqueue a new job in the same module with that hint appended to
the original description. The user gets back the new job_id and can
watch it like any other job.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import stat
import time
from pathlib import Path

from claude_agent_sdk import (
    project_key_for_directory,
)
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from api.queue import get_queue, hard_timeout_for, resolve_timeout
from api.storage import (
    JOBS_DIR,
    job_dir,
    new_job_id,
    parse_targets,
    read_job_meta,
    write_job_meta,
)
from modules._common import resolve_reviewer_model
from modules.reviewer import (
    LATEST_REVIEWER_MODEL,
    RUN_LOG_CONTEXT_CHARS,
    ReviewerError,
    _API_ERROR_PATTERNS,
    _CONTINUABLE_MODULES,
    _HINT_REPLACEMENTS,
    _REVIEWER_MAX_THINKING_TOKENS,
    _REVIEWER_PROMPT,
    _REVIEWER_WALL_CLOCK_S,
    _REVIEW_SOURCE_CANDIDATES,
    _REVIEW_SOURCE_LIMIT,
    _ask_reviewer,
    _ask_reviewer_gpt,
    _ask_reviewer_grok,
    _RETRYABLE_MODULES,
    _ask_reviewer_streaming,
    _ask_reviewer_with_failover,
    _diagnose_reviewer_text,
    _frame_reviewer_context,
    _gather_context,
    _iter_reviewer_messages,
    _looks_like_api_error,
    _public_hint,
    _record_reviewer_usage,
    _resume_id_for_active_provider,
    _reviewer_error_kind,
    _reviewer_provider_and_model,
    _sanitize_hint,
    _stream_reviewer_once,
)
from modules.settings_io import apply_to_env, get_setting


router = APIRouter()


_CLAUDE_HOME = Path("/root/.claude")


_STALE_SENTINEL_NAME = "_STALE_DO_NOT_WRITE_HERE.md"


def _drop_stale_sentinel(prev_work: Path, prev_id: str) -> None:
    """Drop a marker file into the prior job's work tree.

    The forked SDK session frequently `cd`s back into the prior cwd
    (`/data/jobs/<prev_id>/work/`) because that path is hard-baked
    into its tool history. The first thing a careful agent does
    after `cd` is `ls` — when this sentinel shows up in the listing
    the agent sees an unmistakable signal that the directory has
    been retired.

    Best-effort: ignored if the dir is gone or fs is read-only.
    Repeated retries refresh the file in place (it just gets the
    latest description).
    """
    try:
        sentinel = prev_work / _STALE_SENTINEL_NAME
        sentinel.write_text(
            f"# 🚨 THIS DIRECTORY IS STALE — DO NOT WRITE HERE\n\n"
            f"You are looking at `/data/jobs/{prev_id}/work/`. This was the "
            f"work tree of a PREVIOUS attempt that the user has already "
            f"retried/resumed.\n\n"
            f"The orchestrator collects artifacts only from the CURRENT job's "
            f"`work/` tree. Any Write/Edit you make under this directory will "
            f"be silently discarded — your retry will return UNCHANGED files "
            f"and waste a full agent run.\n\n"
            f"**Action**: `cd` back to your job's work tree (the one whose id "
            f"matches the JOB_ID env var, NOT `{prev_id}`) and re-issue your "
            f"writes with bare names (`exploit.py`) or `./`-relative paths.\n"
        )
    except OSError:
        pass


def _carry_session_jsonl(sid: str, prev_work: Path, new_work: Path) -> None:
    """Make a prev SDK session reachable from the new job's cwd.

    The bundled `claude` CLI (the SDK's default transport) indexes
    transcripts by `project_key_for_directory(cwd)`. When the new
    job's cwd differs from the prior job's cwd — which it always
    does — fork_session=True can't find the session id and the
    spawn dies in ~2 seconds with exit 1. Copying the jsonl into
    the new project-key directory makes the lookup succeed.

    Best-effort: silently no-ops if anything is missing. Worst case
    the new agent boots fresh, which is the fallback path the
    preamble already documents.
    """
    try:
        prev_key = project_key_for_directory(str(prev_work))
        new_key = project_key_for_directory(str(new_work))
    except Exception:
        return
    src = _CLAUDE_HOME / "projects" / prev_key / f"{sid}.jsonl"
    if not src.is_file():
        return
    dst_dir = _CLAUDE_HOME / "projects" / new_key
    try:
        dst_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst_dir / src.name)
        # Subagent jsonls live in a `subagents/` subdir alongside the
        # main session file — copy those too so subagent context isn't
        # lost on fork.
        sub_src = _CLAUDE_HOME / "projects" / prev_key / sid / "subagents"
        if sub_src.is_dir():
            sub_dst = dst_dir / sid / "subagents"
            shutil.copytree(sub_src, sub_dst, dirs_exist_ok=True)
    except OSError:
        # ~/.claude mounted read-only, or some other fs error. Caller
        # already records the prev session id in meta, so the agent
        # will just start fresh — which is the documented fallback.
        pass


# Entries inside work/ that copytree should skip during /retry +
# /resume. The first generation is the load-bearing one:
#
#   tmp/        — per-job scratch (sandboxed claude tempdir, extracted
#                 rootfs cpios, gdb probe scripts, etc.). Contents are
#                 transient AND frequently contain character/block
#                 devices (rootfs dev/console, dev/log) or named pipes
#                 that copytree(dirs_exist_ok=False) would try to open
#                 with open(..., 'rb') and hang on indefinitely. The
#                 fresh job recreates ./tmp lazily — no semantic loss.
#                 (Concrete incident 2026-05-17 on job 9f93bc8dcd0d:
#                 every retry attempt left a half-copied work tree
#                 behind because copytree blocked on tmp/rootfs/dev/
#                 console; the SSE stream timed out and the user saw
#                 "UI새로고침이 안됨".)
#
# __pycache__ — Python bytecode caches; the worker container has a
#               different Python minor version path-binding than the
#               api container, so carried .pyc files just get
#               regenerated. Saves a few MB on every retry.
#
# libsrc      — pinned web-stack SOURCE staged by web autoboot Layer-1
#               (modules/web/analyzer.py _stage_pinned_web_stack). It is
#               re-staged deterministically each attempt from the chal's
#               manifests, so carrying it just bloats the retry tree by
#               tens of MB (and re-pays the copytree cost) for nothing.
_CARRY_WORK_IGNORE_NAMES = frozenset({
    "tmp", "__pycache__", "libsrc", ".codex-stop-requested",
})


# Special-file types that shutil.copytree would try to open(.., 'rb') and
# hang on FOREVER: character + block device nodes, FIFOs, and unix sockets.
# (symlinks=True copies symlinks AS links, so a dev/stdout->/proc/... symlink
# is harmless — lstat reports S_ISLNK, not the device type, and we keep it.)
_COPYTREE_BLOCKING_MODES = (stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK)


def _carry_work_ignore(src: str, names: list[str]) -> list[str]:
    """`shutil.copytree(..., ignore=...)` callback for /retry + /resume.

    Skips two classes of entries so the carry-copy can neither HANG nor bloat:

    1. By NAME (any level): ``tmp`` and ``__pycache__`` — transient scratch /
       bytecode, recreated lazily; agents never keep their own copies.

    2. SPECIAL FILES (any level): character/block device nodes, FIFOs, and
       sockets. ``shutil.copytree(dirs_exist_ok=False)`` opens regular-looking
       entries with ``open(.., 'rb')``; a device node — e.g. an extracted
       rootfs's ``dev/console`` — blocks that ``open()`` INDEFINITELY. Because
       ``_resubmit`` runs SYNCHRONOUSLY inside the async ``/retry/stream``
       handler, that one blocked syscall freezes uvicorn's entire event loop
       (every route → 000) until a manual ``docker compose restart api`` — no
       asyncio timeout can fire on a thread blocked in a syscall. The tmp/
       name-skip used to be enough because rootfs extractions lived under
       ``tmp/``, but job 21314c04d74d unpacked one to ``./rootfs_x/`` (top
       level), dodging the name filter and wedging the api three times on
       2026-06-04. Detect the node type via ``lstat`` and drop it — these are
       rootfs artifacts with zero value in a retry tree. (Generalises the
       2026-05-17 job-9f93bc8dcd0d fix from "skip tmp/" to "skip the actual
       blocker wherever it lives".)
    """
    skip = []
    for n in names:
        if n in _CARRY_WORK_IGNORE_NAMES:
            skip.append(n)
            continue
        try:
            mode = os.lstat(os.path.join(src, n)).st_mode
        except OSError:
            continue
        if stat.S_IFMT(mode) in _COPYTREE_BLOCKING_MODES:
            skip.append(n)
    return skip


def _resolve_targets(
    target_override: str | None, prev_meta: dict,
) -> tuple[str | None, list[str] | None]:
    """Resolve (primary_target, target_urls) for a retry / continue.

    `target_override` (operator-supplied; may carry several targets via
    newline/comma) REPLACES the prior target list when given — "(none)"/""
    clears it; None means keep the prior job's target_url (+ target_urls).
    Returns (primary or None, target_urls list [only when ≥2, else None]).
    Keeping target_urls alongside target_url means a multi-target job that is
    retried / continued / target-updated doesn't silently drop its extras.
    """
    if target_override is not None:
        clean_t = target_override.strip()
        if clean_t.lower() in ("(none)", "none", ""):
            return None, None
        ts = parse_targets(clean_t)
        primary = ts[0] if ts else None
        return primary, (ts if len(ts) >= 2 else None)
    primary = (prev_meta.get("target_url") or "").strip() or None
    prior = [t for t in (prev_meta.get("target_urls") or []) if t]
    return primary, (prior if len(prior) >= 2 else None)


# Modules whose agent runs in the JOB ROOT instead of `<job>/work/`. Their
# run_job sets `work_dir = _job_dir(job_id)` and never creates a work tree;
# every analyzer-shaped module mkdirs `<job>/work` and puts the agent there.
#
# This drives the preamble's cwd anchor, and it deliberately does NOT ask the
# filesystem. `carried` used to double as the shape signal because a missing
# work/ implied a job-root module — but once `carried` narrowed to "the carry
# will deliver files", a pwn parent whose work/ held only `tmp/` began
# rendering the job-root text, telling an agent whose cwd really is
# `<job>/work` to stop and re-orient on its MANDATORY FIRST CALL. Module
# shape is a property of the module, not of what the last run happened to
# leave behind.
_JOB_ROOT_CWD_MODULES = frozenset({"misc", "forensic"})


def _agent_cwd_is_work_tree(prev_meta: dict) -> bool:
    """Does this module's agent run in `<job>/work/` rather than the job root."""
    return (prev_meta.get("module") or "") not in _JOB_ROOT_CWD_MODULES


def _carry_will_deliver(prev_jd: Path) -> bool:
    """Whether `_resubmit`'s carry will actually put files in the child.

    This is what the preamble's `carried` flag must mean. It used to be
    `(jd / "work").is_dir()`, a pure existence test — but the carry filters
    what it copies through `_carry_work_ignore`, so the two disagree. A work/
    holding only `tmp/` and `__pycache__` exists and copies nothing, and
    `work/tmp` is created eagerly when the agent environment is built, so that
    state is reachable rather than hypothetical. The child then stood in an
    empty tree while the preamble told it everything its predecessor produced
    "has been COPIED into your new cwd and sits directly at `./`".

    Top level only: a work/ whose sole entry is ignored delivers nothing
    regardless of what is nested inside it, since copytree never descends
    into a name the ignore filter removed.

    It calls `_carry_work_ignore` rather than re-deriving the rule. That
    filter drops more than `_CARRY_WORK_IGNORE_NAMES`: it lstats each entry
    and also skips device nodes, FIFOs and sockets (the class that once
    blocked copytree's `open()` and froze uvicorn). A name-set reimplementation
    would call a work/ holding one FIFO a delivery and be wrong, and would go
    on being wrong every time that filter grows.

    The stale sentinel is excluded on top of it. It is not in the ignore set —
    the copy does bring it across — but `_resubmit` deletes it from the child
    immediately afterwards, so it is never a file the child ends up with.
    Counting it broke the second retry of the same parent: the first retry
    plants the sentinel in the parent's work/, and the second then saw a
    "real" file there and promised a carry that arrived empty.
    """
    prev_work = prev_jd / "work"
    if not prev_work.is_dir():
        return False
    try:
        names = [p.name for p in prev_work.iterdir()]
    except OSError:
        return False
    dropped = set(_carry_work_ignore(str(prev_work), names))
    dropped.add(_STALE_SENTINEL_NAME)
    return any(n not in dropped for n in names)


def _carry_binary_name(bin_dir: Path, prev_meta: dict) -> str | None:
    """Which staged file is THIS challenge, on a retry.

    This used to be `iterdir()`'s first regular file. Directory order is not
    the challenge, and on the real corpus it disagreed with the identity the
    original upload had chosen in 4 of 12 rev retries (4 of 7 once you look
    only at multi-file jobs): `3a948819a443` was retried as `README.md`,
    `d342333ffed3` and `4c96e913b6e6` as `output.pdf.enc`, `c918d057a4fc` as
    `client_old` instead of `server`. That name is written straight into
    `meta["filename"]` and handed to the analyzer, so a retry could re-enter
    with a documentation file as its subject.

    Preferring the IMMEDIATE parent's name is not enough, because the bug
    propagates: `4c96e913b6e6` inherited `output.pdf.enc` from `d342333ffed3`,
    which had itself drifted away from the root's `CVE-2015-2291.exe`. Trusting
    the parent there would keep re-promoting a ciphertext as the challenge
    forever.

    So walk to the ROOT of the retry chain. The root is a direct upload, and it
    is the only generation whose name was never produced by the broken retry
    picker -- that is what makes it authoritative rather than merely older. On
    the four recorded drift cases the root carries `main`,
    `CVE-2015-2291.exe` (for both `d342333ffed3` and the chain that inherited
    from it) and `client_old`, which is the right answer in every one.

    Order of preference:
      1. the ROOT of the retry chain, if that file is staged here
      2. the immediate parent's name, if staged -- covers a chain whose root
         meta is gone or whose bundle genuinely changed
      3. the deterministic picker every ingest path shares
      4. nothing, leaving the caller's own fallback in charge
    """
    def _staged(name: str | None) -> str | None:
        name = (name or "").strip()
        return name if name and (bin_dir / name).is_file() else None

    # 1. root of the chain
    seen: set[str] = set()
    cur = prev_meta
    root_name = None
    while cur:
        jid = str(cur.get("id") or "")
        if jid in seen:
            break              # defensive: a cycle in retry_of
        seen.add(jid)
        parent_id = cur.get("retry_of")
        if not parent_id:
            root_name = cur.get("filename")
            break
        try:
            cur = read_job_meta(str(parent_id))
        except Exception:
            break
    if _staged(root_name):
        return _staged(root_name)

    # 2. the immediate parent
    if _staged(prev_meta.get("filename")):
        return _staged(prev_meta.get("filename"))

    # 3. the shared picker — same function the direct upload and the hybrid
    #    worker use, so the three paths cannot disagree again.
    try:
        from modules._common import pick_challenge_binary
    except Exception:
        picked = None
    else:
        picked = pick_challenge_binary(bin_dir)
    if picked is not None:
        return picked.name

    files = sorted(p.name for p in bin_dir.iterdir() if p.is_file())
    return files[0] if files else None


def _resubmit(
    prev_meta: dict,
    hint: str,
    prev_jd: Path,
    *,
    carry_work: bool = False,
    mark_resumed: bool = False,
    target_override: str | None = None,
    fresh_session: bool = False,
    secret_key: str | None = None,
    secret_value: str | None = None,
) -> str:
    """Enqueue a new job in the same module with description + hint, copying
    over the original uploaded source/binary so the user doesn't re-upload.

    `carry_work=True` additionally copies prev_jd/work → new_jd/work so the
    new agent inherits any partial exploit/solver/report drafts the prior
    attempt had written. Both /retry and /resume now set this.

    `mark_resumed=True` records the new job as a 'resume' lineage in
    meta.resumed_from. /resume uses this; /retry does not (it remains a
    plain retry that just happens to read prior drafts as reference).
    Either way the new meta still records `retry_of` for traceability.

    `fresh_session=True` carries the work tree + hint as usual but does NOT
    fork the prior SDK conversation (resume_session_id=None) — the new agent
    boots with a clean context and reads the carried artifacts + compressed
    hint instead of re-inheriting the full prior transcript. This is the
    operator-selectable defence against retry-fork-chain context overflow:
    deep chains (e.g. 21314 → 3c518 → 740134) accumulate the entire prior
    conversation every generation until the main session hits "Prompt is too
    long". The reviewer hint + carried files already encode the progress, so
    dropping the raw transcript is the cheaper, overflow-proof signal.
    """
    module = prev_meta.get("module")
    if module not in _RETRYABLE_MODULES:
        raise HTTPException(
            status_code=400,
            detail=(
                "retry-with-hint is only supported for "
                f"{'/'.join(sorted(_RETRYABLE_MODULES))} (got {module})"
            ),
        )

    # A source may already say ``stopped`` while its killed Codex CLI is still
    # unwinding.  The direct /resume path waits in _halt_source_job(), but a
    # later /retry of that stopped job reaches this shared builder instead.
    # Recheck the inherited turn guard immediately before allocating any
    # successor state so no route can reopen the same thread concurrently.
    from modules.codex_turn_guard import wait_for_turn_teardown

    source_quiescent, _ = wait_for_turn_teardown(
        prev_jd / "work",
        timeout_s=0.0,
    )
    if not source_quiescent:
        raise HTTPException(
            status_code=409,
            detail={
                "kind": "stop_ack_timeout",
                "message": (
                    "source Codex process is still terminating; "
                    "no successor job was created"
                ),
            },
        )

    new_id = new_job_id()
    new_jd = job_dir(new_id)

    # Carry forward the previous agent's work directory (drafts, notes,
    # partial exploit.py / solver.py / report.md). Done first so any
    # subsequent module-specific copy step sits alongside it cleanly.
    if carry_work:
        prev_work = prev_jd / "work"
        if prev_work.is_dir():
            shutil.copytree(
                prev_work, new_jd / "work",
                dirs_exist_ok=False,
                ignore=_carry_work_ignore,
                # Don't follow symlinks: pwn chals routinely extract a
                # Linux rootfs (cpio) into ./tmp/rootfs whose dev/stdin,
                # dev/stdout, dev/log, etc. are symlinks back to host
                # devices. Following them would either dereference into
                # /dev or attempt to read the device. Preserving them as
                # symlinks is safe — they're irrelevant for the retry.
                symlinks=True,
            )
            # Plant a stale-marker into the OLD work tree so a forked
            # session that `cd`s back into its baked-in absolute path
            # sees an unmistakable file in `ls` output.
            _drop_stale_sentinel(prev_work, prev_meta.get("id") or "")
        # Carry the SDK session transcript so fork_session=True can
        # actually find the prior conversation. The CLI transport
        # derives the project key from cwd; without copying the jsonl
        # into the *new* cwd's key directory, the fork attempt silently
        # fails (~2s exit 1, no init message).
        prev_sid = (
            prev_meta.get("claude_session_id")
            if prev_meta.get("agent_provider") == "claude" else None
        )
        if prev_sid:
            # Key on the directory the agent ACTUALLY ran in. misc and
            # forensic set `work_dir = _job_dir(job_id)` — the job root — so
            # their transcript is indexed under the key for `<job>`, not
            # `<job>/work`. Passing the work-tree shape regardless made the
            # lookup miss, `src.is_file()` return False, and the copy no-op
            # in silence, leaving fork_session with nothing to find. Both key
            # shapes exist side by side in ~/.claude/projects, so this is not
            # a distinction the slug collapses.
            if prev_work.is_dir():
                _carry_session_jsonl(prev_sid, prev_work, new_jd / "work")
            else:
                _carry_session_jsonl(prev_sid, prev_jd, new_jd)
        # The sentinel was carried into the new work tree by copytree —
        # drop it from the new tree so the agent doesn't trip over it
        # when working in its own cwd.
        new_sentinel = new_jd / "work" / _STALE_SENTINEL_NAME
        if new_sentinel.is_file():
            try:
                new_sentinel.unlink()
            except OSError:
                pass

    # Target: caller can override (user-supplied via UI). Empty
    # override falls back to the prior target. Sentinel "(none)" lets
    # the user explicitly clear a target without re-using the prior.
    target, target_urls = _resolve_targets(target_override, prev_meta)
    # Strip any prior [retry-hint] section so chained retries don't
    # accumulate stale hint paragraphs in the description blob — the
    # newest hint is always the only one attached.
    description = (prev_meta.get("description") or "").strip()
    marker = "\n\n[retry-hint]\n"
    cut = description.find(marker)
    if cut == -1:
        # Also handle the no-leading-blank-lines variant just in case.
        cut = description.find("[retry-hint]")
        if cut != -1:
            description = description[:cut].rstrip()
    else:
        description = description[:cut].rstrip()
    description = (description + "\n\n[retry-hint]\n" + hint).strip()
    from modules.job_secrets import SecretIngressError, prepare_job_secret

    try:
        description = prepare_job_secret(
            new_id,
            description,
            secret_key=secret_key,
            secret_value=secret_value,
            copy_from=str(prev_meta.get("id") or "") or None,
        ) or ""
    except SecretIngressError as exc:
        from api.storage import cleanup_job

        cleanup_job(new_id)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    auto_run = bool(prev_meta.get("auto_run"))
    # Carry the 'Docker challenge' opt-in forward (mirrors auto_run) — a retry of
    # a docker-challenge job must keep detecting+running the bundled Dockerfile,
    # else the retry silently reverts to a static-only solve.
    docker_challenge = bool(prev_meta.get("docker_challenge"))
    job_timeout = resolve_timeout(prev_meta.get("job_timeout"))
    model = prev_meta.get("model")  # honor prior choice; user can override

    # If the prior job ended with judge explicitly saying "stop —
    # this approach is structurally blocked", forking its 60M-token
    # conversation poisons the new agent with the dead-end reasoning
    # it was just told to abandon. Skip the session fork in that case
    # — the retry_hint + carried work tree are the actionable signal;
    # the prior conversation is noise. (Observed in 2d22aa9f338e
    # forked d809a5187990: 23M cache_read on a 1-turn retry because
    # the fork inherited d809's poisoned context.)
    prior_stopped = (
        (prev_meta.get("judge_next_action") or "").lower() == "stop"
    )
    # If the prior job died on a server-side Usage-Policy (AUP) block
    # (error_kind=policy_refusal), the prior SDK transcript IS the poison:
    # forking it (fork_session=True) re-presents the exact accumulated
    # conversation the classifier already refused, so a DEFAULT /retry
    # (fresh=False) re-blocks deterministically. Every observed AUP death
    # fires at attempt 0 (before any postjudge auto-retry), so /retry is the
    # SOLE recovery path — it MUST shed the transcript, not inherit it. Force
    # a clean context (same effect as the operator ticking "fresh start"); the
    # carried work tree + reviewer hint preserve the actionable progress. This
    # makes the WHY_STOPPED "de-facto cure" claim actually true by default
    # rather than only when the operator remembers to tick the box.
    prior_aup_blocked = (
        (prev_meta.get("error_kind") or "") == "policy_refusal"
    )
    # fresh_session (operator-selected) forces a clean context too — same
    # rationale as prior_stopped, but chosen explicitly to break a
    # retry-fork-chain context overflow rather than inferred from a judge stop.
    if prior_stopped or fresh_session or prior_aup_blocked:
        resume_sid = None
    else:
        resume_sid = _resume_id_for_active_provider(prev_meta) if carry_work else None

    meta = {
        "id": new_id,
        "module": module,
        "status": "queued",
        "target_url": target,
        "target_urls": target_urls,
        "description": description,
        "auto_run": auto_run,
        "docker_challenge": docker_challenge,
        "job_timeout": job_timeout,
        "model": model,
        "retry_of": prev_meta.get("id"),
        # Carry the operator's refusals into the child. The whole point of
        # keeping a rejected value is that a later run which re-derives it is
        # repeating a known dead end — and the run most likely to re-derive it
        # is this one, started because the parent's answer was wrong. Dropping
        # it here made the record forget precisely where it mattered most.
        "flag_rejected": [r for r in (prev_meta.get("flag_rejected") or []) if r],
        # Same reasoning as flag_rejected, for mechanisms rather than answers.
        # A retry that re-derives a mechanism the lineage already named is not
        # necessarily wrong — r.0.0.mca was solved that way three times — but it
        # should know it is doing so. Entries carry whether the attempt actually
        # got to test the mechanism (K1-c): a run cut off by a timeout is not
        # evidence against it.
        "technique_history": _carry_technique_history(prev_meta, prev_jd),
        "resumed_from": prev_meta.get("id") if mark_resumed else None,
        # Pass the prior Claude SDK session_id along so the new agent
        # can resume + fork the conversation rather than start fresh.
        # Only meaningful when we're carrying the work/ tree too —
        # without that the forked thread would reference paths that
        # don't exist any more in the new cwd. Also cleared when the
        # prior judge decided stop (see prior_stopped above).
        "resume_session_id": resume_sid,
        "resume_skipped_due_to_judge_stop": prior_stopped,
        # True when the prior job died of an AUP policy_refusal: the fork was
        # force-skipped so the new agent boots on a clean context instead of
        # re-inheriting the poisoned transcript that the classifier refused.
        "resume_skipped_due_to_aup": prior_aup_blocked,
        # True when the operator ticked "fresh start (no conversation fork)"
        # on this retry — carried files + hint only, clean SDK context.
        "fresh_session_requested": bool(fresh_session),
    }
    # A retry IS a job create, so it gets the same create-time provider stamp
    # the module routes give a first-run job. Without it the literal above
    # carries no `agent_provider` at all, and every consumer falls back to
    # whatever Settings says whenever it happens to ask — which for the role
    # map means the routing chosen for this retry is lost outright.
    #
    # Stamping the ACTIVE provider (rather than copying the parent's) is what
    # retry already assumes: `_resume_id_for_active_provider` above drops the
    # resume id precisely when the active provider differs from the parent's,
    # i.e. a retry deliberately follows the current Settings backend.
    from modules.agent_provider import enrich_job_meta

    enrich_job_meta(meta)

    q = get_queue()

    if module in ("web", "crypto", "web3"):
        # Copy source dir
        src_extracted = prev_jd / "src" / "extracted"
        if src_extracted.is_dir():
            (new_jd / "src").mkdir(exist_ok=True)
            shutil.copytree(src_extracted, new_jd / "src" / "extracted")
            new_src_root = str(new_jd / "src" / "extracted")
        else:
            new_src_root = None
        meta["src_root"] = new_src_root
        meta["filename"] = prev_meta.get("filename")
        meta["remote_only"] = new_src_root is None
        write_job_meta(new_id, meta)
        if module == "web":
            q.enqueue(
                "modules.web.analyzer.run_job",
                new_id, new_src_root, target, description, auto_run, model,
                job_id=new_id, job_timeout=hard_timeout_for(job_timeout),
            )
        elif module == "web3":
            q.enqueue(
                "modules.web3.analyzer.run_job",
                new_id, new_src_root, target, description, auto_run, model,
                job_id=new_id, job_timeout=hard_timeout_for(job_timeout),
            )
        else:
            q.enqueue(
                "modules.crypto.analyzer.run_job",
                new_id, new_src_root, target, description, auto_run, model,
                job_id=new_id, job_timeout=hard_timeout_for(job_timeout),
            )
    elif module == "forensic":
        # The image is the job's whole input and it can be enormous — this
        # module exists for disk images. shutil.copy2 of a 60 GiB .raw to set
        # up a retry would be a self-inflicted outage, so link it: same
        # device, constant time, no second copy of the bytes. The image is
        # read-only input to both jobs, so sharing the inode is safe.
        # os.link fails across devices and on a filesystem without hardlinks;
        # fall back to a copy there rather than refusing the retry.
        image_name = prev_meta.get("filename")
        carried = None
        if image_name:
            src = prev_jd / Path(image_name).name
            if src.is_file():
                dst = new_jd / src.name
                try:
                    os.link(src, dst)
                except OSError:
                    shutil.copy2(src, dst)
                carried = src.name
        meta["filename"] = carried or image_name
        # Everything else the orchestrator is called with lives in meta and is
        # carried verbatim: re-deciding image_type / target_os here would let a
        # retry silently analyse the image as something the operator never
        # chose.
        meta["image_type"] = prev_meta.get("image_type")
        meta["target_os"] = prev_meta.get("target_os")
        meta["bulk_extractor"] = prev_meta.get("bulk_extractor")
        meta["remote_only"] = carried is None
        write_job_meta(new_id, meta)
        q.enqueue(
            "modules.forensic.orchestrator.run_job",
            new_id,
            carried or image_name,
            prev_meta.get("image_type"),
            prev_meta.get("target_os"),
            description,
            bool(prev_meta.get("bulk_extractor")),
            False,
            model,
            job_id=new_id, job_timeout=hard_timeout_for(job_timeout),
        )
    elif module == "misc":
        # misc keeps its upload as a single file directly in the job dir, the
        # way forensic does, so carry it the same way: hardlink first (a misc
        # bundle can be a large archive and a retry must not duplicate the
        # bytes), copy where the filesystem will not link.
        upload_name = prev_meta.get("filename")
        carried = None
        if upload_name:
            src = prev_jd / Path(upload_name).name
            if src.is_file():
                dst = new_jd / src.name
                try:
                    os.link(src, dst)
                except OSError:
                    shutil.copy2(src, dst)
                carried = src.name
        meta["filename"] = carried or upload_name
        meta["skip_claude"] = bool(prev_meta.get("skip_claude"))
        meta["remote_only"] = carried is None
        write_job_meta(new_id, meta)
        # passphrase=None ON PURPOSE. It is not in meta and must not be: the
        # orchestrator reads it back from the job-secrets rail, which this
        # child already inherited via prepare_job_secret(copy_from=...) above.
        # Threading it through here would put a live credential in an RQ
        # argument list and in this route's frame for no gain.
        q.enqueue(
            "modules.misc.orchestrator.run_job",
            new_id,
            carried or upload_name,
            None,
            description,
            bool(prev_meta.get("skip_claude")),
            model,
            job_id=new_id, job_timeout=hard_timeout_for(job_timeout),
        )
    else:  # pwn / rev
        prev_bin = prev_jd / "bin"
        binary_name = None
        if prev_bin.is_dir():
            new_bin = new_jd / "bin"
            new_bin.mkdir(exist_ok=True)
            for f in prev_bin.iterdir():
                if f.is_file():
                    shutil.copy2(f, new_bin / f.name)
            binary_name = _carry_binary_name(new_bin, prev_meta)
        meta["filename"] = binary_name or prev_meta.get("filename")
        meta["remote_only"] = binary_name is None
        write_job_meta(new_id, meta)
        if module == "pwn":
            q.enqueue(
                "modules.pwn.analyzer.run_job",
                new_id, binary_name, target, description, auto_run, model,
                job_id=new_id, job_timeout=hard_timeout_for(job_timeout),
            )
        else:  # rev
            q.enqueue(
                "modules.rev.analyzer.run_job",
                new_id, binary_name, description, auto_run, model,
                job_id=new_id, job_timeout=hard_timeout_for(job_timeout),
            )
    return new_id


# ---------------------------------------------------------------------------
# Continue-in-place (operator comment, NOT a retry).
#
# For jobs that solved the chal but were blocked on an EXTERNAL action the
# operator must take (restart a one-shot DreamHack instance, bring the remote
# back up, hand over a credential) — e15333348597 is the canonical case. A
# /retry forks the session into a NEW job id → NEW cwd, so the carried
# conversation's paths go stale and the preamble forces the agent to re-read /
# re-investigate (exactly why its retry bfcb125eda1c spun in circles and burned
# the fresh slot with a wrong registration). Continuing IN PLACE keeps the same
# job id, cwd, work tree AND SDK session, so the forked conversation's paths are
# still valid and the agent picks up where it left off with just the operator's
# note — no re-orientation.
# ---------------------------------------------------------------------------
_CONTINUE_HINT_TMPL = (
    "OPERATOR CONTINUATION — the external blocker is resolved.\n"
    "Operator note: {comment}\n\n"
    "You are CONTINUING THE SAME job in the SAME work tree — your cwd is "
    "UNCHANGED and every file you already wrote (exploit.py / solver.py / "
    "report.md / findings.json / decomp / scratch) is still exactly where you "
    "left it. This is NOT a fresh job and NOT a re-investigation.\n"
    "DO NOT re-read, re-decompile, re-fingerprint or re-derive what you already "
    "established — your full prior reasoning and analysis are intact. ACT on the "
    "operator note immediately: run your existing exploit against the "
    "now-unblocked target, or apply the single change the note implies. If a "
    "one-shot / rate-limited resource just became available (a fresh "
    "registration slot, a reset instance), spend it on your COMPLETE working "
    "exploit in one shot — do NOT waste it on manual probing or experiments."
)


def _continue_in_place(
    prev_meta: dict,
    comment: str,
    target_override: str | None = None,
    *,
    secret_key: str | None = None,
    secret_value: str | None = None,
) -> str:
    """Re-enqueue the SAME job id, resuming its SDK session with the operator's
    note folded in as priority guidance. No new job, no cwd change, no work
    copy — build_user_prompt surfaces the [retry-hint] and the forked session
    references the unchanged cwd. Returns the (unchanged) job id.

    `target_override` updates the target (a restarted DreamHack instance often
    comes back on a NEW port); blank keeps the prior, "(none)" clears it."""
    # Refuse BEFORE any side effect. This check used to read _RETRYABLE_MODULES,
    # so forensic passed it and was caught much later at the dispatch site —
    # after write_job_meta had already set status=queued, rewritten the
    # description and cleared the markers. The caller saw 400 and the operator
    # saw a queued job that nothing had enqueued.
    module = prev_meta.get("module")
    if module not in _CONTINUABLE_MODULES:
        raise HTTPException(
            status_code=400,
            detail=(
                "continue is only supported for "
                f"{'/'.join(sorted(_CONTINUABLE_MODULES))} (got {module})"
                + (" — use retry, which rebuilds the job with the image "
                   "carried forward" if module == "forensic" else "")
            ),
        )
    job_id = prev_meta.get("id")
    if not job_id:
        raise HTTPException(status_code=400, detail="job has no id")

    from modules.codex_turn_guard import clear_turn_stop, wait_for_turn_teardown
    from modules.job_secrets import SecretIngressError, prepare_job_secret

    try:
        continue_ack_timeout = float(
            os.environ.get("CODEX_STOP_ACK_TIMEOUT_S", "15")
        )
    except (TypeError, ValueError):
        continue_ack_timeout = 15.0
    acknowledged, _ = wait_for_turn_teardown(
        JOBS_DIR / job_id / "work",
        timeout_s=max(0.0, continue_ack_timeout),
    )
    if not acknowledged:
        raise HTTPException(
            status_code=409,
            detail={
                "kind": "stop_ack_timeout",
                "message": "prior Codex process is still terminating; continue was not queued",
            },
        )
    try:
        comment = prepare_job_secret(
            job_id,
            comment,
            secret_key=secret_key,
            secret_value=secret_value,
        ) or ""
    except SecretIngressError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    clear_turn_stop(JOBS_DIR / job_id / "work")
    # The /continue comment is typed by the operator. Never rewrite it;
    # `continue_comment` in the same meta.json already stores it verbatim,
    # so a rewrite here made the two disagree with nothing logging why.
    hint = _CONTINUE_HINT_TMPL.format(comment=comment.strip())
    # Strip any prior [retry-hint] block so repeated continues don't stack.
    description = (prev_meta.get("description") or "").strip()
    cut = description.find("[retry-hint]")
    if cut != -1:
        description = description[:cut].rstrip()
    description = (description + "\n\n[retry-hint]\n" + hint).strip()

    # Same cwd → the prior session jsonl is already under this cwd's project
    # key, so fork_session=True finds it without any carry step.
    resume_sid = _resume_id_for_active_provider(prev_meta)
    cont_n = int(prev_meta.get("continue_count") or 0) + 1
    target, target_urls = _resolve_targets(target_override, prev_meta)
    auto_run = bool(prev_meta.get("auto_run"))
    job_timeout = resolve_timeout(prev_meta.get("job_timeout"))
    model = prev_meta.get("model")

    write_job_meta(job_id, {
        **prev_meta,
        "status": "queued",
        "stage": "continue",
        "target_url": target,
        "target_urls": target_urls,
        "remote_only": prev_meta.get("remote_only", target is not None),
        "description": description,
        "resume_session_id": resume_sid,
        "resume_skipped_due_to_judge_stop": False,
        "fresh_session_requested": False,
        "continue_count": cont_n,
        "continue_comment": comment,
        # clear the prior terminal markers so the UI shows it active again.
        "finished_at": None,
        "error": None,
        "error_kind": None,
        # ...including the JUDGE verdict. `judge_next_action == "stop"` is read
        # by the /retry path (:761) as "this approach is structurally blocked"
        # and makes it DISCARD the SDK session. Carrying a previous session's
        # stop into a continued job means a later /retry silently sheds a
        # conversation the operator was told would be kept — which is exactly
        # what the `no_artifact` playbook promises does NOT happen. A continue
        # re-opens the job, so the old verdict no longer describes it.
        "judge_next_action": None,
        "judge_stop_reason": None,
        # ...and which worker SLOT served the previous run. This spreads
        # `**prev_meta`, so without this the re-queued job would advertise the
        # OLD slot while sitting in the queue, and the continue can be picked
        # up by any slot. deploy.sh only trusts worker_slot on status=running
        # (a queued job defers every slot), so this is belt-and-braces rather
        # than a live bug — but a meta that claims a slot it may not get is
        # exactly the kind of stale field that later reads as authoritative.
        # The serving slot re-stamps it on its first write_meta.
        "worker_slot": None,
    })

    q = get_queue()
    rq_id = f"{job_id}-c{cont_n}"
    ht = hard_timeout_for(job_timeout)
    if module == "web":
        q.enqueue("modules.web.analyzer.run_job",
                  job_id, prev_meta.get("src_root"), target, description, auto_run, model,
                  job_id=rq_id, job_timeout=ht)
    elif module == "web3":
        q.enqueue("modules.web3.analyzer.run_job",
                  job_id, prev_meta.get("src_root"), target, description, auto_run, model,
                  job_id=rq_id, job_timeout=ht)
    elif module == "crypto":
        q.enqueue("modules.crypto.analyzer.run_job",
                  job_id, prev_meta.get("src_root"), target, description, auto_run, model,
                  job_id=rq_id, job_timeout=ht)
    elif module == "pwn":
        q.enqueue("modules.pwn.analyzer.run_job",
                  job_id, prev_meta.get("filename"), target, description, auto_run, model,
                  job_id=rq_id, job_timeout=ht)
    elif module == "rev":
        q.enqueue("modules.rev.analyzer.run_job",
                  job_id, prev_meta.get("filename"), description, auto_run, model,
                  job_id=rq_id, job_timeout=ht)
    else:
        # Unreachable while the head check and this table agree, which the
        # parity assertion enforces. If they ever disagree, fail loudly rather
        # than hand the job to whichever branch happens to be last — that is
        # exactly how a forensic disk image nearly reached the rev analyzer.
        raise HTTPException(
            status_code=500,
            detail=f"continue dispatch has no branch for module {module!r}",
        )
    return job_id


_MAX_MANUAL_HINT = 4000


def _validate_retry(safe: str, *, require_claude_auth: bool = True) -> tuple[Path, dict]:
    """Validate a job can be retried.

    ``require_claude_auth`` is kept as the kwarg name for call-site
    compatibility, but the check is **provider-aware**: when Settings
    ``agent_provider=grok`` (or the job meta stamps grok), Grok auth is
    required instead of Claude. Manual-hint retries pass
    ``require_claude_auth=False`` and skip this gate entirely.
    """
    jd = JOBS_DIR / safe
    if not jd.is_dir():
        raise HTTPException(status_code=404, detail="job not found")
    prev_meta = read_job_meta(safe) or {}
    # Reads the module list rather than repeating it. 58326cb introduced
    # _RETRYABLE_MODULES and converted the two builders (_resubmit,
    # _continue_in_place) but not this one — and this is the only one an HTTP
    # request reaches, so a finished forensic job rendered Retry, Retry-with-
    # my-hint and Continue and got 400 from all three. A literal here cannot
    # disagree with the list if it is the list.
    module = prev_meta.get("module")
    if module not in _RETRYABLE_MODULES:
        raise HTTPException(
            status_code=400,
            detail=(
                "retry is only supported for "
                f"{'/'.join(sorted(_RETRYABLE_MODULES))} (got {module})"
            ),
        )
    if require_claude_auth:
        apply_to_env()
        from modules.agent_provider import (
            get_gpt_runtime,
            has_provider_auth,
            normalize_provider,
            provider_display_name,
            provider_for_job,
        )
        # The gate exists to stop a retry that cannot run, and what runs first
        # is the REVIEWER. Checking the whole-job provider rejected jobs whose
        # reviewer was routed to an authed backend, and — worse — admitted
        # jobs whose routed reviewer had no auth at all, where the failure
        # then surfaced as an auth error that the policy-refusal failover is
        # deliberately not allowed to retry.
        from modules.agent_provider import provider_for_role

        provider = normalize_provider(
            provider_for_role(safe, "reviewer")
            or prev_meta.get("agent_provider")
            or provider_for_job(safe)
        )
        if not has_provider_auth(provider):
            if provider == "gpt":
                if get_gpt_runtime() == "codex":
                    detail = (
                        "no Codex ChatGPT OAuth configured (run `codex login` "
                        "and mount the isolated HOST_CODEX_HOME)"
                    )
                else:
                    detail = (
                        "no OpenAI API key configured "
                        "(Settings → OpenAI API key)"
                    )
            elif provider == "grok":
                detail = (
                    "no Grok/xAI auth configured (Settings → xAI API key, "
                    "or `grok login` with ~/.grok mounted)"
                )
            else:
                detail = (
                    "no Claude auth configured (set Settings → API key "
                    "or claude login)"
                )
            raise HTTPException(
                status_code=400,
                detail=f"{detail} [provider={provider_display_name(provider)}]",
            )
    return jd, prev_meta


# Generous cap: a multi-target override (several host:ports / URLs, one per
# line) must fit. parse_targets caps the COUNT separately.
_MAX_MANUAL_TARGET = 4096


async def _read_retry_body(
    request: Request,
) -> tuple[str | None, str | None, bool, str | None, str | None]:
    """Parse retry controls plus optional dedicated challenge secret fields.

    `hint` / `target` are optional; empty / whitespace-only values become None
    so callers can detect "user supplied nothing" vs "user wanted to blank it
    out". Callers that want to clear a target explicitly can pass the literal
    string "(none)" — handled at the call site.

    `fresh` (default False) — when truthy, the new job is started WITHOUT
    forking the prior SDK conversation (carried files + hint only). Accepts a
    JSON bool or the strings "1"/"true"/"yes"/"on". Surfaced to _resubmit as
    `fresh_session`.
    """
    try:
        body = await request.json()
    except Exception:
        return None, None, False, None, None
    if not isinstance(body, dict):
        return None, None, False, None, None

    hint_raw = body.get("hint")
    hint = (hint_raw.strip()[:_MAX_MANUAL_HINT]) if isinstance(hint_raw, str) and hint_raw.strip() else None

    target_raw = body.get("target") or body.get("target_url")
    target = (target_raw.strip()[:_MAX_MANUAL_TARGET]) if isinstance(target_raw, str) and target_raw.strip() else None

    fresh_raw = body.get("fresh")
    if isinstance(fresh_raw, bool):
        fresh = fresh_raw
    elif isinstance(fresh_raw, str):
        fresh = fresh_raw.strip().lower() in ("1", "true", "yes", "on")
    else:
        fresh = bool(fresh_raw)
    secret_key_raw = body.get("challenge_secret_key")
    secret_value_raw = body.get("challenge_secret_value")
    secret_key = secret_key_raw if isinstance(secret_key_raw, str) else None
    secret_value = secret_value_raw if isinstance(secret_value_raw, str) else None
    return hint, target, fresh, secret_key, secret_value


async def _read_manual_hint(request: Request) -> str | None:
    """Back-compat shim. Reads only the hint field; loses target.

    All current call sites have been migrated to _read_retry_body, so
    this exists only for any out-of-tree caller still on the old name.
    """
    hint, _, _, _, _ = await _read_retry_body(request)
    return hint


@router.post("/{job_id}/retry/stream")
async def retry_with_hint_stream(job_id: str, request: Request):
    """SSE stream of retry progress.

    Events emitted:
      stage : {"name": "gathering" | "asking" | "submitting"}
      token : {"delta": "<partial reviewer output>"}
      done  : {"new_job_id": "...", "hint": "...", "retry_of": "...", "manual": bool}
      error : {"message": "..."}

    If the request body is JSON `{"hint": "<user-supplied>"}`, the reviewer
    call is skipped entirely and the user's hint goes straight to the new
    job. The 'gathering' / 'asking' stages and 'token' events are then
    omitted — only 'submitting' and 'done' fire.
    """
    safe = Path(job_id).name
    manual_hint, target_override, fresh_session, secret_key, secret_value = (
        await _read_retry_body(request)
    )
    jd, prev_meta = _validate_retry(safe, require_claude_auth=manual_hint is None)

    async def event_gen():
        def sse(name: str, data: dict) -> bytes:
            return f"event: {name}\ndata: {json.dumps(data)}\n\n".encode()

        hint = manual_hint or ""

        if manual_hint is None:
            yield sse("stage", {"name": "gathering"})
            await asyncio.sleep(0)
            try:
                context = _gather_context(roots=(jd,))
                if not context.strip():
                    yield sse("error", {
                        "message": "no prior-job context found to review",
                        "kind": "no_context",
                    })
                    return
            except Exception as e:
                yield sse("error", {
                    "message": f"gather failed: {e}",
                    "kind": "gather",
                })
                return

            _rv_model = resolve_reviewer_model(job_id)
            # Announce what will actually run. `resolve_reviewer_model` coerces
            # to the WHOLE-JOB provider, so a routed reviewer was announced as
            # one model and then called as another — and the UI presents this
            # as fact.
            _rv_provider, _rv_shown = _reviewer_provider_and_model(_rv_model, job_id)
            yield sse("stage", {
                "name": "asking", "model": _rv_shown, "provider": _rv_provider,
            })
            try:
                async for kind, payload in _ask_reviewer_streaming(
                    context, model=_rv_model, job_id=job_id):
                    if kind == "token":
                        yield sse("token", payload)
                    elif kind == "note":
                        # A failover is in progress. Dropping this left the UI
                        # with an unexplained pause between two providers.
                        yield sse("note", payload)
                    elif kind == "done":
                        hint = payload.get("hint", "")
                    elif kind == "error":
                        yield sse("error", payload)
                        return
            except Exception as e:
                raw = str(e)
                yield sse("error", {
                    "message": f"reviewer failed: {raw}",
                    "kind": _reviewer_error_kind(raw),
                })
                return

        yield sse("stage", {"name": "submitting"})
        # The whole reviewer block above is inside `if manual_hint is None`, so
        # a surviving manual_hint means these are the operator's own words. The
        # UI's manual retry lands HERE, not on the direct route, so omitting
        # this defaulted to False and rewrote a human's sentence.
        augmented = _retry_preamble(
            safe, hint, fresh=fresh_session,
            operator_text=manual_hint is not None,
            history=_carry_technique_history(prev_meta, jd),
            carried=_carry_will_deliver(jd),
            work_tree=_agent_cwd_is_work_tree(prev_meta))
        try:
            new_id = _resubmit(
                prev_meta, augmented, jd,
                carry_work=True,
                target_override=target_override,
                fresh_session=fresh_session,
                secret_key=secret_key,
                secret_value=secret_value,
            )
        except HTTPException as he:
            yield sse("error", {
                "message": f"submit rejected: {he.detail}",
                "kind": "submit",
            })
            return
        except Exception as e:
            yield sse("error", {
                "message": f"submit failed: {e}",
                "kind": "submit",
            })
            return

        yield sse("done", {
            "new_job_id": new_id,
            "hint": _public_hint(new_id, hint),
            "retry_of": safe,
            "manual": manual_hint is not None,
            "carried_work": (jd / "work").is_dir(),
            "fresh_session": fresh_session,
            "target_overridden": target_override is not None,
        })

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/{job_id}/retry")
async def retry_with_hint(job_id: str, request: Request):
    """Non-streaming form, kept for clients that don't want SSE.

    Request body (optional): JSON `{"hint": "...", "target": "..."}`.
    When `hint` is provided, the reviewer call is skipped and the
    user's hint is appended to the new job's description directly.
    When `target` is provided it overrides the prior job's
    target_url; pass "(none)" to clear it.
    """
    safe = Path(job_id).name
    manual_hint, target_override, fresh_session, secret_key, secret_value = (
        await _read_retry_body(request)
    )
    jd, prev_meta = _validate_retry(safe, require_claude_auth=manual_hint is None)

    if manual_hint is not None:
        hint = manual_hint
    else:
        context = _gather_context(roots=(jd,))
        if not context.strip():
            raise HTTPException(status_code=400, detail="no context to review")
        try:
            hint = await _ask_reviewer_with_failover(
                context, model=resolve_reviewer_model(job_id), job_id=job_id)
        except ReviewerError as e:
            # 502 = upstream (Claude API) failure. The retry never reached
            # the queue, so the client knows nothing new was scheduled.
            raise HTTPException(
                status_code=502,
                detail={
                    "stage": "reviewer",
                    "kind": e.kind,
                    "message": str(e),
                    "submitted": False,
                },
            ) from e

    augmented = _retry_preamble(
        safe, hint, fresh=fresh_session,
        operator_text=manual_hint is not None,
        history=_carry_technique_history(prev_meta, jd),
        carried=_carry_will_deliver(jd),
        work_tree=_agent_cwd_is_work_tree(prev_meta))
    new_id = _resubmit(
        prev_meta, augmented, jd,
        carry_work=True,
        target_override=target_override,
        fresh_session=fresh_session,
        secret_key=secret_key,
        secret_value=secret_value,
    )
    return {
        "new_job_id": new_id,
        "hint": _public_hint(new_id, hint),
        "retry_of": safe,
        "manual": manual_hint is not None,
        "carried_work": (jd / "work").is_dir(),
        "fresh_session": fresh_session,
        "target_overridden": target_override is not None,
    }


@router.post("/{job_id}/continue")
async def continue_with_comment(job_id: str, request: Request):
    """Continue a finished job IN PLACE with an operator note — NOT a retry.

    For the "agent solved it but was blocked on an external action" case
    (restart a one-shot instance, remote came back, credential handed over).
    Keeps the same job id / cwd / work tree / SDK session and just injects the
    operator's note so the agent acts on it without re-investigating.

    Body: JSON `{"comment": "...", "challenge_secret_key":
    "CTFD_ACCESS_TOKEN", "challenge_secret_value": "..."}`. A credential-only
    continuation may omit ``comment``; a safe generic note is injected.
    """
    safe = Path(job_id).name
    _jd, prev_meta = _validate_retry(safe)
    if prev_meta.get("status") in ("running", "queued", "analyze"):
        raise HTTPException(
            status_code=409,
            detail="job is still active — use Stop & resume instead of Continue",
        )
    try:
        body = await request.json()
    except Exception:
        body = {}
    comment = (body.get("comment") or "").strip() if isinstance(body, dict) else ""
    secret_key = body.get("challenge_secret_key") if isinstance(body, dict) else None
    secret_value = body.get("challenge_secret_value") if isinstance(body, dict) else None
    has_secret_input = bool(
        isinstance(secret_key, str) and secret_key.strip()
        or isinstance(secret_value, str) and secret_value.strip()
    )
    if not comment and not has_secret_input:
        raise HTTPException(status_code=400, detail="comment or challenge secret required")
    if not comment:
        comment = "Challenge credential supplied through the dedicated secret ingress."
    if len(comment) > _MAX_MANUAL_HINT:
        comment = comment[:_MAX_MANUAL_HINT]
    target_raw = body.get("target") if isinstance(body, dict) else None
    target_override = target_raw if isinstance(target_raw, str) and target_raw.strip() else None
    new_id = _continue_in_place(
        prev_meta,
        comment,
        target_override=target_override,
        secret_key=secret_key if isinstance(secret_key, str) else None,
        secret_value=secret_value if isinstance(secret_value, str) else None,
    )
    return {
        "job_id": new_id,
        "status": "queued",
        "continued": True,
        "resumed_session": bool(_resume_id_for_active_provider(prev_meta)),
    }


@router.post("/{job_id}/resume")
async def stop_and_resume(job_id: str, request: Request):
    """Halt a queued/running job and immediately enqueue a fresh one with
    the user's extra description appended as `[retry-hint]`.

    Required body: JSON `{"hint": "<extra context>", "target": "..."}`.
    `hint` is required (the reviewer is NOT called here). `target` is
    optional and overrides the prior job's target_url; pass "(none)"
    to clear it.

    If the source job has already finished/failed, this behaves like
    `/retry` with a manual hint (no stop is needed).
    """
    safe = Path(job_id).name
    manual_hint, target_override, fresh_session, secret_key, secret_value = (
        await _read_retry_body(request)
    )
    if manual_hint is None:
        raise HTTPException(
            status_code=400,
            detail="hint is required for /resume — provide a non-empty 'hint' field",
        )
    # Manual hint means we don't need Claude auth here; if the new job
    # auto-runs the agent it will pick up auth itself via apply_to_env.
    jd, prev_meta = _validate_retry(safe, require_claude_auth=False)

    prev_status = prev_meta.get("status")
    halt_info = (
        await asyncio.to_thread(_halt_source_job, safe, prev_meta)
        if prev_status in ("queued", "running") else None
    )
    # /resume refuses without a manual hint, so this is always operator text.
    augmented_hint = _resume_preamble(safe, manual_hint, fresh=fresh_session,
                                      operator_text=True,
                                      history=_carry_technique_history(prev_meta, jd),
                                      carried=_carry_will_deliver(jd),
                                      work_tree=_agent_cwd_is_work_tree(prev_meta))

    new_id = _resubmit(
        prev_meta, augmented_hint, jd,
        carry_work=True, mark_resumed=True,
        target_override=target_override,
        fresh_session=fresh_session,
        secret_key=secret_key,
        secret_value=secret_value,
    )
    return {
        "new_job_id": new_id,
        "hint": _public_hint(new_id, manual_hint),
        "stopped_from": safe,
        "prev_status": prev_status,
        "halt": halt_info,
        "carried_work": (jd / "work").is_dir(),
        "fresh_session": fresh_session,
        "target_overridden": target_override is not None,
    }


def _halt_source_job(safe: str, prev_meta: dict) -> dict:
    """Hard-stop a queued/running job and rewrite its meta so the UI
    no longer shows it as live. Late-imports _hard_stop_job to avoid a
    circular at module load.
    """
    from api.routes.jobs import _hard_stop_job
    from api.stop_audit import append_operator_stop_audit
    from modules.codex_turn_guard import request_turn_stop, wait_for_turn_teardown

    request_turn_stop(JOBS_DIR / safe / "work")
    halt = _hard_stop_job(safe)
    try:
        timeout_s = float(os.environ.get("CODEX_STOP_ACK_TIMEOUT_S", "15"))
    except (TypeError, ValueError):
        timeout_s = 15.0
    acknowledged, waited_s = wait_for_turn_teardown(
        JOBS_DIR / safe / "work",
        timeout_s=max(0.0, timeout_s),
    )
    stopped_meta = append_operator_stop_audit({
        **prev_meta,
        "status": "stopped",
        "stopped_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "error": "Stopped by user (resume with extra hint)",
        "error_kind": "stopped_for_resume",
    }, action="stop_and_resume", previous_status=prev_meta.get("status"),
        halt=halt, termination_acknowledged=acknowledged,
        acknowledgement_wait_ms=round(waited_s * 1000))
    write_job_meta(safe, stopped_meta)
    halt = {
        **halt,
        "termination_acknowledged": acknowledged,
        "acknowledgement_wait_ms": round(waited_s * 1000),
    }
    if not acknowledged:
        raise HTTPException(
            status_code=409,
            detail={
                "kind": "stop_ack_timeout",
                "message": (
                    "source Codex process has not acknowledged termination; "
                    "no successor job was created"
                ),
                "stopped_from": safe,
            },
        )
    return halt


_CTF_CONTEXT_HEADER = (
    "[CTF CONTEXT — authorized challenge instance]\n"
    "You are solving an isolated CTF challenge on behalf of the operator. "
    "The target host is a chal-platform-issued instance (e.g. Dreamhack, "
    "pwnable.kr, picoCTF, in-house competition infra) — NOT a production "
    "system, NOT a third-party service. Any out-of-band callback used to "
    "report the recovered flag goes through the orchestrator's own "
    "collector endpoint, which is provisioned for this job. No external "
    "third-party services and no unauthorized infrastructure are involved.\n"
    "Standard exploit-development primitives — heap grooming, FSOP, ROP, "
    "libc gadgets, one_gadget, hook overwrites, format-string writes, "
    "deserialization gadgets, SSRF chains — are the expected, authorized "
    "techniques for this challenge class. The chal's `flag` file IS the "
    "goal artifact.\n"
)


_STALE_PATH_WARNING_TMPL = (
    "🚨 CRITICAL — your cwd has CHANGED since the prior session.\n"
    "The prior agent's tool history shows absolute writes like "
    "`{stale_example}`. THAT PATH IS NOW STALE — "
    "the new job has a DIFFERENT id and the orchestrator collects "
    "artifacts ONLY from your CURRENT cwd. Writing to the old "
    "absolute path will silently leak edits into the dead prior "
    "directory and your retry will return UNCHANGED files.\n"
    "RULES for every Write/Edit/Bash you issue from now on:\n"
    "  • Use bare names (`exploit.py`, `report.md`) or `./`-relative "
    "paths (`./decomp/main.c`).\n"
    "  • NEVER write to `/data/jobs/{prev_id}/...` — that directory "
    "is no longer yours{stale_marker_note}.\n"
    "  • NEVER `cd /data/jobs/{prev_id}/...` — your cwd is already "
    "{cwd_desc}; there is no reason to leave it.\n"
    "  • NEVER write to `/root/...` (empty home dir).\n"
    "{work_rule}"
    "MANDATORY FIRST CALL — before ANY other tool, run exactly:\n"
    "  Bash(command=\"pwd && echo \\\"job_id=$JOB_ID\\\" && ls -la\", "
    "description=\"anchor cwd on retry\")\n"
    "If pwd doesn't match `{pwd_expect}`, stop and "
    "re-orient before any further tool call."
)


# `work_rule` / `pwd_expect` exist because the cwd is NOT the same shape in
# every module. web / pwn / rev / crypto / web3 run the agent in
# `<job>/work/`; misc and forensic run it in the job root itself
# (`work_dir = _job_dir(job_id)` in their orchestrators), so they have no
# `work/` at all and `_resubmit`'s `if prev_work.is_dir()` carries NOTHING.
#
# Before this was parameterised the template asserted `/data/jobs/$JOB_ID/work`
# unconditionally, so the MANDATORY FIRST CALL told every misc/forensic retry
# child to "stop and re-orient before any further tool call" — an instruction
# to halt, handed to the agent as its opening move. Observed lineage:
# b7c25bb93d13 -> 56b4d47d5b4c (forensic), where neither job has a work/ dir.
def _stale_path_warning(prev_id: str, *, work_tree: bool) -> str:
    """The stale-path block, told truthfully for this module's cwd shape."""
    if work_tree:
        return _STALE_PATH_WARNING_TMPL.format(
            prev_id=prev_id,
            pwd_expect="/data/jobs/$JOB_ID/work",
            cwd_desc="the new job's work tree",
            stale_example="/data/jobs/%s/work/exploit.py" % prev_id,
            stale_marker_note=("; you'll find a "
                               "`_STALE_DO_NOT_WRITE_HERE.md` marker if you "
                               "`ls` it"),
            work_rule=("  • NEVER prefix with `./work/` (doubled path — "
                       "your cwd IS the work tree).\n"),
        )
    # The example path and the cwd description have to move together with the
    # rule below them. Left literal, the block told a job-root agent that its
    # cwd "is already the new job's work tree" four lines above the bullet
    # saying there is no work tree — and cited a predecessor write to
    # `<prev>/work/exploit.py`, a path that module never used and a filename it
    # never produces, since it writes no script at all.
    return _STALE_PATH_WARNING_TMPL.format(
        prev_id=prev_id,
        pwd_expect="/data/jobs/$JOB_ID",
        cwd_desc="the new job's directory",
        stale_example="/data/jobs/%s/report.md" % prev_id,
        # No marker is promised here. `_drop_stale_sentinel` runs inside the
        # copytree branch, so a prior job with no `work/` never gets one —
        # and an agent told to expect a marker, that then `ls`es and finds
        # none, reads the directory as still live. Exactly backwards.
        stale_marker_note="",
        work_rule=("  • There is NO `./work/` subdirectory in this module — "
                   "your cwd IS the job directory. Do not look for one.\n"),
    )


# What the carry does NOT bring across, stated where the preamble already
# enumerates what it DOES.
#
# The work tree and the forked conversation both survive a slot change: /data
# and /root/.claude are shared mounts, and _carry_session_jsonl keys the
# transcript by project_key_for_directory(cwd), which is the new job dir — the
# same path on any slot. Globally-installed packages do NOT survive, and that
# is new: the worker used to be ONE container shared by every job, so a
# `pip install` from the previous attempt was always still there on a retry.
# It is now one container per slot, and a retry goes back to the queue, so it
# may well run somewhere else. modules/rev/prompts.py explicitly tells rev
# agents to install bytecode decompilers on demand, which is exactly the case
# that breaks.
#
# Deliberately framed as "re-install, don't assume" rather than as a warning
# about slots: the agent cannot see which slot it is on, and the same advice is
# correct on a fresh container for any other reason. It also matches what the
# sandbox does — the runner image never had those packages either, so anything
# silently depending on one would have failed at auto-run regardless.
_CARRY_LIMITS_NOTE_TMPL = (
    "CARRIED vs NOT: {what_came}. Anything the previous attempt installed "
    "GLOBALLY — `pip install`, `apt-get install` — did NOT, and neither did "
    "its /tmp files; you may be on a fresh container. Re-run the install if "
    "you need the tool, prefer installing into {install_target}, and keep a "
    "path that works without it (the sandbox that auto-runs your exploit "
    "never had those packages either).\n\n"
)


def _carry_limits_note(*, carried: bool, work_tree: bool) -> str:
    """What did and did not come across, told per module shape.

    The note used to open with "your cwd and (unless stated otherwise above)
    the prior conversation came with you" unconditionally. For a module whose
    agent runs in the job root there is no work tree to copy, so the cwd did
    NOT come with it — and the note sat three lines under the sentence saying
    exactly that. The conversation half is true for every module since
    760a011 wired resume/fork_session into misc and forensic.
    """
    if carried:
        return _CARRY_LIMITS_NOTE_TMPL.format(
            what_came=("your cwd and (unless stated otherwise above) the "
                       "prior conversation came with you"),
            install_target="the work tree" if work_tree else "your cwd",
        )
    return _CARRY_LIMITS_NOTE_TMPL.format(
        what_came=("the prior conversation came with you (unless stated "
                   "otherwise above); your cwd did NOT — no files were "
                   "carried, as said above"),
        install_target="the work tree" if work_tree else "your cwd",
    )


_RETRY_ANTI_OVERFIT_NOTE = (
    "PROBLEM-SOLVING / ANTI-OVERFIT CONTRACT:\n"
    "The goal is the real remote result, not preserving the previous theory "
    "or polishing a script that has no verified end-to-end chain. Explicit "
    "operator decisions remain authoritative; technical claims from prior "
    "artifacts, model conclusions, and retry hints do not. Treat such claims "
    "as hypotheses unless source or an executed probe supports them.\n"
    "Before editing, classify the failure as IMPLEMENTATION (verified chain, "
    "broken code), STRATEGY (chain/prerequisite disproved), ENVIRONMENT, or "
    "UNKNOWN. Preserve verified primitives and record which branches are "
    "refuted. For IMPLEMENTATION, patch the concrete defect. For STRATEGY or "
    "UNKNOWN, do not keep tuning the same payload, wordlist, or wrapper: form "
    "at least two materially different, untested hypotheses and run the "
    "cheapest discriminating test for each before choosing a new chain. Do "
    "not repeat a refuted branch without new evidence that changes a premise. "
    "Do not call a route intended/required/unnecessary without direct "
    "evidence. Defer report, timeout, and parser polish until a required "
    "primitive has produced its expected runtime signal.\n\n"
)

# Truncation kinds: the attempt stopped before its hypothesis was tested.
#
# The vocabulary is the ORCHESTRATOR'S, not a second opinion about what a
# timeout is. The first version of this set said so in a comment and then got
# a member wrong anyway: it listed `budget`, which no producer ever writes —
# `modules/_common.py:9259` writes `budget_fallback`. A dead token silently
# rates a truncation as `looked: true`, which is the exact misreading K1-c
# exists to prevent, so both directions are now pinned by a census regression
# (`scripts/test_lineage_technique_carry.py`): every member here must be
# producible, and every producible kind must be classified in exactly one of
# these two sets.
#
# The split is "did this attempt get to find out?", not "was it our fault".
_TRUNCATED_KINDS = frozenset({
    "timeout",               # classify_agent_error / _STOP_REASON_KIND
    "killed",                # _common.py:9342 (SIGKILL / OOM)
    "policy_refusal",        # AUP block — the run never started
    "transport_error",       # _STOP_REASON_KIND: process_error / EOF
    "transport_unavailable",  # live_fire_job.py:48
    "budget_fallback",       # _common.py:9259 — tool budget cut the turn short
    "rate_limit",            # classify_agent_error — provider refused to serve
    "auth",                  # classify_agent_error — never authenticated
    "cli_infra_error",       # bundled CLI failed to start (glibc pollution)
    "target_unusable",       # _runner.py:1147 — remote target never answered
    "stopped_for_resume",    # retry.py:1362 — operator halted it mid-flight
})

# Kinds where the run DID happen and failed on its own terms. These are real
# evidence about the mechanism, so they carry `looked: true`. `agent_error` is
# here deliberately: a generic agent failure is not a truncation. NB until the
# peer's `classify_stop_reason` work lands, misc/forensic flatten a Codex CLI
# turn timeout into `agent_error` (measured: b7c25bb93d13, 56b4d47d5b4c,
# fd5bb1470319 all carry `[Codex CLI turn timed out after 3600s]` in run.log
# and `error_kind=agent_error` in meta), so those three read as `looked: true`
# here until that fix merges. That is a producer defect, not a reason to widen
# this set — widening it would rate every genuine agent failure as untested.
_RAN_KINDS = frozenset({
    "agent_error",
    "agent_exception",
    "import_error",
    "unknown",
})


def _technique_of(job_dir: Path) -> str | None:
    """The mechanism a finished attempt said its challenge WAS.

    `chain.technique_name` for pwn/web/crypto, `solver_strategy.technique_name`
    for rev. Deliberately NOT `solver_strategy.approach`: measured on 2026-08-25,
    approach was `static-emit` in 16 of the 18 findings that had a strategy at
    all, so carrying it forward would carry no information.
    """
    try:
        data = json.loads((job_dir / "findings.json").read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    chain = data.get("chain") if isinstance(data.get("chain"), dict) else {}
    strategy = (data.get("solver_strategy")
                if isinstance(data.get("solver_strategy"), dict) else {})
    name = chain.get("technique_name") or strategy.get("technique_name")
    name = str(name or "").strip()
    return name or None


def _carry_technique_history(prev_meta: dict, prev_jd: Path) -> list[dict]:
    """The lineage's mechanisms, oldest first, with the parent appended.

    Mirrors `flag_rejected`: accumulate down the chain rather than recomputing,
    so a grandchild sees what the grandparent tried without walking the tree.

    Each entry says whether the attempt actually TESTED its mechanism.
    `looked` is false when the run was cut off — a timeout is not evidence the
    mechanism was wrong, and three of 2026-08-25's jobs died that way with the
    operator's job_timeout set to 9999999.

    An entry survives with NO technique when the attempt was truncated: a run
    that was cut off before it wrote findings.json named nothing, and dropping
    it would hide the cut-off itself. Both of the forensic attempts the K2
    corpus excluded (`b7c25bb93d13`, `56b4d47d5b4c`) are that shape — no
    findings.json at all — so without this the child of a truncated attempt
    would see a history that says the attempt never happened.
    """
    history = [
        h for h in (prev_meta.get("technique_history") or [])
        # A truncated entry has no technique to carry and must still survive the
        # next hop; keying the filter on `technique` alone dropped exactly the
        # entries K1-c adds.
        if isinstance(h, dict) and (h.get("technique") or h.get("looked") is False)
    ]
    technique = _technique_of(prev_jd)
    # The key is `error_kind`. meta.json has never held `agent_error_kind` —
    # that is the RESPONSE field name (`api/routes/jobs.py:1461` renames it on
    # the way out) and the result.json field name. Counted over every job tree
    # on disk, 95 of them:
    #
    #     error_kind        key present on 86, absent on 9
    #                       of the 86: null 74, non-null 12
    #                       (stopped_for_resume 4, agent_error 3,
    #                        transport_error 2, unknown 2, timeout 1)
    #     agent_error_kind  present on 0
    #
    # An earlier version of this comment said 96 trees and 22 present. Both
    # were wrong and the second was wrong by a factor of four — it appears to
    # have counted something other than the key. Reading the wrong KEY is the
    # defect that mattered: it made `looked` unconditionally true, so K1-c was
    # inert in production while its suite passed on a fabricated key.
    kind = str(prev_meta.get("error_kind") or "").strip().lower()
    truncated = kind in _TRUNCATED_KINDS
    if technique or truncated:
        history = history + [{
            "job_id": prev_meta.get("id"),
            "technique": technique,
            "status": prev_meta.get("status"),
            # K1-c. False means "this attempt did not get to find out", which is
            # a different fact from "this mechanism did not work".
            "looked": not truncated,
            "stopped_by": kind or None,
        }]
    # A lineage can run long; keep the tail. 12 is the same visible-window size
    # the exploit-library hint uses, for the same reason: past it the prompt
    # grows without the reader gaining anything.
    return history[-12:]


def _technique_history_block(history: list[dict]) -> str:
    """Render the history for the retry preamble, or "" when there is none.

    The instruction attached to it is NOT "do not repeat". That rule is refuted
    by this project's own corpus: r.0.0.mca was retried five times, every
    attempt naming the same mechanism, and it went no_flag, no_flag, finished,
    finished, finished. Repeating the mechanism is how it was solved.

    What the agent is asked for is a DECLARATION: re-executing, or refuting.
    The failure this addresses is the other lineage — instagram.exe, seven
    attempts, six distinct technique strings that a reading of the artifacts
    resolves to two mechanisms. Nothing there noticed it was circling.
    """
    if not history:
        return ""
    lines = ["[what this lineage has already named]"]
    for h in history:
        if h.get("looked"):
            outcome = h.get("status") or "?"
        else:
            outcome = "NOT TESTED — cut off by %s" % (h.get("stopped_by") or "?")
        # A truncated attempt can have named nothing at all — it died before it
        # wrote findings.json. Say so rather than rendering "None", because the
        # useful fact for the reader is that an attempt was spent, not that a
        # field is empty.
        lines.append("  - %s   (%s, %s)"
                     % (h.get("technique") or "(no mechanism recorded)",
                        h.get("job_id") or "?", outcome))
    lines.append("")
    lines.append(
        "Naming the same mechanism again is ALLOWED and is sometimes right: a "
        "prior attempt can have identified the mechanism correctly and failed "
        "to execute it. What is not allowed is leaving it ambiguous. State "
        "which you are doing:\n"
        "  RE-EXECUTING <mechanism> — say what you will do DIFFERENTLY this "
        "time, at the execution level.\n"
        "  REFUTING <mechanism> — say what evidence rules it out, then name "
        "the new one.\n"
        "An entry marked NOT TESTED did not get to find out. It is not "
        "evidence against that mechanism and must not be treated as a dead "
        "end."
    )
    return "\n".join(lines) + "\n\n"


def _retry_preamble(prev_id: str, hint: str, *, fresh: bool = False,
                    operator_text: bool = False,
                    history: list[dict] | None = None,
                    carried: bool = True,
                    work_tree: bool = True) -> str:
    """Preamble for the standard retry path (failed / no_flag /
    finished). The new agent is launched with `resume=<prev_session>` +
    `fork_session=True`, so its conversation already holds the prior
    reasoning, thinking, and tool history; ./work/ has been carried
    over so any path the prior agent wrote still resolves.

    The stale-path warning is the load-bearing part: without it, the
    forked agent re-uses the prior absolute paths from its tool
    history (`/data/jobs/<prev_id>/work/...`), edits the OLD job dir,
    and our `collect_outputs(work_dir, ...)` step picks up the
    untouched carry-copy in the NEW job dir.

    `fresh=True` (operator picked "fresh context"): the conversation was
    NOT forked, so there is NO prior reasoning/tool-history in context.
    The preamble must say so explicitly — telling a context-less agent to
    "continue from your conversation" (the forked wording) is a lie that
    wastes turns hunting for history it doesn't have. Instead, frame the
    carried ./work/ files + the hint as the sole starting point. The
    stale-path warning still applies: the carried files were authored
    under the OLD job's absolute paths, so the bare/relative-path rule
    matters regardless of whether a transcript was forked.
    """
    # The operator's own words go through untouched. _sanitize_hint exists to
    # keep MODEL-generated phrasing from tripping the prompt classifier; a human
    # who typed "reverse shell to 127.0.0.1:4444" meant that, and silently
    # rewriting it is the same class of defect as the provenance mislabelling
    # fixed on 2026-08-24 — the reader is told something the author did not say.
    _hint_text = hint if operator_text else _sanitize_hint(hint)
    # Rendered before the hint, not after: the agent should know what the
    # lineage has already named BEFORE it reads an instruction that may
    # push it toward one of those names again.
    _hist_block = _technique_history_block(history or [])
    # `carried` is False for modules whose agent cwd is the job root (misc,
    # forensic): there is no `<job>/work/` for `_resubmit` to copy, so the
    # carry silently did nothing. Saying "your predecessor's files are at ./"
    # to an agent standing in an empty tree costs it the turns it spends
    # looking, and the previous wording additionally told it to STOP.
    _cwd_desc = "work tree" if work_tree else "directory"
    # WHY nothing arrived — two different facts that used to share one flag.
    # A job-root module has no work/ to copy at all; a work-tree module can
    # have one that held nothing worth copying. Saying the first to a pwn
    # agent standing in a real (if empty) work tree is the mirror image of
    # the bug this wording was written to fix.
    _why_empty = ("the previous attempt left nothing worth copying, so your "
                  "cwd is an empty work tree holding only this job's own "
                  "inputs" if work_tree else
                  "this module keeps no `work/` tree, so your cwd holds only "
                  "this job's own inputs")
    _carry_note = (
        "The previous attempt's artifacts — exploit.py / solver.py / "
        "report.md / findings.json / THREAT_MODEL.md / decomp/ / bin/ / "
        "its scratch files — have been COPIED into your cwd at `./`. "
        "START by reading the relevant ones (`ls -la`, then read "
        "report.md / exploit.py / findings.json) so you reconstruct where "
        "the prior attempt got to, THEN apply the hint below. "
        if carried else
        "NOTHING was carried from the previous attempt — " + _why_empty +
        ". Do NOT hunt for the prior attempt's files; they are not here. "
        "Reconstruct what it established from your conversation history "
        "(if you have one) and the hint below, then start work. "
    )

    if fresh:
        return (
            _CTF_CONTEXT_HEADER
            + _hist_block
            + f"\n[retry of job {prev_id} — FRESH CONTEXT, conversation NOT "
            "forked]\n"
            "You are starting with a CLEAN context. There is NO prior "
            "conversation, reasoning, or tool history available to you — do "
            "NOT look for it or assume you remember earlier turns. Everything "
            "you have is: " + ("(1) the carried work tree in your cwd, and "
                                "(2) the hint below.\n" if carried else
                                "(1) this job's own inputs in your cwd — the "
                                "prior attempt's files were NOT carried — and "
                                "(2) the hint below.\n")
            + _stale_path_warning(prev_id, work_tree=work_tree)
            + f"\n\nYour current working directory IS the new job's {_cwd_desc}. "
            + _carry_note
            + "Every Write/Edit MUST use bare or `./`-relative paths per the "
            "rules above.\n\n"
            + _carry_limits_note(carried=carried, work_tree=work_tree)
            + _RETRY_ANTI_OVERFIT_NOTE
            + f"{_hint_text}"
        )
    return (
        _CTF_CONTEXT_HEADER
        + _hist_block
        + f"\n[retry of job {prev_id} — prior-session fork requested]\n"
        + _stale_path_warning(prev_id, work_tree=work_tree)
        + f"\n\nYour current working directory IS the new job's {_cwd_desc}. "
        + (("Everything the previous agent produced — partial "
            "exploit.py / solver.py / report.md / decomp/ / extracted/ "
            "/ bin/ / scratch — has been COPIED into your new cwd and "
            "sits directly at `./`. ") if carried else
           ("NOTHING was carried from the previous attempt — " + _why_empty
            + ". Do NOT hunt for the prior attempt's files. "))
        + f"If your conversation context "
        f"already shows the prior reasoning + tool history, continue "
        f"from where you left off in light of the hint below — but "
        f"every new Write/Edit MUST use bare or `./`-relative paths "
        f"per the rules above. If the SDK couldn't locate the prior "
        f"session (rare), `ls` once and read whichever file matters "
        f"before applying the hint.\n\n"
        + _carry_limits_note(carried=carried, work_tree=work_tree)
        + _RETRY_ANTI_OVERFIT_NOTE
        + f"{_hint_text}"
    )


def _resume_preamble(prev_id: str, hint: str, *, fresh: bool = False,
                     operator_text: bool = False,
                     history: list[dict] | None = None,
                     carried: bool = True,
                     work_tree: bool = True) -> str:
    """Preamble for stop-and-resume. Same fork semantics as retry, but
    the prior session was halted MID-RUN by the user — so the agent
    should treat the work as in-flight ("pick up where you left off")
    rather than as a finished failure to revisit.

    The lineage block belongs here too. The first pass at K1-a left it out on
    the stated grounds that "a resume keeps the SAME job id, so there is no
    child and no carry" — that describes `_continue_in_place` (":752-755",
    which really does re-enqueue the same id), not `/resume`. `/resume` calls
    `_resubmit`, which mints a `new_job_id()` and writes `technique_history`
    into the child meta unconditionally. So resume children were accumulating a
    history no reader ever saw, which is the carry without the point of it.

    Same stale-path concern as retry: the forked tool history
    references `/data/jobs/<prev_id>/work/...`, but the new cwd is
    `/data/jobs/<new_id>/work/`. Without the explicit warning the
    agent edits the dead directory.

    `fresh=True`: conversation NOT forked — see _retry_preamble. There is
    no prior transcript to "continue from", so reconstruct state from the
    carried ./work/ files + hint instead.
    """
    # The operator's own words go through untouched. _sanitize_hint exists to
    # keep MODEL-generated phrasing from tripping the prompt classifier; a human
    # who typed "reverse shell to 127.0.0.1:4444" meant that, and silently
    # rewriting it is the same class of defect as the provenance mislabelling
    # fixed on 2026-08-24 — the reader is told something the author did not say.
    _hint_text = hint if operator_text else _sanitize_hint(hint)
    # Before the hint, for the same reason as in _retry_preamble: the agent
    # should know what the lineage has already named before it reads an
    # instruction that may push it back toward one of those names.
    _hist_block = _technique_history_block(history or [])
    # See _retry_preamble: misc / forensic have no `<job>/work/`, so the carry
    # copies nothing and the "everything you wrote is at ./" wording is false.
    _cwd_desc = "work tree" if work_tree else "directory"
    _why_empty = ("the previous attempt left nothing worth copying, so your "
                  "cwd is an empty work tree holding only this job's own "
                  "inputs" if work_tree else
                  "this module keeps no `work/` tree, so your cwd holds only "
                  "this job's own inputs")

    if fresh:
        return (
            _CTF_CONTEXT_HEADER
            + _hist_block
            + f"\n[resume of job {prev_id} — FRESH CONTEXT, conversation NOT "
            "forked]\n"
            "You are starting with a CLEAN context. There is NO prior "
            "conversation, reasoning, or tool history available — do NOT look "
            "for it. The prior run was halted mid-work; "
            + ("everything it had written has been COPIED into your cwd at "
               "`./`.\n" if carried else
               "NOTHING it wrote was carried — " + _why_empty + ".\n")
            + _stale_path_warning(prev_id, work_tree=work_tree)
            + f"\n\nYour current working directory IS the NEW job's {_cwd_desc}. "
            + (("START by reading the in-progress artifacts (`ls -la`, then "
                "report.md / exploit.py / solver.py / findings.json / "
                "THREAT_MODEL.md) to reconstruct where the work stood, THEN "
                "continue it in light of the guidance below — do not restart "
                "the analysis from scratch. ") if carried else
               ("The halted run's files are NOT here. Do not hunt for them; "
                "reconstruct what it established from the guidance below and "
                "continue rather than restarting. "))
            + "Every Write/Edit MUST use bare or "
            "`./`-relative paths per the rules above.\n\n"
            + _carry_limits_note(carried=carried, work_tree=work_tree)
            + f"{_hint_text}"
        )
    return (
        _CTF_CONTEXT_HEADER
        + _hist_block
        + f"\n[resume of job {prev_id} — interrupted, same session forked]\n"
        + _stale_path_warning(prev_id, work_tree=work_tree)
        + "\n\nYour prior session was halted mid-run. Your current "
        + f"working directory IS the NEW job's {_cwd_desc}"
        + ((" — whatever files you had already written have been COPIED "
            "into the new cwd and sit directly at `./`. ") if carried else
           ", and the files you had already written were NOT carried — "
           + _why_empty + ". Do not hunt for them. ")
        + f"If your conversation "
        f"context still has the prior reasoning + tool history, "
        f"continue exactly where you left off and apply the new "
        f"guidance below — do not restart the analysis, and remember "
        f"every new Write/Edit MUST use bare or `./`-relative paths. "
        f"If the SDK couldn't locate the prior session (rare), `ls` "
        f"once and read whichever file matters before applying the "
        f"hint.\n\n"
        + _carry_limits_note(carried=carried, work_tree=work_tree)
            + f"{_hint_text}"
    )


@router.post("/{job_id}/resume/stream")
async def stop_and_resume_stream(job_id: str, request: Request):
    """Streaming variant of /resume. Stops the running source job, then
    either uses the user's `{"hint": "..."}` body verbatim or — when the
    body is empty — calls the latest reviewer to write the hint, exactly
    like /retry/stream. Either way the new job carries the prior agent's
    work/ and gets a [RESUMING] preamble.

    SSE events:
      stage : {"name": "halting" | "gathering" | "asking" | "submitting"}
      token : {"delta": "<reviewer text>"}
      done  : {"new_job_id": "...", "hint": "...", "stopped_from": "...",
               "manual": bool, "carried_work": bool}
      error : {"message": "...", "kind": "..."}
    """
    safe = Path(job_id).name
    manual_hint, target_override, fresh_session, secret_key, secret_value = (
        await _read_retry_body(request)
    )
    jd, prev_meta = _validate_retry(safe, require_claude_auth=manual_hint is None)

    async def event_gen():
        def sse(name: str, data: dict) -> bytes:
            return f"event: {name}\ndata: {json.dumps(data)}\n\n".encode()

        prev_status = prev_meta.get("status")
        halt_info = None
        # 1) halt the source job up front so its watchdog/log doesn't keep
        #    growing while we ask the reviewer.
        if prev_status in ("queued", "running"):
            yield sse("stage", {"name": "halting"})
            try:
                halt_info = await asyncio.to_thread(_halt_source_job, safe, prev_meta)
            except Exception as e:
                yield sse("error", {
                    "message": f"halt failed: {e}",
                    "kind": "halt",
                })
                return

        # 2) decide the hint — manual vs reviewer.
        hint = manual_hint or ""
        if manual_hint is None:
            yield sse("stage", {"name": "gathering"})
            await asyncio.sleep(0)
            try:
                context = _gather_context(roots=(jd,))
                if not context.strip():
                    yield sse("error", {
                        "message": "no prior-job context found to review",
                        "kind": "no_context",
                    })
                    return
            except Exception as e:
                yield sse("error", {
                    "message": f"gather failed: {e}",
                    "kind": "gather",
                })
                return

            _rv_model = resolve_reviewer_model(job_id)
            # Announce what will actually run. `resolve_reviewer_model` coerces
            # to the WHOLE-JOB provider, so a routed reviewer was announced as
            # one model and then called as another — and the UI presents this
            # as fact.
            _rv_provider, _rv_shown = _reviewer_provider_and_model(_rv_model, job_id)
            yield sse("stage", {
                "name": "asking", "model": _rv_shown, "provider": _rv_provider,
            })
            try:
                async for kind, payload in _ask_reviewer_streaming(
                    context, model=_rv_model, job_id=job_id):
                    if kind == "token":
                        yield sse("token", payload)
                    elif kind == "note":
                        # A failover is in progress. Dropping this left the UI
                        # with an unexplained pause between two providers.
                        yield sse("note", payload)
                    elif kind == "done":
                        hint = payload.get("hint", "")
                    elif kind == "error":
                        yield sse("error", payload)
                        return
            except Exception as e:
                raw = str(e)
                yield sse("error", {
                    "message": f"reviewer failed: {raw}",
                    "kind": _reviewer_error_kind(raw),
                })
                return

        # 3) submit the new job with the same [RESUMING] preamble used
        #    by /resume + carry_work=True.
        yield sse("stage", {"name": "submitting"})
        # Same shape as the streaming retry above: the reviewer branch is
        # guarded by `if manual_hint is None`, so a surviving manual_hint is
        # operator text and must not be sanitized.
        augmented = _resume_preamble(
            safe, hint, fresh=fresh_session,
            operator_text=manual_hint is not None,
            history=_carry_technique_history(prev_meta, jd),
            carried=_carry_will_deliver(jd),
            work_tree=_agent_cwd_is_work_tree(prev_meta))
        try:
            new_id = _resubmit(
                prev_meta, augmented, jd,
                carry_work=True, mark_resumed=True,
                target_override=target_override,
                fresh_session=fresh_session,
                secret_key=secret_key,
                secret_value=secret_value,
            )
        except HTTPException as he:
            yield sse("error", {
                "message": f"submit rejected: {he.detail}",
                "kind": "submit",
            })
            return
        except Exception as e:
            yield sse("error", {
                "message": f"submit failed: {e}",
                "kind": "submit",
            })
            return

        yield sse("done", {
            "new_job_id": new_id,
            "hint": _public_hint(new_id, hint),
            "stopped_from": safe,
            "prev_status": prev_status,
            "manual": manual_hint is not None,
            "carried_work": (jd / "work").is_dir(),
            "fresh_session": fresh_session,
            "halt": halt_info,
            "target_overridden": target_override is not None,
        })

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
