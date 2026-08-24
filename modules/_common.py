"""Shared helpers for module orchestrators."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Dict  # noqa: F401

# Large prompt strings live in modules/_prompts.py (extracted to keep
# this file navigable). Re-exported here so existing references resolve.
from modules._prompts import (  # noqa: E402,F401
    mission_block,
    adapt_system_prompt_for_grok,
    GROK_DELEGATION_CONTRACT,
    GROK_ROLE_TO_SUBAGENT_TYPE,
    CTF_PREAMBLE,
    _TOOLS_BASE,
    TOOLS_WEB,
    TOOLS_PWN,
    TOOLS_REV,
    TOOLS_CRYPTO,
    TOOLS_WEB3,
    TOOLS_FORENSIC,
    TOOLS_MISC,
    RECON_AGENT_PROMPT,
    JUDGE_AGENT_PROMPT,
    TRIAGE_AGENT_PROMPT,
    DEBUGGER_AGENT_PROMPT,
)
from modules.storage import DATA_DIR, JOBS_DIR  # noqa: E402
from modules._events import emit_event  # noqa: E402

# Common CTF flag formats. The leading prefix can vary per event; cover the
# usual suspects + a generic short-prefix fallback.
FLAG_RE = re.compile(
    r"(?:FLAG|flag|CTF|ctf|HTB|htb|picoCTF|pico|DH|dreamhack|HACKTHEBOX|"
    r"BSidesCP|XCTF|KCTF|TWN|hcamp|hackcamp|samsung|N0PSctf|CCE)\{[^\s}]{1,200}\}",
    re.IGNORECASE,
)
LIBERAL_FLAG_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9_]{1,16}\{[!-~]{2,200}\}")

# A generic sweep of regex SOURCE such as ``DH{[^}]+}`` sees ``DH{[^}`` as a
# complete flag because the character-class ``}`` also closes FLAG_RE's match.
# The candidate alone is indistinguishable from a real flag, so reject it only
# when the bytes immediately AFTER the match complete that exact source shape:
# ``]`` + regex quantifier + literal closing ``}``.  Explicit FLAG_CANDIDATE
# markers are parsed separately and never consult this rule.
_REGEX_SOURCE_TAIL_RE = re.compile(r"\](?:[+*?]|\{\d+(?:,\d*)?\})\}")

# Explicit flag declaration emitted by the exploit/solver itself.
# The agent is instructed (CTF_PREAMBLE) to print `FLAG_CANDIDATE: <flag>`
# on its own line to stdout once it has captured the flag from a genuine
# run. This is the AUTHORITATIVE flag source: it carries no flag-format
# assumption (works for DH{...}, FLAG{...}, raw-hex, or any prefix-less
# format), so it sidesteps the FLAG_RE prefix list and the placeholder
# heuristics entirely. MULTILINE so each printed line matches on its own;
# the capture runs to end-of-line and is trimmed by the caller.
_FLAG_MARKER_RE = re.compile(
    r"FLAG[_-]?CANDIDATE\s*[:=]\s*([^\r\n]+)",
    re.IGNORECASE | re.MULTILINE,
)
# Some trusted sources (for example callbacks.jsonl) embed the run's stdout as
# a JSON string, so the marker line's terminating
# newline becomes a literal `\n` (two chars) and the rest of the JSON (`",`
# the next key, ...) rides on the same PHYSICAL line. `[^\r\n]+` then over-
# captures `DH{...}\n",` (real job a3d4d4484233). Cut the candidate at the
# first literal escape sequence so we keep only the declared flag; raw
# stdout (real newlines) has no such sequence, so this is a no-op there.
_MARKER_ESCAPE_RE = re.compile(r"\\[nrtu\"\\]")


# ---------------------------------------------------------------------------
# Bash kill-guard (PreToolUse hook)
# ---------------------------------------------------------------------------
# An agent cleaning up its own background test scripts with a broad process
# kill can SIGTERM the job's own processes and abort the run:
#   * `pkill -f <pat>` matches the FULL /proc/<pid>/cmdline. The SDK passes the
#     system_prompt as `--system-prompt <prompt>`, so the agent's claude CLI
#     cmdline contains the prompt text — `pkill -f "exploit.py"` is a fratricide
#     (job fcc2e85c6a78 self-killed exactly this way → exit 143/SIGTERM mid-run).
#   * `pkill`/`killall` of python/python3/node/claude/sh/... kills the RQ worker
#     running THIS job (python), the agent's claude CLI, or the wrapping shell.
# The prompt already warns against this (modules/_prompts.py PROCESS HYGIENE) but
# the agent ignored it (fcc2), so this hook HARD-BLOCKS the dangerous forms while
# leaving precise termination (kill <PID>, kill -- -<PGID>, `timeout`,
# `pkill -9 -x <basename>`) free.
_KILL_PROTECTED = ("python3", "python", "node", "claude", "rqworker", "rq",
                   "bash", "zsh", "dash", "sh")
_PKILL_FULL_RE = re.compile(r"\bpkill\b[^\n;&|]*?(?:\s-[a-zA-Z]*f|\s--full)\b", re.I)
_PROTECTED_KILL_RE = re.compile(
    r"\b(?:pkill|killall)\b[^\n;&|]*?\b(?:" + "|".join(_KILL_PROTECTED) + r")\b", re.I)
_PGREP_FULL_RE = re.compile(r"\bpgrep\b[^\n;&|]*?(?:\s-[a-zA-Z]*f|\s--full)\b", re.I)

_KILL_GUARD_MSG = (
    "BLOCKED: this would kill the job's own processes and abort the run. "
    "`pkill -f <pat>` matches the claude CLI / tool-shell /proc cmdline (the SDK "
    "puts your system_prompt there), and killing python3/node/claude/sh kills the "
    "RQ worker running THIS job — job fcc2e85c6a78 self-killed via "
    "`pkill -f \"exploit.py\"` (exit 143). To stop YOUR OWN background script, "
    "target it precisely instead:\n"
    "  - by PID:           python3 driver.py & PID=$!; ... ; kill $PID\n"
    "  - self-terminating: timeout 5 python3 driver.py\n"
    "  - process group:    setsid python3 driver.py & kill -- -$!\n"
    "  - COMM-exact (a COMPILED inferior, never python/node): pkill -9 -x <basename>"
)


def dangerous_kill_reason(command: str) -> str | None:
    """Deny reason if `command` issues a process-kill broad enough to hit the
    job's own claude CLI / RQ worker / shell; else None. Precise kills
    (kill PID, kill -- -PGID, pkill -9 -x <non-protected comm>) return None."""
    if not command:
        return None
    if _PKILL_FULL_RE.search(command) or _PROTECTED_KILL_RE.search(command):
        return _KILL_GUARD_MSG
    # `kill $(pgrep -f ...)` / `pgrep -f ... | xargs kill` — indirect self-kill.
    if _PGREP_FULL_RE.search(command) and re.search(r"\b(?:kill|xargs)\b", command):
        return _KILL_GUARD_MSG
    return None


async def _bash_kill_guard(input_data, tool_use_id, context):
    """PreToolUse hook: deny self-killing Bash commands (see dangerous_kill_reason)."""
    try:
        if (input_data or {}).get("tool_name") != "Bash":
            return {}
        cmd = ((input_data.get("tool_input") or {}).get("command")) or ""
        reason = dangerous_kill_reason(cmd)
    except Exception:
        return {}
    if not reason:
        return {}
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


# ---------------------------------------------------------------------------
# Web-research block REMOVED 2026-07-22 (operator decision, reversing 9fcf3ab
# "block web search across all modules"). WebSearch/WebFetch are now ENABLED:
# recon owns the tools (see _AGENT_TOOLS_BY_TYPE) so main can delegate CVE /
# technique / doc lookups to it, and the PreToolUse deny hook + _WEB_BLOCK_MSG
# + web_block_matchers() that used to gate them are gone. Trade-off accepted:
# no anti-writeup gate — the agent CAN reach published writeups. Re-introduce
# the deny hook here (spread into kill_guard_hooks / main_session_hooks) if the
# policy is ever reversed again.


# ---------------------------------------------------------------------------
# Stale-target guard (PreToolUse hook on Bash)
# ---------------------------------------------------------------------------
# The orchestrator already notices a mid-run `Change Target` and injects a
# notice — but ONLY at a loop boundary, i.e. after `async for msg in
# client.receive_response()` returns. One receive_response() spans the agent's
# ENTIRE agentic turn, every tool call included, so on a long job that boundary
# can be hours away. Job 6e434e820b3f: the operator moved the target at
# 01:03:47 (:19231 -> :12949); at 01:10:27 main wrote a 90-iteration poll loop
# against the DEAD :19231, and the watchdog had still not fired once — the job
# had been inside a single turn since 23:18.
#
# A PreToolUse hook is the only thing in this codebase that runs MID-TURN, and
# the deny reason demonstrably reaches the model: in job 99cf1ec14d48 the
# kill-guard denied a Bash call at 01:41:40 and main re-issued the corrected
# command at 01:41:45.
#
# Staleness is derived from meta.target_url read fresh on every call — no new
# meta key, no "history" that only exists for changes made after this deploys,
# and it works for a job that was already running when the code landed.
_STALE_TARGET_MSG = (
    "BLOCKED: that endpoint is STALE. The operator changed this job's remote "
    "target mid-run:\n"
    "    OLD (now dead): {stale}\n"
    "    NEW (use this): {current}\n\n"
    "A challenge instance that expires and is restarted comes back on a "
    "different port, so any 'target is down / connection refused' conclusion "
    "you drew from the old value is WRONG — the service is most likely up "
    "right now. Re-point every remote()/connect/nc at {current} and re-run. "
    "Read the endpoint from sys.argv[1] rather than a hardcoded literal: the "
    "sandbox runner rewrites argv[1] from live meta on every run, so an "
    "argv-driven exploit survives the next change with no edit.\n\n"
    "Your analysis, work tree and files are all still valid — ONLY the "
    "endpoint moved. Do NOT restart the investigation."
)


def _split_host_port(target: str):
    """('host3.dreamhack.games', '19231') from a `host:port` target, else None."""
    m = re.fullmatch(r"\s*(?:\w+://)?([A-Za-z0-9._-]+):(\d{1,5})/?\s*", target or "")
    return (m.group(1), m.group(2)) if m else None


def stale_target_reason(command: str, current: str | None,
                        live_targets=()) -> str | None:
    """Deny reason if `command` aims at an endpoint the operator has superseded.

    Two shapes, both anchored on the CURRENT target so a generic host:port
    elsewhere in the command is never touched:
      A. port drift — the current host followed by a different port. Covers
         `host:PORT`, pwntools `remote("host", PORT)` and `nc host PORT`.
      B. host drift — a different host under the same registrable domain,
         e.g. host3.dreamhack.games -> host1.dreamhack.games.

    Never fires when the command also names the live target (so prose like
    "moved from X to Y", and a multi-target job's other endpoints, pass), and
    never for a target that is not host:port shaped.
    """
    hp = _split_host_port(current or "")
    if not command or not hp:
        return None
    host, port = hp
    ok = {t.strip() for t in (current, *(live_targets or ())) if t and t.strip()}
    if any(t in command for t in ok):
        return None
    stale = []
    # A — current host, some other port. The separator covers `:`, `", ` and ` `.
    for p in re.findall(re.escape(host) + r"""['"]?\s*[:,]\s*['"]?(\d{2,5})\b"""
                        r"""|""" + re.escape(host) + r"""\s+(\d{2,5})\b""", command):
        got = p[0] or p[1]
        if got and got != port:
            stale.append(f"{host}:{got}")
    # B — sibling host under the same last-two-label domain. Hostnames only:
    # on a bare IP the "domain" would be its last two octets, so 10.0.3.4 and
    # 192.168.3.4 would look like siblings.
    domain = ".".join(host.split(".")[-2:])
    if host.count(".") >= 2 and not re.fullmatch(r"[\d.]+", host):
        for h, p in re.findall(r"\b([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\."
                               + re.escape(domain) + r"):(\d{2,5})\b", command):
            if f"{h}:{p}" not in ok and (h != host or p != port):
                stale.append(f"{h}:{p}")
    if not stale:
        return None
    # Dedupe but keep first-seen order so the message names what it saw first.
    seen, ordered = set(), []
    for s in stale:
        if s not in seen:
            seen.add(s)
            ordered.append(s)
    return _STALE_TARGET_MSG.format(stale=", ".join(ordered), current=current)


def _stale_target_guard(job_id: str | None):
    """Factory → PreToolUse hook denying a Bash call aimed at a superseded
    endpoint. Reads meta on every invocation so it tracks live changes."""
    async def _guard(input_data, tool_use_id, context):
        if not job_id:
            return {}
        try:
            if (input_data or {}).get("tool_name") != "Bash":
                return {}
            cmd = ((input_data.get("tool_input") or {}).get("command")) or ""
            meta = read_meta(job_id) or {}
            reason = stale_target_reason(
                cmd, meta.get("target_url"), meta.get("target_urls") or ())
        except Exception:
            return {}
        if not reason:
            return {}
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
    return _guard


def kill_guard_hooks(job_id: str | None = None):
    """Hooks dict for ClaudeAgentOptions(hooks=...) that blocks self-killing
    Bash commands on the agent owning the session (main + isolated subagents),
    plus the stale-target guard so a subagent probing the remote also gets
    corrected mid-turn.

    The web-research block (WebSearch/WebFetch deny) was REMOVED here on
    2026-07-22 per operator decision — web research is now enabled (recon owns
    the web tools; see _AGENT_TOOLS_BY_TYPE)."""
    from claude_agent_sdk import HookMatcher
    return {"PreToolUse": [
        HookMatcher(matcher="Bash",
                    hooks=[_bash_kill_guard, _stale_target_guard(job_id)]),
    ]}


# ---------------------------------------------------------------------------
# Read-only-source guard (PreToolUse hook on Write/Edit)
# ---------------------------------------------------------------------------
# main's cwd is work_dir (<jobroot>/work/), and the orchestrator's auto-run
# collects the deliverable ONLY from there (with a job_dir-root fallback,
# commit 6299cdf). But main sometimes writes the solver with an ABSOLUTE path
# INTO the challenge source dir — which is declared read-only in the prompt
# yet is actually writable because it's passed via add_dirs. Job cb6e7896d1ec
# wrote /data/jobs/<id>/src/extracted/solver.py there; auto-run never saw it,
# the sandbox never ran, and the job ended no_flag despite a correct solver.
# The prompt already forbids this (CTF_PREAMBLE relative-path rule) and the
# agent ignored it — same failure class as the Bash kill-guard — so a HARD
# deny that redirects to cwd is the durable fix. Only ABSOLUTE paths are
# judged: a relative file_path resolves against main's cwd (= work_dir), which
# is exactly where deliverables belong, so those always pass. The job_dir ROOT
# is intentionally NOT guarded (it's not in add_dirs, and the 6299cdf fallback
# rescues a root write) — this hook owns only the source-dir escape.
_READONLY_WRITE_MSG = (
    "BLOCKED: {src} is the READ-ONLY challenge source directory. A solver/"
    "exploit written here is INVISIBLE to the orchestrator's auto-run — it "
    "collects your deliverable only from your CURRENT WORKING DIRECTORY "
    "({wd}), so the job would end no_flag even if your code is correct (job "
    "cb6e7896d1ec did exactly this). Write to cwd with a RELATIVE name "
    "instead:  Write(file_path=\"solver.py\", ...)  — never an absolute path "
    "into the source tree."
)


def readonly_write_reason(
    file_path: str, readonly_dirs, work_dir,
) -> str | None:
    """Deny reason if `file_path` is an ABSOLUTE write into one of the
    read-only reference dirs (and not under work_dir); else None. Pure /
    synchronously testable — the async hook is a thin wrapper."""
    if not file_path or not os.path.isabs(file_path):
        # Relative → resolves against main's cwd (work_dir); always allowed.
        return None
    target = os.path.realpath(file_path)
    wd = os.path.realpath(str(work_dir)) if work_dir else None
    # work_dir (incl. its absolute TMPDIR <work>/tmp) is always writable —
    # check FIRST so a cwd-absolute write passes even if a future add_dirs
    # entry were ever to overlap the work tree.
    if wd and (target == wd or target.startswith(wd + os.sep)):
        return None
    for d in (readonly_dirs or []):
        if not d:
            continue
        rd = os.path.realpath(d)
        if target == rd or target.startswith(rd + os.sep):
            return _READONLY_WRITE_MSG.format(src=rd, wd=wd or "<cwd>")
    return None


def _readonly_write_guard(readonly_dirs, work_dir):
    """Factory → PreToolUse hook denying Write/Edit into a read-only source
    dir. Bound to the session's add_dirs + work_dir at option-build time."""
    async def _guard(input_data, tool_use_id, context):
        try:
            if (input_data or {}).get("tool_name") not in ("Write", "Edit"):
                return {}
            ti = input_data.get("tool_input") or {}
            fp = ti.get("file_path") or ""
            reason = readonly_write_reason(fp, readonly_dirs, work_dir)
        except Exception:
            return {}
        if not reason:
            return {}
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
    return _guard


def main_session_hooks(add_dirs, work_dir, job_id: str | None = None):
    """PreToolUse hooks for a MAIN agent session: the Bash kill-guard PLUS a
    read-only-source guard that denies Write/Edit whose absolute path escapes
    into the challenge source dir (add_dirs). Subagents keep the bare
    kill_guard_hooks() — they only READ the source, never write deliverables.

    The web-research block (WebSearch/WebFetch deny) was REMOVED on 2026-07-22
    per operator decision — web research is now enabled."""
    from claude_agent_sdk import HookMatcher
    guard = _readonly_write_guard(add_dirs, work_dir)
    return {"PreToolUse": [
        # Bash only for the stale-target guard: the failure mode is CONNECTING
        # to a dead endpoint, and a report.md that narrates the old port is a
        # legitimate write we must not block.
        HookMatcher(matcher="Bash",
                    hooks=[_bash_kill_guard, _stale_target_guard(job_id)]),
        HookMatcher(matcher="Write", hooks=[guard]),
        HookMatcher(matcher="Edit", hooks=[guard]),
    ]}


# Operator-curated exploit library; mounted into worker via the
# existing ./data:/data bind-mount. Agents browse via plain Bash:
# `ls /data/exploits/`, `cat /data/exploits/<id>/report.md`.
EXPLOITS_DIR = DATA_DIR / "exploits"

# Account-global rate-limit status cache for the UI usage chip. The SDK emits
# a RateLimitEvent (claude_agent_sdk types) on EVERY run — status ∈
# allowed/allowed_warning/rejected, plus resets_at + (subscription) a
# `utilization` float that is frequently absent for OAuth accounts. Rate limit
# is per-ACCOUNT, not per-job, so we persist the latest event to ONE global
# file (last-write-wins across concurrent workers) and the api reads it for
# GET /api/usage. Best-effort observability — never blocks the run.
RATE_LIMIT_CACHE = DATA_DIR / "rate_limit.json"


def record_rate_limit_event(msg) -> None:
    """If `msg` is an SDK RateLimitEvent, persist its RateLimitInfo to the
    account-global RATE_LIMIT_CACHE. Duck-typed on class name so it needs no
    import and silently ignores every other message type. Never raises."""
    try:
        if type(msg).__name__ != "RateLimitEvent":
            return
        info = getattr(msg, "rate_limit_info", None)
        if info is None:
            return
        utilization = getattr(info, "utilization", None)
        try:
            used_pct = round(float(utilization) * 100.0, 1)
            remaining_pct = max(0.0, round(100.0 - used_pct, 1))
        except (TypeError, ValueError):
            used_pct = None
            remaining_pct = None
        payload = {
            "status": getattr(info, "status", None),
            "resets_at": getattr(info, "resets_at", None),
            "rate_limit_type": getattr(info, "rate_limit_type", None),
            "utilization": utilization,
            "used_pct": used_pct,
            "remaining_pct": remaining_pct,
            "overage_status": getattr(info, "overage_status", None),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "source": "sdk_rate_limit_event",
        }
        RATE_LIMIT_CACHE.parent.mkdir(parents=True, exist_ok=True)
        tmp = RATE_LIMIT_CACHE.with_name(
            f"{RATE_LIMIT_CACHE.name}.event.{os.getpid()}.tmp"
        )
        tmp.write_text(json.dumps(payload))
        tmp.replace(RATE_LIMIT_CACHE)  # atomic swap
    except Exception:
        pass


def read_rate_limit() -> dict | None:
    """Current Claude OAuth quota, falling back to the latest SDK event."""
    try:
        # Imported lazily to keep this very large shared module's import graph
        # unchanged for worker processes that never render the web UI.
        from modules.claude_rate_limit import read_claude_rate_limit

        return read_claude_rate_limit()
    except Exception:
        try:
            if RATE_LIMIT_CACHE.is_file():
                return json.loads(RATE_LIMIT_CACHE.read_text())
        except Exception:
            pass
    return None


# ---------------------------------------------------------------------------
# Grok (SuperGrok / OAuth) weekly usage chip
# ---------------------------------------------------------------------------
# Grok Build's `/usage` slash command hits cli-chat-proxy:
#   GET https://cli-chat-proxy.grok.com/v1/billing?format=credits
# with the OIDC access token from ~/.grok/auth.json. Response shape (2026):
#   config.creditUsagePercent  — % of the weekly pool USED (0–100+)
#   config.currentPeriod.end   — weekly reset timestamp
#   config.productUsage[]      — per-product breakdown (GrokBuild, …)
# Unlike Claude's RateLimitEvent (passive, last-seen), this is an active poll
# against the billing API. Cache for GROK_RATE_LIMIT_TTL_S so the 7s UI
# heartbeat does not hammer the proxy. Never raises — missing auth / network
# just means the chip stays hidden.
GROK_RATE_LIMIT_CACHE = DATA_DIR / "grok_rate_limit.json"
GROK_RATE_LIMIT_TTL_S = 60
_GROK_BILLING_URL = "https://cli-chat-proxy.grok.com/v1/billing?format=credits"
_GROK_TOKEN_URL = "https://auth.x.ai/oauth2/token"
_GROK_AUTH_REFRESH_LOCK = threading.Lock()


def _grok_auth_paths() -> list[Path]:
    return [
        Path("/root/.grok/auth.json"),
        Path.home() / ".grok" / "auth.json",
        Path(os.environ.get("GROK_HOME", "") or "/nonexistent") / "auth.json",
    ]


def _load_grok_auth_entry() -> tuple[Path | None, str | None, dict | None]:
    """Return (path, entry_key, entry_dict) for the first usable auth.json."""
    for p in _grok_auth_paths():
        try:
            if not p.is_file() or p.stat().st_size <= 0:
                continue
            data = json.loads(p.read_text())
            if not isinstance(data, dict) or not data:
                continue
            # Prefer an entry that has an access token ("key") and looks like OIDC.
            for ek, ev in data.items():
                if isinstance(ev, dict) and ev.get("key"):
                    return p, ek, ev
        except Exception:
            continue
    return None, None, None


def _grok_token_expired(entry: dict, skew_s: int = 120) -> bool:
    """True if the access token is missing an expiry or is within skew of it."""
    exp = entry.get("expires_at")
    if not exp:
        return False  # unknown — try the token as-is; 401 triggers refresh
    try:
        # "2026-07-31T15:07:04.382952296Z" — trim sub-micro if present
        s = str(exp).replace("Z", "+00:00")
        # fromisoformat chokes on >6 fractional digits; keep microseconds
        if "." in s:
            head, rest = s.split(".", 1)
            frac = ""
            tz = ""
            for i, ch in enumerate(rest):
                if ch.isdigit():
                    frac += ch
                else:
                    tz = rest[i:]
                    break
            s = f"{head}.{frac[:6]}{tz}"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (dt.timestamp() - skew_s) <= datetime.now(timezone.utc).timestamp()
    except Exception:
        return False


def _refresh_grok_token(auth_path: Path, entry_key: str, entry: dict) -> str | None:
    """OIDC refresh_token grant. Updates auth.json and preserves host ownership."""
    import urllib.parse
    import urllib.request

    failed_access = entry.get("key")
    with _GROK_AUTH_REFRESH_LOCK:
        # Another API request or the Grok CLI may have refreshed while this
        # caller was waiting.  Always reload before rotating a refresh token.
        try:
            raw = json.loads(auth_path.read_text())
        except Exception:
            raw = {}
        if not isinstance(raw, dict):
            raw = {}
        current = raw.get(entry_key)
        if isinstance(current, dict):
            current_access = current.get("key")
            if current_access and current_access != failed_access:
                return str(current_access)
            entry = dict(current)

        refresh = entry.get("refresh_token")
        client_id = entry.get("oidc_client_id")
        if not refresh or not client_id:
            return None
        body = urllib.parse.urlencode({
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": client_id,
        }).encode()
        req = urllib.request.Request(
            _GROK_TOKEN_URL,
            data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=12) as resp:
            payload = json.loads(resp.read())
        access = payload.get("access_token")
        if not access:
            return None
        entry["key"] = access
        if payload.get("refresh_token"):
            entry["refresh_token"] = payload["refresh_token"]
        expires_in = payload.get("expires_in")
        if isinstance(expires_in, (int, float)) and expires_in > 0:
            expires_at = datetime.now(timezone.utc).timestamp() + float(expires_in)
            entry["expires_at"] = datetime.fromtimestamp(
                expires_at, tz=timezone.utc
            ).isoformat().replace("+00:00", "Z")
        raw[entry_key] = entry
        try:
            _replace_auth_json(auth_path, raw)
        except Exception:
            pass  # token still usable even if disk write fails
        return str(access)


def _replace_auth_json(auth_path: Path, payload: dict) -> None:
    """Atomically replace auth JSON without turning a host bind file root-owned.

    The API runs as container root while ``~/.grok`` belongs to the host user.
    A plain ``tmp.replace(auth_path)`` therefore changed ``auth.json`` to an
    unmapped/nobody owner after the first token refresh.  Use the directory's
    owner (the account that owns the auth store) and retain the file mode.
    """
    original = auth_path.stat()
    directory = auth_path.parent.stat()
    tmp = auth_path.with_name(f"{auth_path.name}.hextech.{os.getpid()}.tmp")
    fd = -1
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.fchmod(fd, original.st_mode & 0o777)
        try:
            os.fchown(fd, directory.st_uid, directory.st_gid)
        except (AttributeError, PermissionError, OSError):
            pass
        with os.fdopen(fd, "w") as out:
            fd = -1
            json.dump(payload, out, indent=2)
        tmp.replace(auth_path)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def _fetch_grok_billing_credits(token: str) -> dict:
    """GET billing?format=credits; return parsed JSON. Raises on HTTP error."""
    import urllib.request

    req = urllib.request.Request(
        _GROK_BILLING_URL,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "x-grok-client-mode": "cli",
            "User-Agent": "HexTech_CTF_TOOL/grok-usage",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=12) as resp:
        return json.loads(resp.read())


def _normalize_grok_billing(raw: dict) -> dict:
    """Map cli-chat-proxy billing response → UI chip fields."""
    cfg = raw.get("config") if isinstance(raw, dict) else None
    if not isinstance(cfg, dict):
        cfg = raw if isinstance(raw, dict) else {}

    used_pct = cfg.get("creditUsagePercent")
    try:
        used_pct = float(used_pct) if used_pct is not None else None
    except (TypeError, ValueError):
        used_pct = None

    remaining_pct = None
    utilization = None
    if used_pct is not None:
        utilization = max(0.0, min(used_pct / 100.0, 9.99))
        remaining_pct = max(0.0, round(100.0 - used_pct, 1))

    # Weekly reset: prefer currentPeriod.end, fall back to billingPeriodEnd.
    period = cfg.get("currentPeriod") if isinstance(cfg.get("currentPeriod"), dict) else {}
    end_s = period.get("end") or cfg.get("billingPeriodEnd")
    resets_at = None
    if end_s:
        try:
            s = str(end_s).replace("Z", "+00:00")
            if "." in s:
                head, rest = s.split(".", 1)
                frac, tz = "", ""
                for i, ch in enumerate(rest):
                    if ch.isdigit():
                        frac += ch
                    else:
                        tz = rest[i:]
                        break
                s = f"{head}.{frac[:6]}{tz}"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            resets_at = int(dt.timestamp())
        except Exception:
            resets_at = None

    period_type = period.get("type") or ""
    rate_limit_type = "seven_day" if "WEEKLY" in str(period_type).upper() else (
        "weekly" if period_type else "subscription"
    )

    if used_pct is None:
        status = "unknown"
    elif used_pct >= 100:
        status = "rejected"
    elif used_pct >= 80:
        status = "allowed_warning"
    else:
        status = "allowed"

    product_usage = []
    for row in (cfg.get("productUsage") or []):
        if not isinstance(row, dict):
            continue
        try:
            product_usage.append({
                "product": row.get("product"),
                "usage_percent": float(row.get("usagePercent") or 0),
            })
        except (TypeError, ValueError):
            continue

    return {
        "status": status,
        "utilization": utilization,
        "used_pct": round(used_pct, 1) if used_pct is not None else None,
        "remaining_pct": remaining_pct,
        "resets_at": resets_at,
        "rate_limit_type": rate_limit_type,
        "product_usage": product_usage,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "source": "billing_credits",
    }


def _write_grok_rate_limit_cache(payload: dict) -> None:
    try:
        GROK_RATE_LIMIT_CACHE.parent.mkdir(parents=True, exist_ok=True)
        tmp = GROK_RATE_LIMIT_CACHE.with_name(GROK_RATE_LIMIT_CACHE.name + ".tmp")
        tmp.write_text(json.dumps(payload))
        tmp.replace(GROK_RATE_LIMIT_CACHE)
    except Exception:
        pass


def read_grok_rate_limit(force: bool = False) -> dict | None:
    """Latest Grok weekly usage for the UI chip (or None).

    Serves a short-TTL disk cache so the top-bar 7s poll stays free; refreshes
    from the billing API when the cache is stale / missing / forced. Never
    raises — any failure returns the last good cache (if any) or None.
    """
    # Serve cache when fresh.
    if not force:
        try:
            if GROK_RATE_LIMIT_CACHE.is_file():
                cached = json.loads(GROK_RATE_LIMIT_CACHE.read_text())
                if isinstance(cached, dict) and cached.get("status"):
                    ts = cached.get("updated_at")
                    age_ok = False
                    if ts:
                        try:
                            s = str(ts).replace("Z", "+00:00")
                            if "." in s:
                                head, rest = s.split(".", 1)
                                frac, tz = "", ""
                                for i, ch in enumerate(rest):
                                    if ch.isdigit():
                                        frac += ch
                                    else:
                                        tz = rest[i:]
                                        break
                                s = f"{head}.{frac[:6]}{tz}"
                            dt = datetime.fromisoformat(s)
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=timezone.utc)
                            age_ok = (
                                datetime.now(timezone.utc).timestamp() - dt.timestamp()
                            ) < GROK_RATE_LIMIT_TTL_S
                        except Exception:
                            age_ok = False
                    if age_ok:
                        return cached
        except Exception:
            pass

    # Live fetch.
    try:
        auth_path, entry_key, entry = _load_grok_auth_entry()
        if not entry or not entry.get("key"):
            # No OAuth — weekly SuperGrok pool is not visible via API key alone.
            return _read_stale_grok_cache()
        token = entry["key"]
        if _grok_token_expired(entry):
            try:
                new_tok = _refresh_grok_token(auth_path, entry_key, entry)
                if new_tok:
                    token = new_tok
            except Exception:
                pass  # try the existing token anyway
        try:
            raw = _fetch_grok_billing_credits(token)
        except Exception as e:
            # 401 → one refresh retry
            code = getattr(e, "code", None)
            if code == 401 and auth_path and entry_key:
                try:
                    new_tok = _refresh_grok_token(auth_path, entry_key, entry)
                    if new_tok:
                        raw = _fetch_grok_billing_credits(new_tok)
                    else:
                        return _read_stale_grok_cache()
                except Exception:
                    return _read_stale_grok_cache()
            else:
                return _read_stale_grok_cache()
        payload = _normalize_grok_billing(raw)
        _write_grok_rate_limit_cache(payload)
        return payload
    except Exception:
        return _read_stale_grok_cache()


def _read_stale_grok_cache() -> dict | None:
    try:
        if GROK_RATE_LIMIT_CACHE.is_file():
            cached = json.loads(GROK_RATE_LIMIT_CACHE.read_text())
            if isinstance(cached, dict) and cached.get("status"):
                cached["stale"] = True
                try:
                    cached["stale_age_seconds"] = max(
                        0,
                        int(
                            datetime.now(timezone.utc).timestamp()
                            - GROK_RATE_LIMIT_CACHE.stat().st_mtime
                        ),
                    )
                except OSError:
                    pass
                return cached
    except Exception:
        pass
    return None


# Single source of truth for the latest Claude model used by ad-hoc
# Claude calls (retry reviewer, exploit/solver judge). Bump here and
# every helper that imports it picks up the new model on the next
# run — no per-callsite edit needed.
LATEST_JUDGE_MODEL = "claude-opus-4-7"


def job_dir(job_id: str) -> Path:
    p = JOBS_DIR / job_id
    p.mkdir(parents=True, exist_ok=True)
    return p


# --- SSE live-stream publish helpers ---------------------------------
# Lazy-init a single redis client per worker process; publish is fire-
# and-forget. On any error we cache the failure so subsequent calls
# short-circuit (avoid hammering a dead redis on every log line).
# Channels: job:<id>:log (run-log lines), job:<id>:meta (token/heartbeat),
# job:<id>:sdk (raw SDK messages — Phase 4).
_REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
_redis_pub = None
_redis_pub_failed = False


def _get_redis_pub():
    """Return a process-local Redis client for publish. None on failure."""
    global _redis_pub, _redis_pub_failed
    if _redis_pub is not None:
        return _redis_pub
    if _redis_pub_failed:
        return None
    try:
        from redis import Redis
        _redis_pub = Redis.from_url(
            _REDIS_URL,
            socket_timeout=1,
            socket_connect_timeout=1,
        )
    except Exception:
        _redis_pub_failed = True
        return None
    return _redis_pub


def _publish(job_id: str, channel_suffix: str, payload: dict) -> None:
    """Fire-and-forget publish to job:<id>:<suffix>. Never raises."""
    r = _get_redis_pub()
    if r is None:
        return
    try:
        r.publish(f"job:{job_id}:{channel_suffix}", json.dumps(payload))
    except Exception:
        pass


def log_line(job_id: str, line: str) -> None:
    from modules.job_secrets import redact_job_value

    line = str(redact_job_value(job_id, str(line)))
    f = job_dir(job_id) / "run.log"
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    with f.open("a") as fp:
        fp.write(f"[{ts}] {line}\n")
    # The FILE keeps the whole line (that is what run.log is for now — grep /
    # filter). The live SSE frame does not: format_tool_result stopped
    # truncating (101beba) and joins newlines with " | ", so one subagent tool
    # result became a single un-splittable frame of up to the 200 KB valve —
    # while the SIBLING `sdk` publish in log_user_blocks has clamped itself to
    # 2000 chars all along. Same asymmetry, same browser (the live view runs a
    # regex colorizer over each frame), so apply the same clamp.
    sse_line = line
    if len(sse_line) > 2000:
        sse_line = sse_line[:2000] + " …(truncated in the live view; run.log has the full line)"
    _publish(job_id, "log", {"ts": ts, "line": sse_line})


def log_block(
    job_id: str,
    prefix: str,
    body: str,
    *,
    tag: str | None = None,
) -> None:
    """Multi-line log write where every output line carries the same
    timestamp + agent tag prefix. Used for full-fidelity main agent
    output (no truncation, real newlines preserved). The repeated
    prefix is mild visual noise but lets the existing run-log
    colorizer style every row consistently — without it, continuation
    lines would render as plain gray text and lose their agent color.

    Single-line bodies behave the same as log_line.
    """
    from modules.job_secrets import redact_job_value

    prefix = str(redact_job_value(job_id, str(prefix)))
    body = str(redact_job_value(job_id, str(body or "")))
    f = job_dir(job_id) / "run.log"
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    tag_part = f"[{tag}] " if tag else ""
    lines = body.splitlines() or [""]
    out = "".join(f"[{ts}] {tag_part}{prefix}: {line}\n" for line in lines)
    with f.open("a") as fp:
        fp.write(out)
    # Stream each rendered line individually so the SSE consumer can
    # show progress incrementally (matches file readers using tail).
    for line in lines:
        _publish(
            job_id,
            "log",
            {"ts": ts, "line": f"{tag_part}{prefix}: {line}"},
        )


# A run that produced flag candidates but could not promote one is not the
# same thing as a run that found nothing, and collapsing both into `no_flag`
# threw away the difference. Job f24519394073 is the case: the remote returned
# a real flag with exit 0, the reproduction run was blocked, the candidate was
# recorded — and the job read as a plain miss until a human went looking.
#
# `flag_ready` is terminal for the WORKER and non-terminal for the OPERATOR.
# The agent is done, the monitor stops, finished_at is stamped, usage counts —
# but a verdict is still owed, so bulk-delete's safe defaults leave it alone.
# Every terminal set below therefore includes it; `safe_default_statuses` in
# api/routes/jobs.py deliberately does not. `scripts/test_flag_ready.py` pins
# that split so the two halves cannot drift apart.
FLAG_READY = "flag_ready"

_TERMINAL_STATUSES = {"finished", "failed", "no_flag", "stopped", FLAG_READY}


def no_flag_status(job_id: str) -> str:
    """The terminal status for a run that promoted no flag.

    `flag_ready` when there is something for the operator to adjudicate,
    `no_flag` when there is not. Falls back to `no_flag` on any read failure:
    a job stuck awaiting a verdict it can never receive is worse than one
    filed as a miss, and the candidates are still on disk either way.
    """
    try:
        meta = read_meta(job_id) or {}
    except Exception:
        return "no_flag"
    candidates = meta.get("flag_candidates")
    if isinstance(candidates, list) and any(c for c in candidates if c):
        return FLAG_READY
    return "no_flag"


_SSE_META_KEYS = {
    "status", "flag", "summary", "error", "agent_error_kind",
    "started_at", "finished_at",
}


_JOB_LABEL = "hextech_ctf_tool_job_id"
_JOB_ROLE_LABEL = "hextech_ctf_tool_role"
# Jobs already reaped in THIS process. write_meta can be called again after a
# terminal status (a late cost-counter flush, a collector callback), and the
# disk-state gate below already handles that — this is the cheap second belt.
_REAPED_JOBS: set[str] = set()
# Hard bound on the whole sweep. A wedged docker call here would hang the RQ
# work horse AFTER the job is done, which blocks the slot from taking the next
# job — the same class of failure as the /retry copytree that froze uvicorn on
# a device node. Better to leak a container than to wedge a slot.
_REAP_TIMEOUT_S = 30.0


def reap_job_siblings(job_id: str) -> dict:
    """Remove containers and networks labelled for this job.

    A role=runner container is preserved until Docker positively reports it as
    exited/dead; an OOB callback can make the job terminal while that runner is
    still executing. All other labelled siblings remain immediately reapable.

    The label is set at creation: the orchestrator tags the sandbox containers
    it spawns, and worker/docker_memguard.sh tags whatever the AGENT starts
    from Bash. Before that shim there was no tag at all, which is why
    containers from June were still running in August.

    Networks are swept too, and they are not a nicety: docker's default
    address pool is finite, so an accumulation of `chal_<id>_net` bridges
    eventually fails new job setups outright with "could not find an
    available, non-overlapping IPv4 address pool".

    Never raises. A cleanup that breaks a finished job would be worse than the
    leak it fixes.
    """
    out = {"containers": [], "networks": [], "preserved": [], "errors": []}
    try:
        import docker

        client = docker.from_env()
        flt = {"label": f"{_JOB_LABEL}={job_id}"}
        for c in client.containers.list(all=True, filters=flt):
            name = getattr(c, "name", "?")
            labels = getattr(c, "labels", {}) or {}
            if labels.get(_JOB_ROLE_LABEL) == "runner":
                # A collector callback can make meta terminal while the sandbox
                # runner is still producing output.  The runner shares the job
                # label with ordinary siblings, so preserve it unless Docker has
                # positively reported a terminal container state.  Unknown is
                # deliberately fail-safe: a transient daemon hiccup may leak a
                # runner, but must never kill a live solver.
                status = str(getattr(c, "status", "") or "").strip().lower()
                if status not in {"exited", "dead"}:
                    out["preserved"].append(
                        f"{name} ({status or 'unknown status'})"
                    )
                    continue
            try:
                c.remove(force=True, v=True)
                out["containers"].append(name)
            except Exception as e:
                out["errors"].append(f"{name}: {type(e).__name__}")
        # Networks AFTER containers — a network with an attached container
        # cannot be removed, so ordering is what makes this work at all.
        #
        # Ordering alone is NOT enough, though, and the first live run proved
        # it: job 7955d4ad066a reaped protoss-app and protoss-db cleanly and
        # then failed on the network with "protossnet: APIError". The agent had
        # run `docker network connect protossnet <worker>` so the challenge
        # stack was reachable from its own container — and the WORKER is not
        # ours to remove, so that endpoint outlives every container we delete
        # and blocks the network forever. Left alone this leaks one dead
        # network per docker-challenge job, and docker's default address pool
        # is finite: enough of them and new job setups fail outright with "could
        # not find an available, non-overlapping IPv4 address pool" — the exact
        # failure this sweep exists to prevent.
        #
        # So: on failure, force-disconnect whatever is still attached and try
        # once more. Safe because the network carries THIS job's label — it was
        # created for this job, and anything still on it is either a container
        # we could not remove or an outsider the agent attached. Disconnecting
        # a live worker from a dead challenge network costs nothing.
        for n in client.networks.list(filters=flt):
            name = getattr(n, "name", "?")
            try:
                n.remove()
                out["networks"].append(name)
                continue
            except Exception as e:
                first = type(e).__name__
            try:
                n.reload()
                for cid in list((n.attrs.get("Containers") or {}).keys()):
                    try:
                        n.disconnect(cid, force=True)
                    except Exception:
                        pass
                n.remove()
                out["networks"].append(name)
            except Exception as e:
                out["errors"].append(
                    f"{name}: {first}, then after disconnect {type(e).__name__}")
    except Exception as e:
        out["errors"].append(f"docker unreachable: {type(e).__name__}")
    return out


def _reap_after_terminal(job_id: str) -> None:
    """Fire-and-log the sweep when a job reaches a terminal status.

    Runs AFTER meta.json is written, so a slow or wedged docker daemon can
    never delay or lose the final status the UI is waiting on.
    """
    if job_id in _REAPED_JOBS:
        return
    _REAPED_JOBS.add(job_id)
    try:
        if not _coerce_bool(get_setting("reap_job_containers"), True):
            return
    except Exception:
        pass
    try:
        import concurrent.futures as _cf

        with _cf.ThreadPoolExecutor(max_workers=1) as ex:
            res = ex.submit(reap_job_siblings, job_id).result(
                timeout=_REAP_TIMEOUT_S)
    except Exception as e:
        log_line(job_id, f"[reap] sweep did not finish ({type(e).__name__}) — "
                         f"leaving containers in place; the Containers tab can "
                         f"clear them")
        return
    if res["containers"] or res["networks"]:
        parts = []
        if res["containers"]:
            parts.append(f"{len(res['containers'])} container(s): "
                         + ", ".join(res["containers"]))
        if res["networks"]:
            parts.append(f"{len(res['networks'])} network(s): "
                         + ", ".join(res["networks"]))
        log_line(job_id, "[reap] removed " + "; ".join(parts))
    if res["preserved"]:
        log_line(job_id, "[reap] preserved active runner(s): "
                 + ", ".join(res["preserved"]))
    if res["errors"]:
        log_line(job_id, "[reap] could not remove: " + "; ".join(res["errors"]))


def _coerce_bool(v: Any, default: bool) -> bool:
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() not in ("0", "false", "no", "off")


def write_meta(job_id: str, **updates: Any) -> None:
    f = job_dir(job_id) / "meta.json"
    meta = {}
    if f.exists():
        meta = json.loads(f.read_text())
    now_iso = datetime.now(timezone.utc).isoformat()

    # Auto-stamp lifecycle timestamps so the UI can show elapsed /
    # duration without each module having to remember to set them.
    new_status = updates.get("status")
    if new_status == "running" and not meta.get("started_at"):
        updates.setdefault("started_at", now_iso)
    if new_status in _TERMINAL_STATUSES and not meta.get("finished_at"):
        updates.setdefault("finished_at", now_iso)
    # Computed against the PREVIOUS on-disk status, so it is true exactly once
    # per job — a later write while already terminal (a cost-counter flush, a
    # collector callback) does not re-fire it.
    _became_terminal = (new_status in _TERMINAL_STATUSES
                        and meta.get("status") not in _TERMINAL_STATUSES)

    # Which worker SLOT container is serving this job. Stamped from the
    # environment because the process doing this write IS the work horse on
    # that slot — the api container has no WORKER_SLOT and so never stamps.
    #
    # deploy.sh needs this to restart only the idle slots. It cannot use
    # `rq_worker_name`: that field is computed live by GET /api/jobs from RQ
    # and never persisted, so every meta.json on disk lacks it and a
    # disk-based scan would see EVERY running job as unplaced and defer all
    # slots — the deploy win, silently gone. Verified against live job
    # 72f960d9628c, whose meta.json had no worker/rq key at all.
    # Guard on the VALUE, not just key presence. /continue clears the field by
    # re-queueing with an explicit `worker_slot: None`, but that None lands in
    # `meta`, not in `updates`, so `updates.setdefault(...)` would in fact
    # still stamp correctly today — this is defence against a future caller
    # that passes worker_slot=None through write_meta itself, where setdefault
    # would see the key present and leave the job with no slot recorded for
    # its whole life (deploy.sh would then defer every slot until it ended).
    _slot = (os.environ.get("WORKER_SLOT") or "").strip()
    if _slot and not updates.get("worker_slot"):
        updates["worker_slot"] = _slot

    meta.update(updates)
    meta["updated_at"] = now_iso
    from modules.job_secrets import redact_job_value

    meta = redact_job_value(job_id, meta)
    updates = redact_job_value(job_id, updates)
    f.write_text(json.dumps(meta, indent=2))

    # SSE: publish only the "lifecycle" subset to avoid spamming the
    # channel with every token-counter throttle write (agent_heartbeat
    # already emits its own meta events).
    sse_payload = {k: updates[k] for k in _SSE_META_KEYS if k in updates}
    if sse_payload:
        _publish(job_id, "meta", {"status_update": sse_payload})

    # The job is over: take back the containers and networks it created.
    # LAST, deliberately — meta.json and the SSE event are already out, so a
    # slow docker daemon cannot delay the status the UI is waiting on, and a
    # failure here cannot lose it.
    if _became_terminal:
        _reap_after_terminal(job_id)


def read_meta(job_id: str) -> dict[str, Any]:
    """Best-effort read of the job's meta.json. Returns {} if absent."""
    f = job_dir(job_id) / "meta.json"
    if not f.exists():
        return {}
    try:
        data = json.loads(f.read_text())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


# Subdirectory names that `collect_outputs(..., deep_search=True)` will
# NOT descend into during its recovery scan. These are autoboot- or
# chal-author-owned trees; finding `report.md` inside them is almost
# always the chal's own README, not the main agent's analysis. Keep this
# narrow on purpose — over-skipping makes the recovery scan useless.
_COLLECT_DEEP_SEARCH_SKIP = frozenset({
    "chal", "bin", "tmp", ".chal-libs", ".scratch", ".claude",
    "__pycache__", "decomp", "src",
})


def collect_outputs(
    work_dir: Path,
    names: list[str],
    *,
    fallback_dirs: list[Path] | None = None,
    deep_search: bool = True,
    log_fn=None,
) -> dict[str, Path]:
    """Find each requested filename. Looks in work_dir first, then falls
    back to /root/ (the agent's HOME — sometimes the agent ignores cwd
    and uses an absolute path under home), and finally any caller-supplied
    `fallback_dirs`.

    On a retry/resume the forked SDK session occasionally re-uses the
    PRIOR job's absolute paths (`/data/jobs/<prev_id>/work/...`) from
    its tool history, so the new agent's edits land in the OLD job
    dir while the new work_dir keeps the untouched carry-copy. To
    recover from that, callers can pass the prior work dir(s) here:
    when the same name appears in multiple candidates, the one with
    the most-recent mtime wins (carry-copy preserves the original
    mtime via copy2/copytree, so any post-carry rewrite in the prior
    dir naturally registers as newer).

    `deep_search=True` (default) adds a final recovery scan across
    `work_dir`'s subtree for any name that the direct + fallback
    lookup couldn't find. The scan skips autoboot-owned dirs (see
    `_COLLECT_DEEP_SEARCH_SKIP`) so we don't pick up the chal
    author's own README.md as the agent's analysis. Concrete
    incident 2026-05-25 (job bfce7f3e0c11): `report.md` +
    `chain.json` were written but landed somewhere other than
    work_dir root (cwd-confusion via a `cd ./chal/deploy/app && cat
    > ./report.md` heredoc); orchestrator collected only
    exploit.py, ship phase had nothing to summarize from.

    Returns a dict {name: actual_path} for files that were located.
    """
    fallback_dirs = list(fallback_dirs or [])
    candidates_dirs = [work_dir, Path("/root"), *fallback_dirs]
    found: dict[str, Path] = {}
    for name in names:
        best: Path | None = None
        best_mtime: float = -1.0
        for d in candidates_dirs:
            p = d / name
            try:
                if not p.is_file():
                    continue
                mt = p.stat().st_mtime
            except OSError:
                continue
            if mt > best_mtime:
                best = p
                best_mtime = mt
        if best is not None:
            found[name] = best

    if deep_search:
        missing = [n for n in names if n not in found]
        if missing and work_dir.is_dir():
            for name in missing:
                hit = _deep_search_for(work_dir, name)
                if hit is not None:
                    found[name] = hit
                    if log_fn is not None:
                        try:
                            log_fn(
                                f"[collect] recovered {name!r} from "
                                f"unexpected path "
                                f"{hit.relative_to(work_dir)} — main "
                                f"wrote to a cwd-shifted subdir; "
                                f"orchestrator using this copy"
                            )
                        except Exception:
                            pass
    return found


def _deep_search_for(work_dir: Path, name: str) -> Path | None:
    """Return the newest `name` under `work_dir`'s subtree, skipping
    `_COLLECT_DEEP_SEARCH_SKIP` directories. Returns None when none
    exist.
    """
    best: Path | None = None
    best_mtime: float = -1.0
    try:
        for entry in work_dir.iterdir():
            if not entry.is_dir():
                continue
            if entry.name in _COLLECT_DEEP_SEARCH_SKIP:
                continue
            try:
                matches = list(entry.rglob(name))
            except OSError:
                continue
            for m in matches:
                # Re-filter rglob results — they descend past our
                # top-level skip set (a `chal/inner/decomp/report.md`
                # is still excluded because `chal` is the entry, but
                # if the agent created `weird_dir/chal/report.md`
                # we'd hit it. Filter by checking ancestors.)
                rel_parts = m.relative_to(work_dir).parts
                if any(p in _COLLECT_DEEP_SEARCH_SKIP for p in rel_parts[:-1]):
                    continue
                try:
                    mt = m.stat().st_mtime
                except OSError:
                    continue
                if mt > best_mtime:
                    best = m
                    best_mtime = mt
    except OSError:
        return None

    # Targeted rescue inside the SDK CLI's own working subdir(s)
    # `tmp/claude-*/`. TMPDIR is set to `<work>/tmp` for the agent, and
    # the bundled `claude` CLI uses a `claude-<N>` subdir under it as its
    # process cwd. When the agent's Bash cwd drifts there (or it never
    # left it) and it Writes a RELATIVE path, exploit.py / report.md land
    # in `tmp/claude-N/` — which the generic `tmp` skip above excludes,
    # so a real, flag-producing exploit silently vanishes when the tmp
    # tree is later cleaned (concrete incident 2026-06-14 job
    # d4c452f2f6d4: live RCE flag captured, both artifacts lost this way).
    # We can't un-skip `tmp` wholesale (it holds genuine scratch debris),
    # so we glob ONLY the SDK working subdir for the EXACT artifact name —
    # those names are never scratch, so this can't scoop noise.
    if best is None:
        try:
            for m in work_dir.glob(f"tmp/claude-*/{name}"):
                if not m.is_file():
                    continue
                try:
                    mt = m.stat().st_mtime
                except OSError:
                    continue
                if mt > best_mtime:
                    best = m
                    best_mtime = mt
        except OSError:
            pass

    # Last resort: the agent `cd`-d INTO a SKIPPED dir (most often `bin/`,
    # where the local challenge binary lives, to run it) and then Wrote a
    # RELATIVE artifact there — a Bash `cd` shifts the process cwd that the
    # Write/Read tools resolve against, despite the prompt claiming otherwise
    # (job 4100442bcf71: report.md landed in work/bin/report.md after a
    # `cd ./bin && ./similar`, and the `bin` skip above hid it → no report.md
    # / findings.json). We DO want the agent's artifact out of a skipped dir,
    # but must NOT scoop a challenge-author file of the same name. Gate on the
    # job-start marker: AUTOBOOT.md is written fresh at run start, while staged
    # chal files keep their (earlier) upload/extract mtime via copytree's
    # copy2 — so an artifact NEWER than AUTOBOOT.md was written by the agent
    # this run, not shipped with the challenge. Search even skipped dirs under
    # that gate; newest wins.
    if best is None:
        try:
            ab = work_dir / "AUTOBOOT.md"
            gate = ab.stat().st_mtime if ab.is_file() else work_dir.stat().st_mtime
        except OSError:
            gate = 0.0
        try:
            for m in work_dir.rglob(name):
                if not m.is_file():
                    continue
                try:
                    mt = m.stat().st_mtime
                except OSError:
                    continue
                # Only agent-written files (post job-start); rejects
                # challenge-shipped same-name files (pre-start mtime).
                if mt >= gate and mt > best_mtime:
                    best = m
                    best_mtime = mt
        except OSError:
            pass
    return best


def extract_flags_from_text(text: str, liberal: bool = False) -> list[str]:
    """Return unique CTF-style flags found in `text` (placeholders filtered)."""
    if not text:
        return []
    found = set(FLAG_RE.findall(text))
    if liberal:
        found |= set(LIBERAL_FLAG_RE.findall(text)) - found
    return sorted(f for f in found if not _is_placeholder_flag(f))


# Files produced by the actual sandbox runner / OOB collector — these
# prove the exploit/solver REALLY captured a flag from the target.
_TRUSTED_FLAG_SOURCES = (
    "exploit.py.stdout",
    "exploit.py.stderr",
    "solver.py.stdout",
    "solver.py.stderr",
    "callbacks.jsonl",
    "summary.json",          # forensic — no exploit.py; flag comes from artifact analysis
)

# Narrative artifacts the agent itself authored or that derive from
# its prose. These regularly contain chal-author placeholders quoted
# from `chal/run.sh` (e.g. `DH{this_is_a_flag}`) — only consult them
# as a LAST RESORT when no trusted source produced anything.
_NARRATIVE_FLAG_SOURCES = (
    "report.md",
    # run.log REMOVED 2026-07-23: it is the raw interleaved firehose of every
    # tool result (Bash output, WebSearch results, recon/subagent summaries,
    # chal-source quotes). With web research re-enabled (0cd2c7d) a PUBLISHED
    # WRITEUP's flag now lands here verbatim — job dc981a8c4741 false-finished
    # on `DH{0DB34...}` scraped from a recon WebSearch summary that existed
    # ONLY in run.log (report.md was placeholder-clean). A REAL capture never
    # depends on run.log: it rides the TRUSTED tier (exploit stdout /
    # callbacks.jsonl) or the FLAG_CANDIDATE marker — both untouched here. This
    # also closes the recurring narrative-from-run.log false-positive class
    # (44dd25365173 sha256 echoes; the stale-log false-success gate).
    "findings.json",         # auto-generated from report.md by REPORT phase
    "log_findings.json",
)


def flag_format_prefix(raw: str | None) -> str | None:
    """Normalize an operator-supplied flag format into a bare prefix.

    Accepts a prefix (`DH`), a sample (`DH{...}`), or a template
    (`DH{}`); returns the token before the first `{`, stripped. Returns
    None when empty/unusable so callers fall back to the generic
    FLAG_RE. Prefix is validated to a sane charset to avoid building a
    junk/over-broad regex.
    """
    if not raw:
        return None
    s = str(raw).strip()
    if "{" in s:
        s = s.split("{", 1)[0]
    s = s.strip()
    # A real flag prefix is a short token (letters/digits/_- ., e.g. DH,
    # flag, CTF, picoCTF). Reject anything else so we never compile an
    # operator typo into an over-matching pattern.
    if not s or len(s) > 32 or not re.fullmatch(r"[A-Za-z0-9_.\-]+", s):
        return None
    return s


def job_flag_format_re(job_id: str) -> "re.Pattern | None":
    """Per-job authoritative flag matcher from `meta.flag_format`.

    When the operator declares the real flag's format (e.g. `DH{...}`),
    only flags of that exact prefix shape count — so local-test flags in
    a DIFFERENT format (e.g. `LOCAL{...}`) are auto-excluded, and a real
    `DH{<64 hex>}` is kept (the declared format IS the validation).
    Returns None when unset/invalid (callers fall back to FLAG_RE).
    """
    try:
        prefix = flag_format_prefix((read_meta(job_id) or {}).get("flag_format"))
    except Exception:
        return None
    if not prefix:
        return None
    try:
        # `[^\s}]`, NOT `[^}\r\n]` — parity with FLAG_RE (:38), which has
        # always excluded whitespace. The looser class made this feature, which
        # the docstring above advertises as NARROWING the match, strictly
        # WIDER on the whitespace axis: it admits spaces, brackets and plus
        # signs, so an English sentence between the braces matched.
        #
        # Job 0c04e636633c is what that costs. Its solver printed the
        # diagnostic banner
        #     print("target: DH{ + 36 chars of [a-z0-9_] + }")
        # as line 1 of its stdout; line 25 of the same file read "no flag
        # found; tried 3383296 candidates in 1500s", report.md said "The flag
        # itself was not captured", findings.json said exploit_status
        # "tested-failed", and the solver emitted ZERO FLAG_CANDIDATE markers.
        # The banner still matched, landed in meta.flags at the TRUSTED tier,
        # and the job reported status=finished. Generic FLAG_RE rejects that
        # string; only the operator's own safety feature accepted it — turning
        # the guard on is what manufactured the false success.
        return re.compile(re.escape(prefix) + r"\{[^\s}]{1,256}\}")
    except re.error:
        return None


def _recorded_artifact_names(job_id: str) -> list[str]:
    """Runner-written artifact filenames for this job, from `meta.artifacts`.

    Empty for jobs that predate the recording, and for any job whose meta is
    unreadable — callers union this with the legacy name tuple so neither case
    loses coverage. Only basenames are returned: the trusted tier joins them
    onto the job directory itself, and a recorded value containing a path
    would otherwise reach outside it.
    """
    try:
        arts = (read_meta(job_id) or {}).get("artifacts") or {}
    except Exception:
        return []
    out = []
    for key in ("stdout", "stderr"):
        name = arts.get(key)
        if isinstance(name, str) and name:
            base = Path(name).name
            if base and base not in out:
                out.append(base)
    return out


def _recorded_artifact_names_in_retry_chain(job_id: str) -> list[str]:
    """Runner-written output names recorded by this job and its retry parents.

    A retry may carry an earlier attempt's work tree into a fresh job.  The new
    job's metadata deliberately starts fresh, so the provenance needed to
    identify a copied runner output can live on ``retry_of`` instead.  Follow a
    bounded, cycle-safe chain and return basenames only; unreadable or malformed
    metadata simply ends the best-effort lookup.
    """
    out: list[str] = []
    current: object = job_id
    seen: set[str] = set()
    for _ in range(64):
        if not isinstance(current, str) or not current or current in seen:
            break
        # retry_of is an internal job id, never a path.  Refuse a malformed
        # value before read_meta could resolve it outside JOBS_DIR.
        if Path(current).name != current:
            break
        seen.add(current)
        for name in _recorded_artifact_names(current):
            if name not in out:
                out.append(name)
        try:
            meta = read_meta(current) or {}
        except Exception:
            break
        current = meta.get("retry_of") if isinstance(meta, dict) else None
    return out


def scan_job_for_flags(
    job_id: str,
    extra_files: list[str] | None = None,
    *,
    sandbox_result: dict | None = None,
    sandbox_started: bool | None = None,
    agent_error: bool = False,
    trusted_only: bool = False,
    provenance_out: dict | None = None,
) -> list[str]:
    """Return real captured flags for a job.

    `provenance_out`, when given, receives `{"tier": <name>}` naming WHICH
    tier produced the return value:

        "marker"       the solver printed `FLAG_CANDIDATE: <flag>` — it is
                       declaring this exact string as its capture
        "runner_regex" a flag-SHAPED string merely appeared somewhere in the
                       runner's output; nobody declared anything
        "narrative"    only the agent's own prose (report.md / findings.json)
                       carries it
        ""             no flags

    The first two were indistinguishable before: both were recorded as
    `flag_trusted_tier=True`, so no caller could tell "the solver said it
    captured this" from "a flag-shaped string appeared in its output". Job
    0c04e636633c fell through exactly that gap. Out-param rather than a changed
    return type so the ~20 existing call sites are untouched.

    `trusted_only=True` skips the NARRATIVE tier entirely (run.log /
    report.md / findings.json) — the caller is asserting that the only
    valid evidence is a genuine runner/collector artifact. The OOB
    collector uses this: a beacon proves a capture ONLY via its own
    logged content (callbacks.jsonl, a trusted source); the agent's
    run.log prose (recon's flag-FORMAT description, chal-source seeds
    like `DH{**fake_flag**}`) must never trigger a finish. Without it,
    ANY beacon — including the agent's own selftest of the collector /
    `/_hits` API mid-analyze — re-scanned run.log and false-finished the
    job on scraped placeholders (job da10075b585e: marked finished at
    turn 9 mid-analyze, before exploit.py existed or the judge gate
    ran).

    Two-tier scan to keep test/placeholder flags out of `meta.flags`:

      1. TRUSTED tier — files produced by the actual runner / OOB
         collector (exploit/solver stdout/stderr, callbacks.jsonl,
         summary.json). If ANY non-placeholder flag
         appears here, return ONLY those — they prove the exploit
         really retrieved the flag from the target.
      2. NARRATIVE tier — report.md, run.log, findings.json. Consulted
         only when the trusted tier is empty. These regularly contain
         chal-author placeholders quoted from `chal/run.sh` (e.g. the
         job 9a240a221f1b incident: `DH{this_is_a_flag}` got pulled
         into FLAGS FOUND alongside the real flag).

    `extra_files` are treated as TRUSTED — callers who add them are
    asserting the file is runner output.

    `sandbox_result`, when provided, gates the NARRATIVE fallback.
    If the sandbox was NEVER spawned (prejudge ship-block / agent
    aborted before runner), no flag can be REAL — every match must
    come from prose the agent wrote, which is exactly the case the
    NARRATIVE tier is meant to be a last-resort fallback for. Job
    44dd25365173 (2026-05-23) shipped 4 fake `DH{<sha256>}` /
    `DH{3cbdaf...}` entries to meta.flags because prejudge blocked
    ship (no sandbox stdout existed) yet narrative scan still
    surfaced agent-authored hashes from report.md + run.log. With
    sandbox_result['judge_aborted']=True or
    sandbox_result['error']='prejudge_blocked', the narrative tier
    is skipped entirely.

    `sandbox_started` is separate from `sandbox_result`: a runner attempt may
    legitimately return ``None``.  When the orchestrator explicitly records
    ``sandbox_started=False`` *and* the agent errored, runner-owned outputs
    recorded in ``meta.artifacts`` (including retry ancestors) and narrative
    prose cannot promote the crashed job to a terminal success.  OOB sources
    such as ``callbacks.jsonl`` remain eligible because they are not runner
    outputs.  ``None`` remains unknown for older and non-orchestrator callers
    rather than being treated as no-run.

    ``result.json`` is deliberately not a scan input.  Analyzers write it after
    their final scan and include the selected flags, so trusting it on a later
    rescan upgrades the analyzer's own narrative decision to runner evidence.
    """
    jd = job_dir(job_id)

    def _prov(tier: str) -> None:
        if provenance_out is not None:
            provenance_out["tier"] = tier

    def _prov_suppressed(denial: str) -> None:
        """Record that the runner's output DID carry a flag-shaped string which
        the denial rule then dropped.

        Separate from `tier` because they are separate facts and the tier alone
        gets the story backwards. When the sweep is suppressed and the NARRATIVE
        tier then finds the same string in report.md, `tier` is honestly
        "narrative" — but reporting only that tells the operator "the runner's
        own output does not contain it", which is the opposite of what happened.
        """
        if provenance_out is not None:
            provenance_out["suppressed"] = denial

    _prov("")

    # Operator-declared flag format (per-job, optional). When set it
    # REPLACES the generic FLAG_RE for the scan tiers below: only flags
    # of the declared prefix shape (e.g. DH{...}) match, so local-test
    # flags in another format (LOCAL{...}) never surface and a real
    # DH{<64 hex>} is kept. The FLAG_CANDIDATE marker tier stays
    # format-agnostic (the exploit explicitly declares its capture).
    fmt_re = job_flag_format_re(job_id)
    scan_re = fmt_re or FLAG_RE

    def _is_regex_source_match(text: str, match) -> bool:
        return bool(_REGEX_SOURCE_TAIL_RE.match(text, match.end()))

    def _scan(names) -> set[str]:
        out: set[str] = set()
        for name in names:
            p = jd / name
            if not p.is_file():
                continue
            try:
                text = p.read_text(errors="replace")
            except Exception:
                continue
            for match in scan_re.finditer(text):
                if _is_regex_source_match(text, match):
                    continue
                out.add(match.group(0))
        return out

    def _scan_markers(names) -> set[str]:
        out: set[str] = set()
        for name in names:
            p = jd / name
            if not p.is_file():
                continue
            try:
                text = p.read_text(errors="replace")
            except Exception:
                continue
            for raw in _FLAG_MARKER_RE.findall(text):
                cand = _MARKER_ESCAPE_RE.split(raw.strip(), 1)[0]
                cand = cand.strip().strip("\"'`").strip()
                # A FLAG_CANDIDATE marker quoted INSIDE prose (e.g.
                # result.json's judge stop_reason: "Flag captured cleanly:
                # FLAG_CANDIDATE: DH{x} on stdout, exit 0, no errors.")
                # otherwise captures the whole trailing sentence as the flag
                # (job bcd883b0e70f surfaced 3 entries: the flag + two prose
                # tails once the <<_>> flag stopped being filtered). If the
                # value carries a PREFIX{...} brace-flag, reduce to it;
                # brace-less declared flags (raw hex / prefix-less) have no
                # `{...}` and are kept verbatim.
                # Same whitespace parity as job_flag_format_re — a candidate
                # whose braces contain prose is a description, not a capture.
                _bf = re.search(r"\w{1,15}\{[^\s}]{1,256}\}", cand)
                if _bf:
                    cand = _bf.group(0)
                elif re.search(r"\s", cand):
                    # No PREFIX{...} brace-flag AND the value carries internal
                    # whitespace → this is PROSE that merely quotes the
                    # `FLAG_CANDIDATE:` convention, not a declared capture. A
                    # genuine brace-less flag (raw hex / prefix-less token) is a
                    # single whitespace-free token. result.json is a TRUSTED
                    # source but embeds the judge's prejudge/postjudge prose
                    # (e.g. "...uses a `FLAG_CANDIDATE:` prefix the harvester
                    # must strip."), which the marker regex over-captured as the
                    # flag `prefix the harvester must strip.`. This surfaces only
                    # on a RE-SCAN (result.json exists after finish; a live job's
                    # finish-time harvest predates it), e.g. the 187a2d3ee182
                    # backfill. Skip it.
                    continue
                if cand:
                    out.add(cand)
        return out

    crashed_before_sandbox = sandbox_started is False and bool(agent_error)
    recorded_artifacts = _recorded_artifact_names(job_id)
    trusted_set = list(_TRUSTED_FLAG_SOURCES)
    # The runner records the artifact names it ACTUALLY wrote (meta.artifacts),
    # because they derive from the script it ran and no fixed list can enumerate
    # them: a crypto Sage job writes `solver.sage.stdout`, which the tuple above
    # does not contain. Job 606175dde9d6 (2026-08-11) printed
    # `FLAG_CANDIDATE: DH{Not_bad!_10.8+_is_ezpz}`, the file sat on disk, and the
    # job still finished `no_flag` for exactly that reason.
    #
    # UNION, not replacement. Jobs that ran before this was recorded have no
    # `meta.artifacts`, and re-scanning them must keep working — the tuple is
    # the fallback, not the truth.
    trusted_set.extend(recorded_artifacts)
    if extra_files:
        trusted_set.extend(extra_files)
    if crashed_before_sandbox:
        # The runner provably did not execute in this attempt.  Files it owns
        # are therefore stale even when they contain an explicit marker.  Use
        # metadata provenance rather than suffix/name guesses so a recorded
        # `solver.sage.stdout` is handled like every other runner spelling,
        # while collector/OOB sources remain available.  Retry-parent records
        # cover a carried output whose provenance is absent from the fresh
        # child's meta; the current record covers multiple attempts in one job.
        runner_owned = set(_recorded_artifact_names_in_retry_chain(job_id))
        trusted_set = [name for name in trusted_set if name not in runner_owned]

    # AUTHORITATIVE tier — an explicit `FLAG_CANDIDATE: <flag>` marker the
    # exploit/solver printed on a genuine run (CTF_PREAMBLE instructs it).
    # The agent is declaring "this exact string is the flag I captured", so
    # we honor it verbatim regardless of flag format — no FLAG_RE prefix and
    # no hash-width heuristic. Only the minimal placeholder guard applies
    # (trusted=True): it drops `<...>` template echoes / your_flag_here while
    # keeping real DH{<64 hex>} and bare prefix-less flags. Markers are read
    # ONLY from the TRUSTED tier (actual run stdout/stderr), never narrative
    # prose, so an agent quoting the marker convention in report.md can't
    # forge a capture.
    marker = {
        c for c in _scan_markers(trusted_set)
        if not _is_placeholder_flag(c, trusted=True)
    }
    if marker:
        _prov("marker")
        return sorted(marker)

    # Below this line is a bare REGEX SWEEP of the same files, not an explicit
    # declaration. Both outcomes are recorded as flag_trusted_tier=True, so
    # nothing downstream can tell "the solver said it captured this" apart from
    # "a flag-shaped string appeared in its output".
    #
    # Job 0c04e636633c fell exactly through this gap: the marker tier correctly
    # returned EMPTY (the solver emits FLAG_CANDIDATE only inside verify()-gated
    # branches, and it never verified anything), and the sweep then scraped the
    # solver's own diagnostic banner. Two machine-readable negatives sat unread
    # in the very stream being scanned — zero markers, and a final line reading
    # "no flag found; tried 3383296 candidates in 1500s".
    #
    # A run that printed NO marker and then said it found nothing is not a
    # capture. Treat the sweep as the weaker evidence it is: when the run's own
    # output declares failure, do not promote a regex hit from that same output.
    def _declares_failure(names) -> str:
        """The run's own words for 'I did not find it', or "".

        Read from the SAME files the sweep scans, so this can never disagree
        with what was scraped. Deliberately narrow — these are phrases a solver
        prints about ITSELF, not prose an agent might quote about the chal.

        POSITION MATTERS. Only the tail of each file AFTER its last flag-shaped
        hit is consulted. A denial is evidence about how the run ENDED; one
        printed BEFORE a flag describes an earlier attempt, not the capture that
        followed it. Reading the whole file would silently lose the flag of any
        solver that reports per-attempt — `no flag found for k=1` … then the
        real flag on attempt 2 — which is the exact shape of a brute-force loop,
        and losing a genuine flag is the failure mode that cost job a3d4d448
        (memory real_flag_dropped_as_placeholder). Job 0c04e636633c is still
        suppressed: its banner is line 1 of 25 and its denial is line 25.
        """
        for name in names:
            p = jd / name
            if not p.is_file():
                continue
            try:
                text = p.read_text(errors="replace")
            except Exception:
                continue
            _tail_from = 0
            for _m in scan_re.finditer(text):
                if _is_regex_source_match(text, _m):
                    continue
                _tail_from = _m.end()
            for line in text[_tail_from:].splitlines():
                low = line.strip().lower()
                if not low:
                    continue
                for needle in ("no flag found", "flag not found",
                               "no flag recovered", "failed to recover the flag",
                               "could not recover the flag", "exhausted without"):
                    if needle in low:
                        return line.strip()[:200]
        return ""

    trusted = {
        f for f in _scan(trusted_set)
        if not _is_placeholder_flag(f, trusted=True)
    }
    if trusted:
        _denial = _declares_failure(trusted_set)
        if _denial:
            # The sweep found a flag-shaped string in output that says it found
            # nothing. Believe the sentence, not the shape.
            #
            # NEVER silently: dropping a possible real capture without saying so
            # is how job a3d4d448 lost a genuine DH{<64 hex>} to an over-eager
            # width rule. The operator gets the candidate, the sentence that
            # overrode it, and enough to disagree.
            #
            # The MARKER tier above is deliberately unaffected — a solver that
            # explicitly declares FLAG_CANDIDATE on a verified capture is
            # believed even if some earlier line said it had found nothing.
            # Only the weaker bare-regex sweep defers to the denial.
            try:
                log_line(job_id, (
                    "⚑ FLAG SWEEP SUPPRESSED — the run's own output declares "
                    f"failure: {_denial!r}. Candidate(s) dropped from the "
                    f"trusted tier: {sorted(trusted)}. If one of these is real, "
                    f"the solver should print `FLAG_CANDIDATE: <flag>` on "
                    f"capture — the marker tier is not subject to this rule."
                ))
            except Exception:
                pass
            _prov_suppressed(_denial)
            trusted = set()
    if trusted:
        _prov("runner_regex")
        return sorted(trusted)

    # Skip narrative fallback when the sandbox never ran. Without a
    # sandbox cycle, every flag-like string in run.log / report.md /
    # findings.json is necessarily agent-authored (recon notes, chal
    # source quotes, FSOP analysis examples) — never a real capture.
    sandbox_skipped = bool(
        sandbox_result and (
            sandbox_result.get("judge_aborted")
            or sandbox_result.get("error") == "prejudge_blocked"
        )
    )
    if sandbox_skipped or crashed_before_sandbox or trusted_only:
        return []

    narrative = {f for f in _scan(_NARRATIVE_FLAG_SOURCES) if not _is_placeholder_flag(f)}
    if narrative:
        _prov("narrative")
    return sorted(narrative)


_UUIDISH = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def _norm_chal(s: str) -> str:
    """Comparison form for a challenge identity: basename, no archive
    extension, alphanumerics only."""
    s = (s or "").strip().lower().rsplit("/", 1)[-1]
    for ext in (".tar.gz", ".tgz", ".tar", ".zip", ".gz", ".elf", ".bin", ".exe"):
        if s.endswith(ext):
            s = s[: -len(ext)]
            break
    return re.sub(r"[^a-z0-9]+", "", s)


# Names that identify a build artifact rather than a challenge. Matching on
# these is worse than not matching: `_score` gives containment a point, so a
# rev job whose binary is `main` scored against every stored `main` and filled
# all twelve visible slots with unrelated entries -- measured on the real
# corpus, the recency set went from 12 survivors to 1.
#
# Deliberately a SMALL EXPLICIT LIST rather than a derived rule, because every
# data-driven alternative was tried against the real corpus and each one had a
# counter-example:
#   library frequency > 1  -- kept rev `server`, and blocked pwn's genuine
#                             `qemu-system-x86_64` (2 real entries)
#   length <= 4            -- kept `server`, blocked genuine `er` and `obf`
#   Shannon entropy        -- `server` 1.918 > `obf` 1.585 > `er` 1.0, so the
#                             ordering does not separate meaning at all
# Add to this list only with a corpus measurement attached; a name that is
# genuinely a challenge title must never appear here.
_LIBRARY_STOP_NAMES = frozenset({
    "main", "chal", "chall", "challenge", "prob", "problem", "task",
    "server", "client", "app", "run", "test", "bin", "binary", "aout",
    "program", "readme", "readmemd", "index", "flag", "vuln", "dockerfile",
    "output", "source", "src", "file", "data", "target", "sample",
})


def _library_display_name(meta: dict) -> str:
    """What to CALL an entry in the hint.

    `chal_filename` is an upload UUID (`58294f50-bf6c-…zip`) for every entry
    saved from the UI, so preferring it — as this used to — rendered all twelve
    lines as anonymous hashes. `chal_name` is the human name the saver derives
    from the description or binary, which is the only field an agent can match
    its own challenge against.
    """
    name = (meta.get("chal_name") or "").strip()
    if name:
        return name
    fn = (meta.get("chal_filename") or "").strip()
    return "?" if not fn or _UUIDISH.match(fn) else fn


def build_exploit_library_hint(module: str, *, max_entries: int = 12,
                               chal_name: str = "",
                               stats: dict | None = None) -> str:
    """Return a short paragraph nudging the agent to consult
    `/data/exploits/` when stuck on technique / leak-vector choice, or
    `""` when the library is empty or the operator has turned the hint
    off via `enable_exploit_library_hint`.

    Filtering: same-module entries only (a pwn chal sees only pwn
    exploits, etc.). Cap at `max_entries` entries so the prompt doesn't blow up
    on large libraries. The agent is expected to `ls /data/exploits/` + `cat`
    the relevant report.md itself — we just surface what's available and what
    each one solved.

    Pass a dict as `stats` to receive the shadow counters for one call
    (`query`, `query_generic`, `suppressed`) without adding state anywhere.
    Nothing in the rendered hint changes; this exists so the stoplist
    vocabulary can be tuned against real traffic rather than guessed at.

    Ranking is by RELEVANCE, not recency, and `chal_name` is what makes that
    possible. Job e601cd358ad6 is the worked example: an advanced version of a
    protoss chal already in the library as pwn-506c22dd0b8d, with a 10 KB
    report and a working 15 KB exploit. The agent re-derived the identical
    primitive — unchecked `std::vector::operator[]` indexed by a DB primary key
    into a forged std::string for an AAR — over 88 turns and $23.77. Recency
    ordering would not have helped even with the hint enabled: with 147 entries
    the match can sit anywhere, and every line rendered as an upload UUID so
    there was nothing to match ON.
    """
    try:
        from modules.settings_io import get_setting
    except Exception:
        return ""

    if not get_setting("enable_exploit_library_hint"):
        return ""

    if not EXPLOITS_DIR.is_dir():
        return ""

    mod_norm = (module or "").lower().strip()
    entries: list[dict] = []
    for d in sorted(EXPLOITS_DIR.iterdir()):
        if not d.is_dir():
            continue
        mp = d / "meta.json"
        if not mp.is_file():
            continue
        try:
            meta = json.loads(mp.read_text(errors="replace"))
        except Exception:
            continue
        if (meta.get("module") or "").lower() != mod_norm:
            continue
        entries.append(meta)

    if not entries:
        return ""

    # Relevance first, recency only as a tiebreak. A same-name entry is the
    # strongest signal available here: an advanced/variant version of a chal
    # keeps the name while the binary hash changes, so hashing would MISS
    # exactly the case this is for.
    want = _norm_chal(chal_name)

    want_generic = want in _LIBRARY_STOP_NAMES
    if stats is not None:
        # Counted once here, NOT inside _score: the two stable sorts plus the
        # render loop each call _score per entry, so incrementing there would
        # report three times the real number.
        stats["query"] = want
        stats["query_generic"] = want_generic
        stats["suppressed"] = sum(
            1 for m in entries
            if _norm_chal(m.get("chal_name") or "") in _LIBRARY_STOP_NAMES
        )

    def _score(m: dict) -> int:
        """2 = same challenge name, 1 = one name contains the other, 0 = no
        relation. Substring counts because variants get suffixed ('protoss2',
        'protoss-rev2').

        A build-artifact name on EITHER side scores 0. Both sides are needed:
        suppressing only the query still lets a real name like `nsprobe`
        contain a stored `prob`, which on the live corpus starred nine
        unrelated entries alongside the one true match."""
        if not want or want_generic:
            return 0
        got = _norm_chal(m.get("chal_name") or "")
        if not got or got in _LIBRARY_STOP_NAMES:
            return 0
        if got == want:
            return 2
        return 1 if (got in want or want in got) else 0

    # Two stable sorts: recency first, then score. The second preserves the
    # recency order within each score band.
    entries.sort(key=lambda m: m.get("saved_at") or "", reverse=True)
    entries.sort(key=_score, reverse=True)
    entries = entries[:max_entries]

    lines = [
        "PRIOR-EXPLOIT LIBRARY (operator-curated) — available at "
        "`/data/exploits/` (read-only). When stuck on technique / "
        "leak-vector / chain choice, browse these and extract the "
        "PRIMITIVE NAME + version-specific gotcha. Do NOT blindly "
        "copy — re-derive that primitive in YOUR chal's context.",
        "",
        f"Entries for module `{mod_norm}` "
        + (f"(most relevant first, {len(entries)} shown):"
           if want else f"(newest first, {len(entries)} shown):"),
    ]
    for m in entries:
        eid = m.get("id") or "?"
        chal = _library_display_name(m)
        _rank = _score(m)
        same = _rank > 0
        arch = m.get("arch") or "?"
        glibc = m.get("glibc_version") or "?"
        technique = m.get("technique_name") or "?"
        bug = ",".join(m.get("bug_classes") or []) or "?"
        tags = ",".join(m.get("tags") or [])
        notes = (m.get("notes") or "").replace("\n", " ").strip()
        if len(notes) > 120:
            notes = notes[:117] + "..."
        tags_part = f" tags=[{tags}]" if tags else ""
        notes_part = f" — {notes}" if notes else ""
        bullet = "★" if same else "•"
        # Two tiers, because `_score` returns 2 for an equal normalized name
        # and 1 for mere containment, and calling BOTH "SAME CHALLENGE NAME as
        # yours" is false at tier 1: `protoss` and `protoss2` are related, not
        # the same challenge. The false version was load-bearing in the wrong
        # direction -- a rev job whose binary is named `main` matched every
        # stored `main` and got twelve unrelated exploits each captioned as its
        # own challenge, with an imperative to read them first.
        # The identity claim differs by tier; the ACTION does not. Both tiers
        # still tell the agent to look before re-deriving, which is the whole
        # point of the variant case the regression suite pins.
        if _rank == 2:
            flag = ("  <<< EXACT NORMALIZED NAME MATCH — read its report.md "
                    "and exploit.py FIRST, then re-derive for THIS variant")
        elif _rank == 1:
            flag = ("  <<< RELATED NAME (one name contains the other; NOT "
                    "necessarily the same challenge) — inspect before "
                    "re-deriving")
        else:
            flag = ""
        lines.append(
            f"  {bullet} {eid}  chal={chal}  arch={arch}  glibc={glibc}  "
            f"bug={bug}  technique={technique}{tags_part}{notes_part}{flag}"
        )
    lines.append("")
    lines.append(
        "To consult: `ls /data/exploits/` + `cat "
        "/data/exploits/<id>/report.md` (or `exploit.py` / `solver.py`)."
    )
    return "\n".join(lines)


_PLACEHOLDER_INNERS = {
    "...", "…", "?", "??", "???", "????", "??????",
    "example", "redacted", "placeholder", "sample", "test", "todo",
    "tbd", "n/a", "na", "hidden", "secret", "truncated", "x",
    "your_flag", "your_flag_here", "the_flag", "the_flag_here",
    "real_flag", "real_flag_here", "flag", "flag_here",
    "flag_goes_here", "fill_in_the_blank", "...the actual flag...",
    "actual_flag", "captured_flag",
    # Common chal-author local-test placeholders that the agent's
    # recon often copies verbatim from `chal/run.sh` into report.md.
    # Concrete incident 2026-05-17 job 9a240a221f1b: both real flag
    # and `DH{this_is_a_flag}` appeared in FLAGS FOUND because the
    # chal's local-test runner literally exports
    # FLAG="DH{this_is_a_flag}" as a default.
    "this_is_a_flag", "this_is_the_flag", "this_is_flag",
    "here_is_the_flag", "here_is_a_flag", "here_is_flag",
    "insert_flag_here", "insert_flag", "fake_flag", "dummy_flag",
    "local_test_flag", "test_flag", "default_flag",
    # Job 44dd25365173 (2026-05-23): narrative scan extracted
    # agent-authored hashes from report.md / run.log. The chal printed
    # "Flag is: DH{<sha256>}" and the agent quoted the printf format,
    # also computed sha256("") = e3b0c... as an illustrative example.
    "<sha256>", "<md5>", "<hash>", "<value>", "<address>", "<libc>",
    # Empty-input hashes — agents frequently reference these as
    # baseline examples when discussing crypto chals.
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256("")
    "d41d8cd98f00b204e9800998ecf8427e",                                  # md5("")
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",                          # sha1("")
}

# Glued placeholder words the exact-match set above misses: DH{testflag},
# DH{faketest}, DH{dummyflag1}. Job ca27378ee3ee echoed `DH{testflag}` as a
# local oracle test and it surfaced as a flag_candidate (→ [FLAG?] box + the
# new flag alarm). The set has "test"/"test_flag" but not the glued "testflag".
# SAFETY (memory real_flag_dropped_as_placeholder): this must NEVER drop a real
# flag. Two guards make that true: (1) a leading lookahead REQUIRES at least one
# UNAMBIGUOUS placeholder word, so a bare hex digest / `DH{123}` is not caught;
# (2) the body is a full-match of placeholder-words+filler only, so an
# incidental substring (`con-test-_winner`, `winnertest`) fails the body match
# even though the lookahead sees "test". Real Dreamhack hex flags contain no
# such word → never matched. `candidate` is also unambiguous in an inner
# made entirely from this vocabulary: jobs 5c3974d26ab4, 47de39fd0c01 and
# 94d105ace230 all promoted the agent-authored `DH{candidate_here}` and ended
# their retry loops without the solver ever printing that string.
_PLACEHOLDER_WORD_RE = re.compile(
    r"^(?=.*(?:test|fake|dummy|example|sample|placeholder|redacted|todo|candidate))"
    r"(?:test|fake|dummy|example|sample|placeholder|redacted|todo|candidate|flag|"
    r"local|default|your|here|insert|the|real|change(?:me)?|goes|fill|blank|"
    r"[_\-\s\d])+$"
)


def _is_placeholder_flag(flag: str, trusted: bool = False) -> bool:
    """True if `flag` is an obvious placeholder like FLAG{...} / DH{xxx} /
    CTF{your_flag_here} that just happened to match the FLAG_RE — it
    appears in reports and prompt templates but is not a real captured flag.

    `trusted=True` marks the flag as coming from a genuine RUN artifact
    (sandbox stdout/stderr / collector) rather than agent prose. For those
    the over-broad hash-WIDTH heuristic (any `DH{<32|40|64 hex>}`) is
    suppressed — a hex flag printed by a real run is a real flag, and
    Dreamhack flags ARE literally `DH{<64 hex>}` (job a3d4d4484233 solved the
    chal but was recorded no_flag because the real flag matched that rule).
    The specific decoy markers (empty-input hashes, %s, <...>, your_flag…)
    still apply to trusted captures too.
    """
    i = flag.find("{")
    if i >= 0 and flag.endswith("}"):
        inner_raw = flag[i + 1 : -1].strip()
    else:
        # No CTF-style braces. Reached only via the FLAG_CANDIDATE marker
        # path, where the declared flag may be raw-hex or prefix-less. Treat
        # the whole string as the inner so the metavariable / placeholder-word
        # guards below still catch a brace-less template echo (e.g. the agent
        # printing `FLAG_CANDIDATE: <the flag>` without ever capturing). The
        # FLAG_RE / narrative path never produces a brace-less match.
        inner_raw = flag.strip()
    inner = inner_raw.lower()
    if not inner:
        return True
    if inner in _PLACEHOLDER_INNERS:
        return True
    # Glued placeholder-word combos the exact set misses (DH{testflag} …).
    # See _PLACEHOLDER_WORD_RE — engineered to never catch a real hex flag.
    if _PLACEHOLDER_WORD_RE.match(inner):
        return True
    # All the same character (.... / xxxx / ____)
    if len(inner) >= 2 and len(set(inner)) == 1 and inner[0] in "._-x?…":
        return True
    # Only filler characters (dots, underscores, dashes, spaces)
    import re as _re
    if _re.fullmatch(r"[._\-\s…]+", inner):
        return True
    # printf format / metavariable markers
    # Job 44dd25365173: chal's printf("Flag is: DH{%s}\n", ...) leaked
    # into report.md verbatim → `DH{%s}` scanned as a flag. Any inner
    # containing `%` (format) is a template.
    if "%" in inner_raw:
        return True
    # A `<word>` METAVARIABLE template (`<flag>`, `<your_flag_here>`,
    # `<secret>`) is a placeholder — but ONLY when the angle brackets wrap a
    # LETTER-led token. Do NOT reject a flag that merely CONTAINS `<` / `>`
    # as literal content: job bcd883b0e70f's REAL flag was
    # `DH{Br1ll1ant_bit_dr1bble_<<_>>}` (the chal is a bit-shift `<<`/`>>`
    # keygen). The old "`<` and `>` both present" pair-rule discarded it at
    # EVERY tier (marker + trusted + narrative), after which the narrative
    # fallback scraped the logged solver SOURCE line
    # `flag = "DH{" + secret + "}"` out of run.log as the (wrong) capture.
    # `<%s>` stays caught by the `%` rule above; `<<_>>` has no letter after
    # any `<`, so it correctly survives.
    #
    # The anchor is `[a-z0-9]`, not `[a-z]`: the most common metavariable an
    # agent writes for a flag it has NOT captured is DIGIT-led — `DH{<64hex>}`,
    # `DH{<32 hex chars>}`, `DH{<36 chars>}` — and a letter-only anchor passed
    # every one of them at every tier. This is the gap the whitespace parity
    # fix (job_flag_format_re) does NOT close: `<64hex>` contains no whitespace,
    # so it is promoted on the plain FLAG_RE path too. `DH{<36 chars>}` was
    # sitting in job 0c04e636633c's findings.json. Corpus-checked: zero of the
    # 150 recorded real flags contain `<` at all, and `<<_>>` still survives
    # because each `<` is followed by `<` or `_`.
    if _re.search(r"<[a-z0-9][\w ]*>", inner):
        return True
    # A literal quote in the inner is a code fragment, never a flag (a real
    # flag can't contain the quote that delimits the string it is printed
    # from). Backstop for the bcd883b0e70f narrative scrape above:
    # `DH{" + secret + "}` carries a `"` and would otherwise pass.
    if '"' in inner_raw or "'" in inner_raw:
        return True
    # Embedded ellipsis in NARRATIVE prose = an ABBREVIATED / elided flag.
    # Job a15ff70a6ed5: the judge wrote "captured the REAL flag DH{...20207ea}"
    # into a prejudge issue; that abbreviation was scanned out of run.log
    # (narrative tier, trusted=False) and stored as meta.flags[0] — while the
    # genuine DH{<40 hex>} was dropped by the hash-width rule below.
    #
    # `not trusted`-ONLY: a TRUSTED capture (FLAG_CANDIDATE marker / runner
    # stdout) may legitimately carry `...` as real flag CONTENT. Job
    # 187a2d3ee182's genuine capture was `DH{Amo_is_watching_you...:...==}`
    # (the chal is literally "Amo is watching you…"); this rule silently
    # dropped it at EVERY tier → status=no_flag despite judge verdict=success,
    # flag never shown in the UI. The bare `DH{...}` template echo this rule
    # was also meant to catch for trusted is ALREADY caught by the filler-only
    # rule above (`[._\-\s…]+` fullmatches `...`), so exempting trusted here
    # lets only real mid-content ellipses through, never a template. Mirrors
    # the hash-width gate below, which is likewise `not trusted`.
    if not trusted and ("..." in inner_raw or "…" in inner_raw):
        return True
    # Raw hex BLOBS — only the absurdly-long ones are placeholders.
    # Real Dreamhack flags ARE `DH{<32|40|64 raw hex>}` (md5/sha1/sha256
    # widths), so the old exact-width drop (32|40|64) was a false-negative
    # machine: it killed genuine narrative-only captures — job
    # a15ff70a6ed5 (DH{<40 hex>}) and db015a6d013c (DH{<64 hex>}, a real
    # live XSS-exfil flag) both vanished from FLAG FOUND this way.
    # Operator relaxed the ceiling to 100 hex (2026-06-08): hex inners up
    # to 100 chars are KEPT as potential real flags; only hex strings
    # LONGER than 100 chars (clearly a dumped blob / decomp constant, not
    # a flag) are dropped. The specific empty-input hash decoys
    # (sha256("")/md5("")/sha1("")) stay blocked via `_PLACEHOLDER_INNERS`
    # above, independent of this width rule — so the job 44dd25365173
    # empty-hash case is still caught; only ARBITRARY canonical-width
    # hex in narrative prose is now allowed through (last-resort tier
    # only; trusted captures already bypassed this rule entirely).
    import re as _re
    if not trusted and _re.fullmatch(r"[0-9a-f]{101,}", inner):
        return True
    return False


# ---------------------------------------------------------------------------
# Worker-container tool catalogue.
#
# These blocks are dropped into each module's SYSTEM_PROMPT so the agent
# knows which CLIs and Python packages it can shell out to via Bash. Keep
# in sync with worker/Dockerfile + worker/requirements.txt — anything
# listed here MUST exist in the worker image, otherwise the agent will
# burn tokens trying to call something that returns "command not found".
#
# Heavy reverse-engineering / forensic / unpacking tools live in the
# *sibling* container images (decompiler / forensic / misc / runner) and
# are reachable only through the wrappers each module mentions explicitly
# (e.g. `ghiant` for the agent's Bash, summary.json for forensic, etc.).
# ---------------------------------------------------------------------------


REFUSAL_HINTS = (
    "usage policy",
    "unable to respond to this request",
    "violates our usage policy",
)


def _recon_def(model: str | None):
    """AgentDefinition for the recon subagent. Read-only tools; same
    model as the main agent so it shares cache prefixes.
    """
    from claude_agent_sdk import AgentDefinition

    return AgentDefinition(
        description=(
            "Read-only reconnaissance subagent for the main exploit "
            "writer. Delegate any disasm walk, symbol/offset lookup, "
            "rootfs/firmware unpacking, libc gadget search, or source-"
            "tree grep that would otherwise pollute the main "
            "conversation context. Pass a single specific question; "
            "expect a ≤2KB summary."
        ),
        prompt=RECON_AGENT_PROMPT,
        # Read-only — main keeps the only Write/Edit hand on
        # exploit.py / solver.py / report.md.
        tools=["Read", "Bash", "Glob", "Grep"],
        model=model,
    )


def _judge_def(model: str | None = None):
    """AgentDefinition for the judge subagent. Pinned to the latest
    Claude model (LATEST_JUDGE_MODEL) regardless of what the user
    selected for main, because the judge's job is a final-pass quality
    gate and we never want it lagging the main model.
    """
    from claude_agent_sdk import AgentDefinition

    return AgentDefinition(
        description=(
            "Read-only quality-gate / verdict subagent. Reviews the "
            "just-written exploit/solver for I/O hangs, parse mismatches, "
            "and wrong-target bugs; categorizes finished runs; can "
            "delegate heavy investigation to the recon subagent. "
            "Cannot Write or Edit. Pinned to the latest Claude model."
        ),
        prompt=JUDGE_AGENT_PROMPT,
        tools=["Read", "Bash", "Glob", "Grep", "Agent"],
        model=model or LATEST_JUDGE_MODEL,
    )


def _triage_def(model: str | None):
    """AgentDefinition for the triage subagent. Verdict-only; re-reads
    the cited file:lines and emits {real | duplicate | false_positive
    | out_of_scope} per candidate. Same model as main so cache prefixes
    line up.
    """
    from claude_agent_sdk import AgentDefinition

    return AgentDefinition(
        description=(
            "Independent verifier for candidate vulnerabilities. Re-"
            "reads each cited file:line, marks {real | duplicate | "
            "false_positive | out_of_scope}, RE-DERIVES severity "
            "from reachability + blast radius (does NOT inherit the "
            "upstream guess). Read-only — no writes, no shell beyond "
            "trivial size checks."
        ),
        prompt=TRIAGE_AGENT_PROMPT,
        tools=["Read", "Bash", "Glob", "Grep"],
        model=model,
    )


def _debugger_def(model: str | None):
    """AgentDefinition for the debugger subagent. Has Write because it
    needs to drop scratch gdb scripts / probe inputs under /tmp; it
    will NOT touch ./exploit.py / ./solver.py / ./report.md per the
    DEBUGGER_AGENT_PROMPT contract. Same model as main so cache
    prefixes line up between main's reasoning and debugger's
    responses.
    """
    from claude_agent_sdk import AgentDefinition

    return AgentDefinition(
        description=(
            "Dynamic-analysis subagent that runs the binary under "
            "gdb / strace / ltrace / qemu-user and reports observed "
            "register state, heap layouts, leaked addresses, signals "
            "fired. Patchelfs the binary against the chal's bundled "
            "libc/ld first (via `chal-libc-fix`) so offsets match the "
            "remote. Same model as main for cache locality."
        ),
        prompt=DEBUGGER_AGENT_PROMPT,
        # Write/Edit allowed for /tmp scratch (gdb command files,
        # probe inputs); the debugger's prompt forbids touching the
        # main artifacts. Agent tool so debugger can ask recon for
        # static facts mid-session.
        tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep", "Agent"],
        model=model,
    )


def build_team_agents(model: str | None) -> dict:
    """`agents` dict for the MAIN session. Registers all three peers
    main can delegate to:

      recon    — heavy read-only static investigation, ≤2 KB summary.
      judge    — quality gate / verdict, peer subagent main can ask
                 for a pre-merge sanity check.
      debugger — dynamic analysis (gdb / strace / ltrace under a
                 patchelf'd binary), reports observed runtime state.

    Imported lazily inside analyzers so unit tests / non-SDK paths
    don't have to install the SDK.

    An active model-preset can pin any of these roles independently; a blank
    entry falls through to the existing default (recon/debugger/triage follow
    main for cache alignment; judge → LATEST_JUDGE_MODEL).
    """
    from modules.model_presets import resolve_role_model
    return {
        "recon": _recon_def(resolve_role_model("recon", model)),
        "judge": _judge_def(resolve_role_model("judge", LATEST_JUDGE_MODEL)),
        "debugger": _debugger_def(resolve_role_model("debugger", model)),
        "triage": _triage_def(resolve_role_model("triage", model)),
    }


def build_judge_agents(model: str | None) -> dict:
    """`agents` dict for the JUDGE's own session (orchestrator-invoked).

    Registers only `recon` — the judge can delegate to recon for heavy
    investigation, but is not allowed to invoke itself recursively.
    Recon uses the same LATEST_JUDGE_MODEL so cache prefixes line up
    between judge's own thinking and recon's responses — unless an active
    model-preset pins the recon role, which overrides (at the cost of that
    cache alignment).
    """
    from modules.model_presets import resolve_role_model
    return {"recon": _recon_def(resolve_role_model("recon", model or LATEST_JUDGE_MODEL))}


# Backward compatibility — the analyzers historically called
# build_recon_agents(); now the same call returns the full team
# (recon + judge), which means existing main agents pick up judge as
# a peer subagent automatically. No analyzer code change needed.
build_recon_agents = build_team_agents


# ─────────────────────────────────────────────────────────────
# Isolated subagent path (process-per-subagent via MCP)
# ─────────────────────────────────────────────────────────────
# Verified empirically (see memory/worker_fork_oom.md): the SDK runs
# ALL agent contexts inside a single `claude` CLI Node.js process.
# When main spawns `Agent(subagent_type=...)` (legacy path), the
# subagent's conversation accumulates into main's process heap and
# inflates main's cache_read by KB per subagent step. The MCP-based
# path below replaces the built-in `Agent` tool with a custom
# `spawn_subagent` MCP tool. Each call to that tool creates a FRESH
# `ClaudeSDKClient` (= fresh `claude` CLI subprocess) for the
# subagent. The subagent runs to completion, returns its final text
# response, and the subprocess dies. main only ever sees the final
# text as a tool_result — the subagent's full conversation never
# touches main's context. This is what "main / recon / debugger /
# judge are independent agents" means at the OS process level, and
# it's the reason isolated mode keeps main's cache_read small even
# on long heap-pwn runs.

_AGENT_PROMPT_BY_TYPE = {
    # Filled lazily — RECON_AGENT_PROMPT etc. are defined later in
    # this file, after the prompt constants block. The lookup uses
    # globals() at call time so we don't have a circular reference.
    "recon": "RECON_AGENT_PROMPT",
    "debugger": "DEBUGGER_AGENT_PROMPT",
    "judge": "JUDGE_AGENT_PROMPT",
    "triage": "TRIAGE_AGENT_PROMPT",
}

_AGENT_TOOLS_BY_TYPE = {
    # recon owns WebSearch + WebFetch so main can delegate CVE / technique /
    # documentation lookups to it (web research is ENABLED — operator decision
    # 2026-07-22, reversing the 9fcf3ab anti-writeup block). Routing web
    # research through recon keeps the large result bodies in the subagent's
    # transient context instead of bloating main's (job d809a5187990: main
    # called WebSearch 33× directly, ~200 KB of result bodies in-context).
    "recon": ["Read", "Bash", "Glob", "Grep", "WebSearch", "WebFetch"],
    "debugger": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
    # judge has no Agent tool here — in isolated mode, subagents can't
    # cascade-spawn further subagents (preserves the "ONE level deep"
    # invariant the original AgentDefinition-based path enforced via
    # the SDK's recursive-Agent block).
    "judge": ["Read", "Bash", "Glob", "Grep"],
    # triage is verdict-only — re-reads cited files to verify, no
    # writes, no shell. Bash is included for `wc -l` / `head` size
    # checks before a Read, but triage prompts forbid running any
    # binary or compiling anything.
    "triage": ["Read", "Bash", "Glob", "Grep"],
}


# Control bytes that cannot ride in argv across execve. The kernel
# treats argv[i] as a NUL-terminated C string, so ANY embedded NUL kills
# the spawn with `ValueError: embedded null byte` before the new process
# even starts. The other bytes (SOH/STX/ETX/EOT/BS/VT/FF/SO/SI) aren't
# argv-fatal in themselves but mangle the claude CLI's JSON framing and
# the user-facing log preview, so we strip them in the same pass.
#
# CAUSE: source-level Python escape sequences (`\0`, `\x00`, `\x01`) in
# prompt string literals — easy to introduce by accident (`"writes \0 at
# buf+N"` reads as "documenting", actually emits a literal NUL byte). The
# rule is that *anything* heading to ClaudeSDKClient as a system_prompt /
# initial prompt / tool description must go through this filter, no
# exceptions.
_ARGV_FATAL_BYTES = "\x00\x01\x02\x03\x04\x08\x0b\x0c\x0e\x0f"
_ARGV_STRIP_TABLE = str.maketrans({c: "" for c in _ARGV_FATAL_BYTES})


def sanitize_for_argv(s: str | None, *, label: str = "", log_fn=None) -> str:
    """Strip control bytes that would crash subprocess.Popen via argv.

    Returns the cleaned string. When bytes are stripped AND `log_fn` is
    provided, emits a one-line audit so the cause is traceable in the
    job's run.log instead of disappearing silently.
    """
    if not s:
        return s or ""
    cleaned = s.translate(_ARGV_STRIP_TABLE)
    if cleaned != s and log_fn is not None:
        removed = len(s) - len(cleaned)
        tag = f"[{label}] " if label else ""
        log_fn(
            f"{tag}stripped {removed} argv-fatal control byte(s) from "
            f"option/prompt text (would have crashed subprocess.Popen "
            f"with `embedded null byte`)"
        )
    return cleaned


# Module-specialized RECON web-research guidance. The base RECON_AGENT_PROMPT
# "Web research — ENABLED" section is pwn/heap-flavored (FSOP / tcache /
# House-of-* / libc-struct / gadget examples); a crypto/rev/web/forensic recon
# inherits pwn framing for what "local ground truth first" and "what the web is
# good for" mean. This appends a domain-correct reframe for NON-pwn recon
# subagents (pwn → "" so its prompt stays byte-identical), keyed off the job's
# module. Continuous with the MODULE-SCOPE note prepended in
# make_standalone_options: that note says the pwn framing below is reference-
# only; this supplies the positive per-domain guidance. Recon-only (the
# debugger prompt is separate and not web-research-shaped).
_RECON_WEB_ADDENDUM = {
    "crypto": (
        "WEB RESEARCH FOR THIS crypto JOB (overrides the pwn-flavored web "
        "examples above)\n"
        "-----------------------------------------------------------------\n"
        "Local ground truth = the challenge's OWN source + the exact "
        "parameters you extract from it; a generic writeup is usually wrong "
        "for a modified scheme and its constants won't match. Use the web to: "
        "NAME the primitive/scheme (e.g. a named curve, 'Paillier', "
        "'McNie rank-metric'), find the CONCRETE attack ALGORITHM (Coppersmith "
        "bound + polynomial, HNP/biased-nonce lattice construction, a specific "
        "decoding / linearization / lattice recipe, a CVE), and locate "
        "reference code to adapt. When an academic PDF (arXiv / "
        "eprint.iacr.org / HAL / IEEE) fails to fetch or renders as garbage, "
        "RETRY THE HTML MIRROR (ar5iv.labs.arxiv.org/html/<id>, "
        "arxiv.org/abs/<id>, the eprint HTML page) before giving up — do not "
        "silently drop the algorithm you need. Then RE-DERIVE the math from "
        "the paper and VERIFY it against a local test vector; never trust a "
        "writeup's numbers."
    ),
    "rev": (
        "WEB RESEARCH FOR THIS rev JOB (overrides the pwn-flavored web "
        "examples above)\n"
        "--------------------------------------------------------------\n"
        "Local ground truth = the disassembly / decompilation / a dynamic "
        "trace of the binary in front of you. Use the web to: RECOGNIZE a "
        "library / algorithm / packer signature (a known magic constant, hash "
        "IV, VM-handler pattern, obfuscator, known crypto S-box), and find "
        "file-format / instruction-set / ABI specs. Recover ACTUAL behavior by "
        "running / tracing (gdb / qemu / ltrace / strace), not by trusting a "
        "blog — a deliberately-modified binary won't match the reference."
    ),
    "web3": (
        "WEB RESEARCH FOR THIS web3 JOB (overrides the pwn-flavored web "
        "examples above)\n"
        "--------------------------------------------------------------\n"
        "Local ground truth = the Solidity in front of you and what a local "
        "anvil chain actually does when you run it. Use the web to: look up "
        "EXACT semantics you must not guess at (opcode behaviour and gas "
        "rules, `delegatecall` storage context, proxy/EIP-1967 slot layout, "
        "ERC-20/721/777 hook order, precompile addresses), read the reference "
        "docs for a library the challenge imports (OpenZeppelin version "
        "differences are load-bearing — `_beforeTokenTransfer` moved, "
        "`Initializable` changed), and recognise a known bug pattern by name. "
        "Do NOT copy an exploit from a writeup of a similarly-named "
        "challenge: CTF contracts are deliberately modified, and the one line "
        "they changed is the whole puzzle. Verify every claim on anvil — it "
        "is free and instant, so there is no excuse for shipping an untested "
        "assumption about EVM behaviour."
    ),
    "web": (
        "WEB RESEARCH FOR THIS web JOB (overrides the pwn-flavored web "
        "examples above)\n"
        "--------------------------------------------------------------\n"
        "Local ground truth = the app's OWN source / routes / config / the "
        "installed dependency VERSIONS. Use the web to: find framework & "
        "library CVEs and version-specific bypasses, and known gadget chains "
        "(deserialization, SSTI, prototype-pollution, auth bypass, SSRF) for "
        "the DETECTED stack. VERIFY every payload against the running app — a "
        "public PoC rarely fits an unmodified copy of the challenge, and a "
        "borrowed gadget must be checked against the actual dependency version."
    ),
    "forensic": (
        "WEB RESEARCH FOR THIS forensic JOB (overrides the pwn-flavored web "
        "examples above)\n"
        "-------------------------------------------------------------------\n"
        "Local ground truth = the artifact itself (file carving, headers, "
        "metadata, packet/memory image). Use the web to: look up file-format / "
        "magic-byte specs, tool usage, and known malware / stego / filesystem / "
        "protocol signatures. Confirm every finding against the bytes you can "
        "actually see."
    ),
    "misc": (
        "WEB RESEARCH FOR THIS misc JOB (overrides the pwn-flavored web "
        "examples above)\n"
        "---------------------------------------------------------------\n"
        "Identify the domain first from the material you have, then use the web "
        "for the relevant format / protocol specs, known techniques, and "
        "reference implementations. Prefer local ground truth and verify "
        "anything borrowed against the challenge's own data. When an academic "
        "PDF fails to fetch, retry an HTML mirror (ar5iv / arxiv.org/abs / "
        "publisher HTML) before dropping it."
    ),
}


def _recon_web_research_addendum(module: str) -> str:
    """Per-module RECON web-research reframe; '' for pwn/unknown (no change)."""
    return _RECON_WEB_ADDENDUM.get((module or "").lower(), "")


def agent_job_env(
    job_id: str,
    role: str,
    work_dir,
    extra: dict | None = None,
) -> dict[str, str]:
    """The per-job environment EVERY agent process gets.

    Three call sites built this independently — main, sub-agents, and (not at
    all) pre-recon. The omission was not cosmetic: with no per-job TMPDIR, GPT
    pre-recon extracted an archive into the container-global /tmp and then
    analysed a `prob.ko` left there by an earlier job, while the initramfs it
    was handed contained only `serendipity.ko` (job 6685e3e65add). A whole
    recon pass answered about the wrong binary.

    So it lives in one place. `TMPDIR`/`TMP`/`TEMP` cover library calls
    (tempfile, pwntools, pip, pyc cache); absolute-path escapes in Bash are a
    separate concern the CTF_PREAMBLE scratch-file rule owns.
    """
    env: dict[str, str] = {"JOB_ID": str(job_id)}
    if role:
        env["AGENT_ROLE"] = str(role)
    tmp_dir = Path(work_dir) / "tmp"
    try:
        tmp_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        # A scratch dir we cannot create is not a reason to fail the run; the
        # agent falls back to the container default exactly as before.
        pass
    _t = str(tmp_dir)
    env["TMPDIR"] = _t
    env["TMP"] = _t
    env["TEMP"] = _t
    # Terminal-mode quietness: pwntools/checksec print a terminfo error per
    # invocation inside the worker container without these.
    env.setdefault("TERM", "xterm")
    env.setdefault("PWNLIB_NOTERM", "1")
    if extra:
        env.update({k: str(v) for k, v in extra.items()})
    from modules.job_secrets import read_job_secrets

    env.update(read_job_secrets(job_id))
    return env


def make_standalone_options(
    agent_type: str,
    model: str | None,
    work_dir,
    job_id: str,
    extra_env: dict | None = None,
):
    """Build `ClaudeAgentOptions` for a subagent running as a STANDALONE
    session — i.e. it IS the main of its own SDK client, not a sub-
    conversation inside another client. Used by the spawn_subagent MCP
    tool to fork a fresh `claude` CLI subprocess per subagent
    invocation, which keeps the parent main's heap from accumulating
    the subagent's full conversation context.
    """
    from claude_agent_sdk import ClaudeAgentOptions

    if agent_type not in _AGENT_PROMPT_BY_TYPE:
        raise ValueError(f"unknown agent_type {agent_type!r}")
    prompt_name = _AGENT_PROMPT_BY_TYPE[agent_type]
    prompt = globals().get(prompt_name)
    if not prompt:
        raise RuntimeError(
            f"agent prompt {prompt_name} not yet defined — module init "
            f"order bug; ensure prompts load before "
            f"make_standalone_options is called"
        )
    # MODULE SCOPE guard. RECON_AGENT_PROMPT / DEBUGGER_AGENT_PROMPT are
    # pwn-exploit-flavored (29 KB / 20 KB of one_gadget / FSOP / safe-linking /
    # tcache-poison / House-of-* / hooks heap-RCE framing) and are selected by
    # agent_type ALONE — no module key — so a rev / web / crypto recon|debugger
    # subagent inherits the full pwn exploitation frame. That mis-stamped job
    # afeda41720a4: an alloc-only (no free/realloc) Aho-Corasick matcher got
    # its rev pre-recon ranked "House-of-Einherjar / tcache-overlap" as the TOP
    # candidate into main's authoritative frame. (It self-corrected, but the
    # leak is structural + has multi-hour-waste precedent.) Prepend a scope note
    # for NON-pwn recon/debugger so the exploit-mitigation vocabulary reads as
    # PWN-ONLY reference, not a family hypothesis to pursue. The exploit-LIBRARY
    # hint already filters by module (build_exploit_library_hint); the system
    # prompts didn't — this closes that asymmetry. pwn stays byte-identical.
    module = ""
    try:
        module = (read_meta(job_id).get("module") or "").lower()
    except Exception:
        pass
    if agent_type in ("recon", "debugger") and module and module != "pwn":
        prompt = (
            f"MODULE SCOPE — this is a `{module}` job, NOT pwn. The exploit-"
            "mitigation framing in the guidance below (one_gadget / FSOP / "
            "safe-linking / tcache-poison / House-of-* / hooks / heap-spray / "
            "ROP-to-RCE) is PWN-ONLY. Do NOT assume memory corruption, do NOT "
            "pre-commit an exploitation plan, and do NOT classify the challenge "
            "family as heap-pwn unless EXECUTED evidence (a real free/realloc + "
            "a reachable metadata write, or a UAF/overflow you actually "
            "demonstrated) proves it. Use heap / allocator / libc knowledge "
            "ONLY to UNDERSTAND data structures and RECOVER data (custom "
            "allocators, tries, object layouts, serialization). Classify the "
            "challenge family from disassembly / source evidence, never from "
            "the technique vocabulary below.\n\n"
        ) + prompt

    # ENV SCOPE for the non-pwn DEBUGGER: the debugger prompt asserts the pwn
    # autoboot already ran chal-libc-fix (./.chal-libs staged, libc_profile.json
    # emitted, "do NOT re-run"). That is FALSE for rev/web/crypto/etc. — correct
    # the premise so the debugger doesn't trust a bootstrap that never happened.
    if agent_type == "debugger" and module and module != "pwn":
        prompt = (
            f"ENV SCOPE — this is a `{module}` job: `chal-libc-fix` was NOT "
            "auto-run for you (it runs only in the pwn autoboot). So any claim "
            "below that the environment is already bootstrapped — `./.chal-libs/` "
            "staged, `libc_profile.json` emitted, 'chal-libc-fix already ran / do "
            "NOT re-run' — is PWN-ONLY and does NOT describe your environment. If "
            "you actually need a patched binary or staged libs, set them up "
            "yourself; otherwise ignore that framing.\n\n"
        ) + prompt

    # Module-specialized web-research reframe for recon (pwn → no-op, stays
    # byte-identical). Appended so it directly follows / overrides the
    # pwn-flavored "Web research — ENABLED" examples in the base prompt.
    if agent_type == "recon":
        _wr = _recon_web_research_addendum(module)
        if _wr:
            prompt = prompt + "\n\n" + _wr

    tools = list(_AGENT_TOOLS_BY_TYPE[agent_type])
    # Base = existing behavior: judge pinned to LATEST_JUDGE_MODEL, everyone
    # else follows the spawner (main). An active model-preset can override the
    # role (recon / debugger / triage / judge); a blank entry keeps the base.
    from modules.agent_provider import provider_for_job
    from modules.model_presets import resolve_role_model
    _base_sub_model = (
        LATEST_JUDGE_MODEL if agent_type == "judge"
        else (model or LATEST_JUDGE_MODEL)
    )
    sub_model = resolve_role_model(
        agent_type, _base_sub_model, provider_for_job(job_id)
    )
    env = agent_job_env(job_id, agent_type, work_dir, extra_env)
    # Defense-in-depth: strip argv-fatal control bytes from the system
    # prompt before it crosses the SDK → claude CLI argv boundary. An
    # accidental `\0` in a Python string literal anywhere in the prompt
    # text would otherwise crash subprocess.Popen at spawn time. Audit
    # any stripping into the job's run.log so the cause is traceable.
    safe_prompt = sanitize_for_argv(
        prompt, label=f"{agent_type}-options",
        log_fn=lambda s: log_line(job_id, s),
    )
    return ClaudeAgentOptions(
        system_prompt=safe_prompt,
        model=sub_model,
        cwd=str(work_dir),
        allowed_tools=tools,
        permission_mode="bypassPermissions",
        env=env,
        hooks=kill_guard_hooks(job_id),
    )


PRE_RECON_CACHE_FILENAME = "pre_recon_reply.txt"

# Bump this whenever `_build_pre_recon_prompt` adds, removes, or reshapes
# a mandatory section. A bump invalidates every previously-cached reply
# on next /retry — the old recon was generated against a prompt that
# didn't ask for the new sections (e.g. the v2 bump on 2026-05-20 added
# HEAP STATE MATRIX, ENV-AWARE PATHS, and RCE TARGET TABLE; pre-v2
# replies don't fill those, so feeding them to main would silently
# bypass the new guardrails). Keep this as a short string; only the
# equality check matters.
PRE_RECON_CACHE_SCHEMA = "v7"
_PRE_RECON_HEADER_PREFIX = "## pre_recon_cache_schema "


def _pre_recon_cache_path(work_dir) -> Path:
    return Path(work_dir) / PRE_RECON_CACHE_FILENAME


def load_cached_pre_recon(work_dir, log_fn, *, retry_of: str | None = None) -> str:
    """Return the pre-recon reply cached by a prior run, or '' if absent.

    /retry + /resume copy ``prev_jd/work`` → ``new_jd/work`` (see
    ``api/routes/retry.py:_resubmit``), so when this returns non-empty
    the binary has not changed since the prior static triage and the
    spawn can be skipped — saving ~$0.50 and 2–6 min of pre-recon
    subagent wall time per retry.

    Schema gate: the first line carries ``PRE_RECON_CACHE_SCHEMA``. When
    the schema bumps (because the prompt itself grew new mandatory
    sections), legacy caches are invalidated so /retry actually
    exercises the new prompt. Without this gate a /retry on a job whose
    prior recon predates the prompt change would silently feed main the
    stale reply and bypass the new guardrails entirely.

    Retry gate: when ``retry_of`` is set the cache is bypassed
    unconditionally. Rationale: retries inherit the prior job's
    pre_recon_reply.txt under the same schema version, so a cache hit
    would feed the new agent the SAME static-triage that the prior
    agent already failed against. Re-spawning lets the (possibly
    updated) prompt + a fresh recon turn re-evaluate the chal in light
    of whatever new system guardrails landed since the original run.
    Cost: ~$0.50 + 2–6 min extra per retry — cheap vs. a $15+ retry
    that re-reasons against stale assumptions (observed on job
    de15654c8f39, May 2026).
    """
    if retry_of:
        log_fn(
            f"[pre-recon] retry of {retry_of} — bypassing cache so "
            f"the current prompt schema actually runs against this chal"
        )
        return ""
    p = _pre_recon_cache_path(work_dir)
    if not p.is_file():
        return ""
    try:
        text = p.read_text(errors="ignore")
    except OSError:
        return ""

    first_line, _, body = text.partition("\n")
    if first_line.startswith(_PRE_RECON_HEADER_PREFIX):
        cached_ver = first_line[len(_PRE_RECON_HEADER_PREFIX):].strip()
        if cached_ver != PRE_RECON_CACHE_SCHEMA:
            log_fn(
                f"[pre-recon] cache schema mismatch "
                f"(cached={cached_ver!r}, current="
                f"{PRE_RECON_CACHE_SCHEMA!r}) — respawning so the new "
                f"prompt sections are actually filled"
            )
            return ""
        text = body
    else:
        # No header → pre-v2 cache (Tier 1 retrofit boundary). Skip so
        # /retry runs against the current prompt shape with STATE
        # MATRIX / ENV-AWARE / RCE TABLE asked of recon.
        log_fn(
            "[pre-recon] legacy cache without schema header — "
            "respawning to pick up new prompt sections"
        )
        return ""

    text = text.strip()
    if text:
        log_fn(
            f"[pre-recon] using cached reply from prior run "
            f"({len(text)} chars, schema={PRE_RECON_CACHE_SCHEMA}) — "
            f"skipping spawn"
        )
    return text


def store_pre_recon_cache(work_dir, reply: str, log_fn) -> None:
    """Persist the pre-recon reply for future /retry + /resume.

    The first line carries ``PRE_RECON_CACHE_SCHEMA`` so future loads
    can detect prompt-shape changes and invalidate stale replies.
    Best-effort: a failure here only costs a future cache miss, not
    the current run. Empty replies are skipped so a known-bad recon
    doesn't poison the cache.
    """
    if not reply or not reply.strip():
        return
    p = _pre_recon_cache_path(work_dir)
    try:
        p.write_text(
            f"{_PRE_RECON_HEADER_PREFIX}{PRE_RECON_CACHE_SCHEMA}\n"
            f"{reply}"
        )
    except OSError as e:
        log_fn(f"[pre-recon] cache write failed: {e}")


# Schemas live next to the validator so the prompt and the check stay
# in lockstep. Update REQUIRED_TOP / vulns / chain in validate_findings()
# when you change the pwn template. Web/crypto/rev schemas are domain-
# specific shapes — they don't share validate_findings()'s checks
# (which assume heap-pwn vocabulary like primitive_quality + glibc).
_FINDINGS_SCHEMA_FOR_REPORT_PROMPT = """\
{
  "schema_version": 1,
  "chal_name": "<from description or filename>",
  "glibc_version": "<2.39 | null>",
  "arch": "x86_64 | aarch64 | arm | i386",
  "mitigations": {
    "canary": true|false,
    "nx": true|false,
    "pie": true|false,
    "relro": "full | partial | none | null"
  },
  "vulns": [
    {
      "id": "V-01",
      "bug_class": "heap-overflow | uaf | double-free | fmt-string | bof | int-overflow | oob-read | oob-write | logic | …",
      "file": "<decomp filename or binary symbol>",
      "line": <int or null>,
      "trigger": "<one paragraph: how attacker reaches it>",
      "primitive_class": "AAW | RCE | UAF | AAR | partial-write | info-leak | dos",
      "primitive_quality": "HIGH | MED | LOW"
    }
  ],
  "chain": {
    "technique_name": "tcache_poison | house_of_tangerine | house_of_water | ret2libc | rop | fsop_wfile | …",
    "how2heap_file": "/opt/how2heap/glibc_<VER>/<name>.c | null",
    "steps": ["<ordered one-line steps>"],
    "one_gadget_offset": "0x… | null",
    "expected_observable": "<what you expect on stdout if it works>"
  },
  "exploit_status": "drafted | tested-failed | tested-partial | flag-captured | aborted",
  "caveats": ["<remote-untested | aslr-unstable | requires-N-attempts | …>"]
}"""


REPORT_SCHEMA_WEB = """\
{
  "schema_version": 1,
  "chal_name": "<from description or filename>",
  "stack": "<framework + language + DB — e.g. 'Flask + SQLAlchemy + SQLite'>",
  "vulns": [
    {
      "id": "V-01",
      "bug_class": "sqli | xss | ssrf | rce | lfi | rfi | deserialization | jwt-misuse | path-traversal | command-injection | auth-bypass | idor | xxe | csrf | logic | …",
      "route": "<METHOD /path — e.g. 'POST /api/login'>",
      "file": "<source file>",
      "line": <int or null>,
      "sink": "<unsafe call / pattern — e.g. 'subprocess.run(shell=True)'>",
      "trigger": "<one paragraph: how attacker reaches it (auth required? prerequisites?)>",
      "primitive_quality": "HIGH | MED | LOW"
    }
  ],
  "chain": {
    "technique_name": "blind-sqli-time | union-sqli | sstemplate-injection | pickle-rce | jwt-none | …",
    "steps": ["<ordered one-line steps>"],
    "expected_observable": "<flag location — e.g. '/flag.txt via LFI; cat through SQLi subquery'>"
  },
  "exploit_status": "drafted | tested-failed | tested-partial | flag-captured | aborted",
  "caveats": ["<auth-required | remote-untested | rate-limited | …>"]
}"""


REPORT_SCHEMA_WEB3 = """\
{
  "schema_version": 1,
  "chal_name": "<from description or filename>",
  "chain_env": "local-anvil | anvil-fork | remote-rpc",
  "contracts": [
    {
      "name": "<contract name>",
      "file": "<source file>",
      "address": "<deployed address, or null if not deployed yet>",
      "role": "<setup | target | token | helper — what it is FOR>"
    }
  ],
  "vulns": [
    {
      "id": "V-01",
      "bug_class": "reentrancy | access-control | unchecked-return | delegatecall | selfdestruct-force-send | tx-origin-auth | integer-overflow | price-oracle-manipulation | flashloan | signature-replay | uninitialized-proxy | storage-collision | weak-randomness | front-running | precision-loss | logic | …",
      "contract": "<contract name>",
      "function": "<function signature — e.g. 'withdraw()'>",
      "file": "<source file>",
      "line": <int or null>,
      "why": "<one paragraph: the state or check that is wrong, and why the EVM lets you abuse it>",
      "primitive_quality": "HIGH | MED | LOW"
    }
  ],
  "chain": {
    "technique_name": "reentrancy-drain | delegatecall-takeover | oracle-manipulation | proxy-init-race | …",
    "steps": ["<ordered one-line steps, each an on-chain action>"],
    "win_condition": "<the exact predicate the challenge checks — e.g. 'Setup.isSolved() returns true' or 'target balance == 0'>",
    "expected_observable": "<how you will SEE it: the isSolved() call returning true, the flag the remote handout prints, …>"
  },
  "exploit_status": "drafted | tested-failed | tested-partial | local-solved | flag-captured | aborted",
  "_exploit_status_note": "local-solved = the predicate flipped on YOUR anvil and there was no flag to take. flag-captured = you hold the actual flag string from the remote instance. They are different claims; picking the second for a local run overstates what happened.",
  "caveats": ["<local-only | remote-untested | needs-funded-key | gas-bound | …>"]
}"""


REPORT_SCHEMA_CRYPTO = """\
{
  "schema_version": 1,
  "chal_name": "<from description or filename>",
  "cipher": "<primitive — e.g. 'RSA-OAEP', 'AES-CBC', 'ECDSA-secp256k1', 'custom-LFSR'>",
  "parameters": {
    "key_bits": <int or null>,
    "iv_reuse": true|false|null,
    "padding": "<pkcs1v15 | oaep | pkcs7 | none | null>",
    "extra": "<any other public params — short string or null>"
  },
  "vulns": [
    {
      "id": "V-01",
      "attack_class": "small-e | common-modulus | partial-key | padding-oracle | lattice-LLL | coppersmith | NTRU | LWE | nonce-reuse | weak-PRNG | malleability | side-channel | …",
      "file": "<source/notes file>",
      "line": <int or null>,
      "trigger": "<what condition makes this exploitable>",
      "primitive_quality": "HIGH | MED | LOW"
    }
  ],
  "chain": {
    "technique_name": "<canonical attack name — e.g. 'Coppersmith partial-p', 'CCA2 padding oracle'>",
    "uses_sage": true|false,
    "libs": ["<pycryptodome | gmpy2 | sympy | z3 | sagemath | …>"],
    "steps": ["<ordered one-line steps>"],
    "expected_observable": "<recovered plaintext / private key / decrypted flag>"
  },
  "exploit_status": "drafted | tested-failed | tested-partial | flag-captured | aborted",
  "caveats": ["<requires-sage | LLL-runtime-unknown | offline-only | …>"]
}"""


REPORT_SCHEMA_REV = """\
{
  "schema_version": 1,
  "chal_name": "<from description or filename>",
  "arch": "x86_64 | aarch64 | arm | i386 | wasm | jvm | dotnet | go | …",
  "language": "C | C++ | Go | Rust | .NET | Java | Python-packed | …",
  "protections": {
    "packed": true|false|null,
    "stripped": true|false|null,
    "anti_debug": true|false|null
  },
  "flag_path": "<one paragraph: where the flag is constructed/printed/checked — file:addr>",
  "key_facts": [
    {
      "id": "K-01",
      "fact_class": "constant | algorithm | check-routine | obfuscation | side-channel | …",
      "file": "<decomp file or addr>",
      "line": <int or null>,
      "description": "<what this fact tells the solver — e.g. 'XOR key 0xC0FFEE at .rodata:0x4080'>"
    }
  ],
  "solver_strategy": {
    "approach": "static-emit | brute-force | constraint-solver | dynamic-trace | hash-reverse | symbolic-exec | unpack-first | …",
    "libs": ["<pwntools | z3 | angr | unicorn | …>"],
    "steps": ["<ordered one-line steps>"],
    "expected_observable": "<printed flag / accepted serial / cracked password>"
  },
  "exploit_status": "drafted | tested-failed | tested-partial | flag-captured | aborted",
  "caveats": ["<obfuscation-residual | timing-sensitive | …>"]
}"""


REPORT_PHASE_MODEL = "claude-sonnet-4-6"


async def run_report_phase(
    *,
    job_id: str,
    work_dir,
    model: str | None = None,
    log_fn,
    chal_name_hint: str = "",
    schema_text: str | None = None,
    timeout_s: int = 300,
) -> bool:
    """Run the terminal REPORT phase: convert ./report.md + ./exploit.py +
    ./THREAT_MODEL.md (whichever exist) into a strict-schema findings.json.

    Mirrors the cookbook's "report" phase pattern (stateless ``query()``,
    no tools, no MCP server, pure JSON transformation). The whole point
    is to keep the schema OUT of main's system_prompt — main focuses on
    exploitation, this phase converts artifacts to structured data.

    Hook order: after main finishes writing ./report.md + ./exploit.py,
    BEFORE sandbox / postjudge / artifact carry. Idempotent: re-runs
    overwrite the prior findings.json (so a retry that re-runs main also
    re-runs this).

    ``model`` defaults to ``REPORT_PHASE_MODEL`` (sonnet) — the
    transformation is rote pattern-matching, not chain reasoning, so
    paying for opus here is waste. Callers can override when their
    schema needs heavier reasoning (e.g. multi-vuln deduplication).

    ``schema_text`` lets each module supply its own JSON shape. None
    falls back to the pwn schema (the most-used path historically).

    Best-effort: any failure (SDK import, timeout, malformed JSON) is
    logged and swallowed. Downstream ``validate_findings`` already
    tolerates missing/empty files; UI has no readers.
    """
    report_md = work_dir / "report.md"
    exploit_py = work_dir / "exploit.py"
    solver_py = work_dir / "solver.py"
    threat_md = work_dir / "THREAT_MODEL.md"

    sources: list[tuple[str, Path]] = []
    if report_md.is_file():
        sources.append(("report.md", report_md))
    if exploit_py.is_file():
        sources.append(("exploit.py", exploit_py))
    elif solver_py.is_file():
        sources.append(("solver.py", solver_py))
    if threat_md.is_file():
        sources.append(("THREAT_MODEL.md", threat_md))

    if not sources:
        log_fn("[report] no source artifacts (report.md / exploit.py) — skipping")
        return False

    parts: list[str] = []
    # Cap each source at 16 KB to keep the report prompt cheap. Most
    # report.md files are 2-8 KB; exploit.py 4-12 KB. The schema only
    # needs facts (mitigations, primitive class, technique name) that
    # live in the first ~half.
    for name, p in sources:
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        if len(text) > 16_384:
            text = text[:16_384] + "\n# ... (truncated)\n"
        parts.append(f"==== {name} ====\n{text}\n")

    sources_blob = "\n".join(parts)
    chal_hint = f"\nChal name hint: {chal_name_hint}\n" if chal_name_hint else ""
    effective_schema = schema_text or _FINDINGS_SCHEMA_FOR_REPORT_PROMPT

    report_prompt = (
        "Convert the artifacts below into strict JSON conforming to the "
        "schema. Every field is REQUIRED — use null for not-applicable, "
        "never omit a key. Respond with JSON ONLY: no surrounding prose, "
        "no markdown fences, no commentary.\n\n"
        f"{chal_hint}"
        "## Schema\n\n"
        f"{effective_schema}\n\n"
        "## Source artifacts (main agent's output)\n\n"
        f"{sources_blob}"
    )

    # Keep the system_prompt minimal — cookbook's report phase ships
    # only the engagement_context and the schema itself. NO mission_block,
    # NO per-module SYSTEM_PROMPT, NO tool catalog.
    sys_prompt = sanitize_for_argv(
        CTF_PREAMBLE + "\nROLE: post-run REPORT phase. Pure JSON transformation. "
        "You have no tools — write JSON as your final text only.",
        label="report-options", log_fn=log_fn,
    )

    from modules.agent_provider import (
        coerce_model_for_provider, default_model_for, provider_for_job,
    )
    from modules.model_presets import resolve_role_model

    provider = provider_for_job(job_id)
    report_model = resolve_role_model(
        "report", model or REPORT_PHASE_MODEL, provider
    )
    report_model = coerce_model_for_provider(report_model, provider)
    if provider == "grok" and (
        not report_model
        or str(report_model).lower().startswith("claude")
        or str(report_model).lower().startswith("anthropic")
    ):
        report_model = default_model_for("grok")

    # ---- Grok path: avoid Claude weekly-limit failures on Grok jobs -------
    if provider == "grok":
        from modules.grok_acp import query_grok_once
        log_fn(
            f"[report] launching report phase via Grok (model={report_model}, "
            f"sources={[n for n, _ in sources]})"
        )
        try:
            r = await query_grok_once(
                prompt=report_prompt,
                cwd=str(work_dir),
                system_prompt=sys_prompt,
                model=report_model,
                effort="low",
                timeout_s=float(timeout_s),
            )
        except Exception as e:
            log_fn(f"[report] Grok report phase failed ({e}); skipping")
            return False
        if r.get("error"):
            log_fn(f"[report] Grok error: {r['error']}; skipping")
            return False
        accumulated = (r.get("text") or "").strip()
        # fall through to shared JSON extract / write below
    elif provider == "gpt":
        from modules.gpt_agent import query_gpt_once
        log_fn(
            f"[report] launching report phase via OpenAI Codex/GPT "
            f"(model={report_model}, sources={[n for n, _ in sources]})"
        )
        try:
            r = await query_gpt_once(
                prompt=report_prompt,
                cwd=str(work_dir),
                system_prompt=sys_prompt,
                model=report_model,
                effort="low",
                timeout_s=float(timeout_s),
                enable_tools=False,
            )
        except Exception as e:
            log_fn(f"[report] GPT report phase failed ({e}); skipping")
            return False
        if r.get("error"):
            log_fn(f"[report] GPT error: {r['error']}; skipping")
            return False
        accumulated = (r.get("text") or "").strip()
    else:
        try:
            from claude_agent_sdk import ClaudeAgentOptions, query
        except Exception as e:
            log_fn(f"[report] SDK import failed ({e}); skipping report phase")
            return False

        options = ClaudeAgentOptions(
            system_prompt=sys_prompt,
            # Active model-preset pins the report role; when unset it falls through
            # to the caller's model (the analyzers pass main's per-job model here,
            # so report follows main) or REPORT_PHASE_MODEL if neither is given.
            # NB: the preset must win OVER the caller's model — the analyzers always
            # pass model=<main>, so `model or resolve(...)` would never consult it.
            model=report_model,
            cwd=str(work_dir),
            allowed_tools=[],
            disallowed_tools=["Agent", "Task", "WebSearch", "WebFetch", "Bash",
                              "Read", "Write", "Edit", "Glob", "Grep"],
            permission_mode="bypassPermissions",
        )

        log_fn(f"[report] launching report phase (model={options.model}, "
               f"sources={[n for n, _ in sources]})")

        accumulated = ""
        try:
            import anyio
            with anyio.fail_after(timeout_s):
                async for msg in query(prompt=report_prompt, options=options):
                    phase_heartbeat(job_id, "report", msg)
                    cls = type(msg).__name__
                    if cls == "AssistantMessage":
                        for block in getattr(msg, "content", []) or []:
                            if type(block).__name__ == "TextBlock":
                                accumulated += getattr(block, "text", "") or ""
                    elif cls == "ResultMessage":
                        if getattr(msg, "is_error", False):
                            log_fn(
                                f"[report] SDK ResultMessage error: "
                                f"{getattr(msg, 'result', '')[:200]}"
                            )
                            return False
        except TimeoutError:
            log_fn(
                f"[report] timed out after {timeout_s}s — keeping any prior "
                f"findings.json untouched"
            )
            return False
        except Exception as e:
            log_fn(f"[report] phase crashed: {type(e).__name__}: {e}")
            kind = classify_agent_error(f"{type(e).__name__}: {e}")
            if kind == "cli_infra_error":
                log_fn(
                    "[report] INFRA: claude CLI spawn failed (likely worker glibc "
                    "pollution from in-run lib/ld manipulation) — this no_flag is "
                    "an infrastructure cascade, not a clean miss"
                )
                try:
                    write_meta(
                        job_id, report_phase_error=f"{kind}: {str(e)[:200]}"
                    )
                except Exception:
                    pass
            return False

    raw = accumulated.strip()
    if not raw:
        log_fn("[report] empty response from report phase")
        return False

    # Strip code fences if the model emitted them despite instructions
    if raw.startswith("```"):
        # ```json\n{...}\n```  or  ```\n{...}\n```
        body = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
        if body.endswith("```"):
            body = body[:-3]
        raw = body.strip()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        log_fn(f"[report] response is not valid JSON ({e}); keeping any "
               f"prior findings.json")
        return False

    out = work_dir / "findings.json"
    try:
        out.write_text(json.dumps(parsed, indent=2))
    except OSError as e:
        log_fn(f"[report] write failed: {e}")
        return False

    log_fn(f"[report] findings.json written ({out.stat().st_size} B)")
    return True


# Ceiling on the pre-recon reply that gets prepended to main's user_prompt.
# Sized from MEASURED output, not taste: heap-pwn recon emits ~18-19.5 KB when
# it answers every section the prompt demands, so 32 KB leaves real headroom
# while still bounding a runaway. ~8 K tokens of opus input (~$0.04), paid once
# and cached — against ~$1.20 + ~5 min for each respawn the old 8 KB cap
# provoked. This is a runaway guard, NOT a cost control.
PRE_RECON_MAX_CHARS = 32000


class PreReconReply(str):
    """The reply that reaches main, carrying the PRE-CLIP original.

    A str subclass rather than a tuple return: run_pre_recon has five callers
    (web / pwn x2 / rev / crypto) and only ONE of them — pwn's mandatory-section
    gate — needs the original, so widening the signature would churn four call
    sites for nothing. Every existing caller keeps treating this as the string
    it always was.

    Read `.full` BEFORE any string operation: `.strip()` and friends return a
    plain str and drop the attribute. `getattr(reply, "full", reply)` is the
    safe access and degrades to the clipped text if it ever isn't one of these.
    """

    __slots__ = ("full",)

    def __new__(cls, clipped: str, full: str):
        obj = super().__new__(cls, clipped)
        obj.full = full
        return obj


def _elide_preserving(out: str, cap: int, keep: tuple[str, ...],
                      log_fn, tag: str) -> str:
    """Clip `out` to ~`cap`, cutting from the gaps BETWEEN `keep` titles.

    The blind head-70%/tail-30% cut this replaces destroys whatever sits in the
    middle, and on job 71edd90398f4 that was `ENV-AWARE PATHS` — one of the
    four titles pwn's gate requires. Cutting around the titles keeps the
    sections main is supposed to receive.

    Falls back to the plain middle cut when the protected titles alone leave no
    droppable gap big enough. That is survivable now only because the caller
    also carries the pre-clip text: the gate reads THAT, so a fallback costs
    main some content but no longer provokes a respawn loop.
    """
    need = len(out) - cap
    if need <= 0:
        return out

    # Protect the title itself plus a little following context, so a cut never
    # starts immediately after a heading and swallows its first line.
    _CTX = 200
    prot: list[tuple[int, int]] = []
    for t in keep:
        start = 0
        while True:
            i = out.find(t, start)
            if i < 0:
                break
            prot.append((i, min(len(out), i + len(t) + _CTX)))
            start = i + 1
    prot.sort()
    merged: list[tuple[int, int]] = []
    for a, z in prot:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], z))
        else:
            merged.append((a, z))

    # Gaps = everything not protected. Keep a head so ARCH/PROTECTIONS/LIBC
    # survive even when no title appears early.
    head_reserve = min(4000, len(out) // 4)
    gaps: list[tuple[int, int]] = []
    cursor = head_reserve
    for a, z in merged:
        if a > cursor:
            gaps.append((cursor, a))
        cursor = max(cursor, z)
    if cursor < len(out):
        gaps.append((cursor, len(out)))

    gaps.sort(key=lambda g: g[1] - g[0], reverse=True)
    cuts: list[tuple[int, int]] = []
    freed = 0
    for a, z in gaps:
        if freed >= need:
            break
        take = min(z - a, need - freed)
        if take <= 0:
            continue
        cuts.append((a, a + take))
        freed += take

    if freed < need:
        # The mandatory sections alone overflow the budget. Keep the historic
        # behaviour rather than inventing a worse one; the gate is protected by
        # the pre-clip text either way.
        head = out[: int(cap * 0.7)]
        tail = out[-(cap - len(head)):]
        dropped = len(out) - len(head) - len(tail)
        log_fn(
            f"[{tag}] reply was {len(out)} chars — could not elide {need} "
            f"chars without cutting a mandatory section; fell back to a middle "
            f"cut and dropped {dropped}. The section gate reads the PRE-CLIP "
            f"text, so this will not trigger a respawn."
        )
        return (head + f"\n\n…({dropped} chars elided from the MIDDLE to fit "
                f"the {cap // 1000} KB pre-recon budget)…\n\n" + tail)

    cuts.sort()
    pieces: list[str] = []
    prev = 0
    for a, z in cuts:
        pieces.append(out[prev:a])
        pieces.append(f"\n\n…({z - a} chars elided here to fit the "
                      f"{cap // 1000} KB pre-recon budget; mandatory sections "
                      f"kept intact)…\n\n")
        prev = z
    pieces.append(out[prev:])
    log_fn(
        f"[{tag}] reply was {len(out)} chars — elided {freed} chars from "
        f"{len(cuts)} gap(s) BETWEEN mandatory sections to fit the "
        f"{cap // 1000} KB budget (all {len(keep)} section titles kept)"
    )
    return "".join(pieces)


async def run_pre_recon(
    *,
    job_id: str,
    work_dir,
    model: str | None,
    prompt: str,
    log_fn,
    tag: str = "pre-recon",
    keep_sections: tuple[str, ...] = (),
) -> str:
    """Run a recon subagent BEFORE main's first turn so main starts with
    the static-analysis summary already in its user_prompt. Eliminates
    main's "should I delegate?" decision (which is consistently mis-made
    in favor of direct Bash analysis, bloating main's cache_read).

    Backend follows Settings ``agent_provider``:
      * claude — standalone ``ClaudeSDKClient`` (historical path)
      * grok   — standalone ``GrokACPClient`` (avoids burning Claude quota
        / weekly limits when the job itself is on Grok)
      * gpt    — Codex CLI OAuth by default (Responses API is optional)

    Returns ONLY recon's final text (joined assistant TextBlocks), capped
    at 8 KB. Best-effort: crashes return partial/empty text; caller falls
    back to "main delegates as needed".
    """
    from modules.agent_provider import (
        active_provider,
        default_model_for,
        provider_display_name,
    )

    chunks: list[str] = []
    crashed = False
    result_is_error = False
    provider = active_provider()

    # ---- OpenAI GPT path --------------------------------------------------
    if provider == "gpt":
        try:
            from modules.gpt_agent import (
                GptAgentClient,
                GptSessionOptions,
                AssistantMessage as GptAssistantMessage,
                ResultMessage as GptResultMessage,
            )
        except Exception as e:
            log_fn(f"[{tag}] GPT adapter import failed ({e}); skipping pre-recon")
            return ""
        gpt_model = (model or "").strip()
        if not gpt_model or gpt_model.lower().startswith(("claude", "grok")):
            gpt_model = default_model_for("gpt")
        # GPT has its own provider-scoped preset bucket.  Pre-recon used to
        # bypass its ``recon`` slot and always inherit main's model, which is
        # why job 0e215989d8dc launched pre-recon on gpt-5.6-sol even though
        # the active GPT preset pins recon to gpt-5.6-terra.  Keep this inside
        # the GPT branch so Claude/Grok resolution is unchanged.
        from modules.model_presets import resolve_role_model
        gpt_model = resolve_role_model("recon", gpt_model, "gpt")
        log_fn(f"[{tag}] backend={provider_display_name('gpt')} model={gpt_model}")
        opts = GptSessionOptions(
            system_prompt=RECON_AGENT_PROMPT,
            model=gpt_model,
            cwd=str(work_dir),
            effort=None,
            env=agent_job_env(job_id, "recon", work_dir),
            enable_tools=True,
            enable_subagents=False,
        )
        try:
            async with GptAgentClient(opts) as client:
                await client.query(prompt)
                async for msg in client.receive_response():
                    phase_heartbeat(job_id, "pre-recon", msg)
                    if isinstance(msg, GptAssistantMessage):
                        for block in (getattr(msg, "content", None) or []):
                            kind = type(block).__name__
                            if kind == "TextBlock":
                                txt = getattr(block, "text", "") or ""
                                if txt.strip():
                                    chunks.append(txt)
                                    log_line(job_id, f"[{tag}] AGENT: {txt[:500]}")
                            elif kind == "ToolUseBlock":
                                log_line(job_id, f"[{tag}] TOOL {getattr(block, 'name', '?')}")
                    elif isinstance(msg, GptResultMessage):
                        result_is_error = bool(getattr(msg, "is_error", False))
        except Exception as e:
            crashed = True
            log_fn(f"[{tag}] crashed: {e!r} — returning partial output")

    # ---- Grok path --------------------------------------------------------
    elif provider == "grok":
        try:
            from modules.grok_acp import (
                GrokACPClient,
                GrokSessionOptions,
                AssistantMessage as GrokAssistantMessage,
                ResultMessage as GrokResultMessage,
                ToolUseBlock as GrokToolUseBlock,
            )
        except Exception as e:
            log_fn(f"[{tag}] Grok ACP import failed ({e}); skipping pre-recon")
            return ""
        # Reuse recon system prompt from the standalone options builder.
        try:
            claude_opts = make_standalone_options("recon", model, work_dir, job_id)
            recon_system = getattr(claude_opts, "system_prompt", "") or ""
        except Exception:
            recon_system = (
                "You are a read-only recon agent. Investigate the challenge "
                "statically and return a concise summary (≤2 KB)."
            )
        grok_model = (model or "").strip()
        if not grok_model or grok_model.lower().startswith("claude"):
            grok_model = default_model_for("grok")
        log_fn(f"[{tag}] backend=Grok model={grok_model}")
        opts = GrokSessionOptions(
            system_prompt=recon_system,
            model=grok_model,
            cwd=str(work_dir),
            effort=None,
            env=agent_job_env(job_id, "recon", work_dir),
        )
        try:
            async with GrokACPClient(opts) as client:
                await client.query(prompt)
                async for msg in client.receive_response():
                    phase_heartbeat(job_id, "pre-recon", msg)
                    if isinstance(msg, GrokAssistantMessage):
                        for block in (getattr(msg, "content", None) or []):
                            if type(block).__name__ == "TextBlock":
                                txt = getattr(block, "text", "") or ""
                                if txt.strip():
                                    chunks.append(txt)
                                    log_line(
                                        job_id,
                                        f"[{tag}] AGENT: {txt[:500]}",
                                    )
                            elif type(block).__name__ == "ToolUseBlock":
                                nm = getattr(block, "name", "?")
                                inp = getattr(block, "input", None) or {}
                                try:
                                    preview = json.dumps(inp)[:200]
                                except Exception:
                                    preview = str(inp)[:200]
                                log_line(
                                    job_id,
                                    f"[{tag}] TOOL {nm}: {preview}",
                                )
                    elif isinstance(msg, GrokResultMessage):
                        result_is_error = bool(getattr(msg, "is_error", False))
        except Exception as e:
            crashed = True
            log_fn(f"[{tag}] crashed: {e!r} — returning partial output")
        # fall through to shared post-processing below
    else:
        # ---- Claude path --------------------------------------------------
        try:
            from claude_agent_sdk import (
                AssistantMessage,
                ClaudeSDKClient,
                ResultMessage,
                UserMessage,
            )
        except Exception as e:
            log_fn(f"[{tag}] SDK import failed ({e}); skipping pre-recon")
            return ""

        options = make_standalone_options(
            "recon", model, work_dir, job_id,
        )
        try:
            async with ClaudeSDKClient(options=options) as client:
                await client.query(prompt)
                async for msg in client.receive_response():
                    phase_heartbeat(job_id, "pre-recon", msg)
                    if isinstance(msg, AssistantMessage):
                        for block in (getattr(msg, "content", None) or []):
                            if type(block).__name__ == "TextBlock":
                                txt = getattr(block, "text", "") or ""
                                if txt.strip():
                                    chunks.append(txt)
                                    log_line(
                                        job_id,
                                        f"[{tag}] AGENT: {txt[:500]}",
                                    )
                            elif type(block).__name__ == "ToolUseBlock":
                                nm = getattr(block, "name", "?")
                                inp = getattr(block, "input", None) or {}
                                try:
                                    preview = json.dumps(inp)[:200]
                                except Exception:
                                    preview = str(inp)[:200]
                                log_line(
                                    job_id,
                                    f"[{tag}] TOOL {nm}: {preview}",
                                )
                    elif isinstance(msg, UserMessage):
                        # Tool RESULTS arrive as UserMessage/ToolResultBlock.
                        # This branch did not exist, so pre-recon logged every
                        # command it ran and not one of their outputs — job
                        # 62531f9da538 counted 18 TOOL calls and 0 TOOL_RESULT
                        # for this phase (main 46/772, the recon subagent
                        # 21/21). The cost is not cosmetic: pre-recon runs a
                        # job's FIRST dynamic probes, so when one silently
                        # returns nothing there is no way afterwards to tell
                        # "the tool failed" from "it worked and the agent moved
                        # on" — exactly the question a post-mortem asks. Same
                        # formatter the isolated subagents use, so the 200 KB
                        # disaster valve applies and a huge objdump cannot
                        # flood run.log.
                        for block in (getattr(msg, "content", None) or []):
                            if type(block).__name__ != "ToolResultBlock":
                                continue
                            try:
                                line = format_tool_result(
                                    getattr(block, "content", None),
                                    bool(getattr(block, "is_error", False)),
                                )
                            except Exception:
                                continue
                            log_line(job_id, f"[{tag}] {line}")
                    elif isinstance(msg, ResultMessage):
                        result_is_error = bool(getattr(msg, "is_error", False))
                        cost = getattr(msg, "total_cost_usd", None)
                        if isinstance(cost, (int, float)) and cost:
                            log_fn(f"[{tag}] cost: ${cost:.4f}")
        except Exception as e:
            crashed = True
            log_fn(f"[{tag}] crashed: {e!r} — returning partial output")

    out = "".join(chunks).strip()
    if not out:
        return ""
    # A hard API error / policy refusal comes back as assistant text that
    # IS the error — the bundled `claude` CLI surfaces an AUP block as an
    # AssistantMessage TextBlock ("API Error: … violates our Usage Policy")
    # rather than a clean exception — or as a ResultMessage is_error=True.
    # Returning that text would LAUNDER a refusal into main's user_prompt
    # inside `==== RECON REPLY ====` as if it were legitimate recon output,
    # and store_pre_recon_cache would persist it for a later /resume. Job
    # d8989cc6a8d1 (a benign Byte-Caesar chal): the pre-recon AUP string
    # got injected + cached, and main itself AUP-blocked 10s later — the
    # laundered refusal is a plausible contamination vector. Treat it as a
    # failed recon → "" so the caller's `if recon_reply:` skips injection
    # and store_pre_recon_cache skips the empty reply; main then falls back
    # to its own delegate-as-needed flow with a clean context.
    # is_error is the authoritative signal. The text-match is a fallback for
    # when the CLI surfaces AUP as assistant text WITHOUT setting is_error;
    # bound it to a SHORT reply so a long, legitimate recon that merely
    # mentions "usage policy" verbatim (e.g. web recon over a site's ToS
    # page) isn't false-discarded — a real refusal IS the ~250-char error
    # string and nothing else, whereas a real recon reply is structured bullets.
    if result_is_error or (
        len(out) < 800 and classify_agent_error(out) == "policy_refusal"
    ):
        log_fn(
            f"[{tag}] reply flagged as error/refusal "
            f"(is_error={result_is_error}) — discarding so it isn't "
            f"laundered into main's prompt; main will delegate as needed"
        )
        return ""
    # Sanitize control bytes that would corrupt downstream consumers.
    # The recon reply is embedded into main's user_prompt and shipped
    # to the `claude` CLI subprocess via argv (execve). argv CANNOT
    # contain NUL bytes — they trigger `ValueError: embedded null byte`
    # at subprocess.Popen time, killing main's spawn before its first
    # turn. The model occasionally emits literal \x00 when summarizing
    # binary disasm output (objdump on stripped ELFs, decomp of obfu-
    # scated funcs, etc.). Strip them defensively; also strip other
    # control codes that can confuse the SDK's JSON framing.
    out = sanitize_for_argv(out, label=f"{tag}-reply", log_fn=log_fn)
    if crashed:
        out = (
            "[partial — pre-recon subprocess died before emitting its "
            "final summary; the assistant text below is what was "
            "collected. Spawn a follow-up recon if you need more.]\n\n"
        ) + out
    # 8 KB cap on what reaches main's user_prompt. TRUNCATE FROM THE MIDDLE,
    # never the tail: pwn's pre-recon gate (`_missing_pre_recon_sections` in
    # modules/pwn/analyzer.py) substring-checks the returned text for MANDATORY
    # section titles, and those sections are the LAST thing recon writes. A
    # plain tail cut therefore removed the very titles the gate looks for, the
    # gate read "the model silently dropped sections", and it respawned the
    # whole recon — up to 4 times, each a full spawn.
    #
    # Job 302cd87de603 (heap pwn) is the worked example: 4 attempts, every one
    # logged at exactly `len=8013` (= 8000 + len("\n…(truncated)")) while the
    # reported `missing=[...]` list KEPT CHANGING. A stable length with a
    # moving miss-list is the signature of a hard cap eating the tail, not of
    # a model omitting sections. Cost: 44 min and ~$6.4 of a 3 h / $38.5 job,
    # and it recurs on any heap-pwn job whose recon is a few hundred chars
    # over the cap (this reply was 8042 — it overshot by 42).
    #
    # Middle-out keeps both ends, so the header (ARCH / PROTECTIONS / LIBC)
    # AND the trailing mandatory sections survive; only the least
    # position-critical middle is dropped, with an explicit marker so main
    # knows material is missing. Under the cap this is a no-op.
    #
    # 2026-07-26 — the cap was RAISED 8000 -> PRE_RECON_MAX_CHARS after the
    # middle-elision logging exposed the real scale: on a heap chal recon
    # actually emits ~18-19.5 KB (job 98dd2c0a3c58: 19458 and 18274 chars),
    # i.e. 2.4x the old budget. At that ratio NO truncation strategy can
    # work — head+tail saved the trailing sections but then killed the
    # MIDDLE ones (HEAP STATE MATRIX / ENV-AWARE PATHS), and the gate
    # respawned anyway. 7 of 18 stored replies sat at the old cap.
    #
    # The economics are lopsided: 19.5 KB is ~5.1 K tokens = ~$0.026 of opus
    # input, prepended ONCE and cached thereafter — while a single respawn
    # costs ~$1.20 and ~5 minutes, i.e. ~47x more, and the loop runs up to 4
    # times. The cap was never a cost control; it was a tidiness rule that
    # became a self-inflicted retry loop.
    # The gate that checks for mandatory sections must judge what the MODEL
    # wrote, not what our budget left of it — so the pre-clip text rides along
    # on the return value. Job 71edd90398f4 is the worked example: three
    # respawns, every one logged at exactly len=32166 (= 32000 + a 166-char
    # marker) with missing=['ENV-AWARE PATHS'], because the section sat at
    # bytes 22400-26252, precisely the band the head-70%/tail-30% cut removes.
    # Respawning cannot fix truncation: each attempt regenerates a ~35 KB
    # report, the same band is cut, the same title vanishes. ~$1.20 and ~5 min
    # per attempt, up to 4, against ~$0.047 for passing the whole thing once.
    full_text = out
    if len(out) > PRE_RECON_MAX_CHARS:
        out = _elide_preserving(out, PRE_RECON_MAX_CHARS, keep_sections,
                                log_fn, tag)
    # Persist the ORIGINAL. Until now it lived only in memory, so a truncation
    # loop left nothing behind but a length in run.log — this investigation had
    # to reconstruct the cut band by arithmetic. 35 KB is too big for run.log
    # but trivial as a file next to the other artifacts.
    try:
        (Path(work_dir) / "pre_recon_raw.md").write_text(full_text)
    except Exception:
        pass
    return PreReconReply(out, full_text)


_VALID_EFFORTS_BACKEND = frozenset(
    ("none", "minimal", "low", "medium", "high", "xhigh", "max")
)


def resolve_effort(
    meta_effort: str | None,
    provider: str | None = None,
) -> str | None:
    """Resolve the per-job effort with the global Settings fallback.

    Per-job effort (saved in meta.json by api/routes/*_module.py)
    wins when set; otherwise fall back to the active provider's effort
    Setting (``claude_effort``, ``grok_effort``, or ``gpt_effort``);
    otherwise return None
    and let the SDK/CLI pick its own default (model-dependent).
    """
    from modules.agent_provider import default_effort_for

    def _norm(v: object) -> str | None:
        if v is None:
            return None
        s = str(v).strip().lower()
        if not s:
            return None
        return s if s in _VALID_EFFORTS_BACKEND else None

    per_job = _norm(meta_effort)
    if per_job is not None:
        return per_job
    # An active model-preset can pin effort for the main session (overrides the
    # global effort Setting); a blank preset slot falls through to global.
    try:
        from modules.model_presets import get_preset_effort
        preset_e = _norm(get_preset_effort(provider))
        if preset_e is not None:
            return preset_e
    except Exception:
        pass
    return _norm(default_effort_for(provider))


def resolve_main_model(
    model_override: str | None,
    provider: str | None = None,
) -> str:
    """Resolve the MAIN CTF agent's model.

    Precedence: explicit per-job pick (``model_override``) > active preset's
    ``main`` slot > global provider model Setting (``claude_model``,
    ``grok_model``, or ``gpt_model``) > provider default. When no preset is active (or its
    ``main`` slot is blank), this is byte-identical to the historical
    ``model_override or get_setting("claude_model") or default`` for the
    Claude provider.

    Provider safety: if a model-preset pins a model from another provider
    (common after switching providers), coerce it to the selected provider's
    default so sessions never launch with a mismatched model id.
    """
    from modules.agent_provider import coerce_model_for_provider, default_model_for
    from modules.model_presets import resolve_role_model

    if model_override and str(model_override).strip():
        return coerce_model_for_provider(str(model_override).strip(), provider)
    global_default = default_model_for(provider)
    resolved = resolve_role_model("main", global_default, provider)
    return coerce_model_for_provider(resolved, provider)


def resolve_judge_model(job_id: str | None) -> str:
    """Resolve the model a NON-main phase (prejudge / supervise / postjudge /
    judge-spawned recon / report) should run on so it FOLLOWS the job's
    main-agent model — NEVER diverging. (The /retry reviewer has its own
    ``resolve_reviewer_model``, which folds the ``reviewer`` slot over this.)

    Base is derived through ``resolve_main_model`` (per-job ``meta.model``
    override → preset ``main`` → global provider default), so the judge
    family tracks main even when main is pinned by a preset. An active
    preset's own ``judge`` slot then folds over that base; a blank slot falls
    through to it. Always coerced to the job's ``agent_provider`` family so
    a Grok job never launches a Claude judge (and vice versa).
    """
    from modules.agent_provider import coerce_model_for_provider, provider_for_job
    from modules.model_presets import resolve_role_model

    provider = provider_for_job(job_id)
    meta_model = (read_meta(job_id) or {}).get("model") if job_id else None
    base = resolve_main_model(meta_model, provider)
    resolved = resolve_role_model("judge", base, provider)
    return coerce_model_for_provider(resolved, provider)


def resolve_reviewer_model(job_id: str | None) -> str:
    """Resolve the /retry REVIEWER's model — configurable INDEPENDENTLY of the
    judge family.

    Fold order: an active preset's ``reviewer`` slot wins; else it falls back to
    the ``judge`` slot (which itself follows main); else to the main-derived
    base. Coerced to the job's ``agent_provider`` so reviewer is Grok when
    the job/settings selected Grok.
    """
    from modules.agent_provider import coerce_model_for_provider, provider_for_job
    from modules.model_presets import resolve_role_model

    provider = provider_for_job(job_id)
    meta_model = (read_meta(job_id) or {}).get("model") if job_id else None
    base = resolve_main_model(meta_model, provider)
    judge_base = resolve_role_model("judge", base, provider)  # reviewer default
    resolved = resolve_role_model("reviewer", judge_base, provider)
    return coerce_model_for_provider(resolved, provider)


def make_main_session_options(
    *,
    job_id: str,
    work_dir,
    model: str,
    system_prompt: str,
    base_tools: list,
    summary: dict,
    add_dirs: list | None = None,
    resume_sid: str | None = None,
    extra_env: dict | None = None,
    effort: str | None = None,
):
    """Build agent options for a main session (Claude, Grok, or Codex/GPT).

    When Settings ``agent_provider=grok``, returns ``GrokSessionOptions``.
    When ``agent_provider=gpt``, returns ``GptSessionOptions``.
    Otherwise builds ``ClaudeAgentOptions`` and selects isolated-subagent
    (MCP) vs legacy in-process (``agents=``) based on
    ``USE_ISOLATED_SUBAGENTS`` (default ON).

    Args:
      base_tools: the per-module tool set (Read/Write/Bash/...) WITHOUT
        the subagent-spawn tool. The builder appends either
        ``mcp__team__spawn_subagent`` or ``Agent`` depending on the
        active path (Claude only).
      summary: the main session's summary dict; passed through to the
        MCP tool so per-spawn cost + counter increments roll up.
    """
    from modules.agent_provider import active_provider

    log_fn_local = lambda s: log_line(job_id, s)
    # Strip argv-fatal control bytes before the prompt is shipped via
    # CLI argv (Claude) or ACP meta (Grok). A stray `\0` in any prompt
    # constant makes execve(2) reject the spawn with
    # `ValueError: embedded null byte`.
    system_prompt = sanitize_for_argv(
        system_prompt, label="main-options", log_fn=log_fn_local,
    )
    # Same builder as sub-agents and pre-recon. `role` is empty on purpose:
    # main never carried AGENT_ROLE, and adding it here would change what the
    # process sees for a reason unrelated to this fix.
    env = agent_job_env(job_id, "", work_dir, extra_env)

    # Per-job scratch dir under cwd. Keeps tempfile.* / pwntools /
    # pip / pyc cache from colliding when WORKER_CONCURRENCY > 1 in
    # the same container. Bash absolute-path escapes (cd /tmp, raw
    # /tmp/foo) are addressed by the SCRATCH FILES rule in
    # CTF_PREAMBLE — env-vars only cover library calls. Cleanup is
    # implicit: job DELETE rmtree's the whole /data/jobs/<id>/.

    # Terminal-mode quietness:
    #   TERM=xterm — silences `_curses.error: setupterm: could not find
    #     terminfo database` that pwntools / pwn checksec prints on every
    #     invocation inside the worker container (no /etc/terminfo). ~3
    #     lines of pure noise per checksec call.
    #   PWNLIB_NOTERM=1 — disables pwntools' terminal-mode rewrites
    #     (cursor positioning, color escapes, progress bars) so Bash
    #     tool_result captures stay clean. The agent doesn't see ANSI
    #     anyway; this just drops the carriage-return chatter.
    # We deliberately do NOT set PWNLIB_SILENT=1: the pwntools-based
    # `checksec` command emits its findings via `log.info`, and silencing
    # the logger silences checksec itself. Observed empirically in the
    # debugger fidelity smoke — `checksec --file=` exited 0 with empty
    # output under PWNLIB_SILENT=1, forcing the agent to derive RELRO/
    # canary/PIE from readelf+nm fallbacks. Letting pwntools log adds
    # one `[*] '<file>'` line per call; minor cost vs. losing checksec.

    provider = active_provider()

    if provider == "gpt":
        from modules.gpt_agent import GptSessionOptions
        from modules.agent_provider import get_gpt_runtime
        turn_timeout_s = 1800.0
        try:
            jt = int((read_meta(job_id) or {}).get("job_timeout") or 0)
            if jt > 0:
                turn_timeout_s = float(max(jt, 1800))
        except Exception:
            pass
        log_fn_local(
            "[orchestrator] agent backend: "
            + (
                "OpenAI Codex CLI (ChatGPT OAuth); native Codex tools/subagents; "
                if get_gpt_runtime() == "codex"
                else "OpenAI GPT (Responses API); local tools/subagents; "
            )
            + f"turn_timeout={turn_timeout_s:.0f}s"
        )
        return GptSessionOptions(
            system_prompt=system_prompt,
            model=model,
            cwd=str(work_dir),
            effort=effort,
            env=env,
            resume=resume_sid,
            add_dirs=list(add_dirs or []),
            turn_timeout_s=turn_timeout_s,
        )

    if provider == "grok":
        from modules.grok_acp import GrokSessionOptions
        # Rewrite Claude MCP delegation (mcp__team__spawn_subagent, recon
        # as a Claude type, …) into Grok native spawn_subagent + role map.
        # Claude path never enters this branch — SYSTEM_PROMPT constants stay
        # Claude-correct for agent_provider=claude.
        system_prompt = adapt_system_prompt_for_grok(system_prompt)
        # Per-turn budget: at least 30 min, or the job soft-timeout if larger.
        # Kernel/pwn CTF turns routinely need >10 min of tool use (3c0e0edb73db).
        turn_timeout_s = 1800.0
        try:
            jt = int((read_meta(job_id) or {}).get("job_timeout") or 0)
            if jt > 0:
                turn_timeout_s = float(max(jt, 1800))
        except Exception:
            pass
        log_fn_local(
            "[orchestrator] agent backend: Grok Build (ACP stdio); "
            "native spawn_subagent for delegation "
            "(recon→explore, debugger/judge→general-purpose; "
            "[HEXTECH_ROLE=…] prefix required); "
            "kill-guard hooks under $GROK_HOME/hooks/; "
            f"turn_timeout={turn_timeout_s:.0f}s"
        )
        return GrokSessionOptions(
            system_prompt=system_prompt,
            model=model,
            cwd=str(work_dir),
            effort=effort,
            env=env,
            resume=resume_sid,
            add_dirs=list(add_dirs or []),
            turn_timeout_s=turn_timeout_s,
        )

    from claude_agent_sdk import ClaudeAgentOptions

    use_isolated = os.environ.get(
        "USE_ISOLATED_SUBAGENTS", "1") != "0"

    if use_isolated:
        mcp_server, spawn_tool = make_spawn_subagent_mcp(
            model=model,
            work_dir=work_dir,
            job_id=job_id,
            log_fn=log_fn_local,
            summary=summary,
        )
        env["USE_ISOLATED_SUBAGENTS"] = "1"
        # Disallowed-tools list. permission_mode=bypassPermissions
        # lets the model call ANY built-in tool regardless of
        # allowed_tools — including the SDK's Task/Agent tool which
        # dispatches to a built-in "general-purpose" subagent that
        # runs in main's same Node.js process (= exactly the
        # cumulative-heap pattern the MCP path exists to escape).
        # Block both names defensively; main must use our MCP tool.
        # Verified in job 6ac97fb2fb4e (2026-05-12): main bypassed
        # allowed_tools and spawned a general-purpose Agent that
        # accumulated context into main's heap.
        options = ClaudeAgentOptions(
            system_prompt=system_prompt,
            model=model,
            cwd=str(work_dir),
            allowed_tools=[*base_tools, spawn_tool],
            # Block built-in Agent/Task (would dispatch to a general-purpose
            # subagent that shares main's Node.js heap). WebSearch/WebFetch are
            # NO LONGER blocked (web research enabled, 2026-07-22): main may
            # research directly, though the prompt nudges it to delegate heavy
            # web lookups to recon so the large result bodies land in recon's
            # transient context, not main's (job d809a5187990: 33 direct
            # WebSearch calls, ~200 KB in main's context).
            disallowed_tools=["Agent", "Task"],
            permission_mode="bypassPermissions",
            add_dirs=add_dirs or [],
            env=env,
            resume=resume_sid,
            fork_session=bool(resume_sid),
            mcp_servers={"team": mcp_server},
            effort=effort,
            hooks=main_session_hooks(add_dirs, work_dir, job_id),
        )
        log_fn_local(
            "[orchestrator] subagent isolation: ON "
            f"(tool={spawn_tool}; Agent/Task blocked on main; "
            "web research ENABLED — recon owns WebSearch/WebFetch, main may too)"
        )
    else:
        env["USE_ISOLATED_SUBAGENTS"] = "0"
        options = ClaudeAgentOptions(
            system_prompt=system_prompt,
            model=model,
            cwd=str(work_dir),
            allowed_tools=[*base_tools, "Agent"],
            permission_mode="bypassPermissions",
            add_dirs=add_dirs or [],
            env=env,
            resume=resume_sid,
            fork_session=bool(resume_sid),
            agents=build_recon_agents(model),
            effort=effort,
            hooks=main_session_hooks(add_dirs, work_dir, job_id),
        )
        log_fn_local(
            "[orchestrator] subagent isolation: OFF (legacy in-process)"
        )
    return options


_NOCACHE_TOKEN = "[NOCACHE]"
_SUBAGENT_CACHE_DIRNAME = "subagent_cache"


def _normalize_subagent_prompt_for_cache(prompt: str) -> str:
    """Strip whitespace + collapse runs of whitespace so trivially-
    different prompts (extra blank line, trailing spaces) hit the
    same cache entry. We do NOT strip case or punctuation — those
    are sometimes semantic in CTF prompts (e.g. `LIBC_` vs `libc_`).
    The leading [NOCACHE] sentinel is removed by the caller before
    this is invoked.
    """
    return " ".join((prompt or "").split())


def _subagent_cache_key(sub_type: str, normalized_prompt: str) -> str:
    """Per-job cache key. 16 hex chars is enough — collision odds at
    O(10) spawns per job are negligible and the key only has to be
    unique inside one job's .scratch dir.
    """
    h = hashlib.sha256(f"{sub_type}|{normalized_prompt}".encode("utf-8"))
    return h.hexdigest()[:16]


def _load_subagent_cache(
    work_dir, sub_type: str, raw_prompt: str,
) -> tuple[str, dict | None]:
    """Look up a cached reply. Returns (cache_key, entry_or_None).
    Returns (None_key, None) when caching is bypassed via [NOCACHE].
    """
    if (raw_prompt or "").lstrip().startswith(_NOCACHE_TOKEN):
        return ("", None)
    norm = _normalize_subagent_prompt_for_cache(raw_prompt)
    key = _subagent_cache_key(sub_type, norm)
    p = Path(work_dir) / ".scratch" / _SUBAGENT_CACHE_DIRNAME / f"{key}.json"
    if not p.is_file():
        return (key, None)
    try:
        return (key, json.loads(p.read_text(errors="ignore")))
    except (OSError, json.JSONDecodeError):
        return (key, None)


def _store_subagent_cache(
    work_dir, cache_key: str, sub_type: str, prompt: str,
    reply: str, cost_usd: float, spawn_idx: int, log_fn,
) -> None:
    """Persist a fresh reply to the job-scoped cache. Best-effort:
    a write failure only costs a future cache miss, not the current
    run. Empty replies are skipped so a failed spawn doesn't poison
    the cache.
    """
    if not cache_key or not (reply or "").strip():
        return
    cache_dir = Path(work_dir) / ".scratch" / _SUBAGENT_CACHE_DIRNAME
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        log_fn(f"[cache] dir create failed: {e}")
        return
    entry = {
        "sub_type": sub_type,
        "prompt_preview": prompt[:400],
        "reply": reply,
        "cost_usd": float(cost_usd or 0.0),
        "spawn_idx": int(spawn_idx),
        "ts": datetime.now().isoformat(timespec="seconds"),
    }
    try:
        (cache_dir / f"{cache_key}.json").write_text(json.dumps(entry))
    except OSError as e:
        log_fn(f"[cache] write failed: {e}")


# Subagent reply schema validators — Phase 2. recon stays free-form
# because its questions vary widely (libc offsets / decomp triage /
# rootfs unpack); enforcing one schema would either be too loose to
# help or too strict to fit. Triage and debugger have FIXED shapes
# (verdict table / observed-trace-conclusion-caveats) so JSON is a
# clean win — main can `json.loads(tool_result)` once and access
# fields directly instead of parsing markdown.
_JSON_REPLY_SUBAGENTS = {"triage", "debugger"}


def _extract_json_from_reply(text: str) -> dict | None:
    """Permissively pull a JSON object out of a subagent reply.

    Accepts:
      * pure JSON (best case — what the prompt asks for)
      * JSON inside a ```json ... ``` fence
      * JSON inside a ``` ... ``` fence
      * JSON object embedded in prose (outermost brace-balanced span)

    Returns the parsed dict, or None when no JSON object is recoverable.

    String-aware: braces inside JSON string literals don't shift
    depth (e.g. `{"note":"some {prose} here"}` is one balanced span).
    """
    s = (text or "").strip()
    if not s:
        return None
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass
    # Strip code fences
    if s.startswith("```"):
        body = s.split("\n", 1)[1] if "\n" in s else s[3:]
        if body.endswith("```"):
            body = body[:-3]
        try:
            return json.loads(body.strip())
        except json.JSONDecodeError:
            pass
    # Scan forward from each `{`; return the first balanced span
    # that parses as a dict. Forward (not rfind) so nested objects
    # don't shadow the outer one. String-aware so brace chars in
    # JSON string literals don't disturb depth tracking.
    n = len(s)
    i = 0
    while i < n:
        if s[i] != "{":
            i += 1
            continue
        depth = 0
        j = i
        in_str = False
        escape = False
        while j < n:
            c = s[j]
            if in_str:
                if escape:
                    escape = False
                elif c == "\\":
                    escape = True
                elif c == '"':
                    in_str = False
            else:
                if c == '"':
                    in_str = True
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            parsed = json.loads(s[i:j+1])
                            if isinstance(parsed, dict):
                                return parsed
                        except json.JSONDecodeError:
                            pass
                        break
            j += 1
        i += 1
    return None


def make_spawn_subagent_mcp(
    model: str | None,
    work_dir,
    job_id: str,
    log_fn,
    summary: dict,
):
    """Build the MCP server that hosts the `spawn_subagent` tool. Each
    invocation of the tool launches a FRESH `ClaudeSDKClient` for the
    requested subagent and returns its final text response. The
    subprocess dies as soon as the subagent finishes, so main's heap
    stays lean.

    Returns a tuple ``(mcp_config, tool_name_full)`` where:
      * ``mcp_config`` goes into ``ClaudeAgentOptions(mcp_servers={...})``
      * ``tool_name_full`` (``"mcp__team__spawn_subagent"``) goes into
        ``allowed_tools=[...]`` and is what the prompt tells main to
        call.
    """
    from claude_agent_sdk import (
        create_sdk_mcp_server,
        tool,
        ClaudeSDKClient,
        AssistantMessage,
        UserMessage,
        ResultMessage,
    )

    server_name = "team"

    @tool(
        "spawn_subagent",
        (
            "Spawn an INDEPENDENT subagent (recon / debugger / judge "
            "/ triage) in its own SDK session (= its own claude CLI "
            "subprocess). The subagent runs to completion, then "
            "returns its FINAL text response as the tool result. Use "
            "this in place of the built-in `Agent` tool whenever you "
            "want process-isolated memory — main's heap will not grow "
            "with the subagent's investigation context. Parameters: "
            "subagent_type ∈ {recon, debugger, judge, triage}; "
            "prompt is the question/task you want the subagent to "
            "answer (keep it specific and bounded — the subagent's "
            "session ends when it finishes the response). "
            "Replies are CACHED by (subagent_type, normalized_prompt) "
            "for the lifetime of this job — identical re-spawns return "
            "the prior reply instantly. Prefix your prompt with "
            "[NOCACHE] to force a fresh spawn (rare; use when you "
            "explicitly want a second independent opinion or when "
            "underlying files have changed since the cached run)."
        ),
        {"subagent_type": str, "prompt": str},
    )
    async def spawn_subagent(args: dict) -> dict:
        sub_type = (args.get("subagent_type") or "").strip().lower()
        sub_prompt = args.get("prompt") or ""
        if sub_type not in _AGENT_PROMPT_BY_TYPE:
            return {
                "content": [{
                    "type": "text",
                    "text": (
                        f"ERROR: unknown subagent_type {sub_type!r}. "
                        f"Valid: {', '.join(sorted(_AGENT_PROMPT_BY_TYPE))}."
                    ),
                }],
                "isError": True,
            }
        if not sub_prompt.strip():
            return {
                "content": [{
                    "type": "text",
                    "text": "ERROR: empty prompt — pass a specific question.",
                }],
                "isError": True,
            }

        # Strip the optional [NOCACHE] sentinel from the prompt main
        # sees the subagent execute; the sentinel only signals the
        # caching layer (above) and shouldn't reach the subagent.
        raw_prompt_for_lookup = sub_prompt
        if sub_prompt.lstrip().startswith(_NOCACHE_TOKEN):
            sub_prompt = sub_prompt.lstrip()[len(_NOCACHE_TOKEN):].lstrip()

        # NOTE: the spawn counter is incremented in log_assistant_blocks
        # the moment main's ToolUseBlock(mcp__team__spawn_subagent)
        # is yielded — that lets _maybe_subagent_cap() set the break
        # flag before this function even gets called. Do NOT increment
        # here or we'd double-count. By the time we're inside this
        # function, summary["subagent_spawns"] already reflects this
        # spawn.
        spawn_idx = int(summary.get("subagent_spawns", 0))

        # Phase 1: reply cache. Identical (sub_type, prompt) pairs
        # return the prior reply instantly — saves the ~$0.5-2 + 2-5
        # min that re-running a spawn for the same question costs.
        # The "recon#3 + recon#4 both re-derived libc symbol VMA→file
        # mapping" pattern from job 89d442ef3291 is exactly what this
        # short-circuits. Cache scope is per-job (work_dir is per-job).
        cache_key, cached = _load_subagent_cache(
            work_dir, sub_type, raw_prompt_for_lookup,
        )
        if cached and isinstance(cached.get("reply"), str):
            saved_cost = float(cached.get("cost_usd") or 0.0)
            log_fn(
                f"[orchestrator] subagent #{spawn_idx} ({sub_type}) "
                f"cache HIT — returning prior reply "
                f"({len(cached['reply'])} B, saved ~${saved_cost:.4f})"
            )
            return {"content": [{"type": "text", "text": cached["reply"]}]}

        log_fn(
            f"[orchestrator] isolated subagent #{spawn_idx} spawning "
            f"({sub_type})"
        )

        # CONTEXT-SHARING (kills re-derivation across isolated subagents).
        # Each prior subagent's final summary lives at
        # ./.scratch/subagent_log.md ; we prepend the last ~8 KB to this
        # spawn's prompt so it doesn't repeat work the previous one
        # already finished. Subagent isolation keeps the heavy
        # investigation context out of MAIN, but two consecutive recons
        # rediscovering the same symbol offsets / RPATH workaround is
        # waste — past jobs (89d442ef3291: recon#3 + recon#4 both
        # re-derived libc symbol VMA→file mapping; debugger#2 + recon#4
        # both re-solved the chal-libc-fix RPATH issue independently).
        scratch_dir = Path(work_dir) / ".scratch"
        try:
            scratch_dir.mkdir(parents=True, exist_ok=True)
        except OSError as _e:
            log_fn(f"[orchestrator] scratch dir create failed: {_e}")
        sub_log = scratch_dir / "subagent_log.md"
        prior_block = ""
        if sub_log.is_file():
            try:
                raw = sub_log.read_text(errors="replace")
            except OSError:
                raw = ""
            if raw:
                # Take the last 8 KB so we don't unbound-grow the
                # prompt as the job spawns more subagents. The most
                # recent summaries are the ones likeliest to inform
                # the new spawn anyway; earlier ones already shaped
                # main's user-prompt for THIS spawn.
                tail = raw[-8000:]
                prior_block = (
                    "PRIOR SUBAGENT FINDINGS (read-only context — extend "
                    "or contradict with evidence; do NOT silently repeat "
                    "work already done):\n\n"
                    f"{tail}\n\n"
                    "=== END PRIOR FINDINGS ===\n\n"
                    "=== YOUR NEW TASK BELOW ===\n\n"
                )

        # AUTOBOOT.md auto-prepend (deterministic orientation breadcrumb).
        # The orchestrator writes ./AUTOBOOT.md before main's first turn
        # to capture environment + module-specific tips (effective
        # binary, libc profile, sibling-docker HOST_DATA_DIR pattern,
        # decomp/scratch hints) — but isolated subagents previously had
        # to discover those facts by reading the file themselves. They
        # often skipped it (job c410 / 58b124 debugger spent tool calls
        # re-deriving the launch pattern that was already in AUTOBOOT
        # extras). Injecting it ahead of prior_block guarantees every
        # spawn starts with the same baseline as main, while keeping the
        # raw breadcrumb file as the on-disk source of truth.
        autoboot_block = ""
        autoboot_path = Path(work_dir) / "AUTOBOOT.md"
        if autoboot_path.is_file():
            try:
                autoboot_raw = autoboot_path.read_text(errors="replace")
            except OSError:
                autoboot_raw = ""
            if autoboot_raw:
                # Cap at 4 KB so an unusually long extras section can't
                # crowd out the actual task. AUTOBOOT.md is normally
                # ~1-2 KB; we head-truncate (not tail) so the front-
                # matter and module orientation block stay intact.
                autoboot_head = autoboot_raw[:4096]
                autoboot_block = (
                    "ENVIRONMENT BREADCRUMB (./AUTOBOOT.md — same baseline "
                    "main started from; do NOT re-derive what's here):\n\n"
                    f"{autoboot_head}\n\n"
                    "=== END AUTOBOOT ===\n\n"
                )

        sub_prompt_effective = autoboot_block + prior_block + sub_prompt

        sub_options = make_standalone_options(
            sub_type, model, work_dir, job_id,
        )
        # Collect final text + record tool activity on a per-subagent
        # tag so the run.log lines stay self-describing.
        tag = f"{sub_type}#{spawn_idx}"
        chunks: list[str] = []
        sub_summary: dict = {}
        try:
            async with ClaudeSDKClient(options=sub_options) as sub_client:
                await sub_client.query(sub_prompt_effective)
                async for msg in sub_client.receive_response():
                    record_rate_limit_event(msg)  # account-global usage chip
                    # Liveness only — the token ledger below is deliberately
                    # the SUBAGENT's, not main's, so agent_heartbeat must not
                    # be called here.
                    phase_heartbeat(job_id, tag, msg)
                    # Logging mirrors log_assistant_blocks but tagged
                    # by the isolated subagent's identity. We don't
                    # call log_assistant_blocks because that helper
                    # mutates main's `summary["tool_calls"]` counter,
                    # and we want subagent tool calls counted on the
                    # subagent's own ledger.
                    if isinstance(msg, AssistantMessage):
                        for block in (getattr(msg, "content", None) or []):
                            kind = type(block).__name__
                            if kind == "TextBlock":
                                txt = getattr(block, "text", "") or ""
                                if txt.strip():
                                    chunks.append(txt)
                                    log_line(
                                        job_id,
                                        f"[{tag}] AGENT: {txt[:500]}",
                                    )
                            elif kind == "ToolUseBlock":
                                nm = getattr(block, "name", "?")
                                inp = getattr(block, "input", None) or {}
                                try:
                                    preview = json.dumps(inp)[:200]
                                except Exception:
                                    preview = str(inp)[:200]
                                log_line(
                                    job_id,
                                    f"[{tag}] TOOL {nm}: {preview}",
                                )
                    elif isinstance(msg, UserMessage):
                        # CANNOT use log_user_blocks here — it calls
                        # agent_tag() which looks up parent_tool_use_id
                        # in the per-job subagent registry. Isolated
                        # subagents run in a SEPARATE ClaudeSDKClient,
                        # so their UserMessage (= tool_result) blocks
                        # don't carry a parent_tool_use_id that maps to
                        # any registered Agent call in main's session.
                        # The lookup falls back to "main" and we get
                        # `[main] TOOL_RESULT: ...` lines attributed to
                        # the wrong agent. Log directly with our tag.
                        content = getattr(msg, "content", None)
                        if isinstance(content, list):
                            for blk in content:
                                if type(blk).__name__ != "ToolResultBlock":
                                    continue
                                is_err = bool(getattr(blk, "is_error", False))
                                body_raw = getattr(blk, "content", None)
                                preview = format_tool_result(body_raw, is_err)
                                log_line(job_id, f"[{tag}] " + preview)
                                _check_runaway(job_id, tag, preview)
                    elif isinstance(msg, ResultMessage):
                        # Bill the subagent's cost to the main job.
                        cost = (
                            getattr(msg, "total_cost_usd", None)
                            or getattr(msg, "cost_usd", None)
                            or 0.0
                        )
                        if cost:
                            sub_summary["cost_usd"] = float(cost)
                            summary["cost_usd"] = (
                                float(summary.get("cost_usd", 0.0))
                                + float(cost)
                            )
                        # Capture the subagent's terminal error flag. An AUP
                        # policy_refusal (or transport / timeout) surfaces here
                        # as is_error=True — frequently with NO assistant text,
                        # which would otherwise fall through to the misleading
                        # "returned no text — treat as no useful output" default
                        # below and trick main into concluding the candidate
                        # space is EMPTY. Record it so we return a LOUD
                        # incomplete signal instead (see post-loop guard).
                        if getattr(msg, "is_error", False):
                            sub_summary["is_error"] = True
        except Exception as e:
            log_fn(
                f"[orchestrator] isolated {tag} crashed: {e!r} — "
                f"returning error to main"
            )
            return {
                "content": [{
                    "type": "text",
                    "text": (
                        f"SUBAGENT_ERROR ({sub_type}): {type(e).__name__}: "
                        f"{str(e)[:400]}"
                    ),
                }],
                "isError": True,
            }

        # A subagent that ended on a terminal error (AUP policy_refusal /
        # transport / timeout) must NOT be handed back as a low-signal
        # "no useful output": main would read that as "the enumeration found
        # nothing" and falsely concede the candidate space is empty — a NEW
        # false-negative that the breadth-first OFFLOAD directive could
        # introduce by relocating a main-session trip into the subagent. The
        # main loop's policy_refusal detection + halt does NOT reach this
        # isolated child, so guard it here: return an explicit INCOMPLETE
        # marker so main falls back to doing the analysis itself (= original,
        # no-worse behavior) or re-delegates a narrower slice — never treats
        # the error as a finding. Skip the cache (don't memoize a non-result).
        if sub_summary.get("is_error"):
            log_fn(
                f"[orchestrator] isolated {tag} ended with is_error — "
                f"returning INCOMPLETE (not 'empty') to main"
            )
            return {
                "content": [{
                    "type": "text",
                    "text": (
                        f"SUBAGENT_INCOMPLETE ({sub_type}): the isolated "
                        f"subagent did not finish — its session ended with an "
                        f"error (e.g. policy / transport / timeout). This is "
                        f"NOT a result of 'nothing found' and does NOT mean "
                        f"the candidate space is empty. Do this analysis "
                        f"yourself in the main session, or re-delegate a "
                        f"NARROWER slice; never treat this as a finding."
                    ),
                }],
                "isError": True,
            }

        final = "\n".join(chunks).strip()
        # Same control-byte sanitization as run_pre_recon — the subagent
        # may emit \x00 while summarizing disasm/binary content, and the
        # tool_result text rides back into main's conversation. If main
        # later forks via /retry the same prompt argv would carry the
        # NUL and crash subprocess.Popen. Strip defensively at the
        # source (this MCP wrapper) so it can never reach main.
        final = sanitize_for_argv(
            final, label=f"orchestrator {tag} reply", log_fn=log_fn,
        )
        if not final:
            final = (
                f"(subagent {sub_type} returned no text — likely hit "
                f"its own budget or token limit. Treat as no useful "
                f"output.)"
            )
        cost_note = (
            f" cost=${sub_summary.get('cost_usd', 0):.4f}"
            if sub_summary.get("cost_usd")
            else ""
        )
        log_fn(
            f"[orchestrator] isolated {tag} done — "
            f"{len(final)} B response{cost_note}"
        )

        # ---- Frame-lockin dead-end detector (Tooth 1 arming) ----
        # If this isolated subagent returned evidence that DISCONFIRMS a
        # core assumption of main's current frame (a "no primitive" /
        # "premise wrong" / "dead end" reply) AND the job is easy-/shortcut-
        # framed AND we are past the spend threshold, arm a ONE-SHOT
        # contrarian reframe user-turn (consumed at the main-loop turn
        # boundary). This is the anti-anchoring lever: job 78bd896e0f3c
        # ground $19.81 because main re-subordinated exactly this class of
        # subagent evidence to a frame it would not abandon (recon#4 ASM-
        # proved the core assumption wrong; main kept the frame). Gated +
        # one-shot so it can't nag, and easy_framing-gated so a normal hard
        # chal's expected "no primitive yet" replies don't trigger it.
        try:
            if (
                summary.get("easy_framing")
                and not summary.get("contrarian_fired")
                and _DEADEND_REPLY_RE.search(final)
            ):
                try:
                    thr = float(os.environ.get(
                        "CONTRARIAN_MIN_COST_USD",
                        str(DEFAULT_CONTRARIAN_MIN_COST_USD),
                    ))
                except (TypeError, ValueError):
                    thr = DEFAULT_CONTRARIAN_MIN_COST_USD
                # TRUE spend = subagent sum (summary["cost_usd"]) + main's
                # cumulative cost (summary["result"]; set at the prior turn
                # boundary — spawns run mid-turn so it lags the current turn's
                # main spend, which only harmlessly delays arming). See the
                # cost-cap note in run_main_agent_session for why these two
                # sources are disjoint and must be summed.
                spent_now = (
                    float(summary.get("cost_usd", 0.0) or 0.0)
                    + float(
                        (summary.get("result") or {}).get("total_cost_usd", 0.0)
                        or 0.0
                    )
                )
                if thr >= 0 and spent_now >= thr:
                    summary["contrarian_fired"] = True
                    summary["contrarian_pending"] = True
                    log_fn(
                        f"[orchestrator] CONTRARIAN_ARM: {tag} returned a "
                        f"premise-refuted/dead-end signal on an easy-framed "
                        f"job at ${spent_now:.2f} — arming one contrarian "
                        f"reframe user-turn (Tooth 1)."
                    )
        except Exception:
            pass

        # Phase 2: JSON-typed reply validation for triage / debugger.
        # The prompts ask for strict JSON; main programmatically
        # consumes the fields. If we can't recover a JSON object,
        # log a warning + pass the raw text through (so a malformed
        # reply doesn't crash main — degrades to free-form parsing).
        if sub_type in _JSON_REPLY_SUBAGENTS:
            parsed = _extract_json_from_reply(final)
            if parsed is None:
                log_fn(
                    f"[orchestrator] {tag} reply was not valid JSON "
                    f"(expected per prompt) — main will see raw text"
                )
            else:
                # Re-serialize so main always sees compact JSON, even
                # if the subagent emitted fenced or trailing prose.
                try:
                    final = json.dumps(parsed, ensure_ascii=False)
                except (TypeError, ValueError) as _e:
                    log_fn(
                        f"[orchestrator] {tag} JSON re-serialize failed: "
                        f"{_e} — keeping original text"
                    )

        # Persist this subagent's final response to the shared scratch
        # so the NEXT spawn picks it up via the prior_block prepend
        # above. Cap each entry's body at ~4 KB to bound the file
        # growth across many spawns.
        try:
            entry = (
                f"\n\n## {tag} ({datetime.now().isoformat(timespec='seconds')})"
                f"{cost_note}\n"
                f"PROMPT_HEAD: {sub_prompt[:400]}\n\n"
                f"FINAL:\n{final[:4000]}\n"
                f"=== /{tag} ===\n"
            )
            with sub_log.open("a") as f:
                f.write(entry)
        except OSError as _e:
            log_fn(f"[orchestrator] scratch log append failed: {_e}")

        # Phase 1: persist to per-job cache so a future identical
        # (sub_type, prompt) spawn hits instantly. Skipped on empty
        # replies (handled inside _store_subagent_cache).
        _store_subagent_cache(
            work_dir, cache_key, sub_type, sub_prompt, final,
            float(sub_summary.get("cost_usd", 0.0)), spawn_idx, log_fn,
        )

        return {"content": [{"type": "text", "text": final}]}

    server = create_sdk_mcp_server(
        name=server_name,
        version="1.0.0",
        tools=[spawn_subagent],
    )
    tool_name_full = f"mcp__{server_name}__spawn_subagent"
    return server, tool_name_full


def budget_exceeded(tool_calls: int, work_dir: Path, expected: tuple[str, ...]) -> bool:
    """Trip-wire: True when the agent has burned `INVESTIGATION_BUDGET`
    tool calls without producing any of the expected output files.

    Used by analyzers as a circuit breaker — better to abort early
    and let the user retry with a hint than to let the SDK exhaust
    the conversation context and exit with 'Prompt is too long'.
    Disabled by default (cap=0). Operators can re-enable by setting
    INVESTIGATION_BUDGET=<positive int> in .env if they want a hard
    abort instead of letting the SDK exhaust its context. The soft
    prompt budget mentioned in the system prompt is still 10.
    """
    try:
        cap = int(os.environ.get("INVESTIGATION_BUDGET", "0"))
    except ValueError:
        cap = 0
    if cap <= 0:
        return False
    if tool_calls < cap:
        return False
    for name in expected:
        if (work_dir / name).is_file():
            return False
    return True


_HEARTBEAT_MIN_INTERVAL_S = 5.0
_heartbeat_state: dict[str, float] = {}
# Separate throttle for phase_heartbeat. Keyed on job_id alone, NOT on the
# actor: several subagents run concurrently and a per-actor key would multiply
# the write rate by the fan-out.
_phase_heartbeat_state: dict[str, float] = {}
# Per-job accumulators. Each AssistantMessage emits a usage dict that
# is the API call's own totals (NOT job-cumulative), so we have to
# sum across turns to get the real spend. We also dedupe by
# message_id when available — Anthropic occasionally re-emits the
# same message snapshot during a stream and we don't want to
# double-count it.
_token_state: dict[str, dict[str, int]] = {}
_token_seen_ids: dict[str, set[str]] = {}
_token_turns: dict[str, int] = {}

SOFT_EJECT_USER_TURN = """\
⏰ TOOL-CALL BUDGET ALERT — you have burned 80%+ of the
INVESTIGATION_BUDGET (default 100 tool calls per analyzer run) WITHOUT
an `./exploit.py` artifact on disk. Job d8decbd77ed9 hit this exact
state at 80 calls and burned the remaining 20 on more recon delegations
before BUDGET_ABORT shut it down with no artifact produced.

What you MUST do BEFORE your next investigation step:

  1. WRITE THE DRAFT. Even your second-best hypothesis is better than
     `agent_error_kind=budget` with `exploit_present=false`. The auto-
     retry loop will inject postjudge feedback so you can refine it —
     that loop CANNOT start until exploit.py exists.
  2. If your chain depends on a heap technique, START FROM A SCAFFOLD
     instead of from scratch:
         cp /opt/scaffold/heap_menu.py ./exploit.py     # menu chal
     and import the helpers (`safe_link`, `build_full_chain`,
     `aslr_retry`) so you DON'T re-derive the boilerplate.
  3. Set `context.timeout = 10` and add `timeout=` on every recv-family
     call. The judge will flag unbounded recvs as HIGH severity.
  4. Write `./report.md` even if it's just "currently best guess: X
     because Y; unconfirmed assumptions: Z".

You can keep investigating AFTER the draft lands. The trip-wire is one-
shot per job; it won't re-warn. The HARD abort fires at 100 calls.
"""


FINAL_DRAFT_USER_TURN = """\
🛑 LAST CHANCE — INVESTIGATION BUDGET EXHAUSTED. You have made 100
tool calls without writing `./exploit.py`. The orchestrator was about
to abort the job entirely, but is giving you ONE MORE TURN to land a
draft from your CURRENT understanding (even an incomplete or
speculative one). DO NOT investigate further this turn — just write.

What to write THIS TURN, in order, AND THEN END YOUR TURN:

  1. Open `./exploit.py` (Write tool). Use `/opt/scaffold/heap_menu.py`
     as a starting point if the chal is menu-driven — even just
     `cp /opt/scaffold/heap_menu.py ./exploit.py` and edit the prompt
     strings is good enough. If you have no scaffold candidate, write
     a pwntools skeleton with your best-known offsets / one_gadget /
     trigger sequence. The script DOES NOT have to succeed; it has
     to EXIST so the orchestrator can sandbox it, surface the failure
     to postjudge, and feed you a real retry hint next round.

  2. Open `./report.md` and write WHAT YOU KNOW so far: vuln class,
     primitive class, glibc version, candidate technique, one-line
     run command. Even a draft report saves the next agent (or you
     in the next /retry) from re-doing the analysis.

  3. END YOUR TURN. The sandbox runs, postjudge fires, and the
     auto-retry loop hands you actionable feedback — that is the
     channel that turns a partial exploit into a working one. The
     #1 reason chals fail is "exploit.py never written" — past 100
     tool calls of analysis is sunk cost; the only path to a flag is
     a runnable script + postjudge iteration.

If genuinely nothing can be drafted (chal is opaque even to your best
guess), explicitly `Bash(rm -f ./exploit.py)` and write the report
explaining what you tried — the orchestrator will mark the job
no_flag instead of failed, which is still better than `budget` with
empty artifacts.
"""


SCAFFOLD_MISSING_USER_TURN = """\
🪜 SCAFFOLD NUDGE — this is a HEAP / FSOP / tcache / UAF challenge
(detected from your description or recon's CANDIDATES) but you've
made {n} tool calls without using any of the /opt/scaffold/ templates.
The scaffolds encode invariants that judge has historically flagged
as HIGH severity when written from scratch:

  /opt/scaffold/heap_menu.py
    — alloc / free / edit / show wrappers + libc_profile.json loader +
      `safe_link(target, chunk)` + `assert_libc_base()`.
      Just: `cp /opt/scaffold/heap_menu.py ./exploit.py` then fill
      the prompt strings.

  /opt/scaffold/fsop_wfile.py
    — `_IO_FILE_plus` / `_IO_wide_data` / `_wide_vtable` builders
      that ENFORCE the "vtable LAST" ordering (the documented #1
      cause of FSOP SIGSEGVs). Use `build_full_chain(fake_file_addr=...,
      doallocate_addr=...)` and flip vtable separately afterward.

  /opt/scaffold/tcache_poison.py
    — `safe_link()` auto-branches on libc_profile.json safe_linking.
      `key_bypass_needed()` for glibc >= 2.29 and patched 2.28.

  /opt/scaffold/aslr_retry.py
    — `aslr_retry(exploit_one, max_attempts=64)` for nibble-race
      chains; `expected_attempts_for(success_rate)` for sizing.

If the chal is NOT menu-shaped (e.g. single-shot ROP, custom protocol),
ignore this — but say so explicitly in report.md so the judge knows
why you skipped them. This nudge fires once per job.
"""


CONTRARIAN_REFRAME_USER_TURN = """\
⚠️ ORCHESTRATOR INTERRUPT — POSSIBLE FRAME LOCK-IN.

An independent subagent just returned evidence that DISCONFIRMS a core
assumption of your current approach (a "no primitive" / "premise wrong" /
"proven wrong" / "dead end" signal), and this run has now spent enough
that continuing on the same frame risks grinding to no result. This is a
checkpoint, NOT an instruction to give up. Before you spend anything more:

  1. STATE, in one sentence, the load-bearing ASSUMPTION your current
     plan depends on. Then ask: did a subagent just contradict it with
     concrete evidence (ASM, a failed primitive, a proof)? If yes, you
     may NOT re-subordinate that evidence back under the frame — when an
     experiment disproves the premise, the experiment wins, not the plan.

  2. SPAWN ONE subagent whose prompt does NOT assume your current frame
     is correct. Tell it explicitly: "find a DIFFERENT solution path, or
     argue this challenge needs a different frame / cannot be solved as
     currently approached." Do not pre-commit it to your existing
     heap/oracle/ROP/etc narrative — a spawn that inherits your framing
     cannot falsify it.

  3. THEN CHOOSE: (a) pursue a genuinely different approach the contrarian
     surfaced, or (b) conclude this frame is disproven and write up what
     you actually have in report.md (including the confirmed primitives)
     rather than repeating the ruled-out chain.

If your assumption genuinely still holds despite the signal, say why in
one line and proceed — this fires once per job and won't nag again.
"""


# ---- Cost / framing circuit-breaker configuration ----
# Framing-INDEPENDENT hard ceiling on TOTAL spend (main's cumulative cost +
# the subagent sum + reviewer calls — see _total_spend / the cost-cap note for
# why these are disjoint). Historically a backstop against runaway grinding
# when an anchored model won't abandon a disconfirmed frame (job 78bd896e0f3c: 51
# turns / ~5h, ~$27 all-in, with no stop mechanism).
#
# Armed at $40: the historical hard-solve observation is $30+ all-in, while a
# reviewer averages $0.19 (28 measured calls / $5.33). That keeps meaningful
# headroom for a difficult solve and its reviews while bounding the observed
# $131.70 non-converging lineage far below its eventual loss. Set <=0 only for
# an explicit operator override that accepts unbounded spend.
DEFAULT_COST_CAP_USD = 40.0


def cost_cap_usd() -> float:
    """Worker-side COST_CAP_USD reader with a safe numeric fallback."""

    try:
        return float(os.environ.get("COST_CAP_USD", str(DEFAULT_COST_CAP_USD)))
    except (TypeError, ValueError):
        return DEFAULT_COST_CAP_USD


# Minimum TOTAL spend before a subagent dead-end signal is allowed to arm
# the contrarian reframe (Tooth 1). The forensic point-of-no-return on job
# 78bd896e0f3c was ~$7 all-in — below this, a "no primitive yet" reply is
# just normal early exploration, not evidence of a locked-in frame. Override
# with CONTRARIAN_MIN_COST_USD.
DEFAULT_CONTRARIAN_MIN_COST_USD = 6.0

# Generic author-tone "this is easy / take the shortcut" framing. When an
# operator description minimizes difficulty or implies a cheap intended
# path, an anchored model is likelier to lock onto a single "intended"
# frame and grind past disconfirming evidence. Presence of any of these
# arms the contrarian breaker (Tooth 1) so a dead-end signal can trigger a
# reframe. Kept to GENERIC tone words ONLY — no phrasing lifted from the
# one challenge that motivated it (job 78bd896e0f3c) — so it does not
# overfit. A false arm is low-harm: it only adds ONE reframe user-turn, and
# only when a dead-end signal ALSO fires past the spend threshold.
_EASY_FRAMING_KEYWORDS = (
    "easy", "simple", "trivial", "shortcut", "short cut",
    "one line", "one-line", "one-liner", "beginner",
    "warmup", "warm-up", "baby chal", "babyheap", "baby heap",
)

# Subagent-reply signals that a core premise of the current frame is
# disconfirmed. Focused on high-precision markers ("no primitive",
# "premise/assumption wrong", refute/disprove, "dead end", "structural
# deadlock", "no viable path") to keep false positives low; the arm is
# additionally gated by easy_framing + a spend threshold + one-shot.
_DEADEND_REPLY_RE = re.compile(
    r"no\s+(?:write|useful|viable|exploitable|working)\s+primitiv"
    r"|(?:premise|assumption)\s+(?:is\s+|was\s+)?(?:wrong|false|incorrect|flawed|invalid)"
    r"|(?:disprove|disproven|disproved|refute|refuted|contradict)"
    r"|proven\s+(?:wrong|false|impossible)"
    r"|structural\s+deadlock"
    r"|dead[\s-]?end"
    r"|no\s+(?:viable|working|feasible)\s+(?:path|chain|exploit|approach)"
    r"|cannot\s+be\s+(?:exploited|solved)\s+as",
    re.IGNORECASE,
)


def _detect_easy_framing(description: str | None) -> bool:
    """True when the operator description leans on difficulty-minimizing or
    shortcut-implying language (arms the contrarian reframe breaker). Pure
    substring scan over GENERIC tone words — see `_EASY_FRAMING_KEYWORDS`."""
    if not description:
        return False
    low = description.lower()
    return any(kw in low for kw in _EASY_FRAMING_KEYWORDS)


_TOKEN_KEYS = (
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)


_MODEL_USAGE_KEYMAP = {
    "inputTokens": "input_tokens",
    "outputTokens": "output_tokens",
    "cacheCreationInputTokens": "cache_creation_input_tokens",
    "cacheReadInputTokens": "cache_read_input_tokens",
}


def _tokens_from_model_usage(model_usage: dict) -> dict[str, int]:
    """Fold the SDK's per-model `model_usage` into our flat token schema.

    Accepts both the camelCase wire keys and the snake_case aliases; unknown
    keys are ignored. Returns {} when nothing usable is present, so the caller
    can fall back to the streamed sum.
    """
    out: dict[str, int] = {}
    try:
        for per_model in model_usage.values():
            if not isinstance(per_model, dict):
                continue
            for k, v in per_model.items():
                dest = _MODEL_USAGE_KEYMAP.get(k, k if k in _TOKEN_KEYS else None)
                if dest and isinstance(v, (int, float)):
                    out[dest] = out.get(dest, 0) + int(v)
    except Exception:
        return {}
    return out if any(out.values()) else {}


def _accumulate_tokens(
    job_id: str, usage: dict | None, message_id: str | None = None,
) -> dict[str, int]:
    """SUM the SDK's per-turn usage into a job-scoped running total.

    Anthropic's `usage` field is per-API-call (each AssistantMessage
    has the totals for that one call), NOT job-cumulative. Taking
    max() across turns under-reports massively for any non-trivial
    run: 50 turns of 4k input each → real spend 200k, but max-only
    shows 4k.

    Dedupe by message_id when present so an SDK stream snapshot that
    re-emits the same Assistant message doesn't double-count.
    """
    if not isinstance(usage, dict):
        return _token_state.get(job_id, {})
    if message_id:
        seen = _token_seen_ids.setdefault(job_id, set())
        if message_id in seen:
            return _token_state.get(job_id, {})
        seen.add(message_id)
    cur = _token_state.setdefault(job_id, {})
    for k in _TOKEN_KEYS:
        v = usage.get(k)
        if isinstance(v, (int, float)) and v > 0:
            cur[k] = cur.get(k, 0) + int(v)
    _token_turns[job_id] = _token_turns.get(job_id, 0) + 1
    return cur


# Live flag-candidate scan: surface possible flags WHILE the job runs so
# the operator can submit fast (the `[FLAG?]` box), WITHOUT writing them
# into the curated meta.flags / FLAG FOUND. Accumulated per job from the
# streamed agent messages; the operator-declared flag_format (if set)
# narrows the matcher so local LOCAL{...} test flags never appear.
_flag_candidate_state: dict[str, set[str]] = {}
_flag_fmt_cache: dict[str, object] = {}
_FMT_UNSET = object()


def _job_scan_re(job_id: str):
    """Cached per-job flag matcher (operator format if set, else FLAG_RE).
    read_meta runs once per job, not once per streamed message."""
    cached = _flag_fmt_cache.get(job_id, _FMT_UNSET)
    if cached is _FMT_UNSET:
        try:
            cached = job_flag_format_re(job_id)
        except Exception:
            cached = None
        _flag_fmt_cache[job_id] = cached
    return cached or FLAG_RE


def _extract_msg_text(msg) -> str:
    """Best-effort plain text from an SDK message (AssistantMessage
    TextBlocks + UserMessage tool-result content) for the candidate scan."""
    parts: list[str] = []
    content = getattr(msg, "content", None)
    if isinstance(content, str):
        parts.append(content)
    elif isinstance(content, list):
        for block in content:
            t = getattr(block, "text", None)
            if isinstance(t, str):
                parts.append(t)
            c = getattr(block, "content", None)
            if isinstance(c, str):
                parts.append(c)
            elif isinstance(c, list):
                for sub in c:
                    st = getattr(sub, "text", None)
                    if isinstance(st, str):
                        parts.append(st)
    return "\n".join(parts)


def _accumulate_flag_candidates(job_id: str, msg) -> bool:
    """Scan one streamed message for flag candidates (format-aware) +
    explicit `FLAG_CANDIDATE:` markers; accumulate per job. Returns True
    when a NEW candidate was added (used to flush the heartbeat
    immediately so a found flag shows up without the 5s throttle delay).
    Cheap: a regex over the message text, matcher cached, no disk I/O."""
    text = _extract_msg_text(msg)
    # The `{` fast-path is for the FORMAT-AWARE regex only. `FLAG_CANDIDATE:`
    # is documented as format-agnostic ("works for DH{...}, FLAG{...}, raw-hex,
    # or any prefix-less format"), so gating the whole function on a brace made
    # that promise false for exactly the brace-less formats it names: a
    # raw-hex capture never reached the LIVE meta.flag_candidates the UI shows,
    # only the post-run file scan (which has no such guard).
    if not text or ("{" not in text and "FLAG_CANDIDATE" not in text.upper()):
        return False
    found = set(_job_scan_re(job_id).findall(text))
    for raw in _FLAG_MARKER_RE.findall(text):
        cand = _MARKER_ESCAPE_RE.split(raw.strip(), 1)[0].strip().strip("\"'`").strip()
        # Reduce a prose-embedded marker to its PREFIX{...} brace-flag (see
        # _scan_markers in scan_job_for_flags); brace-less flags kept as-is.
        # Same whitespace parity as job_flag_format_re (see :1350).
        _bf = re.search(r"\w{1,15}\{[^\s}]{1,256}\}", cand)
        if _bf:
            cand = _bf.group(0)
        elif re.search(r"\s", cand):
            # No brace-flag AND the tail has whitespace → this is not a flag
            # token, it is SOURCE CODE. The marker regex takes the rest of the
            # line, and the agent's own solver contains the line that PRINTS
            # the marker: `print("FLAG_CANDIDATE: " + m.group(0).decode())`
            # streams past here and yielded the candidate
            # `+ m.group(0).decode())` on job a4729b5d91f2. A real emitted flag
            # is one whitespace-free token on its own line, brace-less formats
            # included — so this rejects the parse artifact without touching
            # flag curation, which stays manual and the operator's.
            continue
        if cand:
            found.add(cand)
    fresh = {f for f in found if f and not _is_placeholder_flag(f)}
    if not fresh:
        return False
    acc = _flag_candidate_state.setdefault(job_id, set())
    before = len(acc)
    acc.update(fresh)
    return len(acc) > before


def phase_heartbeat(job_id: str, actor: str, msg) -> None:
    """Liveness ONLY, for the SDK loops that are not the main session.

    `agent_heartbeat` is main's loop. It also carries the token/cost ledger,
    and that ledger is deliberately per-actor: the subagent loop's own comment
    says subagent tool calls belong on the subagent's ledger, and summing a
    stream twice is exactly how agent_tokens once came out at EXACTLY 2.0000x
    (see _accumulate_tokens). So this writes the three liveness fields and
    NOTHING else — no usage, no cost, no turns, no flag scan.

    Without it, `meta.last_agent_event_at` freezes for the entire duration of
    every subagent delegation, pre-recon, and report phase — the job is working
    hard and the timestamp says it has been quiet for ten minutes. Observed on
    job 06f3a326d453: main's last event 10:35:49, `recon#1` still emitting at
    10:42:19, and the UI's age readout stuck at 6m40s throughout.

    `actor` is what to CALL the thing that is alive ("main", "pre-recon",
    "report", "recon#1"). Both this and agent_heartbeat always write it, so it
    can never go stale and describe the wrong actor.
    """
    # `_time` is a function-local import everywhere else in this module; the
    # broad `except` below would have swallowed the NameError and turned this
    # whole function into a silent no-op.
    import time as _time
    try:
        now = _time.monotonic()
        if now - _phase_heartbeat_state.get(job_id, 0.0) < _HEARTBEAT_MIN_INTERVAL_S:
            return
        _phase_heartbeat_state[job_id] = now
        write_meta(
            job_id,
            last_agent_event_at=datetime.now(timezone.utc).isoformat(),
            last_event_kind=type(msg).__name__,
            last_event_actor=actor,
        )
    except Exception:
        # Liveness is cosmetic. It must never be able to break a running phase.
        pass


def agent_heartbeat(job_id: str, msg) -> None:
    """Throttled write of agent liveness + token/cost tracking to
    meta.json. Called from each analyzer's SDK message loop on every
    received message (Assistant/User/System/Result/etc.).

    Liveness: meta.last_agent_event_at + last_event_kind refreshed
    on a 5-second throttle so disk I/O stays bounded.

    Tokens: AssistantMessage.usage cumulative-by-turn maxes are
    merged into meta.agent_tokens. ResultMessage.total_cost_usd is
    merged into meta.cost_usd.

    Result messages always flush (never throttled) so the final
    numbers are accurate the moment the run ends.
    """
    import time as _time
    kind = type(msg).__name__
    is_result = kind == "ResultMessage"

    # Live flag-candidate scan (always, before the throttle) so no flag is
    # missed; a NEW candidate force-flushes below so it shows up at once.
    new_candidate = _accumulate_flag_candidates(job_id, msg)

    # Token accumulation (lock-free per-process dict). Always update
    # in-memory; flush at most once per 5s except on Result.
    updates: dict = {}
    usage = getattr(msg, "usage", None)
    msg_id = getattr(msg, "message_id", None)
    # A ResultMessage carries `usage` too — but it is the SESSION-CUMULATIVE
    # total, and its dataclass has NO `message_id`, so the dedupe guard in
    # _accumulate_tokens cannot see it. Summing it added the whole session a
    # second time: measured EXACTLY 2.0000x against the SDK's own `model_usage`
    # on all three jobs on disk (cache_creation and cache_read both). Every
    # displayed token count and every cost estimate derived from them was
    # double. Only per-turn AssistantMessages feed the accumulator.
    tokens = (_token_state.get(job_id, {}) if is_result
              else _accumulate_tokens(job_id, usage, msg_id))
    turns = _token_turns.get(job_id, 0)

    session_cost = None
    if is_result:
        cost = getattr(msg, "total_cost_usd", None)
        if isinstance(cost, (int, float)):
            # + earlier sessions of this same job (stop -> continue in place),
            # otherwise each session's cumulative total overwrites the last.
            updates["cost_usd"] = prior_session_cost(job_id) + float(cost)
            # THIS session's figure, un-summed. meta.cost_usd is the job total;
            # the usage ledger wants one row per session, so adding the prior
            # sessions again there would double every earlier one.
            session_cost = float(cost)
        # Result also carries the SDK's own authoritative model_usage
        # — surface alongside our running sum for cross-checking.
        model_usage = getattr(msg, "model_usage", None)
        if isinstance(model_usage, dict):
            updates["model_usage"] = model_usage
            # AUTHORITATIVE. Pricing these totals reproduces the SDK's own
            # total_cost_usd to the cent (c552faf18d31: $12.4872 computed vs
            # $12.487236750000001 reported), so prefer them over our streamed
            # sum for everything the operator sees.
            _auth = _tokens_from_model_usage(model_usage)
            if _auth:
                # Seed the accumulator, and let the SINGLE explicit
                # `agent_tokens=` kwarg below pick it up via `tokens`.
                # Putting it in `updates` instead collided with that kwarg —
                # `write_meta() got multiple values for keyword argument
                # 'agent_tokens'` — which blew up the FINAL heartbeat of every
                # job (jobs 3452d4d7956e, c1669e159e2c: flag captured, then
                # meta.error stamped with the TypeError and the last token /
                # cost numbers never written).
                _token_state[job_id] = dict(_auth)
                tokens = _auth

    now = _time.monotonic()
    last = _heartbeat_state.get(job_id, 0.0)
    # A newly-found flag candidate bypasses the 5s throttle so it appears
    # in the `[FLAG?]` box immediately.
    throttled = (not is_result) and (not new_candidate) and (now - last < _HEARTBEAT_MIN_INTERVAL_S)
    if throttled:
        return
    _heartbeat_state[job_id] = now

    # IN-FLIGHT spend estimate. `cost_usd` is only ever set from a
    # ResultMessage, so a long-running job reports NOTHING to the usage pill
    # for its whole life: job c552faf18d31 sat at cost_usd=None for 4 hours
    # while burning 12.8M cache-read tokens (~$7 by token estimate) plus
    # $1.34 of judge subagents, and /api/jobs/usage counted it as $0. Park a
    # running estimate under its OWN key so the aggregator can fall back to
    # it — never under `cost_usd`, which is the authoritative SDK number and
    # whose meaning must not be diluted (an earlier estimate-into-cost_usd
    # bug poisoned the spend meter; see the _snapshot_cost fix).
    # The job's provider and model, resolved ONCE. Both the estimate below and
    # the usage-ledger row further down need them, and resolving them
    # separately let them disagree: the estimate omitted the provider, so it
    # fell through to whatever Settings says NOW, while the ledger row used the
    # job's create-time snapshot. A job stamped `claude` with no model override,
    # running while Settings said `gpt`, produced a row reading
    # model=claude-opus-4-8 with a dollar figure computed at gpt-5.6-luna rates
    # — $0.13 against $0.625 for the model the row names. Resolving once makes
    # that divergence impossible rather than asking two call sites to agree.
    _job_provider = None
    _job_model = None
    try:
        from modules.agent_provider import provider_for_job as _pfj

        _job_provider = _pfj(job_id)
        _job_model = resolve_main_model(read_meta(job_id).get("model"), _job_provider)
    except Exception:
        pass

    if tokens and "cost_usd" not in updates:
        try:
            # RESOLVE the model — do not read meta.model raw. That key holds the
            # per-job OVERRIDE and is null whenever the operator didn't pick a
            # model in the form, which is the common case: the real model then
            # comes from the preset / global setting. Passing that null fell
            # through to _rates_for_model's unknown-model default and priced an
            # opus-5 run at the legacy $15/$75 — the live job c552faf18d31 was
            # parked at $13.28 against a true-rate estimate of $7.14.
            est = estimate_cost_from_tokens(tokens, _job_model)
            if est > 0:
                updates["cost_usd_estimate"] = round(est, 4)
        except Exception:
            pass

    candidates = sorted(_flag_candidate_state.get(job_id) or [])
    write_meta(
        job_id,
        last_agent_event_at=datetime.now(timezone.utc).isoformat(),
        last_event_kind=kind,
        # Always written, so a subagent's actor tag can never linger and
        # mislabel main's own event (phase_heartbeat writes it too).
        last_event_actor="main",
        agent_tokens=tokens or None,
        agent_turns=turns or None,
        flag_candidates=candidates or None,
        **updates,
    )

    if is_result:
        # One usage-ledger row per MAIN session. Separate from meta because a
        # hybrid job's spend is in two units that must not be added: Claude
        # reports dollars, Codex OAuth reports none and is metered in windows.
        # See modules/usage_ledger.py. Entirely best-effort — accounting must
        # never break the run it is accounting for.
        try:
            from modules.agent_provider import get_gpt_runtime
            from modules.usage_ledger import (
                codex_window_snapshot,
                record_usage_by_model,
            )

            # Same values the estimate above was priced with — see the comment
            # there. Never re-resolve here.
            _prov = _job_provider or "claude"
            # The cost contract is per BACKEND, not per provider name, and a
            # turn is not necessarily single-model: the Responses adapter
            # merges every subagent's usage into the parent map, and the
            # preset can pin a subagent to a different model. Both concerns
            # live in usage_ledger.record_usage_by_model, shared with the
            # judge wiring — the model-collapse defect was found once in each
            # because the logic lived in neither.
            _runtime = get_gpt_runtime() if _prov == "gpt" else None
            record_usage_by_model(
                job_id,
                role="main",
                stage="main",
                provider=_prov,
                primary_model=_job_model,
                model_usage=updates.get("model_usage"),
                tokens=tokens,
                reported_cost=session_cost,
                estimate_for=estimate_cost_from_tokens,
                rates_known=model_rates_are_known,
                gpt_runtime=_runtime,
                window_for=lambda: codex_window_snapshot(cached_only=True),
                # Cumulative-per-session cost plus a stream that can re-emit a
                # Result means the same session must not add a second row.
                dedupe_key=getattr(msg, "session_id", None) or None,
            )
        except Exception:
            pass

    # SSE meta delta — fires on the same throttle as write_meta so the
    # frontend never gets out of sync with on-disk meta.json.
    meta_payload: dict = {
        "kind": kind,
        "turns": turns,
    }
    if tokens:
        meta_payload["tokens"] = tokens
    if "cost_usd" in updates:
        meta_payload["cost_usd"] = updates["cost_usd"]
    if candidates:
        meta_payload["flag_candidates"] = candidates
    if is_result:
        meta_payload["is_result"] = True
    _publish(job_id, "meta", meta_payload)


# Per-job map { tool_use_id: subagent_type } — populated when the main
# agent emits an Agent/Task tool_use, consulted when a subagent's reply
# message comes back with parent_tool_use_id pointing at that id. Lets
# us tell apart `recon` / `judge` / `debugger` (all subagents; all
# inherit parent_tool_use_id) so the run.log per-line prefix is precise.
_subagent_registry: dict[str, dict[str, str]] = {}


def agent_tag(msg, job_id: str | None = None) -> str:
    """Return a stable identifier for whichever agent emitted `msg`.

    Subagents inherit the `parent_tool_use_id` of the Task/Agent call
    that spawned them. With `job_id` provided we can look up which
    specific subagent (recon | judge | debugger) the parent invocation
    targeted; without it we fall back to the legacy "recon" tag for
    any subagent.

    As a side effect, when `job_id` is given we also pre-register any
    Agent/Task tool_use blocks present in THIS message so subsequent
    subagent replies can be tagged correctly.
    """
    parent = getattr(msg, "parent_tool_use_id", None)
    if job_id:
        # Pre-register tool_use blocks in this message (typically main's
        # own AssistantMessage that just kicked off the subagent).
        content = getattr(msg, "content", None)
        if isinstance(content, list):
            registry = _subagent_registry.setdefault(job_id, {})
            for block in content:
                tu_id = getattr(block, "id", None)
                if not tu_id:
                    continue
                name = getattr(block, "name", None)
                if name not in ("Task", "Agent"):
                    continue
                inp = getattr(block, "input", None) or {}
                if isinstance(inp, dict):
                    stype = inp.get("subagent_type")
                    if isinstance(stype, str) and stype:
                        registry[tu_id] = stype
    if not parent:
        return "main"
    if job_id:
        sub = _subagent_registry.get(job_id, {}).get(parent)
        if sub:
            return sub
    return "recon"


def capture_session_id(msg, job_id: str) -> None:
    """If `msg` is the SDK 'init' SystemMessage, persist its session_id
    to meta.json so a later /retry or /resume can fork the conversation
    (carrying full reasoning history, not just the work/ artifacts).

    Tolerant of variant SDK shapes — duck-types `subtype` and `data`,
    no-ops if the message isn't an init or has no usable session_id.
    """
    subtype = getattr(msg, "subtype", None)
    if subtype != "init":
        return
    data = getattr(msg, "data", None)
    sid = None
    if isinstance(data, dict):
        sid = data.get("session_id") or data.get("sessionId")
    if not sid:
        return
    # `claude_session_id` is what /retry feeds to `claude --resume <sid>
    # --fork-session`. A Grok ACP session id lives in the Grok agent process,
    # not in ~/.claude/projects/<key>/<sid>.jsonl, so writing one there hands
    # /retry an id the Claude CLI rejects outright:
    #   {"subtype":"error_during_execution","errors":["No conversation found
    #    with session ID: ..."]}
    # (verified against the pinned CLI, not just the SDK bundle).
    #
    # This never mattered while a job used one backend end to end. The AUP
    # recovery ladder's `other_provider` rung makes a mid-job switch possible,
    # and grok_acp yields a SYNTHETIC init SystemMessage whose subtype really
    # is "init" — so the early return above does not save us. Keep the
    # provider-neutral field always; gate only the Claude-specific one.
    # Read the JOB's provider, not Settings'. active_provider() reflects the
    # global setting, which still says "claude" after a per-job AUP switch —
    # so gating on it would never fire on the one path that needs it.
    # _aup_restart_session stamps meta.agent_provider when it switches.
    try:
        _is_claude = (read_meta(job_id) or {}).get("agent_provider") == "claude"
    except Exception:
        _is_claude = True
    if _is_claude:
        # Historical field name kept for /retry resume compatibility;
        # agent_session_id is provider-neutral.
        write_meta(job_id, claude_session_id=sid, agent_session_id=sid)
    else:
        write_meta(job_id, agent_session_id=sid)


_RETRY_HINT_MARKER = "[retry-hint]"


def module_autoboot(
    module: str,
    work_dir: Path,
    log_fn,
    *,
    extras: dict | None = None,
) -> dict:
    """Generic per-module autoboot hook (Item 5).

    Centralizes the "before main's first turn, pre-bake environment +
    write a breadcrumb file" pattern that pwn's _autobootstrap_libc
    already does in a heavy way. For non-pwn modules this is light:
    we record what the worker container can do for that module and
    drop an `AUTOBOOT.md` into work_dir so every subagent (recon /
    debugger) can read the same orientation breadcrumbs instead of
    re-discovering them per spawn (Item 3 — subagent isolation cost).

    The pwn module continues to call its own `_autobootstrap_libc` for
    the heavy chal-libc-fix / libc_profile.json / decomp pre-bake; this
    function is the LIGHT companion that records the module's flavor.

    Returns a small summary dict the caller can merge into its
    `summary` so postjudge / judge can see what autoboot did.
    """
    extras = extras or {}
    autoboot_md = work_dir / "AUTOBOOT.md"
    parts: list[str] = [
        f"# Autoboot summary ({module})",
        "",
        "This file is generated BEFORE main's first turn. It captures the",
        "environment + module-specific orientation tips so every subagent",
        "starts from the same baseline (see Item 3 — context-sharing).",
        "",
        "## What's in the worker container",
    ]
    # Module-specific orientation. These mirror the per-module TOOLS_*
    # blocks in the SYSTEM_PROMPT, but as on-disk breadcrumbs so a
    # subagent that reads ./AUTOBOOT.md gets the highlights without
    # having to absorb the full TOOLS_* in its prompt.
    if module == "pwn":
        parts.append("- chal-libc-fix already ran; check ./.chal-libs/")
        parts.append("- libc_profile.json present iff chal-libc-fix found a libc + ld pair")
        parts.append("- /opt/scaffold/ contains pwn templates (heap_menu / fsop_wfile / aslr_retry / tcache_poison)")
        parts.append("- /opt/how2heap/ has shellphish PoCs keyed by glibc version")
        parts.append("- decomp pre-staged into ./decomp/ when ghiant ran during autoboot")
        parts.append("")
        parts.append("## Running the binary with chal libs")
        parts.append("```")
        parts.append("# Preferred (RPATH'd by chal-libc-fix):")
        parts.append("./prob")
        parts.append("# If RPATH not set, fall back to:")
        parts.append("LD_LIBRARY_PATH=./.chal-libs ./bin/<binary_name>")
        parts.append("# If ld.so version mismatch: try patchelf manually:")
        parts.append("patchelf --set-interpreter $(realpath ./.chal-libs/ld-*.so 2>/dev/null || echo /lib64/ld-linux-x86-64.so.2) \\")
        parts.append("         --set-rpath './.chal-libs' ./bin/<binary_name>")
        parts.append("```")
        parts.append("")
        parts.append("## Sibling docker (cross-arch / RV64 / QEMU / different glibc)")
        parts.append("The worker has `/var/run/docker.sock` mounted, so `docker run ...` from inside")
        parts.append("the worker spawns a SIBLING container on the host daemon — NOT a child of the")
        parts.append("worker. Volume mounts therefore resolve against the **host** filesystem, not")
        parts.append("the worker container's filesystem. `/tmp` inside the worker is invisible to")
        parts.append("the host docker daemon; mounting it gives the sibling an empty directory.")
        parts.append("")
        parts.append("Use the `HOST_DATA_DIR` env var (pre-set by docker-compose) plus the per-job")
        parts.append("subdir to give the sibling container access to your work tree:")
        parts.append("```")
        parts.append("docker run --rm -v \"$HOST_DATA_DIR/jobs/$JOB_ID/work:/work\" \\")
        parts.append("    ubuntu:24.04 bash -c 'ls /work && /work/bin/<binary>'")
        parts.append("```")
        parts.append("`JOB_ID` is also pre-set. Confirm both are non-empty before invoking docker:")
        parts.append("`echo \"HOST_DATA_DIR=$HOST_DATA_DIR JOB_ID=$JOB_ID\"`.")
    elif module == "web":
        parts.append("- curl/httpx/requests available; pwntools for raw-socket")
        parts.append("- sqlmap for URL-driven SQLi probes")
        parts.append("- prefer fuzzing common params (id, page, search, cmd, url, file) before deep source review")
        parts.append("")
        parts.append("## Reflexive checks (don't skip)")
        parts.append("- robots.txt / sitemap.xml / .git/ / .env / backup files")
        parts.append("- header injection (Host:, X-Forwarded-For:, X-Original-URL:)")
        parts.append("- common bypass classes: SSRF (gopher://, file://), IDOR (parameter sequence walk), race (concurrent submit)")
    elif module == "crypto":
        parts.append("- pycryptodome / gmpy2 / sympy / z3-solver / ecdsa available")
        parts.append("- fpylll available (LLL/BKZ/GSO/enum) — Coppersmith / HNP biased-nonce / LWE without a Sage round-trip")
        parts.append("- sage NOT in THIS container, but a separate Sage sandbox (image pre-pulled) runs solver.sage for EC ops / small_roots / discrete_log")
        parts.append("- BENCH a .sage BEFORE ship (its decisive Gröbner/variety/resultant/small_roots is otherwise UNMEASURED): `python3 -m worker.sage_smoke <script.sage> [args] --timeout N` times ONE run in that sandbox; for a remote/multi-stage oracle build a local synthetic bench.sage (don't burn the one-shot target). Never claim 'sub-second' from the literature — measure. alarm()-guard EVERY solve incl. the variety() fallback")
        parts.append("- a deterministic pre-analysis (param extraction + RSA auto-factor) may already be in your prompt — check it first")
        parts.append("- before deep math: encrypt a known plaintext through the oracle and OBSERVE patterns")
    elif module == "rev":
        parts.append("- ghiant pre-bake (cached project under ./.ghidra_proj/)")
        parts.append("- gdb / strace / ltrace / qemu-{arm,aarch64}-static")
        parts.append("- BEFORE deep disasm: run with 5 varied inputs (empty, random, structured, expected, edge)")
    elif module in ("forensic", "misc"):
        parts.append("- exiftool / yara / binwalk results already in findings.json")
        parts.append("- carved artifacts in extracted/")
        parts.append("- check entropy histogram before assuming encryption")
    else:
        parts.append(f"- (module={module}) no module-specific notes")

    # Sandbox / scratch dir hint — applies to ALL modules.
    parts.append("")
    parts.append("## Scratch / temp")
    parts.append("- $TMPDIR is pre-set to ./tmp/ (per-job, isolated)")
    parts.append("- Prior subagent summaries: ./.scratch/subagent_log.md (auto-prepended to each new spawn)")

    if extras:
        parts.append("")
        parts.append("## Module-specific autoboot output")
        for k, v in extras.items():
            parts.append(f"- {k}: {v}")

    try:
        autoboot_md.write_text("\n".join(parts) + "\n")
        log_fn(f"[autoboot] wrote AUTOBOOT.md ({autoboot_md.stat().st_size} B)")
    except OSError as e:
        log_fn(f"[autoboot] AUTOBOOT.md write failed: {e}")

    return {
        "module": module,
        "autoboot_md": str(autoboot_md.name),
        "extras": dict(extras),
    }


def docker_challenge_block(job_id: str) -> str:
    """Prompt stanza injected ONLY when the operator ticked the 'Docker
    challenge' box (``meta.docker_challenge``). Deterministically DETECTS a
    bundled Dockerfile / compose file under ``./bin/`` and instructs the agent
    to BUILD + RUN it as the real runtime and dynamic oracle.

    Design (opt-in, additive):
      - Returns "" when the box is unticked, so the caller's ``if block:``
        guard drops it cleanly and pre-existing / non-docker jobs are wholly
        unaffected.
      - Wired into web/rev/crypto/misc/forensic/web3 — and, since 2026-08-09,
        pwn. Web retains its always-available optional system guidance when the
        box is off; the opt-in block makes BUILD + RUN mandatory when it is on.
        The original note here claimed "web and pwn already build+run challenge
        Dockerfiles unconditionally in their own prompts". Web only offered it
        as an OPTIONAL agent decision (see `modules/web/prompts.py`, "RUN THE
        CHALLENGE LOCALLY"), and the claim was FALSE of pwn, whose prompts
        overwhelmingly say to READ a Dockerfile for deploy
        context (sysctl knobs, xinetd) with a single parenthetical about
        building one. Acting on that false premise is what kept pwn out of the
        opt-in, and job b914889c1f9c paid for it: the agent verified a 2 MiB
        libc-alignment premise against the STAGED libc, assumed the remote
        matched "from identical deployment image", and burned 10,000 remote
        attempts on a chain whose premise a local `docker build` falsifies in
        seconds.
      - DETECTION is deterministic (scan the OPERATOR-SUPPLIED upload roots).
        When enabled, BUILD + RUN is mandatory; only the run parameters and
        interaction are agent-driven because a CTF ENTRYPOINT almost always
        needs the right input (e.g. ``main flag.png``). The flag therefore comes
        from the agent using the container interactively, not a blind auto-run.
      - Cleanup is handled by ``reap_chal_containers`` (label
        ``hextech_job=<id>``), which the SAME modules now call at start+finally
        whenever this box is set — so a container the agent spins up here can't
        orphan (see the WSL2-orphan-shadows-port class).
    """
    if not (read_meta(job_id) or {}).get("docker_challenge"):
        return ""
    job_root = JOBS_DIR / job_id
    # WHERE OPERATOR-SUPPLIED challenge files land, per module:
    #   rev/pwn -> ./bin/ , crypto/web -> ./src/ (extracted) , misc/forensic ->
    #   the job-dir root itself.
    # This deliberately does NOT recursively scan the whole job dir. misc and
    # forensic run their collector with `--out /job` (= the job ROOT) BEFORE
    # this prompt is built, so a recursive scan walks CARVE/EXTRACT OUTPUT and
    # would happily present a Dockerfile recovered FROM THE EVIDENCE IMAGE as
    # "the challenge bundle" — i.e. instruct the agent to build+run untrusted
    # carved content. (It also made the walk unbounded: a forensic job dir is
    # multi-GB, and `sorted(rglob("*"))` materialised the whole tree before the
    # result cap could bound anything.) So: job-root TOP-LEVEL files only, plus
    # bin/ and src/ recursively with scratch/noise dirs PRUNED at every level.
    _noise = {"work", "__pycache__", ".git", ".ghidra_proj", "decomp",
              "node_modules", ".venv", "tmp", ".scratch"}
    # ...with ONE carve-out. pwn's autoboot unpacks the operator's upload into
    # `work/chal/` and flattens only the binaries into `bin/`, so for a pwn
    # bundle the Dockerfile lives inside the very directory `work` prunes. The
    # result was worse than silence: with the box ticked this reported "found
    # NOTHING" about a bundle that shipped one (job b914889c1f9c). `work/chal`
    # is the deterministic unpack target of the OPERATOR's own archive, not
    # agent scratch, so it is safe in a way the rest of `work/` is not — the
    # forensic hazard this pruning exists for is carved EVIDENCE output, which
    # never lands there.
    _extra_roots = [job_root / "work" / "chal"]
    _compose = {
        "docker-compose.yml", "docker-compose.yaml",
        "compose.yml", "compose.yaml",
    }

    def _is_target(name: str) -> bool:
        # Match suffixed variants too (`Dockerfile.challenge`, `chal.dockerfile`)
        # — matching only the bare name produced a confident "found NOTHING" on
        # a bundle that clearly shipped one.
        n = name.lower()
        return (
            n == "dockerfile" or n.startswith("dockerfile.")
            or n.endswith(".dockerfile") or n in _compose
        )

    found: list[str] = []
    truncated = 0
    _MAX = 12

    def _add(p: Path) -> None:
        nonlocal truncated
        try:
            rel = p.relative_to(job_root).as_posix()
        except ValueError:
            return
        if rel in found:
            return
        if len(found) >= _MAX:
            truncated += 1
            return
        found.append(rel)

    try:
        for p in sorted(job_root.iterdir()):
            if p.is_file() and _is_target(p.name):
                _add(p)
    except OSError:
        pass
    for base in [job_root / t for t in ("bin", "src")] + _extra_roots:
        if not base.is_dir():
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(base):
                dirnames[:] = [d for d in dirnames if d not in _noise]
                for fn in sorted(filenames):
                    if _is_target(fn):
                        _add(Path(dirpath) / fn)
        except OSError:
            pass

    header = (
        "DOCKER CHALLENGE (you opted in via the 'Docker challenge' box)\n"
        "--------------------------------------------------------------\n"
    )
    if not found:
        return (
            header
            + "You ticked 'Docker challenge' but I found NO Dockerfile / compose "
            "file in the operator-supplied bundle (searched /data/jobs/$JOB_ID "
            "top level plus ./bin/, ./src/ and ./work/chal/ recursively). Run "
            "`ls -R /data/jobs/$JOB_ID/bin /data/jobs/$JOB_ID/src "
            "/data/jobs/$JOB_ID/work/chal 2>/dev/null; ls "
            "/data/jobs/$JOB_ID` to confirm. If the challenge genuinely needs a "
            "container, locate its build file yourself and proceed; otherwise "
            "just do normal static/dynamic analysis — this note is not a "
            "blocker."
        )
    # Build context = the dir holding the first plain Dockerfile (else the first
    # detected file's dir; a file at the job root → the job dir itself). Absolute
    # /data/... paths so it works from ANY module's cwd (rev=./bin, crypto=./src,
    # misc/forensic=job root) — the worker mounts /data and a build context from
    # a worker-local path is fine (the CLI tars+sends it). QUOTED in the emitted
    # command: an extracted dir name with a space would otherwise produce a
    # syntactically broken line the agent has been told to run.
    _df = next((f for f in found if f.lower().endswith("dockerfile")), found[0])
    _ctx_rel = _df.rsplit("/", 1)[0] if "/" in _df else ""
    ctx = "/data/jobs/$JOB_ID" + (f"/{_ctx_rel}" if _ctx_rel else "")
    listed = ", ".join(f"/data/jobs/$JOB_ID/{f}" for f in found)
    if truncated:
        listed += f" (+{truncated} more not listed — `ls -R` to see them all)"
    # Never claim more coverage than the reaper actually has, and never let a
    # job-root build context read as safe: for misc/forensic the job root also
    # holds the uploaded evidence/artifact AND the collector's carve output, so
    # `docker build` there would tar gigabytes, and anything recovered FROM an
    # evidence image is untrusted input, not a challenge bundle.
    ctx_note = ""
    if not _ctx_rel:
        ctx_note = (
            "\n- ⚠ CONTEXT IS THE JOB ROOT: it also holds the uploaded "
            "artifact/image and (misc/forensic) the collector's extract/carve "
            "output, so `docker build` would tar ALL of it. Copy the Dockerfile "
            "plus only the files it COPYs into a small dir first (e.g. `mkdir "
            "-p /tmp/ctx && cp ... /tmp/ctx`) and build from there.\n"
            "- ⚠ PROVENANCE: confirm this file is the OPERATOR-SUPPLIED "
            "challenge bundle, not something recovered from the evidence image "
            "you are analysing. NEVER build+run carved/extracted content — "
            "treat it as untrusted data and analyse it statically instead."
        )
    return (
        header
        + f"Detected in the challenge bundle: {listed}. This challenge is meant "
        "to run INSIDE its own container — BUILD IT AND RUN IT, and use the "
        "running container as the real runtime and the dynamic oracle. This "
        "worker has the docker CLI and the host docker socket mounted.\n"
        "Mechanics — ALWAYS pass `--label hextech_job=$JOB_ID`: the orchestrator "
        "reaps by that label at job end, but a hard kill/timeout can skip it, so "
        "also prefer `--rm` and stop anything you no longer need:\n"
        f'- Build:  `docker build -t chal_$JOB_ID "{ctx}"`  (build context = the '
        "dir holding the Dockerfile; the CLI tars+sends it, so this worker-local "
        f"path is fine here).{ctx_note}\n"
        "- Run:    `docker run --rm --label hextech_job=$JOB_ID --name "
        "chal_$JOB_ID chal_$JOB_ID <args>`  — pass the input file / args the "
        "ENTRYPOINT+CMD expect; add `-i`/`-t` or pipe stdin as needed.\n"
        "- INTERACT: the flag rarely falls out of a blind run — a CTF ENTRYPOINT "
        "usually needs the RIGHT input (e.g. `main flag.png`). Drive the "
        "container the way the challenge expects: feed candidate inputs, read "
        "its verdict (Correct!/Wrong!/output), iterate. For a shell inside the "
        "intended env use `docker run -it --label hextech_job=$JOB_ID "
        "chal_$JOB_ID bash` (override the entrypoint with `--entrypoint bash` if "
        "needed) or `docker exec`.\n"
        "- VERIFY, DON'T ASSUME: a static reconstruction / offline derivation is "
        "NOT a confirmation — run it against THIS container and confirm the "
        "binary actually accepts it (prints the success path) before you claim "
        "the flag.\n"
        "- compose: `docker compose` is NOT installed here; if only a compose "
        "file ships, read it and translate each service to `docker build` / "
        "`docker run` (label every container `hextech_job=$JOB_ID`, join them on "
        "a `chal_${JOB_ID}_net` network if they must talk).\n"
        "- REACHING IT from here — you run inside the WORKER container and "
        "the docker daemon is the HOST's, so three obvious routes all fail, "
        "each in a different way (job 1ede2b4d8ac3 spent turns on this): "
        "`-p 127.0.0.1::8080` publishes on the HOST loopback, not yours -> "
        "ConnectionRefused; the container's own bridge IP (172.17.x.x) is on "
        "a different network from the worker -> timeout; `docker top` reports "
        "HOST pids, so `/proc/<that pid>/maps` does not exist in your PID "
        "namespace -> No such file.\n"
        "  WHAT WORKS (verified): publish with `-p 8080`, read the port back "
        "with `docker port <name> 8080/tcp`, and connect to your "
        "DEFAULT-ROUTE GATEWAY on it — parse `/proc/net/route` for the "
        "`00000000` destination (little-endian hex), e.g. 172.18.0.1:32768. "
        "To inspect INSIDE the container use `docker exec <name> /bin/sh -c "
        "'...'`, and end a `for p in /proc/[0-9]*` loop with `; true` or a "
        "non-matching last iteration exits 1.\n"
        "- HOST-PATH gotcha: the daemon is the HOST's, so any `-v` volume path "
        "must be a HOST path — use `$HOST_DATA_DIR/jobs/$JOB_ID/...`, NOT the "
        "container-local `/data/...` (the `docker build <dir>` context is exempt)."
    )


# NOTE: modules/pwn/analyzer.py carries its own `_JS_ENGINE_DATA` /
# `_JS_ENGINE_NAMES` for the STAGING half of this feature (it runs before
# any prompt exists and must not import a prompt helper). The two pairs
# agree today and will drift if only one is edited — change both.
#
# SCOPE, stated honestly: the anchor is V8's external-startup-data output, so
# TODAY this detects V8/Chromium builds only. SpiderMonkey and JSC ship no
# such file — their names are in the shell tuple so a future anchor for them
# has one less thing to change, NOT because they are covered.
_JS_ENGINE_ANCHORS = ("snapshot_blob.bin",)
_JS_ENGINE_SHELLS = ("d8", "js", "jsc", "js_shell", "chakra", "ch",
                     "spidermonkey")


def js_engine_block(job_id: str) -> str:
    """Prompt stanza injected when the bundle ships a PREBUILT JS ENGINE
    (d8 / SpiderMonkey js / JSC) — i.e. a browser-pwn challenge.

    Detection is deterministic and anchored on ``snapshot_blob.bin`` sitting
    next to an executable, not on the binary's name: the file is essentially
    never present in an ordinary chal, so the block cannot fire on a normal
    pwn/web job, while a renamed engine shell still resolves.

    The block is pure GUIDANCE (no suppression, no tool invocation), so it is
    safe to wire into any module. The suppressive half — skipping
    chal-libc-fix / ghiant, staging the engine WITH its runtime data — lives
    in the pwn autoboot, which owns ``./bin/``.

    Everything here is engine-level and version-agnostic on purpose: field
    NAMES and the version windows they apply to, never byte offsets, and no
    reference to any particular challenge's patched builtin.
    """
    job_root = JOBS_DIR / job_id
    _noise = {"work", "__pycache__", ".git", ".ghidra_proj", "decomp",
              "node_modules", ".venv", "tmp", ".scratch", "obj"}
    engine_rel: str | None = None
    # `work/bin` is explicit because `work` is in _noise: the pwn module STAGES
    # the engine there (autoboot unpacks the upload into work/chal/ and flattens
    # the engine + its runtime data into work/bin/), so a pwn job that uploaded
    # a .zip — the exact case this feature exists for — has NOTHING matching
    # under ./bin/ or ./src/ and the block silently returned "". Caught by a live
    # smoke test, not by review. Only that one subtree is opened up; the rest of
    # work/ (scratch, tmp, decomp, .ghidra_proj) stays pruned.
    for top in (".", "bin", "src", "work/bin"):
        base = job_root if top == "." else job_root / top
        if not base.is_dir():
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(base):
                dirnames[:] = [d for d in dirnames if d not in _noise]
                if not any(a in filenames for a in _JS_ENGINE_ANCHORS):
                    continue
                here = Path(dirpath)
                names = sorted(filenames)
                shells = [n for n in names if n in _JS_ENGINE_SHELLS]
                if not shells:
                    # No recognisable name — take the largest executable file
                    # sitting with the snapshot blob. HARD-CAPPED: this
                    # function runs at prompt-build time on EVERY pwn and web
                    # job, and pruning `_noise` only stops the walk from
                    # DESCENDING — the anchor directory's own file list is
                    # whatever the bundle put there. Never stat an unbounded
                    # number of entries for a fallback this speculative.
                    execs = [
                        n for n in names[:200]
                        if (here / n).is_file() and os.access(here / n, os.X_OK)
                    ]
                    shells = sorted(
                        execs,
                        key=lambda n: (here / n).stat().st_size, reverse=True,
                    )[:1]
                if shells:
                    engine_rel = (here / shells[0]).relative_to(
                        job_root).as_posix()
                    break
        except OSError:
            continue
        if engine_rel:
            break
    if not engine_rel:
        return ""

    preflight = ""
    if (job_root / "work" / "V8_PREFLIGHT.md").is_file():
        preflight = (
            "A deterministic preflight — version, the globals this build "
            "actually exposes, whether --allow-natives-syntax works, the build "
            "config, and the patch SPLIT into 'candidate bug' vs 'd8 "
            "attack-surface removal' — is already in `./V8_PREFLIGHT.md`. "
            "READ IT FIRST; it is fact, not speculation.\n"
        )

    # ABSOLUTE path, mirroring docker_challenge_block: every module's agent runs
    # with cwd=<job>/work, so a job-root-relative path ("src/extracted/...")
    # does NOT resolve from where the agent actually stands. When the engine was
    # staged by pwn autoboot the ./bin/ shorthand does work — offer both.
    engine_abs = f"/data/jobs/$JOB_ID/{engine_rel}"
    shorthand = ""
    if engine_rel.startswith("work/"):
        shorthand = (
            f"  From your cwd that is `./{engine_rel[len('work/'):]}`.\n"
            "NOTE — autoboot deliberately SKIPPED chal-libc-fix and the Ghidra "
            "pre-bake for this job, so `./prob`, `./.chal-libs/libc_profile.json` "
            "and `./decomp/` DO NOT EXIST and the libc/heap/ROP parts of your "
            "instructions do not apply. The engine ships no chal libc, and "
            "decompiling a multi-MB engine build is not how these are solved. Do "
            "not go looking for those files, and do not run `ghiant` on the "
            "engine.\n"
        )

    return (
        "JS-ENGINE (BROWSER PWN) CHALLENGE — auto-detected\n"
        "--------------------------------------------------\n"
        f"Engine shell: `{engine_abs}`\n"
        + shorthand +
        "Its runtime data lives in the SAME directory: the engine resolves "
        "`snapshot_blob.bin` relative to argv[0]'s DIRECTORY, so a copy of the "
        "binary on its own will NOT start. Run it in place, or copy the whole "
        "directory.\n"
        + preflight +
        "\n"
        "STAGE MAP — name the stage you are on in every status line; "
        "conflating them is the classic failure mode here:\n"
        "  1. TRIGGER    get the patched path to actually RUN in optimized code\n"
        "  2. PRIMITIVE  turn the divergence into an OOB read/write on the JS heap\n"
        "  3. addrof / fakeobj -> arbitrary R/W INSIDE the sandbox cage\n"
        "  4. ESCAPE     cage-relative R/W is NOT code execution when "
        "v8_enable_sandbox=true; you need a RAW pointer\n"
        "  5. RCE        shellcode/ROP -> run whatever reads the flag\n"
        "\n"
        "STAGE 1 — traps that look like 'the bug does not reproduce':\n"
        "- A patched `JSCallTyper` case can be INERT. `JSCallReducer` inlines "
        "many builtins into machine-level nodes BEFORE TyperPhase, so the "
        "patched case never executes. Force the call site to "
        "`SpeculationMode::kDisallowSpeculation`: warm -> optimize -> call ONCE "
        "with a non-number argument (a string, or `{valueOf(){...}}`) -> re-warm "
        "-> re-optimize. Confirm with `--trace-turbo-reduction`: you want the "
        "node reduced 'by reducer Typer', not 'by reducer JSCallReducer'.\n"
        "- A `Math.min`/`Math.max` clamp can LAUNDER a NaN-poisoned value: "
        "under the bogus type the clamp has been observed to return the "
        "non-NaN operand, so the poison is gone while the type still looks "
        "wrong and every downstream check quietly agrees. Do not assume the "
        "lowering — CHECK what your build emits (`--print-opt-code`) — but "
        "prefer a ternary clamp (`v = v > 3 ? 3 : v`), which keeps the value "
        "itself intact.\n"
        "- `|0` and `>>>0` are TRUNCATING uses -> `TruncateFloat64ToWord32` "
        "(NaN -> 0). They never produce 0x80000000; only a NON-truncating "
        "Signed32 consumer reaches the unchecked `ChangeFloat64ToInt32`.\n"
        "- PROVE the divergence before building on it: under optimization, "
        "`v === v` folding to `true` while the runtime value is NaN is direct "
        "evidence the typer is wrong.\n"
        "\n"
        "STAGE 2 — CheckBounds hardening (aborting bounds checks) landed in "
        "V8 ~7.4 (early 2019). CONFIRM which side of that your build is on "
        "before choosing an approach: on an OLDER build the classic "
        "typer-range bounds-check elimination still works and is the short "
        "path. On a hardened build a typer range that 'proves' the index "
        "in-bounds no longer deletes the check — it deopts with `reason: out "
        "of bounds`; if you see that, stop re-rolling the same shape and use "
        "one of these instead:\n"
        "- `LOAD_IGNORE_OUT_OF_BOUNDS` / `STORE_IGNORE_OUT_OF_BOUNDS` "
        "element-access feedback: a SEPARATE `NumberLessThan(index, length)` is "
        "emitted and IS constant-folded by the bogus type. The IC must have SEEN "
        "an OOB access before optimization for that feedback to exist.\n"
        "- induction-variable phi typing (`TypeInductionVariablePhi`).\n"
        "- a const-folded length (in-function array literal) vs a global whose "
        "length is not const-folded — only the former folds the compare.\n"
        "\n"
        "STAGE 4 — WHERE the raw pointers live depends on the ENGINE VERSION:\n"
        "- sandbox disabled: no escape stage at all.\n"
        "- V8 ~11.0 up to ~12.2: `WasmInstanceObject` still holds RAW pointers "
        "(`jump_table_start`, `memory_start`) INSIDE the cage -> spray shellcode "
        "as `i64.const` immediates in a wasm function, overwrite "
        "`jump_table_start`, then call the export.\n"
        "- V8 >= ~12.2: those fields moved to `WasmTrustedInstanceData` outside "
        "the cage -> go through the trusted-pointer / code-pointer tables.\n"
        "DERIVE THE OFFSETS EMPIRICALLY for the build in front of you "
        "(`%DebugPrint`, gdb via `%SystemBreak`, or allocate a "
        "`WebAssembly.Memory` of known size and match the pointer). NEVER "
        "hardcode an offset from a writeup — they move between minor versions, "
        "and a stale offset reads as 'the technique does not work'.\n"
        "\n"
        "WORKFLOW\n"
        "- Triage LOCALLY with `--allow-natives-syntax` (`%DebugPrint`, "
        "`%OptimizeFunctionOnNextCall`, `%SystemBreak`) plus `--trace-deopt`, "
        "`--trace-turbo-reduction`, `--print-opt-code`.\n"
        "- The REMOTE service almost never passes that flag. Every primitive "
        "must be re-proven with plain warm-up loops (~0x20000 iterations) "
        "before it goes into the shipped exploit.\n"
        "- Read the service's runner script FIRST: these challenges usually cap "
        "the payload size and terminate input on a sentinel. A 4 KB exploit is "
        "worthless against a 2 KB cap — find the cap before you write, not "
        "after.\n"
        "- Deliverable is still `./exploit.py` (pwntools): connect, send the JS, "
        "print `FLAG_CANDIDATE: <flag>`."
    )


def reap_chal_containers(job_id: str, log_fn=None, *, reason: str = "") -> int:
    """Tear down any LOCAL challenge containers/networks a job spun up.

    Web (and pwn) agents may `docker build`/`docker run` the challenge's
    own Dockerfile/compose locally to understand the real runtime env and
    test the exploit end-to-end before the remote (the prompt prescribes a
    job-scoped name `chal_<job_id>`, the label `hextech_job=<job_id>`, and —
    for multi-service stacks — the network `chal_<job_id>_net`). The worker
    talks to the host docker daemon over the mounted socket, so these are
    HOST siblings that DON'T die with the job: a SIGKILL/OOM skips the
    finally block, orphaning a container that holds a port + RAM (see the
    WSL2-orphan-shadows-port class). So this reaps by the job label both at
    job START (sweep stale leftovers from a prior crashed run of the SAME
    id) and at job END (finally). Idempotent + best-effort — never raises;
    a missing docker / no matches is a silent no-op. Returns the number of
    containers removed.

    Keyed on the label so it catches anything the agent tagged regardless
    of how it named/ran it; also reaps the compose project + the job net.
    """
    import subprocess
    import socket as _socket

    def _run(args, timeout=60):
        try:
            return subprocess.run(
                ["docker", *args], capture_output=True, text=True,
                timeout=timeout,
            )
        except Exception:
            return None

    label = f"hextech_job={job_id}"
    proj = f"chal_{job_id}"
    net = f"chal_{job_id}_net"
    removed = 0
    try:
        ids: set[str] = set()
        for filt in (
            f"label={label}",
            f"label=com.docker.compose.project={proj}",
            f"name=^{proj}",
        ):
            r = _run(["ps", "-aq", "--filter", filt], timeout=30)
            if r and r.returncode == 0 and r.stdout.strip():
                ids.update(r.stdout.split())
        if ids:
            r = _run(["rm", "-f", *sorted(ids)], timeout=90)
            if r and r.returncode == 0:
                removed = len(ids)
        # Drop the job network: disconnect THIS worker first (it joined the
        # net to reach the chal by service-name), else `network rm` blocks.
        _run(["network", "disconnect", "-f", net, _socket.gethostname()],
             timeout=20)
        _run(["network", "rm", net], timeout=20)
        if removed and log_fn:
            log_fn(
                f"[chal-docker] reaped {removed} local challenge "
                f"container(s) for {job_id}"
                + (f" ({reason})" if reason else "")
            )
    except Exception as e:  # noqa: BLE001 - teardown must never break the job
        if log_fn:
            log_fn(f"[chal-docker] teardown best-effort error: {e}")
    return removed


def split_retry_hint(description: str | None) -> tuple[str, str]:
    """Split a job description into (base, retry_hint).

    /retry, /retry/stream, /resume, /resume/stream all stitch the next
    attempt's guidance onto the previous description as
    `<original>\\n\\n[retry-hint]\\n<hint>`. We split on the LAST
    occurrence so chained retries always surface the freshest hint;
    everything before that marker is treated as base context.

    Both halves are stripped. Either may be empty (e.g. fresh job has
    no marker → all base, no hint; pure retry of an empty description
    → no base, only hint).
    """
    if not description:
        return "", ""
    idx = description.rfind(_RETRY_HINT_MARKER)
    if idx == -1:
        return description.strip(), ""
    base = description[:idx].strip()
    hint = description[idx + len(_RETRY_HINT_MARKER):].strip()
    return base, hint


def prior_work_dirs(job_id: str) -> list[Path]:
    """Return prior-attempt work directories for a retry/resume chain.

    Walks the `retry_of` / `resumed_from` lineage in meta.json so the
    caller can include those dirs as fallbacks when collecting agent
    artifacts. The forked SDK session sometimes re-uses absolute
    paths (`/data/jobs/<prev_id>/work/...`) from the prior tool
    history — without this fallback the new run's exploit.py /
    report.md silently lands in the OLD job dir while the new one
    keeps the unmodified carry-copy. Bounded walk (8 hops) so a
    pathological chain can't loop forever.
    """
    seen: set[str] = set()
    out: list[Path] = []
    cur = read_meta(job_id) or {}
    for _ in range(8):
        prev = cur.get("retry_of") or cur.get("resumed_from")
        if not prev or prev in seen:
            break
        seen.add(prev)
        candidate = job_dir(prev) / "work"
        if candidate.is_dir():
            out.append(candidate)
        cur = read_meta(prev) or {}
        if not cur:
            break
    return out


def classify_agent_error(message: str) -> str | None:
    """Return a short error_kind tag for known SDK / Claude failure modes."""
    if not message:
        return None
    low = message.lower()
    if any(h in low for h in REFUSAL_HINTS):
        return "policy_refusal"
    if "rate" in low and "limit" in low:
        return "rate_limit"
    if "timeout" in low or "timed out" in low:
        return "timeout"
    if "auth" in low or "401" in low or "credential" in low:
        return "auth"
    if "exit code -9" in low or "sigkill" in low or "killed by signal 9" in low:
        return "killed"
    # Bundled `claude` CLI failed to start / died on spawn. exit 127 +
    # "symbol lookup error" is the signature of the worker's glibc being
    # polluted (e.g. the agent patchelf'd / ldconfig'd global libs while
    # reproducing a remote env), so the CLI loads the wrong libc. This is
    # an INFRA failure, not a chal failure — job 1da4ac550c9f cascaded
    # judge/prejudge/postjudge/report this way while ending status=no_flag
    # with error=null. (See memory agent_libpollution_breaks_worker_cli.)
    if ("exit code 127" in low or "symbol lookup error" in low
            or "cliconnectionerror" in low
            or "cannot write to terminated process" in low):
        return "cli_infra_error"
    return "unknown"


def _safe_agent_exception_details(
    exc: BaseException,
) -> tuple[str, str, str]:
    """Return exception type, message, and traceback without raising.

    This runs after the main SDK transport has already failed.  A hostile or
    partially-initialized exception can itself raise from ``__str__`` or
    ``__getattribute__``; losing the recovery path while trying to describe
    that first failure is worse than recording a placeholder message.  Frame
    formatting is deliberately separate from exception formatting so a bad
    ``__str__`` cannot discard an otherwise usable traceback.
    """
    exc_type = "Exception"
    try:
        candidate = type(exc).__name__
        if isinstance(candidate, str) and candidate:
            exc_type = candidate
    except BaseException:
        pass

    try:
        message = str(exc)
    except BaseException:
        message = "<exception message unavailable>"

    try:
        exc_tb = object.__getattribute__(exc, "__traceback__")
    except BaseException:
        exc_tb = None
    try:
        frames = traceback.format_tb(exc_tb) if exc_tb is not None else []
    except BaseException:
        frames = []

    terminal = f"{exc_type}: {message}"
    if frames:
        rendered = "Traceback (most recent call last):\n" + "".join(frames) + terminal
    else:
        rendered = "Traceback unavailable\n" + terminal
    return exc_type, message, rendered


# Approximate per-million-token prices in USD (Anthropic public pricing,
# 2026-Q2). Used as a FALLBACK when the SDK's authoritative
# `ResultMessage.total_cost_usd` never arrives — e.g. the bundled
# `claude` CLI gets SIGKILLed mid-stream before emitting the final
# accounting message, leaving meta.cost_usd at $0.00 even for runs
# that obviously spent dollars.
# Tuple shape: (input, cache_create, cache_read, output) per Mtok.
# ORDER MATTERS: _rates_for_model takes the FIRST substring hit, so the
# version-specific entries must precede the bare family name.
# The Opus family was repriced from $15/$75 to $5/$25 per Mtok at 4.6; the
# single "opus" row below still carried the OLD numbers, so every estimate for
# an opus-4.6+/opus-5 run came out ~3x high. Measured against real
# ResultMessage costs on finished opus-5 jobs, the old row produced 4.2x and
# 5.2x overestimates.
_MODEL_RATES_USD_PER_MTOK = {
    # OpenAI GPT-5.6 family (Responses API). Explicit cache-write pricing is
    # 1.25x input; cached reads use the documented discounted input rate.
    "gpt-5.6-terra": (2.5, 3.125, 0.25, 15.0),
    "gpt-5.6-luna":  (1.0, 1.25,  0.10,  6.0),
    "gpt-5.6-sol":   (5.0, 6.25,  0.50, 30.0),
    "gpt-5.6":       (5.0, 6.25,  0.50, 30.0),
    "opus-5": (5.0,  6.25,  0.50, 25.0),
    "opus-4-8": (5.0, 6.25, 0.50, 25.0),
    "opus-4-7": (5.0, 6.25, 0.50, 25.0),
    "opus-4-6": (5.0, 6.25, 0.50, 25.0),
    "fable":  (10.0, 12.50, 1.00, 50.0),
    "opus":   (15.0, 18.75, 1.50, 75.0),   # opus <= 4.5, the old pricing
    "sonnet": (3.0,  3.75,  0.30, 15.0),
    "haiku":  (1.0,  1.25,  0.10, 5.0),
}


def _rates_for_model(model: str | None) -> tuple[float, float, float, float]:
    if model:
        low = model.lower()
        for needle, rates in _MODEL_RATES_USD_PER_MTOK.items():
            if needle in low:
                return rates
    # Unknown model. This used to return the bare "opus" row as a "conservative
    # upper bound", but that row is now the LEGACY (<= 4.5) pricing — since the
    # 4.6 repricing it over-reports a modern Opus run by 3x, which is not
    # conservative, just wrong. Default to the CURRENT Opus rates: that is the
    # family this deployment actually runs, and it is still the most expensive
    # of the modern tiers, so it stays an upper bound among plausible models.
    return _MODEL_RATES_USD_PER_MTOK["opus-5"]


# Failure fields across every adapter. `errors` is a LIST on the Claude SDK
# ResultMessage and is where its parser puts the wire's error payload; GPT and
# Grok carry `stop_reason` and have no `result` at all. Reading only one of
# these is how a structured AUP block came back classified as a generic error.
AGENT_FAILURE_ATTRS = ("errors", "result", "error", "error_detail", "api_error_status")

_STOP_REASON_KIND = {
    "timeout": "timeout",
    "process_error": "transport_error",
    "unexpected_eof": "transport_error",
    "eof": "transport_error",
    "cancelled": "killed",
    "canceled": "killed",
    "max_tokens": "agent_error",
    "max_tool_rounds": "agent_error",
}
_AGENT_FAILURE_DETAIL_MAX_CHARS = 2000


def structured_failure_bits(msg: Any) -> list[str]:
    """Authoritative failure strings an adapter/SDK set on a result message.

    Shared deliberately. This extraction lived in the judge only, so the
    reviewer — asked the SAME question about the SAME SDK object — answered
    `api_error` where the judge answered `policy_refusal`, and the
    policy-refusal-only failover never fired. Third time in this work that
    logic living in one caller instead of between them produced the same
    defect twice.
    """
    bits: list[str] = []
    for attr in AGENT_FAILURE_ATTRS:
        value = getattr(msg, attr, None)
        if not value:
            continue
        if isinstance(value, (list, tuple, set)):
            bits.extend(str(v) for v in value if v)
        else:
            bits.append(str(value))
    stop_reason = getattr(msg, "stop_reason", None)
    if stop_reason:
        bits.append(str(stop_reason))
    return bits


def classify_failure_kind(detail: str, fallback: str) -> str:
    """`classify_agent_error`, with "unknown" treated as UNclassified.

    It answers "unknown" rather than None when nothing matched, so the
    `... or "fallback"` idiom is dead code — every unrecognised failure came
    back tagged "unknown", which tells a reader nothing about where it
    happened.
    """
    kind = classify_agent_error(detail or "")
    return fallback if kind in (None, "", "unknown") else kind


def classify_result_failure(
    msg: Any, parts: list[str], fallback: str,
) -> tuple[str, str]:
    """Classify a failed provider result with structured fields first.

    Adapter ``stop_reason`` is authoritative for transport/process failures;
    assistant prose is consulted only when structured fields are ambiguous.
    This is shared by main and judge so the same ResultMessage cannot become a
    transport error in one path and ``unknown`` in the other.
    """

    structured = structured_failure_bits(msg)
    prose = "".join(parts).strip() if parts else ""
    detail = " | ".join(structured + ([prose] if prose else []))
    stored_detail = detail.strip(" |")[:_AGENT_FAILURE_DETAIL_MAX_CHARS]

    for source in structured:
        kind = classify_failure_kind(source, "")
        if kind:
            return kind, stored_detail

    stop_reason = str(getattr(msg, "stop_reason", "") or "").strip().lower()
    if stop_reason in _STOP_REASON_KIND:
        return _STOP_REASON_KIND[stop_reason], stored_detail

    tail = next((part for part in reversed(parts) if part and part.strip()), "")
    kind = classify_failure_kind(tail, "")
    if kind:
        return kind, stored_detail
    return fallback, stored_detail


def model_rates_are_known(model: str | None) -> bool:
    """True when the rate table has a row that actually matches `model`.

    `_rates_for_model` deliberately falls back to the current Opus row for
    anything it does not recognise, which is a defensible upper bound for the
    SPEND METER — but it is fabrication in a ledger. `grok-build` has no row,
    so its "estimate" is Opus-5 pricing applied to Grok tokens: not an
    inaccurate estimate, an estimate of nothing. Callers that record money
    must ask this first and record null instead.
    """
    low = (model or "").strip().lower()
    return bool(low) and any(needle in low for needle in _MODEL_RATES_USD_PER_MTOK)


def estimate_cost_from_tokens(
    tokens: dict | None, model: str | None,
) -> float:
    """Rough cost estimate from accumulated agent_tokens + model name.

    Schema (see `_accumulate_tokens` and `_TOKEN_KEYS`):
      tokens = {
        "input_tokens":               int,
        "output_tokens":              int,
        "cache_creation_input_tokens": int,
        "cache_read_input_tokens":    int,
      }
    Any missing key is treated as 0. Returns 0.0 if `tokens` is empty.
    """
    if not isinstance(tokens, dict) or not tokens:
        return 0.0
    inp = float(tokens.get("input_tokens") or 0)
    out = float(tokens.get("output_tokens") or 0)
    cw = float(tokens.get("cache_creation_input_tokens") or 0)
    cr = float(tokens.get("cache_read_input_tokens") or 0)
    r_in, r_cw, r_cr, r_out = _rates_for_model(model)
    return ((inp * r_in) + (cw * r_cw) + (cr * r_cr) + (out * r_out)) / 1_000_000.0


def prior_session_cost(job_id: str) -> float:
    """Spend already banked by EARLIER sessions of this same job.

    `ResultMessage.total_cost_usd` is cumulative for ONE SDK session, and both
    agent_heartbeat and the analyzers' finalize write it straight into
    `meta.cost_usd` — an OVERWRITE. A job that is stopped and continued in
    place (same job id, `/api/jobs/{id}/continue`) therefore ends up recording
    only its LAST session: job c552faf18d31 ran 5h17m across three sessions,
    the first two were stopped by the operator and never emitted a
    ResultMessage at all, and the ledger kept $12.49 against a token-based
    estimate of $23.92 for the whole job. Nearly half the spend vanished from
    the operator's total.

    `cost_usd_prior_sessions` is stamped once at session start with whatever
    `cost_usd` had reached, so the running total is prior + this session.
    """
    try:
        return float((read_meta(job_id) or {}).get("cost_usd_prior_sessions") or 0.0)
    except Exception:
        return 0.0


def extract_cost(claude_summary: dict | None) -> float:
    """Pull total_cost_usd out of an agent summary dict, returning 0.0 if absent.

    Preference order:
      1. summary['result']['total_cost_usd']  (authoritative — ResultMessage)
      2. summary['cost_usd_estimate']         (parked by _snapshot_cost when a
                                               ResultMessage cost was lost)
      3. summary['cost_usd']                  (LAST resort — note this key is
                                               the SUBAGENT spend accumulator,
                                               so it under-reports a job's cost;
                                               kept only for back-compat with
                                               summaries written before the
                                               estimate got its own key)
      4. estimate from summary['agent_tokens'] + summary['model']
         (so SIGKILL'd runs still show a non-zero, estimated spend, not $0.00).
    """
    if not isinstance(claude_summary, dict):
        return 0.0
    res = claude_summary.get("result")
    if isinstance(res, dict):
        v = res.get("total_cost_usd")
        if isinstance(v, (int, float)) and v > 0:
            return float(v)
    parked = claude_summary.get("cost_usd_estimate")
    if isinstance(parked, (int, float)) and parked > 0:
        return float(parked)
    direct = claude_summary.get("cost_usd")
    if isinstance(direct, (int, float)) and direct > 0:
        return float(direct)
    return estimate_cost_from_tokens(
        claude_summary.get("agent_tokens"),
        claude_summary.get("model"),
    )


def format_tool_result(content: Any, is_error: bool | None = None) -> str:
    """Render a tool result as ONE run.log line (newlines -> " | ").

    Tool results are otherwise invisible — the agent sees them, but the
    user just sees a TOOL line followed by silence until the agent's
    next message lands. Logging the result closes that gap.

    NOT a preview any more: the 300-char cut was removed in 101beba, so
    the body is written in FULL and only a 200 KB disaster valve remains
    (see the comment at the cap). run.log is the searchable record; the
    live SSE frame and the monitor apply their own, much smaller clamps.
    """
    text = ""
    if content is None:
        text = ""
    elif isinstance(content, str):
        text = content
    elif isinstance(content, list):
        # SDK shape: list of {"type": "text"|"image", "text": "..."} dicts.
        parts = []
        for blk in content:
            if isinstance(blk, dict):
                if blk.get("type") == "text" and isinstance(blk.get("text"), str):
                    parts.append(blk["text"])
                elif blk.get("type") == "image":
                    parts.append("<image>")
                else:
                    parts.append(str(blk)[:200])
            else:
                parts.append(str(blk)[:200])
        text = "\n".join(parts)
    else:
        text = str(content)
    text = text.replace("\n", " | ")
    text = text.strip()
    # TOOL_RESULT is logged IN FULL. The old 300-char "preview cut" was
    # removed 2026-07-26: run.log is now read with a filter/search (and the
    # curated live view is monitor.jsonl), so a 300-char preview cost more
    # than it saved. Measured over 17 jobs / 422 truncated lines before
    # removing it: full logging grows run.log 3.2 MB -> 4.7 MB total (1.4x),
    # because the SDK already bounds tool output upstream (median cut content
    # 1.3 KB, p90 10.8 KB, max 28 KB). It also un-hides signal: the monitor
    # checks its FLAG/ERROR patterns BEFORE discarding tool echo, so a flag or
    # a connection error past char 300 used to be invisible to it (370 of
    # those 422 lines showed no flag/error signal in their visible prefix).
    #
    # The bound below is a DISASTER VALVE, not a preview: nothing observed
    # comes close to it, but a pathological single result (a Read of a huge
    # generated file) must not put a megabyte on one log line.
    _HARD_MAX = 200_000
    if len(text) > _HARD_MAX:
        full_len = len(text)
        text = (
            text[:_HARD_MAX]
            + f" …(hard cap: {_HARD_MAX}/{full_len} bytes; trailing chars are "
            "mid-cut, not a complete token)"
        )
    prefix = "TOOL_RESULT"
    if is_error:
        prefix = "TOOL_ERROR"
    if not text:
        return f"{prefix}: (empty)"
    return f"{prefix}: {text}"


def log_thinking(log_fn, prefix: str, thinking_text: str) -> None:
    """Write a multi-line ThinkingBlock to run.log, line-by-line, so the
    user can see reasoning progress instead of one truncated 500-char
    blob. Caps each line at 500 chars and the whole burst at 2 KB.
    """
    if not thinking_text:
        return
    text = thinking_text[:2000]
    seen = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if len(line) > 500:
            line = line[:500] + "…"
        log_fn(f"{prefix}: {line}")
        seen += 1
        if seen >= 8:
            break


def format_tool_result_body(content: Any) -> str:
    """Extract the readable text from a ToolResultBlock.content (string,
    list of {type, text} dicts, or anything else stringifiable) WITHOUT
    truncation or newline normalization. Used for full-fidelity main
    agent logging — log_block then writes each line with its own
    timestamp + agent tag prefix.
    """
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for blk in content:
            if isinstance(blk, dict):
                if blk.get("type") == "text" and isinstance(blk.get("text"), str):
                    parts.append(blk["text"])
                elif blk.get("type") == "image":
                    parts.append("<image>")
                else:
                    parts.append(str(blk))
            else:
                parts.append(str(blk))
        return "\n".join(parts)
    return str(content)


def log_assistant_blocks(job_id: str, msg, summary: dict) -> None:
    """Walk an AssistantMessage's content blocks and write run-log
    entries. Main agent gets full-fidelity output (no truncation, real
    newlines, pretty-printed JSON tool inputs). Subagents (recon /
    judge) keep concise single-line previews — their job is to be
    short, and clipping their output keeps the timeline skimmable.

    Duck-types block class names so this helper can live in _common.py
    without importing the SDK at module load. Mutates `summary` to
    increment the tool_calls counter.

    Also publishes each block to the SDK SSE channel for the live
    "typing-effect" panel (Phase 4 — modules/_common._publish).
    """
    tag = agent_tag(msg, job_id)
    blocks = getattr(msg, "content", None)
    if not isinstance(blocks, list):
        return
    is_main = tag == "main"
    for block in blocks:
        kind = type(block).__name__
        if kind == "TextBlock":
            text = getattr(block, "text", "") or ""
            if is_main:
                log_block(job_id, "AGENT", text, tag=tag)
            else:
                log_line(job_id, f"[{tag}] AGENT: {text[:500]}")
            _publish(job_id, "sdk", {
                "kind": "text", "tag": tag, "text": text[:8000],
            })
        elif kind == "ToolUseBlock":
            summary["tool_calls"] = summary.get("tool_calls", 0) + 1
            name = getattr(block, "name", "?")
            inp = getattr(block, "input", None) or {}
            # Tally subagent spawns so the orchestrator's spawn-cap
            # guard fires BEFORE the SDK executes the tool — the
            # increment runs in log_assistant_blocks (= as soon as we
            # see the ToolUseBlock yielded), so _maybe_subagent_cap()
            # at the bottom of the receive loop body can set the
            # break flag in the same iteration. By the time the SDK
            # tries to execute the tool, the receive loop has already
            # exited and the SDK context manager closes (= MCP tool
            # is never called, legacy Agent dispatch is interrupted).
            # The MCP tool function intentionally does NOT increment
            # the counter (avoids double count). Legacy `Agent`, MCP
            # `mcp__team__spawn_subagent` (Claude), and Grok native
            # `spawn_subagent` all count the same way.
            if is_main and (
                name == "Agent"
                or name == "mcp__team__spawn_subagent"
                or name == "spawn_subagent"
            ):
                summary["subagent_spawns"] = (
                    int(summary.get("subagent_spawns", 0)) + 1
                )
            if is_main:
                try:
                    pretty = json.dumps(inp, indent=2, ensure_ascii=False)
                except Exception:
                    pretty = str(inp)
                log_block(job_id, f"TOOL {name}", pretty, tag=tag)
            else:
                try:
                    args_preview = json.dumps(inp)[:200]
                except Exception:
                    args_preview = str(inp)[:200]
                log_line(job_id, f"[{tag}] TOOL {name}: {args_preview}")
            try:
                inp_serial = inp if isinstance(inp, (dict, list)) else str(inp)
                # Cap serialized input so a giant Write/Edit payload
                # doesn't bloat the SSE channel.
                if isinstance(inp_serial, (dict, list)):
                    s = json.dumps(inp_serial, ensure_ascii=False)
                    if len(s) > 4000:
                        inp_serial = {"_truncated": True,
                                      "preview": s[:4000]}
            except Exception:
                inp_serial = None
            _publish(job_id, "sdk", {
                "kind": "tool_use", "tag": tag,
                "name": name, "input": inp_serial,
            })
        elif kind == "ThinkingBlock":
            thinking = getattr(block, "thinking", "") or ""
            if is_main:
                log_block(job_id, "THINK", thinking, tag=tag)
            else:
                log_thinking(
                    lambda s, _t=tag: log_line(job_id, f"[{_t}] {s}"),
                    "THINK", thinking,
                )
            _publish(job_id, "sdk", {
                "kind": "thinking", "tag": tag,
                "thinking": thinking[:8000],
            })


# SDK auto-truncates Bash/Read tool results above its size cap and
# replaces the body with this header. We detect it to surface a
# RUNAWAY_OUTPUT warning so the agent (and the operator reading
# run.log) can spot it instantly — the model has been observed to
# stall after this happens, mistaking the truncated preview for the
# true command output.
_RUNAWAY_RE = re.compile(
    r"Output too large\s*\(([\d.]+\s*[KMG]?B)\)\.\s*Full output saved to:?\s*(\S+)",
    re.IGNORECASE,
)


def _check_runaway(job_id: str, tag: str, body: str) -> None:
    if not body:
        return
    m = _RUNAWAY_RE.search(body)
    if not m:
        return
    size, path = m.group(1), m.group(2)
    log_line(
        job_id,
        f"[{tag}] RUNAWAY_OUTPUT detected ({size}). Saved at {path}. "
        "DO NOT analyze the preview — re-examine the command (likely "
        "infinite loop / EOF re-spew). Re-run with `| head -c 65536` "
        "or `| head -200` size guard.",
    )


def log_user_blocks(job_id: str, msg) -> None:
    """Walk a UserMessage's content blocks (typically tool results) and
    write run-log entries. Main agent gets the full body of each tool
    result with newlines PRESERVED (one log line per source line);
    subagents get the same body collapsed to ONE line (' | '-joined
    newlines) via format_tool_result. Both are full-length since 101beba
    — the old ≤300-byte subagent preview is gone.
    """
    tag = agent_tag(msg, job_id)
    content = getattr(msg, "content", None)
    if not isinstance(content, list):
        return
    is_main = tag == "main"
    for block in content:
        if type(block).__name__ != "ToolResultBlock":
            continue
        is_error = bool(getattr(block, "is_error", False))
        body_raw = getattr(block, "content", None)
        if is_main:
            body = format_tool_result_body(body_raw)
            prefix = "TOOL_ERROR" if is_error else "TOOL_RESULT"
            if not body:
                log_line(job_id, f"[{tag}] {prefix}: (empty)")
            else:
                log_block(job_id, prefix, body, tag=tag)
            _check_runaway(job_id, tag, body)
        else:
            preview = format_tool_result(body_raw, is_error)
            log_line(job_id, f"[{tag}] " + preview)
            _check_runaway(job_id, tag, preview)
        # SDK SSE channel: send a capped preview of every tool result
        # so the live panel can show the agent's perspective end-to-end.
        try:
            preview_for_sse = format_tool_result(body_raw, is_error)
        except Exception:
            preview_for_sse = ""
        if len(preview_for_sse) > 2000:
            preview_for_sse = preview_for_sse[:2000] + " …(truncated)"
        _publish(job_id, "sdk", {
            "kind": "tool_result", "tag": tag,
            "is_error": is_error,
            "preview": preview_for_sse,
        })


def auto_retry_max() -> int:
    """How many postjudge-driven auto retries to allow per job.

    Semantics:
      0                    → disabled (initial run only, no auto retry)
      N (positive int)     → exactly N retries on top of the initial run
      -1 / inf / unlimited → unlimited; loop continues until natural exit
                             (marker capture · verdict==success · empty
                             retry_hint · agent error · BUDGET_ABORT · user
                             Stop · soft/hard timeout).

    Default: -1 (unlimited). The natural exit conditions above keep cost
    bounded for well-behaved runs, and the user can always hit Stop.
    """
    raw = (os.environ.get("AUTO_RETRY_MAX", "-1") or "-1").strip().lower()
    if raw in ("inf", "unlimited", "-1", ""):
        return -1
    try:
        n = int(raw)
    except ValueError:
        return -1
    return max(0, n)


def _auto_retry_success(
    flags_now: list[str], verdict: str | None, provenance_tier: str
) -> bool:
    """Whether the current sandbox attempt may terminate the retry loop.

    A flag value remains visible regardless of tier, but only an explicit
    ``FLAG_CANDIDATE`` marker is strong enough to short-circuit retries on its
    own. Bare runner regex hits and narrative prose are useful evidence, not a
    capture decision: plausible decoys survive the placeholder filter. A judge
    success remains an independent terminal signal, including the existing
    zero-harvest warning path below.
    """
    return verdict == "success" or (
        bool(flags_now) and provenance_tier == "marker"
    )


# Heap-specific failure code → prescriptive fix snippet. Kept here next
# to _format_postjudge_user_turn so the model's textual retry_hint is
# always sharpened by a deterministic "this code → this exact fix"
# preamble. The keys mirror _VALID_HEAP_FAILURE_CODES in modules._judge.
HEAP_FIX_HINTS: dict[str, str] = {
    "heap.libc_version_mismatch": (
        "FIX: Use ./.chal-libs/libc.so.6 (NOT the worker's system "
        "libc) for ALL offset / one_gadget / ROPgadget queries. If "
        "./.chal-libs/libc.so.6 doesn't exist yet, run "
        "`chal-libc-fix ./bin/<n>` first — it writes "
        "./.chal-libs/libc_profile.json with version + safe_linking + "
        "tcache_key + hooks_alive flags you can `json.load` in your "
        "exploit. Worker libc is glibc 2.41 which almost never matches "
        "the chal."
    ),
    "heap.unaligned_libc_base": (
        "FIX: Validate every libc base before using it. Add "
        "`assert (leaked & 0xfff) == EXPECTED_PAGE_OFF` immediately "
        "after the leak. If the assert fires, your sym_offset is wrong "
        "for this glibc — re-derive from ./.chal-libs/libc.so.6 via "
        "pwn.ELF() OR delegate the offset lookup to recon (one-shot "
        "JSON of symbol→offset)."
    ),
    "heap.safe_linking_missing": (
        "FIX: glibc >= 2.32 uses safe-linking. tcache fd value MUST be "
        "`target_addr ^ (heap_chunk_addr >> 12)` — NOT raw target. "
        "Leak a heap address FIRST (e.g. write a freed-chunk's fd back "
        "via show()), then XOR. Use "
        "`from scaffold.tcache_poison import safe_link; "
        "fd = safe_link(target, chunk_addr)` — it branches on the "
        "libc_profile.json safe_linking flag automatically."
    ),
    "heap.safe_linking_misapplied": (
        "FIX: glibc <= 2.31 has NO safe-linking. Drop the XOR — write "
        "the raw target address as the freed chunk's fd. Verify the "
        "glibc version via `./.chal-libs/libc_profile.json` "
        "(`safe_linking: false`) before re-writing."
    ),
    "heap.hook_on_modern_libc": (
        "FIX: `__free_hook` / `__malloc_hook` / `__realloc_hook` were "
        "REMOVED in glibc 2.34. Switch your AAW target to one of: "
        "(a) `_IO_list_all` overwrite + FSOP via _IO_wfile_jumps "
        "overflow → _IO_wdoallocbuf (see /opt/scaffold/fsop_wfile.py), "
        "(b) `__exit_funcs` (needs PTR_MANGLE stack/TLS leak), or "
        "(c) `_rtld_global._dl_rtld_lock_recursive`. Read "
        "./.chal-libs/libc_profile.json → `preferred_fsop_chain` for "
        "the recommended path on this glibc version."
    ),
    "heap.str_finish_patched": (
        "FIX: `_IO_str_jumps` __finish chain was patched in glibc "
        "2.37. Switch to `_IO_wfile_jumps` overflow → `_IO_wdoallocbuf` "
        "→ `_wide_vtable->__doallocate` = your gadget. Use "
        "`scaffold.fsop_wfile.build_full_chain(fake_file_addr=..., "
        "doallocate_addr=...)` which returns the body WITHOUT the "
        "vtable pointer; flip the vtable separately, LAST."
    ),
    "heap.vtable_write_order_violated": (
        "FIX: FSOP vtable pointer MUST be the LAST write of the "
        "chain. Order: (1) write _IO_FILE_plus body, (2) write "
        "_wide_data, (3) write _wide_vtable / __doallocate, (4) write "
        "/bin/sh if you need it, (5) ONLY NOW flip vtable = "
        "_IO_wfile_jumps. Any incidental stdio (prompt loop, log "
        "print) between the vtable flip and the trigger fires "
        "_IO_wfile_overflow on partial state and SIGSEGVs. The "
        "/opt/scaffold/fsop_wfile.py helpers enforce this — "
        "build_full_chain() leaves the vtable slot zeroed."
    ),
    "heap.tcache_key_not_bypassed": (
        "FIX: mainline glibc 2.29 adds a `key` field at offset +0x08 of "
        "every freed tcache entry; the same change was officially backported "
        "to the 2.28 stable branch, so libc_profile.json conservatively treats "
        "2.28 as affected too. In 2.34 the stored value became random, but the "
        "check is older. Double-free aborts with "
        "`free(): double free detected in tcache 2`. Pattern: "
        "`free(victim); edit(victim, p64(0) * 2)  # zeroes fd AND the "
        "key at +0x08 via UAF; free(victim)` — the write MUST reach "
        "offset +0x08. A bare `p64(0)` clears only fd and the same "
        "abort repeats byte-for-byte. The key-bypass check is "
        "helper-available in "
        "/opt/scaffold/tcache_poison.py::key_bypass_needed(). After "
        "that, normal tcache poison resumes."
    ),
    "heap.aslr_unstable": (
        "FIX: Wrap your exploit in a reconnect loop — most heap "
        "chains succeed 1/16 (nibble race). Move the body into "
        "`def exploit_one(): ...` that opens its own tube each call, "
        "returns the flag on success or None on failure. Then call "
        "`from scaffold.aslr_retry import aslr_retry; "
        "flag = aslr_retry(exploit_one, max_attempts=64)`. "
        "`expected_attempts_for(1/16)` ≈ 72 — pick a bound that fits "
        "in the 300s runner timeout."
    ),
    "heap.unaligned_tcache_target": (
        "FIX: tcache poison target MUST be 0x10-aligned on glibc "
        ">= 2.32 — otherwise `malloc(): unaligned tcache chunk "
        "detected` aborts. Either pick a 0x10-aligned offset within "
        "the target object, add a valid aligned fake chunk at that address, "
        "OR use a different primitive (large-bin / unsorted). The freed "
        "tcache_entry `key` is at user-data offset +0x08 and is therefore "
        "NOT itself a valid aligned allocation target."
    ),
    "heap.whitespace_in_address": (
        "FIX: A critical address contains 0x09/0x0a/0x0b/0x0c/0x0d/"
        "0x20 and the chal's input path is `cin >>` / "
        "`getline(cin, ...)` — that TRUNCATES on whitespace, so your "
        "field write smashes the wrong byte. Mitigations: re-roll "
        "ASLR (wrap with aslr_retry), pick a different gadget with "
        "no whitespace in its critical byte, or switch primitive "
        "to one that uses `read()` instead. Document the constraint "
        "in report.md."
    ),
    "heap.interactive_in_sandbox": (
        "FIX: `p.interactive()` blocks on stdin and the runner "
        "sandbox has no TTY → the run hangs until the hard "
        "timeout ends it, with no flag. Replace with explicit "
        "`p.sendline(b'cat /flag*'); print(p.recvrepeat(2.0)"
        ".decode(errors='replace'))`. Use the `if sys.stdin.isatty(): "
        "p.interactive()` guard if you want local-debug ergonomics."
    ),
    "heap.unbounded_recv": (
        "FIX: Every `recvuntil` / `recv` / `recvline` / `readuntil` "
        "MUST have an explicit `timeout=` argument. Mismatched "
        "prompts otherwise hang the run until the hard timeout. "
        "Add `context.timeout = 10` at the top of the script and "
        "`timeout=context.timeout` on EVERY recv-family call."
    ),
}


def _format_postjudge_user_turn(
    *,
    attempt_idx: int,
    max_attempts: int,
    script_filename: str,
    sandbox_result: dict,
    method_change: bool = False,
) -> str:
    """Compose the user-turn body that gets injected back into main's
    SDK session after a failed sandbox run or a prejudge ship-block.
    Tells main what verdict came back, gives it the retry_hint verbatim,
    and asks for a corrected implementation or a genuinely different
    strategy. Tail of stdout/stderr is included so main can cross-check
    rather than trusting judge's summary blindly.

    findings.json schema validation is intentionally NOT plumbed in:
    cookbook fidelity puts the structured-output transformation in a
    terminal REPORT phase (run_report_phase) that fires once at job
    end. Main is responsible only for report.md prose; nothing it
    writes mid-retry would feed back here anyway.
    """
    judge = (sandbox_result or {}).get("judge") or {}
    verdict = judge.get("verdict") or "unknown"
    summary = (judge.get("summary") or "").strip()
    retry_hint = (judge.get("retry_hint") or "").strip()
    failure_code = (judge.get("failure_code") or "").strip().lower() or None
    next_action = (judge.get("next_action") or "continue").lower()
    # New structured fields (Item 6 — backwards-compatible: empty
    # defaults if judge didn't emit them).
    what_worked = judge.get("what_worked") or []
    what_failed = judge.get("what_failed") or []
    specific_diagnosis = (judge.get("specific_diagnosis") or "").strip()
    alternative_paths = judge.get("alternative_paths") or []
    if not isinstance(what_worked, list):
        what_worked = []
    if not isinstance(what_failed, list):
        what_failed = []
    if not isinstance(alternative_paths, list):
        alternative_paths = []

    exit_code = sandbox_result.get("exit_code")
    stdout = (sandbox_result.get("stdout") or "")[-2000:]
    stderr = (sandbox_result.get("stderr") or "")[-2000:]
    timeout_marker = ""
    if sandbox_result.get("timeout"):
        timeout_marker = "  · runner timeout fired before container exit\n"
    if sandbox_result.get("killed_by_supervise"):
        timeout_marker += (
            "  · supervise judge killed the container due to stalled output\n"
        )
    cap_str = "∞" if max_attempts < 0 else str(max_attempts)
    # Provenance. FOUR producers reach this formatter and only one of them
    # is a postjudge verdict: the prejudge ship-block redirect, the
    # runner_crash_hint stderr regex (no model is involved at all) and the
    # one-shot auto-reviewer each synthesize a judge dict whose
    # next_action="continue" no judge ever voted for. None of those three
    # sentinel verdicts is in modules._judge._VALID_VERDICTS, so `verdict`
    # alone identifies the producer without extra plumbing. Labelling all
    # four "from postjudge" corrupts step 2 below, which asks main to grade
    # the hint's authority. Kept local to the function on purpose: the
    # anti-overfit test execs this function source with only
    # HEAP_FIX_HINTS in scope, so a module-level table would NameError.
    _hint_provenance = {
        "prejudge_blocked": (
            "prejudge",
            "prejudge ship-block, no sandbox run — apply this",
        ),
        "runner_crash": (
            "runner",
            "the runner's own stderr matched by regex, no model wrote it "
            "— apply this",
        ),
        "reviewer_redirect": (
            "reviewer",
            "the one-shot auto-reviewer, not the judge; this job gets "
            "exactly one — apply this",
        ),
    }
    hint_source, hint_origin = _hint_provenance.get(
        verdict, ("postjudge", "postjudge — apply this")
    )
    prejudge_only = verdict == "prejudge_blocked"
    if prejudge_only:
        execution_notice = (
            "PREJUDGE STOPPED THE SHIP BEFORE SANDBOX EXECUTION. The issues "
            "below describe an unproven chain, not a failed runtime attempt."
        )
    else:
        execution_notice = (
            "THE SANDBOX RUN HAS COMPLETED. The stdout/stderr below are "
            "runtime evidence."
        )

    # Prescriptive fix snippet for the heap failure code, prepended
    # ahead of the model's free-form retry_hint. The deterministic
    # FIX line is shorter to act on than the model-authored paragraph
    # and avoids the retry-hint drift we sometimes see where each
    # retry phrases the same issue differently.
    fix_preamble = ""
    if failure_code and failure_code in HEAP_FIX_HINTS:
        fix_preamble = (
            f"\n=== prescriptive fix (failure_code={failure_code}) ===\n"
            f"{HEAP_FIX_HINTS[failure_code]}\n"
        )
    # Structured diagnosis block — included only when judge emitted
    # at least one of the new fields. Keeps the retry feedback shape
    # backwards-compatible for older runs whose meta doesn't carry it.
    diagnosis_block = ""
    if (
        what_worked or what_failed or specific_diagnosis or alternative_paths
    ):
        diagnosis_parts: list[str] = ["\n=== structured diagnosis ==="]
        if what_worked:
            diagnosis_parts.append("WHAT WORKED (preserve these on the patch):")
            diagnosis_parts.extend(f"  ✓ {s}" for s in what_worked[:3])
        if what_failed:
            diagnosis_parts.append("WHAT FAILED (these are the bugs to fix):")
            diagnosis_parts.extend(f"  ✗ {s}" for s in what_failed[:3])
        if specific_diagnosis:
            diagnosis_parts.append(
                f"PINPOINT: {specific_diagnosis}"
            )
        # On a method-change conversion the same alternatives are already
        # embedded below in the one-shot retry hint with the load-bearing
        # instruction to pick one and rebuild.  Rendering them here as a
        # deferred "try if the patch keeps failing" list duplicates them and
        # gives the opposite urgency before the agent reaches that hint.
        if alternative_paths and not method_change:
            diagnosis_parts.append(
                "ALTERNATIVE PATHS (try if the patch keeps failing — "
                "these were NOT exhausted by this run):"
            )
            diagnosis_parts.extend(f"  → {s}" for s in alternative_paths[:3])
        diagnosis_block = "\n".join(diagnosis_parts) + "\n"

    return (
        f"🔁 AUTO-RETRY {attempt_idx}/{cap_str} — postjudge feedback\n"
        f"\n"
        f"⚠️ {execution_notice} This message IS the current verdict — do NOT "
        f"respond with 'awaiting sandbox' "
        f"or 'I'll stop the loop here / reschedule'. The orchestrator "
        f"is in the auto-retry loop NOW. First classify the failure: for an "
        f"IMPLEMENTATION defect, modify ./{script_filename}; for a STRATEGY "
        f"or UNKNOWN failure, test materially different hypotheses and "
        f"replace the invalid chain rather than polishing it. "
        f"Doing neither — returning without an edit — does NOT buy you "
        f"another attempt. The orchestrator recorded this script's SHA when "
        f"it sent you this message; before the next ship it re-hashes the "
        f"file, and if the bytes are identical there is no second sandbox "
        f"spin at all — the job ENDS HERE with "
        f"stop_kind=retry_hint_ignored, and WHY_STOPPED.md records it as "
        f"'Script unchanged after the postjudge retry hint', a permanent "
        f"diagnosis that /retry copies into the next job's work tree for "
        f"the next agent to read. Edit ./{script_filename} or replace the "
        f"chain before you end this turn.\n"
        f"\n"
        f"Runner/prejudge result for `{script_filename}`:\n"
        f"  · exit_code: {exit_code}\n"
        f"  · {hint_source} verdict: {verdict}\n"
        f"  · {hint_source} summary: {summary or '(empty)'}\n"
        f"  · judge next_action: {next_action} "
        + (
            "(the judge voted STOP on this approach; the orchestrator "
            "converted that into the ONE method-change retry — rebuild "
            "the decisive step, do NOT keep iterating on this method)\n"
            if method_change
            else "(judge endorses this retry — keep iterating)\n"
            if hint_source == "postjudge" and next_action == "continue"
            else f"(no judge voted on this retry — the orchestrator "
            f"synthesized it alongside the {hint_source} hint)\n"
            if hint_source != "postjudge"
            else "(the judge did not vote to continue; the orchestrator "
            "is retrying anyway)\n"
        )
        + (f"  · failure_code: {failure_code}\n" if failure_code else "")
        + f"{timeout_marker}"
        f"{fix_preamble}"
        f"{diagnosis_block}"
        f"\n"
        f"=== retry hint (from {hint_origin}) ===\n"
        f"{retry_hint or '(judge produced no actionable hint; debug from the tails below)'}\n"
        f"\n"
        f"=== stdout tail ===\n"
        f"{stdout or '(empty)'}\n"
        f"\n"
        f"=== stderr tail ===\n"
        f"{stderr or '(empty)'}\n"
        f"\n"
        f"WHAT TO DO NOW:\n"
        f"  1. Read the script as it stands (`Read ./{script_filename}`).\n"
        f"  2. Audit the hint against source and executed evidence. Record\n"
        f"     VERIFIED, REFUTED, and UNTESTED premises; the hint is not\n"
        f"     authoritative merely because a judge wrote it.\n"
        f"  3. If the chain is verified, patch its concrete implementation\n"
        f"     defect. If the chain/prerequisite is refuted or unknown, test\n"
        f"     at least two materially different untested hypotheses using\n"
        f"     their cheapest discriminating probes, then replace the script\n"
        f"     only with the strongest evidence-backed chain.\n"
        f"  4. Re-run the JUDGE GATE (peer subagent) on the patched script\n"
        f"     before ending your turn. The orchestrator will rerun the\n"
        f"     sandbox automatically after you finish.\n"
        f"  5. Keep the artifact path stable (`./{script_filename}` and\n"
        f"     `./report.md`).\n"
        f"  6. Do not delete the artifact merely because the current theory\n"
        f"     failed. `Bash(rm -f ./{script_filename})` is the final\n"
        f"     concession only after the alternative-hypothesis audit is\n"
        f"     documented and no untested evidence-backed branch remains.\n"
    )


def _pick_present_artifact(
    work_dir: Path, names: tuple[str, ...],
) -> str | None:
    for n in names:
        if (work_dir / n).is_file():
            return n
    return None


def failed_turn_reuses_artifact(
    work_dir: Path,
    names: tuple[str, ...],
    before: dict[str, str | None],
) -> tuple[str, bool]:
    """Return the runnable artifact and whether its bytes predate the turn."""

    picked = _pick_present_artifact(work_dir, names)
    if not picked:
        return "", False
    prior_sha = before.get(picked)
    if prior_sha is None:
        return picked, False
    try:
        current_sha = hashlib.sha256((work_dir / picked).read_bytes()).hexdigest()
    except OSError:
        return picked, False
    return picked, current_sha == prior_sha


# Minimal pwntools skeleton the orchestrator drops in when the budget
# is exhausted or the SDK transport dies WITHOUT main producing an
# exploit.py. The scaffold's only job is to land SOMETHING runnable
# so the sandbox + postjudge path activates, which means the next
# auto-retry hand-off carries an actionable artifact instead of an
# empty failed job. Loads libc_profile.json if present so re-entries
# inherit the staged glibc symbols + how2heap recommendation.
_FALLBACK_EXPLOIT_TEMPLATE = '''\
#!/usr/bin/env python3
"""Auto-generated fallback exploit — main session exhausted its
budget or the SDK transport died before drafting a real exploit.
This skeleton exists ONLY so the sandbox + postjudge cycle can fire
and feed a real retry hint into the next attempt. Replace with proper
chain on /retry.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from pwn import ELF, context, log, p64, process, remote, u64  # noqa: F401

context.log_level = "info"
context.timeout = 10

BIN = "./prob"


def make_tube():
    if len(sys.argv) >= 2 and ":" in sys.argv[1]:
        host, port = sys.argv[1].rsplit(":", 1)
        return remote(host, int(port))
    return process(BIN)


# Profile-driven branch (filled by chal-libc-fix autoboot).
PROFILE_PATH = Path("./.chal-libs/libc_profile.json")
profile = None
if PROFILE_PATH.is_file():
    try:
        profile = json.loads(PROFILE_PATH.read_text())
        log.info(f"libc: {profile.get('version')} | "
                 f"recommended: {(profile.get('recommended_techniques') or [None])[0]}")
    except Exception as e:
        log.warn(f"profile read failed: {e}")

p = make_tube()

# TODO(auto-fallback): the analysis phase never landed a real exploit;
# this script connects, probes, and exits. Replace the body below with
# a real chain on /retry — the postjudge feedback for THIS run will
# carry actionable hints.
try:
    banner = p.recv(timeout=2)
    log.info(f"banner: {banner[:200]!r}")
    p.sendline(b"help")
    follow = p.recv(timeout=2)
    log.info(f"after help: {follow[:200]!r}")
except Exception as e:
    log.warn(f"probe error: {e}")
finally:
    p.close()
'''

_FALLBACK_REPORT_TEMPLATE = '''\
# Fallback report (auto-generated)

**Status**: `exploit_status: aborted` — main session exhausted its tool-call
budget or the SDK transport died without producing a working exploit.
The orchestrator dropped a probe-only skeleton at `./exploit.py` so the
sandbox + postjudge cycle still fires.

## What the auto-fallback knows

- libc version: see `./.chal-libs/libc_profile.json` (`version` field)
- recommended chain: same JSON, `recommended_techniques`
- how2heap PoC for this glibc: `how2heap.dir`

## What the auto-fallback does NOT know

- the chal's input protocol (menu structure, prompt strings)
- the specific vulnerable function
- the offsets / one_gadget choice

## Next step

Click **/retry** in the UI. The postjudge feedback for the probe run
will feed into the next attempt's user-turn so analysis resumes from
where the budget hit. The retry SDK session is forked so prior
reasoning context carries over.
'''

# Web-shaped fallback: a pwn socket skeleton (connect / send 'help' /
# close) is meaningless against an HTTP target — `remote(host,port)`
# treats the web service as a raw socket and the runner captures
# nothing (job 5f4bb59d0b44). For module=="web" we drop an HTTP probe
# instead so the sandbox + postjudge cycle gets coherent diagnostics.
_FALLBACK_WEB_EXPLOIT_TEMPLATE = '''\
#!/usr/bin/env python3
"""Auto-generated WEB fallback — main session ended before drafting a
real exploit. Probe-only: fingerprints the target so the sandbox +
postjudge cycle fires and the next /retry carries an actionable hint.
Replace with the real chain on /retry.
"""
import sys

import requests

# The orchestrator passes a bare host:port (no scheme) — normalize it.
arg = sys.argv[1] if len(sys.argv) >= 2 else "http://127.0.0.1"
base = arg if arg.startswith(("http://", "https://")) else "http://" + arg
base = base.rstrip("/")


def probe(path=""):
    url = base + path
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        print(f"[{r.status_code}] {url}  ({len(r.content)} B)")
        srv = r.headers.get("Server") or r.headers.get("X-Powered-By")
        if srv:
            print(f"    server: {srv}")
        return r
    except Exception as e:
        print(f"[!] {url} -> {e}")
        return None


def main():
    print(f"[*] web fallback probe against {base}")
    root = probe("/")
    for p in ("/robots.txt", "/admin", "/api", "/flag", "/.git/HEAD"):
        probe(p)
    if root is not None:
        body = root.text[:500]
        print("--- root body (first 500 B) ---")
        print(body)
    print("[!] no real exploit drafted — /retry to resume from postjudge hint")


if __name__ == "__main__":
    main()
'''


WHY_STOPPED_FILENAME = "WHY_STOPPED.md"


_STOP_KIND_HEADERS = {
    "judge_stop": "Judge ruled the chain unrecoverable",
    "budget_exhausted": "Auto-retry budget exhausted",
    "no_hint": "Postjudge produced no actionable retry hint",
    "agent_error": "Main agent session error",
    # States the OBSERVATION, not an intent the code cannot establish: all it
    # knows is that the bytes are identical. The old wording ("Main ignored
    # postjudge retry_hint") was written into WHY_STOPPED as ground truth and
    # carried into /retry — on job df7dd1b4a9e8 it libelled a run in which main
    # engaged with the hint in detail and then conceded on purpose.
    "retry_hint_ignored": (
        "Script unchanged after the postjudge retry hint"
    ),
    "conceded_by_deletion": (
        "Main DELETED the deliverable after the retry hint — a recorded "
        "concession, taken via the exact path the postjudge message offers"
    ),
    "no_artifact": (
        "No solver artifact was found in work/ or at the job root — nothing "
        "to execute (usually a filename/location mismatch, not a dead end)"
    ),
    "unsolvable_by_analysis": (
        "Conceded unsolvable — artifacts self-admit no working chain and "
        "prejudge flag_likelihood≈0 (true-negative, not a fixable near-miss)"
    ),
    "prejudge_dead_target": (
        "Prejudge verified the declared remote target is dead — operator "
        "re-provisioning is required, not another script rewrite"
    ),
    "prejudge_blocked_no_run": (
        "Prejudge blocked twice before any sandbox execution — escalated "
        "instead of spending a third analysis turn"
    ),
    "judge_shadow_no_verdict": (
        "Judge shadow recorded evidence but supplied no gating verdict"
    ),
    "reviewer_redirect_no_run": (
        "The one-shot reviewer redirect produced another sandbox run without "
        "a capture, live judge verdict, or further retry hint"
    ),
    "policy_refusal": (
        "Main turn blocked by the server-side Usage-Policy classifier "
        "(AUP) — session context poisoned; halted without an in-place retry"
    ),
    "cost_cap": (
        "Cumulative spend hit the cost-cap circuit breaker — halted to "
        "bound runaway grinding on a non-converging run; recoverable via /retry"
    ),
}


# --- AUP recovery -----------------------------------------------------------
# A server-side Usage-Policy block ends the SESSION, not the JOB. The session's
# accumulated transcript is what the classifier refused, so re-querying it
# re-blocks deterministically (jobs ab95a434bb0f, 2eba75783e83) — but a FRESH
# context over the same work tree does not, which is why /retry has always been
# the de-facto cure. These helpers automate that cure instead of parking the
# job until an operator notices.
#
# NOT an attempt to evade the classifier. Nothing here rewrites, launders or
# re-words the prompt: the recovery starts a clean session and, failing that,
# hands the same work to the other configured provider under its own policy.
# This repository already learned that lesson the expensive way — vocabulary
# scaffolding added to dodge a soft refusal turned into a HARD server-side
# block on every reviewer call (A/B proven 2026-06-02), and the fix was to
# delete the scaffolding.
_AUP_RECOVERY_STEPS = ("fresh_session", "other_provider")


def aup_recovery_step(summary: dict, *, grok_available: bool) -> str | None:
    """Next recovery to try after a policy refusal, or None to halt.

    Pure and side-effect free so the ladder can be tested without an actual
    refusal. Each step is attempted AT MOST ONCE per job — a second refusal
    after a clean context means the challenge content itself is what the
    classifier objects to, and burning further sessions on it is waste.
    """
    done = list(summary.get("aup_recoveries") or [])
    for step in _AUP_RECOVERY_STEPS:
        if step in done:
            continue
        if step == "other_provider" and not grok_available:
            continue
        return step
    return None


def write_resume_state(
    work_dir: Path,
    *,
    job_id: str = "",
    summary: dict | None,
    sandbox_result: dict | None,
    judge_out: dict | None,
    attempt_idx: int,
    reason: str,
    log_fn,
) -> str:
    """Write RESUME_STATE.md — what a CLEAN session needs to carry on.

    WHY_STOPPED.md explains to a HUMAN why the run ended. This is the other
    audience: an agent booting with no conversation history, looking at a work
    tree it did not build. Without it a fresh session re-derives what the dead
    session already knew — job e601cd358ad6 spent 88 turns and $23.77
    rediscovering a primitive that was already written down.

    Deliberately points at FILES rather than restating their contents: the
    work tree is carried intact, so the cheapest correct thing is to tell the
    new session what exists and what was already settled.
    """
    # The LIVE target, not whatever the dead session was spawned with. A
    # mid-run Change Target is invisible to a restarted session otherwise: its
    # prompt is the spawn-time one, and the loop's own change detector re-reads
    # meta at re-entry so it compares NEW to NEW and can never fire.
    live_target = ""
    try:
        # Fall back to the work-tree path (/data/jobs/<id>/work) when no id was
        # passed, so an older caller still gets the live value.
        _jid = job_id or Path(work_dir).parent.name
        live_target = str((read_meta(_jid) or {}).get("target_url") or "")
    except Exception:
        pass

    lines: list[str] = [
        "# RESUME STATE",
        "",
        f"The previous session ended early: **{reason}**. Its conversation is "
        "gone; this work tree is not. Everything below survived.",
        "",
        "## Read these first",
    ]
    for name in ("report.md", "findings.json", "chain.json", "THREAT_MODEL.md",
                 "exploit.py", "solver.py", "AUTOBOOT.md", "pre_recon_raw.md"):
        f = work_dir / name
        try:
            if f.is_file() and f.stat().st_size > 0:
                lines.append(f"- `{name}` ({f.stat().st_size:,} B)")
        except OSError:
            pass
    lines += ["", "## Where the previous session got to", ""]
    s = summary or {}
    lines.append(f"- turns: {s.get('messages') or s.get('agent_turns') or '?'}"
                 f" · tool calls: {s.get('tool_calls', '?')}"
                 f" · auto-run attempts: {attempt_idx}")
    if s.get("exploit_present") or s.get("solver_present"):
        lines.append("- an exploit/solver artifact EXISTS — read it before "
                     "writing a new one; it encodes offsets and a chain that "
                     "were already validated")
    if sandbox_result:
        lines.append(
            f"- last sandbox run: verdict={sandbox_result.get('verdict')} "
            f"exit={sandbox_result.get('exit_code')} "
            f"— stdout/stderr are in the job dir")
    if judge_out and judge_out.get("retry_hint"):
        # NOT "the judge's" — same provenance lie the postjudge wrapper carried
        # until 2026-08-24, in a second place the audit missed. Three of the
        # four producers that fill retry_hint are not the judge: the prejudge
        # ship-block redirect, runner_crash_hint (a stderr regex, no model),
        # and the one-shot auto-reviewer. The verdict names which one.
        _src = {"prejudge_blocked": "prejudge ship-block",
                "runner_crash": "the runner's own stderr",
                "reviewer_redirect": "the one-shot reviewer"}.get(
                    str(judge_out.get("verdict") or ""), "postjudge")
        # 3200, not 1200. The module-missing hint is ~2800 chars and its
        # actionable half — the runner's package inventory and the
        # `pip install --target ./.pydeps` recipe — sits at the END, so a
        # 1200-char cut carried NONE of it into the next job. This file is
        # markdown on disk that an operator and the next agent read
        # selectively, not a prompt injection, so the extra bytes are free.
        lines += ["", f"## The last actionable hint (from {_src})", "",
                  "> " + str(judge_out["retry_hint"])[:3200].replace("\n", "\n> ")]
    lines += [
        "",
        "## What to do",
        "",
        "1. Read the artifacts above. Do NOT re-run triage that `report.md` "
        "or `findings.json` already answers.",
        "2. Re-verify only what the artifacts leave uncertain.",
        # NOT "the target is unchanged" — that was an unconditional assertion
        # this function had no way to know was true. An operator can change the
        # target mid-run (a restarted DreamHack instance comes back on a new
        # port), and on a restart after that the sentence was a GENERATED
        # FALSEHOOD handed to a context-less agent. State the live value, or
        # say nothing about it.
        "3. Continue from there — the goal is unchanged."
        + (f" The CURRENT target is `{live_target}` — it is authoritative, and "
           f"it may differ from what older artifacts say."
           if live_target else ""),
        "",
    ]
    out = "\n".join(lines)
    try:
        (work_dir / "RESUME_STATE.md").write_text(out)
        log_fn(f"[orchestrator] wrote RESUME_STATE.md ({len(out)} B) for the "
               f"next session")
    except OSError as e:
        log_fn(f"[orchestrator] could not write RESUME_STATE.md: {e}")
    return out


_RUNNER_MISSING_MODULE_RE = re.compile(
    r"(?:ModuleNotFoundError|ImportError): No module named ['\"]([\w.]+)['\"]")
# The four shapes a missing binary actually takes in the runner. Measured, not
# assumed — `/bin/sh` there is a symlink to dash, and dash and bash disagree on
# both halves of the message:
#     sh: 1: nosuchtool: not found                      dash, exec'd directly
#     /bin/sh: 1: nosuchtool: not found                 dash, via subprocess(shell=True)
#     bash: line 1: nosuchtool: command not found       bash
#     FileNotFoundError: [Errno 2] ... : 'nosuchtool'   subprocess with a list argv
# A first pass required the literal "command not found" and a "/bin/" prefix,
# which between them matched only the bash form — the one the runner does not
# use by default.
_RUNNER_MISSING_BIN_RE = re.compile(
    r"FileNotFoundError: \[Errno 2\][^\n]*?['\"]([\w.\-/]+)['\"]"
    r"|(?:^|\n)(?:/\S+/)?(?:ba)?sh: (?:(?:line )?\d+: )?([\w.\-/]+): "
    r"(?:command )?not found")


def runner_crash_hint(sandbox_result: dict | None) -> str:
    """A retry hint for the crash classes that need no judgment, or "".

    The auto-retry loop only continues when it holds a `retry_hint`, and the
    only producer is the LLM judge. With `enable_judge` off — an operator
    setting, not a fault — there is no producer, so the loop stops after turn 0
    no matter how trivially fixable the failure was.

    Job 06f3a326d453 is what that costs. 61 turns and $23.43 of UOV
    cryptanalysis produced a 28 KB solver whose line 33 read `import numpy as
    np`; the runner has no numpy, so it died in 2 seconds having executed none
    of the attack, and the run ended `no_flag` with `verdict=None,
    next_action=continue` and no retry. A missing import is the most actionable
    failure there is — the fix does not need a model to think about it.

    Deliberately narrow. Only failures whose remedy is mechanical and whose
    diagnosis is a literal string in the runner's own stderr qualify; anything
    needing an opinion about the ATTACK stays the judge's job and still stops
    here. `prejudge_blocked` / `judge_aborted` sentinels are skipped — those
    mean the sandbox never ran, so its stderr describes nothing.
    """
    sr = sandbox_result or {}
    if not sr or sr.get("error") == "prejudge_blocked" or sr.get("judge_aborted"):
        return ""
    if sr.get("exit_code") in (0, None):
        return ""
    err = str(sr.get("stderr") or "")
    if not err:
        return ""

    m = _RUNNER_MISSING_MODULE_RE.search(err)
    if m:
        mod = m.group(1)
        stdout_chars = len(str(sr.get("stdout") or ""))
        return (
            f"Your solver died at `import {mod}` (exit "
            f"{sr.get('exit_code')}, stdout {stdout_chars} characters). FIRST "
            f"decide which of these two it is — they need opposite fixes.\n\n"
            f"(a) `{mod}` IS YOURS: a `{mod}.py` or `{mod}/` you wrote, or a "
            f"`./.pydeps` you vendored. Then nothing is missing from the "
            f"runner and installing a package fixes nothing. The sandbox runs "
            f"`python3 /data/jobs/<id>/work/<script>` with cwd "
            f"`/data/jobs/<id>/work`, so `sys.path[0]` is the SCRIPT'S OWN "
            f"directory — not the work root, and not the directory you "
            f"happened to be in when you tested it. Two shapes bite here: the "
            f"script sits in a subdirectory while its helpers sit in work/, "
            f"or the script was left at the jobroot instead of work/ — in "
            f"that case the orchestrator copies THAT ONE FILE into work/ for "
            f"the run and its siblings stay behind. Ship the script and "
            f"everything it imports into the SAME directory, or insert that "
            f"directory on sys.path derived from `__file__` (recipe below) "
            f"before the import, and list the work tree to confirm.\n\n"
            f"(b) `{mod}` is a third-party package you pip-installed into the "
            f"worker. Only then does the rest of this apply.\n\n"
            f"The worker you developed in is a DIFFERENT container from the "
            f"runner your solver is executed in, and they are not guaranteed to "
            f"carry the same packages: anything an earlier job pip-installed "
            f"into the worker persists there and does NOT exist in the runner. "
            f"That `{mod}` imported cleanly while you were working proves "
            f"nothing about the sandbox.\n\n"
            f"The runner is NOT stdlib-only. It ships pwntools, pycryptodome, "
            f"gmpy2, sympy, z3-solver, pyboolector, cvc5, ecdsa, requests, "
            f"httpx, numpy, web3/eth-abi/eth-account and the `scaffold` "
            f"package (fpylll/cysignals are best-effort). Check that list "
            f"first — `{mod}` may have a drop-in already present.\n\n"
            f"If it genuinely is absent, VENDOR IT — do not hand-roll a "
            f"replacement. First identify its PyPI DISTRIBUTION name (an "
            f"import name is not necessarily a package name: `elftools` is "
            f"provided by `pyelftools`, `PIL` by `Pillow`, and `Crypto` by "
            f"`pycryptodome`). Then, from your work dir:\n"
            f"    python3 -m pip install --target ./.pydeps <distribution-name>\n"
            f"and make these the FIRST lines of the solver:\n"
            f"    import os, sys\n"
            f"    sys.path.insert(0, os.path.join(\n"
            f"        os.path.dirname(os.path.abspath(__file__)), \".pydeps\"))\n"
            f"The sandbox mounts this job dir at the SAME absolute path and "
            f"both images share one Python base, so even compiled wheels load "
            f"there. Derive the path from `__file__`, not from a relative "
            f"\"./.pydeps\". Rewrite without `{mod}` only if vendoring "
            f"actually fails — a pure-Python reimplementation of a numpy or "
            f"sympy step is the usual way an import crash turns into a "
            f"runner-timeout on the next attempt. Then verify the fix in the "
            f"REAL sandbox before you finish:\n"
            f"    python3 -m worker.solver_smoke <script> [args] --timeout N\n"
            f"Do NOT re-ship until that reports exit_code 0."
        )

    # A solver may catch and print an early ENOENT, continue, then die on a
    # different one.  The stderr tail is chronological; diagnose the last
    # matching failure instead of reviving an already handled probe.
    _bin_matches = list(_RUNNER_MISSING_BIN_RE.finditer(err))
    m = _bin_matches[-1] if _bin_matches else None
    if m:
        enoent_name, shell_name = m.group(1), m.group(2)
        name = shell_name or enoent_name
        runner_tools = (
            "gdb, qemu-*-static interpreters, ltrace, strace, "
            "gcc/g++/make, cpp, "
            "binutils, java, forge/cast/anvil, git and curl"
        )
        worker_only_tools = (
            "chromium, tshark, wasm2wat, ffuf and seccomp-tools"
        )
        if shell_name:
            # The shell itself identifies this as command lookup.  Unlike the
            # FileNotFoundError spelling below, it cannot be a failed open().
            return (
                f"The runner shell could not execute command/path `{name}` "
                f"(exit {sr.get('exit_code')}). The runner HAS {runner_tools}; "
                f"the runner image omits the worker-only entries for "
                f"{worker_only_tools}.\n\n"
                f"If the command is meant to be a shipped helper, put it in "
                f"the work tree and invoke its `__file__`-relative absolute "
                f"path. Otherwise reimplement that step in-process or switch "
                f"to an installed tool. Verify in the REAL sandbox before "
                f"you finish:\n"
                f"    python3 -m worker.solver_smoke <script> [args] --timeout N\n"
                f"Do NOT re-ship until that reports exit_code 0."
            )
        # Python uses exactly the same ENOENT exception text for
        # subprocess.run([argv0, ...]) and open(path).  Traceback frames may be
        # truncated, and a stderr tail can contain more than one traceback, so
        # the formatter cannot safely infer which operation failed.  State the
        # ambiguity and give both mechanical discriminators instead of turning
        # a data-path bug into a made-up missing-binary fact.
        return (
            f"The runner raised ENOENT for `{name}` (exit "
            f"{sr.get('exit_code')}). That exception text alone does NOT "
            f"distinguish an executable lookup from a missing data path. Read "
            f"the exact failing source line and its final traceback before "
            f"choosing a fix.\n\n"
            f"(a) If the line launches a process (`subprocess`, `exec*`, or a "
            f"tool wrapper), check the runner inventory first. It HAS "
            f"{runner_tools}; the runner image omits the worker-only entries "
            f"for {worker_only_tools}. For a helper you wrote, ship it in the work "
            f"tree and invoke an absolute path derived from `__file__`.\n\n"
            f"(b) If the line opens a file, this is a PATH/creation bug, not "
            f"evidence that a package or tool is absent. The whole job dir is "
            f"bind-mounted at the same `/data/jobs/<id>` path and cwd is "
            f"`/data/jobs/<id>/work`; check for a worker-only absolute path, "
            f"another job id, or a scratch/output file the shipped script "
            f"never creates. Build paths from `__file__` and create parent "
            f"directories and inputs before reading them.\n\n"
            f"Verify the chosen fix in the REAL sandbox before you finish:\n"
            f"    python3 -m worker.solver_smoke <script> [args] --timeout N\n"
            f"Do NOT re-ship until that reports exit_code 0."
        )
    return ""


def _prejudge_stop_metrics(job_id: str, summary: dict | None) -> tuple[int, float]:
    """Best available cumulative main-turn and dollar observations for a stop.

    The heartbeat writes the live values to meta while the in-memory summary
    receives a ResultMessage only at turn boundaries.  Use both, conservatively
    taking the largest non-negative observation, so a prejudge escalation does
    not report zero merely because the last session ended before its final
    ResultMessage.  Dollars remain explicitly an estimate in the caller's
    wording; this helper never turns them into authoritative billing.
    """
    summary = summary or {}
    try:
        meta = read_meta(job_id) or {}
    except Exception:
        meta = {}

    turns: list[int] = []
    for value in (
        meta.get("agent_turns"),
        summary.get("agent_turns"),
        summary.get("messages"),
        (summary.get("result") or {}).get("num_turns")
        if isinstance(summary.get("result"), dict) else None,
    ):
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            continue
        if parsed >= 0:
            turns.append(parsed)

    def _money(value) -> float:
        try:
            return max(0.0, float(value or 0.0))
        except (TypeError, ValueError):
            return 0.0

    banked = _money(meta.get("cost_usd_prior_sessions"))
    subagents = _money(summary.get("cost_usd"))
    result = summary.get("result") if isinstance(summary.get("result"), dict) else {}
    main_now = _money((result or {}).get("total_cost_usd"))
    if main_now <= 0:
        main_now = _money(summary.get("cost_usd_estimate"))
    if main_now <= 0:
        main_now = _money(estimate_cost_from_tokens(
            summary.get("agent_tokens"), summary.get("model")
        ))
    costs = (
        _money(meta.get("cost_usd")),
        banked + _money(meta.get("cost_usd_estimate")),
        banked + main_now + subagents,
    )
    return (max(turns, default=0), max(costs, default=0.0))


def write_why_stopped(
    work_dir: Path,
    *,
    stop_kind: str,
    attempt_idx: int,
    max_attempts: int,
    judge_out: dict | None,
    sandbox_result: dict | None,
    summary: dict | None,
    log_fn,
) -> None:
    """Drop a human-readable WHY_STOPPED.md when the auto-retry loop
    exits without a flag. Consolidates everything an operator would
    otherwise reconstruct from run.log + meta.json:

      * which stop condition fired (judge stop / budget / no hint / error)
      * judge's structured diagnosis (what worked, what failed, the
        specific failing line, alternative paths) when present
      * postjudge retry_hint verbatim (even on STOP — informational)
      * stdout / stderr tails so the reader doesn't have to dig
      * suggested next actions (manual /retry with a hint, /resume,
        give up and read report.md, etc.)

    Lives in the work tree so /retry + /resume carry it forward as
    reference. Best-effort: any write error is logged and swallowed.
    """
    try:
        judge_out = judge_out or {}
        sandbox_result = sandbox_result or {}
        summary = summary or {}

        verdict = (judge_out.get("verdict") or "unknown").strip()
        next_action = (judge_out.get("next_action") or "continue").lower()
        stop_reason = (judge_out.get("stop_reason") or "").strip()
        failure_code = (judge_out.get("failure_code") or "").strip().lower()
        retry_hint = (judge_out.get("retry_hint") or "").strip()
        diagnosis = (judge_out.get("specific_diagnosis") or "").strip()
        what_worked = judge_out.get("what_worked") or []
        what_failed = judge_out.get("what_failed") or []
        alternatives = judge_out.get("alternative_paths") or []
        if not isinstance(what_worked, list):
            what_worked = []
        if not isinstance(what_failed, list):
            what_failed = []
        if not isinstance(alternatives, list):
            alternatives = []

        exit_code = sandbox_result.get("exit_code")
        timed_out = bool(sandbox_result.get("timeout"))
        killed = bool(sandbox_result.get("killed_by_supervise"))
        stdout_tail = (sandbox_result.get("stdout") or "")[-1500:]
        stderr_tail = (sandbox_result.get("stderr") or "")[-1500:]

        header = _STOP_KIND_HEADERS.get(stop_kind, "Job stopped")
        cap_str = "∞" if max_attempts < 0 else str(max_attempts)
        when = datetime.now().isoformat(timespec="seconds")

        # Top: at-a-glance summary so the reader doesn't have to read
        # the whole doc to make a /retry decision.
        out: list[str] = [
            f"# Why this run stopped",
            "",
            f"**Reason class**: `{stop_kind}` — {header}",
            f"**Postjudge verdict**: `{verdict}`"
            + (f" (failure_code: `{failure_code}`)" if failure_code else ""),
            f"**Judge next_action**: `{next_action}`",
            f"**Attempt**: {attempt_idx} / {cap_str}",
            f"**When**: {when}",
            "",
        ]

        # UNREPRODUCED FLAG CANDIDATES — lead with these when they exist.
        # A job can END as no_flag while the REAL flag is already sitting in
        # meta.flag_candidates: the two-tier scan only promotes a flag seen in a
        # TRUSTED source (runner stdout/stderr, OOB collector), and a sandbox run
        # that failed for an ENVIRONMENT reason never produces one — so a genuine
        # capture made by the agent's own testing stays a candidate. Job
        # e1b933afc137 lost a confirmed-correct flag that way (runner could not
        # compile the decrypt harness), and gdb/sage parity jobs did the same.
        # This does NOT promote anything — flag curation stays MANUAL (📌/🗑️ UI);
        # it only stops the candidate from being invisible in a wall of failure.
        # job_id is derived from the work dir (…/jobs/<id>/work) so the signature
        # and every call site stay untouched.
        try:
            _cands = (read_meta(Path(work_dir).parent.name) or {}).get(
                "flag_candidates"
            ) or []
        except Exception:
            _cands = []
        if _cands and not (summary.get("flags") or []):
            out += [
                "## ⚑ Unreproduced flag candidate(s) — CHECK THESE FIRST",
                "",
                "The agent observed the following flag-shaped string(s) during the "
                "run, but the sandbox never re-produced them from a TRUSTED source, "
                "so they were NOT promoted and the job reads as no_flag:",
                "",
            ] + [f"- `{c}`" for c in _cands[:5]] + [
                "",
                "These are MACHINE-UNVERIFIED. One may be the real flag (confirm it "
                "against the challenge and pin it in the UI), or a decoy/sample the "
                "challenge planted. Do NOT hand a candidate to a solver to print "
                "back — only a fresh capture through the real chain counts.",
                "",
            ]

        if stop_reason:
            out += [
                "## Judge's stop reason (verbatim)",
                "",
                f"> {stop_reason}",
                "",
            ]

        if diagnosis:
            out += [
                "## Specific diagnosis (the failing line + observed signal)",
                "",
                f"> {diagnosis}",
                "",
            ]

        if what_worked or what_failed:
            out += ["## What worked vs. what failed", ""]
            if what_worked:
                out += ["**Worked:**"] + [f"- {x}" for x in what_worked[:5]] + [""]
            if what_failed:
                out += ["**Failed:**"] + [f"- {x}" for x in what_failed[:5]] + [""]

        if alternatives:
            out += [
                "## Alternative paths not yet tried (judge's suggestions)",
                "",
            ] + [f"- {x}" for x in alternatives[:5]] + [""]

        if retry_hint:
            out += [
                "## Postjudge retry hint",
                "",
                "Judge emitted a retry hint even though it voted STOP — "
                "this is the model's best guess at a recovery direction. "
                "On a stop verdict it's INFORMATIONAL; treat it as a "
                "starting prompt for `/retry` with a manual hint rather "
                "than auto-truth.",
                "",
                "```",
                # 3200 for the same reason as RESUME_STATE.md: the longest
                # deterministic hint is ~2800 chars with its recipe last, and
                # this is a file the operator reads, not a prompt.
                retry_hint[:3200],
                "```",
                "",
            ]

        # Execution evidence so the reader can sanity-check judge's call
        if exit_code is not None or timed_out or killed or stdout_tail or stderr_tail:
            out += ["## Last sandbox run", ""]
            if exit_code is not None:
                out.append(f"- exit_code: `{exit_code}`")
            if timed_out:
                out.append("- runner timeout fired before container exit")
            if killed:
                out.append("- supervise judge killed the container on stalled output")
            out.append("")
            if stdout_tail:
                out += ["**stdout tail** (last 1500 B):", "", "```",
                         stdout_tail, "```", ""]
            if stderr_tail:
                out += ["**stderr tail** (last 1500 B):", "", "```",
                         stderr_tail, "```", ""]

        # Operator playbook — concrete next steps. Different per kind.
        out += ["## Recommended next steps", ""]
        if stop_kind == "judge_stop":
            out += [
                "Judge is sure THIS approach can't capture the flag — "
                "auto-retry won't help. Options:",
                "",
                "1. **Read `report.md` + this file** and decide whether "
                "judge's diagnosis matches reality. Judge is wrong "
                "sometimes (esp. on novel chal-author tricks).",
                "2. **`/retry` with a manual hint** that explicitly steers "
                "to one of the *Alternative paths* above (or your own "
                "new lead). NOTE: this stop kind SHEDS the prior "
                "conversation — the halt writes `judge_next_action=stop`, "
                "and /retry reads that field to SKIP the SDK session fork "
                "and boot a clean context. Make the hint SELF-CONTAINED: "
                "the new agent inherits only the carried work tree "
                "(`report.md`, `findings.json`, this file), not main's "
                "reasoning. (Its preamble may still be stamped "
                "`prior-session fork requested` — that banner is keyed on "
                "the operator's 'fresh start' checkbox, not on the fork "
                "that actually happened.)",
                "3. **`/resume`** if you want to keep the work tree + "
                "session AND let main re-think from where it was, "
                "without injecting a new direction.",
                "4. **Manual review**: download artifacts, read decomp / "
                "exploit.py / sandbox stdout yourself. The structured "
                "primitives in `findings.json` may help.",
            ]
        elif stop_kind == "budget_exhausted":
            out += [
                "Hit the auto-retry cap (`AUTO_RETRY_MAX`); main was "
                "still making progress on the last attempt. Options:",
                "",
                "1. **`/retry` to add another retry budget** (the new "
                "job starts fresh with cap=AUTO_RETRY_MAX again).",
                "2. **Raise `AUTO_RETRY_MAX`** in `.env` and `/retry` "
                "if the chal genuinely needs more iterations.",
                "3. **Stop and read report.md** if the diagnoses across "
                "attempts converge on the same blocker (judge missed "
                "the structural stop).",
            ]
        elif stop_kind == "no_hint":
            out += [
                "Postjudge couldn't propose a concrete next step. "
                "Usually means the exploit is correct and the chal "
                "isn't responding as expected, OR every reasonable "
                "alternative has been tried. Options:",
                "",
                "1. **`/retry` with a manual hint** if you have domain "
                "knowledge the agent lacks.",
                "2. **Run exploit.py manually** against the target — "
                "the runner sandbox sometimes differs from a local "
                "shell (proxy, DNS, MTU).",
                "3. **Check the target is alive**: `nc -vz <host> <port>`.",
            ]
        elif stop_kind == "prejudge_dead_target":
            out += [
                "Prejudge supplied the structured observation "
                "`target_liveness=dead` after a current direct probe, so "
                "THIS ship attempt was blocked before the sandbox started "
                "and rewriting the same script cannot repair the endpoint. "
                "The escalation reads `target_liveness` ONLY — it does not "
                "check whether anything ran, so earlier attempts in this job "
                "may well have executed. Read the `sandbox runs=` count in "
                "the stop reason above and those runs' output before "
                "concluding nothing ran. Options:",
                "",
                "1. **Re-provision/restart the challenge instance**, then update "
                "the job's target URL(s) in the UI.",
                "2. **Re-probe the new endpoint directly** before `/retry`; do "
                "not reuse the expired host:port from old artifacts.",
                "3. **Keep the existing work tree**. Its exploit/report may be "
                "useful once the operator supplies a live target.",
            ]
        elif stop_kind == "prejudge_blocked_no_run":
            out += [
                "Two prejudge ship-blocks occurred without one real sandbox "
                "execution. The first redirect was preserved; the second block "
                "is escalated so a third full analysis turn is not automatic. "
                "Options:",
                "",
                "1. **Read the two prejudge issue sets** and decide whether a "
                "manual hint identifies a genuinely different fix.",
                "2. **Use `/retry` only with that concrete hint**. The two "
                "historical redirect-saved jobs named above expired from TTL, "
                "so this threshold deliberately records that unresolved risk.",
            ]
        elif stop_kind == "judge_shadow_no_verdict":
            out += [
                "Judge mode was `shadow`: it records prejudge/postjudge inputs "
                "for later evaluation but intentionally returns no verdict to "
                "the live loop. The `unknown` line above is therefore an absence "
                "of a gating opinion, not a judge decision to stop. Options:",
                "",
                "1. **Inspect the real sandbox stdout/stderr**; those execution "
                "facts, not the shadow placeholder, explain the failed attempt.",
                "2. **Use `/retry` with a manual hint** if the output exposes an "
                "actionable correction. Shadow mode cannot synthesize one live.",
            ]
        elif stop_kind == "reviewer_redirect_no_run":
            out += [
                "Judge mode was `shadow`, so the loop asked the routed reviewer "
                "for one independent correction and delivered it to main. The "
                "following real sandbox run still produced no capture, live "
                "judge verdict, or further retry hint. The reviewer redirect is "
                "one-shot, so the loop stops instead of alternating reviewers "
                "and main turns without a bound. Options:",
                "",
                "1. **Inspect both sandbox outputs and the reviewer-directed "
                "edit**; the second execution is the newest ground truth.",
                "2. **Use `/retry` with a manual hint** only if you can name a "
                "new primitive or test that neither run attempted.",
            ]
        elif stop_kind == "unsolvable_by_analysis":
            out += [
                "The script's OWN artifacts (exploit / report.md) admit no "
                "working RCE chain, and prejudge's calibrated "
                "`flag_likelihood` was ≈0 — a confident TRUE-NEGATIVE, not a "
                "fixable near-miss. The loop conceded instead of redirecting "
                "an unsatisfiable \"fix the no-chain defect\" hint (which would "
                "just re-derive the same dead end at full cost). Options:",
                "",
                "1. **Read `report.md` + `chain.json`** — any primitive marked "
                "`verified=true` (e.g. a libc-base leak) is a REAL, reusable "
                "result; the chal may be leak-only by construction.",
                "2. **`/retry` with a manual hint ONLY** if you know a "
                "primitive the agent demonstrably missed — a bare re-run will "
                "reach the same true-negative.",
                "3. **Confirm the remote is alive** (`nc -vz <host> <port>`) in "
                "case the low likelihood was secondary to a dead target.",
            ]
        elif stop_kind == "no_artifact":
            out += [
                "The auto-run loop looked for the solver and found nothing — "
                "neither in `work/` nor at the job root. This is almost always "
                "a LOCATION or FILENAME mismatch, not an unsolvable challenge: "
                "the orchestrator only executes specific names, so a solver "
                "written as e.g. `solve.py` or into a scratch dir is invisible "
                "to it even though the analysis behind it may be complete.",
                "",
                "1. **Look for the file yourself** — `ls -R` the job dir. If a "
                "solver exists under another name, rename it to the expected "
                "one and use **Run in sandbox**; nothing needs re-deriving.",
                "2. **Read `report.md`** — the reasoning is usually intact even "
                "when the artifact is misplaced.",
                "3. **`/retry`** only if there is genuinely no solver. The prior "
                "conversation is NOT discarded for this stop kind, so the agent "
                "keeps its context.",
            ]
        elif stop_kind == "conceded_by_deletion":
            out += [
                "Main removed the deliverable after reading the postjudge "
                "hint. That is the give-up path the postjudge message itself "
                "offers (\"`rm -f ./<script>` if you're giving up\"), so it is "
                "a DELIBERATE concession, not a missed instruction — and this "
                "file does NOT adjudicate whether the challenge is solvable.",
                "",
                "1. **Read main's LAST message in `run.log`** (tag `[main] "
                "AGENT:`) — it states why it conceded. That reasoning, not "
                "this header, is the evidence.",
                "2. **Read `report.md`** — a concession run usually leaves the "
                "most complete write-up of the run, including any primitive "
                "that WAS verified and is reusable.",
                "3. **If the concession rests on an impossibility argument, "
                "attack its ENUMERATION** before accepting it: such arguments "
                "here have failed on unstated premises (a search scoped to two "
                "files, one tier, one input shape) rather than on their logic.",
                "4. **`/retry` with a hint that names a surface the argument "
                "did not cover** — a bare re-run re-derives the same dead end. "
                "Note this stop kind DOES shed the prior conversation "
                "(`judge_next_action=stop` makes /retry start a fresh session), "
                "which is usually what you want after a concession: the agent's "
                "own argument is what talked it into stopping. Its reasoning "
                "survives in `report.md`, so put the surface it missed in the "
                "hint rather than relying on it to remember.",
            ]
        elif stop_kind == "agent_error":
            out += [
                "Main's SDK session died abnormally (SIGKILL / timeout / "
                "transport error). The sandbox + judge results above "
                "are the rescue value from the LAST clean attempt. "
                "Options:",
                "",
                "1. **`/retry`** — fork a fresh SDK session against the "
                "carried work tree. Usually clears transient SDK / API "
                "issues.",
                # Name the slot that actually ran this job. The worker is one
                # container per slot now, so a hard-coded `-worker-1` would
                # point at the wrong container's logs for anything on slot 2+.
                "2. **Check worker container health**: `docker logs "
                f"hextech_ctf_tool-worker-"
                f"{(os.environ.get('WORKER_SLOT') or '1').strip()} "
                "--tail 100`.",
            ]
        elif stop_kind == "policy_refusal":
            out += [
                "Main's turn was blocked by the server-side Usage-Policy "
                "classifier (AUP). The block is on the ACCUMULATED "
                "conversation, so retrying IN PLACE re-blocks "
                "deterministically — the orchestrator therefore halted "
                "without burning a re-block turn. It had already walked its "
                "recovery ladder first (a fresh session, then the other "
                "configured provider): this file is written ONLY once that "
                "ladder is exhausted or could not start, so unless a rung "
                "failed to START, a plain /retry on a clean context has "
                "ALREADY been tried. Grep `run.log` "
                "for `AUP-blocked — recovering via` to see which steps were "
                "spent, and for `recovery could not start` for one that "
                "never ran. Options:",
                "",
                "1. **Treat the challenge class as the cause first** — a "
                "repeat block on a CLEAN context means the CONTENT (e.g. "
                "XSS-exfil / CSP-bypass), not the accumulated transcript, is "
                "what the classifier objects to. Re-framing the task text is "
                "the lever; re-running it unchanged is not.",
                "2. **`/retry`** — still worth one run when the ladder step "
                "failed to START rather than re-blocking, or when you attach "
                "a hint that re-frames the objective. On a policy_refusal "
                "the fork is force-skipped automatically (no need to tick "
                "'fresh start'): the new agent boots on a clean context and "
                "reads the carried `pre_recon_reply.txt` / `report.md` "
                "instead of re-inheriting the blocked transcript.",
            ]
        elif stop_kind == "cost_cap":
            out += [
                "Cumulative known spend from main's session total, the "
                "subagent accumulator, and numeric `cost_usd` values on "
                "`role=reviewer` rows in `usage.jsonl` reached the "
                "`COST_CAP_USD` circuit breaker (default $40). "
                "`role=judge` rows are not included, and reviewer rows without "
                "a numeric dollar value contribute $0 to this breaker. Read "
                "`usage.jsonl` by role/provider before attributing the spend. "
                "This fires when a run keeps "
                "spending without capturing a flag — often an anchored frame "
                "that won't converge (the anti-AI false-negative class, where "
                "the model mis-frames rather than hits a true dead-end). The "
                "cap is a BACKSTOP, not a verdict on solvability. Options:",
                "",
                "1. **Read `report.md` + this file** — decide whether the "
                "approach was genuinely converging or stuck on one frame that "
                "subagent evidence had already disconfirmed.",
                "2. **`/retry` (fresh start)** — a clean context is the most "
                "reliable way to break an anchored frame the in-place session "
                "could not abandon.",
                "3. **Raise `COST_CAP_USD`** in `.env` and `/retry` if the "
                "chal legitimately needs the spend (a hard multi-stage heap "
                "solve can run several debuggers).",
                "4. **`/retry` with a manual hint** that steers to a DIFFERENT "
                "frame if your reading says the approach itself was wrong.",
            ]
        else:
            out += [
                "1. **`/retry`** with whatever hint your reading of the "
                "evidence suggests.",
                "2. **Read report.md** for main's own write-up.",
            ]
        out += [""]

        # Pointers to the other documents the operator should read.
        out += [
            "## Related files in this job",
            "",
            "- `report.md` — main's own write-up of the analysis",
            "- `findings.json` — structured vuln + chain (auto-generated by "
            "the report phase)",
            "- `exploit.py` / `solver.py` — the script that ran",
            "- `exploit.py.stdout` / `exploit.py.stderr` — runner output",
            "- `THREAT_MODEL.md` — main's threat model bootstrap (if written)",
            "- `run.log` — full event timeline (look for `[main]`, "
            "`[judge]`, `[runner]` tags)",
            "",
            "---",
            "",
            "_Generated by `write_why_stopped()` so `/retry` + `/resume` "
            "carry the diagnosis forward in the work tree._",
        ]

        path = Path(work_dir) / WHY_STOPPED_FILENAME
        path.write_text("\n".join(out))
        log_fn(f"[orchestrator] wrote {WHY_STOPPED_FILENAME} ({path.stat().st_size} B)")
        # Mirror to job root so any stale carry-copy from a retry parent
        # gets overwritten. Pre-sandbox carry (analyzer loop) copies
        # work/WHY_STOPPED.md → jobroot/WHY_STOPPED.md only BEFORE each
        # sandbox attempt; on a terminal stop (judge_stop / budget /
        # no_hint / agent_error) the loop returns early and the root
        # copy keeps whatever the previous carry left there — often the
        # retry parent's old reason. Mirror unconditionally so root and
        # work/ never disagree after this call.
        try:
            root_path = Path(work_dir).parent / WHY_STOPPED_FILENAME
            if root_path != path:
                root_path.write_bytes(path.read_bytes())
        except Exception as mirror_err:
            log_fn(
                f"[orchestrator] WHY_STOPPED jobroot mirror failed: "
                f"{type(mirror_err).__name__}: {mirror_err}"
            )
    except Exception as e:
        log_fn(f"[orchestrator] write_why_stopped failed: {type(e).__name__}: {e}")


# Substrings to match against `/proc/<pid>/comm` (Linux comm is
# capped at TASK_COMM_LEN=16 bytes incl. null → 15 visible chars).
# We use substring match because long names get truncated:
#   qemu-system-aarch64 → "qemu-system-aar"
#   qemu-aarch64-static → "qemu-aarch64-st"
# Concrete incidents these patterns target:
#   2026-05-17 job 9a240a221f1b: debugger spawned `qemu-system-aarch64
#   ... -nographic -serial mon:stdio &` for kernel-pwn dynamic
#   analysis; when the agent finished its turn, qemu (280 MB RSS)
#   survived into the next job. Two-jobs-deep, the worker container
#   had TWO qemu instances both holding port forwards on :18000 and
#   ~512 MB combined.
#   2026-05-16 jobs with gdbserver: similar — gdbserver listens on
#   :1234 forever after the agent moves on.
#
# We do NOT match the bundled `claude` CLI (comm="claude") because
# it's the agent's own process. Only background helper executables
# are listed here; substring match means each entry below MUST be
# specific enough to not accidentally hit something we care about.
_JOB_END_KILL_COMM_SUBSTRINGS = (
    "qemu-system",     # qemu-system-aarch64 / -x86_64 / -arm / ...
    "qemu-aarch64",    # qemu-aarch64-static (user-mode)
    "qemu-arm",        # qemu-arm-static (user-mode)
    "gdbserver",       # exact match
)


def _find_job_orphan_pids() -> list[tuple[int, str]]:
    """Scan /proc for LIVING processes whose comm matches a kill pattern.

    Returns list of `(pid, comm)` tuples. Skips:
      * kernel threads (cmdline empty)
      * our own pid + ppid lineage (defense-in-depth — wouldn't
        match anyway since claude CLI's comm is "claude", but the
        belt-and-suspenders check is cheap and avoids self-kill if
        someone later adds a substring that hits "python")
      * **zombie processes** (State: Z) — already dead, waiting for
        their init/parent to reap them. Re-sending SIGKILL to a
        zombie is harmless but useless and would inflate the
        cleanup log. Real reap is init's job (container PID 1).
    """
    import os
    my_pid = os.getpid()
    my_ppid = os.getppid()
    hits: list[tuple[int, str]] = []
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return hits
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid in (my_pid, my_ppid, 1):
            continue
        try:
            comm = (entry / "comm").read_text().strip()
        except OSError:
            continue
        if not comm:
            continue
        # Skip zombies: state field on the first non-name line.
        try:
            status = (entry / "status").read_text(errors="ignore")
        except OSError:
            continue
        if "\nState:\tZ" in status:
            continue
        for needle in _JOB_END_KILL_COMM_SUBSTRINGS:
            if needle in comm:
                hits.append((pid, comm))
                break
    return hits


def cleanup_job_processes(log_fn) -> None:
    """SIGTERM (then SIGKILL after 2s) every background process whose
    `/proc/<pid>/comm` matches `_JOB_END_KILL_COMM_SUBSTRINGS`. Called
    from each analyzer's `finally` block so leftover qemu / gdbserver
    from this job doesn't leak into the next.

    Best-effort: every step is wrapped — orphan-process cleanup must
    never crash the analyzer. Uses /proc scan + os.kill instead of
    pkill because Linux comm is 15-char-capped (`qemu-system-aarch64`
    → comm `qemu-system-aar`), so `pkill -x qemu-system-aarch64`
    silently matches zero processes.
    """
    import os
    import signal as _signal
    import time as _time

    hits = _find_job_orphan_pids()
    if not hits:
        return
    sent_term: list[int] = []
    for pid, comm in hits:
        try:
            os.kill(pid, _signal.SIGTERM)
            sent_term.append(pid)
            log_fn(f"[cleanup] SIGTERM pid={pid} comm={comm}")
        except ProcessLookupError:
            continue
        except PermissionError as e:
            log_fn(f"[cleanup] cannot kill pid={pid}: {e}")
            continue
    if not sent_term:
        return
    # Give the targets ~2s to flush sockets + exit cleanly.
    _time.sleep(2)
    survivors = _find_job_orphan_pids()
    for pid, comm in survivors:
        try:
            os.kill(pid, _signal.SIGKILL)
            log_fn(f"[cleanup] SIGKILL survivor pid={pid} comm={comm}")
        except ProcessLookupError:
            continue
        except PermissionError:
            continue


def write_fallback_artifacts(work_dir: Path, log_fn, module: str | None = None) -> None:
    """Drop a probe-only exploit.py + report.md when main's session
    ends WITHOUT producing them. Best-effort: any write error is logged
    and swallowed (the caller's downstream code handles "no artifact"
    fine — this is purely an upgrade to "no_flag / partial" status
    instead of "failed").

    `module` selects the skeleton shape: web gets an HTTP probe (a pwn
    socket skeleton is useless against an HTTP target — job
    5f4bb59d0b44); everything else gets the pwntools skeleton.
    """
    is_web = (module or "").lower().strip() == "web"
    exploit_template = _FALLBACK_WEB_EXPLOIT_TEMPLATE if is_web else _FALLBACK_EXPLOIT_TEMPLATE
    try:
        ex = work_dir / "exploit.py"
        if not ex.is_file():
            ex.write_text(exploit_template)
            log_fn(f"[orchestrator] wrote fallback ./exploit.py ({len(exploit_template)} B"
                   f"{', web-shaped' if is_web else ''})")
        rp = work_dir / "report.md"
        if not rp.is_file():
            rp.write_text(_FALLBACK_REPORT_TEMPLATE)
            log_fn(f"[orchestrator] wrote fallback ./report.md ({len(_FALLBACK_REPORT_TEMPLATE)} B)")
    except Exception as e:
        log_fn(f"[orchestrator] fallback artifact write failed: {e}")


# Schema for findings.json — checked AFTER main writes it; missing/wrong
# fields produce a "findings.json invalid: ..." warning that gets folded
# into the next auto-retry user-turn so main fixes it on the retry.
# Keep tight enough to catch the obvious mistakes (wrong types, missing
# required keys) without becoming a full JSON-schema implementation —
# we don't ship a validator dep here.
_FINDINGS_REQUIRED_TOP_KEYS = {
    "schema_version", "chal_name", "glibc_version", "arch",
    "mitigations", "vulns", "chain", "exploit_status", "caveats",
}
_FINDINGS_REQUIRED_VULN_KEYS = {
    "id", "bug_class", "file", "line", "trigger",
    "primitive_class", "primitive_quality",
}
_FINDINGS_REQUIRED_CHAIN_KEYS = {
    "technique_name", "how2heap_file", "steps",
    "one_gadget_offset", "expected_observable",
}
_FINDINGS_PRIM_QUALITY = {"HIGH", "MED", "LOW"}
_FINDINGS_PRIM_CLASS = {
    "AAW", "RCE", "UAF", "AAR",
    "partial-write", "info-leak", "dos",
}
_FINDINGS_EXPLOIT_STATUS = {
    "drafted", "tested-failed", "tested-partial",
    "flag-captured", "aborted",
    # web3: the challenge's own predicate (Setup.isSolved()) flipped on a LOCAL
    # chain and there was no flag to capture — the exploit is proven, the
    # challenge is not necessarily finished. Without this value the closest
    # option is "flag-captured", which overstates: job 5e0de4572503 verified
    # `isSolved after = True` on anvil, had no flag to take, and filed
    # flag-captured anyway. The whole point of the web3 prompt is that a local
    # pass is a rehearsal, so the status enum has to be able to say so.
    "local-solved",
}


def validate_findings(work_dir: Path) -> list[str]:
    """Return list of human-readable findings.json schema issues.
    Empty list = either valid OR file missing (callers decide which).
    Used by the auto-retry loop to surface schema drift back to main
    on the next turn.
    """
    p = work_dir / "findings.json"
    if not p.is_file():
        return []
    issues: list[str] = []
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError as e:
        return [f"findings.json is not valid JSON: {e}"]
    if not isinstance(data, dict):
        return ["findings.json top-level is not an object"]
    missing_top = _FINDINGS_REQUIRED_TOP_KEYS - set(data.keys())
    if missing_top:
        issues.append(f"findings.json missing top-level keys: {sorted(missing_top)}")
    vulns = data.get("vulns")
    if not isinstance(vulns, list) or not vulns:
        issues.append("findings.json `vulns` must be a non-empty array")
    else:
        any_high = False
        for i, v in enumerate(vulns):
            if not isinstance(v, dict):
                issues.append(f"findings.json vulns[{i}] is not an object")
                continue
            m = _FINDINGS_REQUIRED_VULN_KEYS - set(v.keys())
            if m:
                issues.append(f"findings.json vulns[{i}] missing keys: {sorted(m)}")
            pc = v.get("primitive_class")
            if pc is not None and pc not in _FINDINGS_PRIM_CLASS:
                issues.append(
                    f"findings.json vulns[{i}].primitive_class={pc!r} "
                    f"not in {sorted(_FINDINGS_PRIM_CLASS)}"
                )
            pq = v.get("primitive_quality")
            if pq is not None and pq not in _FINDINGS_PRIM_QUALITY:
                issues.append(
                    f"findings.json vulns[{i}].primitive_quality={pq!r} "
                    f"not in {sorted(_FINDINGS_PRIM_QUALITY)}"
                )
            if pq == "HIGH":
                any_high = True
        if vulns and not any_high:
            issues.append(
                "findings.json has no HIGH-tier primitive — chain made "
                "of MED/LOW stepping stones alone won't capture a flag. "
                "See QUALITY TIERS in the heap cheat-sheet."
            )
    chain = data.get("chain")
    if not isinstance(chain, dict):
        issues.append("findings.json `chain` must be an object")
    else:
        m = _FINDINGS_REQUIRED_CHAIN_KEYS - set(chain.keys())
        if m:
            issues.append(f"findings.json chain missing keys: {sorted(m)}")
        if (chain.get("technique_name")
                and chain.get("how2heap_file") is None):
            issues.append(
                f"findings.json chain.technique_name="
                f"{chain.get('technique_name')!r} set but how2heap_file "
                "is null — point at /opt/how2heap/glibc_<VER>/<name>.c "
                "if it exists in the corpus, else explain in caveats."
            )
    status = data.get("exploit_status")
    if status is not None and status not in _FINDINGS_EXPLOIT_STATUS:
        issues.append(
            f"findings.json exploit_status={status!r} not in "
            f"{sorted(_FINDINGS_EXPLOIT_STATUS)}"
        )
    glibc_in_profile = None
    try:
        profile_path = work_dir / ".chal-libs" / "libc_profile.json"
        if profile_path.is_file():
            pdata = json.loads(profile_path.read_text())
            glibc_in_profile = pdata.get("version")
    except Exception:
        pass
    if (glibc_in_profile and data.get("glibc_version")
            and data["glibc_version"] != glibc_in_profile):
        issues.append(
            f"findings.json glibc_version={data['glibc_version']!r} "
            f"disagrees with libc_profile.json ({glibc_in_profile!r}). "
            "Trust the profile — it was extracted from the actual libc."
        )
    return issues


# Heap-allocation needles used by `_chal_source_has_heap_ops` to gate
# SCAFFOLD_NUDGE. Kept narrow on purpose — TOCTOU race / format-string /
# syscall-only pwn chals routinely score `heap_advanced=True` via the
# work-tree classifier (custom .so + glibc 2.31) yet have zero heap
# operations in source, in which case the heap scaffolds don't apply
# and the nudge is pure noise. Adding more keywords (e.g. `chunk`,
# `bin`) would over-trigger on disassembly artifacts.
_HEAP_OP_NEEDLES = (
    b"malloc(", b"calloc(", b"realloc(", b"free(",
    b"tcache", b"fastbin", b"smallbin", b"largebin",
    b"unsorted_chunks", b"main_arena",
    b"_int_malloc", b"_int_free",
)


def _chal_source_has_heap_ops(
    work_dir: Path,
    *,
    max_files: int = 40,
    max_bytes: int = 50_000,
) -> bool:
    """Quick grep across `chal/` + `decomp*/` for heap-allocation
    operations. Returns True when in doubt — caller treats False as a
    strong signal to suppress SCAFFOLD_NUDGE.

    Looks at .c / .cpp / .cc / .h / .hpp / .py in `chal/` (operator-
    supplied source) and .c in any `decomp*/` directory (Ghidra
    output). Reads the first `max_bytes` of each file and gives up
    after `max_files` candidates. The cap exists because a glibc
    source mirror would otherwise hit every needle trivially —
    we want the OPERATOR's chal source, not transitive deps.

    Concrete incident 2026-05-25 (job bfce7f3e0c11): uniqdb chal is
    a TOCTOU race on plain .bss globals (no malloc/free anywhere).
    SCAFFOLD_NUDGE fired anyway because `heap_advanced=True` came
    from the custom-libuniqdb-detection branch of the classifier,
    not from actual heap usage. Main had to spend ~30 seconds
    writing a "Why no /opt/scaffold/ used" section to dispel it.
    """
    candidates: list[Path] = []
    chal_dir = work_dir / "chal"
    if chal_dir.is_dir():
        for ext in ("*.c", "*.cpp", "*.cc", "*.h", "*.hpp", "*.py"):
            try:
                candidates.extend(chal_dir.rglob(ext))
            except OSError:
                pass
    for d in work_dir.glob("decomp*"):
        if d.is_dir():
            try:
                candidates.extend(d.rglob("*.c"))
            except OSError:
                pass
    if not candidates:
        return True  # no chal source visible -> don't suppress
    for p in candidates[:max_files]:
        try:
            data = p.read_bytes()[:max_bytes]
        except OSError:
            continue
        if any(n in data for n in _HEAP_OP_NEEDLES):
            return True
    return False


# Sentinel: "the restart could not even be attempted" — distinct from a restart
# that ran and returned None (no sandbox result), which is a legitimate outcome
# the caller must not confuse with failure to start.
_AUP_RESTART_FAILED = object()


async def _aup_restart_session(
    job_id: str,
    *,
    step: str,
    options,
    original_prompt: str,
    summary: dict,
    work_dir: Path,
    artifact_names: tuple[str, ...],
    auto_run: bool,
    sandbox_runner,
    log_fn,
):
    """Re-enter the main session with a CLEAN context after a policy refusal.

    `step` is one of _AUP_RECOVERY_STEPS:
      fresh_session   same backend, `resume` dropped so no accumulated
                      transcript is re-presented.
      other_provider  the same work tree handed to the other configured
                      backend, which applies its own policy.

    Nothing here rewrites or re-words the request — only the conversation
    history is dropped and, at the second step, the backend changes. Each step
    runs at most once per job (see aup_recovery_step); a refusal that survives
    a clean context is about the work itself, not the transcript, and further
    sessions would just repeat it.

    Returns whatever the restarted session returns, or _AUP_RESTART_FAILED when
    it could not be started at all, so the caller falls back to the historical
    halt rather than reporting progress that never happened.
    """
    from dataclasses import replace as _dc_replace

    try:
        new_options = _dc_replace(options, resume=None)
    except Exception:
        try:
            import copy as _copy

            new_options = _copy.copy(options)
            setattr(new_options, "resume", None)
        except Exception:
            return _AUP_RESTART_FAILED

    if step == "other_provider":
        from modules.agent_provider import default_model_for

        try:
            from modules.grok_acp import GrokSessionOptions as _GSO

            # The Claude system prompt has to be ADAPTED, not copied. The
            # normal Grok path runs it through adapt_system_prompt_for_grok
            # (its only other call site is the Grok branch of
            # make_main_session_options), which rewrites Claude-specific
            # delegation wiring — mcp__team__spawn_subagent and the Agent tool
            # — into Grok's native equivalents. Handing Grok the raw text tells
            # it to call tools that do not exist in its runtime.
            _sp = getattr(options, "system_prompt", "") or ""
            try:
                _sp = adapt_system_prompt_for_grok(_sp)
            except Exception:
                pass
            new_options = _GSO(
                system_prompt=_sp,
                model=default_model_for("grok"),
                cwd=str(getattr(options, "cwd", work_dir) or work_dir),
                effort=getattr(options, "effort", None),
                env=dict(getattr(options, "env", None) or {}),
                resume=None,
                add_dirs=list(getattr(options, "add_dirs", None) or []),
            )
            summary["aup_provider_switch"] = "grok"
            # The cost estimator prices tokens from summary["model"], which the
            # analyzer set once to the Claude model and never reassigns. Leave
            # it and a Grok successor's spend is billed at Claude rates.
            summary["model"] = default_model_for("grok")
            # Stamp the JOB's backend. Settings still says "claude" — this
            # switch is per job and in memory — so every consumer that asks
            # "which backend produced this?" needs a job-scoped answer:
            # capture_session_id (so a Grok ACP id never lands in
            # claude_session_id, which /retry feeds to `claude --resume`), the
            # UI's provider label, and cost attribution.
            try:
                write_meta(job_id, agent_provider="grok",
                           agent_provider_label="Grok (AUP fallback)")
            except Exception:
                pass
            log_fn(
                "[orchestrator] AUP recovery: handing the unchanged work tree "
                "to Grok, which applies its own policy"
            )
        except Exception as e:
            log_fn(
                f"[orchestrator] AUP recovery: cannot build Grok options "
                f"({type(e).__name__}) — skipping this step"
            )
            return _AUP_RESTART_FAILED

    # A clean session has NO history, so the opening turn must be the carried
    # state rather than "carry on where you left off" — telling a context-less
    # agent to continue a conversation it cannot see wastes turns hunting for
    # it. Same lesson as _retry_preamble's fresh=True branch.
    # The ORIGINAL prompt must come along. It carries the mission, the target,
    # the flag format and the pre-recon summary — none of which the new session
    # can recover from the work tree, and RESUME_STATE.md is a pointer list, not
    # a task statement. An earlier draft appended a `summary["initial_prompt_
    # tail"]` that nothing ever set, so the restarted agent would have booted
    # with the preamble alone and no idea what it was solving.
    resume_prompt = (
        "[session restarted — you have NO prior conversation]\n"
        "A previous session on this job ended early. Its files are intact in "
        "your cwd, and `RESUME_STATE.md` lists what was already established "
        "and what to read first. Read that FIRST, then continue the solve. Do "
        "not re-run analysis those artifacts already answer. The original "
        "task follows unchanged.\n\n"
    ) + (original_prompt or "")

    # The error belongs to the DEAD session: left in place it would make the
    # restarted run look like it failed the moment it produced anything.
    #
    # But it has to come BACK if the restart cannot start. The caller then falls
    # through to the historical halt, and the job is finalized from this same
    # summary — without the marker, meta.error_kind would not say
    # policy_refusal, and api/routes/retry.py keys `prior_aup_blocked` on
    # exactly that field. Clearing it unconditionally would therefore disable
    # the MANUAL cure as well as the automatic one.
    # Every key here is SESSION-scoped, and `summary` is shared by reference
    # with the successor. Before this change no summary ever spanned two
    # sessions in one process, so each of these leaks is new:
    #
    #   fallback_artifact_used  the guard at ~7677 is
    #                           `is_error and not agent_error and not
    #                           fallback_artifact_used`. A turn-0 refusal with
    #                           no artifact writes a probe-only fallback and
    #                           sets this — and that write is ALSO what makes
    #                           `picked` non-empty and the ladder reachable. So
    #                           on exactly the path that reaches recovery, the
    #                           leak silences the successor's OWN refusal:
    #                           agent_error_kind stays None, rung 2 is never
    #                           consulted, and the loop queries feedback into an
    #                           already-blocked session.
    #   result / cost_usd_estimate
    #                           the banking preamble runs at function-body level
    #                           on re-entry and re-banks the dead session's cost
    #                           (measured 2.0x); _snapshot_cost is write-once so
    #                           the successor's own spend never lands.
    #   prejudge_block_redirects / prejudge_block_sigs
    #                           the redirect that spent the counter was never
    #                           delivered — the ladder fires before
    #                           `client.query(feedback)` — so the successor
    #                           would inherit a budget it never got the benefit
    #                           of, and its FIRST block would satisfy the
    #                           concede-unsolvable gate's `n >= 1`.
    #
    # Deliberately KEPT: `method_change_retries` (capped once per JOB by
    # design) and `judge_hints` (they describe the carried ARTIFACT, which the
    # successor inherits, not the dead transcript).
    _SESSION_SCOPED = (
        "agent_error", "agent_error_kind", "agent_error_type",
        "agent_error_traceback", "fallback_artifact_used",
        "result", "cost_usd_estimate",
        "prejudge_block_redirects", "prejudge_block_sigs",
    )
    _dead_state = {k: summary.pop(k) for k in _SESSION_SCOPED if k in summary}

    def _restore_dead_error() -> None:
        """Put the dead session's state back when the restart never started.

        ALL of it, not just the error: the caller then falls through to the
        historical halt and the job is finalized from this same summary. A
        partial restore would leave the cost ledger and the refusal marker
        disagreeing about which session produced them.
        """
        summary.update(_dead_state)

    try:
        return await run_main_agent_session(
            job_id,
            options=new_options,
            initial_prompt=resume_prompt,
            summary=summary,
            work_dir=work_dir,
            artifact_names=artifact_names,
            auto_run=auto_run,
            sandbox_runner=sandbox_runner,
            log_fn=log_fn,
        )
    except Exception as e:
        _restore_dead_error()
        log_fn(
            f"[orchestrator] AUP recovery `{step}` failed to start: "
            f"{type(e).__name__}: {e} — restoring the original error so the "
            f"job is still filed as policy_refusal"
        )
        return _AUP_RESTART_FAILED


async def run_main_agent_session(
    job_id: str,
    *,
    options,  # ClaudeAgentOptions; deferred import to avoid SDK at module load
    initial_prompt: str,
    summary: dict,
    work_dir: Path,
    artifact_names: tuple[str, ...],
    auto_run: bool,
    sandbox_runner,  # Callable[[str], Optional[dict]] | None
    log_fn,           # Callable[[str], None]
) -> dict | None:
    """One-stop main-agent driver with postjudge feedback loop.

    Opens a single ClaudeSDKClient session, sends `initial_prompt`,
    streams main's response cycle, then — if auto_run is on and an
    artifact was produced — runs the sandbox (with judge stages) and,
    on a non-success postjudge verdict, injects the retry_hint as a
    new user turn back into the same SDK session.

    Provider gate: Settings ``agent_provider`` must be ready (auth +
    runtime). Grok selection fails here until the ACP client is wired,
    so the job does not silently run Claude after the operator switched.

    Loop terminates on FIRST hit among:
      * flag captured / postjudge verdict == "success"
      * postjudge produced no actionable retry_hint
      * agent error / SDK exception
      * BUDGET_ABORT (investigation_budget tripwire)
      * AUTO_RETRY_MAX cap reached (when configured to a non-negative N)
      * user pressed Stop (RQ stop signal) / soft / hard timeout

    `auto_retry_max()` defaults to unlimited (-1); set
    `AUTO_RETRY_MAX=N` env to cap.

    Mutates `summary` with messages / tool_calls / agent_error /
    exploit_present / decomp counts as the inline analyzer code did.
    Returns the LAST sandbox_result dict (or None if auto_run disabled
    or no artifact was ever produced).

    Caller is responsible for the carry / flag-scan / meta-finalize
    steps after this returns.
    """
    def _snapshot_cost(summary: dict, label: str) -> None:
        """Mirror heartbeat-accumulated tokens into `summary` so
        extract_cost's fallback can estimate a real spend when the
        SDK's ResultMessage never arrives (SIGKILL / BUDGET_ABORT /
        exception)."""
        try:
            tokens_now = _token_state.get(job_id) or {}
            if not tokens_now:
                return
            summary["agent_tokens"] = dict(tokens_now)
            est = estimate_cost_from_tokens(
                tokens_now, summary.get("model"),
            )
            # Park the estimate in its OWN key. `summary["cost_usd"]` is the
            # SUBAGENT spend accumulator (written at the spawn_subagent site),
            # and `_total_spend()` adds it to main's cost — so writing a
            # whole-session estimate here inflated the running spend meter that
            # the cost cap and the contrarian-reframe tooth both read. Job
            # 2109b7ee6502: a turn-0 is_error snapshotted $19.60 into it while
            # the job's real main cost was $15.55 and subagent spend was $0.45.
            # extract_cost's fallback reads the estimate; nothing else should.
            if est > 0 and not summary.get("cost_usd_estimate"):
                summary["cost_usd_estimate"] = est
                # The label is a SNAPSHOT REASON, not a claim about the SDK: on
                # the RESULT_IS_ERROR path the ResultMessage did arrive (the
                # DONE line one line above prints its total_cost_usd) — it just
                # carried is_error=True. Saying "ResultMessage missing" there
                # was flatly contradicted by the adjacent log line.
                log_fn(
                    f"COST_FALLBACK [{label}]: parked a ${est:.4f} estimate "
                    f"from {sum(tokens_now.values())} accumulated tokens "
                    f"(used only if no usable ResultMessage cost lands)"
                )
        except Exception:
            pass

    from modules.agent_provider import (
        ensure_provider_ready,
        provider_display_name,
        provider_meta_fields,
    )
    from modules.grok_acp import GrokSessionOptions
    from modules.gpt_agent import GptSessionOptions

    # Fail fast when Settings selects an unready backend (missing auth,
    # or Grok runtime not yet wired). Stamps agent_provider on meta so
    # the UI /retry path can show which backend was intended.
    # AUP recovery may deliberately hand this function options for a backend
    # different from the global Settings value. Treat an adapter-specific
    # options object as authoritative; otherwise use the active provider and
    # retain the defensive rebuild path below for a late Settings switch.
    _requested_provider = None
    if isinstance(options, GrokSessionOptions):
        _requested_provider = "grok"
    elif isinstance(options, GptSessionOptions):
        _requested_provider = "gpt"
    _provider = ensure_provider_ready(_requested_provider)
    try:
        write_meta(job_id, **provider_meta_fields(_provider))
    except Exception:
        pass
    log_fn(f"[orchestrator] agent provider: {provider_display_name(_provider)}")

    # Branch message/client types so isinstance checks in the shared loop
    # match the active backend.
    if _provider == "grok" or isinstance(options, GrokSessionOptions):
        from modules.grok_acp import (
            GrokACPClient as AgentClient,
            AssistantMessage,
            ResultMessage,
            UserMessage,
        )
        _use_grok = True
        _use_gpt = False
    elif _provider == "gpt" or isinstance(options, GptSessionOptions):
        from modules.gpt_agent import (
            GptAgentClient as AgentClient,
            AssistantMessage,
            ResultMessage,
            UserMessage,
        )
        _use_grok = False
        _use_gpt = True
    else:
        from claude_agent_sdk import (
            AssistantMessage,
            ClaudeSDKClient as AgentClient,
            ResultMessage,
            UserMessage,
        )
        _use_grok = False
        _use_gpt = False
    import anyio

    max_retries = auto_retry_max() if auto_run else 0

    # Module drives the fallback skeleton shape (web → HTTP probe, not a
    # pwn socket skeleton). Read once; tolerate a missing meta.
    try:
        _meta_for_run = read_meta(job_id) or {}
    except Exception:
        _meta_for_run = {}
    _fallback_module = _meta_for_run.get("module")
    # Arm the contrarian reframe breaker (Tooth 1) when the operator's
    # description leans on easy/shortcut framing — that tone correlates
    # with anti-anchoring traps where a disconfirmed frame must be
    # abandoned mid-run. Stored on the SHARED summary so the isolated-
    # subagent spawn path (which sets contrarian_pending on a dead-end
    # reply) can read it without a signature change. Framing-INDEPENDENT
    # levers (the cost cap below) do not consult this.
    try:
        summary["easy_framing"] = _detect_easy_framing(
            _meta_for_run.get("description")
        )
        if summary["easy_framing"]:
            log_fn(
                "[orchestrator] easy/shortcut framing detected in "
                "description — contrarian reframe breaker armed (Tooth 1)"
            )
    except Exception:
        summary["easy_framing"] = False

    last_sandbox: dict | None = None
    # This signal is independent of the runner's return value: a real attempt
    # may return None.  Final analyzers use it together with agent_error to keep
    # an agent crash before the runner from promoting narrative prose.
    summary.setdefault("sandbox_started", False)
    # Unlike `sandbox_started` above (the historical "we dispatched the runner
    # wrapper" bit), this counts containers the runner says it ACTUALLY spawned.
    # A prejudge ship-block returns before spawn and must leave this at zero so
    # A2 can distinguish two analysis-only blocks from failed real executions.
    summary.setdefault("sandbox_runs", 0)
    # Track retry hints across attempts so the next postjudge call can
    # see "you already said this" — drives next_action=stop more
    # aggressively. summary["judge_hints"] is what the sandbox_runner
    # closure reads (analyzers wire it through attempt_sandbox_run).
    summary.setdefault("judge_hints", [])

    # Soft-eject machinery: at 80% of INVESTIGATION_BUDGET with no
    # artifact yet, queue a user-turn injection so the agent SEES the
    # warning in its own context (a log_line alone doesn't reach the
    # model). Fires AT MOST ONCE per job — the inject_after_turn flag
    # is consumed by the main loop after the current agent turn ends.
    soft_eject_fired = {"value": False}
    soft_eject_pending = {"value": False}

    def _maybe_soft_eject(tool_calls: int) -> None:
        if soft_eject_fired["value"]:
            return
        try:
            cap = int(os.environ.get("INVESTIGATION_BUDGET", "0"))
        except ValueError:
            cap = 0
        if cap <= 0:
            return
        threshold = int(cap * 0.8)
        if tool_calls < threshold:
            return
        if any((work_dir / n).is_file() for n in artifact_names):
            return
        soft_eject_fired["value"] = True
        soft_eject_pending["value"] = True
        log_fn(
            f"SOFT_EJECT_WARN: {tool_calls}/{cap} tool calls without "
            f"{' / '.join(artifact_names)}. Hard abort fires at "
            f"{cap}. Will inject finalize-now user-turn after current "
            f"turn ends."
        )

    # Scaffold-missing nudge: heap chals where main is making tool calls
    # but hasn't `cp`'d any /opt/scaffold/ template into the work dir by
    # SCAFFOLD_NUDGE_THRESHOLD calls. One-shot per job. Gated by the
    # heap_keywords_match flag the analyzer can pass through `summary`
    # so non-heap modules don't see this nudge.
    scaffold_nudge_fired = {"value": False}
    scaffold_nudge_pending = {"value": False}

    def _maybe_scaffold_nudge(tool_calls: int) -> None:
        if scaffold_nudge_fired["value"]:
            return
        if not summary.get("heap_chal"):
            return
        try:
            threshold = int(os.environ.get("SCAFFOLD_NUDGE_THRESHOLD", "30"))
        except ValueError:
            threshold = 30
        if threshold <= 0 or tool_calls < threshold:
            return
        # Already cp'd a scaffold? Look for the canonical fingerprint
        # (the heap_menu.py docstring's first line lives at the top).
        ex = work_dir / "exploit.py"
        scaffold_in_use = False
        if ex.is_file():
            try:
                head = ex.read_text(errors="replace")[:512]
                if "Heap-menu chal scaffold" in head or "scaffold.fsop_wfile" in head \
                        or "scaffold.tcache_poison" in head or "scaffold.aslr_retry" in head:
                    scaffold_in_use = True
            except Exception:
                pass
        if scaffold_in_use:
            scaffold_nudge_fired["value"] = True  # never nudge if already in use
            return
        # Chal-aware gate: heap_advanced=True can flag a chal as heap
        # just because it has a custom .so + glibc 2.31 — that branch
        # of the classifier fires even on TOCTOU races / format
        # strings / syscall-only pwn where /opt/scaffold/ heap
        # templates don't apply. Confirmed regression 2026-05-25
        # (job bfce7f3e0c11): uniqdb's `arr[0x800000]` aliases the
        # `top` int via .bss, no allocator anywhere. Suppress the
        # nudge when chal source has no heap-op needles. See
        # `_chal_source_has_heap_ops` for what counts.
        if not _chal_source_has_heap_ops(work_dir):
            scaffold_nudge_fired["value"] = True  # one-shot suppress
            log_fn(
                f"SCAFFOLD_NUDGE: SKIPPED at {tool_calls} tool calls — "
                f"heap_advanced=True but chal source has no "
                f"malloc/free/tcache/fastbin patterns (likely non-menu "
                f"pwn: TOCTOU race / FSOP-only / format-string)."
            )
            return
        scaffold_nudge_fired["value"] = True
        scaffold_nudge_pending["value"] = True
        scaffold_nudge_pending["n"] = tool_calls
        log_fn(
            f"SCAFFOLD_NUDGE: {tool_calls} tool calls into a heap chal "
            f"without /opt/scaffold/ in exploit.py. Will inject nudge "
            f"user-turn after current turn ends."
        )

    # Final-draft last-chance guard. When budget_exceeded fires WITHOUT
    # an artifact, we inject FINAL_DRAFT_USER_TURN and give main ONE
    # more turn to write the draft. Only after that turn also fails to
    # produce an artifact do we actually abort. Used at most once per
    # session — the second failure is hard.
    final_draft_pending = {"value": False}
    final_draft_used = {"value": False}

    # ---- Cost-cap circuit breaker (Tooth 2) ----
    # Framing-INDEPENDENT backstop against runaway grinding. The known-dollar
    # spend is main's cumulative cost PLUS the subagent sum PLUS reviewer
    # ledger rows. Main and subagents live in two disjoint places: main runs in
    # this SDK session (its cumulative total_cost_usd lands in summary["result"]
    # at each turn boundary — the
    # SDK reports it cumulatively, see the overwrite in agent_heartbeat),
    # while every subagent runs in a SEPARATE CLI process whose cost is
    # accumulated into summary["cost_usd"] on each spawn return
    # (make_spawn_subagent_mcp ~L2569). main's cost is NEVER added to
    # cost_usd, so we must sum both here — reading cost_usd alone would only
    # gate on subagent spend and miss a main-heavy grind (few spawns, long
    # self-loop) entirely. On breach we HALT with a RECOVERABLE
    # write_why_stopped so the operator can /retry (ideally fresh-start)
    # rather than pay for more of the same. Un-dismissible by the anchored
    # model — pure orchestrator arithmetic on the shared summary. NB the cap
    # defaults to $40. _total_spend includes reviewer ledger rows because those
    # calls run outside both the main SDK session and the subagent accumulator.
    def _total_spend() -> float:
        sub = 0.0
        main = 0.0
        reviewer = 0.0
        try:
            sub = float(summary.get("cost_usd", 0.0) or 0.0)
        except (TypeError, ValueError):
            sub = 0.0
        try:
            main = float(
                (summary.get("result") or {}).get("total_cost_usd", 0.0) or 0.0
            )
        except (TypeError, ValueError):
            main = 0.0
        try:
            from modules.usage_ledger import dollar_cost_parts, read_usage

            reviewer, _ = dollar_cost_parts(
                read_usage(job_id), roles={"reviewer"}
            )
        except Exception:
            reviewer = 0.0
        return sub + main + reviewer

    cost_cap_fired = {"value": False}
    cost_cap_pending = {"value": False}

    def _maybe_cost_cap() -> None:
        if cost_cap_fired["value"]:
            return
        cap = cost_cap_usd()
        if cap <= 0:
            return
        spent = _total_spend()
        if spent < cap:
            return
        cost_cap_fired["value"] = True
        cost_cap_pending["value"] = True
        log_fn(
            f"COST_CAP: total spend ${spent:.2f} "
            f"(main + subagents + reviewer) ≥ cap "
            f"${cap:.2f} (COST_CAP_USD; 0=disable) — will halt after this "
            f"turn boundary (recoverable via /retry)."
        )

    # SHA of the script we last fed into a sandbox run. After injecting
    # postjudge retry feedback we capture the script's SHA; on the next
    # auto-run iteration we compare against the CURRENT SHA — if main
    # returned a ResultMessage without modifying the script, the next
    # sandbox would re-execute identical bytes and prejudge would
    # ship-block (or postjudge would emit the same retry_hint) at the
    # cost of another $2-5 of cache_creation. Halt instead.
    # Concrete incident 2026-05-25 (job bfce7f3e0c11): main responded
    # "I'll stop the loop here rather than reschedule" to the retry
    # inject WITHOUT editing exploit.py; orchestrator re-ran the
    # unchanged script → flag_likelihood=0.12 ship-block → job ended
    # ~2 minutes later than it should have.
    script_sha_at_last_inject: dict = {"sha": None, "script": None}
    # Last assistant text of the current turn — used to CLASSIFY a
    # ResultMessage is_error (the ResultMessage itself carries no message;
    # an AUP refusal / transport error shows up as the final AGENT text).
    last_assistant_text: dict = {"value": ""}
    # judge_out gets populated in the post-sandbox block (line ~6054).
    # Pre-initialize so the SHA-unchanged ship gate can reference it
    # safely when it fires before the first sandbox run completes
    # (attempt > 0 guards against that path anyway, but the static
    # analyzer doesn't know that).
    judge_out: dict = {}

    def _script_sha(p: Path) -> str | None:
        try:
            import hashlib
            return hashlib.sha256(p.read_bytes()).hexdigest()
        except OSError:
            return None

    # Target as it was when the prompt was built. The operator can change it
    # mid-run from the UI (a chal-platform instance that expired and was
    # restarted comes back on a NEW port), but the agent's prompt is already
    # baked — see the loop check below.
    target_at_spawn = (read_meta(job_id) or {}).get("target_url")

    # Bank what earlier sessions of this job already spent. A continue-in-place
    # reuses the job id, and cost_usd is an OVERWRITE of one session's
    # cumulative total — without this the ledger silently drops every stopped
    # session (see prior_session_cost).
    try:
        _m = read_meta(job_id) or {}
        _authoritative = float(_m.get("cost_usd") or 0.0)
        _already_banked = float(_m.get("cost_usd_prior_sessions") or 0.0)
        # `cost_usd` is written ONLY by a ResultMessage or by an analyzer's
        # finalize — both on paths a SIGKILLed session never reaches. An
        # operator Stop hard-kills the RQ work horse mid-turn, so the stopped
        # session's spend was NEVER written and banking `cost_usd` alone banks
        # nothing: replaying job c552faf18d31 under that version reproduced its
        # ledger BIT-IDENTICALLY ($12.487237), i.e. the fix was a no-op for the
        # job it was written for.
        # `cost_usd_estimate` DOES survive — the heartbeat parks it every 5 s —
        # and now that the token double-count is gone it prices to the SDK's own
        # figure within 0.2%. So take whichever account is higher: the
        # authoritative total when a ResultMessage landed, else what this
        # session is known to have spent on top of what was already banked.
        _from_estimate = _already_banked + float(_m.get("cost_usd_estimate") or 0.0)
        _banked = max(_authoritative, _from_estimate)
        if _banked > 0:
            _src = "authoritative" if _authoritative >= _from_estimate else "token estimate"
            log_fn(
                f"[orchestrator] continuing a job that already spent "
                f"${_banked:.2f} ({_src}) — banking it so this session adds "
                f"to the total"
            )
            write_meta(job_id, cost_usd_prior_sessions=_banked,
                       cost_usd=_banked)
    except Exception as _be:
        # Log it: a silently-failed bank used to be byte-identical in run.log
        # to a genuinely fresh session.
        log_fn(
            f"[orchestrator] could NOT bank prior-session spend "
            f"({type(_be).__name__}: {_be}) — this job's ledger will report "
            f"this session only"
        )

    if _use_grok and not isinstance(options, GrokSessionOptions):
        # Analyzer built Claude options while provider flipped mid-flight —
        # rebuild from the Claude options fields we still understand.
        from modules.grok_acp import GrokSessionOptions as _GSO
        options = _GSO(
            system_prompt=getattr(options, "system_prompt", "") or "",
            model=getattr(options, "model", None) or "grok-build",
            cwd=str(getattr(options, "cwd", work_dir) or work_dir),
            effort=getattr(options, "effort", None),
            env=dict(getattr(options, "env", None) or {}),
            resume=getattr(options, "resume", None),
            add_dirs=list(getattr(options, "add_dirs", None) or []),
        )

    if _use_gpt and not isinstance(options, GptSessionOptions):
        # Same defensive rebuild as the Grok branch for a Settings flip that
        # occurred after an analyzer created its options object.
        from modules.agent_provider import default_model_for
        options = GptSessionOptions(
            system_prompt=getattr(options, "system_prompt", "") or "",
            model=default_model_for("gpt"),
            cwd=str(getattr(options, "cwd", work_dir) or work_dir),
            effort=getattr(options, "effort", None),
            env=dict(getattr(options, "env", None) or {}),
            resume=getattr(options, "resume", None),
            add_dirs=list(getattr(options, "add_dirs", None) or []),
        )

    _client_kwargs = {"options": options}
    async with AgentClient(**_client_kwargs) as client:
        await client.query(initial_prompt)

        # max_retries semantics: 0 = disabled, N>0 = cap, -1 = unlimited.
        cap_str = "∞" if max_retries < 0 else str(max_retries)
        attempt = 0  # 0 = initial run; 1..N = postjudge-driven retries
        while True:
            log_fn(f"Main session turn (attempt {attempt}/{cap_str})")
            artifact_sha_before_turn = {
                name: _script_sha(work_dir / name) for name in artifact_names
            }
            last_assistant_text["value"] = ""
            try:
                async for msg in client.receive_response():
                    capture_session_id(msg, job_id)
                    agent_heartbeat(job_id, msg)
                    record_rate_limit_event(msg)  # account-global usage chip
                    if isinstance(msg, AssistantMessage):
                        summary["messages"] = summary.get("messages", 0) + 1
                        log_assistant_blocks(job_id, msg, summary)
                        try:
                            _t = " ".join(
                                getattr(b, "text", "") for b in (msg.content or [])
                                if getattr(b, "text", "")
                            ).strip()
                            if _t:
                                last_assistant_text["value"] = _t[:2000]
                        except Exception:
                            pass
                    elif isinstance(msg, UserMessage):
                        log_user_blocks(job_id, msg)
                    _maybe_soft_eject(summary.get("tool_calls", 0))
                    _maybe_scaffold_nudge(summary.get("tool_calls", 0))
                    # Cost-cap backstop (Tooth 2): checked every msg so a
                    # single runaway turn spawning many subagents can't blow
                    # past the ceiling before a turn boundary. On breach we
                    # break out and the turn-boundary handler halts.
                    _maybe_cost_cap()
                    if cost_cap_pending["value"]:
                        break
                    # Budget check is SUPPRESSED during the FINAL_DRAFT
                    # turn — `tool_calls` and missing-artifact state
                    # carry over from the previous turn, so re-running
                    # the check immediately would fire on the very first
                    # msg of main's response and abort before main can
                    # write anything (job 13a3fc9993ee — BUDGET_ABORT
                    # fired in the same wall-clock second as FINAL_DRAFT
                    # was injected, no chance for the model to react).
                    # Once main's ResultMessage arrives we check the
                    # artifact instead.
                    if not final_draft_used["value"] and budget_exceeded(
                        summary.get("tool_calls", 0),
                        work_dir, artifact_names,
                    ):
                        final_draft_used["value"] = True
                        final_draft_pending["value"] = True
                        log_fn(
                            "BUDGET_LAST_CHANCE: "
                            f"{summary.get('tool_calls', 0)} tool "
                            f"calls, no {' / '.join(artifact_names)}. "
                            f"Injecting FINAL_DRAFT user-turn — "
                            "main gets one more turn to write the "
                            "draft before hard abort."
                        )
                        # Break out of the receive loop so the
                        # turn-boundary inject block runs.
                        break
                    if isinstance(msg, ResultMessage):
                        summary["result"] = {
                            "duration_ms": msg.duration_ms,
                            "num_turns": msg.num_turns,
                            "total_cost_usd": msg.total_cost_usd,
                            "is_error": msg.is_error,
                            "stop_reason": getattr(msg, "stop_reason", None),
                        }
                        # Grok soft turn-budget: continue the same session
                        # instead of dying into the no_artifact / fallback path
                        # (job 3c0e0edb73db: 600s hard timeout mid-exploit draft).
                        _sr = (getattr(msg, "stop_reason", None) or "").lower()
                        if _sr == "turn_budget" and not msg.is_error:
                            summary["grok_turn_budget_continue"] = True
                        log_fn(f"DONE: {summary['result']}")
                        # Post-FINAL_DRAFT artifact verdict: main has
                        # had one full turn since the inject. If we're
                        # still missing the artifact, drop a probe-only
                        # fallback so the sandbox + postjudge cycle
                        # still fires. The job ends as no_flag (or
                        # finished/partial if the probe surfaces useful
                        # output) instead of aborted/failed — which is
                        # the contract the user asked for ("abort 자체
                        # 가 없게").
                        if (final_draft_used["value"]
                                and not final_draft_pending["value"]
                                and not _pick_present_artifact(
                                    work_dir, artifact_names)):
                            log_fn(
                                "BUDGET_FALLBACK: main never produced "
                                f"{' / '.join(artifact_names)} after "
                                "FINAL_DRAFT push — dropping probe-only "
                                "skeleton so sandbox still runs."
                            )
                            write_fallback_artifacts(
                                work_dir, log_fn, _fallback_module,
                            )
                            summary["agent_error"] = (
                                "budget exhausted; fallback artifact used"
                            )
                            summary["agent_error_kind"] = "budget_fallback"
                            summary["fallback_artifact_used"] = True
                            _snapshot_cost(summary, "BUDGET_FALLBACK")
                            # Break the receive loop and let the
                            # sandbox / postjudge / auto-retry path
                            # downstream pick up the fallback artifact.
                            break
                        # SDK returned a ResultMessage with is_error=True
                        # (e.g. transport "Request timed out" on a very long
                        # single turn) and main produced no artifact. Same
                        # end-state as the killed/timeout EXCEPTION path below,
                        # but it arrives as a clean message — that handler
                        # never sees it, so without this branch the job ends
                        # no_flag with error=null and ZERO artifacts. Job
                        # cbccac4e85fc (2026-05-26) lost ~100 min / $7.60 this
                        # exact way (a 57-min turn timed out mid-synthesis).
                        # Converge on the same salvage: make the failure
                        # visible (error_kind) and keep a probe runnable.
                        if (msg.is_error
                                and not summary.get("agent_error")
                                and not summary.get("fallback_artifact_used")):
                            # Classify from the final AGENT text — is_error is
                            # generic but the text reveals WHY (an AUP policy
                            # refusal, a transport timeout, …). Recording the
                            # specific kind matters because the retry-loop's
                            # SHA-unchanged gate below uses it to avoid the
                            # FALSE "main ignored the hint" diagnosis when the
                            # turn actually DIED (job ca27378ee3ee: a redirect
                            # turn refused on AUP, recorded as retry_hint_ignored).
                            _err_txt = last_assistant_text["value"]
                            _err_kind, _err_detail = classify_result_failure(
                                msg, [_err_txt], "agent_error"
                            )
                            summary["agent_error"] = (
                                _err_txt[:300] if _err_kind == "policy_refusal"
                                else (_err_detail[:300] or
                                      "SDK ResultMessage is_error")
                            )
                            summary["agent_error_kind"] = _err_kind
                            _snapshot_cost(summary, "RESULT_IS_ERROR")
                            # AUP poisons the conversation: clear any pending
                            # in-place user-turn injections (FINAL_DRAFT /
                            # soft-eject / scaffold) so they can't re-query the
                            # blocked session and re-block. The postjudge-redirect
                            # re-block is gated separately below.
                            if _err_kind in (
                                "policy_refusal", "transport_error", "timeout", "killed"
                            ):
                                final_draft_pending["value"] = False
                                soft_eject_pending["value"] = False
                                scaffold_nudge_pending["value"] = False
                            if not _pick_present_artifact(
                                    work_dir, artifact_names):
                                write_fallback_artifacts(work_dir, log_fn, _fallback_module)
                                summary["fallback_artifact_used"] = True
                                log_fn(
                                    "[orchestrator] ResultMessage is_error "
                                    "with no artifact — wrote fallback so "
                                    "sandbox still runs (job ends no_flag "
                                    "with error_kind set, not a silent "
                                    "zero-artifact run)"
                                )
            except Exception as e:
                exc_type, msg_text, traceback_text = _safe_agent_exception_details(e)
                error_text = f"{exc_type}: {msg_text}"
                kind = classify_agent_error(error_text)
                if kind in (None, "unknown"):
                    kind = "agent_exception"
                summary["agent_error"] = msg_text
                summary["agent_error_kind"] = kind
                summary["agent_error_type"] = exc_type
                summary["agent_error_traceback"] = traceback_text
                # SIGKILL on the bundled `claude` CLI would surface here
                # as `Command failed with exit code -9`. Historically
                # every observed exit -9 was a fratricide from the
                # debugger subagent's `pkill -f "./prob"` matching its
                # own cmdline (fixed via pkill -x, see commit 15a5f85);
                # real cgroup OOM has not been observed. Classify as
                # "killed" if we get an unknown -9; the sandbox path
                # below still picks up whatever main managed to write.
                if kind == "agent_exception" and (
                    "exit code -9" in error_text or "killed" in error_text.lower()
                ):
                    summary["agent_error_kind"] = "killed"
                log_fn(
                    f"AGENT_ERROR ({summary['agent_error_kind']}):\n"
                    f"{traceback_text}"
                )
                _snapshot_cost(summary, "AGENT_ERROR")
                # SDK transport may have died on this exception. Keep
                # the run alive: drop a fallback artifact if main never
                # wrote one, clear pending user-turn injections, and
                # fall through to sandbox dispatch. The fallback path
                # makes the job end as no_flag/partial instead of
                # failed even if main didn't produce a real exploit.
                if summary.get("agent_error_kind") in ("killed", "timeout"):
                    exploit_missing = not (work_dir / "exploit.py").is_file()
                    report_missing = not (work_dir / "report.md").is_file()
                    write_fallback_artifacts(work_dir, log_fn, _fallback_module)
                    if exploit_missing or report_missing:
                        summary["fallback_artifact_used"] = True
                        log_fn(
                            f"[orchestrator] {summary.get('agent_error_kind')}"
                            " fired — wrote fallback ("
                            f"exploit.py {'missing' if exploit_missing else 'kept'}"
                            f", report.md {'missing' if report_missing else 'kept'}"
                            ") so sandbox still runs"
                        )
                    else:
                        log_fn(
                            f"[orchestrator] {summary['agent_error_kind']}"
                            " fired but main already produced both "
                            "artifacts — proceeding to sandbox"
                        )
                    final_draft_pending["value"] = False
                    soft_eject_pending["value"] = False
                    scaffold_nudge_pending["value"] = False
                else:
                    return last_sandbox

            # A failed turn may inherit a runnable script from the source job.
            # It is not evidence produced by this turn. Never let that stale
            # file reach prejudge/sandbox: doing so converted Codex's
            # process_error into a misleading exploit failure on c387c20adc61.
            if bool((summary.get("result") or {}).get("is_error")):
                stale_name, is_stale = failed_turn_reuses_artifact(
                    work_dir, artifact_names, artifact_sha_before_turn
                )
                if is_stale:
                    error_kind = summary.get("agent_error_kind") or "agent_error"
                    summary["failed_turn_stale_artifact"] = stale_name
                    summary["judge_stop_reason"] = (
                        f"agent turn failed ({error_kind}); carried {stale_name} "
                        "was unchanged, so it was not sent to prejudge or sandbox"
                    )
                    log_fn(
                        f"[orchestrator] failed turn left carried {stale_name} "
                        "byte-identical — blocking stale artifact before prejudge"
                    )
                    write_meta(
                        job_id,
                        judge_next_action="stop",
                        judge_stop_reason=summary["judge_stop_reason"],
                    )
                    write_why_stopped(
                        work_dir,
                        stop_kind="agent_error",
                        attempt_idx=attempt,
                        max_attempts=max_retries,
                        judge_out=judge_out,
                        sandbox_result=last_sandbox,
                        summary=summary,
                        log_fn=log_fn,
                    )
                    return last_sandbox

            # ---- Cost-cap halt (Tooth 2) — highest priority: stop the bleed ----
            # Fires before every other turn-boundary handler. A recoverable
            # hard stop: write WHY_STOPPED (stop_kind=cost_cap) + meta stop,
            # then return so the caller collects whatever artifacts exist.
            if cost_cap_pending["value"]:
                cost_cap_pending["value"] = False
                spent = _total_spend()
                log_fn(
                    f"[orchestrator] COST_CAP halt at ${spent:.2f} "
                    f"(main + subagents + reviewer) — writing WHY_STOPPED and returning "
                    f"(recoverable via /retry)"
                )
                summary["judge_stop_reason"] = (
                    f"cost cap reached (${spent:.2f} total ≥ COST_CAP_USD) — "
                    f"halted to bound runaway spend on a non-converging run; "
                    f"recoverable via /retry (ideally fresh-start)"
                )
                # Deliberate stop, NOT an agent error: follow the judge_stop /
                # retry_hint_ignored precedent (judge_next_action=stop +
                # judge_stop_reason) so the status finalizer resolves this to
                # no_flag/stopped, not failed, and any flag in last_sandbox is
                # still captured on the return below.
                write_meta(
                    job_id,
                    judge_next_action="stop",
                    judge_stop_reason=summary["judge_stop_reason"],
                )
                _snapshot_cost(summary, "COST_CAP")
                write_why_stopped(
                    work_dir,
                    stop_kind="cost_cap",
                    attempt_idx=attempt,
                    max_attempts=max_retries,
                    judge_out=judge_out,
                    sandbox_result=last_sandbox,
                    summary=summary,
                    log_fn=log_fn,
                )
                return last_sandbox

            # ---- Target changed under us (operator restarted the instance) ----
            # A chal-platform instance that expires and is restarted comes back
            # on a NEW host:port. The operator updates it from the UI, which
            # writes meta — but the agent's target was baked into the spawn
            # prompt and nothing ever told it. Job c552faf18d31: the port
            # changed at 11:15:42 and main kept polling the DEAD one, printing
            # "DOWN: Could not connect ... :18745" at 11:37 while the real
            # target had been up for 22 minutes; it only recovered when the
            # operator stopped and continued the job by hand at 11:45.
            # The sandbox runner already self-heals from meta
            # (_runner._refresh_target_from_meta) — this closes the same gap
            # for the agent, using the injection mechanism already proven by
            # the four user-turns below.
            #
            # SCOPE — this fires only HERE, at a loop boundary, i.e. after
            # receive_response() has returned. One receive_response() spans the
            # agent's entire agentic turn, so on a long job the boundary can be
            # hours away: job 6e434e820b3f changed target at 01:03:47 and this
            # had still not run by 01:11 (single turn since 23:18) while main
            # polled the dead port. The mid-turn half of the fix is the
            # PreToolUse stale-target guard (stale_target_reason above); this
            # stays as the belt to its braces — it also covers a change made
            # while the agent is between turns and issues no Bash call at all.
            #
            # NEVER query a session that is already dying. When the bundled
            # CLI has been SIGKILLed the transport is gone, and the SDK's
            # write() raises CLIConnectionError("Cannot write to terminated
            # process"). That exception is NOT inside the try/except that wraps
            # receive_response, so it escapes run_main_agent_session entirely —
            # and every analyzer's outer handler does
            # `write_meta(status="failed"); raise`, which SKIPS the whole
            # salvage sequence (fallback artifact -> sandbox -> postjudge ->
            # flag scan -> WHY_STOPPED). An adversarial run reproduced exactly
            # that: with the target unchanged the sandbox ran and WHY_STOPPED
            # was written; with the target changed in the same window the
            # exception escaped and sandbox_runner was never called. The
            # policy_refusal case is the same hazard for a different reason —
            # re-querying an AUP-blocked session just re-blocks it, which is
            # why the three sibling injections are explicitly cleared above.
            try:
                _target_now = (read_meta(job_id) or {}).get("target_url")
            except Exception:
                _target_now = target_at_spawn
            # Only the kinds that actually mean the transport is GONE. An
            # earlier version gated on any truthy kind, which also caught
            # `budget_fallback` — a session whose transport is perfectly
            # healthy and which the loop keeps querying — permanently
            # suppressing the notice for the rest of that job.
            if summary.get("agent_error_kind") in (
                    "killed", "timeout", "policy_refusal", "cli_infra_error"):
                _target_now = target_at_spawn   # dying session: do not query it
            if _target_now and _target_now != target_at_spawn:
                _prior, target_at_spawn = target_at_spawn, _target_now
                log_fn(
                    f"[orchestrator] target changed mid-run "
                    f"({_prior!r} -> {_target_now!r}) — injecting a notice so "
                    f"main stops using the stale one"
                )
                _target_notice = (
                    "⚠️ ORCHESTRATOR INTERRUPT — THE TARGET CHANGED MID-RUN.\n\n"
                    f"The operator updated this job's remote target:\n"
                    f"    OLD (now dead): {_prior}\n"
                    f"    NEW (use this): {_target_now}\n\n"
                    "This almost always means the challenge instance EXPIRED "
                    "and was RESTARTED, so it came back on a different port. "
                    "Any 'target is down / connection refused' conclusion you "
                    "drew from the old value is STALE — the service is most "
                    "likely up right now.\n\n"
                    "Do this before anything else:\n"
                    f"  1. Re-probe {_target_now} (a plain TCP connect is enough).\n"
                    "  2. Update every hardcoded host:port in your exploit/solver "
                    "— better, read it from argv[1] so the next change costs "
                    "nothing.\n"
                    "  3. Resume where you left off. Your analysis, work tree and "
                    "files are all still valid; ONLY the endpoint moved. Do NOT "
                    "restart the investigation.\n\n"
                    "If the restarted instance is time-limited, spend it on your "
                    "best current exploit rather than on fresh probing."
                )
                try:
                    await client.query(_target_notice)
                except Exception as _qe:
                    # Belt and braces on top of the agent_error_kind gate: a
                    # transport that died between the last message and here
                    # must not take the salvage path down with it.
                    log_fn(
                        f"[orchestrator] target notice could not be delivered "
                        f"({type(_qe).__name__}) — session is gone; falling "
                        f"through to the sandbox/postjudge path"
                    )
                else:
                    continue

            # ---- Grok soft turn-budget continue ----
            # A long Grok turn hit its wall-clock budget after real tool work.
            # Keep the ACP session alive and ask main to resume (especially
            # to write exploit.py / report.md). Without this the loop falls
            # through to no_artifact + fallback skeleton.
            if summary.pop("grok_turn_budget_continue", False):
                if summary.get("agent_error_kind") in (
                        "killed", "timeout", "policy_refusal", "cli_infra_error"):
                    pass  # transport already dead
                elif not _pick_present_artifact(work_dir, artifact_names):
                    log_fn(
                        "[orchestrator] Grok turn budget hit with no deliverable "
                        "yet — injecting CONTINUE user-turn"
                    )
                    _cont = (
                        "⚠️ ORCHESTRATOR INTERRUPT — TURN TIME BUDGET REACHED.\n\n"
                        "Your previous turn hit the wall-clock budget while you "
                        "were still investigating. The session and work tree are "
                        "intact (decomp, notes, tmp files). Do NOT restart analysis "
                        "from scratch.\n\n"
                        "Priority now:\n"
                        "1. Synthesize what you already know into "
                        f"{' / '.join(artifact_names)} in the CURRENT WORKING "
                        "DIRECTORY (relative paths only).\n"
                        "2. Prefer a working / partially-working exploit over more "
                        "recon. Local-proof is fine; remote capture is better.\n"
                        "3. Write report.md with the vuln, primitive, and remaining "
                        "open questions.\n"
                        "4. If you need one more focused tool check before writing, "
                        "do it — then WRITE THE DELIVERABLES this turn."
                    )
                    try:
                        await client.query(_cont)
                    except Exception as _qe:
                        log_fn(
                            f"[orchestrator] turn-budget continue failed "
                            f"({type(_qe).__name__}) — falling through"
                        )
                    else:
                        continue

            # ---- FINAL_DRAFT last-chance injection ----
            # Highest priority — budget already overrun and the
            # alternative is aborting the whole job. Always inject if
            # pending, regardless of other guards.
            if final_draft_pending["value"]:
                final_draft_pending["value"] = False
                log_fn("[orchestrator] injecting FINAL_DRAFT last-chance user-turn")
                await client.query(FINAL_DRAFT_USER_TURN)
                continue

            # ---- Soft-eject (budget 80%) user-turn injection ----
            # Job d8decbd77ed9 hit SOFT_EJECT_WARN at 80/100 calls but
            # the log_line alone didn't reach the model — it kept
            # investigating until BUDGET_ABORT fired with no artifact.
            # Inject the warning as a user-turn so main actually sees it.
            if soft_eject_pending["value"]:
                soft_eject_pending["value"] = False
                log_fn("[orchestrator] injecting soft-eject user-turn")
                await client.query(SOFT_EJECT_USER_TURN)
                continue

            # ---- Scaffold-missing nudge ----
            # Heap chal + N tool calls + no /opt/scaffold/ template in
            # exploit.py → nudge main to use the canonical templates
            # instead of reinventing the wheel from scratch.
            if scaffold_nudge_pending["value"]:
                scaffold_nudge_pending["value"] = False
                log_fn("[orchestrator] injecting scaffold-missing nudge")
                # The constant carried a literal `N` that nothing ever
                # substituted, so the agent read "you've made N tool calls".
                # The run.log line right above it was an f-string and did show
                # the real number — only the text the MODEL sees was unfilled.
                await client.query(SCAFFOLD_MISSING_USER_TURN.format(
                    n=scaffold_nudge_pending.get("n", "several")))
                continue

            # ---- Contrarian reframe injection (Tooth 1) ----
            # An isolated subagent returned a premise-refuted / dead-end
            # signal on an easy-framed job past the spend threshold (armed
            # in make_spawn_subagent_mcp) — the exact shape of the anchoring
            # trap. Inject ONE contrarian user-turn that de-commits main from
            # its current frame and points it at a genuinely independent
            # spawn or a reframe/concede. One-shot (contrarian_fired guards
            # re-arming); does not halt — main keeps its turn budget.
            # NOTE: unlike final_draft / soft_eject / scaffold_nudge, this
            # flag is NOT cleared by the killed/timeout/policy_refusal branches
            # above — so before this guard a dead-end signal arriving in the
            # same turn as a SIGKILL queried a terminated transport and threw
            # CLIConnectionError straight out of the session, skipping the
            # entire salvage path. Same shape as the target-notice hazard;
            # reproduced against the pre-change commit, so this one is a
            # PRE-EXISTING bug fixed in passing.
            if summary.get("contrarian_pending") and not summary.get("agent_error_kind"):
                summary["contrarian_pending"] = False
                log_fn(
                    "[orchestrator] injecting contrarian reframe user-turn "
                    "(Tooth 1) — dead-end signal on an easy-framed job"
                )
                try:
                    await client.query(CONTRARIAN_REFRAME_USER_TURN)
                except Exception as _qe:
                    log_fn(
                        f"[orchestrator] contrarian reframe could not be "
                        f"delivered ({type(_qe).__name__}) — session is gone"
                    )
                else:
                    continue

            # ---- Decide whether to feed postjudge back to main ----
            if not auto_run or sandbox_runner is None:
                return last_sandbox
            picked = _pick_present_artifact(work_dir, artifact_names)

            # DELIBERATE DELETION is not "main produced nothing".
            # _format_postjudge_user_turn tells main, in writing, to
            # `rm -f ./<script>` if it is giving up. When main takes that
            # published path the artifact vanishes from work/ — and the
            # job-root fallback below (built for a DIFFERENT case: main wrote
            # the solver to the wrong directory, job 389e39530990) would find
            # the byte-identical copy the pre-sandbox carry left at the job
            # root and silently promote it back. The SHA gate then compares
            # bytes, sees "unchanged", and stamps retry_hint_ignored — the
            # code resurrecting a file main deleted on the code's own
            # instruction, then blaming main for not editing it. Job
            # df7dd1b4a9e8 ended that way after a 19-minute, source-level
            # concession that WHY_STOPPED recorded as "Main ignored the hint".
            # Detect it with state the loop already tracks and halt honestly.
            _inject_script = script_sha_at_last_inject["script"]
            # Only a STALE copy means concession. If the job root holds a
            # DIFFERENT build of the artifact, main rewrote it there (the exact
            # wrong-directory case the promotion below exists for) — promote and
            # run it instead of recording a concession that never happened.
            _root_sha = _script_sha(job_dir(job_id) / _inject_script) if _inject_script else None
            _root_is_stale = (
                _root_sha is None
                or _root_sha == script_sha_at_last_inject["sha"]
            )
            if (
                not picked
                and attempt > 0
                and _inject_script
                and script_sha_at_last_inject["sha"] is not None
                and not (work_dir / _inject_script).is_file()
                and _root_is_stale
            ):
                log_fn(
                    f"[orchestrator] {_inject_script} was DELETED from work/ "
                    f"after the retry_hint inject (attempt {attempt}/"
                    f"{cap_str}) — that is the concession path the postjudge "
                    f"message offers. Not promoting any job-root copy; "
                    f"halting as a recorded concession."
                )
                summary["conceded_by_deletion"] = True
                summary["judge_stop_reason"] = (
                    f"main deleted {_inject_script} after postjudge feedback "
                    f"— deliberate concession via the documented give-up path, "
                    f"NOT an ignored hint"
                )
                write_meta(
                    job_id,
                    judge_next_action="stop",
                    judge_stop_reason=summary["judge_stop_reason"],
                )
                write_why_stopped(
                    work_dir,
                    stop_kind="conceded_by_deletion",
                    attempt_idx=attempt,
                    max_attempts=max_retries,
                    judge_out=judge_out,
                    sandbox_result=last_sandbox,
                    summary=summary,
                    log_fn=log_fn,
                )
                return last_sandbox

            if not picked:
                # The agent sometimes writes the solver with an ABSOLUTE
                # path to the JOB_DIR ROOT (/data/jobs/<id>/) instead of its
                # cwd (work_dir = <jobroot>/work/). Job 389e39530990 wrote
                # /data/jobs/<id>/solver.sage; auto-run then skipped entirely
                # (picked=None) and the sandbox NEVER ran, despite a valid
                # solver — status ended no_flag with sandbox=null.
                # attempt_sandbox_run ALREADY tolerates the jobroot layout
                # (it scans <jobroot>/<script> and copies into work/), so
                # this gate was strictly NARROWER than the runner it guards.
                # Mirror the runner: fall back to job_dir root and PROMOTE
                # the file into work_dir so every downstream `work_dir/picked`
                # (sha gate, carry, re-inject) resolves. work_dir stays
                # canonical (checked first) so a fresh /retry solver always
                # wins over a stale prior-attempt copy at the root.
                jd_root = job_dir(job_id)
                root_pick = _pick_present_artifact(jd_root, artifact_names)
                if root_pick:
                    try:
                        (work_dir / root_pick).write_bytes(
                            (jd_root / root_pick).read_bytes()
                        )
                        picked = root_pick
                        log_fn(
                            f"[orchestrator] {root_pick} was written to the "
                            f"job_dir root (not cwd/work) — promoted into "
                            f"work/ so auto-run can execute it"
                        )
                    except OSError as e:
                        log_fn(
                            f"[orchestrator] found {root_pick} at job_dir "
                            f"root but promote into work/ failed: {e}"
                        )
                        picked = None
            if not picked:
                # Main produced nothing this round — no script to run.
                # RECORD it: this used to return with no WHY_STOPPED, no
                # judge_next_action and stage left at auto-retry-N, so the job
                # ended no_flag with no stated reason at all — the exact
                # silent halt the WHY_STOPPED mechanism exists to eliminate.
                summary.setdefault(
                    "judge_stop_reason",
                    "no solver artifact present in work/ (or at the job root) "
                    "when the auto-run loop looked — nothing to execute",
                )
                try:
                    # judge_next_action is deliberately NOT set to "stop" here.
                    # api/routes/retry.py:761 reads that field as "the judge
                    # ruled this approach structurally blocked" and drops the
                    # SDK session fork — so stamping it for a missing FILE
                    # would cost the operator the entire conversation on the
                    # next /retry, for what is usually a filename mismatch.
                    write_meta(
                        job_id,
                        judge_stop_reason=summary["judge_stop_reason"],
                    )
                    write_why_stopped(
                        work_dir,
                        stop_kind="no_artifact",
                        attempt_idx=attempt,
                        max_attempts=max_retries,
                        judge_out=judge_out,
                        sandbox_result=last_sandbox,
                        summary=summary,
                        log_fn=log_fn,
                    )
                except Exception as e:
                    log_fn(f"[orchestrator] could not record no-artifact halt: {e}")
                return last_sandbox

            # SHA-unchanged ship gate: if we're on a post-retry iteration
            # and main returned without modifying the script we just fed
            # back retry_hint about, the re-run is a guaranteed-fail
            # repeat. Halt instead of burning another sandbox cycle.
            if (
                attempt > 0
                and script_sha_at_last_inject["sha"] is not None
                and script_sha_at_last_inject["script"] == picked
            ):
                current_sha = _script_sha(work_dir / picked)
                if (
                    current_sha is not None
                    and current_sha == script_sha_at_last_inject["sha"]
                ):
                    # The script is unchanged — but WHY? Distinguish
                    # "main deliberately declined to apply the fix"
                    # (retry_hint_ignored) from "the retry TURN died
                    # before main could apply it" (AUP policy refusal /
                    # transport error / timeout → ResultMessage is_error).
                    # A dead turn also leaves the script byte-identical,
                    # but stamping retry_hint_ignored writes a FALSE
                    # "main ignored the hint" diagnosis into WHY_STOPPED
                    # that /retry then carries forward as ground truth.
                    # Job ca27378ee3ee: the redirect turn refused on AUP
                    # (is_error) yet was recorded as retry_hint_ignored.
                    retry_turn_errored = bool(
                        (summary.get("result") or {}).get("is_error")
                    )
                    if retry_turn_errored:
                        _ek = summary.get("agent_error_kind") or "agent_error"
                        log_fn(
                            f"[orchestrator] {picked} unchanged after "
                            f"retry_hint inject (attempt {attempt}/{cap_str}) "
                            f"— but the retry TURN errored ({_ek}); main never "
                            f"got to apply the fix. Halting as agent_error, "
                            f"NOT retry_hint_ignored."
                        )
                        summary["judge_stop_reason"] = (
                            f"retry turn errored ({_ek}) before it could apply "
                            f"postjudge feedback — {picked} unchanged because "
                            f"the turn DIED, not because main ignored the hint"
                        )
                        write_meta(
                            job_id,
                            judge_next_action="stop",
                            judge_stop_reason=summary["judge_stop_reason"],
                        )
                        write_why_stopped(
                            work_dir,
                            stop_kind="agent_error",
                            attempt_idx=attempt,
                            max_attempts=max_retries,
                            judge_out=judge_out,
                            sandbox_result=last_sandbox,
                            summary=summary,
                            log_fn=log_fn,
                        )
                        return last_sandbox
                    log_fn(
                        f"[orchestrator] {picked} unchanged after "
                        f"retry_hint inject (attempt {attempt}/"
                        f"{cap_str}) — main returned without applying "
                        f"the fix. Skipping guaranteed-fail re-run; "
                        f"halting auto-retry loop."
                    )
                    summary["judge_stop_reason"] = (
                        f"main ignored retry_hint — {picked} unchanged "
                        f"after postjudge feedback"
                    )
                    write_meta(
                        job_id,
                        judge_next_action="stop",
                        judge_stop_reason=summary["judge_stop_reason"],
                    )
                    write_why_stopped(
                        work_dir,
                        stop_kind="retry_hint_ignored",
                        attempt_idx=attempt,
                        max_attempts=max_retries,
                        judge_out=judge_out,
                        sandbox_result=last_sandbox,
                        summary=summary,
                        log_fn=log_fn,
                    )
                    return last_sandbox

            # `attempt_sandbox_run` looks at <jobdir>/<artifact>, but the
            # analyzer's full carry block doesn't run until its `finally`
            # (i.e. AFTER this helper returns). Before sandbox_runner gets
            # called we therefore promote the picked artifact and any
            # report.md companion ourselves — otherwise the runner sees
            # "exploit.py missing, cannot auto-run" on every cycle and the
            # auto-retry loop short-circuits with verdict=None.
            jd = job_dir(job_id)
            for nm in (picked, "report.md", "findings.json",
                        "THREAT_MODEL.md", "WHY_STOPPED.md"):
                src = work_dir / nm
                if not src.is_file():
                    continue
                dst = jd / nm
                try:
                    if src.resolve() != dst.resolve():
                        dst.write_bytes(src.read_bytes())
                except Exception as e:
                    log_fn(f"[orchestrator] pre-sandbox carry of {nm} failed: {e}")

            # Run sandbox + judge synchronously off the event loop.
            write_meta(job_id, stage=f"sandbox-run-{attempt}" if attempt else "sandbox-run")
            log_fn(f"[orchestrator] auto-run turn {attempt}: executing {picked}")
            try:
                summary["sandbox_started"] = True
                last_sandbox = await anyio.to_thread.run_sync(sandbox_runner, picked)
            except Exception as e:
                log_fn(f"[orchestrator] sandbox runner crashed: {e}")
                return last_sandbox

            # New runners state this fact explicitly.  The conservative legacy
            # fallback counts only a result with an exit_code and excludes both
            # no-run sentinels, keeping older/custom sandbox callbacks usable
            # without letting a prejudge block masquerade as an execution.
            _actual_sandbox_started = (last_sandbox or {}).get("sandbox_started")
            if _actual_sandbox_started is None:
                _actual_sandbox_started = bool(
                    last_sandbox
                    and "exit_code" in last_sandbox
                    and last_sandbox.get("error") != "prejudge_blocked"
                    and not last_sandbox.get("judge_aborted")
                )
            if _actual_sandbox_started:
                summary["sandbox_runs"] = int(summary.get("sandbox_runs") or 0) + 1

            # Did we capture a flag this turn? `last_sandbox` is the
            # judge_aborted-aware sentinel; pass it so the orchestrator
            # loop applies the same NARRATIVE-skip gate as the final
            # analyzer scan (see scan_job_for_flags docstring + job
            # 44dd25365173 incident).
            flag_provenance: dict = {}
            flags_now = scan_job_for_flags(
                job_id,
                sandbox_result=last_sandbox,
                provenance_out=flag_provenance,
                sandbox_started=summary.get("sandbox_started"),
                agent_error=bool(summary.get("agent_error")),
            )
            judge_out = ((last_sandbox or {}).get("judge") or {})
            verdict = judge_out.get("verdict")
            # Accumulate the just-emitted retry_hint so the NEXT
            # postjudge call sees prior history and can decide
            # next_action=stop when its new hint would repeat.
            _hint_just_now = (judge_out.get("retry_hint") or "").strip()
            if _hint_just_now:
                summary["judge_hints"].append(_hint_just_now)
            terminal_capture = _auto_retry_success(
                flags_now, verdict, flag_provenance.get("tier", "")
            )
            if verdict == "success":
                gate_reason = "judge_success"
            elif flags_now and flag_provenance.get("tier") == "marker":
                gate_reason = "marker_capture"
            elif flags_now:
                gate_reason = "weak_flag_evidence"
            else:
                gate_reason = "no_capture_evidence"
            emit_event(
                job_id,
                "run",
                "flag_gate",
                flags_count=len(flags_now),
                tier=flag_provenance.get("tier", ""),
                suppressed=bool(flag_provenance.get("suppressed")),
                verdict=verdict,
                exit_code=(last_sandbox or {}).get("exit_code"),
                terminal_capture=terminal_capture,
                reason=gate_reason,
            )
            if terminal_capture:
                if verdict == "success" and not flags_now:
                    # Silent contradiction: the judge confirmed a capture but
                    # scan_job_for_flags harvested nothing. Almost always a
                    # placeholder-filter false-positive eating a real flag
                    # (job 187a2d3ee182: `DH{...}`-content flag dropped by the
                    # ellipsis rule). Surface it loudly so the flag isn't lost
                    # to a silent no_flag — see memory real_flag_dropped_as_placeholder.
                    log_fn(
                        f"[orchestrator] WARNING turn {attempt}: judge verdict=success "
                        f"but 0 flags harvested — a real capture may have been dropped by "
                        f"the placeholder filter; check solver stdout for FLAG_CANDIDATE"
                    )
                # Clear the SALVAGE markers a FAILED EARLIER TURN may have left
                # behind. The `msg.is_error and no artifact` branch above exists
                # to keep a zero-artifact run runnable, and its comment assumes
                # "the job ends no_flag with error_kind set" — but the loop can
                # go on to succeed, and nothing un-set the marker. Job
                # 2109b7ee6502 (RISC-V kernel, real remote flag on auto-run turn
                # 1) finished with meta.error = "SDK ResultMessage is_error …;
                # no artifact" and error_kind=unknown, while exploit_present was
                # True and the flag was captured — the message was false on both
                # counts by then. Only clear on a REAL capture (flags_now), never
                # on a bare verdict=success, so a judge-says-success/0-flags
                # contradiction keeps its error trail for the operator.
                #
                # THREE guards, each from a confirmed way the naive version of
                # this clear does harm:
                #  * policy_refusal is NEVER cleared. /retry keys its AUP
                #    recovery on exactly this value (api/routes/retry.py:776
                #    `prior_aup_blocked = error_kind == "policy_refusal"` ->
                #    resume_sid=None). Dropping it makes the next default
                #    /retry fork the AUP-poisoned transcript instead of a fresh
                #    session — the one path documented as the sole cure.
                #  * budget_fallback is NEVER cleared. That branch ships the
                #    probe-only skeleton as the artifact, and the skeleton
                #    echoes the service banner to stdout — so a service that
                #    greets with the flag yields a TRUSTED flag while the
                #    "exploit" is a stub. The marker is the only record of that.
                #  * TRUSTED tier only. `flags_now` is not proof of a capture:
                #    scan_job_for_flags falls back to the NARRATIVE tier
                #    (report.md / findings.json) whenever the sandbox ran, and
                #    _is_placeholder_flag passes plausible fabrications like
                #    DH{decoy_do_not_submit}. Re-scan trusted-only so an
                #    agent-authored string cannot erase a real error trail.
                # `fallback_artifact_used` is deliberately KEPT — it is
                # evidence, its only readers are in this function, and this
                # branch returns immediately.
                _stale_kind = summary.get("agent_error_kind")
                if flags_now and _stale_kind not in (
                        "policy_refusal", "budget_fallback"):
                    try:
                        _trusted = scan_job_for_flags(
                            job_id, sandbox_result=last_sandbox,
                            trusted_only=True,
                        )
                    except Exception:
                        _trusted = []
                    if _trusted:
                        for _k in (
                            "agent_error", "agent_error_kind",
                            "agent_error_type", "agent_error_traceback",
                        ):
                            if summary.get(_k):
                                log_fn(
                                    f"[orchestrator] clearing stale {_k} "
                                    f"(kind={_stale_kind}) — turn {attempt} "
                                    f"captured a TRUSTED-tier flag, so the "
                                    f"earlier turn's failure no longer "
                                    f"describes this job"
                                )
                                summary.pop(_k, None)
                # PROVENANCE of the promoted flag. A capture that only the
                # AGENT'S PROSE records is not the same evidence as one the
                # runner printed, and today both render identically. Job
                # a4729b5d91f2 finished with a real DH{...} whose only home was
                # report.md / findings.json: main captured it live mid-session,
                # then the instance died and the auto-run's own stdout said
                # "no flag captured". Right answer, fragile mechanism — the
                # identical path promotes a fabrication. Do NOT drop anything
                # (flag curation is the operator's, via the UI); just say which
                # tier it came from, in the log and in meta.
                _trusted_now: list = []
                _prov_now: dict = {}
                try:
                    _trusted_now = scan_job_for_flags(
                        job_id, sandbox_result=last_sandbox, trusted_only=True,
                        provenance_out=_prov_now,
                    )
                except Exception:
                    pass
                _narrative_only = bool(flags_now) and not _trusted_now
                if _narrative_only:
                    log_fn(
                        f"[orchestrator] ⚑ the promoted flag has NO trusted-tier "
                        f"source — the runner's own stdout/stderr did not "
                        f"contain it (verdict={verdict}). It comes from the "
                        f"agent's report.md / findings.json. Genuine when the "
                        f"agent captured it live and the target then died; "
                        f"indistinguishable from a fabrication. Re-run the "
                        f"exploit against a live instance to confirm."
                    )
                # Only record provenance when there IS a flag to have
                # provenance about. The success branch is also entered on
                # `verdict == "success"` with zero flags harvested, and writing
                # flag_trusted_tier=True there claims the most-trusted
                # provenance for a job that captured nothing.
                if flags_now:
                    # `flag_trusted_tier` is a BOOL and cannot express the
                    # distinction that mattered in 0c04e636633c: a solver that
                    # DECLARED `FLAG_CANDIDATE: <flag>` and a regex that merely
                    # found a flag-shaped string in the same stdout both set it
                    # True. Record the tier by name beside it so the UI, the
                    # library-save gate and any later status rule can key on
                    # something better than a bool. Nothing is dropped here —
                    # flag curation stays the operator's, via the UI.
                    _tier = _prov_now.get("tier") or (
                        "narrative" if _narrative_only else ""
                    )
                    # A suppressed sweep is NOT the same as "the runner never
                    # printed it". Both end with an empty trusted tier, so
                    # `_narrative_only` cannot tell them apart and would label
                    # the first one "narrative" — asserting the runner's output
                    # does not contain a string that it demonstrably does.
                    _supp = _prov_now.get("suppressed") or ""
                    if _supp:
                        log_fn(
                            f"[orchestrator] ⚑ the runner's output DID carry a "
                            f"flag-shaped string, dropped because the same "
                            f"output declares failure: {_supp!r}. The promoted "
                            f"flag is therefore not the runner's word for it."
                        )
                    if _tier == "runner_regex":
                        log_fn(
                            f"[orchestrator] ⚑ the promoted flag was SWEPT from "
                            f"the runner's output, not declared: the solver "
                            f"printed no `FLAG_CANDIDATE:` marker, so nothing "
                            f"asserts this string is the capture — only that it "
                            f"is flag-SHAPED. Job 0c04e636633c shipped its own "
                            f"diagnostic banner this way."
                        )
                    try:
                        write_meta(job_id, flag_trusted_tier=not _narrative_only,
                                   flag_provenance=_tier,
                                   flag_sweep_suppressed=bool(_supp))
                    except Exception:
                        pass

                # A run that SUCCEEDED has no "why it stopped". write_why_stopped
                # is not called on this path, so a WHY_STOPPED.md carried in from
                # the /retry parent survives in work/ and gets published as THIS
                # job's stop reason: a4729b5d91f2 shipped one dated to its parent
                # saying "Main agent session error" while holding a real flag.
                for _p in (work_dir / WHY_STOPPED_FILENAME,
                           work_dir.parent / WHY_STOPPED_FILENAME):
                    try:
                        if _p.is_file():
                            _p.unlink()
                            log_fn(
                                f"[orchestrator] removed stale "
                                f"{WHY_STOPPED_FILENAME} ({_p.parent.name}/) — "
                                f"this run succeeded, so the retry parent's stop "
                                f"reason is not this job's"
                            )
                    except OSError:
                        pass

                log_fn(
                    f"[orchestrator] auto-run turn {attempt} succeeded "
                    f"(flags={len(flags_now)}, verdict={verdict}, "
                    f"trusted_tier={not _narrative_only}) — exiting loop"
                )
                return last_sandbox

            # If the SDK transport died on this attempt (SIGKILL /
            # timeout), any `client.query(retry_hint)` below would
            # crash again. The sandbox + judge we just ran is the
            # rescue value of this job — surface it and stop instead
            # of trying to feed postjudge back into a broken session.
            # `.get()` (not direct indexing): the key is only set on
            # abnormal SDK termination paths; a clean DONE leaves
            # it absent.
            if summary.get("agent_error_kind") in ("killed", "timeout"):
                log_fn(
                    f"[orchestrator] client died this attempt "
                    f"({summary.get('agent_error_kind')}); surfacing sandbox "
                    f"verdict={verdict} without further retries"
                )
                write_why_stopped(
                    work_dir,
                    stop_kind="agent_error",
                    attempt_idx=attempt,
                    max_attempts=max_retries,
                    judge_out=judge_out,
                    sandbox_result=last_sandbox,
                    summary=summary,
                    log_fn=log_fn,
                )
                return last_sandbox

            # Judge's explicit stop decision — final authority. If the
            # judge agent decided this run is unrecoverable (wrong vuln
            # class picked, target unreachable, repeated mistakes…) we
            # halt the auto-retry loop and surface for human /retry,
            # even if max_retries would have allowed more attempts.
            next_action = (judge_out.get("next_action") or "continue").lower()
            stop_reason = (judge_out.get("stop_reason") or "").strip()
            # P2 — bounded ONE-shot method-change retry. Default OFF: unless the
            # judge explicitly sets retry_worthwhile=True on a STOP, this whole
            # branch is byte-identical to the historical terminal stop.
            _method_change_convert = False
            if next_action == "stop":
                # When the judge STOPs the current approach as structurally
                # doomed BUT flags a concrete DIFFERENT in-budget method
                # (retry_worthwhile=True), spend exactly ONE automated retry
                # that swaps the decisive step instead of halting — the
                # corrective method hint (e.g. McNie c1edf9e91910: "GB over
                # GF(2^19) too slow → Kipnis-Shamir linearization / FGLM /
                # reduced-var XL") otherwise dies with the STOP and needs a
                # human /retry. Capped at ONE per job; the judge prompt
                # excludes dead-remote / env-limit / true-negative /
                # same-method-tweak, so network_error or an unsolvable
                # true-negative never qualifies. Mirrors the prejudge-block
                # redirect pattern (synthesize continue + retry_hint, fall
                # through to the shared inject path). See [[concede_unsolvable_gate]].
                _mc_n = summary.get("method_change_retries", 0)
                _mc_hint = (judge_out.get("retry_hint") or "").strip()
                _mc_alt = judge_out.get("alternative_paths") or []
                if (judge_out.get("retry_worthwhile")
                        and _mc_n < 1 and (_mc_hint or _mc_alt)
                        and verdict != "network_error"):
                    _body = _mc_hint or stop_reason
                    if _mc_alt:
                        _body += (
                            "\n\nAlternative methods the judge flagged — pick ONE "
                            "and REBUILD the decisive step around it (do NOT merely "
                            "add a timeout / alarm / offset tweak to the SAME "
                            "method):\n- " + "\n- ".join(str(a) for a in _mc_alt[:3])
                        )
                    # Mutate judge_out in place — it IS last_sandbox["judge"]
                    # (same object; the key exists because we're in the stop
                    # branch), so the downstream inject path reads the new hint.
                    judge_out["retry_hint"] = (
                        "METHOD CHANGE REQUIRED (one-time conversion — the "
                        "orchestrator converts a judge STOP into a retry only "
                        "ONCE per job, and this attempt has spent it. Ordinary "
                        "auto-retries can still follow while postjudge keeps "
                        "voting continue, but the next postjudge STOP is "
                        "terminal: there is no second conversion). "
                        "The judge ruled the CURRENT "
                        "approach structurally cannot succeed within budget, but a "
                        "DIFFERENT method is viable. REPLACE the decisive step; do "
                        "NOT re-ship the same approach:\n\n" + _body
                    )
                    judge_out["next_action"] = "continue"
                    next_action = "continue"  # keep local in sync (logs + gates)
                    _method_change_convert = True
                    log_fn(
                        f"[orchestrator] judge STOP but retry_worthwhile=True — "
                        f"spending the ONE method-change retry (verdict={verdict}); "
                        f"injecting the alternative-method hint instead of halting"
                    )
                else:
                    summary["judge_stop_reason"] = stop_reason or "judge requested stop"
                    write_meta(
                        job_id,
                        judge_next_action="stop",
                        judge_stop_reason=summary["judge_stop_reason"],
                    )
                    log_fn(
                        f"[orchestrator] judge requested STOP "
                        f"(verdict={verdict}, reason={stop_reason or '(none)'}) — "
                        f"halting auto-retry loop"
                    )
                    write_why_stopped(
                        work_dir,
                        stop_kind="judge_stop",
                        attempt_idx=attempt,
                        max_attempts=max_retries,
                        judge_out=judge_out,
                        sandbox_result=last_sandbox,
                        summary=summary,
                        log_fn=log_fn,
                    )
                    return last_sandbox

            # Out of retries? Stop. Negative max_retries means unlimited
            # — only natural exit conditions (marker flag / verdict==success /
            # empty retry_hint / agent_error / user Stop / timeout) end
            # the loop in that case.
            if max_retries >= 0 and attempt >= max_retries:
                if max_retries > 0:
                    log_fn(
                        f"[orchestrator] auto-retry budget exhausted "
                        f"(attempt {attempt}/{max_retries}) — postjudge "
                        f"verdict={verdict}; surfacing for user retry"
                    )
                    write_why_stopped(
                        work_dir,
                        stop_kind="budget_exhausted",
                        attempt_idx=attempt,
                        max_attempts=max_retries,
                        judge_out=judge_out,
                        sandbox_result=last_sandbox,
                        summary=summary,
                        log_fn=log_fn,
                    )
                return last_sandbox

            # No retry hint? Nothing actionable to feed back — UNLESS prejudge
            # BLOCKED ship (sandbox never ran → no postjudge verdict/hint, so
            # this would dead-end). prejudge's own issues ARE the concrete fix
            # ("use BL/CL not AL", "untestable — remote is the only test",
            # "convert to leak-first"). Redirect them into a fix-and-retry turn
            # so main gets one more shot to fix + re-ship, instead of stopping
            # on a fixable near-miss. (Jobs bc2138675967 / 6b8b78b702b1 / 8244…
            # 12f1ada49: prejudge/postjudge gave concrete fixes that became
            # STOP signals.) Bounded by a hard cap, an anti-repeat signature
            # (same block twice → stop), and the existing SHA-unchanged gate.
            retry_hint = (judge_out.get("retry_hint") or "").strip()
            if not retry_hint and (last_sandbox or {}).get("error") == "prejudge_blocked":
                _pj = (last_sandbox or {}).get("prejudge") or {}
                _pj_issues = [
                    str(i).strip() for i in (_pj.get("issues") or [])
                    if str(i).strip()
                ]
                _pj_sig = " | ".join(sorted(_pj_issues))[:600]
                _seen = summary.setdefault("prejudge_block_sigs", [])
                _n = summary.setdefault("prejudge_block_redirects", 0)
                # CONCEDE-UNSOLVABLE gate. A prejudge block is normally a
                # FIXABLE near-miss worth a redirect. But when the script's OWN
                # artifacts self-admit no working chain (Phase-9 self-defeat hit
                # → "self-defeat in …" issue, emitted from a regex match on the
                # real exploit/report — not LLM prose) AND prejudge's calibrated
                # flag_likelihood is ≈0 (≤0.05), this is a confident
                # TRUE-NEGATIVE: "fix the no-chain defect" is unsatisfiable, and
                # redirecting just burns cost before the agent gives up anyway
                # (job 520f593c4590: flag_likelihood=0.02 + "leak-only chain"
                # self-defeat → 2 redirects + ~$30/3h → manual abort that
                # destroyed a VERIFIED libc leak). Concede + stop with a
                # structured verdict.
                #
                # Require _n >= 1 — i.e. concede only on the SECOND qualifying
                # block, AFTER at least one redirect has already been spent.
                # The first redirect is the safety net for a PREMATURE give-up
                # (agent wrote "leak-only" but a fix the redirect surfaces does
                # exist); historical redirect-saved jobs 6b8b78b702b1 /
                # 824412f1ada49 relied on it. If the agent ships ANOTHER
                # self-defeating fl≈0 script after being told to fix it, the
                # true-negative is corroborated. This caps 520f at 1 redirect
                # (down from 2 + manual abort) without the early-dead-end risk.
                #
                # EXCLUDE untestable-locally (vsyscall / CET / kernel): there
                # the low likelihood is an ENV limit, not a dead chain, and
                # remote-probe is legitimate — do NOT regress job bc2138675967.
                _pj_fl = _pj.get("flag_likelihood")
                try:
                    _pj_fl = None if _pj_fl is None else float(_pj_fl)
                except (TypeError, ValueError):
                    _pj_fl = None
                _self_defeat = any(
                    s.lower().startswith("self-defeat in ") for s in _pj_issues
                )
                try:
                    from modules.pwn import chain_schema as _cs
                    _untestable = any(
                        _cs._UNTESTABLE_LOCALLY_RE.search(s) for s in _pj_issues
                    )
                except Exception:
                    # Safe fallback: if we can't classify, do NOT concede
                    # (preserve the existing redirect behavior).
                    _untestable = True
                _concede_unsolvable = bool(
                    _pj_fl is not None and _pj_fl <= 0.05
                    and _self_defeat and not _untestable and _n >= 1
                )
                _block_count = int(_n or 0) + 1
                _sandbox_runs = int(summary.get("sandbox_runs") or 0)
                _turns, _estimated_cost = _prejudge_stop_metrics(job_id, summary)

                def _write_prejudge_escalation(_kind: str, _reason: str) -> None:
                    summary["judge_stop_reason"] = _reason
                    write_meta(
                        job_id,
                        judge_next_action="stop",
                        judge_stop_reason=_reason,
                    )
                    _stop_out = dict(judge_out or {})
                    _stop_out.update({
                        "verdict": "prejudge_blocked",
                        "next_action": "stop",
                        "stop_reason": _reason,
                    })
                    write_why_stopped(
                        work_dir,
                        stop_kind=_kind,
                        attempt_idx=attempt,
                        max_attempts=max_retries,
                        judge_out=_stop_out,
                        sandbox_result=last_sandbox,
                        summary=summary,
                        log_fn=log_fn,
                    )

                # A8 has its own terminal class.  This predicate consumes only
                # the typed field produced by prejudge; issue prose is evidence
                # for the human, never a control-flow API.  It precedes the
                # analytical concede because a dead endpoint is an operator
                # action regardless of what the exploit artifacts also admit.
                if _pj.get("target_liveness") == "dead":
                    summary["prejudge_dead_target"] = True
                    _reason = (
                        "prejudge verified target_liveness=dead on BLOCKED "
                        f"{_block_count}; sandbox runs={_sandbox_runs}; cumulative "
                        f"main turns={_turns}; estimated cumulative cost="
                        f"${_estimated_cost:.2f}. Escalated for operator target "
                        "re-provisioning/update; no script redirect was issued."
                    )
                    log_fn(f"[orchestrator] {_reason}")
                    _write_prejudge_escalation("prejudge_dead_target", _reason)
                    return last_sandbox

                # ORDER IS LOAD-BEARING (A2 truth table): concede MUST be tested
                # before the generic second-BLOCK/no-run escalation below.
                # Otherwise every second qualifying self-defeat is swallowed by
                # prejudge_blocked_no_run and `unsolvable_by_analysis` becomes
                # unreachable.  A dead target remains the separate A8 case above.
                if _concede_unsolvable:
                    summary["conceded_unsolvable"] = True
                    log_fn(
                        "[orchestrator] prejudge BLOCKED + flag_likelihood="
                        f"{_pj_fl:.2f}≤0.05 + self-defeat after {_n} redirect(s) "
                        "(artifacts still admit no working chain) — conceding "
                        "unsolvable_by_analysis; stopping auto-retry"
                    )
                    write_why_stopped(
                        work_dir,
                        stop_kind="unsolvable_by_analysis",
                        attempt_idx=attempt,
                        max_attempts=max_retries,
                        judge_out=judge_out,
                        sandbox_result=last_sandbox,
                        summary=summary,
                        log_fn=log_fn,
                    )
                    return last_sandbox

                # A2: preserve one corrective redirect, but a second ship-block
                # with zero real sandbox executions is enough evidence that the
                # analysis loop is not converging.  The stop reason carries the
                # measured cost/turns AND the known historical uncertainty; the
                # latter must survive into the operator-facing artifact rather
                # than living only in this source comment.
                if _n >= 1 and _sandbox_runs == 0:
                    summary["prejudge_no_run_escalated"] = True
                    _reason = (
                        f"prejudge BLOCKED {_block_count} times with sandbox "
                        f"runs=0; cumulative main turns={_turns}; estimated "
                        f"cumulative cost=${_estimated_cost:.2f}. Automatic "
                        "redirects stop at threshold 2. Unverified regression "
                        "risk: redirect-saved jobs 6b8b78b702b1 and "
                        "824412f1ada49 expired from TTL before their successful "
                        "redirect ordinal could be checked; threshold 2 may have "
                        "stopped either job early."
                    )
                    log_fn(f"[orchestrator] {_reason}")
                    _write_prejudge_escalation(
                        "prejudge_blocked_no_run", _reason
                    )
                    return last_sandbox
                if _pj_issues and _pj_sig and _pj_sig not in _seen and _n < 3:
                    _seen.append(_pj_sig)
                    summary["prejudge_block_redirects"] = _n + 1
                    retry_hint = (
                        "prejudge BLOCKED ship — the sandbox never ran. "
                        "These issues are evidence about the CURRENT chain, "
                        "not proof that one proposed correction is the "
                        "intended solution. First classify them as an "
                        "IMPLEMENTATION defect (verified chain, broken code) "
                        "or a STRATEGY/UNKNOWN defect (missing or disproved "
                        "primitive). Patch and re-ship the same chain only in "
                        "the first case. In the second case, stop polishing "
                        "that chain: preserve verified primitives, mark "
                        "refuted premises, test at least two materially "
                        "different untried hypotheses with the cheapest "
                        "discriminating probe, and replace the script with "
                        "the strongest evidence-backed chain. Do not repeat "
                        "a refuted branch without new evidence.\n\n"
                        "CURRENT CHAIN ISSUES:\n- "
                        + "\n- ".join(_pj_issues[:6])
                        + "\n\nIf an issue says a primitive is 'untestable "
                        "locally' (vsyscall / CET / kernel — the worker "
                        "physically cannot test it), do NOT abandon it: the run "
                        "is now allowed to probe the remote. Either keep it AND "
                        "add a fallback that does not depend on the unverifiable "
                        "feature, or convert to a leak-first design that reads "
                        "ground truth from the target."
                    )
                    if _sandbox_runs == 0:
                        retry_hint += (
                            "\n\nBUDGET: this is the LAST automatic redirect "
                            "unless a real sandbox execution happens first. "
                            "prejudge has blocked this job's ship once and no "
                            "sandbox run has completed yet; if it blocks again "
                            "before one real execution, the orchestrator ends "
                            "the job (stop_kind=prejudge_blocked_no_run) "
                            "instead of redirecting. End this turn with a "
                            "shipped script that clears the gate, not with "
                            "another analysis round."
                        )
                    # Synthesize a judge dict so the existing inject path
                    # (_format_postjudge_user_turn) carries this hint verbatim.
                    last_sandbox["judge"] = {
                        "verdict": "prejudge_blocked",
                        "next_action": "continue",
                        "retry_hint": retry_hint,
                        "summary": (
                            "prejudge ship-block — classify the failure, "
                            "reassess the chain, then retry"
                        ),
                    }
                    log_fn(
                        f"[orchestrator] prejudge BLOCKED — redirecting its "
                        f"{len(_pj_issues)} issue(s) into a fix-and-retry turn "
                        f"(redirect {_n + 1}; "
                        + ("the next no-run block escalates"
                           if _sandbox_runs == 0 else "hard cap 3")
                        + ") instead of dead-ending"
                    )
                else:
                    log_fn(
                        "[orchestrator] prejudge BLOCKED with no new actionable "
                        "issues (repeat / cap reached) — stopping auto-retry"
                    )
            # Last resort before giving up: a crash whose diagnosis is a literal
            # string in the runner's own stderr does not need the judge. This is
            # the ONLY hint producer that survives `enable_judge=False`, which
            # otherwise makes auto-retry structurally impossible — no judge, no
            # hint, stop at turn 0 (job 06f3a326d453: a missing `import numpy`
            # ended a $23 run after 2 seconds of sandbox time).
            if not retry_hint:
                _crash_hint = runner_crash_hint(last_sandbox)
                if _crash_hint:
                    # Same shape the prejudge redirect above uses, so the
                    # existing inject path carries it verbatim.
                    retry_hint = _crash_hint
                    last_sandbox = dict(last_sandbox or {})
                    last_sandbox["judge"] = {
                        "verdict": "runner_crash",
                        "next_action": "continue",
                        "retry_hint": retry_hint,
                        "summary": "solver crashed in the runner — fix and re-ship",
                    }
                    judge_out = last_sandbox["judge"]
                    log_fn(
                        "[orchestrator] the runner's own stderr diagnoses this "
                        "crash — synthesizing a retry hint without the judge "
                        "(this path is what keeps auto-retry alive when "
                        "enable_judge is off)"
                    )
            # AUP-poisoned-session guard. If the main turn that just ran was
            # blocked by the server-side Usage-Policy classifier
            # (policy_refusal), the conversation context is poisoned: the
            # `await client.query()` below re-issues into the SAME session and
            # re-blocks deterministically (ab95a434bb0f 07:30:18,
            # 2eba75783e83 11:39:46 — a guaranteed-fail re-block that wastes a
            # turn + $; the SHA-unchanged gate then halts one iteration too
            # late). Skip the in-place retry; recover or halt here. WHY_STOPPED
            # routes the operator to /retry, which forks a FRESH session that
            # sheds the poison (the de-facto cure).
            #
            # ORDER IS LOAD-BEARING: this must stay ABOVE the `if not
            # retry_hint` give-up below. It used to sit under it, and that made
            # the whole recovery ladder unreachable in the shipped
            # configuration — the give-up returns first, so the ladder only ran
            # when a hint EXISTED, and with `enable_judge` off the only hint
            # producer is runner_crash_hint (missing module / missing binary).
            # Job 3d8cca4e26de is the proof: main was AUP-blocked on turn 37
            # holding an exploit that already connected and leaked, and the run
            # ended `stop_kind=no_hint` with no ladder entry in the log at all.
            # It must also stay BELOW the crash-hint synthesis, so a session
            # that is both AUP-blocked and crashed carries that hint into
            # RESUME_STATE.md for its successor.
            #
            # Moving it changes exactly one case — AUP with no hint, which used
            # to die here. AUP-with-hint already reached the ladder; non-AUP
            # falls through this `if` untouched in both orders.
            if summary.get("agent_error_kind") == "policy_refusal":
                # The SESSION is blocked, not necessarily the JOB. Walk the
                # recovery ladder before giving up: a clean context first,
                # then the other configured provider. Both keep the work tree;
                # neither touches the prompt text.
                from modules.agent_provider import (
                    active_provider, default_model_for, has_grok_auth,
                )
                _grok_ok = False
                try:
                    _grok_ok = (active_provider() != "grok") and has_grok_auth()
                except Exception:
                    pass
                _step = aup_recovery_step(summary, grok_available=_grok_ok)
                if _step:
                    summary.setdefault("aup_recoveries", []).append(_step)
                    write_resume_state(
                        work_dir,
                        job_id=job_id,
                        summary=summary,
                        sandbox_result=last_sandbox,
                        judge_out=judge_out,
                        attempt_idx=attempt,
                        reason="blocked by the server-side Usage-Policy "
                               "classifier (policy_refusal)",
                        log_fn=log_fn,
                    )
                    log_fn(
                        f"[orchestrator] main turn AUP-blocked — recovering via "
                        f"`{_step}` (attempt "
                        f"{len(summary['aup_recoveries'])}/"
                        f"{len(_AUP_RECOVERY_STEPS)}). The work tree is kept; "
                        f"the refused conversation is dropped."
                    )
                    _fresh = await _aup_restart_session(
                        job_id,
                        step=_step,
                        options=options,
                        original_prompt=initial_prompt,
                        summary=summary,
                        work_dir=work_dir,
                        artifact_names=artifact_names,
                        auto_run=auto_run,
                        sandbox_runner=sandbox_runner,
                        log_fn=log_fn,
                    )
                    if _fresh is not _AUP_RESTART_FAILED:
                        # `None` from the successor must NOT overwrite our own
                        # last_sandbox. Ours may be a skip sentinel
                        # ({"error": "prejudge_blocked"} / judge_aborted), and
                        # scan_job_for_flags treats a FALSY sandbox_result as
                        # "the sandbox ran and told us nothing" rather than
                        # "it never ran" — see the sandbox_skipped gate at
                        # modules/_common.py:1505. Losing the sentinel re-opens
                        # the NARRATIVE flag tier and promotes agent-authored
                        # prose in report.md / findings.json to meta.flags with
                        # final_status="finished": a false capture, which is
                        # the exact class the gate exists to prevent.
                        #
                        # None is an ORDINARY successor return (7765 returns
                        # last_sandbox for every classify_agent_error kind that
                        # is not killed/timeout — cli_infra_error, auth,
                        # rate_limit, unknown — and 8259 on a runner crash), so
                        # this is not a corner case.
                        return _fresh if _fresh is not None else last_sandbox
                    log_fn(
                        f"[orchestrator] `{_step}` recovery could not start — "
                        f"falling through to halt."
                    )
                log_fn(
                    "[orchestrator] main turn AUP-blocked (policy_refusal) and "
                    "the recovery ladder is exhausted — halting. A repeat block "
                    "on a CLEAN context means the challenge content itself is "
                    "what the classifier objects to, not the accumulated "
                    "transcript. /retry forks a fresh session if you disagree."
                )
                write_why_stopped(
                    work_dir,
                    stop_kind="policy_refusal",
                    attempt_idx=attempt,
                    max_attempts=max_retries,
                    judge_out=judge_out,
                    sandbox_result=last_sandbox,
                    summary=summary,
                    log_fn=log_fn,
                )
                return last_sandbox

            # Modules outside judge-enforce scope used to stop after their first
            # real sandbox failure: shadow deliberately supplies no live verdict,
            # therefore there was no retry hint to feed back to main.  Spend one
            # bounded reviewer turn here to challenge the failed branch using the
            # same evidence bundle as manual /retry.  The four-part gate is the
            # whole policy: no prose inspection and no module allowlist.
            _reviewer_gate = (
                not retry_hint
                and (last_sandbox or {}).get("judge_mode") == "shadow"
                and not judge_out
                and int(summary.get("reviewer_redirects") or 0) == 0
                and int(summary.get("sandbox_runs") or 0) >= 1
            )
            if _reviewer_gate:
                try:
                    from modules.reviewer import (
                        ReviewerError,
                        _ask_reviewer_with_failover,
                        _gather_context,
                        _sanitize_hint,
                    )

                    _reviewer_context = _gather_context(
                        roots=(job_dir(job_id), work_dir)
                    )
                    if not _reviewer_context.strip():
                        raise ReviewerError(
                            "no job evidence was available to the reviewer",
                            "no_context",
                        )
                    summary["reviewer_calls"] = (
                        int(summary.get("reviewer_calls") or 0) + 1
                    )
                    _reviewer_raw_hint = await _ask_reviewer_with_failover(
                        _reviewer_context,
                        job_id=job_id,
                    )
                    _reviewer_hint = _sanitize_hint(_reviewer_raw_hint).strip()
                    if not _reviewer_hint:
                        raise ReviewerError(
                            "reviewer hint became empty after sanitization",
                            "empty",
                        )
                except Exception as _reviewer_exc:
                    # ReviewerError.kind is the only persisted failure detail.
                    # Raw provider text can contain secrets or policy payloads,
                    # and every failure must retain today's fail-closed direction:
                    # fall through to judge_shadow_no_verdict below.
                    summary["reviewer_error_kind"] = (
                        getattr(_reviewer_exc, "kind", None) or "unavailable"
                    )
                    log_fn(
                        "[orchestrator] one-shot reviewer could not produce a "
                        "redirect "
                        f"(kind={summary['reviewer_error_kind']}) — preserving "
                        "judge_shadow_no_verdict"
                    )
                else:
                    summary["reviewer_redirects"] = (
                        int(summary.get("reviewer_redirects") or 0) + 1
                    )
                    summary["reviewer_hint_chars"] = len(_reviewer_hint)
                    last_sandbox = dict(last_sandbox or {})
                    last_sandbox["judge"] = {
                        "verdict": "reviewer_redirect",
                        "next_action": "continue",
                        "retry_hint": _reviewer_hint,
                        "summary": (
                            "one-shot reviewer challenged the failed shadow-mode "
                            "branch"
                        ),
                    }
                    judge_out = last_sandbox["judge"]
                    retry_hint = _reviewer_hint
                    verdict = judge_out["verdict"]
                    next_action = judge_out["next_action"]
                    log_fn(
                        "[orchestrator] shadow judge supplied no live verdict — "
                        "injecting one reviewer redirect before stopping "
                        f"({len(_reviewer_hint)} chars)"
                    )
            if not retry_hint:
                _shadow_no_verdict = (
                    (last_sandbox or {}).get("judge_mode") == "shadow"
                    and not judge_out
                )
                _no_hint_kind = (
                    "reviewer_redirect_no_run"
                    if _shadow_no_verdict
                    and int(summary.get("reviewer_redirects") or 0) >= 1
                    else "judge_shadow_no_verdict"
                    if _shadow_no_verdict
                    else "no_hint"
                )
                _no_hint_out = judge_out
                if _shadow_no_verdict:
                    # A3 is presentation, not a new gate.  Shadow deliberately
                    # supplies no live opinion; name that absence without
                    # pretending `unknown` voted to stop the run.
                    _no_hint_out = dict(judge_out or {})
                    _no_hint_out["stop_reason"] = (
                        "judge_mode=shadow recorded the run for delayed review "
                        "but supplied no live gating verdict or retry hint; "
                        "unknown is an absence of opinion, not a stop vote"
                    )
                log_fn(
                    f"[orchestrator] postjudge produced no retry_hint "
                    f"(verdict={verdict}, next_action={next_action}) — "
                    f"stopping auto-retry (stop_kind={_no_hint_kind})"
                )
                _no_hint_args = dict(
                    attempt_idx=attempt,
                    max_attempts=max_retries,
                    judge_out=_no_hint_out,
                    sandbox_result=last_sandbox,
                    summary=summary,
                    log_fn=log_fn,
                )
                # Keep the original no-hint class for enforce/off and judge
                # failures; shadow absence and a spent reviewer redirect have
                # their own observable stop kinds.
                write_why_stopped(
                    work_dir,
                    stop_kind=_no_hint_kind,
                    **_no_hint_args,
                )
                return last_sandbox


            # Inject postjudge feedback as next user turn and loop.
            attempt += 1
            # Charge the ONE method-change retry only now that every stop/cap
            # gate above has been cleared and we are definitely re-querying —
            # so a budget_exhausted return never silently burns the allowance
            # without an actual retry.
            if _method_change_convert:
                summary["method_change_retries"] = (
                    summary.get("method_change_retries", 0) + 1
                )
            write_meta(job_id, stage=f"auto-retry-{attempt}")
            feedback = _format_postjudge_user_turn(
                attempt_idx=attempt,
                max_attempts=max_retries,
                script_filename=picked,
                sandbox_result=last_sandbox or {},
                method_change=_method_change_convert,
            )
            log_fn(
                f"[orchestrator] injecting postjudge feedback as new user "
                f"turn (attempt {attempt}/{max_retries}, verdict={verdict})"
            )
            # Persist what was actually injected. The counters next to this
            # (reviewer_redirects, prejudge_block_redirects) already say a
            # producer fired, but nothing recorded WHICH TEXT reached main, so
            # `579a216ed747` could be shown to have traversed the formatter
            # while the rendered bytes were unrecoverable afterwards. Storing
            # the digest rather than 3.4 KB per injection keeps meta small and
            # still lets a later run re-render the same inputs and compare.
            # `verdict` is the producer key `_format_postjudge_user_turn` maps
            # to its origin label, so origin stays derivable without copying
            # that table out of the function it is deliberately local to.
            summary.setdefault("injected_turns", []).append({
                "attempt": attempt,
                "verdict": verdict,
                "chars": len(feedback),
                "sha256": hashlib.sha256(feedback.encode()).hexdigest()[:16],
            })
            await client.query(feedback)
            # Capture script SHA so the next iteration can detect
            # "main returned without applying the fix" and skip the
            # guaranteed-fail re-run (see SHA-unchanged ship gate above).
            script_sha_at_last_inject["sha"] = _script_sha(work_dir / picked)
            script_sha_at_last_inject["script"] = picked
            # loop continues; receive_response on next iteration

    # unreachable; kept for type-checkers
    return last_sandbox


# The soft-timeout watchdog was REMOVED 2026-07-30 (operator: "불필요한 기능").
# It slept for `job_timeout` (default 900 s), then set `awaiting_decision` and
# popped a UI banner the operator had to dismiss by hand. It never interrupted
# anything — the docstring said so — so it protected nothing while firing on
# essentially every real job: this pipeline routinely runs for hours (5h17m on
# c552faf18d31), and job fa511be2e84e needed a manual CONTINUE click 15 minutes
# in. The real backstop is untouched: api.queue.hard_timeout_for() still gives
# RQ a kill ceiling of at least 24 h (7 d cap), derived from the same
# `job_timeout`, which is why that field is still read and still meaningful.
