"""Per-job live MONITOR — a curated, LLM-narrated signal feed over run.log.

Why this exists
---------------
`run.log` is a raw human tail: a long pwn job emits ~1000 lines, ~96% of them
`[main] TOOL`/`TOOL_RESULT` echo. Reading it live to understand "what is the
agent actually doing" means eyeballing that noise. The MONITOR is the answer:
a background task filters run.log to meaningful SIGNAL events (stage/status
changes, `[main] AGENT:` prose, `[orchestrator]` subagent lifecycle, judge /
prejudge / retry, errors, `FLAG_CANDIDATE`), batches them, and asks a cheap
model to narrate WHAT JUST HAPPENED in one short line — in every configured
language (default ko + en). The result is appended to `<job>/monitor.jsonl`
and published to the Redis channel `job:<id>:monitor` so the SSE stream can
push it live to the UI, next to the raw run log, with a language selector.

Design
------
* HYBRID: structured meta changes (stage/status/flag) get a deterministic,
  localized entry (no LLM); prose signal batches get an LLM narration.
* LIVE / always-on: an async supervisor (started from api.main) sweeps
  running jobs every few seconds and ensures a monitor task per job — so
  commentary is generated even if nobody is watching (opt-out via
  MONITOR_ENABLED=0). A cheap model is pinned (MONITOR_MODEL, default
  sonnet) — NEVER the job's own opus, which would be waste.
* Runs in the API container (has claude-agent-sdk + ~/.claude/.env auth +
  the /data mount + redis), which is free of the worker's exploit-run glibc
  pollution that can break CLI spawns.
* Best-effort: every failure is swallowed — observability must never break
  the pipeline it observes, and must never touch run.log/meta.json.

This module is import-light: it talks to redis directly and imports the SDK
lazily inside the narration call, so importing it from api/ is cheap and
side-effect-free.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
JOBS_DIR = DATA_DIR / "jobs"

MONITOR_ENABLED = os.environ.get("MONITOR_ENABLED", "1") != "0"
MONITOR_MODEL = os.environ.get("MONITOR_MODEL", "claude-sonnet-4-6")
MONITOR_LANGS = tuple(
    x.strip() for x in os.environ.get("MONITOR_LANGS", "ko,en").split(",") if x.strip()
) or ("ko", "en")

_LANG_NAMES = {
    "ko": "Korean", "en": "English", "ja": "Japanese", "zh": "Chinese",
    "es": "Spanish", "fr": "French", "de": "German", "ru": "Russian",
}

_TERMINAL = {"finished", "failed", "no_flag", "stopped"}

POLL_S = 4.0          # run.log / meta.json poll cadence
BATCH_MAX = 6         # flush the pending signal batch once it reaches this many
BATCH_MAX_S = 9.0     # ...or once this long has elapsed with >=1 pending
BACKLOG_SKIP = 8192   # if a fresh monitor attaches to a log already bigger than
                      # this, skip narrating the backlog (start live)
_NARRATE_TIMEOUT_S = 60

_REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")

# ---------------------------------------------------------------------------
# redis publish (own tiny client — keep this module independent of _common)
# ---------------------------------------------------------------------------
_redis = None
_redis_failed = False


def _get_redis():
    global _redis, _redis_failed
    if _redis is not None:
        return _redis
    if _redis_failed:
        return None
    try:
        from redis import Redis
        _redis = Redis.from_url(_REDIS_URL, socket_timeout=1, socket_connect_timeout=1)
    except Exception:
        _redis_failed = True
        return None
    return _redis


def _publish(job_id: str, entry: dict) -> None:
    r = _get_redis()
    if r is None:
        return
    try:
        r.publish(f"job:{job_id}:monitor", json.dumps(entry, ensure_ascii=False))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# signal classification (deterministic filter over a run.log line body)
# ---------------------------------------------------------------------------
# `body` = the run.log line WITHOUT the "[HH:MM:SS] " timestamp prefix, e.g.
# "[main] AGENT: ...", "[orchestrator] isolated recon#1 done ...",
# "[judge] prejudge BLOCKED ...". Returns (kind, severity) or None to drop.

_SEV_RANK = {"info": 0, "good": 1, "warn": 2, "err": 3}

_RE_TOOLECHO = re.compile(r"\bTOOL (Bash|Read|Edit|Write|mcp)\b|TOOL_RESULT|\bTHINK\b")
_RE_ARTIFACT = re.compile(r"TOOL (Write|Edit)[^\n]*(exploit|solver)\.py")
_RE_ERROR = re.compile(
    r"traceback|exception:|budget_abort|\bkilled\b|connection refused|"
    r"could not connect|broken pipe|sigsegv|segfault|core dumped",
    re.I,
)
_RE_JUDGE = re.compile(r"prejudge|postjudge|\bjudge\b|verdict|blocked ship", re.I)
_RE_RETRY = re.compile(r"attempt \d+/|auto-retry|retry_hint|contrarian|redirect|halting", re.I)
_RE_NUDGE = re.compile(r"scaffold_nudge|scaffold", re.I)
_RE_SUBAGENT = re.compile(r"\[orchestrator\]|spawning|isolated ", re.I)
_RE_AGENT = re.compile(r"\] AGENT:")
_RE_PHASE = re.compile(r"\[(runner|report|sandbox|autoboot|pre-recon)\]", re.I)


def classify(body: str) -> tuple[str, str] | None:
    # FLAG and ERROR are checked BEFORE the tool-echo skip: a captured flag or a
    # crash/connection error often surfaces inside a TOOL_RESULT line (e.g.
    # "[main] TOOL_RESULT: Could not connect to host"), and dropping those as
    # "tool echo" would lose the two most important signals.
    if "FLAG_CANDIDATE:" in body and "{" in body:
        return ("flag", "good")
    if _RE_ERROR.search(body):
        return ("error", "err")
    if _RE_TOOLECHO.search(body):
        # tool echo is noise — except an exploit/solver write, which is a real
        # milestone worth surfacing.
        if _RE_ARTIFACT.search(body):
            return ("artifact", "info")
        return None
    if _RE_JUDGE.search(body):
        return ("judge", "warn")
    if _RE_RETRY.search(body):
        return ("retry", "warn")
    if _RE_NUDGE.search(body):
        return ("nudge", "warn")
    if _RE_SUBAGENT.search(body):
        return ("subagent", "info")
    if _RE_AGENT.search(body):
        return ("agent", "info")
    if _RE_PHASE.search(body):
        return ("phase", "info")
    return None


# ---------------------------------------------------------------------------
# entry construction + emit
# ---------------------------------------------------------------------------
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _entry(kind: str, sev: str, text: dict, *, raw: list | None = None, **extra) -> dict:
    e: dict[str, Any] = {
        "ts": _now_iso(),
        "kind": kind,
        "sev": sev,
        "text": text,
        "raw": raw or [],
    }
    if extra:
        e.update(extra)
    return e


def _emit(job_id: str, entry: dict) -> None:
    """Append to <job>/monitor.jsonl and publish to redis. Best-effort."""
    try:
        p = JOBS_DIR / Path(job_id).name / "monitor.jsonl"
        if not p.parent.is_dir():
            return
        with p.open("a") as fp:
            fp.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass
    _publish(job_id, entry)


def _read_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# LLM narration of a signal batch (cheap model, strict-JSON multi-language)
# ---------------------------------------------------------------------------
async def _narrate(signal_lines: list[str], model: str) -> dict:
    """Return {lang: one-line summary} for the batch, or {} on any failure."""
    try:
        from claude_agent_sdk import ClaudeAgentOptions, query
        import anyio
    except Exception:
        return {}

    langs = MONITOR_LANGS
    want = ", ".join(
        f'"{l}" ({_LANG_NAMES.get(l, l)})' for l in langs
    )
    sys_prompt = (
        "You are a live MONITOR for an autonomous CTF-solving agent run. "
        "You receive a small batch of already-filtered raw log SIGNAL lines from "
        "one moment of the run (agent prose, subagent lifecycle, judge/retry, "
        "errors, artifacts). Summarize WHAT JUST HAPPENED in ONE short, concrete, "
        "technical line per language (max ~160 chars each). Plain text, no markdown, "
        "no line breaks within a value. "
        f"Respond with STRICT JSON ONLY — an object whose keys are exactly {want}. "
        "No prose, no code fences, nothing but the JSON object."
    )
    prompt = "SIGNAL LINES:\n" + "\n".join(signal_lines[-12:])

    options = ClaudeAgentOptions(
        system_prompt=sys_prompt,
        model=model,
        allowed_tools=[],
        disallowed_tools=["Agent", "Task", "WebSearch", "WebFetch", "Bash",
                          "Read", "Write", "Edit", "Glob", "Grep"],
        permission_mode="bypassPermissions",
    )

    acc = ""
    try:
        with anyio.fail_after(_NARRATE_TIMEOUT_S):
            async for msg in query(prompt=prompt, options=options):
                cls = type(msg).__name__
                if cls == "AssistantMessage":
                    for block in getattr(msg, "content", []) or []:
                        if type(block).__name__ == "TextBlock":
                            acc += getattr(block, "text", "") or ""
                elif cls == "ResultMessage":
                    if getattr(msg, "is_error", False):
                        return {}
    except Exception:
        return {}

    acc = acc.strip()
    if acc.startswith("```"):
        acc = acc.split("\n", 1)[1] if "\n" in acc else acc[3:]
        if acc.endswith("```"):
            acc = acc[:-3]
        acc = acc.strip()
    try:
        d = json.loads(acc)
        if not isinstance(d, dict):
            return {}
        return {l: str(d.get(l, "")).strip() for l in langs}
    except Exception:
        return {}


async def _flush_batch(job_id: str, batch: list[tuple[str, tuple[str, str]]], model: str) -> None:
    """batch = [(body, (kind, sev)), ...]. Narrate + emit ONE entry."""
    if not batch:
        return
    bodies = [b for b, _ in batch]
    # representative kind = most severe; severity = max
    top = max(batch, key=lambda x: _SEV_RANK.get(x[1][1], 0))
    kind, sev = top[1]
    text = await _narrate(bodies, model)
    if not text:
        # LLM unavailable: fall back to a raw-only entry so the signal still
        # shows up in the monitor feed (just without narration).
        text = {l: bodies[-1][:160] for l in MONITOR_LANGS}
        text["_fallback"] = "1"
    _emit(job_id, _entry(kind, sev, text, raw=bodies))


# ---------------------------------------------------------------------------
# the per-job monitor loop
# ---------------------------------------------------------------------------
def _statefile(job_id: str) -> Path:
    return JOBS_DIR / Path(job_id).name / ".monitor.state"


async def run_monitor(job_id: str, model: str | None = None) -> None:
    model = model or MONITOR_MODEL
    jd = JOBS_DIR / Path(job_id).name
    logp = jd / "run.log"
    metap = jd / "meta.json"
    monp = jd / "monitor.jsonl"
    statep = _statefile(job_id)

    # --- resolve starting offset (resume-safe) -----------------------------
    try:
        size = logp.stat().st_size
    except OSError:
        size = 0
    off = 0
    resumed = False
    st = _read_json(statep)
    if isinstance(st.get("off"), int) and 0 <= st["off"] <= size:
        off = st["off"]           # exact resume across an API restart
        resumed = True
    elif not monp.exists() and size > BACKLOG_SKIP:
        off = size                # fresh attach to an already-long log: go live
        _emit(job_id, _entry("start", "info",
              {"ko": "모니터링 시작 (이미 진행 중인 job)", "en": "monitoring started (job already running)"}))
    elif not monp.exists():
        _emit(job_id, _entry("start", "info",
              {"ko": "모니터링 시작", "en": "monitoring started"}))
    else:
        off = size                # monitor file exists but no state: avoid re-narrating

    prev_stage = None
    prev_flags = None
    prev_status = None
    pending: list[tuple[str, tuple[str, str]]] = []
    last_flush = time.monotonic()

    while True:
        # --- ingest new run.log bytes --------------------------------------
        try:
            with logp.open("rb") as fp:
                fp.seek(off)
                data = fp.read()
                off = fp.tell()
        except OSError:
            data = b""
        if data:
            for raw in data.decode("utf-8", "replace").splitlines():
                m = re.match(r"^\[(\d\d:\d\d:\d\d)\] (.*)$", raw)
                body = m.group(2) if m else raw
                kc = classify(body)
                if kc:
                    pending.append((body, kc))
            try:
                statep.write_text(json.dumps({"off": off}))
            except Exception:
                pass

        # --- meta-driven deterministic entries -----------------------------
        meta = _read_json(metap)
        status = meta.get("status")
        stage = meta.get("stage")
        turns = meta.get("agent_turns")
        flags = meta.get("flag_candidates")

        if stage and stage != prev_stage:
            _emit(job_id, _entry("stage", "info",
                  {"ko": f"단계 → {stage}", "en": f"stage → {stage}"},
                  stage=stage, turns=turns))
            prev_stage = stage
        if flags and flags != prev_flags:
            _emit(job_id, _entry("flag", "good",
                  {"ko": f"🚩 FLAG 후보: {flags}", "en": f"🚩 flag candidate: {flags}"},
                  flags=flags))
            prev_flags = flags

        # --- flush the prose batch through the LLM -------------------------
        now = time.monotonic()
        if pending and (len(pending) >= BATCH_MAX or now - last_flush >= BATCH_MAX_S):
            batch, pending = pending, []
            last_flush = now
            await _flush_batch(job_id, batch, model)

        # --- terminal? -----------------------------------------------------
        if status and status in _TERMINAL:
            if pending:
                await _flush_batch(job_id, pending, model)
                pending = []
            _emit(job_id, _entry("terminal", "good" if status == "finished" else "warn",
                  {"ko": f"■ 종료: {status}", "en": f"■ terminal: {status}"},
                  status=status))
            return

        prev_status = status
        await asyncio.sleep(POLL_S)


# ---------------------------------------------------------------------------
# supervisor + ensure — one monitor task per running job (always-on)
# ---------------------------------------------------------------------------
_TASKS: dict[str, "asyncio.Task"] = {}


def _is_terminal(job_id: str) -> bool:
    """True if the job's meta.status is a terminal state (the run is over)."""
    meta = _read_json(JOBS_DIR / Path(job_id).name / "meta.json")
    return meta.get("status") in _TERMINAL


def ensure_monitor(job_id: str) -> None:
    """Start a monitor task for job_id if none is alive. Idempotent.
    Must be called from within the API's asyncio loop."""
    if not MONITOR_ENABLED or not job_id:
        return
    t = _TASKS.get(job_id)
    if t is not None and not t.done():
        return
    # Don't spin up a LIVE monitor for a job that's already terminal. The run
    # is over and run.log won't grow, so a fresh task would only re-emit
    # stage/flag/terminal (prev_* start at None) and re-narrate the tail —
    # which is exactly the "monitor keeps working after the job ends" bug
    # (job cff9474c35cf): the route calls ensure_monitor on every GET
    # /monitor and every SSE /stream open, neither status-gated, so each UI
    # reconnect to a finished job spawned a fresh short-lived task that
    # re-appended duplicate terminal/stage/flag entries. The route serves
    # monitor.jsonl history directly, so a finished job's feed still renders
    # in full without any live task. (The supervisor already filters terminal
    # jobs; this closes the same gap for the two route call sites.)
    if _is_terminal(job_id):
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    _TASKS[job_id] = loop.create_task(_guarded(job_id))


async def _guarded(job_id: str) -> None:
    try:
        await run_monitor(job_id)
    except Exception:
        pass
    finally:
        _TASKS.pop(job_id, None)


def _scan_running() -> list[str]:
    out: list[str] = []
    try:
        for d in JOBS_DIR.iterdir():
            if not d.is_dir():
                continue
            meta = _read_json(d / "meta.json")
            status = meta.get("status")
            # a job is worth monitoring while it has a non-terminal status AND
            # a run.log has begun (skip queued jobs that haven't started).
            if status and status not in _TERMINAL and (d / "run.log").exists():
                out.append(d.name)
    except Exception:
        return out
    return out


async def _supervisor() -> None:
    while True:
        try:
            for jid in _scan_running():
                ensure_monitor(jid)
        except Exception:
            pass
        await asyncio.sleep(8)


def start_supervisor() -> None:
    """Launch the always-on supervisor. Call once from api.main startup."""
    if not MONITOR_ENABLED:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    loop.create_task(_supervisor())
