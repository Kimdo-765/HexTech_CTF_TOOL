"""Shared helpers for module orchestrators."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Dict  # noqa: F401

# Large prompt strings live in modules/_prompts.py (extracted to keep
# this file navigable). Re-exported here so existing references resolve.
from modules._prompts import (  # noqa: E402,F401
    mission_block,
    CTF_PREAMBLE,
    _TOOLS_BASE,
    TOOLS_WEB,
    TOOLS_PWN,
    TOOLS_REV,
    TOOLS_CRYPTO,
    TOOLS_FORENSIC,
    TOOLS_MISC,
    RECON_AGENT_PROMPT,
    JUDGE_AGENT_PROMPT,
    TRIAGE_AGENT_PROMPT,
    DEBUGGER_AGENT_PROMPT,
)

# Common CTF flag formats. The leading prefix can vary per event; cover the
# usual suspects + a generic short-prefix fallback.
FLAG_RE = re.compile(
    r"(?:FLAG|flag|CTF|ctf|HTB|htb|picoCTF|pico|DH|dreamhack|HACKTHEBOX|"
    r"BSidesCP|XCTF|KCTF|TWN|hcamp|hackcamp|samsung|N0PSctf|CCE)\{[^\s}]{1,200}\}",
    re.IGNORECASE,
)
LIBERAL_FLAG_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9_]{1,16}\{[!-~]{2,200}\}")

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
# Some trusted sources (result.json from api/jobs.py:_manual_run, callbacks.jsonl)
# embed the run's stdout as a JSON string, so the marker line's terminating
# newline becomes a literal `\n` (two chars) and the rest of the JSON (`",`
# the next key, ...) rides on the same PHYSICAL line. `[^\r\n]+` then over-
# captures `DH{...}\n",` (real job a3d4d4484233). Cut the candidate at the
# first literal escape sequence so we keep only the declared flag; raw
# stdout (real newlines) has no such sequence, so this is a no-op there.
_MARKER_ESCAPE_RE = re.compile(r"\\[nrtu\"\\]")

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
JOBS_DIR = DATA_DIR / "jobs"
# Operator-curated exploit library; mounted into worker via the
# existing ./data:/data bind-mount. Agents browse via plain Bash:
# `ls /data/exploits/`, `cat /data/exploits/<id>/report.md`.
EXPLOITS_DIR = DATA_DIR / "exploits"

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
    f = job_dir(job_id) / "run.log"
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    with f.open("a") as fp:
        fp.write(f"[{ts}] {line}\n")
    _publish(job_id, "log", {"ts": ts, "line": line})


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
    f = job_dir(job_id) / "run.log"
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    tag_part = f"[{tag}] " if tag else ""
    body = body or ""
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


_TERMINAL_STATUSES = {"finished", "failed", "no_flag", "stopped"}


_SSE_META_KEYS = {
    "status", "flag", "summary", "error", "agent_error_kind",
    "started_at", "finished_at",
}


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

    meta.update(updates)
    meta["updated_at"] = now_iso
    f.write_text(json.dumps(meta, indent=2))

    # SSE: publish only the "lifecycle" subset to avoid spamming the
    # channel with every token-counter throttle write (agent_heartbeat
    # already emits its own meta events).
    sse_payload = {k: updates[k] for k in _SSE_META_KEYS if k in updates}
    if sse_payload:
        _publish(job_id, "meta", {"status_update": sse_payload})


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
    "result.json",           # api/jobs.py:_manual_run dumps sandbox stdout into this
)

# Narrative artifacts the agent itself authored or that derive from
# its prose. These regularly contain chal-author placeholders quoted
# from `chal/run.sh` (e.g. `DH{this_is_a_flag}`) — only consult them
# as a LAST RESORT when no trusted source produced anything.
_NARRATIVE_FLAG_SOURCES = (
    "report.md",
    "run.log",
    "findings.json",         # auto-generated from report.md by REPORT phase
    "log_findings.json",
)


def scan_job_for_flags(
    job_id: str,
    extra_files: list[str] | None = None,
    *,
    sandbox_result: dict | None = None,
) -> list[str]:
    """Return real captured flags for a job.

    Two-tier scan to keep test/placeholder flags out of `meta.flags`:

      1. TRUSTED tier — files produced by the actual runner / OOB
         collector (exploit/solver stdout/stderr, callbacks.jsonl,
         summary.json, result.json). If ANY non-placeholder flag
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
    """
    jd = job_dir(job_id)

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
            out.update(FLAG_RE.findall(text))
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
                if cand:
                    out.add(cand)
        return out

    trusted_set = list(_TRUSTED_FLAG_SOURCES)
    if extra_files:
        trusted_set.extend(extra_files)

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
        return sorted(marker)

    trusted = {
        f for f in _scan(trusted_set)
        if not _is_placeholder_flag(f, trusted=True)
    }
    if trusted:
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
    if sandbox_skipped:
        return []

    narrative = {f for f in _scan(_NARRATIVE_FLAG_SOURCES) if not _is_placeholder_flag(f)}
    return sorted(narrative)


def build_exploit_library_hint(module: str, *, max_entries: int = 12) -> str:
    """Return a short paragraph nudging the agent to consult
    `/data/exploits/` when stuck on technique / leak-vector choice, or
    `""` when the library is empty or the operator has turned the hint
    off via `enable_exploit_library_hint`.

    Filtering: same-module entries only (a pwn chal sees only pwn
    exploits, etc.). Cap at `max_entries` newest entries so the prompt
    doesn't blow up on large libraries. The agent is expected to `ls
    /data/exploits/` + `cat` the relevant report.md itself — we just
    surface what's available and what each one solved.
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

    entries.sort(key=lambda m: m.get("saved_at") or "", reverse=True)
    entries = entries[:max_entries]

    lines = [
        "PRIOR-EXPLOIT LIBRARY (operator-curated) — available at "
        "`/data/exploits/` (read-only). When stuck on technique / "
        "leak-vector / chain choice, browse these and extract the "
        "PRIMITIVE NAME + version-specific gotcha. Do NOT blindly "
        "copy — re-derive that primitive in YOUR chal's context.",
        "",
        f"Entries for module `{mod_norm}` (newest first, "
        f"{len(entries)} shown):",
    ]
    for m in entries:
        eid = m.get("id") or "?"
        chal = m.get("chal_filename") or m.get("chal_name") or "?"
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
        lines.append(
            f"  • {eid}  chal={chal}  arch={arch}  glibc={glibc}  "
            f"bug={bug}  technique={technique}{tags_part}{notes_part}"
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
    # containing `%` (format) or `<...>` (metavariable) is template.
    if "%" in inner_raw:
        return True
    if "<" in inner_raw and ">" in inner_raw:
        return True
    # Raw hex with hash-typical lengths. Real CTF flags almost never
    # take the form DH{<64 raw hex chars>} — chal authors include words
    # / phrases / a leading prefix. Bare hex of canonical hash widths
    # (sha256=64, sha1=40, md5=32) is almost always a chal-internal
    # representation quoted from source / decomp / the agent's
    # crypto analysis, not a captured flag. Job 44dd25365173 leaked
    # `DH{3cbdaf66...}` as the sha256 of an unknown input that the
    # agent imagined while reading `sha256_hexdigest`. The bound is
    # narrow on purpose: 64-char hex IDs (UUIDs aren't hex-only) are
    # rare enough as legit flags that the false-negative risk is low,
    # and operators can override via `extra_files` if a chal really
    # ships a raw-hex flag.
    # Skip the hash-WIDTH heuristic for genuine run captures (trusted): a
    # real run that prints DH{<64 hex>} captured the real flag, and Dreamhack
    # flags take exactly that shape. The rule only guards NARRATIVE prose,
    # where an agent-imagined sha256 (job 44dd25365173) can appear.
    import re as _re
    if not trusted and _re.fullmatch(
        r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", inner
    ):
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
    """
    return {
        "recon": _recon_def(model),
        "judge": _judge_def(),
        "debugger": _debugger_def(model),
        "triage": _triage_def(model),
    }


def build_judge_agents(model: str | None) -> dict:
    """`agents` dict for the JUDGE's own session (orchestrator-invoked).

    Registers only `recon` — the judge can delegate to recon for heavy
    investigation, but is not allowed to invoke itself recursively.
    Recon uses the same LATEST_JUDGE_MODEL so cache prefixes line up
    between judge's own thinking and recon's responses.
    """
    return {"recon": _recon_def(model or LATEST_JUDGE_MODEL)}


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
    # recon owns WebSearch + WebFetch so main can delegate writeup
    # lookups (CTF technique research, libc release notes, …) without
    # the result body landing in main's context. Observed: d809a5187990
    # main used WebSearch 33× directly — ~200 KB of result bodies
    # accumulated in cache_read at ~$0.5/M. Routing through recon
    # keeps that in the subagent's transient context.
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
    tools = list(_AGENT_TOOLS_BY_TYPE[agent_type])
    sub_model = (
        LATEST_JUDGE_MODEL if agent_type == "judge"
        else (model or LATEST_JUDGE_MODEL)
    )
    env = {"JOB_ID": job_id, "AGENT_ROLE": agent_type}
    # Same per-job TMPDIR + terminfo silencing as main session — keeps
    # subagent Bash output clean and prevents /tmp collision when
    # concurrent jobs spawn subagents in the same container.
    sub_tmp = Path(work_dir) / "tmp"
    try:
        sub_tmp.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    _sub_tmp_str = str(sub_tmp)
    env["TMPDIR"] = _sub_tmp_str
    env["TMP"]    = _sub_tmp_str
    env["TEMP"]   = _sub_tmp_str
    env.setdefault("TERM", "xterm")
    env.setdefault("PWNLIB_NOTERM", "1")
    if extra_env:
        env.update({k: str(v) for k, v in extra_env.items()})
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
    timeout_s: int = 90,
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
    try:
        from claude_agent_sdk import ClaudeAgentOptions, query
    except Exception as e:
        log_fn(f"[report] SDK import failed ({e}); skipping report phase")
        return False

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

    options = ClaudeAgentOptions(
        system_prompt=sys_prompt,
        model=model or REPORT_PHASE_MODEL,
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
                cls = type(msg).__name__
                if cls == "AssistantMessage":
                    for block in getattr(msg, "content", []) or []:
                        if type(block).__name__ == "TextBlock":
                            accumulated += getattr(block, "text", "") or ""
                elif cls == "ResultMessage":
                    if getattr(msg, "is_error", False):
                        log_fn(f"[report] SDK ResultMessage error: "
                               f"{getattr(msg, 'result', '')[:200]}")
                        return False
    except TimeoutError:
        log_fn(f"[report] timed out after {timeout_s}s — keeping any prior "
               f"findings.json untouched")
        return False
    except Exception as e:
        log_fn(f"[report] phase crashed: {type(e).__name__}: {e}")
        # Surface infra failures (e.g. bundled claude CLI dies exit 127 from a
        # polluted worker glibc) so the job isn't a silent no_flag with
        # error=null. Stamp a DISTINCT meta field (write_meta merges, so this
        # survives run_job's final write which only touches error_kind/status).
        kind = classify_agent_error(f"{type(e).__name__}: {e}")
        if kind == "cli_infra_error":
            log_fn(
                "[report] INFRA: claude CLI spawn failed (likely worker glibc "
                "pollution from in-run lib/ld manipulation) — this no_flag is "
                "an infrastructure cascade, not a clean miss"
            )
            try:
                write_meta(job_id, report_phase_error=f"{kind}: {str(e)[:200]}")
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


async def run_pre_recon(
    *,
    job_id: str,
    work_dir,
    model: str | None,
    prompt: str,
    log_fn,
    tag: str = "pre-recon",
) -> str:
    """Run a recon subagent BEFORE main's first turn so main starts with
    the static-analysis summary already in its user_prompt. Eliminates
    main's "should I delegate?" decision (which is consistently mis-made
    in favor of direct Bash analysis, bloating main's cache_read).

    Spawned as a STANDALONE ClaudeSDKClient with ``make_standalone_options``
    — same isolation contract as `spawn_subagent` MCP, so main never
    sees recon's investigation context. Returns ONLY recon's final text
    (joined assistant TextBlocks), capped at 8 KB.

    No per-helper timeout: the job-level soft timeout (set via the
    UI / `JOB_TIMEOUT` env) bounds total wall time, and recon's own
    output budget keeps it bounded in practice. A separate pre-recon
    cap was double-counting and (on job fa6520405673) discarded a
    nearly-complete investigation when the final summary was about
    to be emitted. If recon genuinely hangs, the watchdog + user
    Stop button still apply.

    Best-effort: SDK import / unexpected crashes return whatever
    assistant text was accumulated so far (possibly empty); the
    caller falls back to the normal "main delegates as needed" flow.
    """
    try:
        from claude_agent_sdk import (
            AssistantMessage,
            ClaudeSDKClient,
            ResultMessage,
        )
    except Exception as e:
        log_fn(f"[{tag}] SDK import failed ({e}); skipping pre-recon")
        return ""

    options = make_standalone_options(
        "recon", model, work_dir, job_id,
    )
    chunks: list[str] = []
    crashed = False

    try:
        async with ClaudeSDKClient(options=options) as client:
            await client.query(prompt)
            async for msg in client.receive_response():
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
                elif isinstance(msg, ResultMessage):
                    cost = getattr(msg, "total_cost_usd", None)
                    if isinstance(cost, (int, float)) and cost:
                        log_fn(f"[{tag}] cost: ${cost:.4f}")
    except Exception as e:
        crashed = True
        log_fn(f"[{tag}] crashed: {e!r} — returning partial output")

    out = "".join(chunks).strip()
    if not out:
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
    if len(out) > 8000:
        out = out[:8000] + "\n…(truncated)"
    return out


_VALID_EFFORTS_BACKEND = frozenset(("low", "medium", "high", "max"))


def resolve_effort(meta_effort: str | None) -> str | None:
    """Resolve the per-job effort with the global Settings fallback.

    Per-job effort (saved in meta.json by api/routes/*_module.py)
    wins when set; otherwise fall back to the `claude_effort`
    Settings value; otherwise return None and let the SDK pick its
    own default (model-dependent).
    """
    from modules.settings_io import get_setting

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
    return _norm(get_setting("claude_effort"))


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
    """Build ``ClaudeAgentOptions`` for a main agent session. Selects
    isolated-subagent (MCP) vs legacy in-process (``agents=``) path
    based on ``USE_ISOLATED_SUBAGENTS`` (default ON). All four module
    analyzers (pwn / web / crypto / rev) share this builder so the
    isolation behavior is uniform.

    Args:
      base_tools: the per-module tool set (Read/Write/Bash/...) WITHOUT
        the subagent-spawn tool. The builder appends either
        ``mcp__team__spawn_subagent`` or ``Agent`` depending on the
        active path.
      summary: the main session's summary dict; passed through to the
        MCP tool so per-spawn cost + counter increments roll up.
    """
    from claude_agent_sdk import ClaudeAgentOptions

    use_isolated = os.environ.get(
        "USE_ISOLATED_SUBAGENTS", "1") != "0"
    log_fn_local = lambda s: log_line(job_id, s)
    # Strip argv-fatal control bytes before the prompt is shipped via
    # `claude --system-prompt <text>` argv. A stray `\0` in any prompt
    # constant (e.g. a Python source-literal escape like `\0` written
    # without doubling the backslash) makes execve(2) reject the
    # spawn with `ValueError: embedded null byte`, killing the
    # session before turn 1. Job d30897ee5b30 (2026-05-15) failed
    # that way after a `\0` landmine landed in pwn SYSTEM_PROMPT.
    system_prompt = sanitize_for_argv(
        system_prompt, label="main-options", log_fn=log_fn_local,
    )
    env = {"JOB_ID": job_id}
    if extra_env:
        env.update({k: str(v) for k, v in extra_env.items()})

    # Per-job scratch dir under cwd. Keeps tempfile.* / pwntools /
    # pip / pyc cache from colliding when WORKER_CONCURRENCY > 1 in
    # the same container. Bash absolute-path escapes (cd /tmp, raw
    # /tmp/foo) are addressed by the SCRATCH FILES rule in
    # CTF_PREAMBLE — env-vars only cover library calls. Cleanup is
    # implicit: job DELETE rmtree's the whole /data/jobs/<id>/.
    tmp_dir = Path(work_dir) / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    _tmp_str = str(tmp_dir)
    env["TMPDIR"] = _tmp_str
    env["TMP"]    = _tmp_str
    env["TEMP"]   = _tmp_str

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
    env.setdefault("TERM", "xterm")
    env.setdefault("PWNLIB_NOTERM", "1")

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
            # Block built-in Agent/Task (would dispatch to a general-
            # purpose subagent that shares main's Node.js heap). Also
            # block WebSearch + WebFetch — main is NOT allowed to do
            # web research directly. The recon subagent has those
            # tools instead, so the multi-KB result bodies stay in
            # recon's transient context and only a 2 KB summary lands
            # in main. Observed in d809a5187990: 33 direct WebSearch
            # calls inflated main's cache_read by ~200 KB.
            disallowed_tools=["Agent", "Task", "WebSearch", "WebFetch"],
            permission_mode="bypassPermissions",
            add_dirs=add_dirs or [],
            env=env,
            resume=resume_sid,
            fork_session=bool(resume_sid),
            mcp_servers={"team": mcp_server},
            effort=effort,
        )
        log_fn_local(
            "[orchestrator] subagent isolation: ON "
            f"(tool={spawn_tool}; Agent/Task/WebSearch/WebFetch blocked "
            "on main — delegate web research to recon)"
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
made N tool calls without using any of the /opt/scaffold/ templates.
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
      `needs_key_bypass()` for glibc >= 2.35.

  /opt/scaffold/aslr_retry.py
    — `aslr_retry(exploit_one, max_attempts=64)` for nibble-race
      chains; `expected_attempts_for(success_rate)` for sizing.

If the chal is NOT menu-shaped (e.g. single-shot ROP, custom protocol),
ignore this — but say so explicitly in report.md so the judge knows
why you skipped them. This nudge fires once per job.
"""


_TOKEN_KEYS = (
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)


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

    # Token accumulation (lock-free per-process dict). Always update
    # in-memory; flush at most once per 5s except on Result.
    updates: dict = {}
    usage = getattr(msg, "usage", None)
    msg_id = getattr(msg, "message_id", None)
    tokens = _accumulate_tokens(job_id, usage, msg_id)
    turns = _token_turns.get(job_id, 0)

    if is_result:
        cost = getattr(msg, "total_cost_usd", None)
        if isinstance(cost, (int, float)):
            updates["cost_usd"] = float(cost)
        # Result also carries the SDK's own authoritative model_usage
        # — surface alongside our running sum for cross-checking.
        model_usage = getattr(msg, "model_usage", None)
        if isinstance(model_usage, dict):
            updates["model_usage"] = model_usage

    now = _time.monotonic()
    last = _heartbeat_state.get(job_id, 0.0)
    throttled = (not is_result) and (now - last < _HEARTBEAT_MIN_INTERVAL_S)
    if throttled:
        return
    _heartbeat_state[job_id] = now

    write_meta(
        job_id,
        last_agent_event_at=datetime.now(timezone.utc).isoformat(),
        last_event_kind=kind,
        agent_tokens=tokens or None,
        agent_turns=turns or None,
        **updates,
    )

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
    if sid:
        write_meta(job_id, claude_session_id=sid)


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
        parts.append("- sage NOT in this container — write solver.sage for sage runner if needed")
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


# Approximate per-million-token prices in USD (Anthropic public pricing,
# 2026-Q2). Used as a FALLBACK when the SDK's authoritative
# `ResultMessage.total_cost_usd` never arrives — e.g. the bundled
# `claude` CLI gets SIGKILLed mid-stream before emitting the final
# accounting message, leaving meta.cost_usd at $0.00 even for runs
# that obviously spent dollars.
# Tuple shape: (input, cache_create, cache_read, output) per Mtok.
_MODEL_RATES_USD_PER_MTOK = {
    "opus":   (15.0, 18.75, 1.50, 75.0),
    "sonnet": (3.0,  3.75,  0.30, 15.0),
    "haiku":  (1.0,  1.25,  0.10, 5.0),
}


def _rates_for_model(model: str | None) -> tuple[float, float, float, float]:
    if model:
        low = model.lower()
        for needle, rates in _MODEL_RATES_USD_PER_MTOK.items():
            if needle in low:
                return rates
    # Unknown — default to opus rates (conservative upper bound so
    # the fallback never under-reports a real spend).
    return _MODEL_RATES_USD_PER_MTOK["opus"]


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


def extract_cost(claude_summary: dict | None) -> float:
    """Pull total_cost_usd out of an agent summary dict, returning 0.0 if absent.

    Preference order:
      1. summary['result']['total_cost_usd']  (authoritative — ResultMessage)
      2. summary['cost_usd']                  (mirrored by run_main_agent_session
                                               when ResultMessage was lost)
      3. estimate from summary['agent_tokens'] + summary['model']
         (last-resort fallback so SIGKILL'd runs still show a non-zero,
         estimated spend instead of $0.00).
    """
    if not isinstance(claude_summary, dict):
        return 0.0
    res = claude_summary.get("result")
    if isinstance(res, dict):
        v = res.get("total_cost_usd")
        if isinstance(v, (int, float)) and v > 0:
            return float(v)
    direct = claude_summary.get("cost_usd")
    if isinstance(direct, (int, float)) and direct > 0:
        return float(direct)
    return estimate_cost_from_tokens(
        claude_summary.get("agent_tokens"),
        claude_summary.get("model"),
    )


def format_tool_result(content: Any, is_error: bool | None = None) -> str:
    """Compact one-line preview of a tool result for the run log.

    Tool results are otherwise invisible — the agent sees them, but the
    user just sees a TOOL line followed by silence until the agent's
    next message lands. Surfacing a short preview closes that gap.
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
    cap = 300
    full_len = len(text)
    if full_len > cap:
        # Mark truncation with the actual byte counts so a downstream
        # reader (notably the retry reviewer) can tell that the chars
        # right before the marker are mid-cut, not a real terminal
        # token from the tool's output. A bare "…" was previously
        # being mistaken for evidence of a real short string in the
        # target binary (e.g. "yo…" when the truth was "your name >").
        text = (
            text[:cap]
            + f" …(preview cut: showing {cap}/{full_len} bytes; "
            "trailing chars are mid-cut, not a complete token)"
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
            # the counter (avoids double count). Both legacy `Agent`
            # and MCP `mcp__team__spawn_subagent` count the same way.
            if is_main and (
                name == "Agent" or name == "mcp__team__spawn_subagent"
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
    result with newlines preserved; subagents get the existing
    single-line preview (≤300 bytes, ' | '-joined newlines).
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
                             (flag captured · verdict==success · empty
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
        "FIX: glibc >= 2.35 adds a `key` field at offset +0x08 of "
        "every tcache chunk. Double-free aborts with `free(): double "
        "free detected in tcache 2`. Pattern: `free(victim); "
        "edit(victim, p64(0))  # zero the key via UAF; "
        "free(victim)`. The key-bypass check is helper-available in "
        "/opt/scaffold/tcache_poison.py::needs_key_bypass(). After "
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
        "the target struct, OR target the `key` field "
        "(tcache_perthread_struct + 8 * slot) which IS aligned, OR "
        "use a different primitive (large-bin / unsorted)."
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
        "sandbox has no TTY → the supervise watchdog kills it "
        "before flag exfil. Replace with explicit "
        "`p.sendline(b'cat /flag*'); print(p.recvrepeat(2.0)"
        ".decode(errors='replace'))`. Use the `if sys.stdin.isatty(): "
        "p.interactive()` guard if you want local-debug ergonomics."
    ),
    "heap.unbounded_recv": (
        "FIX: Every `recvuntil` / `recv` / `recvline` / `readuntil` "
        "MUST have an explicit `timeout=` argument. Mismatched "
        "prompts otherwise hang the supervise watchdog into a kill. "
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
) -> str:
    """Compose the user-turn body that gets injected back into main's
    SDK session after a failed sandbox run. Tells main what verdict
    came back, gives it the postjudge retry_hint verbatim, and asks
    for a corrected script. Tail of stdout/stderr is included so main
    can cross-check rather than trusting judge's summary blindly.

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
        if alternative_paths:
            diagnosis_parts.append(
                "ALTERNATIVE PATHS (try if the patch keeps failing — "
                "these were NOT exhausted by this run):"
            )
            diagnosis_parts.extend(f"  → {s}" for s in alternative_paths[:3])
        diagnosis_block = "\n".join(diagnosis_parts) + "\n"

    return (
        f"🔁 AUTO-RETRY {attempt_idx}/{cap_str} — postjudge feedback\n"
        f"\n"
        f"⚠️ THE SANDBOX RUN HAS ALREADY COMPLETED. This message IS the "
        f"postjudge verdict — do NOT respond with 'awaiting sandbox' "
        f"or 'I'll stop the loop here / reschedule'. The orchestrator "
        f"is in the auto-retry loop NOW. Either (a) modify "
        f"./{script_filename} per the retry hint and end your turn so "
        f"the orchestrator can re-execute it, or (b) explicitly "
        f"`Bash(rm -f ./{script_filename})` if you're giving up. "
        f"Doing neither — returning without an edit — makes the "
        f"orchestrator re-run the SAME unchanged script for a "
        f"guaranteed-fail second sandbox spin (wasted ~$2-5 of "
        f"cache_creation). The detection added 2026-05-25 will "
        f"actually halt that case mid-flight, so just respond and edit.\n"
        f"\n"
        f"The orchestrator just executed `{script_filename}` in the runner "
        f"sandbox. Result:\n"
        f"  · exit_code: {exit_code}\n"
        f"  · postjudge verdict: {verdict}\n"
        f"  · postjudge summary: {summary or '(empty)'}\n"
        f"  · judge next_action: {next_action} "
        f"(judge endorses this retry — keep iterating)\n"
        + (f"  · failure_code: {failure_code}\n" if failure_code else "")
        + f"{timeout_marker}"
        f"{fix_preamble}"
        f"{diagnosis_block}"
        f"\n"
        f"=== retry hint (from postjudge — apply this) ===\n"
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
        f"  2. Apply the fix from the retry hint. If you disagree with the\n"
        f"     hint after seeing the tails, fix what you actually believe\n"
        f"     is broken — but say so explicitly.\n"
        f"  3. Re-run the JUDGE GATE (peer subagent) on the patched script\n"
        f"     before ending your turn. The orchestrator will rerun the\n"
        f"     sandbox automatically after you finish.\n"
        f"  4. Keep the artifact path stable (`./{script_filename}` and\n"
        f"     `./report.md`).\n"
        f"  5. If you cannot fix this (genuinely stuck or the bug class is\n"
        f"     beyond the available primitive), say so and `Bash(rm -f "
        f"./{script_filename})` so the orchestrator skips the rerun.\n"
    )


def _pick_present_artifact(
    work_dir: Path, names: tuple[str, ...],
) -> str | None:
    for n in names:
        if (work_dir / n).is_file():
            return n
    return None


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


WHY_STOPPED_FILENAME = "WHY_STOPPED.md"


_STOP_KIND_HEADERS = {
    "judge_stop": "Judge ruled the chain unrecoverable",
    "budget_exhausted": "Auto-retry budget exhausted",
    "no_hint": "Postjudge produced no actionable retry hint",
    "agent_error": "Main agent session error",
    "retry_hint_ignored": (
        "Main ignored postjudge retry_hint — script unchanged"
    ),
}


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
            f"**Attempt**: {attempt_idx} / {cap_str}",
            f"**When**: {when}",
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
                retry_hint[:2000],
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
                "new lead). The retry forks the prior SDK session so "
                "main keeps its context, but starts with your hint as "
                "the next user turn.",
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
                "2. **Check worker container health**: `docker logs "
                "hextech_ctf_tool-worker-1 --tail 100`.",
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


def write_fallback_artifacts(work_dir: Path, log_fn) -> None:
    """Drop a probe-only exploit.py + report.md when main's session
    ends WITHOUT producing them. Best-effort: any write error is logged
    and swallowed (the caller's downstream code handles "no artifact"
    fine — this is purely an upgrade to "no_flag / partial" status
    instead of "failed").
    """
    try:
        ex = work_dir / "exploit.py"
        if not ex.is_file():
            ex.write_text(_FALLBACK_EXPLOIT_TEMPLATE)
            log_fn(f"[orchestrator] wrote fallback ./exploit.py ({len(_FALLBACK_EXPLOIT_TEMPLATE)} B)")
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
            if est > 0 and not summary.get("cost_usd"):
                summary["cost_usd"] = est
                log_fn(
                    f"COST_FALLBACK [{label}]: ResultMessage missing; "
                    f"estimated ${est:.4f} from "
                    f"{sum(tokens_now.values())} accumulated tokens"
                )
        except Exception:
            pass

    from claude_agent_sdk import (
        AssistantMessage, ClaudeSDKClient, ResultMessage, UserMessage,
    )
    import anyio

    max_retries = auto_retry_max() if auto_run else 0

    last_sandbox: dict | None = None
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

    async with ClaudeSDKClient(options=options) as client:
        await client.query(initial_prompt)

        # max_retries semantics: 0 = disabled, N>0 = cap, -1 = unlimited.
        cap_str = "∞" if max_retries < 0 else str(max_retries)
        attempt = 0  # 0 = initial run; 1..N = postjudge-driven retries
        while True:
            log_fn(f"Main session turn (attempt {attempt}/{cap_str})")
            try:
                async for msg in client.receive_response():
                    capture_session_id(msg, job_id)
                    agent_heartbeat(job_id, msg)
                    if isinstance(msg, AssistantMessage):
                        summary["messages"] = summary.get("messages", 0) + 1
                        log_assistant_blocks(job_id, msg, summary)
                    elif isinstance(msg, UserMessage):
                        log_user_blocks(job_id, msg)
                    _maybe_soft_eject(summary.get("tool_calls", 0))
                    _maybe_scaffold_nudge(summary.get("tool_calls", 0))
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
                        }
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
                                work_dir, log_fn,
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
                            summary["agent_error"] = (
                                "SDK ResultMessage is_error (transport "
                                "failure / request timeout); no artifact"
                            )
                            summary["agent_error_kind"] = "agent_error"
                            _snapshot_cost(summary, "RESULT_IS_ERROR")
                            if not _pick_present_artifact(
                                    work_dir, artifact_names):
                                write_fallback_artifacts(work_dir, log_fn)
                                summary["fallback_artifact_used"] = True
                                log_fn(
                                    "[orchestrator] ResultMessage is_error "
                                    "with no artifact — wrote fallback so "
                                    "sandbox still runs (job ends no_flag "
                                    "with error_kind set, not a silent "
                                    "zero-artifact run)"
                                )
            except Exception as e:
                msg_text = str(e)
                kind = classify_agent_error(msg_text)
                summary["agent_error"] = msg_text
                summary["agent_error_kind"] = kind
                # SIGKILL on the bundled `claude` CLI would surface here
                # as `Command failed with exit code -9`. Historically
                # every observed exit -9 was a fratricide from the
                # debugger subagent's `pkill -f "./prob"` matching its
                # own cmdline (fixed via pkill -x, see commit 15a5f85);
                # real cgroup OOM has not been observed. Classify as
                # "killed" if we get an unknown -9; the sandbox path
                # below still picks up whatever main managed to write.
                if kind in (None, "unknown") and (
                    "exit code -9" in msg_text or "killed" in msg_text.lower()
                ):
                    summary["agent_error_kind"] = "killed"
                log_fn(f"AGENT_ERROR ({summary['agent_error_kind']}): {msg_text[:400]}")
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
                    write_fallback_artifacts(work_dir, log_fn)
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
                await client.query(SCAFFOLD_MISSING_USER_TURN)
                continue

            # ---- Decide whether to feed postjudge back to main ----
            if not auto_run or sandbox_runner is None:
                return last_sandbox
            picked = _pick_present_artifact(work_dir, artifact_names)
            if not picked:
                # Main produced nothing this round — no script to run.
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
                last_sandbox = await anyio.to_thread.run_sync(sandbox_runner, picked)
            except Exception as e:
                log_fn(f"[orchestrator] sandbox runner crashed: {e}")
                return last_sandbox

            # Did we capture a flag this turn? `last_sandbox` is the
            # judge_aborted-aware sentinel; pass it so the orchestrator
            # loop applies the same NARRATIVE-skip gate as the final
            # analyzer scan (see scan_job_for_flags docstring + job
            # 44dd25365173 incident).
            flags_now = scan_job_for_flags(job_id, sandbox_result=last_sandbox)
            judge_out = ((last_sandbox or {}).get("judge") or {})
            verdict = judge_out.get("verdict")
            # Accumulate the just-emitted retry_hint so the NEXT
            # postjudge call sees prior history and can decide
            # next_action=stop when its new hint would repeat.
            _hint_just_now = (judge_out.get("retry_hint") or "").strip()
            if _hint_just_now:
                summary["judge_hints"].append(_hint_just_now)
            if flags_now or verdict == "success":
                log_fn(
                    f"[orchestrator] auto-run turn {attempt} succeeded "
                    f"(flags={len(flags_now)}, verdict={verdict}) — exiting loop"
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
            if next_action == "stop":
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
            # — only natural exit conditions (flag / verdict==success /
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
                if _pj_issues and _pj_sig and _pj_sig not in _seen and _n < 3:
                    _seen.append(_pj_sig)
                    summary["prejudge_block_redirects"] = _n + 1
                    retry_hint = (
                        "prejudge BLOCKED ship — the sandbox never ran. Fix "
                        "THESE concrete issues and re-ship the SAME script "
                        "(do NOT start over):\n- " + "\n- ".join(_pj_issues[:6])
                        + "\n\nIf an issue says a primitive is 'untestable "
                        "locally' (vsyscall / CET / kernel — the worker "
                        "physically cannot test it), do NOT abandon it: the run "
                        "is now allowed to probe the remote. Either keep it AND "
                        "add a fallback that does not depend on the unverifiable "
                        "feature, or convert to a leak-first design that reads "
                        "ground truth from the target."
                    )
                    # Synthesize a judge dict so the existing inject path
                    # (_format_postjudge_user_turn) carries this hint verbatim.
                    last_sandbox["judge"] = {
                        "verdict": "prejudge_blocked",
                        "next_action": "continue",
                        "retry_hint": retry_hint,
                        "summary": "prejudge ship-block — fix the issues, re-ship",
                    }
                    log_fn(
                        f"[orchestrator] prejudge BLOCKED — redirecting its "
                        f"{len(_pj_issues)} issue(s) into a fix-and-retry turn "
                        f"(redirect {_n + 1}/3) instead of dead-ending"
                    )
                else:
                    log_fn(
                        "[orchestrator] prejudge BLOCKED with no new actionable "
                        "issues (repeat / cap reached) — stopping auto-retry"
                    )
            if not retry_hint:
                log_fn(
                    f"[orchestrator] postjudge produced no retry_hint "
                    f"(verdict={verdict}, next_action={next_action}) — "
                    f"stopping auto-retry"
                )
                write_why_stopped(
                    work_dir,
                    stop_kind="no_hint",
                    attempt_idx=attempt,
                    max_attempts=max_retries,
                    judge_out=judge_out,
                    sandbox_result=last_sandbox,
                    summary=summary,
                    log_fn=log_fn,
                )
                return last_sandbox

            # Inject postjudge feedback as next user turn and loop.
            attempt += 1
            write_meta(job_id, stage=f"auto-retry-{attempt}")
            feedback = _format_postjudge_user_turn(
                attempt_idx=attempt,
                max_attempts=max_retries,
                script_filename=picked,
                sandbox_result=last_sandbox or {},
            )
            log_fn(
                f"[orchestrator] injecting postjudge feedback as new user "
                f"turn (attempt {attempt}/{max_retries}, verdict={verdict})"
            )
            await client.query(feedback)
            # Capture script SHA so the next iteration can detect
            # "main returned without applying the fix" and skip the
            # guaranteed-fail re-run (see SHA-unchanged ship gate above).
            script_sha_at_last_inject["sha"] = _script_sha(work_dir / picked)
            script_sha_at_last_inject["script"] = picked
            # loop continues; receive_response on next iteration

    # unreachable; kept for type-checkers
    return last_sandbox


async def soft_timeout_watchdog(job_id: str, soft_timeout_s: int) -> None:
    """Sleep until the user-set soft timeout elapses, then mark the job as
    `awaiting_decision` in meta and log a single line. The agent loop is
    NOT interrupted — this is a courtesy notification only. The caller is
    expected to cancel this task when the agent finishes normally.

    The user can then click "Continue running" or "Stop now" in the UI;
    the API endpoints handle each side. If the user picks 'continue', the
    watchdog stays cancelled — we don't pester them again — but the worker
    keeps going until completion or until the RQ hard-kill ceiling.
    """
    if soft_timeout_s is None or soft_timeout_s <= 0:
        return
    try:
        await asyncio.sleep(soft_timeout_s)
    except asyncio.CancelledError:
        return
    log_line(
        job_id,
        f"⏰ Soft timeout reached ({soft_timeout_s}s) — waiting for user "
        f"decision (continue / stop). The agent is still running.",
    )
    write_meta(
        job_id,
        awaiting_decision=True,
        decision_at=datetime.now(timezone.utc).isoformat(),
        soft_timeout_s=soft_timeout_s,
    )
