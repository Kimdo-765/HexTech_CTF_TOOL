"""Structured per-job event timeline — `<job>/events.jsonl`.

Why this exists
---------------
`run.log` is a human tail: a long pwn job emits ~1000 lines, ~96% of them
`[main] TOOL`/`TOOL_RESULT` echo (measured on job 9c3198982722: 991/1035).
Reconstructing "what phase was this job in, and what did each judge decide"
means grepping that noise by hand — exactly the pain hit while monitoring
8aff38ac18ac / 9c3198982722 (2026-05-26).

`events.jsonl` is the machine view: one JSON object per line, emitted only
at phase transitions, never on tool echo. It is ADDITIVE — `run.log` and its
SSE publish are untouched, so nothing downstream breaks.

Event schema (locked — append fields, never rename the top three)
-----------------------------------------------------------------
    {"ts": <iso8601 UTC>, "phase": <PHASES>, "kind": <str>, **fields}

`phase` is one of `PHASES`. `kind` is a short verb for the transition
(e.g. "verdict", "blocked", "exit"). Everything else (verdict, severity,
exit_code, cost, ...) goes in `**fields`. If an emit doesn't fit a phase,
it is being emitted at the wrong point — do not widen the enum to fit.

Coverage (v1)
-------------
Wired at the judge lifecycle inside `_runner.attempt_sandbox_run`
(prejudge / run / postjudge) — module-agnostic, so pwn/web/crypto/rev/misc/
forensic all get it for free whenever they run a sandbox — plus the pwn
module's terminal status. Other modules' module-specific events
(recon spawn, report phase) are NOT wired yet; add them as needed.

This module is a stdlib-only leaf: it imports nothing from `modules/` so it
can be reused from api/ and scripts/ without circular-import risk.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _jobs_dir() -> Path:
    """Jobs root, resolved at call time so a `DATA_DIR` override (tests,
    local dev) is honoured. Mirrors `modules._common` / `api.storage`
    without importing them — keeps this module a leaf."""
    return Path(os.environ.get("DATA_DIR", "/data")) / "jobs"

PHASES = frozenset({
    "autoboot",
    "preflight",
    "recon",
    "prejudge",
    "run",
    "postjudge",
    "report",
    "terminal",
})


def _events_path(job_id: str) -> Path:
    return _jobs_dir() / Path(job_id).name / "events.jsonl"


def emit_event(job_id: str, phase: str, kind: str, **fields: Any) -> None:
    """Append one structured event to `<job>/events.jsonl`.

    Best-effort: any failure (bad job_id, unwritable dir, unserialisable
    field) is swallowed — observability must never break the pipeline it
    observes. `phase` outside `PHASES` is still written but tagged so the
    miswiring is visible rather than silently dropped.
    """
    try:
        rec: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "phase": phase if phase in PHASES else f"?{phase}",
            "kind": kind,
        }
        for k, v in fields.items():
            rec[k] = v
        p = _events_path(job_id)
        if not p.parent.is_dir():
            return
        line = json.dumps(rec, default=str, ensure_ascii=False)
        with p.open("a") as fp:
            fp.write(line + "\n")
    except Exception:
        return


def read_events(job_id: str) -> list[dict]:
    """Return all events for a job, oldest first. Empty list if none.

    Deliberately dumb — one object per non-blank line. For filtering or
    pretty-printing, pipe the file through `jq`; this is not a query API.
    """
    p = _events_path(job_id)
    if not p.is_file():
        return []
    out: list[dict] = []
    try:
        for line in p.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except OSError:
        return []
    return out
