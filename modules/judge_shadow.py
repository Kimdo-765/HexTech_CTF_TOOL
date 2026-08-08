"""Shadow judge — record what the judge WOULD have said, change nothing.

The point of shadow mode is to measure a cross-provider judge against real
jobs before letting it gate anything, and the measurement is worthless if
turning it on changes the thing being measured. Two ways that happens, and
both are handled here rather than left to discipline:

  * **Latency.** prejudge / supervise / postjudge sit inside the auto_run
    cycle. A judge call added there lengthens every run, so a shadow job and
    a control job are no longer comparable, and supervise's stall watchdog is
    timing something different from what it times today. Shadow therefore
    records the INPUTS during the run — a file append, no model call — and
    the verdicts are produced afterwards, out of band.

  * **The flag scanner.** Judge prose has been scraped as a job's flag before
    (job a15ff70a6ed5: the judge wrote an abbreviated `DH{...}` into a
    prejudge issue and it landed in meta.flags[0]). `_NARRATIVE_FLAG_SOURCES`
    is an explicit allowlist and `run.log` was removed from it in 2026-07,
    so a NEW file is safe by construction — but only as long as nobody adds
    it. `scripts/test_shadow_judge.py` pins that.

Shadow gates NOTHING. Not the sandbox ship-block, not the supervise kill, not
the postjudge retry. A run in shadow mode must produce byte-identical
execution to the same run with the judge off, which is what makes the
comparison against the recorded outcome meaningful.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SHADOW_FILENAME = "judge_shadow.jsonl"

# Inputs are capped hard. This file is written during a live run; an unbounded
# stdout tail here would turn an observability feature into a disk-usage one.
_MAX_FIELD_CHARS = 8_000

_lock = threading.Lock()


def _jobs_dir() -> Path:
    return Path(os.environ.get("DATA_DIR", "/data")) / "jobs"


def shadow_path(job_id: str) -> Path:
    return _jobs_dir() / Path(job_id).name / SHADOW_FILENAME


def _clip(value: Any) -> Any:
    if isinstance(value, str) and len(value) > _MAX_FIELD_CHARS:
        return value[:_MAX_FIELD_CHARS] + f"…[clipped {len(value)} chars]"
    return value


def record_input(job_id: str, stage: str, inputs: dict) -> dict | None:
    """Append one stage's INPUTS. No model is called; this must stay cheap.

    Returns the written record, or None if it could not be written — a shadow
    that fails to record is a lost measurement, never a failed run.
    """
    try:
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "kind": "input",
            "stage": str(stage),
            "inputs": {str(k): _clip(v) for k, v in (inputs or {}).items()},
        }
        path = shadow_path(job_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with _lock:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec
    except Exception:
        return None


def record_verdict(job_id: str, stage: str, verdict: dict, **extra) -> dict | None:
    """Append one stage's verdict, produced out of band after the run."""
    try:
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "kind": "verdict",
            "stage": str(stage),
            "verdict": verdict,
        }
        for k, v in extra.items():
            if v is not None:
                rec[str(k)] = _clip(v)
        path = shadow_path(job_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with _lock:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec
    except Exception:
        return None


def read_shadow(job_id: str) -> list[dict[str, Any]]:
    """Every shadow record for a job, oldest first. Bad lines are skipped."""
    out: list[dict[str, Any]] = []
    try:
        text = shadow_path(job_id).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def pending_inputs(job_id: str) -> list[dict[str, Any]]:
    """Recorded inputs that have no verdict yet, in order.

    Matched by (stage, ordinal) so a repeated stage — supervise fires more
    than once — is evaluated once per firing rather than once per stage.
    """
    seen: dict[str, int] = {}
    inputs: list[tuple[str, int, dict]] = []
    done: set[tuple[str, int]] = set()
    for rec in read_shadow(job_id):
        stage = str(rec.get("stage") or "")
        if rec.get("kind") == "input":
            n = seen.get(("i", stage), 0)
            seen[("i", stage)] = n + 1
            inputs.append((stage, n, rec))
        elif rec.get("kind") == "verdict":
            n = seen.get(("v", stage), 0)
            seen[("v", stage)] = n + 1
            done.add((stage, n))
    return [rec for stage, n, rec in inputs if (stage, n) not in done]


def evaluate(
    job_id: str,
    job_dir: Path,
    log_fn: Callable[[str], None],
    *,
    runner: Callable[[str, dict], dict] | None = None,
) -> int:
    """Produce verdicts for the recorded inputs, AFTER the run.

    Returns how many were evaluated. Best-effort throughout: a shadow that
    cannot be evaluated is a measurement nobody gets, not a job that fails.

    `runner` is injectable so the evaluation can be tested without a model.
    """
    pend = pending_inputs(job_id)
    if not pend:
        return 0

    if runner is None:
        def runner(stage: str, inputs: dict) -> dict:  # noqa: ANN202
            from modules import _judge

            script_rel = str(inputs.get("script_rel") or "exploit.py")
            if stage == "prejudge":
                return _judge.prejudge_script(
                    job_dir, script_rel, inputs.get("target"), log_fn,
                    job_id=job_id,
                )
            if stage == "supervise":
                return _judge.supervise_run_once(
                    job_dir, script_rel,
                    int(inputs.get("stall_seconds") or 0),
                    inputs.get("stdout_tail") or "",
                    inputs.get("stderr_tail") or "",
                    log_fn, job_id=job_id,
                )
            return _judge.postjudge_run(
                job_dir, script_rel,
                int(inputs.get("exit_code") or 0),
                inputs.get("stdout") or "",
                inputs.get("stderr") or "",
                log_fn, job_id=job_id,
            )

    count = 0
    for rec in pend:
        stage = str(rec.get("stage") or "")
        try:
            verdict = runner(stage, rec.get("inputs") or {})
        except Exception as exc:
            verdict = {"error": f"{type(exc).__name__}: {exc}"}
        record_verdict(job_id, stage, verdict, evaluated_from=rec.get("ts"))
        count += 1
    log_fn(f"[judge] shadow: evaluated {count} recorded stage(s) out of band")
    return count


def summary(job_id: str) -> dict[str, Any]:
    """Operator-facing rollup: what shadow saw, and whether it agreed."""
    inputs = 0
    verdicts: dict[str, list[dict]] = {}
    for rec in read_shadow(job_id):
        if rec.get("kind") == "input":
            inputs += 1
        elif rec.get("kind") == "verdict":
            verdicts.setdefault(str(rec.get("stage") or ""), []).append(
                rec.get("verdict") or {}
            )
    return {
        "inputs": inputs,
        "evaluated": sum(len(v) for v in verdicts.values()),
        "by_stage": {k: len(v) for k, v in verdicts.items()},
        "would_have_blocked": any(
            v.get("ok") is False for v in verdicts.get("prejudge", [])
        ),
        "would_have_killed": any(
            v.get("action") == "kill" for v in verdicts.get("supervise", [])
        ),
        "would_have_retried": any(
            v.get("next_action") == "retry" for v in verdicts.get("postjudge", [])
        ),
    }
