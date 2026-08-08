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

    "Out of band" is literal: `attempt_sandbox_run()` does not call
    `evaluate()` at all. Calling it there — even after the container exits —
    puts the judge's latency back on the return path of every attempt, and
    attempts run in a retry loop under a wall clock. `evaluate()`'s caller is
    the replay / sweep harness, never the runner.

  * **The flag scanner.** Judge prose has been scraped as a job's flag before
    (job a15ff70a6ed5: the judge wrote an abbreviated `DH{...}` into a
    prejudge issue and it landed in meta.flags[0]). `_NARRATIVE_FLAG_SOURCES`
    is an explicit allowlist and `run.log` was removed from it in 2026-07,
    so a NEW file is safe by construction — but only as long as nobody adds
    it. `scripts/test_shadow_judge.py` pins that.

WHAT SHADOW DOES NOT SEE: supervise. That stage fires from inside
`_wait_with_supervise` under the same `enable_judge` gate, which shadow leaves
False, so a shadow job records prejudge and postjudge only. Reaching it would
mean splitting the branch that also holds `container.kill()`, and a shadow
mode that can kill is the one failure this design must not have. Read a replay
with zero supervise rows as "shadow never looked", NOT as "supervise never
fired".

Shadow gates NOTHING. Not the sandbox ship-block, not the supervise kill, not
the postjudge retry. A run in shadow mode must produce byte-identical
execution to the same run with the judge off, which is what makes the
comparison against the recorded outcome meaningful.
"""

from __future__ import annotations

import hashlib
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


# Fields whose value IS the measurement, so the generic cap must not touch
# them. `script_text` is the artifact the gate reviewed — clipping it means
# evaluating different code and never noticing. The postjudge tails are
# already bounded by the judge's own rule (8000/4000 bytes) and re-clipping
# them by a CHARACTER count would cut a byte-exact tail into a different
# string.
_UNCLIPPED_FIELDS = frozenset({
    "script_text", "stdout_tail", "stderr_tail", "extra_context",
})


def _clip(value: Any) -> Any:
    if isinstance(value, str) and len(value) > _MAX_FIELD_CHARS:
        return value[:_MAX_FIELD_CHARS] + f"…[clipped {len(value)} chars]"
    return value


def _clip_field(key: str, value: Any) -> Any:
    return value if key in _UNCLIPPED_FIELDS else _clip(value)


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
            "inputs": {str(k): _clip_field(str(k), v)
                       for k, v in (inputs or {}).items()},
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


# A script is small; the reason it is snapshotted at all is that the retry
# loop REWRITES it between attempts, so by evaluation time the path recorded
# for attempt 1 holds attempt 3's code. Its own cap, because clipping a script
# to the generic field limit would silently change what gets judged.
_MAX_SCRIPT_CHARS = 400_000

SNAPSHOT_DIRNAME = ".judge_shadow"


def script_snapshot(path: Path) -> dict:
    """Identity + contents of the script as it was AT RECORD TIME.

    `sha256` is the part that matters: it lets the evaluator ask "is the file
    still the one the gate saw?" instead of assuming it. Without this, an
    evaluation that runs after the script changed judges different code — and
    `prejudge_script` returns a silent `ok=True, severity=low` when the file
    is simply gone, so the failure looks like a clean verdict.
    """
    try:
        raw = path.read_bytes()
    except Exception:
        return {"script_sha256": None, "script_bytes": None, "script_text": None}
    text = raw.decode("utf-8", errors="replace")
    return {
        "script_sha256": hashlib.sha256(raw).hexdigest(),
        "script_bytes": len(raw),
        "script_text": text if len(text) <= _MAX_SCRIPT_CHARS else None,
    }


def _shadow_logger(job_id: str, stage: str) -> Callable[[str], None]:
    """A log sink that lands in the shadow file and NEVER in `run.log`.

    The judge writes its issues, summary and retry_hint to whatever callback
    it is handed (`_judge.py` prejudge/postjudge). In production that callback
    is `log_line(job_id, …)` — i.e. `run.log`. Handing the judge the run's own
    logger would put judge prose into the run's log the moment an evaluation
    happened, which is exactly what §8.1 forbids and what the "run.log
    unchanged" review gate measures.

    So the default evaluator hands it THIS instead. It is not a matter of
    remembering to pass the right logger: `evaluate()` gives callers no way to
    reach the judge's logger at all.
    """

    def _log(line: str) -> None:
        try:
            rec = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "kind": "log",
                "stage": str(stage),
                "line": _clip(str(line)),
            }
            path = shadow_path(job_id)
            path.parent.mkdir(parents=True, exist_ok=True)
            with _lock:
                with path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:
            pass

    return _log


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


class ArtifactChanged(RuntimeError):
    """The thing the gate judged is not the thing on disk any more."""


def _resolve_script(job_dir: Path, script_rel: str, inputs: dict) -> str:
    """Which path should the evaluator hand prejudge — and is it the right code?

    The evaluation runs long after the run, and the retry loop rewrites
    `exploit.py` between attempts. Judging whatever sits at the recorded path
    would score attempt 3's code against attempt 1's verdict, and if the file
    is gone `prejudge_script` returns a silent `ok=True, severity=low` that is
    indistinguishable from a clean review.

    So: if the file still hashes to what was recorded, judge it in place. If
    not, restore the recorded text next to it — inside the job dir, so the
    judge keeps the same cwd and the same surrounding artifacts — and judge
    that. With no snapshot to restore, refuse; a missing measurement is
    honest, a wrong one is not.
    """
    want = inputs.get("script_sha256")
    live = job_dir / script_rel
    if want:
        try:
            if hashlib.sha256(live.read_bytes()).hexdigest() == want:
                return script_rel
        except Exception:
            pass
    text = inputs.get("script_text")
    if not isinstance(text, str):
        raise ArtifactChanged(
            f"{script_rel} is not the file recorded at run time "
            f"(sha256 {str(want)[:12] or '?'}…) and no snapshot was taken"
        )
    dest = job_dir / SNAPSHOT_DIRNAME / (want or "unknown")[:16] / Path(script_rel).name
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    return str(dest.relative_to(job_dir))


def evaluate(
    job_id: str,
    job_dir: Path,
    *,
    log_fn: Callable[[str], None] | None = None,
    runner: Callable[[str, dict], dict] | None = None,
) -> int:
    """Produce verdicts for the recorded inputs, AFTER the run.

    **This is not called from the run path.** `attempt_sandbox_run()` only
    records; a synchronous evaluation there would add the judge's latency back
    onto every attempt, which is the wall-clock change §8.2 exists to prevent
    (and this project has been bitten by runner timeouts repeatedly). The
    caller is the out-of-band sweep / replay harness.

    Returns how many were evaluated. Best-effort throughout: a shadow that
    cannot be evaluated is a measurement nobody gets, not a job that fails.

    `log_fn` receives ONLY this function's own one-line summary. It is
    deliberately never forwarded to the judge — see `_shadow_logger`. `runner`
    is injectable so the evaluation can be tested without a model.
    """
    pend = pending_inputs(job_id)
    if not pend:
        return 0

    if runner is None:
        def runner(stage: str, inputs: dict) -> dict:  # noqa: ANN202
            from modules import _judge

            script_rel = str(inputs.get("script_rel") or "exploit.py")
            jlog = _shadow_logger(job_id, stage)
            if stage == "prejudge":
                script_rel = _resolve_script(job_dir, script_rel, inputs)
                return _judge.prejudge_script(
                    job_dir, script_rel, inputs.get("target"), jlog,
                    job_id=job_id,
                )
            if stage == "supervise":
                return _judge.supervise_run_once(
                    job_dir, script_rel,
                    int(inputs.get("stall_seconds") or 0),
                    inputs.get("stdout_tail") or "",
                    inputs.get("stderr_tail") or "",
                    jlog, job_id=job_id,
                )
            # The recorded TAILS, not "stdout" — postjudge truncates to the
            # last 8000/4000 bytes anyway, so passing the tail reproduces the
            # prompt byte for byte. `flag_shapes` is passed separately because
            # the placeholder override scans the FULL output, which no longer
            # exists here.
            return _judge.postjudge_run(
                job_dir, script_rel,
                int(inputs.get("exit_code") or 0),
                inputs.get("stdout_tail") or "",
                inputs.get("stderr_tail") or "",
                jlog, job_id=job_id,
                flag_shapes=inputs.get("flag_shapes"),
                # Recorded at run time by the runner, from the same helper the
                # enforce path uses. Dropping it here would judge a prompt the
                # gate never saw — no timeout note, no prior-hint history.
                extra_context=str(inputs.get("extra_context") or ""),
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
    if log_fn is not None:
        log_fn(f"[judge] shadow: evaluated {count} recorded stage(s) out of band")
    return count


def summary(job_id: str) -> dict[str, Any]:
    """Operator-facing rollup: what shadow saw, and whether it agreed.

    Every "would have" here must answer with the SAME rule the real path uses.
    `would_have_blocked` once counted any `ok=False`, but the runner only
    blocks on severity=high — low/med are advisory and the run proceeds — so
    every advisory finding was being reported as a block, and a confusion
    matrix built on that counts them as false positives.
    """
    from modules._judge import prejudge_blocks_ship

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
            prejudge_blocks_ship(v) for v in verdicts.get("prejudge", [])
        ),
        "would_have_killed": any(
            v.get("action") == "kill" for v in verdicts.get("supervise", [])
        ),
        # Normalised exactly as the auto-retry loop reads it: missing means
        # "continue", and the comparison is case-insensitive.
        "would_have_retried": any(
            str(v.get("next_action") or "continue").lower() == "retry"
            for v in verdicts.get("postjudge", [])
        ),
    }
