"""Replay the judge against COMPLETED jobs, to score it before it gates anything.

This is not `judge_shadow.evaluate()` and must not be confused with it.

Shadow asks "would this verdict match what the gate produced on this attempt?"
and refuses when it cannot guarantee the answer — it verifies recorded
fingerprints, resumes the session prejudge opened, and records `unevaluable`
rather than guess. None of that is available here: historical jobs carry no
fingerprints, and `meta.judge` is present on ZERO of them, so there is no gate
decision to reproduce. The question a replay answers is narrower and different:

    given these artifacts, what does the judge say — and does that agree with
    what the job actually achieved?

That is measured against hand-labelled ground truth, not against `meta.status`:
status is wrong on 3 of 42 jobs in the current corpus (two false successes and
one real capture that never got promoted out of `flag_candidates`).

WHICH ATTEMPT. Jobs retry; 7 of 42 ran the sandbox twice. `<solver>.stdout` and
`<solver>.stderr` are overwritten per attempt, so they hold the LAST one, and
`events.jsonl`'s final `phase=run kind=exit` event describes that same attempt
(verified: its `stdout_bytes` equals the file's CHARACTER count — the field is
misnamed, and the two agree on all 42). `result.json["sandbox"]` is NOT a
reliable source: on 4 jobs it holds an older, failed auto-run rather than the
run the job's outcome came from. So the replay judges the last attempt and says
so.

WHAT IS NOT RECONSTRUCTIBLE. `prior_hints` (the retry-hint history postjudge is
shown) is not persisted, so a replayed postjudge sees an empty hint history
where the live gate on attempt 2 would have seen one. That is recorded per job
rather than papered over — 7 jobs are affected.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

# The runner writes these next to the job root, one pair per solver name.
_STDOUT_SUFFIX = ".stdout"
_STDERR_SUFFIX = ".stderr"


def _read(path: Path, limit: int = 4_000_000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except Exception:
        return ""


def _last_run_exit(job_dir: Path) -> dict[str, Any] | None:
    """The final `phase=run kind=exit` event — the attempt the files describe."""
    last = None
    try:
        text = (job_dir / "events.jsonl").read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if isinstance(ev, dict) and ev.get("phase") == "run" and ev.get("kind") == "exit":
            last = ev
    return last


def _solver_name(job_dir: Path) -> str | None:
    """`exploit.py` or `solver.py` — whichever this module actually ran.

    Both appear in the corpus (22 and 20 jobs). Guessing `exploit.py` would
    silently skip every rev and crypto job, which is most of the corpus.
    """
    outs = sorted(p.name for p in job_dir.glob("*" + _STDOUT_SUFFIX))
    if not outs:
        return None
    return outs[0][: -len(_STDOUT_SUFFIX)]


def replay_eligibility(job_dir: Path) -> tuple[bool, str | None]:
    """Keep hybrid chains out of the legacy scalar replay dataset.

    A hybrid parent represents the chain, while each internal child is only a
    private scalar execution unit.  Replaying either would mix a structurally
    different sample or duplicate one chain up to three times.
    """
    job_dir = Path(job_dir)
    meta: dict[str, Any] = {}
    try:
        value = json.loads((job_dir / "meta.json").read_text(encoding="utf-8"))
        if isinstance(value, dict):
            meta = value
    except Exception:
        pass
    if meta.get("module") == "hybrid":
        return False, "hybrid_parent"
    if (
        meta.get("internal") is True
        and isinstance(meta.get("parent_job_id"), str)
        and bool(meta.get("parent_job_id"))
        and isinstance(meta.get("hybrid_stage"), int)
    ):
        return False, "hybrid_child"
    return True, None


def replay_inputs(job_dir: Path) -> dict[str, Any] | None:
    """The judge's inputs for this job's last attempt, or None if unreplayable.

    Unreplayable means "no sandbox output survives", which is a real category —
    10 of 52 jobs — and belongs in the results as its own column rather than
    quietly shrinking the denominator.
    """
    job_dir = Path(job_dir)
    eligible, _reason = replay_eligibility(job_dir)
    if not eligible:
        return None
    script_rel = _solver_name(job_dir)
    if script_rel is None:
        return None

    stdout = _read(job_dir / (script_rel + _STDOUT_SUFFIX))
    stderr = _read(job_dir / (script_rel + _STDERR_SUFFIX))
    ev = _last_run_exit(job_dir) or {}

    meta: dict[str, Any] = {}
    try:
        meta = json.loads((job_dir / "meta.json").read_text(encoding="utf-8"))
    except Exception:
        pass

    res = {
        "exit_code": ev.get("exit_code"),
        "stdout": stdout,
        "stderr": stderr,
        "timeout": bool(ev.get("timeout")),
        "killed_by_supervise": bool(ev.get("killed_by_supervise")),
    }

    # Built by the runner's own helper so the replayed prompt carries the same
    # context assembly the enforce path uses. `target_note` is empty (the
    # reachability probe's note was never persisted) and `prior_hints` is None
    # (not persisted either) — both recorded below as known gaps.
    from modules._runner import _postjudge_extra
    from modules._judge import postjudge_inputs

    return {
        "job_id": job_dir.name,
        "module": meta.get("module"),
        "status": meta.get("status"),
        "script_rel": script_rel,
        "script_present": (job_dir / script_rel).is_file(),
        "target": meta.get("target_url") or None,
        "attempts": _count_attempts(job_dir),
        "exit_code": res["exit_code"],
        "timeout": res["timeout"],
        "killed_by_supervise": res["killed_by_supervise"],
        "extra_context": _postjudge_extra("", res, None),
        "postjudge": postjudge_inputs(stdout, stderr),
        "gaps": _gaps(res, job_dir),
    }


def _count_attempts(job_dir: Path) -> int:
    n = 0
    try:
        text = (job_dir / "events.jsonl").read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return 0
    for line in text.splitlines():
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if isinstance(ev, dict) and ev.get("phase") == "run" and ev.get("kind") == "exit":
            n += 1
    return n


def _gaps(res: dict, job_dir: Path) -> list[str]:
    """What this replay cannot reproduce, named rather than hidden."""
    out = []
    if res.get("exit_code") is None:
        out.append("no run/exit event — exit_code unknown")
    if _count_attempts(job_dir) > 1:
        out.append("multi-attempt job: prior_hints not persisted, so the replayed "
                   "postjudge sees an empty hint history the gate would have had")
    if not (job_dir / "report.md").is_file():
        out.append("no report.md — the deterministic self-defeat scan sees less")
    return out


def replay_job(
    job_dir: Path,
    *,
    log_sink: list[str] | None = None,
    runner: Callable[[str, dict], dict] | None = None,
) -> dict[str, Any] | None:
    """Run prejudge + postjudge over one completed job. Writes nothing to it.

    `log_sink` collects the judge's prose. It must NOT be the job's own logger:
    the review gate requires `run.log` to come out byte-identical, and the
    judge writes its issues and hints to whatever callback it is handed.
    """
    inp = replay_inputs(job_dir)
    if inp is None:
        return None
    sink = log_sink if log_sink is not None else []

    def _log(line: str) -> None:
        sink.append(str(line))

    if runner is None:
        def runner(stage: str, payload: dict) -> dict:  # noqa: ANN202
            from modules import _judge

            if stage == "prejudge":
                return _judge.prejudge_script(
                    Path(job_dir), payload["script_rel"], payload.get("target"),
                    _log, job_id=payload["job_id"],
                )
            return _judge.postjudge_run(
                Path(job_dir), payload["script_rel"],
                int(payload.get("exit_code") or 0),
                payload["postjudge"]["stdout_tail"],
                payload["postjudge"]["stderr_tail"],
                _log, job_id=payload["job_id"],
                extra_context=payload.get("extra_context") or "",
                flag_shapes=payload["postjudge"].get("flag_shapes"),
            )

    out: dict[str, Any] = dict(inp)
    out["prejudge"] = _safe(runner, "prejudge", inp)
    out["postjudge_verdict"] = _safe(runner, "postjudge", inp)
    out["judge_log"] = sink[-200:]
    return out


def _safe(runner, stage: str, payload: dict) -> dict:
    try:
        v = runner(stage, payload)
        return v if isinstance(v, dict) else {"error": f"non-dict verdict: {type(v).__name__}"}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
