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
import uuid
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
            # Identity, not position. Completion used to be matched by
            # (stage, ordinal), so two evaluators that both answered ordinal 0
            # produced two verdicts — and the SECOND one silently marked the
            # next input as done. That input was then never evaluated and
            # nothing said so.
            "id": uuid.uuid4().hex,
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


# The script is kept as EVIDENCE, never as something to restore. Its own cap
# so the generic field limit cannot silently shorten it.
_MAX_SCRIPT_CHARS = 400_000


def _digest(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return None


def postjudge_fingerprint(job_dir: Path, script_rel: str) -> dict:
    """The files a DELAYED postjudge could still read, hashed at record time.

    The postjudge prompt says so in as many words: "You may Read the script +
    std{out,err} files under `{cwd}`". The runner writes those to fixed names
    and overwrites them on the next attempt, so an evaluation that happens
    afterwards can read attempt 3's crash output while being handed attempt
    1's recorded tail — and answer about neither.

    Same rule as prejudge: hash them, and refuse to evaluate if they moved.
    """
    return {
        "script_sha256": _digest(job_dir / script_rel),
        "stdout_file_sha256": _digest(job_dir / f"{script_rel}.stdout"),
        "stderr_file_sha256": _digest(job_dir / f"{script_rel}.stderr"),
    }


def prejudge_fingerprint(job_dir: Path, script_rel: str) -> dict:
    """Every artifact prejudge reads, hashed as it was AT RECORD TIME.

    Not just the script. `deterministic_prejudge` scans `work/report.md` for
    self-defeat admissions and validates `work/chain.json`, and either can
    force severity=high on its own. Fingerprinting the script alone let a
    later `report.md` flip an evaluation that was supposed to reproduce the
    gate's own verdict.

    Hashes, not contents, because a recorded artifact CANNOT be put back
    faithfully: the prejudge prompt embeds both `script_rel` and the absolute
    `script_path`, so judging a restored copy under some other path is a
    different prompt — and re-encoding bytes through text does not even
    round-trip for a non-UTF-8 source. The evaluator's job is to notice that
    the inputs moved and say so, not to reconstruct them.

    `script_text` rides along as evidence for the operator. It is present only
    when the bytes are STRICT UTF-8; a replacement-decoded copy would be a
    different file wearing the same hash.
    """
    work = job_dir / "work" if (job_dir / "work").is_dir() else job_dir
    script = job_dir / script_rel
    try:
        raw = script.read_bytes()
    except Exception:
        raw = None
    try:
        text = raw.decode("utf-8") if raw is not None else None
    except UnicodeDecodeError:
        text = None
    return {
        "script_sha256": _digest(script),
        "script_bytes": len(raw) if raw is not None else None,
        "script_text": text if (text is not None and len(text) <= _MAX_SCRIPT_CHARS) else None,
        # Companion artifacts the deterministic gates read. `None` means
        # "absent at record time", which is itself part of the input.
        "report_sha256": _digest(work / "report.md"),
        "chain_sha256": _digest(work / "chain.json"),
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

    Matched by the input's own `id`. Position was the obvious thing to match
    on and it is wrong under concurrency: two evaluators that both answer the
    first `supervise` firing write two verdicts, and the extra one marks the
    SECOND firing done — an input that is then never evaluated, silently.
    Identity makes a duplicate verdict merely redundant instead of destructive.

    Records written before ids existed fall back to (stage, ordinal), so an
    older shadow file still reads correctly.
    """
    inputs: list[tuple[str, int, dict]] = []
    legacy_seen: dict[tuple[str, str], int] = {}
    answered: set[str] = set()
    legacy_done: set[tuple[str, int]] = set()
    for rec in read_shadow(job_id):
        stage = str(rec.get("stage") or "")
        if rec.get("kind") == "input":
            n = legacy_seen.get(("i", stage), 0)
            legacy_seen[("i", stage)] = n + 1
            inputs.append((stage, n, rec))
        elif rec.get("kind") == "verdict":
            n = legacy_seen.get(("v", stage), 0)
            legacy_seen[("v", stage)] = n + 1
            ans = rec.get("answers")
            if ans:
                answered.add(str(ans))
            else:
                legacy_done.add((stage, n))
    out = []
    for stage, n, rec in inputs:
        rid = rec.get("id")
        if rid:
            if str(rid) not in answered:
                out.append(rec)
        elif (stage, n) not in legacy_done:
            out.append(rec)
    return out


def _cycle_state(job_id: str) -> tuple[set[str], dict[str, str]]:
    """Per CYCLE: which ones recorded a prejudge, and which had it refused.

    Per cycle, not per job. A job retries, and each attempt opens its own
    judge session — so "was my prerequisite evaluated?" is a question about
    the attempt. Keyed job-wide, attempt 1's refusal silenced attempt 2's
    perfectly healthy postjudge and the rollup called both unevaluable.

    Read from the file rather than kept in a local, so a resumed `evaluate()`
    reaches the same conclusion as the first one. Records written before
    cycle ids existed all carry `""`, which collapses to the old job-wide
    behaviour — the honest reading, since they cannot be told apart.

    Returns (cycles that recorded a prejudge INPUT, {cycle: why it was refused},
    {cycle: the session id its prejudge opened}).
    """
    stage_of: dict[str, tuple[str, str]] = {}       # input id -> (cycle, stage)
    have_prejudge: set[str] = set()
    refused: dict[str, str] = {}
    opened_session: dict[str, str] = {}
    answered: set[str] = set()
    for rec in read_shadow(job_id):
        if rec.get("kind") == "input":
            cyc = str((rec.get("inputs") or {}).get("cycle_id") or "")
            stage = str(rec.get("stage") or "")
            stage_of[str(rec.get("id") or "")] = (cyc, stage)
            if stage == "prejudge":
                have_prejudge.add(cyc)
        elif rec.get("kind") == "verdict":
            ans = str(rec.get("answers") or "")
            # FIRST answer wins, like everywhere else that reads this file. Two
            # evaluators can both answer one input; if the redundant one is a
            # refusal, taking it blocked a cycle whose prejudge the rollup
            # simultaneously reported as measured.
            if ans:
                if ans in answered:
                    continue
                answered.add(ans)
            cyc, stage = stage_of.get(ans, ("", ""))
            why = (rec.get("verdict") or {}).get("unevaluable")
            if stage == "prejudge":
                if why:
                    refused[cyc] = str(why)
                elif rec.get("opened_session"):
                    opened_session[cyc] = str(rec.get("opened_session"))
    return have_prejudge, refused, opened_session


def _session_id(job_id: str) -> str | None:
    """The judge session THIS process holds for `job_id`, if any."""
    try:
        from modules._judge import _recall_sid

        return _recall_sid(job_id)
    except Exception:
        return None


def _forget_session(job_id: str) -> None:
    """Drop the job's judge session, so the next prejudge starts clean.

    The map is keyed by job, not by cycle, and `_remember_sid(job, None, p)`
    keeps an existing id while updating only the provider. So a sid left by
    cycle A survived into cycle B and made B's prejudge report that it had
    opened a session it never opened. Clearing before each cycle's prejudge
    makes the provenance per-cycle by construction rather than by inference,
    and mirrors what the enforce path already does per attempt.
    """
    try:
        from modules._judge import _forget_sid

        _forget_sid(job_id)
    except Exception:
        pass


def _mark_model_failure(verdict: dict) -> dict:
    """A stage whose model never answered is not a measurement either.

    Every stage normalises a failed turn into a permissive default so the RUN
    is not blocked — postjudge into `verdict="unknown"`, prejudge into
    `ok=True, severity=low`. That is right for the gate and wrong for anyone
    counting: `auth_error` came back as an `unknown` opinion and landed in the
    evaluated column. `_with_failover` now carries `error_kind` out to the
    public verdict, so the distinction is available here.
    """
    if not isinstance(verdict, dict) or verdict.get("unevaluable"):
        return verdict
    kind = verdict.get("error_kind")
    if not kind:
        return verdict
    out = dict(verdict)
    out["unevaluable"] = f"the judge never answered: {kind}"
    return out


class ArtifactChanged(RuntimeError):
    """The inputs the gate judged are not the inputs on disk any more."""


def _require_unchanged(job_dir: Path, script_rel: str, inputs: dict) -> None:
    """Refuse to evaluate unless every recorded input still matches.

    The evaluation runs long after the run, and the retry loop rewrites
    `exploit.py` between attempts while `report.md` and `chain.json` keep
    moving too. Judging whatever is on disk now would score later artifacts
    against an earlier run's verdict — and when the script is simply gone,
    `prejudge_script` returns `ok=True, severity=low`, which is
    indistinguishable from a clean review.

    Restoring the recorded bytes was tried and abandoned: the prompt embeds
    the script's path, so a copy under any other name is a different prompt,
    and the companions cannot be restored at all without rewriting the job's
    live artifacts. An unevaluable measurement that says which artifact moved
    is worth more than a confident one about the wrong inputs.
    """
    work = job_dir / "work" if (job_dir / "work").is_dir() else job_dir
    for label, path, key in (
        (script_rel, job_dir / script_rel, "script_sha256"),
        ("work/report.md", work / "report.md", "report_sha256"),
        ("work/chain.json", work / "chain.json", "chain_sha256"),
        (f"{script_rel}.stdout", job_dir / f"{script_rel}.stdout", "stdout_file_sha256"),
        (f"{script_rel}.stderr", job_dir / f"{script_rel}.stderr", "stderr_file_sha256"),
    ):
        if key not in inputs:
            continue          # recorded before this field existed; nothing to check
        want, have = inputs.get(key), _digest(path)
        if want != have:
            raise ArtifactChanged(
                f"{label} changed since the run "
                f"(recorded {str(want)[:12] or 'absent'}, now {str(have)[:12] or 'absent'})"
            )


def evaluate(
    job_id: str,
    job_dir: Path,
    *,
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

    There is deliberately NO `log_fn`. It used to take one for its own summary
    line, and production hands around `log_line(job_id, …)` — which appends to
    `run.log`. One line is still a changed `run.log`, and "shadow leaves
    run.log byte-identical" is a review gate, not a preference. The summary
    goes to the shadow file like everything else. `runner` is injectable so
    the evaluation can be tested without a model.
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
                _require_unchanged(job_dir, script_rel, inputs)
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
            # Same rule as prejudge: the delayed postjudge may Read the
            # script and the std{out,err} files from cwd, and the next attempt
            # overwrites all three under fixed names.
            _require_unchanged(job_dir, script_rel, inputs)
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

    # A stage that could not be evaluated blocks the ones that depend on it.
    # The real cycle is pre -> (supervise) -> post sharing ONE judge session:
    # supervise and postjudge resume the id prejudge opened, so a postjudge
    # evaluated without a prejudge has none of the context the gate's
    # postjudge had. Judging it anyway produces a number that looks like a
    # measurement of the gate and is not one.
    have_prejudge, refused, opened_session = _cycle_state(job_id)
    count = unevaluable = 0
    for rec in pend:
        stage = str(rec.get("stage") or "")
        inputs = rec.get("inputs") or {}
        cyc = str(inputs.get("cycle_id") or "")
        why = None
        if stage != "prejudge":
            if cyc not in have_prejudge:
                # Nothing to resume. Recording is best-effort per stage, so a
                # prejudge append can be lost while its postjudge lands; the
                # old check looked for a REFUSED prejudge and saw nothing,
                # which reads identically to "the prerequisite was fine".
                why = "no prejudge was recorded for this cycle"
            elif cyc in refused:
                why = f"prejudge for this cycle was unevaluable: {refused[cyc]}"
            elif cyc in opened_session and _session_id(job_id) != opened_session[cyc]:
                # The prerequisite was checked against the FILE, but the thing
                # it exists to guarantee — that this stage resumes the session
                # prejudge opened — lives in `_judge._session_ids`, a dict in
                # THIS process. A sweep that evaluated the prejudge earlier, in
                # another process or a run that died partway, satisfies every
                # file condition and then judges in a brand-new session with
                # none of prejudge's warnings. The enforce path cannot reach
                # this state: it runs both stages in one process, in one
                # try/finally.
                why = ("the judge session prejudge opened is not available in "
                       "this process — evaluate the whole cycle in one sweep")
        if why:
            verdict = {"unevaluable": why}
        else:
            if stage == "prejudge":
                # Clear the session FIRST, exactly as the enforce path does per
                # attempt (attempt_sandbox_run's `finally: _forget_sid`). A sid
                # left by an earlier cycle otherwise made THIS cycle's prejudge
                # look like it had opened one, and its postjudge resumed the
                # previous attempt's context. Here rather than inside the
                # default runner: it is a property of the evaluation cycle, and
                # an injected runner must not be able to skip it.
                _forget_session(job_id)
            try:
                verdict = runner(stage, inputs)
            except ArtifactChanged as exc:
                verdict = {"unevaluable": str(exc)}
            except Exception as exc:
                verdict = {"unevaluable": f"{type(exc).__name__}: {exc}"}
            else:
                verdict = _mark_model_failure(verdict)
        if verdict.get("unevaluable"):
            unevaluable += 1
            if stage == "prejudge":
                refused[cyc] = str(verdict["unevaluable"])
        else:
            count += 1
        record_verdict(job_id, stage, verdict,
                       answers=rec.get("id"), evaluated_from=rec.get("ts"),
                       # Whether the prejudge left a session for the rest of
                       # the cycle to resume. Recorded, not inferred: a
                       # prejudge that legitimately yielded none is faithful
                       # (enforce would have had none either), and only the
                       # "opened one, cannot reach it now" case is a defect.
                       opened_session=(_session_id(job_id)
                                       if stage == "prejudge" else None))
    _shadow_logger(job_id, "evaluate")(
        f"[judge] shadow: evaluated {count} recorded stage(s) out of band"
        + (f"; {unevaluable} unevaluable" if unevaluable else ""))
    return count


def summary(job_id: str) -> dict[str, Any]:
    """Operator-facing rollup: what shadow saw, and whether it agreed.

    Every "would have" here must answer with the SAME rule the real path uses.
    `would_have_blocked` once counted any `ok=False`, but the runner only
    blocks on severity=high — low/med are advisory and the run proceeds — so
    every advisory finding was being reported as a block, and a confusion
    matrix built on that counts them as false positives.
    """
    from modules._judge import prejudge_blocks_ship, postjudge_would_retry

    inputs = 0
    verdicts: dict[str, list[dict]] = {}
    refused: dict[str, list[dict]] = {}
    answered_ids: set[str] = set()
    for rec in read_shadow(job_id):
        if rec.get("kind") == "input":
            inputs += 1
        elif rec.get("kind") == "verdict":
            v = rec.get("verdict") or {}
            # One measurement per INPUT. `pending_inputs` already folds
            # duplicate answers to the same id — two evaluators racing, or a
            # re-run — but the rollup was appending every row, so `evaluated`
            # could exceed `inputs`. Rows with no `answers` are legacy and
            # cannot be deduped, so they still count individually.
            ans = str(rec.get("answers") or "")
            if ans:
                if ans in answered_ids:
                    continue
                answered_ids.add(ans)
            # A refusal is not a measurement. Counting it as one reported a
            # job where the judge was never called as fully evaluated.
            bucket = refused if v.get("unevaluable") else verdicts
            bucket.setdefault(str(rec.get("stage") or ""), []).append(v)
    return {
        "inputs": inputs,
        "evaluated": sum(len(v) for v in verdicts.values()),
        "unevaluable": sum(len(v) for v in refused.values()),
        "by_stage": {k: len(v) for k, v in verdicts.items()},
        "unevaluable_by_stage": {k: len(v) for k, v in refused.items()},
        # Refused rows are consulted here on purpose. `deterministic_prejudge`
        # runs BEFORE the judge call and escalates on its own, so a prejudge
        # can carry a certain severity=high ship-block AND a failed model turn.
        # The block is model-independent and the fingerprint already proved the
        # artifacts unmoved, so it is a real answer even though the opinion is
        # missing — counting it as "no block" lost a true positive that no
        # later sweep can recover.
        "would_have_blocked": any(
            prejudge_blocks_ship(v)
            for v in verdicts.get("prejudge", []) + refused.get("prejudge", [])
        ),
        "would_have_killed": any(
            v.get("action") == "kill" for v in verdicts.get("supervise", [])
        ),
        # Asked of the predicate that owns the rule. Comparing next_action to
        # "retry" here was a constant False: `_normalize_verdict` clamps the
        # field to {"continue", "stop"}, so no verdict the default evaluator
        # can produce ever matched, and every job the gate WOULD have retried
        # scored as no-retry. Same class as would_have_blocked (D6).
        "would_have_retried": any(
            postjudge_would_retry(v) for v in verdicts.get("postjudge", [])
        ),
    }
