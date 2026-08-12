import asyncio
import json
import os
import re
import shutil
from datetime import datetime, timezone
import ast
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse

from api.queue import get_queue, get_redis
from api.storage import JOBS_DIR, UPLOADS_DIR, parse_targets, read_job_meta, write_job_meta

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")

router = APIRouter()

# Job IDs are always 12 hex chars (api.storage.new_job_id =
# uuid.uuid4().hex[:12]). Anything else — empty string, ".",
# "..", "%2E", path traversals — must be rejected BEFORE the
# Path(...).name + JOBS_DIR / safe construction, because
# Path(".").name returns "" → JOBS_DIR / "" == JOBS_DIR itself,
# and a subsequent rmtree wipes every job. Verified the hard
# way during a security audit on 2026-05-14.
_JOB_ID_RE = re.compile(r"^[a-f0-9]{12}$")


def _validate_job_id(job_id: str) -> str:
    """Reject anything that isn't a canonical 12-hex job id.
    Returns the validated id unchanged."""
    if not _JOB_ID_RE.match(job_id):
        raise HTTPException(status_code=400, detail="invalid job id")
    return job_id


def _is_internal_hybrid_child(meta: dict) -> bool:
    """The exact public-visibility predicate from the hybrid contract."""
    return (
        meta.get("internal") is True
        and isinstance(meta.get("parent_job_id"), str)
        and bool(meta.get("parent_job_id"))
        and isinstance(meta.get("hybrid_stage"), int)
    )


def _hybrid_children(parent_job_id: str, parent_meta: dict) -> list[tuple[dict, dict]]:
    """Return only children whose metadata validates the parent stage link.

    Stage records are not enough authority to stop or delete another job.  A
    linked directory is a child only when its own scalar metadata agrees on
    internal=true, parent id, stage index, and module.
    """
    if parent_meta.get("module") != "hybrid":
        return []
    hybrid = parent_meta.get("hybrid")
    stages = hybrid.get("stages") if isinstance(hybrid, dict) else None
    if not isinstance(stages, list):
        return []
    children: list[tuple[dict, dict]] = []
    for stage in stages:
        if not isinstance(stage, dict):
            continue
        child_id = stage.get("child_job_id")
        if not isinstance(child_id, str) or not _JOB_ID_RE.fullmatch(child_id):
            continue
        child = read_job_meta(child_id)
        if not isinstance(child, dict):
            continue
        if (
            child.get("internal") is True
            and child.get("parent_job_id") == parent_job_id
            and child.get("hybrid_stage") == stage.get("stage")
            and child.get("module") == stage.get("module")
        ):
            children.append((stage, child))
    return children


def _job_cost(job_id: str, meta: dict) -> float:
    """Read one scalar job's authoritative cost with the existing fallback."""
    try:
        cost = float(meta.get("cost_usd") or 0.0)
    except (TypeError, ValueError):
        cost = 0.0
    result_path = JOBS_DIR / job_id / "result.json"
    if cost == 0.0 and result_path.exists():
        try:
            result = json.loads(result_path.read_text())
            cost = float(result.get("cost_usd") or 0.0)
        except Exception:
            pass
    return cost


def _public_job_meta(meta: dict) -> dict:
    """Project a public parent without exposing or double-counting children."""
    if meta.get("module") != "hybrid":
        return meta
    parent_id = meta.get("id")
    if not isinstance(parent_id, str):
        return meta

    # Metadata is JSON-shaped.  Copy before overlaying live child facts so a
    # GET/list operation never mutates the object a caller may later persist.
    public = json.loads(json.dumps(meta))
    linked = _hybrid_children(parent_id, meta)
    total_cost = 0.0
    total_estimate = 0.0
    by_stage = {
        stage.get("stage"): (stage, child)
        for stage, child in linked
        if isinstance(stage.get("stage"), int)
    }
    public_stages = ((public.get("hybrid") or {}).get("stages") or [])
    for public_stage in public_stages:
        if not isinstance(public_stage, dict):
            continue
        linked_stage = by_stage.get(public_stage.get("stage"))
        if linked_stage is None:
            continue
        _, child = linked_stage
        child_id = child["id"]
        child_cost = _job_cost(child_id, child)
        total_cost += child_cost
        try:
            total_estimate += float(child.get("cost_usd_estimate") or 0.0)
        except (TypeError, ValueError):
            pass
        public_stage["status"] = child.get("status", public_stage.get("status"))
        public_stage["cost_usd"] = child_cost
    # The parent owns the public bill. Stats skip internal children, so every
    # scalar child dollar appears exactly once under module=hybrid.
    public["cost_usd"] = round(total_cost, 6)
    if total_estimate:
        public["cost_usd_estimate"] = round(total_estimate, 6)
    return public


def _delete_hybrid_children(parent_job_id: str, parent_meta: dict) -> list[dict]:
    """Stop and delete every validated child owned by a public parent."""
    results = []
    for _, child in _hybrid_children(parent_job_id, parent_meta):
        child_halt = None
        if child.get("status") in ("queued", "running", "analyze", "analyzing"):
            child_halt = _hard_stop_job(child["id"])
        try:
            shutil.rmtree(JOBS_DIR / child["id"])
        except FileNotFoundError:
            pass
        results.append({"id": child["id"], "halt": child_halt})
    return results


def rq_job_id_for(job_id: str, meta: dict | None = None) -> str:
    """The RQ id CURRENTLY backing `job_id` — which is not always `job_id`.

    A continue-in-place re-runs the same job under a NEW RQ id: RQ ids are
    unique and the original has already finished, so `_continue_in_place`
    enqueues under ``<job_id>-c<continue_count>`` (api/routes/retry.py) while
    the job directory, the meta and every URL keep the bare id.

    Everything that reaches into RQ must resolve through here. Signalling the
    bare id after a continue hits the *finished* original, which RQ ignores —
    Stop and Delete then report success while the live agent keeps running and
    keeps spending.
    """
    if meta is None:
        meta = read_job_meta(job_id) or {}
    try:
        n = int((meta or {}).get("continue_count") or 0)
    except (TypeError, ValueError):
        n = 0
    return f"{job_id}-c{n}" if n > 0 else job_id


def _rq_id_candidates(job_id: str, meta: dict | None = None) -> list[str]:
    """Resolved RQ id first, bare job id second (deduped).

    The bare id stays as a fallback so a meta whose `continue_count` ran ahead
    of what was actually enqueued — a continue that wrote meta and then failed
    to enqueue — cannot leave the original permanently unstoppable.
    """
    return list(dict.fromkeys([rq_job_id_for(job_id, meta), job_id]))


def _hard_stop_job(job_id: str) -> dict:
    """Try to actually halt work on a running job:
    1. Send STOP_JOB command to whichever worker is running it (RQ pub-sub).
    2. Find sibling docker containers labelled hextech_ctf_tool_job_id=<id> and
       force-remove them (decompiler / forensic / misc / runner).

    Still best-effort — a cleanup that raises would break the delete it is part
    of — but no longer SILENT. It used to swallow every failure including
    "docker unreachable", so a sweep that removed nothing was indistinguishable
    from one that had nothing to remove. Measured 2026-08-10: container
    609f3504b4d2 (runner, labelled job 9b8168b0ee29) outlived the deletion of
    its own job and its job directory, with nothing anywhere recording that the
    reap had not happened. `containers_failed` / `docker_error` are what make
    that case visible to the caller, which returns this dict in the DELETE
    response.
    """
    info: dict = {"sent_stop": False, "containers_killed": 0,
                  "containers_found": 0, "containers_failed": [],
                  "docker_error": None,
                  "rq_cancelled": False, "rq_ids": []}
    conn = get_redis()
    # 1) Tell RQ to interrupt the running job. send_stop_job_command works only
    #    on running jobs; for queued ones, plain cancel() is enough.
    #    Both candidate ids are signalled: the extra call costs one round trip
    #    and every failure mode here (no such job, already finished) raises and
    #    is swallowed, so it cannot make the stop worse — whereas guessing the
    #    wrong single id makes it a silent no-op.
    for rq_id in _rq_id_candidates(job_id):
        info["rq_ids"].append(rq_id)
        try:
            from rq.command import send_stop_job_command
            send_stop_job_command(conn, rq_id)
            info["sent_stop"] = True
        except Exception:
            pass
        try:
            from rq.job import Job
            rq_job = Job.fetch(rq_id, connection=conn)
            try:
                rq_job.cancel()
                info["rq_cancelled"] = True
            except Exception:
                pass
        except Exception:
            pass

    # 2) Kill any sibling containers spawned for this job
    try:
        import docker as _docker
        client = _docker.from_env()
        containers = client.containers.list(
            all=True,
            filters={"label": f"hextech_ctf_tool_job_id={job_id}"},
        )
        info["containers_found"] = len(containers)
        for c in containers:
            name = getattr(c, "name", None) or (getattr(c, "id", "") or "")[:12]
            try:
                c.kill()
            except Exception:
                # An already-exited container cannot be killed; that is the
                # normal case here, not a failure. Only the remove matters.
                pass
            try:
                # v=True: the anonymous volumes this container created are its
                # own and leak otherwise — 383 of them accumulated on
                # 2026-08-10 alone.
                c.remove(force=True, v=True)
                info["containers_killed"] += 1
            except Exception as e:
                info["containers_failed"].append(f"{name}: {type(e).__name__}")
    except Exception as e:
        # The whole block failing means the daemon was unreachable, which is
        # exactly when siblings survive. Recorded rather than swallowed.
        info["docker_error"] = f"{type(e).__name__}: {e}"

    return info


@router.get("")
def list_jobs():
    if not JOBS_DIR.exists():
        return {"jobs": []}
    out = []
    for d in sorted(JOBS_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        meta = read_job_meta(d.name)
        if meta:
            if _is_internal_hybrid_child(meta):
                continue
            meta = _public_job_meta(meta)
            meta["runnable_script"] = _detect_runnable_script(d)
            out.append(meta)
    return {"jobs": out}


@router.get("/queue")
def queue_info():
    """Live worker + queue status. Used by the UI to show concurrency."""
    from rq import Worker
    conn = get_redis()
    q = get_queue()
    workers = Worker.all(connection=conn)
    busy = []
    idle = []
    for w in workers:
        info = {"name": w.name, "state": w.get_state()}
        if w.get_current_job_id():
            info["job_id"] = w.get_current_job_id()
        if info["state"] == "busy":
            busy.append(info)
        else:
            idle.append(info)
    return {
        "queued": q.count,
        "started": q.started_job_registry.count,
        "failed": q.failed_job_registry.count,
        "workers_total": len(workers),
        "workers_busy": len(busy),
        "workers_idle": len(idle),
        "workers": busy + idle,
    }


@router.get("/stats")
def get_stats():
    """Aggregate cost and counts across all jobs."""
    if not JOBS_DIR.exists():
        return {"total_cost_usd": 0.0, "by_module": {}, "count": 0}
    total = 0.0
    in_flight = 0.0          # token-estimated spend of jobs still running
    by_module: dict[str, dict] = {}
    count = 0
    for d in JOBS_DIR.iterdir():
        if not d.is_dir():
            continue
        meta_path = d / "meta.json"
        if not meta_path.exists():
            continue
        try:
            meta = json.loads(meta_path.read_text())
        except Exception:
            continue
        if _is_internal_hybrid_child(meta):
            continue
        meta = _public_job_meta(meta)
        count += 1
        module = meta.get("module", "unknown")
        bucket = by_module.setdefault(module, {"count": 0, "cost_usd": 0.0})
        bucket["count"] += 1
        cost = _job_cost(d.name, meta)
        # LIVE jobs: surface the part of THIS session's spend that no
        # ResultMessage has confirmed yet. A CONTINUED session carries the
        # banked prior total in cost_usd from its first moment, so the old
        # `cost == 0` gate never fired for it and the operator watched a frozen
        # number for the whole session — the very "in-flight job reports $0"
        # complaint the estimate was added to fix.
        if (meta.get("status") or "") in ("running", "queued", "analyze"):
            _banked = float(meta.get("cost_usd_prior_sessions") or 0.0)
            _est = float(meta.get("cost_usd_estimate") or 0.0)
            _confirmed_this_session = max(0.0, cost - _banked)
            in_flight += max(0.0, _est - _confirmed_this_session)
        elif cost == 0.0:
            # A TERMINAL job with no authoritative cost (killed before any
            # ResultMessage). Its parked estimate is the only record of what it
            # spent, but it is not "in flight" — counting it there labelled dead
            # jobs as still running forever. It is simply absent from the
            # ledger; the session-start banking in _common.prior_session_cost
            # is what recovers it if the job is ever continued.
            pass
        bucket["cost_usd"] += cost
        total += cost
    return {"total_cost_usd": round(total, 4), "by_module": by_module,
            "count": count, "in_flight_estimate_usd": round(in_flight, 4)}


@router.get("/usage")
def get_usage():
    """Top-bar usage pill data: cumulative SPENT cost vs an operator-set
    budget, plus account-global rate-limit status for Claude, Grok and Codex.

    Honest scope:
      * `remaining_usd` is `budget_usd - spent` against the OPERATOR'S
        configured budget (0 = no budget → spent-only). Not the Claude
        account limit.
      * `rate_limit` is Claude's coarse subscription signal the Agent SDK
        emits (status + reset epoch; `utilization` is frequently absent
        for OAuth accounts).
      * `grok_rate_limit` is Grok SuperGrok weekly pool usage polled from
        cli-chat-proxy `/v1/billing?format=credits` (needs `grok login`
        OAuth mounted). Includes `remaining_pct` when available.
      * `codex_rate_limit` is the mounted ChatGPT OAuth account's usage,
        queried through Codex CLI app-server and cached for 15 seconds.
    """
    from modules.settings_io import get_setting
    from modules._common import read_rate_limit, read_grok_rate_limit
    from modules.codex_rate_limit import read_codex_rate_limit

    stats = get_stats()
    spent = float(stats.get("total_cost_usd") or 0.0)
    try:
        budget = float(get_setting("budget_usd") or 0.0)
    except (TypeError, ValueError):
        budget = 0.0
    remaining = round(budget - spent, 4) if budget > 0 else None
    pct_used = round(min(spent / budget * 100.0, 999.9), 1) if budget > 0 else None
    return {
        "spent_usd": round(spent, 4),
        # Token-estimated spend of jobs still RUNNING (no ResultMessage yet, so
        # they contribute 0 to spent_usd). Deliberately NOT added to spent_usd
        # or to the budget maths: it is an estimate that runs high, and the
        # budget number must stay the authoritative one.
        "in_flight_estimate_usd": stats.get("in_flight_estimate_usd", 0.0),
        "budget_usd": round(budget, 4),
        "remaining_usd": remaining,
        "pct_used": pct_used,
        "count": stats.get("count", 0),
        "rate_limit": read_rate_limit(),
        "grok_rate_limit": read_grok_rate_limit(),
        "codex_rate_limit": read_codex_rate_limit(),
    }


def _script_missing_siblings(script: Path) -> list[str]:
    """Sibling files the script REQUIRES that are not there.

    "A file named exploit.py exists" was the whole test for `runnable_script`,
    and it is not the same question. Job 6685e3e65add shipped an uploader
    skeleton whose second statement is

        payload_path = Path(__file__).resolve().with_name("serendipity_exp")
        if not payload_path.exists():
            raise SystemExit(f"missing compiled payload: {payload_path}")

    — so "Run in sandbox" offered to run something that could only exit. The
    operator reads that button as "there is an exploit"; it meant "there is a
    filename".

    Deliberately narrow. It resolves LITERAL sibling names only, via
    `.with_name("x")` and `open("x")` / `Path("x")` with no separator, and says
    nothing about a script that builds its payload at run time. A wrong "this
    is fine" is the failure that matters here, so the analysis only reports
    what it can actually see.
    """
    try:
        tree = ast.parse(script.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    wanted: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = ""
        if isinstance(node.func, ast.Attribute):
            name = node.func.attr
        elif isinstance(node.func, ast.Name):
            name = node.func.id
        if name not in {"with_name", "open", "Path"}:
            continue
        for arg in node.args[:1]:
            if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                continue
            v = arg.value
            if not v or "/" in v or v.startswith(".") or len(v) > 100:
                continue
            wanted.append(v)
    here = script.parent
    return sorted({v for v in wanted if not (here / v).exists()})


def _detect_runnable_script(job_dir: Path) -> str | None:
    # Primary: <jobdir>/<name> (populated by the analyzer's carry step at
    # the end of a run). Fallback: <jobdir>/work/<name> — present even
    # when the carry hasn't run yet (e.g. a collector OOB capture marked
    # the job finished while the main agent was still mid-analyze, or the
    # run was stopped before stage=done). The /file/{name} route already
    # has this work/ fallback, so the link resolves either way.
    for name in ("exploit.py", "solver.py", "solver.sage"):
        if (job_dir / name).is_file() or (job_dir / "work" / name).is_file():
            return name
    return None


@router.get("/{job_id}")
def get_job(job_id: str):
    meta = read_job_meta(job_id)
    if meta is None:
        raise HTTPException(status_code=404, detail="job not found")

    rq_status = None
    rq_worker_name = None
    try:
        q = get_queue()
        # Same resolution as the stop path: after a continue the live RQ record
        # is <job_id>-c<n>, so probing the bare id reported rq_status=None and
        # no worker — which the UI reads as "no worker heartbeat" on a job that
        # is in fact running.
        rq_job = None
        for _rq_id in _rq_id_candidates(job_id, meta):
            rq_job = q.fetch_job(_rq_id)
            if rq_job is not None:
                break
        if rq_job is not None:
            rq_status = rq_job.get_status(refresh=True)
            rq_worker_name = rq_job.worker_name
    except Exception:
        pass

    # `rq_worker_heartbeat_at` used to be computed here, from
    # `rq:worker:<name>.last_heartbeat`, purely to drive the UI's liveness
    # chip. Both are gone. The field was semantically wrong as well as unused:
    # a worker name is permanently bound to a slot and reused by every job that
    # runs there, so it answered "is the process called htct-sN-w0 alive?" and
    # not "is THIS job alive?" — after a work horse is SIGKILLed without
    # writing a terminal status, the slot's container returns under the same
    # name and heartbeats every 30 s, so the field stayed fresh for a job that
    # was gone. `rq_status` (below) is the honest per-job signal and is kept.
    #
    # If a per-job heartbeat is ever wanted, RQ does keep one:
    # `rq:job:<id>.last_heartbeat`, written by Worker.maintain_heartbeats for
    # that specific job. Read THAT, not the worker's.

    # Always derive a `runnable_script` field from the filesystem so the UI
    # can show the run-now button even on jobs whose meta was written before
    # the field existed (or whose orchestrator didn't set it).
    _jd = JOBS_DIR / Path(job_id).name
    runnable_script = _detect_runnable_script(_jd)
    # A script can exist and still be unable to run. Reported alongside rather
    # than folded into `runnable_script`, so the /file/ link and the retry
    # paths that key off the name are untouched — only the UI's claim changes.
    script_missing = []
    if runnable_script:
        for _cand in (_jd / runnable_script, _jd / "work" / runnable_script):
            if _cand.is_file():
                script_missing = _script_missing_siblings(_cand)
                break

    # WHY_STOPPED.md only exists on abnormal stops (judge_stop / agent_error /
    # no_hint / budget) — written by write_why_stopped() to the work tree and
    # carried to root at stage=done. Surface a presence flag so the UI can show
    # its file link only when it exists (unlike report.md/exploit.py which are
    # always linked), avoiding a dead 404 link on clean flag-capture runs.
    has_why_stopped = (
        (_jd / "WHY_STOPPED.md").is_file()
        or (_jd / "work" / "WHY_STOPPED.md").is_file()
    )

    return {
        **_public_job_meta(meta),
        "rq_status": rq_status,
        # kept: scripts/job-status.sh prints it, and it identifies the slot
        "rq_worker_name": rq_worker_name,
        "runnable_script": runnable_script,
        "script_missing": script_missing,
        "has_why_stopped": has_why_stopped,
    }


@router.delete("")
def bulk_delete_jobs(
    status: str | None = None,
    module: str | None = None,
    all: bool = False,
):
    """Bulk delete jobs.

    Query params:
      - status: only delete jobs with this status (queued/running/finished/failed)
      - module: only delete jobs from this module
      - all=true: also cancel queued/running jobs (in addition to filesystem cleanup)

    Without any filter, deletes finished + failed only (safe default — leaves
    queued/running jobs alone).
    """
    if not JOBS_DIR.exists():
        return {"deleted": 0, "skipped": 0, "ids": []}

    safe_default_statuses = {"finished", "failed", "no_flag"}
    deleted_ids: list[str] = []
    skipped = 0

    for d in JOBS_DIR.iterdir():
        if not d.is_dir():
            continue
        meta = read_job_meta(d.name)
        if not meta:
            continue
        # Internal children have no public lifecycle of their own. They are
        # removed only by deleting their parent (the explicit policy below).
        if _is_internal_hybrid_child(meta):
            continue
        st = meta.get("status")
        mod = meta.get("module")
        # Filter
        if status and st != status:
            continue
        if module and mod != module:
            continue
        if not status and not all and st not in safe_default_statuses:
            skipped += 1
            continue
        # Halt running/queued jobs: stop the worker + kill sibling containers.
        if st in ("queued", "running"):
            _hard_stop_job(d.name)
        try:
            _delete_hybrid_children(d.name, meta)
        except Exception:
            # Keep the public owner when any hidden child could not be removed;
            # otherwise the API would create an unreachable orphan silently.
            skipped += 1
            continue
        upload_dir = UPLOADS_DIR / d.name
        if upload_dir.exists():
            try:
                shutil.rmtree(upload_dir)
            except Exception:
                skipped += 1
                continue
        try:
            shutil.rmtree(d)
            deleted_ids.append(d.name)
        except Exception:
            skipped += 1

    return {"deleted": len(deleted_ids), "skipped": skipped, "ids": deleted_ids}


@router.delete("/{job_id}")
def delete_job(job_id: str):
    safe = _validate_job_id(job_id)
    d = JOBS_DIR / safe
    # Defense in depth: ensure the resolved path is a direct
    # child of JOBS_DIR. Catches the case where JOBS_DIR is
    # itself a symlink that resolves outside the expected root.
    jobs_root = JOBS_DIR.resolve()
    try:
        d_resolved = d.resolve()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid job id")
    if d_resolved.parent != jobs_root:
        raise HTTPException(status_code=400, detail="invalid job id")
    if not d.exists():
        raise HTTPException(status_code=404, detail="job not found")
    meta = read_job_meta(safe)
    halt_info = None
    if meta and meta.get("status") in ("queued", "running"):
        halt_info = _hard_stop_job(safe)
    # Hybrid deletion policy: a public parent owns its internal children, so
    # deleting the parent deletes every validated linked child after stopping
    # any active child. No child artifact is retained implicitly.
    child_results = _delete_hybrid_children(safe, meta or {})
    upload_dir = UPLOADS_DIR / safe
    if upload_dir.exists():
        shutil.rmtree(upload_dir)
    shutil.rmtree(d)
    return {"deleted": safe, "halt": halt_info, "children_deleted": child_results}


@router.post("/{job_id}/stop")
def stop_job(job_id: str):
    """Pure stop: halt a queued/running job WITHOUT deleting it — keep the job
    record and ./work/ artifacts, just stop the work.

    Cancels the RQ job (so it won't auto-resume on a worker restart) via the
    same _hard_stop_job used by DELETE and by 'stop & resume', then rewrites
    meta.status='stopped' so the UI no longer shows it live. Distinct from:
      * DELETE /{job_id}        — halts AND removes the job entirely.
      * 'stop & resume' (retry) — halts THIS job and forks a fresh one.
    On an already-terminal job it just stamps status=stopped (no re-halt). No
    error/error_kind is set — a user stop is a clean terminal state, not a
    failure, so the detail view shows a plain 'stopped' pill (not an error
    banner). Mirrors retry._halt_source_job minus the resume."""
    safe = _validate_job_id(job_id)
    meta = read_job_meta(safe)
    if meta is None:
        raise HTTPException(status_code=404, detail="job not found")
    was = meta.get("status")
    halt_info = None
    if was in ("queued", "running"):
        halt_info = _hard_stop_job(safe)
    stopped_children = []
    for stage, child in _hybrid_children(safe, meta):
        if child.get("status") not in ("queued", "running", "analyze", "analyzing"):
            continue
        child_halt = _hard_stop_job(child["id"])
        write_job_meta(
            child["id"],
            {
                **child,
                "status": "stopped",
                "stopped_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        stage["status"] = "stopped"
        stopped_children.append({"id": child["id"], "halt": child_halt})
    stopped_meta = {
        **meta,
        "status": "stopped",
        "stopped_at": datetime.now(timezone.utc).isoformat(),
    }
    write_job_meta(safe, stopped_meta)
    return {
        "stopped": safe,
        "prev_status": was,
        "status": "stopped",
        "halt": halt_info,
        "children_stopped": stopped_children,
    }


@router.post("/{job_id}/flags/delete")
async def delete_job_flags(job_id: str, request: Request):
    """Prune operator-selected entries from a job's captured ``flags``.

    Some challenges pad stdout with flag-shaped noise (ASCII-art banners,
    decoys) so the scanner stuffs ``meta.flags`` with dozens of dummies
    around the one real flag (see job 8806b284d740). This lets the operator
    delete the junk by index. Body::

        {"indices": [<int>, ...]}   # positions in the CURRENT meta.flags

    Returns the surviving flags. ``status`` is left untouched — the operator
    is curating the captured list, not re-adjudicating success. Out-of-range
    indices are ignored so a stale UI can't 500 the call.
    """
    safe = _validate_job_id(job_id)
    meta = read_job_meta(safe)
    if meta is None:
        raise HTTPException(status_code=404, detail="job not found")
    try:
        body = await request.json()
    except Exception:
        body = {}
    indices = body.get("indices")
    if not isinstance(indices, list) or not all(isinstance(i, int) for i in indices):
        raise HTTPException(status_code=400, detail="`indices` must be a list of integers")

    flags = list(meta.get("flags") or [])
    remove = {i for i in indices if 0 <= i < len(flags)}
    new_flags = [f for j, f in enumerate(flags) if j not in remove]

    if len(new_flags) != len(flags):
        from modules._common import write_meta
        write_meta(safe, flags=new_flags)
        # Keep result.json in sync so a later download / result view does
        # not resurrect the pruned entries.
        try:
            rp = JOBS_DIR / safe / "result.json"
            if rp.exists():
                rj = json.loads(rp.read_text())
                if isinstance(rj, dict) and "flags" in rj:
                    rj["flags"] = new_flags
                    rp.write_text(json.dumps(rj, indent=2))
        except Exception:
            pass

    return {
        "flags": new_flags,
        "removed": len(flags) - len(new_flags),
        "status": meta.get("status"),
    }


@router.get("/{job_id}/log", response_class=PlainTextResponse)
def get_job_log(job_id: str, tail: int | None = None):
    """Return run.log. With ?tail=N (bytes), returns at most the last N
    bytes — used by the polling UI so multi-MB logs don't get re-shipped
    every 2s after the agent does verbose Read/Bash output. The cut is
    aligned to the next newline so we never start mid-line.
    """
    log = JOBS_DIR / job_id / "run.log"
    if not log.exists():
        return PlainTextResponse("", status_code=200)
    if tail and tail > 0:
        try:
            size = log.stat().st_size
        except OSError:
            return PlainTextResponse("", status_code=200)
        if size > tail:
            with log.open("rb") as fp:
                fp.seek(size - tail)
                fp.readline()  # skip partial line
                data = fp.read()
            text = data.decode("utf-8", errors="replace")
            header = (
                f"…(showing last {len(data)} of {size} bytes — "
                f"download full log via /api/jobs/{job_id}/file/run.log)…\n"
            )
            return PlainTextResponse(header + text)
    return PlainTextResponse(log.read_text(errors="replace"))


@router.get("/{job_id}/monitor")
async def get_job_monitor(job_id: str, tail: int | None = None):
    """Curated MONITOR feed for a job — the filtered, LLM-narrated signal
    entries from <job>/monitor.jsonl. Each entry carries a `text` map keyed
    by language ({"ko": "...", "en": "..."}); the client picks which to show,
    so switching language is instant with no refetch. With ?tail=N, returns
    only the last N entries. Opening this (or the SSE /stream) also ensures
    the job's live monitor task is running. GPT jobs use the deterministic
    Timeline instead, so this endpoint neither starts nor returns Monitor."""
    safe = _validate_job_id(job_id)
    meta = read_job_meta(safe) or {}
    provider = str(meta.get("agent_provider") or "").strip().lower()
    if not provider:
        retry_of = str(meta.get("retry_of") or "").strip()
        if retry_of:
            prior_meta = read_job_meta(Path(retry_of).name) or {}
            provider = str(prior_meta.get("agent_provider") or "").strip().lower()
    if provider == "gpt":
        return {"enabled": False, "entries": []}
    try:
        from modules._monitor import ensure_monitor
        ensure_monitor(safe)
    except Exception:
        pass
    p = JOBS_DIR / safe / "monitor.jsonl"
    entries: list[dict] = []
    if p.exists():
        try:
            for line in p.read_text(errors="replace").splitlines():
                s = line.strip()
                if not s:
                    continue
                try:
                    entries.append(json.loads(s))
                except json.JSONDecodeError:
                    continue
        except OSError:
            entries = []
    if tail and tail > 0:
        entries = entries[-tail:]
    return {"entries": entries}


@router.get("/{job_id}/gpt-timeline")
def get_gpt_timeline(job_id: str, tail: int | None = None):
    """Structured activity for GPT jobs only.

    Claude and Grok deliberately do not enter this path: their existing
    ``run.log`` and Monitor behavior remains byte-for-byte unchanged.  A GPT
    job created before ``gpt-events.jsonl`` existed receives a read-only
    projection of its existing run.log so an in-flight job becomes useful
    immediately without rewriting evidence.
    """
    safe = _validate_job_id(job_id)
    meta = read_job_meta(safe)
    if meta is None:
        raise HTTPException(status_code=404, detail="job not found")
    if str(meta.get("agent_provider") or "").lower() != "gpt":
        return {"enabled": False, "events": [], "agents": [], "source": "disabled"}

    configured_models: dict[str, str] = {}
    configured_providers: dict[str, str] = {}
    preset_name = ""
    try:
        from modules.agent_provider import default_model_for
        from modules.model_presets import CONFIGURABLE_ROLES, get_provider_store

        snapshot = meta.get("gpt_role_models")
        bucket = get_provider_store("gpt")
        preset_name = str(meta.get("gpt_preset") or bucket.get("active") or "")
        preset = (
            snapshot if isinstance(snapshot, dict)
            else (bucket.get("presets") or {}).get(preset_name) or {}
        )
        main = str(meta.get("model") or preset.get("main") or default_model_for("gpt"))
        judge = str(preset.get("judge") or main)
        fallbacks = {
            "main": main,
            "judge": judge,
            "reviewer": str(preset.get("reviewer") or judge),
            "recon": str(preset.get("recon") or main),
            "debugger": str(preset.get("debugger") or main),
            "triage": str(preset.get("triage") or main),
            "report": str(preset.get("report") or main),
        }
        # A role routed to another backend does NOT run the GPT preset's model
        # for it. Reporting the GPT entry there made the Timeline claim every
        # agent was GPT on a hybrid job — the one thing an operator turns
        # hybrid on to be able to see.
        from modules.agent_provider import provider_for_role, role_model_for

        configured_models = {}
        configured_providers = {}
        _timeline_roles = [
            role for role in CONFIGURABLE_ROLES
            if role != "monitor" and fallbacks.get(role)
        ]
        for role in _timeline_roles:
            where = provider_for_role(job_id, role)
            configured_providers[role] = where
            configured_models[role] = (
                fallbacks[role] if where == "gpt"
                else role_model_for(role, where, None)
            )
    except Exception:
        configured_models = {}
        configured_providers = {}

    from modules.gpt_run_events import read_gpt_timeline, summarize_agents

    bounded_tail = max(1, min(int(tail or 600), 2000))
    all_events, source = read_gpt_timeline(
        safe,
        started_at=meta.get("started_at"),
    )
    events = all_events[-bounded_tail:]
    return {
        "enabled": True,
        "source": source,
        "preset": preset_name,
        "events": events,
        "agents": summarize_agents(all_events, configured_models,
                                   configured_providers),
    }


_TERMINAL_META_STATUSES = {"finished", "failed", "no_flag", "stopped"}


@router.get("/{job_id}/stream")
async def stream_job(job_id: str, request: Request):
    """Server-Sent Events live feed of a job's run.log + meta updates.

    Multiplexes three Redis pubsub channels into one HTTP stream:
      - `job:<id>:log`  → SSE event `log`   {ts, line}
      - `job:<id>:meta` → SSE event `meta`  {...}
      - `job:<id>:sdk`  → SSE event `sdk`   {...}  (Phase 4)

    On connect we replay the current run.log + meta.json so the client
    can render the full state without a separate fetch. After backfill,
    it streams new events as they're published. The connection holds
    open until the client disconnects OR the job reaches a terminal
    status (then we emit one final `done` event and close).

    Heartbeat: a comment line (`: ping`) every 15s keeps any proxy
    between client and api from culling the long-lived connection.
    """
    safe = _validate_job_id(job_id)
    jd = JOBS_DIR / safe
    if not jd.exists():
        raise HTTPException(status_code=404, detail="job not found")

    log_path = jd / "run.log"
    meta_path = jd / "meta.json"
    initial_meta = read_job_meta(safe) or {}
    stream_provider = str(initial_meta.get("agent_provider") or "").strip().lower()
    if not stream_provider:
        retry_of = str(initial_meta.get("retry_of") or "").strip()
        if retry_of:
            prior_meta = read_job_meta(Path(retry_of).name) or {}
            stream_provider = str(prior_meta.get("agent_provider") or "").strip().lower()
    is_gpt_job = stream_provider == "gpt"

    def sse(name: str, data) -> bytes:
        return f"event: {name}\ndata: {json.dumps(data)}\n\n".encode()

    async def event_gen():
        # Claude/Grok live streams also guarantee their monitor task is
        # running (belt-and-suspenders with the always-on supervisor). GPT's
        # deterministic Timeline deliberately has no narrator task.
        if not is_gpt_job:
            try:
                from modules._monitor import ensure_monitor
                ensure_monitor(safe)
            except Exception:
                pass
        from redis import asyncio as aioredis
        r = aioredis.from_url(REDIS_URL)
        pubsub = r.pubsub()
        try:
            # Subscribe BEFORE backfill so any event published between
            # backfill-read and subscribe is buffered (Redis pubsub is
            # ephemeral but the gap here is microseconds).
            channels = [
                f"job:{safe}:log",
                f"job:{safe}:meta",
                f"job:{safe}:sdk",
            ]
            if not is_gpt_job:
                channels.append(f"job:{safe}:monitor")
            await pubsub.subscribe(*channels)

            # --- Backfill --------------------------------------------
            # Send current meta.json so the UI has tokens/status from
            # the moment of connect.
            try:
                if meta_path.exists():
                    meta = json.loads(meta_path.read_text())
                    yield sse("meta", {"backfill": True, "meta": meta})
            except Exception:
                pass

            # Send the existing run.log line-by-line. Each line keeps
            # its on-disk timestamp prefix so the frontend can parse
            # it the same way it parses live events.
            try:
                if log_path.exists():
                    # Cap backfill at last 256 KB so a 100MB log doesn't
                    # block the stream open.
                    size = log_path.stat().st_size
                    cap = 256 * 1024
                    with log_path.open("rb") as fp:
                        if size > cap:
                            fp.seek(size - cap)
                            fp.readline()  # skip partial
                        data = fp.read().decode("utf-8", errors="replace")
                    if size > cap:
                        yield sse("log", {
                            "backfill": True,
                            "line": f"…(showing last ~{cap // 1024}KB of {size} bytes — full log via /api/jobs/{safe}/file/run.log)…",
                            "ts": "",
                        })
                    for line in data.splitlines():
                        # Each on-disk line looks like "[HH:MM:SS] <body>".
                        m = re.match(r"^\[(\d\d:\d\d:\d\d)\] (.*)$", line)
                        if m:
                            ts, body = m.group(1), m.group(2)
                        else:
                            ts, body = "", line
                        yield sse("log", {
                            "backfill": True,
                            "ts": ts,
                            "line": body,
                        })
            except Exception:
                pass

            # Backfill the curated monitor feed (last 400 entries) so the
            # Monitor view renders instantly on connect, same as the run log.
            if not is_gpt_job:
                try:
                    mon = jd / "monitor.jsonl"
                    if mon.exists():
                        lines = mon.read_text(errors="replace").splitlines()[-400:]
                        for line in lines:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)
                            except Exception:
                                continue
                            entry["backfill"] = True
                            yield sse("monitor", entry)
                except Exception:
                    pass

            yield sse("backfill_done", {})

            # If the job is already terminal at backfill time, close
            # immediately — no live updates will come.
            try:
                if meta_path.exists():
                    status = json.loads(meta_path.read_text()).get("status")
                    if status in _TERMINAL_META_STATUSES:
                        yield sse("done", {"status": status})
                        return
            except Exception:
                pass

            # --- Live loop -------------------------------------------
            last_ping = asyncio.get_event_loop().time()
            HEARTBEAT_S = 15.0
            while True:
                if await request.is_disconnected():
                    return
                # Wait up to 5s for the next pubsub message.
                msg = await pubsub.get_message(
                    ignore_subscribe_messages=True,
                    timeout=5.0,
                )
                now = asyncio.get_event_loop().time()
                if msg is None:
                    # Heartbeat to keep proxies/clients from cutting us.
                    if now - last_ping >= HEARTBEAT_S:
                        yield b": ping\n\n"
                        last_ping = now
                    continue

                channel = msg["channel"].decode("utf-8", "replace")
                # channel = "job:<id>:<suffix>"
                suffix = channel.rsplit(":", 1)[-1]
                try:
                    payload = json.loads(msg["data"])
                except Exception:
                    payload = {"raw": msg["data"].decode("utf-8", "replace")}

                yield sse(suffix, payload)
                last_ping = now

                # If we just saw a terminal status, close cleanly.
                if suffix == "meta":
                    su = payload.get("status_update") or {}
                    new_status = su.get("status")
                    if new_status in _TERMINAL_META_STATUSES:
                        yield sse("done", {"status": new_status})
                        return
        finally:
            try:
                await pubsub.unsubscribe()
                await pubsub.close()
            except Exception:
                pass
            try:
                await r.close()
            except Exception:
                pass

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.get("/{job_id}/file/{name}")
def get_job_file(job_id: str, name: str):
    safe = Path(name).name
    jd = JOBS_DIR / job_id
    # Primary location: <jobdir>/<name>, populated by the analyzer's
    # carry step at the end of _run_agent. If the run was killed mid-
    # flight (RQ stop / Stop&Resume / SIGKILL) the carry never ran but
    # the artifact is still in <jobdir>/work/<name>. Fall back there
    # so the UI's file links work for stopped jobs too.
    candidates = [jd / safe, jd / "work" / safe]
    for f in candidates:
        if f.is_file():
            return FileResponse(str(f))
    raise HTTPException(status_code=404, detail="file not found")


# ------------------------------------------------------------ file browser
#
# WHY A BROWSER AND NOT MORE LINKS
# The job panel used to hard-code one link per artifact per module
# (`exploit.py.stdout`, `solver.py.stdout`, …). The runner names its artifacts
# after the script it actually ran, so a crypto Sage job produces
# `solver.sage.stdout` — a name no hard-coded list contained, and its links
# 404'd while the file sat on disk. Listing the directory removes the guess:
# whatever the runner wrote is what the operator sees.
#
# LAZY, ONE DIRECTORY AT A TIME. Measured 2026-08-11 across 74 job dirs: the
# median holds 85 files, but the largest holds 8,520 across 1.1 GB at depth 14
# (a decompiler run). A recursive dump would be that whole tree in one
# response, so this lists exactly one level and the UI asks again on expand.
_FILE_LIST_CAP = 2000


def _job_subpath(job_id: str, rel: str) -> Path:
    """Resolve `rel` inside a job directory, or raise 404/403.

    The guard is `realpath` containment, NOT string prefixing, because a job
    directory holds agent-authored content: `work/` is writable by the agent
    and by challenge code running as root in the sandbox, so a symlink like
    `work/x -> /` is something this has to survive rather than assume away.
    Resolving first and then testing ancestry means a link that escapes is
    refused even though its literal path looked fine.
    """
    safe_id = Path(job_id).name
    if not safe_id:
        raise HTTPException(status_code=404, detail="job not found")
    root = (JOBS_DIR / safe_id).resolve()
    if not root.is_dir():
        raise HTTPException(status_code=404, detail="job not found")
    target = (root / (rel or "")).resolve()
    if target != root and root not in target.parents:
        raise HTTPException(status_code=403, detail="path escapes the job directory")
    return target


@router.get("/{job_id}/files")
def list_job_files(job_id: str, path: str = ""):
    """One directory of a job's working tree.

    Entries are ordered directories-first then by name, which is the order an
    operator scans for "where did the run put things".
    """
    target = _job_subpath(job_id, path)
    if not target.is_dir():
        raise HTTPException(status_code=404, detail="not a directory")

    root = (JOBS_DIR / Path(job_id).name).resolve()
    entries = []
    truncated = False
    try:
        with os.scandir(target) as it:
            for de in it:
                if len(entries) >= _FILE_LIST_CAP:
                    truncated = True
                    break
                # follow_symlinks=False: a broken or escaping link must still
                # be listable (so the operator can see it exists) without this
                # call following it off the tree.
                try:
                    st = de.stat(follow_symlinks=False)
                    is_dir = de.is_dir(follow_symlinks=True)
                except OSError:
                    continue
                entries.append({
                    "name": de.name,
                    "path": str(Path(path or "") / de.name).replace("\\", "/"),
                    "is_dir": is_dir,
                    "is_link": de.is_symlink(),
                    "size": None if is_dir else st.st_size,
                    "mtime": datetime.fromtimestamp(
                        st.st_mtime, timezone.utc).isoformat(),
                })
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")

    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    rel = "" if target == root else str(target.relative_to(root)).replace("\\", "/")
    return {
        "job_id": Path(job_id).name,
        "path": rel,
        "parent": "" if not rel else str(Path(rel).parent).replace("\\", "/").lstrip("."),
        "entries": entries,
        "truncated": truncated,
        "cap": _FILE_LIST_CAP,
    }


@router.get("/{job_id}/blob")
def get_job_blob(job_id: str, path: str):
    """Serve one file by its path RELATIVE to the job directory.

    Separate from `/file/{name}`, which takes a bare basename and probes
    `<job>/` then `<job>/work/`. That route is left exactly as it is: existing
    links depend on its fallback, and widening it to accept slashes would
    change what those links resolve to. This one is for the browser, where the
    path is already known exactly.
    """
    target = _job_subpath(job_id, path)
    if not target.is_file():
        raise HTTPException(status_code=404, detail="file not found")
    return FileResponse(str(target), filename=target.name)


@router.get("/{job_id}/result")
def get_job_result(job_id: str):
    f = JOBS_DIR / job_id / "result.json"
    if f.exists():
        return json.loads(f.read_text())
    # result.json is only written by the analyzer's carry step at
    # stage=done. A collector OOB capture can mark the job
    # finished/success BEFORE that point (the bot calls in while the
    # main agent is still mid-analyze), so for ~minutes there is a
    # finished job with flags but no result.json and the UI's result
    # link 404s. Synthesize a minimal result from meta so the link
    # always resolves; the real file overwrites this view once carry
    # runs.
    meta = read_job_meta(Path(job_id).name)
    if meta is None:
        raise HTTPException(status_code=404, detail="job not found")
    return {
        "synthesized_from_meta": True,
        "status": meta.get("status"),
        "flags": meta.get("flags") or [],
        "cost_usd": meta.get("cost_usd"),
        "agent_error": meta.get("error"),
        "agent_error_kind": meta.get("error_kind"),
    }


@router.post("/{job_id}/run")
def post_run_script(job_id: str, target: str | None = None):
    """Manually re-run the produced exploit/solver script in the runner
    sandbox. Useful when the user didn't enable auto-run, when the
    earlier auto-run failed, or when they want to retry against a
    different target.

    Request can supply `?target=...` to override the stored target.
    Returns the sandbox result (stdout/stderr/exit_code) and updated
    flag list. Updates meta.status accordingly.
    """
    safe = Path(job_id).name
    jd = JOBS_DIR / safe
    if not jd.exists():
        raise HTTPException(status_code=404, detail="job not found")
    meta = read_job_meta(safe) or {}

    # Pick the script the agent produced
    script = None
    for name in ("exploit.py", "solver.py", "solver.sage"):
        if (jd / name).is_file():
            script = name
            break
    if not script:
        raise HTTPException(
            status_code=400,
            detail="no exploit.py / solver.py / solver.sage in this job",
        )
    use_sage = script.endswith(".sage")
    # An explicit ?target= override is PERSISTED to meta before the run
    # (below, right after the write_meta import). attempt_sandbox_run
    # proactively prefers meta.target_url over the argv target we hand it
    # (see modules/_runner._refresh_target_from_meta), so an un-persisted
    # override would be clobbered straight back to the STALE stored value —
    # exactly why "Run in sandbox" appeared to ignore a fresh target on
    # dreamhack-style jobs whose instance had rotated. Mirrors PATCH /target.
    _override = (target or "").strip()
    target = (_override or meta.get("target_url") or "").strip() or None

    # Sandbox runner spawn (same path the orchestrators use)
    from modules._common import scan_job_for_flags, write_meta
    from modules._runner import attempt_sandbox_run, remote_target_start_gate
    from modules.settings_io import apply_to_env

    # Persist an operator-supplied target override so the proactive
    # meta-refresh inside attempt_sandbox_run keeps it instead of reverting
    # to the stale stored value (see the _override note above).
    if _override and _override != (meta.get("target_url") or "").strip():
        write_meta(safe, target_url=_override)

    # Pull settings (CALLBACK_URL etc.) into this process's env so the
    # runner spawn picks them up, mirroring what worker run_job() does.
    apply_to_env()

    def _log(line: str):
        log = jd / "run.log"
        ts = __import__("datetime").datetime.utcnow().strftime("%H:%M:%S")
        with log.open("a") as fp:
            fp.write(f"[{ts}] {line}\n")

    _log(f"[manual-run] executing {script} (target={target}, sage={use_sage})")
    remote_target_start_gate(
        safe, meta.get("module") or "", target, _log, manual=True,
    )
    try:
        res = attempt_sandbox_run(safe, script, target, _log, use_sage=use_sage)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"sandbox spawn failed: {e}")
    if res is None:
        raise HTTPException(status_code=500, detail="script missing at run time")

    flags = scan_job_for_flags(safe)
    new_status = "finished" if flags else "no_flag"
    write_meta(safe, status=new_status, flags=flags, manual_run=True)
    return {"sandbox": res, "flags": flags, "status": new_status}


@router.patch("/{job_id}/target")
async def patch_target(job_id: str, request: Request):
    """Update only `target_url` on an existing job's meta — no retry,
    no resume, no new job enqueued.

    The next manual `/run` (and the default of any future `/retry` /
    `/resume`) picks up the new value. Useful when the original target
    was wrong / the challenge moved / you want to point a finished
    job at a fresh remote without forking the conversation.

    Body (JSON): {"target": "<new>"} — pass the literal string
    "(none)" or an empty string to CLEAR the target.

    Returns: {"ok": true, "target_url": <new>, "prior": <old>}.
    """
    # `Path(job_id).name` strips path separators but doesn't reject
    # ".."/"."/"" — those would resolve to JOBS_DIR's parent or itself.
    # Be explicit so the audit-log open() can't punch out of the dir.
    safe = Path(job_id).name
    if safe in ("", ".", "..") or "/" in safe or "\\" in safe:
        raise HTTPException(status_code=400, detail="invalid job_id")
    meta = read_job_meta(safe)
    if not meta:
        raise HTTPException(status_code=404, detail="job not found")
    try:
        body = await request.json()
    except Exception:
        body = {}
    if "target" not in body and "target_url" not in body:
        raise HTTPException(
            status_code=400,
            detail='request body must include "target" (use "(none)" to clear)',
        )
    raw = body.get("target")
    if raw is None:
        raw = body.get("target_url")
    clean = ("" if raw is None else str(raw)).strip()
    if clean.lower() in ("(none)", "none", ""):
        new_target: str | None = None
        new_targets: list[str] | None = None
    else:
        # Accept several targets (newline / comma separated) — primary is
        # argv[1]/target_url; the rest ride along in target_urls so the next
        # run's TARGETS env still has the full multi-target list.
        parsed = parse_targets(clean)
        new_target = parsed[0] if parsed else None
        new_targets = parsed if len(parsed) >= 2 else None

    prior = meta.get("target_url")
    # IMPORTANT: use modules._common.write_meta (read-merge-write at
    # WRITE time), not api.storage.write_job_meta (which would overwrite
    # the entire file from this snapshot). The worker holds the meta
    # for in-flight jobs and writes heartbeat + cost + status updates
    # constantly; full overwrite from here would clobber any keys the
    # worker added between our read and our write.
    from modules._common import write_meta as _merge_write_meta
    _merge_write_meta(safe, target_url=new_target, target_urls=new_targets)

    # Audit trail in run.log so the change is visible to the reviewer
    # on a future retry and to anyone tailing the run.
    log = JOBS_DIR / safe / "run.log"
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    try:
        with log.open("a") as fp:
            extra = (
                f" (+{len(new_targets) - 1} more)" if new_targets else ""
            )
            fp.write(
                f"[{ts}] [meta] target_url updated by user: "
                f"{prior!r} -> {new_target!r}{extra}\n"
            )
    except OSError:
        pass

    # Status-aware guidance. A RUNNING/queued job's live agent has its target
    # baked into the spawn-time prompt and never re-reads meta mid-run, so this
    # PATCH does NOT reach the in-flight agent — it only affects the next
    # /retry|/resume and the orchestrator's final sandbox run (and that run only
    # if the exploit reads argv[1] — a hardcoded host stays stale). Surface that
    # so the operator isn't misled into thinking a running job just switched
    # targets. (Operator report: "Change Target before a remote test didn't
    # reflect in context.")
    status = (meta.get("status") or "").lower()
    live = status in ("running", "queued", "analyzing", "analyze")
    if new_target is None:
        note = "Target cleared."
    elif status == "running":
        # Two mechanisms reach a LIVE agent, and the difference matters to the
        # operator because one of them can lag for hours:
        #   * the PreToolUse stale-target guard (modules/_common.
        #     stale_target_reason) runs MID-TURN — it denies the agent's very
        #     next Bash call at the superseded endpoint and names the new one.
        #   * the orchestrator's turn-boundary watchdog only runs after
        #     `receive_response()` returns, and ONE receive_response spans the
        #     agent's whole agentic turn. Job 6e434e820b3f sat inside a single
        #     turn for two hours, so it never fired at all.
        # An earlier version of this note promised only the boundary path "so
        # no Retry is needed", which read as "it landed" while main went on
        # polling the dead port. Say what actually bounds the delay.
        note = (
            f"Target set to {new_target}. This job is running: the agent's next "
            "connection attempt at the old endpoint is blocked mid-turn and told "
            "to use this one, so the change lands by the next remote Bash call — "
            "not instantly, and not while it is only thinking. The sandbox runner "
            "also re-reads the target, so an argv[1]-driven exploit picks it up "
            "with no edit; a hardcoded host:port needs the agent to rewrite it. "
            "If the agent is deep in a long non-remote stretch and you need the "
            "switch now, Stop then Continue re-spawns it with the new target."
        )
    elif live:
        note = (
            f"Target set to {new_target} in meta — this job is {status}, so no "
            "agent session exists yet; it will start with the new value."
        )
    else:
        note = (
            f"Target set to {new_target}. The next /retry or /resume picks it "
            "up; 'fresh start' avoids re-inheriting the old target from the "
            "prior conversation."
        )

    return {
        "ok": True,
        "target_url": new_target,
        "target_urls": new_targets,
        "prior": prior,
        "job_status": status,
        # `running` now DOES apply live (the orchestrator injects the new
        # endpoint at the next turn boundary); queued/analyzing has no
        # session yet, so the value is simply read when one starts.
        "applies_live": (not live) or status == "running",
        # The UI used to alert only when applies_live was false, so making
        # `running` live-applying silently removed the ONLY feedback that a
        # target change on a running job landed. Decouple the two: this says
        # "show the note", applies_live says what actually happens.
        "show_note": bool(live),
        "note": note,
    }


def _record_decision(safe: str, decision: str, log_msg: str) -> dict:
    """Clear the awaiting_decision flag and append a run.log line. Returns
    the merged meta on success."""
    meta = read_job_meta(safe)
    if not meta:
        raise HTTPException(status_code=404, detail="job not found")
    merged = {
        **meta,
        "awaiting_decision": False,
        "timeout_decision": decision,
    }
    write_job_meta(safe, merged)

    # Append to run.log so the user can see the decision in the live log
    from datetime import datetime
    log = JOBS_DIR / safe / "run.log"
    try:
        ts = datetime.utcnow().strftime("%H:%M:%S")
        with log.open("a") as fp:
            fp.write(f"[{ts}] {log_msg}\n")
    except Exception:
        pass
    return merged


@router.post("/{job_id}/timeout/continue")
def timeout_continue(job_id: str):
    """User chose to keep the job running past its soft timeout. The
    watchdog has already fired once and will NOT re-fire — the agent
    runs to natural completion (or hits RQ's hard kill ceiling)."""
    safe = Path(job_id).name
    meta = read_job_meta(safe)
    if not meta:
        raise HTTPException(status_code=404, detail="job not found")
    if not meta.get("awaiting_decision"):
        return {"ok": True, "noop": True, "decision": meta.get("timeout_decision")}
    _record_decision(
        safe, "continue",
        "User chose CONTINUE — job keeps running past the soft timeout.",
    )
    return {"ok": True, "decision": "continue"}


@router.post("/{job_id}/timeout/kill")
def timeout_kill(job_id: str):
    """User chose to halt the job. Runs the same hard-stop path as
    DELETE: signals RQ, kills sibling containers."""
    safe = Path(job_id).name
    meta = read_job_meta(safe)
    if not meta:
        raise HTTPException(status_code=404, detail="job not found")
    _record_decision(
        safe, "kill",
        "User chose STOP — halting the job at soft timeout.",
    )
    halt_info = _hard_stop_job(safe)
    # Reflect the cancellation in meta so list/detail endpoints don't
    # keep showing it as 'running'.
    final = read_job_meta(safe) or {}
    write_job_meta(safe, {**final, "status": "failed", "error": "Stopped by user at soft timeout"})
    return {"ok": True, "decision": "kill", "halt": halt_info}
