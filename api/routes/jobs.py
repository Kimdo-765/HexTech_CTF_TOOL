import asyncio
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse

from api.queue import get_queue, get_redis
from api.storage import JOBS_DIR, parse_targets, read_job_meta, write_job_meta

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


def _hard_stop_job(job_id: str) -> dict:
    """Try to actually halt work on a running job:
    1. Send STOP_JOB command to whichever worker is running it (RQ pub-sub).
    2. Find sibling docker containers labelled hextech_ctf_tool_job_id=<id> and
       force-remove them (decompiler / forensic / misc / runner).
    Errors are swallowed — best-effort.
    """
    info: dict = {"sent_stop": False, "containers_killed": 0, "rq_cancelled": False}
    conn = get_redis()
    # 1) Tell RQ to interrupt the running job. send_stop_job_command works only
    #    on running jobs; for queued ones, plain cancel() is enough.
    try:
        from rq.command import send_stop_job_command
        send_stop_job_command(conn, job_id)
        info["sent_stop"] = True
    except Exception:
        pass
    try:
        from rq.job import Job
        rq_job = Job.fetch(job_id, connection=conn)
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
        for c in containers:
            try:
                c.kill()
            except Exception:
                pass
            try:
                c.remove(force=True)
                info["containers_killed"] += 1
            except Exception:
                pass
    except Exception:
        pass

    return info


@router.get("")
def list_jobs():
    if not JOBS_DIR.exists():
        return {"jobs": []}
    out = []
    for d in sorted(JOBS_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        meta = read_job_meta(d.name)
        if meta:
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
    by_module: dict[str, dict] = {}
    count = 0
    for d in JOBS_DIR.iterdir():
        if not d.is_dir():
            continue
        meta_path = d / "meta.json"
        result_path = d / "result.json"
        if not meta_path.exists():
            continue
        try:
            meta = json.loads(meta_path.read_text())
        except Exception:
            continue
        count += 1
        module = meta.get("module", "unknown")
        bucket = by_module.setdefault(module, {"count": 0, "cost_usd": 0.0})
        bucket["count"] += 1
        cost = float(meta.get("cost_usd") or 0.0)
        if cost == 0.0 and result_path.exists():
            try:
                result = json.loads(result_path.read_text())
                cost = float(result.get("cost_usd") or 0.0)
            except Exception:
                pass
        bucket["cost_usd"] += cost
        total += cost
    return {"total_cost_usd": round(total, 4), "by_module": by_module, "count": count}


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
    rq_worker_heartbeat = None
    try:
        q = get_queue()
        rq_job = q.fetch_job(job_id)
        if rq_job is not None:
            rq_status = rq_job.get_status(refresh=True)
            rq_worker_name = rq_job.worker_name
    except Exception:
        pass

    # Pull the assigned worker's last_heartbeat directly from Redis so
    # the UI can tell "agent silent but worker alive" apart from
    # "worker process dead". RQ refreshes this every ~10s while the
    # worker is healthy.
    if rq_worker_name:
        try:
            conn = get_redis()
            hb = conn.hget(f"rq:worker:{rq_worker_name}", "last_heartbeat")
            if hb:
                rq_worker_heartbeat = hb.decode() if isinstance(hb, bytes) else hb
        except Exception:
            pass

    # Always derive a `runnable_script` field from the filesystem so the UI
    # can show the run-now button even on jobs whose meta was written before
    # the field existed (or whose orchestrator didn't set it).
    _jd = JOBS_DIR / Path(job_id).name
    runnable_script = _detect_runnable_script(_jd)

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
        **meta,
        "rq_status": rq_status,
        "rq_worker_name": rq_worker_name,
        "rq_worker_heartbeat_at": rq_worker_heartbeat,
        "runnable_script": runnable_script,
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
        # Halt running/queued jobs: stop the worker + kill sibling containers
        if st in ("queued", "running"):
            _hard_stop_job(d.name)
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
    shutil.rmtree(d)
    return {"deleted": safe, "halt": halt_info}


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

    def sse(name: str, data) -> bytes:
        return f"event: {name}\ndata: {json.dumps(data)}\n\n".encode()

    async def event_gen():
        from redis import asyncio as aioredis
        r = aioredis.from_url(REDIS_URL)
        pubsub = r.pubsub()
        try:
            # Subscribe BEFORE backfill so any event published between
            # backfill-read and subscribe is buffered (Redis pubsub is
            # ephemeral but the gap here is microseconds).
            await pubsub.subscribe(
                f"job:{safe}:log",
                f"job:{safe}:meta",
                f"job:{safe}:sdk",
            )

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
    target = (target or meta.get("target_url") or "").strip() or None

    # Sandbox runner spawn (same path the orchestrators use)
    from modules._common import scan_job_for_flags, write_meta
    from modules._runner import attempt_sandbox_run
    from modules.settings_io import apply_to_env

    # Pull settings (CALLBACK_URL etc.) into this process's env so the
    # runner spawn picks them up, mirroring what worker run_job() does.
    apply_to_env()

    def _log(line: str):
        log = jd / "run.log"
        ts = __import__("datetime").datetime.utcnow().strftime("%H:%M:%S")
        with log.open("a") as fp:
            fp.write(f"[{ts}] {line}\n")

    _log(f"[manual-run] executing {script} (target={target}, sage={use_sage})")
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

    return {
        "ok": True,
        "target_url": new_target,
        "target_urls": new_targets,
        "prior": prior,
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
