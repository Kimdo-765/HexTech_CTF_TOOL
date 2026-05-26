import multiprocessing
import os
import shutil
import signal
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, "/app")
from modules.settings_io import get_setting  # noqa: E402

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
JOBS_DIR = Path("/data/jobs")
CLEANUP_INTERVAL_S = 3600


def _resolve_concurrency() -> int:
    val = get_setting("worker_concurrency")
    try:
        n = int(val) if val is not None else 0
    except (TypeError, ValueError):
        n = 0
    if n <= 0:
        n = int(os.environ.get("WORKER_CONCURRENCY", "3") or 3)
    return max(1, n)


def cleanup_loop() -> None:
    while True:
        try:
            ttl = int(get_setting("job_ttl_days") or 0)
            if ttl <= 0:
                time.sleep(CLEANUP_INTERVAL_S)
                continue
            cutoff = datetime.now(timezone.utc) - timedelta(days=ttl)
            removed = 0
            if JOBS_DIR.exists():
                for d in JOBS_DIR.iterdir():
                    if not d.is_dir():
                        continue
                    mtime = datetime.fromtimestamp(d.stat().st_mtime, tz=timezone.utc)
                    if mtime < cutoff:
                        try:
                            shutil.rmtree(d)
                            removed += 1
                        except Exception as e:
                            print(f"[cleanup] failed to rm {d}: {e}", flush=True)
            if removed:
                print(f"[cleanup] removed {removed} jobs older than {ttl}d", flush=True)
        except Exception as e:
            print(f"[cleanup] loop error: {e}", flush=True)
        time.sleep(CLEANUP_INTERVAL_S)


def run_one_worker(idx: int, scheduler: bool) -> None:
    """Worker process target. Reimport everything inside the child so
    state isn't shared across processes (cleaner for the SDK + docker-py
    clients which open file descriptors)."""
    from redis import Redis
    from rq import Queue, Worker

    conn = Redis.from_url(REDIS_URL)
    q = Queue("hextech_ctf_tool", connection=conn)
    name = f"htct-w{idx}"
    print(f"[worker] {name} starting (scheduler={scheduler})", flush=True)
    Worker([q], connection=conn, name=name).work(with_scheduler=scheduler)


def _sweep_stale_workers() -> None:
    """Wipe leftover `rq:worker:htct-w*` registrations from a prior
    container life.

    Worker names are fixed (htct-w0..N) and there is exactly one worker
    container, so on every boot any pre-existing `rq:worker:htct-w*` in
    redis is a corpse from a SIGKILL'd previous life. RQ's
    `register_birth()` refuses to start when the key still exists,
    sending the parent into an infinite "exited code=1; respawning"
    loop. Best-effort delete; don't fail boot if redis is unreachable.
    """
    try:
        from redis import Redis

        conn = Redis.from_url(REDIS_URL)
        keys = list(conn.scan_iter(match="rq:worker:htct-w*"))
        if not keys:
            return
        names = [k.decode().rsplit(":", 1)[1] for k in keys]
        pipe = conn.pipeline()
        for k in keys:
            pipe.delete(k)
        for n in names:
            pipe.srem("rq:workers", n)
        pipe.execute()
        print(
            f"[worker] swept {len(names)} stale RQ registration(s): "
            f"{','.join(names)}",
            flush=True,
        )
    except Exception as e:
        print(f"[worker] sweep failed (non-fatal): {e}", flush=True)


def _sweep_stale_tmp(max_age_h: int = 24) -> None:
    """Best-effort: rm files in `/tmp` older than `max_age_h` hours
    that the worker container itself wrote.

    The agent + every subagent share `/tmp`, and despite the
    `$TMPDIR=./tmp/` env hint in prompts they still routinely
    drop `/tmp/probe.py`, `/tmp/dis.txt`, `cpio` extracts, gdb
    init scripts, etc. directly via Bash. Over days the dir hits
    30+ MB of stale files; concrete incident 2026-05-17 in job
    9a240a221f1b showed a fresh debugger spawn listing `clobber.py`
    + `debug_leak.py` from yesterday's run, which could
    accidentally feed into a new probe.

    We DO NOT touch:
      * directories (`/tmp/initrd_extract`, gdb temp roots) — those
        often hold the *current* job's working state
      * files newer than `max_age_h` hours (default 24)
      * `.X11*` / `systemd-private-*` / `snap-*` / standard daemon
        socket dirs (none expected in our base image, but exclude
        defensively)
    Failures are logged and swallowed — `/tmp` cleanup must never
    block worker boot.
    """
    tmp_root = Path("/tmp")
    if not tmp_root.is_dir():
        return
    cutoff = time.time() - max_age_h * 3600
    removed = 0
    bytes_freed = 0
    skip_prefixes = (".X1", "systemd-", "snap-", ".font-", ".ICE-")
    try:
        for entry in tmp_root.iterdir():
            try:
                name = entry.name
                if any(name.startswith(p) for p in skip_prefixes):
                    continue
                if entry.is_dir() or entry.is_symlink():
                    continue
                st = entry.stat()
                if st.st_mtime >= cutoff:
                    continue
                size = st.st_size
                entry.unlink()
                removed += 1
                bytes_freed += size
            except OSError:
                continue
    except OSError as e:
        print(f"[worker] /tmp sweep failed (non-fatal): {e}", flush=True)
        return
    if removed:
        print(
            f"[worker] swept {removed} stale /tmp file(s) "
            f"({bytes_freed / 1024:.1f} KB freed)",
            flush=True,
        )


def main() -> int:
    n = _resolve_concurrency()
    print(f"[worker] launching {n} worker process(es)", flush=True)

    # Clear any stale `rq:worker:htct-w*` from a SIGKILL'd previous boot
    # before children try to register their birth — otherwise RQ throws
    # "There exists an active worker named ... already" and the parent
    # respawns forever.
    _sweep_stale_workers()
    # Clean leftover /tmp debris from previous container lives. Empty
    # on a freshly-built image; only matters after `docker compose
    # restart worker` on a long-running deployment.
    _sweep_stale_tmp()

    # Cleanup thread runs in the parent only.
    threading.Thread(target=cleanup_loop, daemon=True).start()

    # Use spawn (not fork) to avoid copying threading state and any FDs
    # that should not be shared (docker-py http client, redis pool, etc).
    ctx = multiprocessing.get_context("spawn")
    procs: list[multiprocessing.process.BaseProcess] = []
    for i in range(n):
        p = ctx.Process(
            target=run_one_worker,
            args=(i, i == 0),  # only worker 0 runs the RQ scheduler
            name=f"htct-w{i}",
        )
        p.start()
        procs.append(p)

    def _shutdown(signum, frame):
        print(f"[worker] shutdown signal {signum}, terminating children", flush=True)
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        # Give children up to 10s to call RQ's register_death() —
        # without this the parent exits, container teardown SIGKILLs
        # the children, and `rq:worker:htct-w*` keys leak into redis;
        # next boot then loops on "name already exists".
        deadline = time.time() + 10
        for p in procs:
            remaining = max(0.0, deadline - time.time())
            try:
                p.join(timeout=remaining)
            except Exception:
                pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    # Reap children. If any dies unexpectedly, log and respawn.
    while procs:
        for i, p in enumerate(list(procs)):
            p.join(timeout=1)
            if not p.is_alive():
                print(f"[worker] {p.name} exited code={p.exitcode}; respawning", flush=True)
                np = ctx.Process(
                    target=run_one_worker,
                    args=(i, i == 0),
                    name=f"htct-w{i}",
                )
                np.start()
                procs[i] = np
    return 0


if __name__ == "__main__":
    sys.exit(main())
