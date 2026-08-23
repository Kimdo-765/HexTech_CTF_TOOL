import gzip
import multiprocessing
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, "/app")
from modules.settings_io import get_setting  # noqa: E402

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
JOBS_DIR = Path("/data/jobs")
MEASUREMENT_ARCHIVE_DIR = JOBS_DIR.parent / "job-measurements"
MEASUREMENT_ARTIFACTS = ("events.jsonl", "meta.json", "run.log")
CLEANUP_INTERVAL_S = 3600


# --- slot identity -----------------------------------------------------------
# Set by docker-compose (WORKER_SLOT=1|2). Empty means the legacy single-worker
# container: one process tree forking WORKER_CONCURRENCY children. Both shapes
# are supported so this file still runs against an older compose file.
SLOT = (os.environ.get("WORKER_SLOT") or "").strip()


def _name_prefix() -> str:
    """RQ worker-name prefix OWNED BY THIS CONTAINER.

    Slot mode namespaces the name (`htct-s1-w0`) for one reason that matters
    more than readability: `_sweep_stale_workers()` deletes every registration
    matching the prefix on boot. With the legacy flat `htct-w*` every slot
    would wipe the OTHER slot's LIVE registration on restart, and RQ would
    treat a perfectly healthy worker as dead.
    """
    return f"htct-s{SLOT}-w" if SLOT else "htct-w"


def _worker_name(idx: int) -> str:
    return f"{_name_prefix()}{idx}"


def _resolve_concurrency() -> int:
    # Slot mode: exactly one RQ process per container, non-negotiable. The
    # `worker_concurrency` SETTING cannot be honoured here — settings_io's
    # precedence is file > env > default, and /data/settings.json still holds
    # the pre-split value (3), which would put three jobs back inside every
    # slot and defeat both the per-job memory bound and the PID isolation.
    if SLOT:
        val = get_setting("worker_concurrency")
        if str(val or "") not in ("", "1"):
            print(
                f"[worker] slot {SLOT}: ignoring worker_concurrency={val} "
                f"(one job per slot container; concurrency is the SLOT COUNT "
                f"in docker-compose.yml, not a per-container setting)",
                flush=True,
            )
        return 1

    val = get_setting("worker_concurrency")
    try:
        n = int(val) if val is not None else 0
    except (TypeError, ValueError):
        n = 0
    if n <= 0:
        n = int(os.environ.get("WORKER_CONCURRENCY", "3") or 3)
    return max(1, n)


def _runs_cleanup() -> bool:
    """Elect one cleanup owner across split worker containers."""
    return not SLOT or SLOT == "1"


def _promote_measurement_artifacts(job_dir: Path) -> tuple[str, ...]:
    """Best-effort copy of the durable measurement corpus before TTL removal.

    The archive is deliberately a SIBLING of ``jobs``.  ``cleanup_loop`` only
    walks ``JOBS_DIR``, so an old archive cannot be selected on the next TTL
    cycle.  Copy through a same-directory temporary file and replace the final
    name only after the copy completes; an interrupted copy must not masquerade
    as a complete measurement artifact.

    Promotion is observability, not a retention lock: every failure is logged,
    but the caller still removes the expired job as the existing TTL contract
    requires.
    """
    target_dir = MEASUREMENT_ARCHIVE_DIR / job_dir.name
    promoted: list[str] = []
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(
            f"[cleanup] measurement promotion failed for {job_dir}: "
            f"archive directory: {e}",
            flush=True,
        )
        return ()

    for name in MEASUREMENT_ARTIFACTS:
        source = job_dir / name
        if not source.is_file():
            continue
        archive_name = "run.log.gz" if name == "run.log" else name
        temporary = target_dir / (
            f".{archive_name}.tmp-{os.getpid()}-{threading.get_ident()}"
        )
        try:
            if name == "run.log":
                # The log is the only unbounded measurement artifact.  Gzip is
                # lossless for the offline classifier and avoids turning the
                # sibling archive into another linear disk-growth source.
                with source.open("rb") as src, temporary.open("wb") as raw:
                    with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as dst:
                        shutil.copyfileobj(src, dst)
                shutil.copystat(source, temporary)
            else:
                shutil.copy2(source, temporary)
            os.replace(temporary, target_dir / archive_name)
            promoted.append(archive_name)
        except Exception as e:
            try:
                temporary.unlink(missing_ok=True)
            except Exception:
                pass
            print(
                f"[cleanup] measurement promotion failed for {job_dir}: "
                f"{name}: {e}",
                flush=True,
            )
    return tuple(promoted)


def _cleanup_expired_jobs(ttl: int, *, now: datetime | None = None) -> int:
    """Run one TTL sweep and return the number of removed job directories."""
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=ttl)
    removed = 0
    if not JOBS_DIR.exists():
        try:
            from modules.job_secrets import cleanup_orphaned_secrets

            cleanup_orphaned_secrets(older_than_epoch=cutoff.timestamp())
        except Exception as e:
            print(f"[cleanup] orphan secret sweep failed: {e}", flush=True)
        return removed
    for d in JOBS_DIR.iterdir():
        if not d.is_dir():
            continue
        mtime = datetime.fromtimestamp(d.stat().st_mtime, tz=timezone.utc)
        if mtime >= cutoff:
            continue
        _promote_measurement_artifacts(d)
        try:
            shutil.rmtree(d)
        except Exception as e:
            print(f"[cleanup] failed to rm {d}: {e}", flush=True)
            continue
        removed += 1
        try:
            from modules.job_secrets import delete_job_secrets

            delete_job_secrets(d.name)
        except Exception as e:
            print(f"[cleanup] secret delete failed for {d.name}: {e}", flush=True)
    try:
        from modules.job_secrets import cleanup_orphaned_secrets

        cleanup_orphaned_secrets(older_than_epoch=cutoff.timestamp())
    except Exception as e:
        print(f"[cleanup] orphan secret sweep failed: {e}", flush=True)
    return removed


def cleanup_loop() -> None:
    while True:
        try:
            ttl = int(get_setting("job_ttl_days") or 0)
            if ttl <= 0:
                time.sleep(CLEANUP_INTERVAL_S)
                continue
            removed = _cleanup_expired_jobs(ttl)
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
    name = _worker_name(idx)
    print(f"[worker] {name} starting (scheduler={scheduler})", flush=True)
    Worker([q], connection=conn, name=name).work(with_scheduler=scheduler)


def _sweep_stale_workers() -> None:
    """Wipe leftover RQ registrations from a prior life OF THIS CONTAINER.

    Worker names are fixed, so on boot any pre-existing `rq:worker:<our
    prefix>*` in redis is a corpse from a SIGKILL'd previous life. RQ's
    `register_birth()` refuses to start when the key still exists, sending the
    parent into an infinite "exited code=1; respawning" loop.

    SCOPE IS THE WHOLE POINT. The sweep must match only names this container
    owns. The pre-slot version matched `htct-w*` unconditionally, which was
    correct when there was exactly one worker container and is a live-data
    deletion the moment there are two: slot 2 booting (a routine deploy, since
    deploy.sh now restarts idle slots individually) would delete slot 1's
    REGISTRATION WHILE IT RUNS A JOB.

    Slot 1 additionally sweeps the legacy flat `htct-w*` prefix — those keys
    are left over from the single-container era and, once every slot uses a
    namespaced prefix, nothing else would ever reap them. They would sit in
    `rq:workers` forever and inflate restart.sh's worker count.

    Best-effort delete; don't fail boot if redis is unreachable.
    """
    patterns = [f"rq:worker:{_name_prefix()}*"]
    if SLOT == "1":
        patterns.append("rq:worker:htct-w*")

    try:
        from redis import Redis

        conn = Redis.from_url(REDIS_URL)
        keys: list = []
        for pat in patterns:
            keys.extend(conn.scan_iter(match=pat))
        keys = list(dict.fromkeys(keys))
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


def _preinit_wine_prefix() -> None:
    """Settle the Wine prefix's first-run init to a controlled point, once.

    Native-PE rev jobs run the real .exe under `wine` / `xvfb-run` (Tier C).
    The prefix is deliberately NOT baked into the image (~1.4 GB); it inits
    lazily on first use. Doing that init HERE — once, in the parent at startup,
    before any job's agent can touch wine — means the first agent `wine app.exe`
    finds a ready WINEARCH=win64 prefix instead of racing / overlapping an
    on-demand `wineboot`. That overlap is the most plausible cause of the wine
    segfaults that made job 0d0c3de3fbfb misdiagnose wine as unusable (seccomp)
    and abandon dynamic rendering — the exact capability Tier C added. NOTE the
    crash was NOT reproducible on demand (7 negative repros incl. the job's
    exact sequence), so this is DEFENSIVE / cause-unconfirmed: cheap, idempotent
    and timeout-bounded so a wedged headless `wineboot` can NEVER hang worker
    startup. Best-effort throughout — any failure logs a WARN and the lazy
    first-use path still applies.
    """
    if not shutil.which("wine"):
        return  # Tier C wine layer absent (WARN-masked build) — nothing to do.
    prefix = os.environ.get("WINEPREFIX", "/root/.wine")
    # XDG_RUNTIME_DIR silences Wine's "invalid or not set" warning (cosmetic;
    # all repros were rc=0 without it). setdefault so an operator override wins.
    xrt = os.environ.setdefault("XDG_RUNTIME_DIR", "/run/user/0")
    try:
        os.makedirs(xrt, mode=0o700, exist_ok=True)
        os.chmod(xrt, 0o700)
    except OSError:
        pass
    # Idempotent: a prefix already up as win64 is left untouched, so a plain
    # `restart worker` (writable layer persists /root/.wine) skips instantly;
    # only a fresh / force-recreated container pays the one-time ~15 s init.
    sysreg = Path(prefix) / "system.reg"

    def _is_win64() -> bool:
        try:
            return sysreg.is_file() and "#arch=win64" in sysreg.read_text(
                errors="ignore"
            )[:4096]
        except OSError:
            return False

    if _is_win64():
        print("[worker] wine prefix ready (win64)", flush=True)
        return
    print("[worker] pre-initialising wine prefix (once) ...", flush=True)
    try:
        # wineboot touches an X display → run under a throwaway Xvfb. `timeout`
        # bounds DURATION (|| true would only bound exit status, not a hang).
        subprocess.run(
            ["xvfb-run", "-a", "wineboot", "--init"],
            timeout=180,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Block until wineserver settles so the prefix is fully written.
        subprocess.run(
            ["wineserver", "-w"],
            timeout=60,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        print(
            "[worker] [WARN] wine prefix pre-init timed out; lazy init on first use",
            flush=True,
        )
        return
    except Exception as e:  # noqa: BLE001 — must never block worker startup
        print(
            f"[worker] [WARN] wine prefix pre-init failed ({e}); lazy init on first use",
            flush=True,
        )
        return
    # Verify win64 (the trixie win32-default gotcha: a silently-created win32
    # prefix would abort every x64 PE — treat it as not-ready so first use re-inits).
    print(
        "[worker] wine prefix "
        + ("OK (win64)" if _is_win64() else "[WARN] not win64; lazy re-init on first use"),
        flush=True,
    )


def _runs_scheduler(idx: int) -> bool:
    """Exactly ONE RQ scheduler across the whole deployment.

    Pinned to slot 1 (or worker 0 in legacy single-container mode). Slot 1 is
    now restarted independently by deploy.sh, so the scheduler is briefly down
    on those deploys.

    That is harmless TODAY because nothing in this codebase gives the scheduler
    anything to do. Checked, and all three ways it could matter are absent:
      * no `enqueue_in` / `enqueue_at` caller anywhere;
      * no `retry=Retry(...)` on any `q.enqueue()` — every call site passes
        only `job_id` and `job_timeout` (RQ re-enqueues an interval-based
        Retry from the scheduler thread, so this one is easy to miss);
      * no cron / repeat registration.
    Add any of those and this pin becomes a real availability question.
    """
    if SLOT:
        return SLOT == "1" and idx == 0
    return idx == 0


def main() -> int:
    n = _resolve_concurrency()
    where = f"slot {SLOT}" if SLOT else "single-container mode"
    print(
        f"[worker] {where}: launching {n} worker process(es) "
        f"as {_name_prefix()}0..{n - 1}",
        flush=True,
    )

    # Clear this container's own stale `rq:worker:*` keys from a SIGKILL'd
    # previous boot before children try to register their birth — otherwise RQ
    # throws "There exists an active worker named ... already" and the parent
    # respawns forever.
    _sweep_stale_workers()
    # Clean leftover /tmp debris from previous container lives. Empty
    # on a freshly-built image; only matters after `docker compose
    # restart worker` on a long-running deployment.
    _sweep_stale_tmp()
    # Settle the Wine prefix ONCE before any job can race it (native-PE rev
    # Tier C). Idempotent + timeout-bounded; a no-op when wine is absent or the
    # prefix is already win64-ready.
    _preinit_wine_prefix()

    # Cleanup runs in one parent only.  Both split-slot containers mount the
    # same /data tree; letting both promote and remove the same directory races
    # archive writes against rmtree.  Slot 1 already owns the single scheduler,
    # and the legacy one-container shape remains unchanged.
    if _runs_cleanup():
        threading.Thread(target=cleanup_loop, daemon=True).start()

    # Use spawn (not fork) to avoid copying threading state and any FDs
    # that should not be shared (docker-py http client, redis pool, etc).
    ctx = multiprocessing.get_context("spawn")
    procs: list[multiprocessing.process.BaseProcess] = []
    for i in range(n):
        p = ctx.Process(
            target=run_one_worker,
            args=(i, _runs_scheduler(i)),
            name=_worker_name(i),
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
        # the children, and this slot's `rq:worker:*` keys leak into redis;
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
                    args=(i, _runs_scheduler(i)),
                    name=_worker_name(i),
                )
                np.start()
                procs[i] = np
    return 0


if __name__ == "__main__":
    sys.exit(main())
