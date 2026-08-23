"""Cross-process acknowledgement for Codex turn teardown.

The worker-side adapter holds an exclusive ``flock`` for the whole lifetime of
the Codex CLI subprocess.  The descriptor is inherited by the CLI, so killing
the RQ workhorse cannot make the lock look free while the actual writer still
has the shared Codex thread store open.

The API-side stop-and-resume path waits until it can take the same lock before
it creates a successor job.  This is deliberately job-scoped: CODEX_HOME stays
shared, preserving cross-worker resume semantics.
"""

from __future__ import annotations

import fcntl
import os
import time
from pathlib import Path
from typing import BinaryIO


TURN_LOCK_FILENAME = ".codex-turn.lock"
TURN_STOP_FILENAME = ".codex-stop-requested"


class CodexTurnStopRequested(RuntimeError):
    pass


def request_turn_stop(work_dir: Path) -> None:
    """Fence future Codex launches for a source job before signalling RQ."""

    work_dir.mkdir(parents=True, exist_ok=True)
    path = work_dir / TURN_STOP_FILENAME
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, b"stop\n")
        os.fsync(fd)
    finally:
        os.close(fd)


def clear_turn_stop(work_dir: Path) -> None:
    (work_dir / TURN_STOP_FILENAME).unlink(missing_ok=True)


def acquire_turn_guard(work_dir: Path) -> BinaryIO:
    """Acquire and return the worker-side guard handle.

    The caller must keep the returned handle open until the CLI process is
    reaped.  ``pass_fds=(handle.fileno(),)`` extends that ownership across an
    abrupt workhorse exit.
    """

    work_dir.mkdir(parents=True, exist_ok=True)
    stop_path = work_dir / TURN_STOP_FILENAME
    if stop_path.exists():
        raise CodexTurnStopRequested("operator stop was requested before Codex launch")
    path = work_dir / TURN_LOCK_FILENAME
    handle = path.open("a+b")
    os.chmod(path, 0o600)
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        # Closes the check→lock race with request_turn_stop(): if the API wrote
        # the fence while this worker was waiting, do not spawn after the old
        # writer finally releases the lock.
        if stop_path.exists():
            raise CodexTurnStopRequested(
                "operator stop was requested while Codex launch was waiting"
            )
    except BaseException:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        handle.close()
        raise
    return handle


def release_turn_guard(handle: BinaryIO | None) -> None:
    if handle is None:
        return
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def wait_for_turn_teardown(
    work_dir: Path,
    *,
    timeout_s: float,
    poll_interval_s: float = 0.05,
) -> tuple[bool, float]:
    """Wait for the Codex CLI's inherited guard to become acquirable.

    A missing guard means no Codex subprocess has entered this job.  An
    existing but unlocked file is also an acknowledgement; guard files are
    intentionally durable and contain no data.
    """

    started = time.monotonic()
    path = work_dir / TURN_LOCK_FILENAME
    if not path.exists():
        return True, 0.0

    handle = path.open("a+b")
    deadline = started + max(0.0, float(timeout_s))
    try:
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                now = time.monotonic()
                if now >= deadline:
                    return False, now - started
                time.sleep(min(max(0.001, poll_interval_s), deadline - now))
                continue
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            return True, time.monotonic() - started
    finally:
        handle.close()
