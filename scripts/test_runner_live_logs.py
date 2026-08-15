#!/usr/bin/env python3
"""Runner stdout/stderr reaches the raw job log while the sandbox is alive.

No Docker daemon is needed: the fixtures expose the same ``logs/reload/wait``
surface consumed by ``modules._runner``. ``--mutate stream-order`` disables
the timestamp merge in the test process; the named interleaving check must
then fail, proving that the test guards the production fix.

Run:  python3 scripts/test_runner_live_logs.py [--mutate stream-order]
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

parser = argparse.ArgumentParser()
parser.add_argument(
    "--mutate",
    choices=("none", "stream-order", "not-found-is-unknown"),
    default="none",
)
args = parser.parse_args()


def _missing(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is None
    except (ImportError, ValueError):
        return True


if _missing("docker"):
    docker = types.ModuleType("docker")
    docker.from_env = lambda *a, **k: None
    sys.modules["docker"] = docker

if _missing("claude_agent_sdk"):
    sdk = types.ModuleType("claude_agent_sdk")
    for name in (
        "AssistantMessage", "ClaudeAgentOptions", "ResultMessage",
        "SystemMessage", "TextBlock", "ClaudeSDKClient", "UserMessage",
    ):
        setattr(sdk, name, type(name, (), {"__init__": lambda self, **kw: None}))

    async def _query(*_args, **_kwargs):  # pragma: no cover
        if False:
            yield None

    sdk.query = _query
    for name in ("HookMatcher", "AgentDefinition"):
        setattr(sdk, name, type(name, (), {"__init__": lambda self, **kw: None}))
    sdk.create_sdk_mcp_server = lambda *a, **k: None
    sdk.tool = lambda *a, **k: (lambda fn: fn)
    sdk.project_key_for_directory = lambda *a, **k: ""
    sys.modules["claude_agent_sdk"] = sdk

from modules import _runner as R  # noqa: E402

_InjectedNotFound = R._DockerNotFound

if args.mutate == "stream-order":
    # Test-process mutation only: production contains no mutation switch.
    R._order_live_sandbox_events = lambda events: events
elif args.mutate == "not-found-is-unknown":
    # Test-process mutation only: make the production NotFound handler miss the
    # injected 404 so it falls through to the old generic-unknown behavior.
    R._DockerNotFound = type("NeverRaisedNotFound", (Exception,), {})

passed = failed = 0


def check(label, got, want):
    global passed, failed
    if got == want:
        passed += 1
    else:
        failed += 1
        print(f"FAIL  {label}\n      got  = {got!r}\n      want = {want!r}")


class SnapshotContainer:
    def __init__(self, stdout=b"", stderr=b""):
        self.stdout = stdout
        self.stderr = stderr

    def logs(self, *, stdout=False, stderr=False, timestamps=False):
        if not timestamps:
            raise AssertionError("live forwarding must request Docker timestamps")
        if stdout and not stderr:
            return self.stdout
        if stderr and not stdout:
            return self.stderr
        raise AssertionError("live forwarding must fetch separated streams")


def stamped(nanosecond: int, payload: bytes) -> bytes:
    return b"2026-08-10T13:20:36." + f"{nanosecond:09d}".encode() + b"Z " + payload


# Incremental snapshots are not replayed; a partial line joins the next poll.
container = SnapshotContainer(
    stamped(100_000_000, b"out-one\n") + stamped(300_000_000, b"partial"),
    stamped(200_000_000, b"err-one\n"),
)
state = {}
lines: list[str] = []
check(
    "first poll reports both stream sizes",
    R._forward_live_sandbox_logs(container, state, lines.append),
    (True, len(container.stdout) + len(container.stderr)),
)
check(
    "only complete lines are visible during the run",
    lines,
    ["[runner:stdout] out-one", "[runner:stderr] err-one"],
)

container.stdout += b"-done\n" + stamped(400_000_000, b"out-two\n")
R._forward_live_sandbox_logs(container, state, lines.append)
R._forward_live_sandbox_logs(container, state, lines.append)
check(
    "new bytes appear once and retain their stdout prefix",
    lines,
    [
        "[runner:stdout] out-one",
        "[runner:stderr] err-one",
        "[runner:stdout] partial-done",
        "[runner:stdout] out-two",
    ],
)

# Exit flushes a final non-newline message instead of losing it.
container.stderr += stamped(500_000_000, b"last-error-without-newline")
R._forward_live_sandbox_logs(container, state, lines.append, flush=True)
check("exit flush keeps a partial stderr line", lines[-1],
      "[runner:stderr] last-error-without-newline")
before = list(lines)
R._forward_live_sandbox_logs(container, state, lines.append, flush=True)
check("repeated final snapshots stay idempotent", lines, before)

# The separate Docker reads arrive grouped by stream. Timestamp merge restores
# the daemon's cross-stream occurrence order within one poll.
interleaved = SnapshotContainer(
    stamped(100_000_000, b"OUT-0\n") + stamped(300_000_000, b"OUT-1\n"),
    stamped(200_000_000, b"ERR-0\n") + stamped(400_000_000, b"ERR-1\n"),
)
interleaved_lines: list[str] = []
R._forward_live_sandbox_logs(interleaved, {}, interleaved_lines.append)
check(
    "interleaved streams follow Docker timestamp order",
    interleaved_lines,
    [
        "[runner:stdout] OUT-0",
        "[runner:stderr] ERR-0",
        "[runner:stdout] OUT-1",
        "[runner:stderr] ERR-1",
    ],
)


class ExitBetweenPollsContainer(SnapshotContainer):
    status = "running"

    def __init__(self):
        super().__init__()
        self.poll = 0

    def reload(self):
        self.poll += 1
        if self.poll == 1:
            self.stdout = (
                stamped(100_000_000, b"started\n")
                + stamped(200_000_000, b"unfinished")
            )
        else:
            self.stdout += b"-done\n"
            self.stderr = stamped(300_000_000, b"final-warning")
            self.status = "exited"

    def wait(self, **_kwargs):
        return {"StatusCode": 0}

    def kill(self):
        raise AssertionError("a normally exited fixture must not be killed")


wait_lines: list[str] = []
old_interval = R._POLL_INTERVAL_S
try:
    R._POLL_INTERVAL_S = 0
    result = R._wait_with_supervise(
        ExitBetweenPollsContainer(),
        timeout_s=10,
        job_dir_path=ROOT,
        script_rel="exploit.py",
        log_fn=wait_lines.append,
        enable_supervise=False,
    )
finally:
    R._POLL_INTERVAL_S = old_interval

check("W2-2c normal exit preserves the sandbox StatusCode", result["StatusCode"], 0)
check(
    "output written immediately before exit is flushed to the raw log",
    wait_lines,
    [
        "[runner:stdout] started",
        "[runner:stdout] unfinished-done",
        "[runner:stderr] final-warning",
    ],
)


class VanishedContainer:
    status = "running"

    def __init__(self):
        self.log_calls = 0
        self.remove_calls = 0
        self.kill_calls = 0

    def reload(self):
        raise _InjectedNotFound("No such container")

    def logs(self, **_kwargs):
        self.log_calls += 1
        raise _InjectedNotFound("No such container")

    def remove(self, **_kwargs):
        self.remove_calls += 1

    def kill(self):
        self.kill_calls += 1


# W2-2a: a Docker 404 is a third terminal outcome, distinct from timeout and
# normal exit.  The two log calls prove the last stdout/stderr flush was tried.
vanished = VanishedContainer()
vanished_lines: list[str] = []
result = R._wait_with_supervise(
    vanished,
    timeout_s=0,
    job_dir_path=ROOT,
    script_rel="exploit.py",
    log_fn=vanished_lines.append,
    enable_supervise=False,
)
check(
    "W2-2a Docker 404 returns immediately as disappeared, not timeout",
    (result.get("container_disappeared"), result.get("timeout"), vanished.kill_calls),
    (True, None, 0),
)
check("W2-2a Docker 404 still attempts the final two-stream flush",
      vanished.log_calls, 2)
check("W2-2a Docker 404 is operator-visible in the runner log",
      vanished_lines, ["[runner] container disappeared (Docker 404) — stopping wait"])


class TransientReloadContainer(SnapshotContainer):
    status = "running"

    def __init__(self):
        super().__init__(stdout=stamped(100_000_000, b"kept-running\n"))
        self.reloads = 0

    def reload(self):
        self.reloads += 1
        if self.reloads == 1:
            raise OSError("temporary docker socket hiccup")
        self.status = "exited"

    def wait(self, **_kwargs):
        return {"StatusCode": 7}

    def kill(self):
        raise AssertionError("a transient reload error must not kill the runner")


# W2-2b: a non-404 exception retains the old unknown-and-repoll behavior.
transient = TransientReloadContainer()
old_interval = R._POLL_INTERVAL_S
try:
    R._POLL_INTERVAL_S = 0
    result = R._wait_with_supervise(
        transient,
        timeout_s=10,
        job_dir_path=ROOT,
        script_rel="exploit.py",
        log_fn=lambda _line: None,
        enable_supervise=False,
    )
finally:
    R._POLL_INTERVAL_S = old_interval
check(
    "W2-2b transient reload error stays unknown and polls to normal exit",
    (transient.reloads, result.get("StatusCode"), result.get("container_disappeared")),
    (2, 7, None),
)


# The real caller used to re-fetch logs after wait returned and re-raise the
# same 404, erasing the distinction above.  Drive that boundary with a fake
# containers.run client: no Docker daemon or live job is touched.
class _Containers:
    def __init__(self, item):
        self.item = item

    def run(self, **_kwargs):
        return self.item


class _Client:
    def __init__(self, item):
        self.containers = _Containers(item)


caller_vanished = VanishedContainer()
old_from_env = R.docker.from_env
old_host_data = os.environ.get("HOST_DATA_DIR")
try:
    R.docker.from_env = lambda: _Client(caller_vanished)
    os.environ["HOST_DATA_DIR"] = "/isolated-test-data"
    try:
        payload = R.run_in_sandbox("W2FAKE", "exploit.py", timeout_s=0)
        caller_error = None
    except Exception as exc:  # mutation control: turn a rethrow into a named red
        payload = {}
        caller_error = type(exc).__name__
finally:
    R.docker.from_env = old_from_env
    if old_host_data is None:
        os.environ.pop("HOST_DATA_DIR", None)
    else:
        os.environ["HOST_DATA_DIR"] = old_host_data
check(
    "W2-2a run_in_sandbox preserves disappeared marker without rethrowing 404",
    (caller_error, payload.get("container_disappeared"), payload.get("timeout"),
     payload.get("exit_code"), payload.get("stdout"), payload.get("stderr")),
    (None, True, None, -1, "", ""),
)
check("W2-2a run_in_sandbox still executes best-effort finally removal",
      caller_vanished.remove_calls, 1)

print(f"runner-live-logs: {passed} passed, {failed} failed; mutation={args.mutate}")
raise SystemExit(1 if failed else 0)
