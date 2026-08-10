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
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=("none", "stream-order"), default="none")
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

if args.mutate == "stream-order":
    # Test-process mutation only: production contains no mutation switch.
    R._order_live_sandbox_events = lambda events: events

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

check("wait loop preserves the sandbox exit code", result["StatusCode"], 0)
check(
    "output written immediately before exit is flushed to the raw log",
    wait_lines,
    [
        "[runner:stdout] started",
        "[runner:stdout] unfinished-done",
        "[runner:stderr] final-warning",
    ],
)

print(f"runner-live-logs: {passed} passed, {failed} failed; mutation={args.mutate}")
raise SystemExit(1 if failed else 0)
