#!/usr/bin/env python3
"""S1-ENV job-start gate regression and production-mutation battery.

Each mutation rewrites production source in memory, imports that source, and
must make the named acceptance check fail.  No working-tree file is rewritten.
"""
from __future__ import annotations

import argparse
import ast
import errno
import socket
import sys
import tempfile
import types
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

RUNNER_PATH = ROOT / "modules" / "_runner.py"
SETTINGS_PATH = ROOT / "modules" / "settings_io.py"
PWN_PATH = ROOT / "modules" / "pwn" / "analyzer.py"
REV_PATH = ROOT / "modules" / "rev" / "analyzer.py"
API_PATH = ROOT / "api" / "routes" / "jobs.py"

MUTATIONS = (
    "a-allow-tcp-failure",
    "b-block-no-banner",
    "c-ignore-broken-banner",
    "d-widen-to-web",
    "e-probe-nonremote",
    "f-propagate-probe-error",
    "f-block-local-socket-error",
    "g-allow-nxdomain",
    "h-gate-manual-run",
    "default-on",
)

parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()


def replace_once(source: str, old: str, new: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(
            f"mutation anchor count is {count}, expected 1: {old!r}"
        )
    return source.replace(old, new, 1)


def mutated_sources() -> tuple[str, str]:
    runner = RUNNER_PATH.read_text()
    settings = SETTINGS_PATH.read_text()
    if args.mutate == "a-allow-tcp-failure":
        runner = replace_once(
            runner,
            '        if exc.errno in network_failures:\n'
            '            return True, "tcp_failure", f"{type(exc).__name__}: {exc}"',
            '        if False and exc.errno in network_failures:\n'
            '            return True, "tcp_failure", f"{type(exc).__name__}: {exc}"',
        )
    elif args.mutate == "b-block-no-banner":
        runner = replace_once(
            runner,
            '            return False, "reachable", "TCP connected; no classified banner"',
            '            return True, "missing_banner", "service sent no banner"',
        )
    elif args.mutate == "c-ignore-broken-banner":
        runner = replace_once(
            runner,
            '            return True, "known_broken_banner", signature.decode("ascii")',
            '            return False, "reachable", "known signature ignored"',
        )
    elif args.mutate == "d-widen-to-web":
        runner = replace_once(
            runner,
            'REMOTE_TARGET_GATE_MODULES: tuple[str, ...] = ("pwn", "rev")',
            'REMOTE_TARGET_GATE_MODULES: tuple[str, ...] = ("pwn", "rev", "web")',
        )
    elif args.mutate == "e-probe-nonremote":
        runner = replace_once(
            runner,
            '    if not normalized_target:\n        return None',
            '    if False and not normalized_target:\n        return None',
        )
    elif args.mutate == "f-propagate-probe-error":
        runner = replace_once(
            runner,
            '    except Exception as exc:\n'
            '        log_fn(\n'
            '            f"[target-gate] probe raised {type(exc).__name__}: {exc} "\n'
            '            f"— proceeding"\n'
            '        )\n'
            '        return None\n'
            '    if not blocked:',
            '    except Exception:\n'
            '        raise\n'
            '    if not blocked:',
        )
    elif args.mutate == "f-block-local-socket-error":
        runner = replace_once(
            runner,
            '        return False, "probe_error", f"{type(exc).__name__}: {exc}"',
            '        return True, "tcp_failure", f"{type(exc).__name__}: {exc}"',
        )
    elif args.mutate == "g-allow-nxdomain":
        runner = replace_once(
            runner,
            '            return True, "dns_nxdomain", f"DNS: {exc}"',
            '            return False, "probe_error", f"DNS: {exc}"',
        )
    elif args.mutate == "h-gate-manual-run":
        runner = replace_once(runner, '    if manual:\n', '    if False and manual:\n')
    elif args.mutate == "default-on":
        settings = replace_once(
            settings,
            '("enable_remote_target_gate", "ENABLE_REMOTE_TARGET_GATE", bool, False)',
            '("enable_remote_target_gate", "ENABLE_REMOTE_TARGET_GATE", bool, True)',
        )
    return runner, settings


def load_source_module(name: str, source: str, filename: Path) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__file__ = str(filename)
    module.__package__ = "modules" if filename.parent.name == "modules" else ""
    exec(compile(source, str(filename), "exec"), module.__dict__)
    return module


def load_runner_gate(source: str) -> types.ModuleType:
    """Execute only the shipped gate constants/functions, without Docker SDK."""
    tree = ast.parse(source)
    wanted = {
        "REMOTE_TARGET_GATE_MODULES",
        "_BROKEN_TARGET_BANNER_SIGNATURES",
        "_remote_target_gate_probe",
        "remote_target_start_gate",
    }
    body: list[ast.stmt] = [
        ast.ImportFrom(module="__future__", names=[ast.alias("annotations")], level=0),
    ]
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            target = node.targets[0] if isinstance(node, ast.Assign) else node.target
            if isinstance(target, ast.Name) and target.id in wanted:
                body.append(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in wanted:
            body.append(node)
    found = {
        node.name if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        else (node.targets[0].id if isinstance(node, ast.Assign) else node.target.id)
        for node in body[1:]
    }
    if found != wanted:
        raise RuntimeError(f"gate source extraction drifted: {found} != {wanted}")
    module = types.ModuleType("_s1_env_mutated_runner")
    module.__file__ = str(RUNNER_PATH)
    module.__dict__.update(
        errno=errno,
        socket=socket,
        get_setting=lambda _key: False,
        Optional=__import__("typing").Optional,
    )
    exec(compile(ast.fix_missing_locations(ast.Module(body=body, type_ignores=[])), str(RUNNER_PATH), "exec"), module.__dict__)
    return module


RUNNER_SOURCE, SETTINGS_SOURCE = mutated_sources()
R = load_runner_gate(RUNNER_SOURCE)
S = load_source_module("_s1_env_mutated_settings", SETTINGS_SOURCE, SETTINGS_PATH)


class FakeSocket:
    def __init__(self, payload: bytes | BaseException):
        self.payload = payload
        self.closed = False

    def settimeout(self, _timeout: float) -> None:
        pass

    def recv(self, _size: int) -> bytes:
        if isinstance(self.payload, BaseException):
            raise self.payload
        return self.payload

    def close(self) -> None:
        self.closed = True


checks: list[tuple[str, bool, object]] = []


def check(name: str, condition: bool, detail: object = "") -> None:
    checks.append((name, bool(condition), detail))
    print(("PASS" if condition else "FAIL") + f"  {name}")
    if not condition and detail:
        print(f"      {detail}")


def run_gate(
    module: str,
    target: str | None,
    connector,
    *,
    enabled: bool = True,
    manual: bool = False,
) -> tuple[dict | None, list[str], int]:
    logs: list[str] = []
    calls = 0

    def counted_connector(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return connector()

    with (
        patch.object(R, "get_setting", return_value=enabled),
        patch.object(R.socket, "create_connection", counted_connector),
    ):
        result = R.remote_target_start_gate(
            "fixture-job", module, target, logs.append, manual=manual,
        )
    return result, logs, calls


def refused():
    raise ConnectionRefusedError(111, "Connection refused")


def nxdomain():
    raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")


def probe_boom():
    raise RuntimeError("synthetic probe failure")


def permission_denied():
    raise PermissionError(errno.EPERM, "socket denied by test sandbox")


def main() -> int:
    # Default-off is tested from a genuinely absent settings file and again at
    # the gate boundary to prove that it performs no network operation.
    with tempfile.TemporaryDirectory() as td:
        S.SETTINGS_PATH = Path(td) / "absent.json"
        check(
            "test_default_off_schema_value",
            S.get_setting("enable_remote_target_gate") is False,
            S.get_setting("enable_remote_target_gate"),
        )
    result, _logs, calls = run_gate("pwn", "dead.example:1", refused, enabled=False)
    check(
        "test_default_off_performs_no_probe",
        result is None and calls == 0,
        (result, calls),
    )

    # ⓐ TCP refusal returns an agent-summary-shaped stop before the entrypoint's
    # work-tree/agent boundary (the source ordering assertion is below).
    result, _logs, calls = run_gate("pwn", "dead.example:31337", refused)
    check(
        "test_a_dead_tcp_blocks_before_pwn_agent_start",
        bool(result) and calls == 1
        and result.get("agent_error_kind") == "target_unusable"
        and result.get("messages") == 0
        and result.get("target_gate", {}).get("reason") == "tcp_failure",
        (result, calls),
    )

    # ⓑ Silence after a successful connect is positive evidence, not failure.
    silent = FakeSocket(socket.timeout("no banner"))
    result, _logs, calls = run_gate("pwn", "silent.example:31337", lambda: silent)
    check(
        "test_b_live_no_banner_service_proceeds",
        result is None and calls == 1 and silent.closed,
        (result, calls, silent.closed),
    )

    # ⓒ Only the observed production failure signature blocks a connected peer.
    broken = FakeSocket(
        b"Failed to find an available port: Address already in use\n"
    )
    result, _logs, _calls = run_gate("rev", "banner.example:4444", lambda: broken)
    check(
        "test_c_known_broken_banner_blocks",
        bool(result)
        and result.get("target_gate", {}).get("reason") == "known_broken_banner",
        result,
    )
    unknown = FakeSocket(b"SSH-2.0-unclassified\r\n")
    result, _logs, _calls = run_gate("pwn", "unknown.example:22", lambda: unknown)
    check("test_c_unknown_banner_proceeds", result is None, result)

    # ⓓ Out-of-scope modules do not even touch the network.
    for module in ("web", "web3", "crypto"):
        result, _logs, calls = run_gate(module, "dead.example:1", refused)
        check(
            f"test_d_{module}_never_enters_gate",
            result is None and calls == 0,
            (result, calls),
        )

    # ⓔ Local jobs (no registered target) do not probe.
    result, _logs, calls = run_gate("pwn", None, refused)
    check(
        "test_e_nonremote_job_performs_no_probe",
        result is None and calls == 0,
        (result, calls),
    )

    # ⓕ A bug/restriction in the probe itself cannot kill the job.
    raised = None
    try:
        result, logs, calls = run_gate("pwn", "probe.example:31337", probe_boom)
    except Exception as exc:  # mutation must become a named red check
        raised = exc
        result, logs, calls = None, [], 1
    check(
        "test_f_probe_exception_fails_open",
        raised is None and result is None and calls == 1
        and any("probe raised RuntimeError" in line for line in logs),
        (raised, result, calls, logs),
    )
    result, logs, calls = run_gate(
        "rev", "probe.example:31337", permission_denied,
    )
    check(
        "test_f_local_socket_restriction_fails_open",
        result is None and calls == 1
        and any("probe unavailable" in line for line in logs),
        (result, calls, logs),
    )

    # ⓖ A definite name-resolution miss returns the same pre-agent stop.
    result, _logs, calls = run_gate("rev", "missing.invalid:4444", nxdomain)
    check(
        "test_g_nxdomain_blocks_before_rev_agent_start",
        bool(result) and calls == 1
        and result.get("agent_error_kind") == "target_unusable"
        and result.get("target_gate", {}).get("reason") == "dns_nxdomain",
        (result, calls),
    )

    # ⓗ The operator manual route bypasses without probing and records why.
    result, logs, calls = run_gate(
        "pwn", "dead.example:1", refused, manual=True,
    )
    check(
        "test_h_manual_run_bypasses_gate_with_warning",
        result is None and calls == 0
        and any("operator manual-run bypass" in line for line in logs),
        (result, calls, logs),
    )

    # Source-boundary assertions keep the core decision connected to both
    # automatic entrypoints and to the explicit API manual bypass.
    pwn_source = PWN_PATH.read_text()
    rev_source = REV_PATH.read_text()
    api_source = API_PATH.read_text()
    pwn_entry = pwn_source[pwn_source.index("async def _run_agent("):]
    rev_entry = rev_source[rev_source.index("async def _run_agent("):]
    check(
        "test_pwn_gate_call_precedes_work_tree_and_agent_start",
        pwn_entry.index("gate_summary = remote_target_start_gate(")
        < pwn_entry.index('work_dir = job_dir(job_id) / "work"'),
    )
    check(
        "test_rev_gate_call_precedes_work_tree_and_agent_start",
        rev_entry.index("gate_summary = remote_target_start_gate(")
        < rev_entry.index('work_dir = job_dir(job_id) / "work"'),
    )
    manual_call = api_source.index("remote_target_start_gate(", api_source.index("def post_run_script"))
    sandbox_call = api_source.index("res = attempt_sandbox_run(", manual_call)
    check(
        "test_manual_route_declares_bypass_before_sandbox",
        "manual=True" in api_source[manual_call:sandbox_call],
    )

    failed = [(name, detail) for name, ok, detail in checks if not ok]
    print(
        f"\n{len(checks)} checks, {len(failed)} failed; "
        f"mutation={args.mutate or 'none'}"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
