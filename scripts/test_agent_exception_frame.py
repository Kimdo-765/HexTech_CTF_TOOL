#!/usr/bin/env python3
"""Regression tests for main-agent exception frame preservation.

The production function is executed with a fake SDK client.  The normal path
is compared byte-for-byte with the same source using the legacy exception
handler; the failure path raises an exception whose ``__str__``, ``__repr__``,
and normal ``__traceback__`` lookup all raise.

Run from the repository root::

    python3 scripts/test_agent_exception_frame.py
    python3 scripts/test_agent_exception_frame.py --mutate drop-traceback
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
SOURCE = (ROOT / "modules" / "_common.py").read_text()

MUTATIONS = (
    "drop-class-name",
    "drop-traceback",
    "unknown-error-kind",
    "unsafe-stringify",
    "drop-cost-snapshot",
    "stop-before-sandbox",
    "alter-normal-path",
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()


def _replace_once(source: str, old: str, new: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(
            f"mutation anchor count is {count}, expected 1: {old!r}"
        )
    return source.replace(old, new, 1)


def _mutate(source: str) -> str:
    if args.mutate == "drop-class-name":
        return _replace_once(
            source,
            '                summary["agent_error_type"] = exc_type',
            '                summary["agent_error_type"] = ""',
        )
    if args.mutate == "drop-traceback":
        return _replace_once(
            source,
            '                summary["agent_error_traceback"] = traceback_text',
            '                summary["agent_error_traceback"] = ""',
        )
    if args.mutate == "unknown-error-kind":
        return _replace_once(
            source,
            '                    kind = "agent_exception"',
            '                    kind = "unknown"',
        )
    if args.mutate == "unsafe-stringify":
        return _replace_once(
            source,
            "                exc_type, msg_text, traceback_text = "
            "_safe_agent_exception_details(e)",
            "                exc_type, msg_text, traceback_text = "
            "type(e).__name__, str(e), ''",
        )
    if args.mutate == "drop-cost-snapshot":
        return _replace_once(
            source,
            '                _snapshot_cost(summary, "AGENT_ERROR")',
            "                pass  # production mutation: drop cost snapshot",
        )
    if args.mutate == "stop-before-sandbox":
        return _replace_once(
            source,
            '                if summary.get("agent_error_kind") in '
            '("killed", "timeout"):',
            '                if False and summary.get("agent_error_kind") in '
            '("killed", "timeout"):',
        )
    if args.mutate == "alter-normal-path":
        return _replace_once(
            source,
            '            log_fn(f"Main session turn (attempt {attempt}/{cap_str})")',
            '            log_fn(f"Main session turn (attempt {attempt}/{cap_str})")\n'
            '            log_fn("MUTANT: changed normal-path record")',
        )
    return source


def _legacy_normal_source(source: str) -> str:
    start_marker = (
        "            except Exception as e:\n"
        "                exc_type, msg_text, traceback_text = "
        "_safe_agent_exception_details(e)\n"
    )
    start = source.index(start_marker)
    end = source.index("\n            # ---- Cost-cap halt", start)
    legacy = '''            except Exception as e:
                msg_text = str(e)
                kind = classify_agent_error(msg_text)
                summary["agent_error"] = msg_text
                summary["agent_error_kind"] = kind
                if kind in (None, "unknown") and (
                    "exit code -9" in msg_text or "killed" in msg_text.lower()
                ):
                    summary["agent_error_kind"] = "killed"
                log_fn(f"AGENT_ERROR ({summary['agent_error_kind']}): {msg_text[:400]}")
                _snapshot_cost(summary, "AGENT_ERROR")
                if summary.get("agent_error_kind") in ("killed", "timeout"):
                    exploit_missing = not (work_dir / "exploit.py").is_file()
                    report_missing = not (work_dir / "report.md").is_file()
                    write_fallback_artifacts(work_dir, log_fn, _fallback_module)
                    if exploit_missing or report_missing:
                        summary["fallback_artifact_used"] = True
                    final_draft_pending["value"] = False
                    soft_eject_pending["value"] = False
                else:
                    return last_sandbox
'''
    return source[:start] + legacy + source[end:]


def _load(source: str, name: str):
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / "modules" / "_common.py")
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module


class _ResultMessage:
    duration_ms = 12
    num_turns = 1
    total_cost_usd = 0.25
    is_error = False
    stop_reason = None


class _AssistantMessage:
    content = []


class _UserMessage:
    content = []


class _HostileTimeout(Exception):
    def __str__(self):
        raise RuntimeError("stringification exploded")

    def __repr__(self):
        raise RuntimeError("repr exploded")

    def __getattribute__(self, name):
        if name == "__traceback__":
            raise RuntimeError("traceback lookup exploded")
        return super().__getattribute__(name)


class _GenericAgentFailure(Exception):
    pass


class _Options:
    system_prompt = "system"
    model = "claude-opus-5"
    cwd = "/tmp"
    effort = None
    env = {}
    resume = None
    add_dirs = []


def _configure(module, root: Path, logs: list[str], meta_calls: list[dict]):
    import modules.agent_provider as providers

    if "anyio" not in sys.modules:
        anyio = types.ModuleType("anyio")

        class _ToThread:
            @staticmethod
            async def run_sync(fn, *fn_args):
                return fn(*fn_args)

        anyio.to_thread = _ToThread()
        sys.modules["anyio"] = anyio

    try:
        import claude_agent_sdk as sdk
    except ModuleNotFoundError:
        sdk = types.ModuleType("claude_agent_sdk")
        sys.modules["claude_agent_sdk"] = sdk

    providers.ensure_provider_ready = lambda requested=None: "claude"
    providers.provider_display_name = lambda provider: "Claude"
    providers.provider_meta_fields = lambda provider: {"agent_provider": provider}
    module.read_meta = lambda job_id: {
        "id": job_id,
        "module": "pwn",
        "target_url": "host:31337",
        "description": "ordinary challenge",
    }
    module.write_meta = lambda job_id, **fields: meta_calls.append(dict(fields))
    module.job_dir = lambda job_id: root
    module.emit_event = lambda *a, **k: None
    module.write_why_stopped = lambda *a, **k: logs.append("WHY_STOPPED")
    module.auto_retry_max = lambda: 0
    module.scan_job_for_flags = lambda *a, **k: []
    sdk.ResultMessage = _ResultMessage
    sdk.AssistantMessage = _AssistantMessage
    sdk.UserMessage = _UserMessage
    return sdk


async def _normal(module) -> dict:
    root = Path(tempfile.mkdtemp())
    work = root / "work"
    work.mkdir()
    (work / "exploit.py").write_bytes(b"#!/usr/bin/env python3\nprint('ok')\n")
    (work / "report.md").write_bytes(b"# stable report\n")
    logs: list[str] = []
    meta_calls: list[dict] = []
    sandbox_calls: list[str] = []
    sdk = _configure(module, root, logs, meta_calls)

    class _Client:
        def __init__(self, **kwargs):
            self.queries: list[str] = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def query(self, prompt):
            self.queries.append(prompt)

        async def receive_response(self):
            yield _ResultMessage()

    sdk.ClaudeSDKClient = _Client

    def scan(*_a, **kw):
        if kw.get("provenance_out") is not None:
            kw["provenance_out"]["tier"] = "marker"
        return ["DH{normal_fixture}"]

    module.scan_job_for_flags = scan

    def sandbox(script_name):
        sandbox_calls.append(script_name)
        return {
            "exit_code": 0,
            "stdout": "FLAG_CANDIDATE: DH{normal_fixture}\n",
            "stderr": "",
            "timeout": False,
            "judge": {},
        }

    summary = {"model": "claude-opus-5"}
    result = await module.run_main_agent_session(
        "normal-job",
        options=_Options(),
        initial_prompt="solve",
        summary=summary,
        work_dir=work,
        artifact_names=("exploit.py",),
        auto_run=True,
        sandbox_runner=sandbox,
        log_fn=logs.append,
    )
    for fields in meta_calls:
        if "last_agent_event_at" in fields:
            fields["last_agent_event_at"] = "<heartbeat-timestamp>"
    return {
        "summary": summary,
        "result": result,
        "logs": logs,
        "meta_calls": meta_calls,
        "sandbox_calls": sandbox_calls,
        "exploit": (work / "exploit.py").read_text(),
        "report": (work / "report.md").read_text(),
    }


async def _exception(
    module,
    *,
    exception_factory=None,
    job_id: str = "exception-job",
    auto_run: bool = True,
) -> dict:
    root = Path(tempfile.mkdtemp())
    work = root / "work"
    work.mkdir()
    logs: list[str] = []
    meta_calls: list[dict] = []
    sandbox_calls: list[str] = []
    sdk = _configure(module, root, logs, meta_calls)
    if exception_factory is None:
        exception_factory = _HostileTimeout

    class _Client:
        def __init__(self, **kwargs):
            self.queries: list[str] = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def query(self, prompt):
            self.queries.append(prompt)

        async def receive_response(self):
            raise exception_factory()
            yield None

    sdk.ClaudeSDKClient = _Client
    module._token_state[job_id] = {
        "input_tokens": 1000,
        "output_tokens": 100,
        "cache_creation_input_tokens": 50,
        "cache_read_input_tokens": 25,
    }

    def sandbox(script_name):
        sandbox_calls.append(script_name)
        return {
            "exit_code": 1,
            "stdout": "",
            "stderr": "probe failed",
            "timeout": False,
            "judge": {"verdict": "crash", "next_action": "stop"},
        }

    summary = {"model": "claude-opus-5"}
    escaped = None
    result = None
    try:
        result = await module.run_main_agent_session(
            job_id,
            options=_Options(),
            initial_prompt="solve",
            summary=summary,
            work_dir=work,
            artifact_names=("exploit.py",),
            auto_run=auto_run,
            sandbox_runner=sandbox if auto_run else None,
            log_fn=logs.append,
        )
    except BaseException as exc:
        escaped = type(exc).__name__
    return {
        "summary": summary,
        "result": result,
        "escaped": escaped,
        "logs": logs,
        "sandbox_calls": sandbox_calls,
        "exploit_exists": (work / "exploit.py").is_file(),
        "report_exists": (work / "report.md").is_file(),
    }


checks: list[bool] = []


def check(label: str, condition: bool, got=None) -> None:
    checks.append(bool(condition))
    print(("PASS  " if condition else "FAIL  ") + label)
    if not condition:
        print(f"      got={got!r}")


async def main() -> int:
    current = _load(_mutate(SOURCE), "_agent_exception_current")
    legacy = _load(_legacy_normal_source(SOURCE), "_agent_exception_legacy")

    normal_now = await _normal(current)
    normal_before = await _normal(legacy)
    now_bytes = json.dumps(normal_now, sort_keys=True, separators=(",", ":"))
    before_bytes = json.dumps(normal_before, sort_keys=True, separators=(",", ":"))
    check(
        "normal path behavior and records stay byte-identical",
        now_bytes == before_bytes,
        (normal_before, normal_now),
    )

    failure = await _exception(current)
    summary = failure["summary"]
    trace = summary.get("agent_error_traceback") or ""
    check("hostile exception formatting raises nothing", failure["escaped"] is None,
          failure["escaped"])
    check("exception class name is preserved in the job record",
          summary.get("agent_error_type") == "_HostileTimeout", summary)
    check("traceback header and throwing frame are preserved",
          "Traceback (most recent call last):" in trace
          and "raise exception_factory()" in trace
          and "_HostileTimeout:" in trace,
          trace)
    check("exception error_kind is specific, never unknown",
          summary.get("agent_error_kind") == "timeout", summary)
    generic = await _exception(
        current,
        exception_factory=lambda: _GenericAgentFailure("opaque SDK failure"),
        job_id="generic-exception-job",
        auto_run=False,
    )
    check("unclassified SDK exceptions use agent_exception, never unknown",
          generic["summary"].get("agent_error_kind") == "agent_exception",
          generic["summary"])
    check("fallback artifacts survive the hostile exception",
          failure["exploit_exists"] and failure["report_exists"], failure)
    check("sandbox still runs exactly once with the fallback artifact",
          failure["sandbox_calls"] == ["exploit.py"], failure["sandbox_calls"])
    check("cost snapshot survives the hostile exception",
          bool(summary.get("agent_tokens"))
          and float(summary.get("cost_usd_estimate") or 0) > 0,
          summary)
    check("the full traceback is written to the run record",
          any(trace and trace in line for line in failure["logs"]), failure["logs"])

    failed = len([ok for ok in checks if not ok])
    print(
        f"\n{len(checks)} checks, {failed} failed; "
        f"mutation={args.mutate or 'none'}"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
