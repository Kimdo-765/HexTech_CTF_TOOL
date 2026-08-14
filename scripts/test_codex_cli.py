#!/usr/bin/env python3
"""Offline contract tests for the Codex CLI ChatGPT OAuth adapter."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PASS = 0
FAIL = 0


def report(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {name}" + (f" — {detail}" if detail else ""))
    else:
        FAIL += 1
        print(f"  FAIL  {name}" + (f" — {detail}" if detail else ""))


class FakeWriter:
    def __init__(self):
        self.data = b""

    def write(self, data: bytes) -> None:
        self.data += data

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        return None


class FakeReader:
    def __init__(self, lines: list[bytes] | None = None, body: bytes = b""):
        self.lines = list(lines or [])
        self.body = body

    async def readline(self) -> bytes:
        return self.lines.pop(0) if self.lines else b""

    async def readuntil(self, _separator: bytes = b"\n") -> bytes:
        return await self.readline()

    async def readexactly(self, size: int) -> bytes:
        if not self.lines:
            raise asyncio.IncompleteReadError(b"", size)
        head = self.lines[0]
        if len(head) < size:
            self.lines.pop(0)
            raise asyncio.IncompleteReadError(head, size)
        chunk, self.lines[0] = head[:size], head[size:]
        return chunk

    async def read(self, _size: int = -1) -> bytes:
        body, self.body = self.body, b""
        return body


class FakeProcess:
    _next_pid = 40000

    def __init__(self, events: list[dict], stderr: str = "", returncode: int = 0):
        self.stdin = FakeWriter()
        self.stdout = FakeReader(
            [(json.dumps(event) + "\n").encode() for event in events]
        )
        self.stderr = FakeReader(body=stderr.encode())
        self.returncode = None
        self._wanted_returncode = returncode
        FakeProcess._next_pid += 1
        self.pid = FakeProcess._next_pid

    async def wait(self) -> int:
        self.returncode = self._wanted_returncode
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9


def _events(sid: str, answer: str, *, tool: bool = True) -> list[dict]:
    events: list[dict] = [
        {"type": "thread.started", "thread_id": sid},
        {"type": "turn.started"},
    ]
    if tool:
        events.extend(
            [
                {
                    "type": "item.started",
                    "item": {
                        "id": "item-1",
                        "type": "command_execution",
                        "command": "pwd",
                        "status": "in_progress",
                    },
                },
                {
                    "type": "item.completed",
                    "item": {
                        "id": "item-1",
                        "type": "command_execution",
                        "command": "pwd",
                        "aggregated_output": "/work\n",
                        "exit_code": 0,
                        "status": "completed",
                    },
                },
            ]
        )
    events.extend(
        [
            {
                "type": "item.completed",
                "item": {"id": "item-2", "type": "agent_message", "text": answer},
            },
            {
                "type": "turn.completed",
                "usage": {
                    "input_tokens": 100,
                    "cached_input_tokens": 60,
                    "cache_write_input_tokens": 10,
                    "output_tokens": 20,
                    "reasoning_output_tokens": 5,
                },
            },
        ]
    )
    return events


async def test_jsonl_and_resume() -> None:
    print("\n== Codex JSONL + OAuth session ==")
    from modules.codex_cli import CodexCLIClient
    from modules import model_presets
    from modules.gpt_responses import (
        AssistantMessage,
        GptSessionOptions,
        ResultMessage,
        SystemMessage,
        TextBlock,
        ToolUseBlock,
        UserMessage,
    )

    work = tempfile.mkdtemp(prefix="codex-cli-test-")
    old_presets_path = model_presets.MODEL_PRESETS_PATH
    model_presets.MODEL_PRESETS_PATH = Path(work) / "model_presets.json"
    model_presets.save_store({
        "version": 2,
        "providers": {
            "gpt": {
                "active": "roles",
                "presets": {
                    "roles": {
                        "main": "gpt-5.6-sol",
                        "recon": "gpt-5.6-terra",
                        "debugger": "gpt-5.6-sol",
                        "triage": "gpt-5.6-terra",
                        "judge": "gpt-5.6-sol",
                        "effort": "high",
                    }
                },
            }
        },
    })
    client = CodexCLIClient(
        GptSessionOptions(
            system_prompt="Use mcp__team__spawn_subagent when useful.",
            model="gpt-5.6-sol",
            cwd=work,
            effort="high",
            env={
                "JOB_ID": "test-job",
                "OPENAI_API_KEY": "must-not-leak",
                "CODEX_API_KEY": "must-not-leak-either",
            },
            enable_tools=True,
            enable_subagents=True,
        )
    )
    client._codex_bin = "/usr/local/bin/codex"

    calls: list[tuple[tuple[str, ...], dict]] = []
    fake_processes = [
        FakeProcess(_events("0199a213-81c0-7800-8aa1-bbab2a035a53", "FIRST")),
        FakeProcess(
            _events("0199a213-81c0-7800-8aa1-bbab2a035a53", "SECOND", tool=False)
        ),
    ]
    processes = list(fake_processes)
    original = asyncio.create_subprocess_exec

    async def fake_exec(*args, **kwargs):
        process = processes.pop(0)
        calls.append((tuple(str(arg) for arg in args), kwargs))
        return process

    asyncio.create_subprocess_exec = fake_exec
    try:
        await client.query("first prompt")
        first = [message async for message in client.receive_response()]
        await client.query("follow up")
        second = [message async for message in client.receive_response()]
    finally:
        asyncio.create_subprocess_exec = original
        model_presets.MODEL_PRESETS_PATH = old_presets_path

    first_cmd, first_kwargs = calls[0]
    report(
        "initial turn uses codex exec JSONL",
        first_cmd[:3] == ("/usr/local/bin/codex", "exec", "--json"),
    )
    report(
        "initial turn uses danger-full-access in worker",
        "danger-full-access" in first_cmd,
    )
    report(
        "subprocess stream limit is explicit",
        first_kwargs.get("limit") == __import__(
            "modules.codex_cli", fromlist=["SUBPROCESS_STREAM_LIMIT_BYTES"]
        ).SUBPROCESS_STREAM_LIMIT_BYTES,
    )
    report(
        "user config and rules are ignored",
        "--ignore-user-config" in first_cmd and "--ignore-rules" in first_cmd,
    )
    report(
        "model and effort are explicit",
        "gpt-5.6-sol" in first_cmd and 'model_reasoning_effort="high"' in first_cmd,
    )
    config_values = [
        first_cmd[i + 1]
        for i, value in enumerate(first_cmd[:-1])
        if value == "--config"
    ]
    report(
        "multi-agent routing metadata is exposed",
        "features.multi_agent_v2.hide_spawn_agent_metadata=false" in config_values
        and 'features.multi_agent_v2.tool_namespace="agents"' in config_values,
    )
    report(
        "all CTF roles are registered",
        all(
            any(value.startswith(f"agents.{role}.config_file=") for value in config_values)
            for role in ("recon", "debugger", "triage", "judge")
        ),
    )
    role_dir = Path(work) / "tmp" / "codex-agents"
    report(
        "recon role uses GPT preset model",
        (role_dir / "recon.toml").read_text().startswith(
            'model = "gpt-5.6-terra"\n'
        ),
    )
    env = first_kwargs.get("env") or {}
    report("OAuth process drops OPENAI_API_KEY", "OPENAI_API_KEY" not in env)
    report("OAuth process drops CODEX_API_KEY", "CODEX_API_KEY" not in env)
    process_prompt = fake_processes[0].stdin.data.decode()
    report(
        "Claude MCP spelling removed from system prompt",
        "mcp__team__spawn_subagent" not in process_prompt,
    )
    report(
        "Codex prompt requires a real spawn result before wait",
        "spawn_agent" in process_prompt
        and "operator explicitly selected this GPT role-based workflow" in process_prompt
        and 'fork_turns="none"' in process_prompt
        and "child id" in process_prompt
        and "call `wait` only" in process_prompt,
    )
    report(
        "Codex-only reliability guards are injected",
        "set -o pipefail" in process_prompt
        and "foreground QEMU" in process_prompt
        and "update exploit.py/solver.py and report.md" in process_prompt,
    )
    report(
        "initial prompt carries system contract",
        "hextech_system_instructions" in process_prompt,
    )
    report(
        "resume sends only the follow-up",
        fake_processes[1].stdin.data.decode() == "follow up",
    )
    report(
        "session id captured",
        client.session_id == "0199a213-81c0-7800-8aa1-bbab2a035a53",
    )
    report("SystemMessage emitted", any(isinstance(m, SystemMessage) for m in first))
    report(
        "command tool call and result emitted",
        any(
            isinstance(m, AssistantMessage)
            and any(isinstance(b, ToolUseBlock) for b in m.content)
            for m in first
        )
        and any(isinstance(m, UserMessage) for m in first),
    )
    text = "".join(
        b.text
        for m in first
        if isinstance(m, AssistantMessage)
        for b in m.content
        if isinstance(b, TextBlock)
    )
    report("agent message parsed", "FIRST" in text)
    result = next(m for m in first if isinstance(m, ResultMessage))
    report("turn completes without error", not result.is_error)
    report(
        "cached input usage is separated",
        result.usage.get("inputTokens") == 30
        and result.usage.get("cacheReadInputTokens") == 60
        and result.usage.get("cacheCreationInputTokens") == 10
        and result.usage.get("outputTokens") == 20,
    )
    second_cmd = calls[1][0]
    report(
        "follow-up uses exec resume",
        second_cmd[:3] == ("/usr/local/bin/codex", "exec", "resume"),
    )
    report("resume targets captured session", client.session_id in second_cmd)
    report(
        "usage accumulates across resumed turns",
        next(m for m in second if isinstance(m, ResultMessage)).usage.get("inputTokens")
        == 60,
    )

    no_subagents = CodexCLIClient(
        GptSessionOptions(
            system_prompt="bounded helper",
            model="gpt-5.6-terra",
            cwd=tempfile.mkdtemp(prefix="codex-cli-no-agents-"),
            enable_subagents=False,
        )
    )
    no_subagents._codex_bin = "/usr/local/bin/codex"
    no_subagent_cmd = no_subagents._command(resuming=False)
    report(
        "bounded GPT helper does not receive agent role config",
        not any("agents." in value for value in no_subagent_cmd),
    )


def test_settings_auth_mode() -> None:
    print("\n== Codex auth settings ==")
    from modules import settings_io

    root = Path(tempfile.mkdtemp(prefix="codex-auth-test-"))
    (root / "auth.json").write_text(
        json.dumps({"auth_mode": "chatgpt", "tokens": {"secret": "never-print"}})
    )
    old_home = os.environ.get("CODEX_HOME")
    os.environ["CODEX_HOME"] = str(root)
    try:
        report("ChatGPT auth mode is detected", settings_io.has_codex_oauth())
        view = settings_io.get_settings_view()
        report(
            "settings view exposes only auth method",
            view.get("codex_auth_method") == "chatgpt",
        )
        report("settings view does not expose token object", "tokens" not in view)
        report(
            "GPT runtime defaults to Codex", settings_io.get_gpt_runtime() == "codex"
        )
    finally:
        if old_home is None:
            os.environ.pop("CODEX_HOME", None)
        else:
            os.environ["CODEX_HOME"] = old_home


async def test_auth_retry_and_incomplete_stream() -> None:
    print("\n== Codex failure boundaries ==")
    from modules import codex_cli, settings_io
    from modules.gpt_responses import GptSessionOptions, ResultMessage

    work = tempfile.mkdtemp(prefix="codex-cli-boundary-test-")
    client = codex_cli.CodexCLIClient(
        GptSessionOptions(system_prompt="test", model="gpt-5.6-sol", cwd=work)
    )
    original_resolve = codex_cli.resolve_codex_bin
    original_auth = settings_io.has_codex_oauth
    authenticated = False
    codex_cli.resolve_codex_bin = lambda: "/usr/local/bin/codex"
    settings_io.has_codex_oauth = lambda: authenticated
    try:
        try:
            await client.start()
        except codex_cli.CodexCLIError:
            pass
        report("failed auth does not half-start client", client._codex_bin is None)
        authenticated = True
        await client.start()
        report("same client can start after login", client._codex_bin is not None)
    finally:
        codex_cli.resolve_codex_bin = original_resolve
        settings_io.has_codex_oauth = original_auth

    process = FakeProcess(
        [
            {"type": "thread.started", "thread_id": "0199-boundary"},
            {
                "type": "item.completed",
                "item": {"id": "item-1", "type": "agent_message", "text": "partial"},
            },
        ]
    )
    original_exec = asyncio.create_subprocess_exec

    async def fake_exec(*_args, **_kwargs):
        return process

    asyncio.create_subprocess_exec = fake_exec
    try:
        await client.query("test incomplete stream")
        messages = [message async for message in client.receive_response()]
    finally:
        asyncio.create_subprocess_exec = original_exec
    result = next(message for message in messages if isinstance(message, ResultMessage))
    report("missing turn.completed is an error", result.is_error)
    report(
        "incomplete stream has explicit reason", result.stop_reason == "unexpected_eof"
    )
    _, invalid_exit_is_error = codex_cli._tool_result(
        {"type": "command_execution", "exit_code": "unknown"}
    )
    report("non-numeric command exit does not crash", invalid_exit_is_error)
    report(
        "invalid timeout falls back safely",
        codex_cli._positive_timeout("not-a-number") == codex_cli.DEFAULT_TURN_TIMEOUT_S,
    )


async def test_oversized_jsonl_boundaries() -> None:
    print("\n== Codex oversized JSONL boundaries ==")
    from modules import codex_cli
    from modules.gpt_responses import AssistantMessage, GptSessionOptions, ResultMessage, TextBlock

    # A1-a: this is the production incident shape — a valid event well above
    # asyncio's historical 64 KiB line limit. Preserve every byte and leave the
    # next two records aligned.
    text = "x" * 100_000
    first = (json.dumps({
        "type": "item.completed",
        "item": {"type": "agent_message", "text": text},
    }) + "\n").encode()
    second = b'{"type":"turn.completed"}\n'
    third = b'{"type":"third"}\n'
    reader = asyncio.StreamReader(limit=64 * 1024)
    reader.feed_data(first + second + third)
    reader.feed_eof()
    got_first, dropped_first = await codex_cli._read_bounded_jsonl_line(
        reader, hard_cap=200_000,
    )
    got_second, dropped_second = await codex_cli._read_bounded_jsonl_line(
        reader, hard_cap=200_000,
    )
    got_third, dropped_third = await codex_cli._read_bounded_jsonl_line(
        reader, hard_cap=200_000,
    )
    report(
        "A1-a oversized event is preserved exactly",
        got_first == first
        and len(json.loads(got_first)["item"]["text"]) == 100_000
        and got_second == second
        and got_third == third
        and not any((dropped_first, dropped_second, dropped_third)),
    )

    # A1-b: exercise the full client, not just the reader helper. The first
    # record exceeds a test-sized hard cap; the following valid response must be
    # parsed and the drop must be visible in the event ledger and message stream.
    process = FakeProcess(_events("0199-after-drop", "RECOVERED", tool=False))
    stream = asyncio.StreamReader(limit=128)
    oversized = (
        b'{"type":"noise","blob":"' + (b"z" * 1_000) + b'"}\n'
    )
    valid = b"".join(
        (json.dumps(event) + "\n").encode()
        for event in _events("0199-after-drop", "RECOVERED", tool=False)
    )
    stream.feed_data(oversized + valid)
    stream.feed_eof()
    process.stdout = stream

    client = codex_cli.CodexCLIClient(GptSessionOptions(
        system_prompt="test", model="gpt-5.6-sol",
        cwd=tempfile.mkdtemp(prefix="codex-cli-oversized-"),
    ))
    client._codex_bin = "/usr/local/bin/codex"
    original_exec = asyncio.create_subprocess_exec
    original_emit = codex_cli.emit_gpt_event
    original_cap = codex_cli.MAX_JSONL_EVENT_BYTES
    emitted: list[str] = []

    async def fake_exec(*_args, **_kwargs):
        return process

    def fake_emit(_job_id, kind, **_kwargs):
        emitted.append(kind)

    asyncio.create_subprocess_exec = fake_exec
    codex_cli.emit_gpt_event = fake_emit
    codex_cli.MAX_JSONL_EVENT_BYTES = 512
    try:
        await client.query("test oversized stream")
        messages = [message async for message in client.receive_response()]
    finally:
        asyncio.create_subprocess_exec = original_exec
        codex_cli.emit_gpt_event = original_emit
        codex_cli.MAX_JSONL_EVENT_BYTES = original_cap

    rendered = "".join(
        block.text
        for message in messages
        if isinstance(message, AssistantMessage)
        for block in message.content
        if isinstance(block, TextBlock)
    )
    result = next(message for message in messages if isinstance(message, ResultMessage))
    report(
        "A1-b hard-cap drop is recorded and resumes at the next event",
        "stream_event_dropped" in emitted
        and "exceeded the 512-byte hard cap" in rendered
        and "RECOVERED" in rendered
        and not result.is_error,
    )


async def _exercise_real_process_reap(mode: str) -> tuple[bool, str]:
    """Launch a parent+child process group through the real adapter boundary."""
    from modules import codex_cli
    from modules.gpt_responses import GptSessionOptions, ResultMessage

    root = Path(tempfile.mkdtemp(prefix=f"codex-cli-reap-{mode}-"))
    ready = root / "child-ready"
    stopped = root / "child-stopped"
    child_code = (
        "import pathlib,signal,sys,time;"
        "ready=pathlib.Path(sys.argv[1]);stopped=pathlib.Path(sys.argv[2]);"
        "signal.signal(signal.SIGTERM,lambda *_:(stopped.write_text('term'),sys.exit(0)));"
        "ready.write_text('ready');time.sleep(60)"
    )
    parent_code = (
        "import subprocess,sys,time;"
        "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2],sys.argv[3]]);"
        "time.sleep(60)"
    )

    client = codex_cli.CodexCLIClient(GptSessionOptions(
        system_prompt="test", model="gpt-5.6-sol", cwd=str(root),
    ))
    client._codex_bin = sys.executable
    original_exec = asyncio.create_subprocess_exec
    spawned: list[asyncio.subprocess.Process] = []

    async def standin_exec(*_args, **kwargs):
        proc = await original_exec(
            sys.executable, "-c", parent_code, child_code, str(ready), str(stopped),
            **kwargs,
        )
        spawned.append(proc)
        return proc

    async def consume(timeout: float):
        return [message async for message in client.receive_response(
            turn_timeout_s=timeout,
        )]

    asyncio.create_subprocess_exec = standin_exec
    messages = None
    detail = ""
    try:
        await client.query(f"test {mode} cleanup")
        task = asyncio.create_task(consume(1.0 if mode == "timeout" else 30.0))
        for _ in range(200):
            if ready.exists():
                break
            await asyncio.sleep(0.01)
        if mode == "cancel":
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        else:
            messages = await task
        for _ in range(200):
            if stopped.exists():
                break
            await asyncio.sleep(0.01)
        result_reason = ""
        if messages is not None:
            result_reason = next(
                message.stop_reason for message in messages
                if isinstance(message, ResultMessage)
            )
        ok = (
            ready.exists()
            and stopped.exists()
            and bool(spawned)
            and spawned[0].returncode is not None
            and client._proc is None
            and (mode != "timeout" or result_reason == "timeout")
        )
        detail = f"ready={ready.exists()} stopped={stopped.exists()} reason={result_reason}"
        return ok, detail
    finally:
        asyncio.create_subprocess_exec = original_exec
        for proc in spawned:
            if proc.returncode is None:
                try:
                    os.killpg(proc.pid, 9)
                except ProcessLookupError:
                    pass
                await proc.wait()


async def test_process_group_reaping() -> None:
    print("\n== Codex process-group reaping ==")
    cancel_ok, cancel_detail = await _exercise_real_process_reap("cancel")
    report("A7-a cancellation reaps the spawned child", cancel_ok, cancel_detail)
    timeout_ok, timeout_detail = await _exercise_real_process_reap("timeout")
    report("A7-b timeout still reaps the spawned child", timeout_ok, timeout_detail)


async def main() -> int:
    test_settings_auth_mode()
    await test_jsonl_and_resume()
    await test_auth_retry_and_incomplete_stream()
    await test_oversized_jsonl_boundaries()
    await test_process_group_reaping()
    print(f"\n== summary: {PASS} passed, {FAIL} failed ==")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
