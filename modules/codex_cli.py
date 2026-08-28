"""Codex CLI adapter backed by ChatGPT OAuth.

HexTech's shared orchestration loop expects the small message/client surface
implemented by :mod:`modules.gpt_responses`.  This adapter keeps that surface,
but runs ``codex exec --json`` so a login created by ``codex login`` can use a
ChatGPT subscription instead of a Platform API key.

The CLI owns OAuth token refresh and session persistence.  This module never
copies a token into a prompt or environment variable; it only launches Codex
with the mounted ``CODEX_HOME`` and parses the documented JSONL event stream.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import time
from pathlib import Path
from typing import Any, AsyncIterator

from modules.gpt_responses import (
    AssistantMessage,
    GptSessionOptions,
    ResultMessage,
    SystemMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)
from modules.gpt_run_events import context_from_options, emit_gpt_event
from modules.codex_turn_guard import acquire_turn_guard, release_turn_guard


DEFAULT_TURN_TIMEOUT_S = 3600.0
MAX_EVENT_TEXT_CHARS = 48_000
MAX_STDERR_CHARS = 64_000
# Keep the asyncio transport comfortably above the historical 64 KiB default,
# but do not confuse that implementation limit with our application boundary.
# A JSONL event may legitimately exceed this transport limit, so
# `_read_bounded_jsonl_line()` drains it in chunks up to the separate hard cap.
SUBPROCESS_STREAM_LIMIT_BYTES = 1024 * 1024
MAX_JSONL_EVENT_BYTES = 8 * 1024 * 1024
_STREAM_DRAIN_CHUNK_BYTES = 64 * 1024

# Native Codex roles exposed only for GPT/Codex CLI main sessions.  Their
# config files are generated per job so the provider-scoped GPT preset can
# select a different model for each role without touching Claude/Grok agents.
CODEX_AGENT_ROLES: dict[str, str] = {
    "recon": "Read-only static analysis and concise evidence synthesis.",
    "debugger": "Dynamic analysis with gdb, tracing, and bounded VM probes.",
    "triage": "Independent read-only verification of candidate findings.",
    "judge": "Read-only pre-ship review of solver correctness and reliability.",
}


class CodexCLIError(RuntimeError):
    pass


CODEX_TOOL_ADDENDUM = """
## CODEX CLI TOOL SURFACE

This session runs through OpenAI Codex CLI with ChatGPT OAuth. Use Codex's
native shell, file-editing, web, planning, and subagent capabilities rather
than Claude MCP tool names. Delegate recon/debugger/triage/judge work with the
native `spawn_agent` tool and select the matching registered agent role. The
operator explicitly selected this GPT role-based workflow and requests those
delegations for this CTF run. When
selecting a role/model, set `fork_turns="none"` (or a bounded positive turn
count); a full-history fork inherits the parent agent type and Codex rejects
the role override before a child id is created.

Delegation is real only after `spawn_agent` returns a child id. Never claim
that work was delegated without that tool result, and call `wait` only for a
child id that actually exists. If spawning is unavailable or fails, state that
once and continue the work directly instead of entering a wait loop.

GPT/Codex reliability rules:
- A piped compiler/build command reports the last program's status by default.
  Use `set -o pipefail` (or capture the build log separately), then verify the
  expected artifact with `test -x`, `file`, or an equivalent direct check.
- Bound every foreground QEMU/VM/harness run with a timeout or a tracked PID,
  keep one equivalent VM probe alive at a time, and wait for the actual guest
  prompt before sending input. Reap the exact PID when a probe finishes.
- Do not write an unverified layout guess as a fact in report.md. When a later
  trace disproves an assumption, update exploit.py/solver.py and report.md in
  the same turn before continuing.

Deliverables must be written as relative paths in the current working
directory (`exploit.py` / `solver.py` / `report.md`). Print
`FLAG_CANDIDATE: <flag>` only after capturing a real flag.
""".strip()


def adapt_system_prompt_for_codex(system_prompt: str) -> str:
    """Remove Claude/Grok-specific tool spellings from a shared prompt."""
    text = str(system_prompt or "")
    replacements = {
        "mcp__team__spawn_subagent": "spawn_agent",
        "spawn_subagent": "spawn_agent",
        "subagent_type=": "agent_type=",
        "subagent_type ∈": "agent_type ∈",
        "Claude Code": "Codex CLI",
        "Claude SDK": "Codex CLI",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def resolve_codex_bin() -> str:
    """Return the Codex executable path or raise an operator-facing error."""
    configured = str(os.environ.get("CODEX_BIN") or "").strip()
    candidates = [configured] if configured else []
    found = shutil.which("codex")
    if found:
        candidates.append(found)
    candidates.extend(("/usr/local/bin/codex", "/usr/bin/codex"))
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise FileNotFoundError(
        "Codex CLI is not installed in this container. Rebuild the api and "
        "worker images after the Codex OAuth update."
    )


def _normalize_effort(value: str | None) -> str | None:
    effort = str(value or "").strip().lower()
    return (
        effort
        if effort in {
            "none",
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh",
            "max",
            "ultra",
        }
        else None
    )


def _toml_string(value: Any) -> str:
    """Encode a scalar as a TOML-compatible quoted string."""
    return json.dumps(str(value), ensure_ascii=False)


def _write_codex_agent_configs(
    cwd: str | Path,
    parent_model: str,
    effort: str | None,
    language_instruction: str = "",
) -> dict[str, Path]:
    """Write GPT-only role overlays and return absolute paths by role.

    Codex custom roles accept a ``config_file`` whose values override the
    spawned child.  Keeping these files below the job's own tmp directory
    avoids mutating the operator's CODEX_HOME and makes retries independent.
    """
    from modules.model_presets import resolve_role_model

    role_dir = Path(cwd).resolve() / "tmp" / "codex-agents"
    role_dir.mkdir(parents=True, exist_ok=True)
    normalized_effort = _normalize_effort(effort)
    paths: dict[str, Path] = {}
    for role in CODEX_AGENT_ROLES:
        model = resolve_role_model(role, parent_model, "gpt")
        lines = [f"model = {_toml_string(model)}"]
        if normalized_effort:
            lines.append(
                "model_reasoning_effort = " + _toml_string(normalized_effort)
            )
        if language_instruction:
            # Child agents do not automatically receive the main agent's
            # developer prompt. Put the same immutable job-language policy in
            # every role overlay so native Codex delegation cannot drift.
            lines.append(
                "developer_instructions = "
                + _toml_string(language_instruction)
            )
        content = "\n".join(lines) + "\n"
        path = role_dir / f"{role}.toml"
        try:
            current = path.read_text() if path.is_file() else None
        except OSError:
            current = None
        if current != content:
            tmp = path.with_suffix(".toml.tmp")
            tmp.write_text(content)
            tmp.replace(path)
        paths[role] = path
    return paths


def _positive_timeout(value: Any) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        return DEFAULT_TURN_TIMEOUT_S
    return timeout if timeout > 0 else DEFAULT_TURN_TIMEOUT_S


def _cap_text(value: Any, limit: int = MAX_EVENT_TEXT_CHARS) -> str:
    text = str(value if value is not None else "")
    if len(text) <= limit:
        return text
    half = (limit - 120) // 2
    return (
        text[:half]
        + f"\n... ({len(text) - (2 * half)} characters elided) ...\n"
        + text[-half:]
    )


def _json_text(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        return str(value)


async def _read_bounded_jsonl_line(
    reader: asyncio.StreamReader,
    hard_cap: int = MAX_JSONL_EVENT_BYTES,
) -> tuple[bytes, bool]:
    """Read one newline-delimited event without losing stream alignment.

    ``StreamReader.readline()`` raises ``ValueError`` when a line exceeds the
    reader's transport limit.  ``readuntil()`` exposes how much can be consumed,
    which lets us preserve legitimate multi-limit events and deliberately drain
    an event that exceeds the application hard cap.  The returned boolean says
    that the event was dropped; the next call starts at the next JSONL record.
    """
    cap = max(1, int(hard_cap))
    buf = bytearray()
    dropped = False

    while True:
        try:
            chunk = await reader.readuntil(b"\n")
        except asyncio.LimitOverrunError as exc:
            # Consume exactly the bytes asyncio says precede the separator (or
            # the separator-prefix it retained), but never materialize that
            # potentially large span as one new bytes object.
            remaining = max(1, int(exc.consumed))
            while remaining:
                part = await reader.read(min(remaining, _STREAM_DRAIN_CHUNK_BYTES))
                if not part:
                    return (b"", True) if dropped else (bytes(buf), False)
                remaining -= len(part)
                if dropped:
                    continue
                if len(buf) + len(part) > cap:
                    buf.clear()
                    dropped = True
                else:
                    buf.extend(part)
            continue
        except asyncio.IncompleteReadError as exc:
            chunk = exc.partial
            if dropped or len(buf) + len(chunk) > cap:
                return b"", True
            buf.extend(chunk)
            return bytes(buf), False

        if dropped or len(buf) + len(chunk) > cap:
            return b"", True
        buf.extend(chunk)
        return bytes(buf), False


def _usage_from_event(raw: Any) -> dict[str, int]:
    usage = raw if isinstance(raw, dict) else {}
    total_input = int(usage.get("input_tokens") or usage.get("inputTokens") or 0)
    cached = int(
        usage.get("cached_input_tokens") or usage.get("cachedInputTokens") or 0
    )
    cache_write = int(
        usage.get("cache_write_input_tokens") or usage.get("cacheWriteInputTokens") or 0
    )
    output = int(usage.get("output_tokens") or usage.get("outputTokens") or 0)
    return {
        "inputTokens": max(0, total_input - cached - cache_write),
        "outputTokens": output,
        "cacheCreationInputTokens": cache_write,
        "cacheReadInputTokens": cached,
    }


def _merge_usage(target: dict[str, int], incoming: dict[str, int]) -> None:
    for key in (
        "inputTokens",
        "outputTokens",
        "cacheCreationInputTokens",
        "cacheReadInputTokens",
    ):
        target[key] = int(target.get(key) or 0) + int(incoming.get(key) or 0)


def _heartbeat_usage(usage: dict[str, int]) -> dict[str, int]:
    return {
        "input_tokens": int(usage.get("inputTokens") or 0),
        "output_tokens": int(usage.get("outputTokens") or 0),
        "cache_creation_input_tokens": int(usage.get("cacheCreationInputTokens") or 0),
        "cache_read_input_tokens": int(usage.get("cacheReadInputTokens") or 0),
    }


def _tool_name_and_input(item: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    kind = str(item.get("type") or "")
    if kind == "command_execution":
        return "Bash", {"command": item.get("command") or ""}
    if kind == "file_change":
        return "Edit", {"changes": item.get("changes") or []}
    if kind == "web_search":
        return "WebSearch", {"query": item.get("query") or ""}
    if kind in {"mcp_tool_call", "collab_tool_call"}:
        name = item.get("tool") or item.get("name") or item.get("server") or kind
        raw_input = item.get("arguments") or item.get("input") or {}
        if not isinstance(raw_input, dict):
            raw_input = {"value": raw_input}
        return str(name), raw_input
    return kind or "codex_tool", {"item": item}


def _tool_result(item: dict[str, Any]) -> tuple[str, bool]:
    kind = str(item.get("type") or "")
    status = str(item.get("status") or "").lower()
    is_error = status in {"failed", "error", "cancelled", "declined"}
    if kind == "command_execution":
        body = (
            item.get("aggregated_output")
            or item.get("output")
            or item.get("stdout")
            or ""
        )
        exit_code = item.get("exit_code")
        if exit_code is not None:
            body = f"{body}\n[exit_code={exit_code}]".strip()
            try:
                is_error = is_error or int(exit_code) != 0
            except (TypeError, ValueError):
                is_error = True
        return _cap_text(body), is_error
    body = (
        item.get("result")
        or item.get("output")
        or item.get("error")
        or item.get("changes")
        or item.get("query")
        or status
    )
    return _cap_text(_json_text(body)), is_error


_TOOL_ITEM_TYPES = {
    "command_execution",
    "file_change",
    "mcp_tool_call",
    "web_search",
    "collab_tool_call",
}


class CodexCLIClient:
    """Multi-turn ``codex exec`` client using persisted ChatGPT OAuth."""

    def __init__(self, options: GptSessionOptions):
        self.options = options
        self.session_id: str | None = options.resume
        self._pending_prompt: str | None = None
        self._codex_bin: str | None = None
        self._proc: asyncio.subprocess.Process | None = None
        self._closed = False
        self._turn_count = 0
        self._usage_totals = {
            "inputTokens": 0,
            "outputTokens": 0,
            "cacheCreationInputTokens": 0,
            "cacheReadInputTokens": 0,
        }

    async def __aenter__(self) -> "CodexCLIClient":
        await self.start()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def start(self) -> None:
        if self._codex_bin is not None:
            return
        binary = resolve_codex_bin()
        try:
            from modules.settings_io import has_codex_oauth

            authenticated = has_codex_oauth()
        except Exception:
            authenticated = False
        if not authenticated:
            raise CodexCLIError(
                "Codex ChatGPT OAuth is not available. Run `codex login` on "
                "the host and mount HOST_CODEX_HOME into the containers."
            )
        self._codex_bin = binary

    async def close(self) -> None:
        self._closed = True
        await self._stop_process()

    async def query(self, prompt: str) -> None:
        if self._codex_bin is None:
            await self.start()
        if self._pending_prompt is not None:
            raise CodexCLIError("a Codex turn is already pending")
        self._pending_prompt = str(prompt or " ")

    def _instructions(self, prompt: str, *, resuming: bool) -> str:
        if resuming:
            # A resumed `codex exec` turn does not replay system_prompt. The
            # session normally remembers it, but explicitly carrying this
            # small immutable policy makes /continue and /retry deterministic.
            from modules.output_language import output_language_instruction

            language_instruction = output_language_instruction(
                (self.options.env or {}).get("AGENT_OUTPUT_LANGUAGE")
            )
            return (
                language_instruction + "\n\n" + prompt
                if language_instruction
                else prompt
            )
        system = adapt_system_prompt_for_codex(self.options.system_prompt)
        if self.options.append_tool_addendum and self.options.enable_tools:
            system = system.rstrip() + "\n\n" + CODEX_TOOL_ADDENDUM
        if not self.options.enable_tools:
            system = (
                system.rstrip()
                + "\n\nThis is a text-only helper turn. Do not call shell, file, "
                "web, MCP, or subagent tools; answer only from the supplied context."
            )
        elif not self.options.enable_subagents:
            system = (
                system.rstrip() + "\n\nDo not delegate this bounded role to subagents."
            )
        if self.options.add_dirs:
            dirs = ", ".join(str(d) for d in self.options.add_dirs)
            system += f"\n\nAdditional reference directories: {dirs}"
        return (
            "<hextech_system_instructions>\n"
            + system
            + "\n</hextech_system_instructions>\n\n<user_task>\n"
            + prompt
            + "\n</user_task>"
        )

    def _command(self, *, resuming: bool) -> list[str]:
        assert self._codex_bin is not None
        effort = _normalize_effort(self.options.effort)
        sandbox = "danger-full-access" if self.options.enable_tools else "read-only"
        common = [
            "--json",
            "--ignore-user-config",
            "--ignore-rules",
            "--skip-git-repo-check",
            "--model",
            str(self.options.model),
            "--config",
            f'sandbox_mode="{sandbox}"',
        ]
        if effort:
            common.extend(("--config", f'model_reasoning_effort="{effort}"'))
        if self.options.enable_subagents:
            # GPT-5.6 Sol selects Codex multi-agent v2. Explicitly expose its
            # routing fields and register the GPT preset's per-role overlays;
            # --ignore-user-config otherwise leaves every child inheriting
            # main's model. These flags are confined to this Codex adapter.
            common.extend(
                (
                    "--config",
                    "features.multi_agent_v2.hide_spawn_agent_metadata=false",
                    "--config",
                    'features.multi_agent_v2.tool_namespace="agents"',
                )
            )
            from modules.output_language import output_language_instruction

            role_configs = _write_codex_agent_configs(
                self.options.cwd,
                str(self.options.model),
                effort,
                output_language_instruction(
                    (self.options.env or {}).get("AGENT_OUTPUT_LANGUAGE")
                ),
            )
            for role, path in role_configs.items():
                common.extend(
                    (
                        "--config",
                        f"agents.{role}.description="
                        + _toml_string(CODEX_AGENT_ROLES[role]),
                        "--config",
                        f"agents.{role}.config_file=" + _toml_string(path),
                    )
                )
        if resuming:
            return [
                self._codex_bin,
                "exec",
                "resume",
                *common,
                str(self.session_id),
                "-",
            ]
        command = [self._codex_bin, "exec", *common, "--sandbox", sandbox]
        for path in self.options.add_dirs:
            command.extend(("--add-dir", str(path)))
        command.append("-")
        return command

    def _environment(self) -> dict[str, str]:
        env = {k: str(v) for k, v in os.environ.items()}
        env.update({k: str(v) for k, v in (self.options.env or {}).items()})
        # This runtime is explicitly the ChatGPT OAuth path. Never let an API
        # key inherited from .env silently switch billing/auth semantics.
        env.pop("OPENAI_API_KEY", None)
        env.pop("CODEX_API_KEY", None)
        return env

    async def receive_response(
        self, *, turn_timeout_s: float | None = None
    ) -> AsyncIterator[Any]:
        if self._pending_prompt is None:
            raise CodexCLIError("query() must be called before receive_response()")
        if self._closed:
            raise CodexCLIError("Codex client is closed")
        if self._codex_bin is None:
            await self.start()

        prompt = self._pending_prompt
        self._pending_prompt = None
        resuming = bool(self.session_id)
        prompt = self._instructions(prompt, resuming=resuming)
        timeout_value = (
            turn_timeout_s
            if turn_timeout_s is not None
            else self.options.turn_timeout_s
            if self.options.turn_timeout_s is not None
            else os.environ.get("CODEX_TURN_TIMEOUT_S", DEFAULT_TURN_TIMEOUT_S)
        )
        timeout = _positive_timeout(timeout_value)
        self._turn_count += 1
        started = time.monotonic()
        event_job_id, event_role, event_model = context_from_options(self.options)
        emit_gpt_event(
            event_job_id,
            "turn_started",
            role=event_role,
            model=event_model,
            turn=self._turn_count,
            status="running",
            title="Turn 시작",
        )
        stderr_parts: list[str] = []
        started_tools: set[str] = set()
        tool_started_at: dict[str, float] = {}
        error = False
        turn_completed = False
        stop_reason = "completed"
        turn_usage: dict[str, int] = {}

        command = self._command(resuming=resuming)
        cwd = Path(self.options.cwd)
        cwd.mkdir(parents=True, exist_ok=True)
        turn_guard = None
        try:
            # Acquire outside the subprocess and inherit the descriptor into
            # Codex.  The API can therefore distinguish "RQ stop was sent"
            # from "the actual CLI writer has terminated" before resuming the
            # same thread in a successor job.
            turn_guard = await asyncio.to_thread(acquire_turn_guard, cwd)
            self._proc = await asyncio.create_subprocess_exec(
                *command,
                cwd=str(cwd),
                env=self._environment(),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
                limit=SUBPROCESS_STREAM_LIMIT_BYTES,
                pass_fds=(turn_guard.fileno(),),
            )
        except Exception as exc:
            release_turn_guard(turn_guard)
            turn_guard = None
            emit_gpt_event(
                event_job_id,
                "turn_failed",
                role=event_role,
                model=event_model,
                turn=self._turn_count,
                status="failed",
                summary=f"{type(exc).__name__}: {exc}"[:1000],
            )
            yield AssistantMessage(
                [TextBlock(f"[Codex CLI launch error] {type(exc).__name__}: {exc}")]
            )
            yield self._result(started, True, "process_error")
            return

        assert self._proc.stdin and self._proc.stdout and self._proc.stderr
        self._proc.stdin.write(prompt.encode("utf-8", errors="replace"))
        await self._proc.stdin.drain()
        self._proc.stdin.close()
        stderr_task = asyncio.create_task(
            self._collect_stderr(self._proc.stderr, stderr_parts)
        )

        try:
            while True:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise asyncio.TimeoutError
                line, dropped = await asyncio.wait_for(
                    _read_bounded_jsonl_line(
                        self._proc.stdout,
                        hard_cap=MAX_JSONL_EVENT_BYTES,
                    ),
                    remaining,
                )
                if dropped:
                    summary = (
                        "Codex CLI JSONL event exceeded the "
                        f"{MAX_JSONL_EVENT_BYTES}-byte hard cap; drained through "
                        "the delimiter and resumed at the next event"
                    )
                    emit_gpt_event(
                        event_job_id,
                        "stream_event_dropped",
                        role=event_role,
                        model=event_model,
                        turn=self._turn_count,
                        status="warning",
                        title="Oversized event dropped",
                        summary=summary,
                    )
                    yield AssistantMessage([TextBlock(f"[Codex CLI warning] {summary}")])
                    continue
                if not line:
                    break
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(event, dict):
                    continue
                event_type = str(event.get("type") or "")

                if event_type == "thread.started":
                    sid = str(event.get("thread_id") or "").strip()
                    if sid:
                        self.session_id = sid
                        emit_gpt_event(
                            event_job_id,
                            "agent_started",
                            role=event_role,
                            model=event_model,
                            session_id=sid,
                            turn=self._turn_count,
                            status="running",
                            title="Agent 시작",
                        )
                        yield SystemMessage(
                            {
                                "type": "init",
                                "subtype": "init",
                                "session_id": sid,
                                "auth": "chatgpt_oauth",
                            }
                        )
                    continue

                if event_type in {"item.started", "item.completed"}:
                    item = event.get("item") or {}
                    if not isinstance(item, dict):
                        continue
                    kind = str(item.get("type") or "")
                    item_id = str(item.get("id") or f"{kind}-{len(started_tools)}")
                    if kind == "agent_message" and event_type == "item.completed":
                        text = str(item.get("text") or "")
                        if text:
                            emit_gpt_event(
                                event_job_id,
                                "message",
                                role=event_role,
                                model=event_model,
                                turn=self._turn_count,
                                status="info",
                                title="분석 업데이트",
                                summary=text[:4000],
                            )
                            yield AssistantMessage([TextBlock(text)])
                        continue
                    if kind not in _TOOL_ITEM_TYPES:
                        continue
                    if item_id not in started_tools:
                        name, raw_input = _tool_name_and_input(item)
                        started_tools.add(item_id)
                        tool_started_at[item_id] = time.monotonic()
                        lower_name = name.lower()
                        timeline_kind = (
                            "wait" if lower_name == "wait"
                            else "artifact" if name in {"Edit", "Write"}
                            else "delegation" if lower_name == "spawn_agent"
                            else "tool_started"
                        )
                        event_fields: dict[str, Any] = {
                            "role": event_role,
                            "model": event_model,
                            "turn": self._turn_count,
                            "call_id": item_id,
                            "tool": name,
                            "status": "running",
                            "title": (
                                "Subagent 작업 대기"
                                if timeline_kind == "wait"
                                else f"{name} 실행"
                            ),
                            "input": raw_input,
                        }
                        if timeline_kind == "delegation":
                            event_fields["target_role"] = str(
                                raw_input.get("agent_type") or raw_input.get("role") or "subagent"
                            )
                            event_fields["agent_name"] = str(
                                raw_input.get("task_name") or raw_input.get("name") or ""
                            )
                            event_fields["title"] = (
                                f"{event_fields['target_role']} subagent 시작"
                            )
                        if lower_name == "wait":
                            event_fields["summary"] = "native subagent 응답을 기다리는 중"
                        emit_gpt_event(event_job_id, timeline_kind, **event_fields)
                        yield AssistantMessage(
                            [ToolUseBlock(name=name, input=raw_input, id=item_id)]
                        )
                    if event_type == "item.completed":
                        body, item_error = _tool_result(item)
                        name, raw_input = _tool_name_and_input(item)
                        elapsed = tool_started_at.pop(item_id, None)
                        emit_gpt_event(
                            event_job_id,
                            "tool_completed",
                            role=event_role,
                            model=event_model,
                            turn=self._turn_count,
                            call_id=item_id,
                            tool=name,
                            status="failed" if item_error else "completed",
                            duration_ms=(
                                int((time.monotonic() - elapsed) * 1000)
                                if elapsed is not None else None
                            ),
                            summary=(
                                "native subagent 응답 수신"
                                if name.lower() == "wait"
                                else " ".join(body.split())[:240]
                            ),
                            output_lines=len(body.splitlines()),
                            output_bytes=len(body.encode("utf-8", errors="replace")),
                            detail=body[:12000],
                            input=raw_input,
                        )
                        if body:
                            yield UserMessage(
                                [
                                    ToolResultBlock(
                                        content=body,
                                        is_error=item_error,
                                        tool_use_id=item_id,
                                    )
                                ]
                            )
                    continue

                if event_type == "turn.completed":
                    turn_completed = True
                    turn_usage = _usage_from_event(event.get("usage"))
                    _merge_usage(self._usage_totals, turn_usage)
                    continue
                if event_type in {"turn.failed", "error"}:
                    error = True
                    stop_reason = (
                        "turn_failed" if event_type == "turn.failed" else "error"
                    )
                    detail = event.get("error") or event.get("message") or event
                    yield AssistantMessage(
                        [
                            TextBlock(
                                f"[Codex CLI {stop_reason}] {_cap_text(_json_text(detail))}"
                            )
                        ]
                    )

            return_code = await self._proc.wait()
            try:
                await stderr_task
            except Exception:
                pass
            if return_code != 0:
                error = True
                stop_reason = "process_error"
                detail = "".join(stderr_parts).strip()
                if detail:
                    yield AssistantMessage(
                        [
                            TextBlock(
                                f"[Codex CLI exited {return_code}] {_cap_text(detail)}"
                            )
                        ]
                    )
            elif not turn_completed and not error:
                error = True
                stop_reason = "unexpected_eof"
                yield AssistantMessage(
                    [TextBlock("[Codex CLI ended before turn.completed]")]
                )
        except asyncio.TimeoutError:
            error = True
            stop_reason = "timeout"
            await self._stop_process()
            yield AssistantMessage(
                [TextBlock(f"[Codex CLI turn timed out after {timeout:.0f}s]")]
            )
        finally:
            # Normal completion is already reaped, so this is a cheap no-op in
            # the common case.  On cancellation or any other BaseException it is
            # the only owner-aware cleanup path: terminate the process group
            # before discarding the handle that close() would otherwise need.
            await self._stop_process()
            if not stderr_task.done():
                stderr_task.cancel()
            try:
                await stderr_task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
            self._proc = None
            release_turn_guard(turn_guard)

        duration_ms = int((time.monotonic() - started) * 1000)
        emit_gpt_event(
            event_job_id,
            "turn_failed" if error else "turn_completed",
            role=event_role,
            model=event_model,
            turn=self._turn_count,
            status="failed" if error else "completed",
            stop_reason=stop_reason,
            duration_ms=duration_ms,
            title="Turn 실패" if error else "Turn 완료",
        )
        if turn_usage:
            yield AssistantMessage([], usage=_heartbeat_usage(turn_usage))
        yield self._result(started, error, stop_reason)

    def _result(
        self,
        started: float,
        error: bool,
        stop_reason: str,
    ) -> ResultMessage:
        model_usage = {}
        if any(self._usage_totals.values()):
            model_usage[str(self.options.model)] = dict(self._usage_totals)
        return ResultMessage(
            duration_ms=int((time.monotonic() - started) * 1000),
            num_turns=self._turn_count,
            total_cost_usd=None,
            is_error=error,
            stop_reason=stop_reason,
            usage=dict(self._usage_totals),
            session_id=self.session_id,
            model_usage=model_usage,
        )

    async def _collect_stderr(
        self, stream: asyncio.StreamReader, parts: list[str]
    ) -> None:
        while True:
            chunk = await stream.read(4096)
            if not chunk:
                return
            if sum(len(part) for part in parts) < MAX_STDERR_CHARS:
                parts.append(chunk.decode("utf-8", errors="replace"))

    async def _stop_process(self) -> None:
        proc = self._proc
        if proc is None or proc.returncode is not None:
            return
        # The fallback has to be guarded for the same reason it exists. A
        # ProcessLookupError from killpg most often means the whole group is
        # already gone — so `proc.terminate()` raises it straight back, out of
        # a teardown path whose entire job is to not care whether the child
        # outlived us. Measured flaky, not theoretical: 2 red in 4 runs of
        # test_codex_cli.py, traceback at the unguarded proc.kill.
        #
        # ProcessLookupError ONLY. The first version caught OSError too, which
        # made EPERM and EIO — genuine "could not clean up" failures — return
        # as if teardown had succeeded. That does not remove a flake, it
        # removes the observation of one. Narrowing still closes the race this
        # guard exists for: repeats stay green with EPERM left to propagate.
        #
        # The returncode check at the top of this method cannot close the
        # window either — the process can exit between that check and here.
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            try:
                proc.terminate()
            except ProcessLookupError:
                return
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
            return
        except asyncio.TimeoutError:
            pass
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                proc.kill()
            except ProcessLookupError:
                return
        try:
            await proc.wait()
        except Exception:
            pass


async def query_codex_once(
    *,
    prompt: str,
    cwd: str,
    system_prompt: str,
    model: str,
    effort: str | None = None,
    timeout_s: float | None = None,
    enable_tools: bool = False,
    enable_subagents: bool = False,
) -> dict[str, Any]:
    """Run one Codex OAuth turn and return the provider-neutral helper view."""
    options = GptSessionOptions(
        system_prompt=system_prompt,
        model=model,
        cwd=cwd,
        effort=effort,
        turn_timeout_s=timeout_s,
        append_tool_addendum=enable_tools,
        enable_tools=enable_tools,
        enable_subagents=enable_subagents,
    )
    text_parts: list[str] = []
    result: ResultMessage | None = None
    tool_used = False
    try:
        async with CodexCLIClient(options) as client:
            await client.query(prompt)
            async for message in client.receive_response(turn_timeout_s=timeout_s):
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            text_parts.append(block.text)
                        elif isinstance(block, ToolUseBlock):
                            tool_used = True
                elif isinstance(message, ResultMessage):
                    result = message
    except Exception as exc:
        return {
            "text": "".join(text_parts),
            "error": f"{type(exc).__name__}: {exc}",
        }
    error_text = None
    if tool_used and not enable_tools:
        error_text = "tool_use_in_text_only_role: Codex attempted a tool call"
    elif result is not None and result.is_error:
        error_text = f"Codex CLI turn ended with {result.stop_reason or 'error'}"
    return {
        "text": "".join(text_parts),
        "error": error_text,
        "session_id": getattr(result, "session_id", None),
        "usage": getattr(result, "usage", {}) if result else {},
        "model_usage": getattr(result, "model_usage", {}) if result else {},
    }
