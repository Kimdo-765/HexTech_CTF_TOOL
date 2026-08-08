"""OpenAI Responses API coding-agent adapter for HexTech CTF jobs.

The rest of the project consumes a small ``ClaudeSDKClient``-like surface::

    async with GptResponsesClient(options) as client:
        await client.query(prompt)
        async for message in client.receive_response():
            ...

This module implements that surface on top of the official OpenAI Python SDK
and the Responses API.  Local function tools give GPT the same practical
worker access as the existing Claude/Grok agents (shell, files, grep/glob,
web fetch/search and isolated subagents).  Message classes intentionally use
the Claude SDK class names so the shared logging, liveness and token-accounting
code can stay provider-neutral.
"""

from __future__ import annotations

import asyncio
import fnmatch
import html
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator
from urllib.parse import parse_qs, unquote, urlparse

from modules.gpt_run_events import context_from_options, emit_gpt_event


# ---------------------------------------------------------------------------
# Duck-typed SDK-compatible messages
# ---------------------------------------------------------------------------


class TextBlock:
    def __init__(self, text: str):
        self.text = text
        self.type = "text"


class ToolUseBlock:
    def __init__(self, name: str, input: dict | None = None, id: str | None = None):
        self.name = name
        self.input = input or {}
        self.id = id or ""
        self.type = "tool_use"


class ToolResultBlock:
    def __init__(
        self, content=None, is_error: bool = False, tool_use_id: str | None = None
    ):
        self.content = content if content is not None else ""
        self.is_error = bool(is_error)
        self.tool_use_id = tool_use_id or ""
        self.type = "tool_result"


class AssistantMessage:
    def __init__(
        self,
        content: list | None = None,
        usage: dict | None = None,
        message_id: str | None = None,
    ):
        self.content = content or []
        self.role = "assistant"
        self.usage = usage or {}
        self.message_id = message_id


class UserMessage:
    def __init__(self, content: list | None = None):
        self.content = content or []
        self.role = "user"


class ResultMessage:
    def __init__(
        self,
        *,
        duration_ms: int | None = None,
        num_turns: int | None = None,
        total_cost_usd: float | None = None,
        is_error: bool = False,
        stop_reason: str | None = None,
        usage: dict | None = None,
        session_id: str | None = None,
        model_usage: dict | None = None,
    ):
        self.duration_ms = duration_ms
        self.num_turns = num_turns
        self.total_cost_usd = total_cost_usd
        self.is_error = bool(is_error)
        self.stop_reason = stop_reason
        self.usage = usage or {}
        self.session_id = session_id
        self.model_usage = model_usage or {}


class SystemMessage:
    def __init__(self, data: dict):
        self.data = data
        self.subtype = data.get("subtype") or data.get("type") or "init"


# ---------------------------------------------------------------------------
# Options and tool declarations
# ---------------------------------------------------------------------------


GPT_TOOL_ADDENDUM = """
## OPENAI GPT TOOL SURFACE

This section supersedes any Claude SDK / MCP tool wording earlier in the
system prompt. This session runs through the OpenAI Responses API. Available local tools are
`Read`, `Write`, `Edit`, `Bash`, `Glob`, `Grep`, `WebSearch`, and `WebFetch`.
Deliverables must still be written as relative paths in the current working
directory (`exploit.py` / `solver.py` / `report.md`). Print
`FLAG_CANDIDATE: <flag>` when a real flag is captured.
""".strip()


def adapt_system_prompt_for_gpt(system_prompt: str) -> str:
    """Translate Claude MCP delegation wording to the GPT tool schema."""
    text = str(system_prompt or "")
    text = text.replace("mcp__team__spawn_subagent", "spawn_subagent")
    text = text.replace("subagent_type=", "role=")
    text = text.replace("subagent_type ∈", "role ∈")
    text = text.replace("the isolated MCP tool", "the `spawn_subagent` tool")
    text = text.replace("via the isolated MCP tool", "via `spawn_subagent`")
    text = text.replace("the MCP tool `spawn_subagent`", "the `spawn_subagent` tool")
    return text


DEFAULT_TURN_TIMEOUT_S = 3600.0
DEFAULT_MAX_TOOL_ROUNDS = 160
MAX_TOOL_OUTPUT_CHARS = 48_000


@dataclass
class GptSessionOptions:
    system_prompt: str
    model: str
    cwd: str
    effort: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    resume: str | None = None
    add_dirs: list[str] = field(default_factory=list)
    max_turns: int | None = None
    turn_timeout_s: float | None = None
    append_tool_addendum: bool = True
    enable_tools: bool = True
    enable_subagents: bool = True


def _function_tool(
    name: str, description: str, properties: dict, required: list[str]
) -> dict:
    return {
        "type": "function",
        "name": name,
        "description": description,
        "parameters": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        },
        "strict": True,
    }


def _tool_specs(enable_subagents: bool = True) -> list[dict]:
    tools = [
        _function_tool(
            "Read",
            "Read a UTF-8 text file. Relative paths resolve from the session cwd.",
            {
                "file_path": {"type": "string"},
                "offset": {"type": ["integer", "null"]},
                "limit": {"type": ["integer", "null"]},
            },
            ["file_path", "offset", "limit"],
        ),
        _function_tool(
            "Write",
            "Create or replace a text file. Relative paths resolve from cwd.",
            {
                "file_path": {"type": "string"},
                "content": {"type": "string"},
            },
            ["file_path", "content"],
        ),
        _function_tool(
            "Edit",
            "Replace an exact string in a text file.",
            {
                "file_path": {"type": "string"},
                "old_string": {"type": "string"},
                "new_string": {"type": "string"},
                "replace_all": {"type": "boolean"},
            },
            ["file_path", "old_string", "new_string", "replace_all"],
        ),
        _function_tool(
            "Bash",
            "Run a shell command in cwd and return combined stdout/stderr.",
            {
                "command": {"type": "string"},
                "timeout_seconds": {"type": ["integer", "null"]},
            },
            ["command", "timeout_seconds"],
        ),
        _function_tool(
            "Glob",
            "List paths matching a glob pattern, sorted by modification time.",
            {
                "pattern": {"type": "string"},
                "path": {"type": ["string", "null"]},
            },
            ["pattern", "path"],
        ),
        _function_tool(
            "Grep",
            "Regex-search text files and return path:line:match records.",
            {
                "pattern": {"type": "string"},
                "path": {"type": ["string", "null"]},
                "glob": {"type": ["string", "null"]},
                "max_results": {"type": ["integer", "null"]},
            },
            ["pattern", "path", "glob", "max_results"],
        ),
        _function_tool(
            "WebFetch",
            "Fetch an HTTP(S) URL and return status, headers and text body.",
            {
                "url": {"type": "string"},
                "prompt": {"type": ["string", "null"]},
            },
            ["url", "prompt"],
        ),
        _function_tool(
            "WebSearch",
            "Search the public web and return result titles, URLs and snippets.",
            {
                "query": {"type": "string"},
                "max_results": {"type": ["integer", "null"]},
            },
            ["query", "max_results"],
        ),
    ]
    if enable_subagents:
        tools.append(
            _function_tool(
                "spawn_subagent",
                "Run one isolated GPT subagent and return only its final report.",
                {
                    "role": {
                        "type": "string",
                        "enum": ["recon", "debugger", "triage", "judge"],
                    },
                    "prompt": {"type": "string"},
                },
                ["role", "prompt"],
            )
        )
    return tools


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class GptResponsesError(RuntimeError):
    pass


class GptResponsesClient:
    """Long-lived, multi-turn Responses API client with a local tool loop."""

    def __init__(self, options: GptSessionOptions):
        self.options = options
        self.session_id: str | None = options.resume
        self._pending_prompt: str | None = None
        self._client = None
        self._closed = False
        self._turn_count = 0
        self._usage_totals = {
            "inputTokens": 0,
            "outputTokens": 0,
            "cacheCreationInputTokens": 0,
            "cacheReadInputTokens": 0,
        }
        self._model_usage_totals: dict[str, dict[str, int]] = {}

    async def __aenter__(self) -> "GptResponsesClient":
        await self.start()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def start(self) -> None:
        if self._client is not None:
            return
        key = str(os.environ.get("OPENAI_API_KEY") or "").strip()
        if not key or key.endswith("..."):
            raise GptResponsesError(
                "OPENAI_API_KEY is not configured. Set it in Settings or .env."
            )
        try:
            from openai import AsyncOpenAI
        except Exception as e:  # pragma: no cover - exercised in container build
            raise GptResponsesError(
                "the OpenAI Python SDK is not installed; rebuild the api/worker "
                "images after updating requirements"
            ) from e
        timeout = self.options.turn_timeout_s or _env_float(
            "GPT_TURN_TIMEOUT_S", DEFAULT_TURN_TIMEOUT_S
        )
        self._client = AsyncOpenAI(api_key=key, timeout=timeout)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._client is not None:
            close = getattr(self._client, "close", None)
            if close is not None:
                try:
                    await close()
                except Exception:
                    pass

    async def query(self, prompt: str) -> None:
        if self._client is None:
            await self.start()
        if self._pending_prompt is not None:
            raise GptResponsesError("a GPT turn is already pending")
        self._pending_prompt = str(prompt or " ")

    async def receive_response(
        self, *, turn_timeout_s: float | None = None
    ) -> AsyncIterator[Any]:
        if self._pending_prompt is None:
            raise GptResponsesError("query() must be called before receive_response()")
        assert self._client is not None

        prompt = self._pending_prompt
        self._pending_prompt = None
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
        timeout = (
            turn_timeout_s
            or self.options.turn_timeout_s
            or _env_float("GPT_TURN_TIMEOUT_S", DEFAULT_TURN_TIMEOUT_S)
        )
        max_rounds = self.options.max_turns or _env_int(
            "GPT_MAX_TOOL_ROUNDS", DEFAULT_MAX_TOOL_ROUNDS
        )
        instructions = self.options.system_prompt or ""
        if self.options.enable_tools:
            instructions = adapt_system_prompt_for_gpt(instructions)
        if self.options.append_tool_addendum and self.options.enable_tools:
            instructions = instructions.rstrip() + "\n\n" + GPT_TOOL_ADDENDUM
            instructions += (
                '\nUse `spawn_subagent(role="recon|debugger|triage|judge", '
                'prompt="...")` for isolated delegated work.'
                if self.options.enable_subagents
                else "\nSubagent delegation is disabled for this phase; solve the "
                "bounded task with the listed local tools only."
            )
        tools = (
            _tool_specs(self.options.enable_subagents)
            if self.options.enable_tools
            else []
        )
        next_input: Any = prompt
        previous_id = self.session_id
        error = False
        stop_reason = "completed"

        for _round in range(max_rounds):
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                error = True
                stop_reason = "timeout"
                yield AssistantMessage(
                    [TextBlock(f"[GPT turn timed out after {timeout:.0f}s]")]
                )
                break

            kwargs: dict[str, Any] = {
                "model": self.options.model,
                "instructions": instructions,
                "input": next_input,
                "store": True,
            }
            if previous_id:
                kwargs["previous_response_id"] = previous_id
            if tools:
                kwargs["tools"] = tools
            effort = _normalize_effort(self.options.effort)
            if effort:
                kwargs["reasoning"] = {"effort": effort}

            try:
                response = await asyncio.wait_for(
                    self._client.responses.create(**kwargs), timeout=remaining
                )
            except asyncio.TimeoutError:
                error = True
                stop_reason = "timeout"
                yield AssistantMessage(
                    [TextBlock(f"[GPT Responses API timed out after {timeout:.0f}s]")]
                )
                break
            except Exception as e:
                error = True
                stop_reason = "api_error"
                yield AssistantMessage(
                    [TextBlock(f"[GPT Responses API error] {type(e).__name__}: {e}")]
                )
                break

            self.session_id = str(getattr(response, "id", "") or previous_id or "")
            previous_id = self.session_id
            if self.session_id:
                # Persist every new response id. A tool loop creates several
                # responses; only the newest one contains the complete chain
                # that a later /retry or /continue should resume from.
                yield SystemMessage(
                    {
                        "type": "init",
                        "subtype": "init",
                        "session_id": self.session_id,
                    }
                )

            usage = _response_usage(response)
            _merge_usage(self._usage_totals, usage)
            response_model = str(getattr(response, "model", "") or self.options.model)
            _merge_usage(self._model_usage_totals.setdefault(response_model, {}), usage)
            blocks, calls = _response_blocks(response)
            refused = _response_has_refusal(response)
            if blocks:
                for block in blocks:
                    if isinstance(block, TextBlock) and block.text:
                        emit_gpt_event(
                            event_job_id,
                            "message",
                            role=event_role,
                            model=response_model,
                            turn=self._turn_count,
                            status="info",
                            title="분석 업데이트",
                            summary=block.text[:4000],
                        )
                yield AssistantMessage(
                    blocks,
                    usage=_usage_for_heartbeat(usage),
                    message_id=self.session_id,
                )

            status = str(getattr(response, "status", "completed") or "completed")
            if status in {"failed", "cancelled"}:
                error = True
                stop_reason = status
                break
            if status == "incomplete" and not calls:
                error = True
                details = getattr(response, "incomplete_details", None)
                stop_reason = str(getattr(details, "reason", None) or "incomplete")
                break
            if refused and not calls:
                error = True
                stop_reason = "refusal"
                break

            if not calls:
                stop_reason = status
                break

            outputs: list[dict[str, str]] = []
            for call in calls:
                call_id = str(getattr(call, "call_id", "") or "")
                name = str(getattr(call, "name", "") or "")
                tool_started = time.monotonic()
                try:
                    args = json.loads(getattr(call, "arguments", "{}") or "{}")
                    if not isinstance(args, dict):
                        args = {"value": args}
                except Exception as e:
                    args = {}
                    result = f"ERROR: invalid JSON arguments: {e}"
                    is_error = True
                else:
                    timeline_kind = (
                        "artifact" if name in {"Edit", "Write"}
                        else "delegation" if name == "spawn_subagent"
                        else "tool_started"
                    )
                    emit_gpt_event(
                        event_job_id,
                        timeline_kind,
                        role=event_role,
                        model=response_model,
                        turn=self._turn_count,
                        call_id=call_id,
                        tool=name,
                        status="running",
                        title=(
                            f"{args.get('role', 'subagent')} subagent 시작"
                            if name == "spawn_subagent" else f"{name} 실행"
                        ),
                        input=args,
                        target_role=(args.get("role") if name == "spawn_subagent" else None),
                    )
                    try:
                        result = await self._execute_tool(name, args)
                        is_error = result.startswith("ERROR:")
                    except Exception as e:
                        result = f"ERROR: {type(e).__name__}: {e}"
                        is_error = True
                result = _cap_text(result)
                emit_gpt_event(
                    event_job_id,
                    "tool_completed",
                    role=event_role,
                    model=response_model,
                    turn=self._turn_count,
                    call_id=call_id,
                    tool=name,
                    status="failed" if is_error else "completed",
                    duration_ms=int((time.monotonic() - tool_started) * 1000),
                    summary=" ".join(result.split())[:240],
                    output_lines=len(result.splitlines()),
                    output_bytes=len(result.encode("utf-8", errors="replace")),
                    detail=result[:12000],
                    input=args,
                )
                yield UserMessage(
                    [
                        ToolResultBlock(
                            content=result,
                            is_error=is_error,
                            tool_use_id=call_id,
                        )
                    ]
                )
                outputs.append(
                    {
                        "type": "function_call_output",
                        "call_id": call_id,
                        "output": result,
                    }
                )
            next_input = outputs
        else:
            error = True
            stop_reason = "max_tool_rounds"
            yield AssistantMessage(
                [TextBlock(f"[GPT tool loop stopped after {max_rounds} rounds]")]
            )

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
        estimated_cost = _estimate_model_usage_cost(self._model_usage_totals)
        yield ResultMessage(
            duration_ms=duration_ms,
            num_turns=self._turn_count,
            total_cost_usd=estimated_cost if estimated_cost > 0 else None,
            is_error=error,
            stop_reason=stop_reason,
            usage=dict(self._usage_totals),
            session_id=self.session_id,
            model_usage={
                model: dict(totals)
                for model, totals in self._model_usage_totals.items()
            },
        )

    async def _execute_tool(self, name: str, args: dict) -> str:
        handlers = {
            "Read": self._read,
            "Write": self._write,
            "Edit": self._edit,
            "Bash": self._bash,
            "Glob": self._glob,
            "Grep": self._grep,
            "WebFetch": self._web_fetch,
            "WebSearch": self._web_search,
            "spawn_subagent": self._spawn_subagent,
        }
        handler = handlers.get(name)
        if handler is None:
            return f"ERROR: unknown tool {name!r}"
        return await handler(args)

    def _path(self, raw: str | None) -> Path:
        p = Path(str(raw or "."))
        return p if p.is_absolute() else Path(self.options.cwd) / p

    async def _read(self, args: dict) -> str:
        path = self._path(args.get("file_path"))
        if not path.is_file():
            return f"ERROR: file not found: {path}"
        try:
            text = path.read_text(errors="replace")
        except Exception as e:
            return f"ERROR: cannot read {path}: {e}"
        offset = max(1, int(args.get("offset") or 1))
        limit = max(1, min(int(args.get("limit") or 2000), 5000))
        lines = text.splitlines()
        selected = lines[offset - 1 : offset - 1 + limit]
        body = "\n".join(f"{n:6d}\t{line}" for n, line in enumerate(selected, offset))
        if offset - 1 + limit < len(lines):
            body += f"\n... ({len(lines) - (offset - 1 + limit)} more lines)"
        return body

    async def _write(self, args: dict) -> str:
        path = self._path(args.get("file_path"))
        content = str(args.get("content") or "")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        except Exception as e:
            return f"ERROR: cannot write {path}: {e}"
        return f"wrote {len(content)} characters to {path}"

    async def _edit(self, args: dict) -> str:
        path = self._path(args.get("file_path"))
        old = str(args.get("old_string") or "")
        new = str(args.get("new_string") or "")
        if not old:
            return "ERROR: old_string must not be empty"
        try:
            text = path.read_text(errors="replace")
        except Exception as e:
            return f"ERROR: cannot read {path}: {e}"
        count = text.count(old)
        if count == 0:
            return "ERROR: old_string was not found"
        if count > 1 and not bool(args.get("replace_all")):
            return f"ERROR: old_string occurs {count} times; use replace_all"
        changed = (
            text.replace(old, new)
            if args.get("replace_all")
            else text.replace(old, new, 1)
        )
        try:
            path.write_text(changed)
        except Exception as e:
            return f"ERROR: cannot write {path}: {e}"
        return f"replaced {count if args.get('replace_all') else 1} occurrence(s) in {path}"

    async def _bash(self, args: dict) -> str:
        command = str(args.get("command") or "")
        if not command.strip():
            return "ERROR: empty command"
        try:
            from modules._common import dangerous_kill_reason

            blocked = dangerous_kill_reason(command)
        except Exception:
            blocked = None
        if blocked:
            return f"ERROR: {blocked}"
        timeout = max(1, min(int(args.get("timeout_seconds") or 120), 1800))
        env = os.environ.copy()
        env.update({k: str(v) for k, v in (self.options.env or {}).items()})
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                cwd=str(Path(self.options.cwd)),
                env=env,
                executable="/bin/bash",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                stdout, _ = await proc.communicate()
                return _cap_text(
                    stdout.decode("utf-8", errors="replace")
                    + f"\nERROR: command timed out after {timeout}s"
                )
        except Exception as e:
            return f"ERROR: command failed to start: {e}"
        text = stdout.decode("utf-8", errors="replace")
        return _cap_text(text + f"\n[exit code {proc.returncode}]")

    async def _glob(self, args: dict) -> str:
        base = self._path(args.get("path") or ".")
        pattern = str(args.get("pattern") or "*")
        try:
            paths = list(base.glob(pattern))
            paths.sort(
                key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True
            )
        except Exception as e:
            return f"ERROR: glob failed: {e}"
        return "\n".join(str(p) for p in paths[:1000]) or "(no matches)"

    async def _grep(self, args: dict) -> str:
        base = self._path(args.get("path") or ".")
        pattern = str(args.get("pattern") or "")
        file_glob = str(args.get("glob") or "*")
        max_results = max(1, min(int(args.get("max_results") or 500), 2000))
        try:
            rx = re.compile(pattern)
        except re.error as e:
            return f"ERROR: invalid regex: {e}"

        def _scan() -> str:
            files = [base] if base.is_file() else base.rglob("*")
            out: list[str] = []
            for path in files:
                if len(out) >= max_results:
                    break
                try:
                    if not path.is_file() or not fnmatch.fnmatch(path.name, file_glob):
                        continue
                    if path.stat().st_size > 8 * 1024 * 1024:
                        continue
                    for lineno, line in enumerate(
                        path.read_text(errors="replace").splitlines(), 1
                    ):
                        if rx.search(line):
                            out.append(f"{path}:{lineno}:{line[:2000]}")
                            if len(out) >= max_results:
                                break
                except (OSError, UnicodeError):
                    continue
            return "\n".join(out) or "(no matches)"

        return _cap_text(_scan())

    async def _web_fetch(self, args: dict) -> str:
        url = str(args.get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            return "ERROR: only http:// and https:// URLs are supported"
        try:
            import httpx

            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=30.0,
                headers={"User-Agent": "HexTech-CTF-GPT-Agent/1.0"},
            ) as client:
                response = await client.get(url)
            body = response.text
            prompt = str(args.get("prompt") or "").strip()
            prefix = f"HTTP {response.status_code} {response.url}\n"
            if prompt:
                prefix += f"Requested focus: {prompt}\n"
            return _cap_text(prefix + body)
        except Exception as e:
            return f"ERROR: fetch failed: {type(e).__name__}: {e}"

    async def _web_search(self, args: dict) -> str:
        query = str(args.get("query") or "").strip()
        if not query:
            return "ERROR: empty search query"
        limit = max(1, min(int(args.get("max_results") or 8), 20))
        try:
            import httpx

            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=30.0,
                headers={"User-Agent": "Mozilla/5.0 HexTech-CTF-Agent"},
            ) as client:
                response = await client.get(
                    "https://html.duckduckgo.com/html/", params={"q": query}
                )
            response.raise_for_status()
            page = response.text
        except Exception as e:
            return f"ERROR: search failed: {type(e).__name__}: {e}"
        rows = re.findall(
            r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>.*?'
            r'class="result__snippet"[^>]*>(.*?)</(?:a|div)>',
            page,
            flags=re.I | re.S,
        )
        out: list[str] = []
        for raw_url, raw_title, raw_snippet in rows[:limit]:
            url = html.unescape(raw_url)
            parsed = urlparse(url)
            if "duckduckgo.com" in parsed.netloc and parsed.path.startswith("/l/"):
                url = unquote((parse_qs(parsed.query).get("uddg") or [url])[0])
            title = _strip_html(raw_title)
            snippet = _strip_html(raw_snippet)
            out.append(f"{len(out) + 1}. {title}\n{url}\n{snippet}")
        return "\n\n".join(out) if out else "(no results parsed)"

    async def _spawn_subagent(self, args: dict) -> str:
        if not self.options.enable_subagents:
            return "ERROR: subagents are disabled in this session"
        role = str(args.get("role") or "recon").strip().lower()
        prompt = str(args.get("prompt") or "").strip()
        role_rules = {
            "recon": "Investigate statically. Cite paths/lines and return a concise evidence report.",
            "debugger": "Perform focused dynamic analysis. Record commands, observations and caveats.",
            "triage": "Independently verify the supplied candidate claims and reject unsupported ones.",
            "judge": "Review for correctness, hangs and parse/runtime failures. Return actionable findings.",
        }
        if role not in role_rules:
            return f"ERROR: unsupported subagent role {role!r}"
        child_model = self.options.model
        try:
            from modules.agent_provider import coerce_model_for_provider
            from modules.model_presets import resolve_role_model

            child_model = coerce_model_for_provider(
                resolve_role_model(role, child_model, "gpt"), "gpt"
            )
        except Exception:
            pass
        child = GptResponsesClient(
            GptSessionOptions(
                system_prompt=(
                    f"You are HexTech's isolated {role} subagent. {role_rules[role]} "
                    "Use the available local tools as needed. Do not delegate again."
                ),
                model=child_model,
                cwd=self.options.cwd,
                effort=self.options.effort,
                env={**dict(self.options.env), "AGENT_ROLE": role},
                add_dirs=list(self.options.add_dirs),
                turn_timeout_s=self.options.turn_timeout_s,
                enable_tools=True,
                enable_subagents=False,
            )
        )
        chunks: list[str] = []
        result_error = False
        async with child:
            await child.query(prompt)
            async for msg in child.receive_response():
                if isinstance(msg, AssistantMessage):
                    for block in msg.content:
                        if isinstance(block, TextBlock):
                            chunks.append(block.text)
                elif isinstance(msg, ResultMessage):
                    result_error = msg.is_error
        _merge_usage(self._usage_totals, child._usage_totals)
        for model, totals in child._model_usage_totals.items():
            _merge_usage(self._model_usage_totals.setdefault(model, {}), totals)
        body = "\n".join(chunks).strip()
        if result_error and not body:
            return f"ERROR: {role} subagent failed without output"
        return _cap_text(body or f"({role} subagent returned no text)")


# ---------------------------------------------------------------------------
# One-shot helper used by judge/reviewer/report/monitor phases
# ---------------------------------------------------------------------------


async def query_gpt_once(
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
    opts = GptSessionOptions(
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
    try:
        async with GptResponsesClient(opts) as client:
            await client.query(prompt)
            async for msg in client.receive_response(turn_timeout_s=timeout_s):
                if isinstance(msg, AssistantMessage):
                    for block in msg.content:
                        if isinstance(block, TextBlock):
                            text_parts.append(block.text)
                elif isinstance(msg, ResultMessage):
                    result = msg
    except Exception as e:
        return {"text": "".join(text_parts), "error": f"{type(e).__name__}: {e}"}
    error_text = None
    if result is not None and result.is_error:
        reason = result.stop_reason or "error"
        error_text = (
            "unable to respond to this request (OpenAI refusal)"
            if reason == "refusal"
            else f"GPT response ended with {reason}"
        )
    return {
        "text": "".join(text_parts),
        "error": error_text,
        "session_id": getattr(result, "session_id", None),
        "usage": getattr(result, "usage", {}) if result else {},
        "model_usage": getattr(result, "model_usage", {}) if result else {},
    }


# ---------------------------------------------------------------------------
# Response/usage helpers
# ---------------------------------------------------------------------------


def _normalize_effort(value: str | None) -> str | None:
    effort = str(value or "").strip().lower()
    return (
        effort
        if effort in {"none", "minimal", "low", "medium", "high", "xhigh", "max"}
        else None
    )


def _response_blocks(response) -> tuple[list[Any], list[Any]]:
    blocks: list[Any] = []
    calls: list[Any] = []
    for item in getattr(response, "output", None) or []:
        item_type = str(getattr(item, "type", "") or "")
        if item_type == "message":
            for content in getattr(item, "content", None) or []:
                ctype = str(getattr(content, "type", "") or "")
                if ctype in {"output_text", "text"}:
                    text = str(getattr(content, "text", "") or "")
                    if text:
                        blocks.append(TextBlock(text))
                elif ctype == "refusal":
                    refusal = str(getattr(content, "refusal", "") or "")
                    if refusal:
                        # The shared orchestrator classifies policy blocks from
                        # assistant text. Prefix a stable marker because the
                        # API's natural-language refusal wording can vary.
                        blocks.append(
                            TextBlock(
                                "unable to respond to this request "
                                f"(OpenAI refusal): {refusal}"
                            )
                        )
        elif item_type == "function_call":
            calls.append(item)
            try:
                parsed = json.loads(getattr(item, "arguments", "{}") or "{}")
                if not isinstance(parsed, dict):
                    parsed = {"value": parsed}
            except Exception:
                parsed = {"raw": str(getattr(item, "arguments", "") or "")}
            blocks.append(
                ToolUseBlock(
                    name=str(getattr(item, "name", "tool") or "tool"),
                    input=parsed,
                    id=str(getattr(item, "call_id", "") or ""),
                )
            )
    return blocks, calls


def _response_has_refusal(response) -> bool:
    for item in getattr(response, "output", None) or []:
        if str(getattr(item, "type", "") or "") != "message":
            continue
        for content in getattr(item, "content", None) or []:
            if str(getattr(content, "type", "") or "") == "refusal":
                return True
    return False


def _response_usage(response) -> dict[str, int]:
    usage = getattr(response, "usage", None)
    if usage is None:
        return {}
    details = getattr(usage, "input_tokens_details", None)
    cached = int(getattr(details, "cached_tokens", 0) or 0)
    cache_write = int(getattr(details, "cache_write_tokens", 0) or 0)
    total_input = int(getattr(usage, "input_tokens", 0) or 0)
    return {
        # OpenAI input_tokens includes cache reads/writes; HexTech's ledger
        # prices all three buckets separately, so subtract both here.
        "inputTokens": max(0, total_input - cached - cache_write),
        "outputTokens": int(getattr(usage, "output_tokens", 0) or 0),
        "cacheCreationInputTokens": cache_write,
        "cacheReadInputTokens": cached,
    }


def _usage_for_heartbeat(usage: dict[str, int]) -> dict[str, int]:
    return {
        "input_tokens": int(usage.get("inputTokens") or 0),
        "output_tokens": int(usage.get("outputTokens") or 0),
        "cache_creation_input_tokens": int(usage.get("cacheCreationInputTokens") or 0),
        "cache_read_input_tokens": int(usage.get("cacheReadInputTokens") or 0),
    }


def _merge_usage(target: dict[str, int], incoming: dict[str, int]) -> None:
    for key in (
        "inputTokens",
        "outputTokens",
        "cacheCreationInputTokens",
        "cacheReadInputTokens",
    ):
        target[key] = int(target.get(key) or 0) + int(incoming.get(key) or 0)


def _estimate_model_usage_cost(model_usage: dict[str, dict[str, int]]) -> float:
    """Price GPT usage with HexTech's shared, provider-aware rate table."""
    try:
        from modules._common import estimate_cost_from_tokens
    except Exception:
        return 0.0
    total = 0.0
    for model, usage in model_usage.items():
        tokens = {
            "input_tokens": int(usage.get("inputTokens") or 0),
            "output_tokens": int(usage.get("outputTokens") or 0),
            "cache_creation_input_tokens": int(
                usage.get("cacheCreationInputTokens") or 0
            ),
            "cache_read_input_tokens": int(usage.get("cacheReadInputTokens") or 0),
        }
        total += estimate_cost_from_tokens(tokens, model)
    return total


def _cap_text(text: Any, limit: int = MAX_TOOL_OUTPUT_CHARS) -> str:
    value = str(text if text is not None else "")
    if len(value) <= limit:
        return value
    half = (limit - 120) // 2
    return (
        value[:half]
        + f"\n... ({len(value) - 2 * half} characters elided) ...\n"
        + value[-half:]
    )


def _strip_html(value: str) -> str:
    text = re.sub(r"<[^>]+>", " ", value or "")
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def _env_float(name: str, default: float) -> float:
    try:
        value = float(os.environ.get(name, str(default)))
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default
