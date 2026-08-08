"""Facade for HexTech's GPT provider.

``gpt_runtime=codex`` (the default) uses Codex CLI and ChatGPT OAuth.
``gpt_runtime=responses`` keeps the direct Responses API adapter as an
explicit, usage-billed fallback.  Keeping selection here prevents individual
judge/report/monitor/main paths from drifting onto different auth methods.
"""

from __future__ import annotations

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


def selected_gpt_runtime() -> str:
    try:
        from modules.agent_provider import get_gpt_runtime

        return get_gpt_runtime()
    except Exception:
        return "codex"


class GptAgentClient:
    """Delegate the SDK-shaped client surface to the selected GPT runtime."""

    def __init__(self, options: GptSessionOptions):
        self.options = options
        runtime = selected_gpt_runtime()
        if runtime == "responses":
            from modules.gpt_responses import GptResponsesClient

            self._delegate = GptResponsesClient(options)
        else:
            from modules.codex_cli import CodexCLIClient

            self._delegate = CodexCLIClient(options)

    @property
    def session_id(self) -> str | None:
        return getattr(self._delegate, "session_id", None)

    async def __aenter__(self) -> "GptAgentClient":
        await self._delegate.__aenter__()
        return self

    async def __aexit__(self, *exc) -> None:
        await self._delegate.__aexit__(*exc)

    async def start(self) -> None:
        await self._delegate.start()

    async def close(self) -> None:
        await self._delegate.close()

    async def query(self, prompt: str) -> None:
        await self._delegate.query(prompt)

    def receive_response(
        self, *, turn_timeout_s: float | None = None
    ) -> AsyncIterator[Any]:
        return self._delegate.receive_response(turn_timeout_s=turn_timeout_s)


async def query_gpt_once(**kwargs) -> dict[str, Any]:
    if selected_gpt_runtime() == "responses":
        from modules.gpt_responses import query_gpt_once as query_responses_once

        return await query_responses_once(**kwargs)
    from modules.codex_cli import query_codex_once

    return await query_codex_once(**kwargs)


# Backward-compatible import name for call sites/tests outside this repository.
GptResponsesClient = GptAgentClient


__all__ = [
    "AssistantMessage",
    "GptAgentClient",
    "GptResponsesClient",
    "GptSessionOptions",
    "ResultMessage",
    "SystemMessage",
    "TextBlock",
    "ToolResultBlock",
    "ToolUseBlock",
    "UserMessage",
    "query_gpt_once",
    "selected_gpt_runtime",
]
