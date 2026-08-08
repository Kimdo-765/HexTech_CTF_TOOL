#!/usr/bin/env python3
"""Offline regression tests for the OpenAI GPT Responses API backend.

No SDK installation, API key, network access, or paid request is required.
Run from any directory with::

    python3 scripts/test_gpt_responses.py
"""

from __future__ import annotations

import asyncio
import json
import math
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace as NS


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


def usage(
    input_tokens: int,
    output_tokens: int,
    cached_tokens: int = 0,
    cache_write_tokens: int = 0,
):
    return NS(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        input_tokens_details=NS(
            cached_tokens=cached_tokens,
            cache_write_tokens=cache_write_tokens,
        ),
    )


def test_settings_and_provider() -> None:
    print("\n== settings + provider ==")
    from modules import agent_provider as ap
    from modules import settings_io as settings

    settings.SETTINGS_PATH = (
        Path(tempfile.mkdtemp(prefix="gpt-settings-")) / "settings.json"
    )
    view = settings.get_settings_view()
    report(
        "three providers are exposed",
        view.get("agent_providers") == ["claude", "grok", "gpt"],
    )
    report("GPT defaults are exposed", bool(view.get("gpt_model")))

    view = settings.update_settings(
        {
            "agent_provider": "gpt",
            "gpt_runtime": "responses",
            "openai_api_key": "sk-test-secret-value-123456789",
            "gpt_model": "gpt-5.6-terra",
            "gpt_effort": "high",
        }
    )
    report("GPT provider persists", view.get("agent_provider") == "gpt")
    report("Responses fallback persists", view.get("gpt_runtime") == "responses")
    report("OpenAI key is set but hidden", view.get("openai_api_key_set") is True)
    report(
        "OpenAI key is masked",
        "secret-value" not in (view.get("openai_api_key_masked") or ""),
    )
    report("active provider is GPT", ap.active_provider() == "gpt")
    report("GPT model setting resolves", ap.default_model_for() == "gpt-5.6-terra")
    report("GPT effort setting resolves", ap.default_effort_for() == "high")
    prior_openai_module = sys.modules.get("openai")
    sys.modules["openai"] = NS()
    try:
        report(
            "GPT readiness accepts configured SDK + key",
            ap.ensure_provider_ready() == "gpt",
        )
    finally:
        if prior_openai_module is None:
            sys.modules.pop("openai", None)
        else:
            sys.modules["openai"] = prior_openai_module
    report(
        "Claude preset model is coerced",
        ap.coerce_model_for_provider("claude-opus-4-7") == "gpt-5.6-terra",
    )
    report(
        "custom GPT-family model is preserved",
        ap.coerce_model_for_provider("gpt-custom-preview") == "gpt-custom-preview",
    )


def test_tool_schema() -> None:
    print("\n== strict function schema ==")
    from modules.gpt_responses import _normalize_effort, _tool_specs

    tools = _tool_specs(enable_subagents=True)
    report("core tools and subagent are registered", len(tools) == 9)
    valid = all(
        set(tool["parameters"]["properties"]) == set(tool["parameters"]["required"])
        and tool["parameters"].get("additionalProperties") is False
        and tool.get("strict") is True
        for tool in tools
    )
    report("all schemas satisfy strict-mode shape", valid)
    report("Responses preserves minimal effort", _normalize_effort("minimal") == "minimal")


class FakeResponses:
    def __init__(self):
        self.calls: list[dict] = []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        if len(self.calls) == 1:
            return NS(
                id="resp_tool",
                status="completed",
                usage=usage(10, 2, 4, 1),
                output=[
                    NS(
                        type="function_call",
                        call_id="call_write",
                        name="Write",
                        arguments=json.dumps(
                            {
                                "file_path": "artifact.txt",
                                "content": "created by GPT tool loop\n",
                            }
                        ),
                    )
                ],
            )
        return NS(
            id="resp_done",
            status="completed",
            usage=usage(8, 3),
            output=[
                NS(
                    type="message",
                    content=[NS(type="output_text", text="artifact complete")],
                )
            ],
        )


class FakeClient:
    def __init__(self):
        self.responses = FakeResponses()


async def test_function_call_loop() -> None:
    print("\n== Responses function-call loop ==")
    from modules.gpt_responses import (
        AssistantMessage,
        GptResponsesClient,
        GptSessionOptions,
        ResultMessage,
        SystemMessage,
        ToolUseBlock,
        UserMessage,
    )

    cwd = Path(tempfile.mkdtemp(prefix="gpt-loop-"))
    client = GptResponsesClient(
        GptSessionOptions(
            system_prompt=(
                'use mcp__team__spawn_subagent(subagent_type="recon", prompt="inspect")'
            ),
            model="gpt-5.6",
            cwd=str(cwd),
            effort="medium",
            max_turns=4,
            enable_tools=True,
            enable_subagents=False,
        )
    )
    fake = FakeClient()
    client._client = fake
    await client.query("write an artifact")
    messages = [message async for message in client.receive_response()]

    calls = fake.responses.calls
    report("two Responses API calls are made", len(calls) == 2)
    adapted = calls[0].get("instructions") or ""
    report(
        "Claude MCP delegation syntax is removed",
        "mcp__team__spawn_subagent" not in adapted and "subagent_type=" not in adapted,
    )
    report(
        "disabled subagents are stated explicitly",
        "Subagent delegation is disabled" in adapted,
    )
    report(
        "tool result continues from first response",
        calls[1].get("previous_response_id") == "resp_tool",
    )
    second_input = calls[1].get("input") or []
    report(
        "function_call_output is returned",
        bool(second_input)
        and second_input[0].get("type") == "function_call_output"
        and second_input[0].get("call_id") == "call_write",
    )
    report(
        "local Write tool created the file",
        (cwd / "artifact.txt").read_text() == "created by GPT tool loop\n",
    )
    report(
        "tool-use and tool-result messages are emitted",
        any(
            isinstance(message, AssistantMessage)
            and any(isinstance(block, ToolUseBlock) for block in message.content)
            for message in messages
        )
        and any(isinstance(message, UserMessage) for message in messages),
    )
    report(
        "latest response id is persisted",
        client.session_id == "resp_done"
        and len([m for m in messages if isinstance(m, SystemMessage)]) == 2,
    )
    result = next(m for m in messages if isinstance(m, ResultMessage))
    report("turn completes successfully", not result.is_error)
    report(
        "GPT token rates produce a cost estimate",
        math.isclose(result.total_cost_usd or 0, 0.00022325, rel_tol=1e-9),
    )
    report(
        "cached tokens use a separate ledger bucket",
        result.usage
        == {
            "inputTokens": 13,
            "outputTokens": 5,
            "cacheCreationInputTokens": 1,
            "cacheReadInputTokens": 4,
        },
    )
    report(
        "per-model usage is retained for cost accounting",
        result.model_usage.get("gpt-5.6") == result.usage,
    )


async def test_refusal_is_error() -> None:
    print("\n== refusal handling ==")
    from modules.gpt_responses import (
        AssistantMessage,
        GptResponsesClient,
        GptSessionOptions,
        ResultMessage,
    )

    class RefusalResponses:
        async def create(self, **kwargs):
            return NS(
                id="resp_refusal",
                status="completed",
                usage=usage(2, 4),
                output=[
                    NS(
                        type="message",
                        content=[NS(type="refusal", refusal="request refused")],
                    )
                ],
            )

    client = GptResponsesClient(
        GptSessionOptions(
            system_prompt="test",
            model="gpt-5.6",
            cwd=tempfile.mkdtemp(prefix="gpt-refusal-"),
            enable_tools=False,
        )
    )
    client._client = NS(responses=RefusalResponses())
    await client.query("test")
    messages = [message async for message in client.receive_response()]
    result = next(m for m in messages if isinstance(m, ResultMessage))
    report("refusal marks the turn as failed", result.is_error)
    report("refusal reason is preserved", result.stop_reason == "refusal")
    refusal_text = " ".join(
        getattr(block, "text", "")
        for message in messages
        if isinstance(message, AssistantMessage)
        for block in message.content
    )
    report(
        "refusal carries the shared policy marker",
        "unable to respond to this request" in refusal_text.lower(),
    )


async def main() -> int:
    test_settings_and_provider()
    test_tool_schema()
    await test_function_call_loop()
    await test_refusal_is_error()
    print(f"\n== summary: {PASS} passed, {FAIL} failed ==")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
