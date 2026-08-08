#!/usr/bin/env python3
"""Smoke + adversarial tests for the Grok ACP backend.

Run from the repo root (or any cwd) with host `grok` on PATH and
authenticated (`grok login` or XAI_API_KEY):

    python3 scripts/test_grok_acp.py

Exit 0 = all passed. Prints a per-test summary.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import traceback
from pathlib import Path

# Repo root on sys.path so `import modules.*` works without install.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PASS = 0
FAIL = 0
SKIP = 0


def report(name: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {name}" + (f" — {detail}" if detail else ""), flush=True)
    else:
        FAIL += 1
        print(f"  FAIL  {name}" + (f" — {detail}" if detail else ""), flush=True)


def skip(name: str, reason: str):
    global SKIP
    SKIP += 1
    print(f"  SKIP  {name} — {reason}", flush=True)


# ---------------------------------------------------------------------------
# Unit tests (no network / no grok process)
# ---------------------------------------------------------------------------

def test_settings_schema_and_provider():
    print("\n== unit: settings + provider ==")
    import tempfile as tf
    from modules import settings_io as s
    from modules import agent_provider as ap

    tmp = Path(tf.mkdtemp()) / "settings.json"
    s.SETTINGS_PATH = tmp

    view = s.get_settings_view()
    report("default provider is claude", view.get("agent_provider") == "claude")
    report("grok_model default present", bool(view.get("grok_model")))
    report(
        "agent_providers list",
        view.get("agent_providers") == ["claude", "grok", "gpt"],
    )

    try:
        s.update_settings({"agent_provider": "not-a-provider"})
        report("rejects invalid provider", False, "no ValueError")
    except ValueError:
        report("rejects invalid provider", True)

    v = s.update_settings({
        "agent_provider": "grok",
        "grok_model": "grok-build",
        "grok_effort": "low",
        "claude_effort": "high",
    })
    report("saves agent_provider=grok", v.get("agent_provider") == "grok")
    report("saves grok_model", v.get("grok_model") == "grok-build")
    report("saves claude_effort (schema fix)", v.get("claude_effort") == "high")
    report("active_provider() == grok", ap.active_provider() == "grok")
    report("default_model_for grok", ap.default_model_for() == "grok-build")
    report("default_effort_for grok", ap.default_effort_for() == "low")
    report("GROK_RUNTIME_READY", ap.GROK_RUNTIME_READY is True)

    # Secret masking
    s.update_settings({"xai_api_key": "xai-secret-key-value-1234"})
    v2 = s.get_settings_view()
    report(
        "xai key masked in view",
        v2.get("xai_api_key_set") is True and "xai_api_key" not in v2,
    )
    report(
        "xai key not fully leaked",
        "secret-key-value" not in (v2.get("xai_api_key_masked") or ""),
    )

    # Clear provider back
    s.update_settings({"agent_provider": "claude", "xai_api_key": None})


def test_kill_guard_logic():
    print("\n== unit: kill-guard ==")
    from modules._common import dangerous_kill_reason

    report(
        "blocks pkill -f",
        dangerous_kill_reason("pkill -f exploit.py") is not None,
    )
    report(
        "blocks pkill python3",
        dangerous_kill_reason("pkill python3") is not None,
    )
    report(
        "allows kill $PID",
        dangerous_kill_reason("kill 12345") is None,
    )
    report(
        "allows pkill -x basname",
        dangerous_kill_reason("pkill -9 -x prob") is None,
    )
    report(
        "blocks pgrep -f | xargs kill",
        dangerous_kill_reason("pgrep -f exploit | xargs kill") is not None,
    )


def test_resolve_main_model_provider_aware():
    print("\n== unit: resolve_main_model / resolve_effort ==")
    import tempfile as tf
    from modules import settings_io as s
    from modules._common import resolve_main_model, resolve_effort

    tmp = Path(tf.mkdtemp()) / "settings.json"
    s.SETTINGS_PATH = tmp
    s.update_settings({
        "agent_provider": "grok",
        "grok_model": "grok-4.5",
        "grok_effort": "medium",
        "claude_model": "claude-opus-4-7",
        "claude_effort": "max",
    })
    report("main model follows grok", resolve_main_model(None) == "grok-4.5")
    report("per-job model override wins", resolve_main_model("custom-x") == "custom-x")
    report("effort follows grok", resolve_effort(None) == "medium")
    report("per-job effort wins", resolve_effort("high") == "high")

    s.update_settings({"agent_provider": "claude"})
    report("main model follows claude", resolve_main_model(None) == "claude-opus-4-7")
    report("effort follows claude", resolve_effort(None) == "max")


def test_install_hooks_and_bin():
    print("\n== unit: hooks install + binary resolve ==")
    from modules.grok_acp import install_kill_guard_hooks, resolve_grok_bin

    try:
        bin_path = resolve_grok_bin()
        report("resolve_grok_bin", True, bin_path)
    except FileNotFoundError as e:
        report("resolve_grok_bin", False, str(e))
        return

    wd = Path(tempfile.mkdtemp(prefix="hooks-"))
    hdir = install_kill_guard_hooks(wd)
    report("hooks dir created", hdir is not None and hdir.is_dir())
    report(
        "kill_guard.py present",
        hdir is not None and (hdir / "hextech_kill_guard.py").is_file(),
    )
    report(
        "kill-guard.json present",
        hdir is not None and (hdir / "hextech-kill-guard.json").is_file(),
    )


# ---------------------------------------------------------------------------
# Live ACP smoke (needs grok + auth)
# ---------------------------------------------------------------------------

async def _live_smoke():
    print("\n== live smoke: GrokACPClient ==")
    sys.stdout.flush()
    from modules.grok_acp import (
        GrokACPClient, GrokSessionOptions, AssistantMessage, ResultMessage,
        query_grok_once, resolve_grok_bin,
    )
    from modules.agent_provider import has_provider_auth

    try:
        resolve_grok_bin()
    except FileNotFoundError as e:
        skip("live ACP", str(e))
        return

    if not has_provider_auth("grok"):
        skip("live ACP", "no grok auth (login or XAI_API_KEY)")
        return

    # Prefer a fast chat model for smoke; override via GROK_SMOKE_MODEL.
    model = os.environ.get("GROK_SMOKE_MODEL", "grok-4.5")
    # Bound each turn so a stuck agent cannot hang CI forever.
    os.environ.setdefault("GROK_TURN_TIMEOUT_S", "180")
    turn_t = float(os.environ["GROK_TURN_TIMEOUT_S"])

    wd = Path(tempfile.mkdtemp(prefix="grok-smoke-"))
    (wd / "chal.txt").write_text("secret=SMOKE_FLAG_42\n")

    opts = GrokSessionOptions(
        system_prompt=(
            "You are a brief test agent. Prefer tools when asked to read/write "
            "files. Keep answers short."
        ),
        model=model,
        cwd=str(wd),
        effort="low",
    )

    # --- A: text-only turn (no tools) — must be fast ---
    try:
        async with GrokACPClient(opts) as client:
            sid1 = client.session_id
            report("session created", bool(sid1), str(sid1)[:12] if sid1 else "")
            await client.query("Reply with exactly the single word: PONG")
            texts = []
            result = None
            async for msg in client.receive_response(turn_timeout_s=turn_t):
                if isinstance(msg, AssistantMessage):
                    for b in msg.content or []:
                        t = getattr(b, "text", None)
                        if t:
                            texts.append(t)
                elif isinstance(msg, ResultMessage):
                    result = msg
            body = "".join(texts)
            report("text-only ResultMessage", result is not None,
                   getattr(result, "stop_reason", None) or "")
            report(
                "text-only not is_error",
                result is not None and not result.is_error,
                getattr(result, "stop_reason", None) or "",
            )
            report("text-only contains PONG", "PONG" in body, body[:80])

            # --- B: tool turn — write a file ---
            await client.query(
                "Using tools, create hello.txt in the cwd containing exactly "
                "HELLO_GROK and nothing else. Then stop."
            )
            tools = 0
            result2 = None
            async for msg in client.receive_response(turn_timeout_s=turn_t):
                if isinstance(msg, AssistantMessage):
                    for b in msg.content or []:
                        if type(b).__name__ == "ToolUseBlock" or getattr(b, "type", None) == "tool_use":
                            tools += 1
                elif isinstance(msg, ResultMessage):
                    result2 = msg
            report("tool-turn ResultMessage", result2 is not None)
            report(
                "tool-turn not is_error",
                result2 is not None and not result2.is_error,
                getattr(result2, "stop_reason", None) or "",
            )
            report(
                "hello.txt written",
                (wd / "hello.txt").is_file()
                and "HELLO_GROK" in (wd / "hello.txt").read_text(),
                (wd / "hello.txt").read_text()[:40] if (wd / "hello.txt").is_file() else "missing",
            )
            report("tool-turn saw tool_call events or wrote file",
                   tools > 0 or (wd / "hello.txt").is_file())
            report("same session id across turns", client.session_id == sid1)
    except Exception as e:
        report("live ACP session", False, f"{type(e).__name__}: {e}")
        traceback.print_exc()
        return

    # --- one-shot helper ---
    r = await query_grok_once(
        prompt="Reply with exactly: PONG",
        cwd=str(wd),
        system_prompt="Reply briefly with no tools.",
        model=model,
        effort="low",
        timeout_s=turn_t,
    )
    report(
        "query_grok_once PONG",
        r.get("error") is None and "PONG" in (r.get("text") or ""),
        (r.get("text") or r.get("error") or "")[:80],
    )


async def _adversarial():
    print("\n== adversarial ==")
    from modules.grok_acp import GrokACPClient, GrokSessionOptions, ResultMessage
    from modules.agent_provider import (
        ensure_provider_ready, normalize_provider, has_provider_auth,
    )
    from modules import settings_io as s
    from modules.grok_acp import resolve_grok_bin
    import tempfile as tf

    # A1: normalize garbage provider
    report("normalize garbage → claude", normalize_provider("OPENAI") == "claude")
    report("normalize empty → claude", normalize_provider("") == "claude")
    report("normalize GROK case", normalize_provider("Grok") == "grok")

    # A2: ensure_provider_ready without auth when forced grok
    tmp = Path(tf.mkdtemp()) / "settings.json"
    s.SETTINGS_PATH = tmp
    # Wipe any env-based key for this process view by setting empty and
    # temporarily hiding auth file detection is hard; instead call with
    # explicit checks.
    s.update_settings({"agent_provider": "grok", "xai_api_key": ""})
    # If host has ~/.grok/auth.json this still has auth — that's fine;
    # then ensure_provider_ready should pass when binary exists.
    try:
        resolve_grok_bin()
        has_bin = True
    except FileNotFoundError:
        has_bin = False

    if has_provider_auth("grok") and has_bin:
        try:
            p = ensure_provider_ready("grok")
            report("ensure_provider_ready ok with auth+bin", p == "grok")
        except RuntimeError as e:
            report("ensure_provider_ready ok with auth+bin", False, str(e))
    else:
        try:
            ensure_provider_ready("grok")
            report("ensure_provider_ready fails without auth", False, "did not raise")
        except RuntimeError as e:
            report("ensure_provider_ready fails without auth", True, str(e)[:60])

    # A3: kill-guard script denies pkill -f
    import subprocess
    from modules.grok_acp import install_kill_guard_hooks
    wd = Path(tempfile.mkdtemp(prefix="adv-hooks-"))
    hdir = install_kill_guard_hooks(wd)
    script = (hdir / "hextech_kill_guard.py") if hdir else None
    if script is None or not script.is_file():
        report("hook script denies pkill -f", False, "script missing")
        report("hook script allows echo", False, "script missing")
    else:
        proc = subprocess.run(
            [sys.executable, str(script)],
            input=json.dumps({
                "tool_name": "run_terminal_command",
                "tool_input": {"command": "pkill -f exploit.py"},
            }),
            capture_output=True, text=True, timeout=5,
        )
        denied = "permissionDecision" in proc.stdout and "deny" in proc.stdout
        report("hook script denies pkill -f", denied, proc.stdout[:120])

        proc2 = subprocess.run(
            [sys.executable, str(script)],
            input=json.dumps({
                "tool_name": "run_terminal_command",
                "tool_input": {"command": "echo hello"},
            }),
            capture_output=True, text=True, timeout=5,
        )
        report(
            "hook script allows echo",
            proc2.returncode == 0 and "deny" not in proc2.stdout,
            proc2.stdout[:80],
        )

    # A4: empty / huge prompt edge — only if live
    if not (has_provider_auth("grok") and has_bin):
        skip("adv live edges", "no grok auth/bin")
        return

    model = os.environ.get("GROK_SMOKE_MODEL", "grok-4.5")
    os.environ.setdefault("GROK_TURN_TIMEOUT_S", "180")
    turn_t = float(os.environ["GROK_TURN_TIMEOUT_S"])
    wd2 = Path(tempfile.mkdtemp(prefix="adv-live-"))
    opts = GrokSessionOptions(
        system_prompt="Be brief. No tools needed unless asked.",
        model=model,
        cwd=str(wd2),
        effort="low",
    )
    try:
        async with GrokACPClient(opts) as client:
            # empty-ish prompt
            await client.query(" ")
            got_result = False
            async for msg in client.receive_response(turn_timeout_s=turn_t):
                if isinstance(msg, ResultMessage):
                    got_result = True
            report("empty prompt still returns ResultMessage", got_result)

            # second turn after first — session stability
            await client.query("Say OK")
            ok_text = []
            async for msg in client.receive_response(turn_timeout_s=turn_t):
                if hasattr(msg, "content"):
                    for b in msg.content or []:
                        if getattr(b, "text", None):
                            ok_text.append(b.text)
                if isinstance(msg, ResultMessage):
                    report("second turn ok", not msg.is_error, msg.stop_reason or "")
            report("second turn produced text", bool("".join(ok_text).strip()))
    except Exception as e:
        report("adv live edges", False, f"{type(e).__name__}: {e}")
        traceback.print_exc()

    # A5: double close should not raise
    opts3 = GrokSessionOptions(
        system_prompt="hi", model=model, cwd=str(wd2), effort="low",
    )
    try:
        client = GrokACPClient(opts3)
        await client.start()
        await client.close()
        await client.close()  # idempotent
        report("double close idempotent", True)
    except Exception as e:
        report("double close idempotent", False, str(e))


def main():
    print("HexTech Grok ACP — smoke + adversarial")
    test_settings_schema_and_provider()
    test_kill_guard_logic()
    test_resolve_main_model_provider_aware()
    test_install_hooks_and_bin()
    asyncio.run(_live_smoke())
    asyncio.run(_adversarial())

    print(f"\n==== SUMMARY: {PASS} passed, {FAIL} failed, {SKIP} skipped ====")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
