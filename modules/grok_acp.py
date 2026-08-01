"""Grok Build ACP client for HexTech CTF jobs.

Spawns ``grok agent --always-approve --no-leader stdio`` and speaks the
Agent Client Protocol (JSON-RPC over stdio). Exposes a surface close to
``ClaudeSDKClient`` so ``run_main_agent_session`` can share the same
multi-turn / auto-retry loop:

  * ``async with GrokACPClient(options) as client``
  * ``await client.query(prompt)``
  * ``async for msg in client.receive_response()``

Message types here are intentionally named like the Claude SDK's so the
session loop's ``isinstance`` checks work when this module's classes are
imported in the Grok branch.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Optional


# ---------------------------------------------------------------------------
# Duck-typed message classes (mirrors claude_agent_sdk names used by the loop)
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
    """A tool's OUTCOME, shaped like the Anthropic SDK's block of the same name.

    The name matters: modules/_common.py dispatches on
    `type(block).__name__ == "ToolResultBlock"` for TOOL_RESULT logging, the
    runaway detector and the SSE preview, and `_extract_msg_text` — which feeds
    the LIVE flag-candidate scan — reads `.content`. Without this class the
    Grok path yielded tool CALLS and never their results, so a flag printed to
    a tool's stdout (the normal capture path) was invisible to the live scan
    and never reached the [FLAG?] box during a run.
    """

    def __init__(self, content=None, is_error: bool = False,
                 tool_use_id: str | None = None):
        self.content = content if content is not None else ""
        self.is_error = bool(is_error)
        self.tool_use_id = tool_use_id or ""
        self.type = "tool_result"


class AssistantMessage:
    def __init__(self, content: list | None = None, usage: dict | None = None):
        self.content = content or []
        self.role = "assistant"
        # ACP reports usage once, on the turn's response — not per assistant
        # chunk — so this is normally empty. It exists so the shared heartbeat's
        # `getattr(msg, "usage", None)` sees a dict rather than nothing.
        self.usage = usage or {}


class UserMessage:
    def __init__(self, content: list | None = None):
        self.content = content or []
        self.role = "user"


def _tool_result_text(update: dict) -> str:
    """Readable text out of an ACP `tool_call_update`.

    Deliberately permissive: ACP carries a tool's output as a list of content
    blocks, but the nesting differs between agents and versions
    (`{"type":"content","content":{"type":"text","text":…}}`,
    `{"type":"text","text":…}`, or a bare string), and some tools report only
    `rawOutput`. Anything unrecognised falls back to a JSON dump rather than
    being dropped — a missed tool result is a missed flag.
    """
    parts: list[str] = []

    def _walk(node, depth: int = 0) -> None:
        if depth > 6 or node is None:
            return
        if isinstance(node, str):
            if node:
                parts.append(node)
        elif isinstance(node, list):
            for sub in node:
                _walk(sub, depth + 1)
        elif isinstance(node, dict):
            t = node.get("text")
            if isinstance(t, str) and t:
                parts.append(t)
            if "content" in node:
                _walk(node.get("content"), depth + 1)

    _walk(update.get("content"))
    if not parts:
        raw = update.get("rawOutput") or update.get("raw_output")
        if isinstance(raw, str):
            parts.append(raw)
        elif raw is not None:
            try:
                parts.append(json.dumps(raw, ensure_ascii=False)[:20000])
            except Exception:
                parts.append(str(raw)[:20000])
    return "\n".join(p for p in parts if p)


def _acp_usage_to_model_usage(usage: dict, model: str | None) -> dict:
    """Shape ACP's `_meta.usage` like the Anthropic SDK's `model_usage`.

    The shared ledger already speaks camelCase (`_MODEL_USAGE_KEYMAP` in
    modules/_common.py maps inputTokens/outputTokens/cacheCreationInputTokens/
    cacheReadInputTokens), and on a ResultMessage the heartbeat reads
    `model_usage` — never `usage` — to get its authoritative numbers. Grok
    carried usage only under `usage`, and named its cache field
    `cachedReadTokens`, which is in neither the keymap nor _TOKEN_KEYS. Net
    effect: every Grok job recorded zero tokens and $0, which also made the
    operator's COST_CAP_USD inert on that provider. Translate here so nothing
    in the shared ledger has to know Grok exists.
    """
    if not isinstance(usage, dict):
        return {}
    alias = {
        "cachedReadTokens": "cacheReadInputTokens",
        "cacheReadTokens": "cacheReadInputTokens",
        "cachedInputTokens": "cacheReadInputTokens",
        "cacheCreationTokens": "cacheCreationInputTokens",
    }
    wanted = {"inputTokens", "outputTokens",
              "cacheCreationInputTokens", "cacheReadInputTokens"}
    out: dict[str, int] = {}
    for k, v in usage.items():
        key = alias.get(k, k)
        if key in wanted and isinstance(v, (int, float)):
            out[key] = out.get(key, 0) + int(v)
    if not any(out.values()):
        return {}
    return {str(model or "grok"): out}


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
        self.is_error = is_error
        self.stop_reason = stop_reason
        self.usage = usage or {}
        self.session_id = session_id
        # The heartbeat treats `model_usage` as authoritative on a result and
        # ignores `usage` there, so this is the field that actually lands in
        # meta.agent_tokens. See _acp_usage_to_model_usage.
        self.model_usage = model_usage or {}


class SystemMessage:
    """Init / status messages. capture_session_id looks for session_id here."""

    def __init__(self, data: dict):
        self.data = data
        self.subtype = data.get("subtype") or data.get("type") or "init"


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

# Appended to the CTF system prompt so tool names match Grok's surface.
# Full HexTech role→type mapping + mandatory routing lives in
# modules._prompts.GROK_DELEGATION_CONTRACT (injected only when
# agent_provider=grok via adapt_system_prompt_for_grok). This short
# addendum is a last-line safety net if that adapter was skipped.
GROK_TOOL_ADDENDUM = """
## GROK TOOL SURFACE (this session runs on Grok Build, not Claude Code)

Tool names differ from Claude Code. Map them as follows:
- File read → `read_file` / `list_dir` / `grep` (NOT `Read` / `Glob` / `Grep`)
- File write/edit → `search_replace` or write tools (NOT `Write` / `Edit`)
- Shell → `run_terminal_command` (NOT `Bash`)
- Web → `web_search` / `web_fetch` (NOT `WebSearch` / `WebFetch`)
- Delegate investigation → built-in `spawn_subagent` only.
  There is NO `mcp__team__spawn_subagent` tool — never call that name.
  HexTech roles map to Grok types:
    recon / triage  → subagent_type=`explore`         (+ capability_mode=`read-only`)
    debugger / judge → subagent_type=`general-purpose` (judge: capability_mode=`read-only`)
  Always start the child prompt with `[HEXTECH_ROLE=recon|debugger|triage|judge]`.
  Heavy disasm/decomp/gadget dumps MUST go through ROLE=recon, not your own
  `run_terminal_command` (keeps your context small). Pre-ship hang/parse review
  MUST go through ROLE=judge before you finalize exploit.py/solver.py.

Deliverables still land as relative paths in the CURRENT WORKING DIRECTORY
(`exploit.py` / `solver.py` / `report.md`). Print `FLAG_CANDIDATE: <flag>`
when you capture a real flag.
""".strip()


# Default per-turn wall clock for CTF main sessions. Kernel/pwn work
# routinely exceeds 10 minutes of tool use in a single turn (job
# 3c0e0edb73db hit the old 600s cap mid-exploit draft). Override with
# env GROK_TURN_TIMEOUT_S or GrokSessionOptions.turn_timeout_s.
DEFAULT_TURN_TIMEOUT_S = 3600.0


@dataclass
class GrokSessionOptions:
    """Session config for the Grok ACP backend."""

    system_prompt: str
    model: str
    cwd: str
    effort: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    resume: str | None = None
    add_dirs: list[str] = field(default_factory=list)
    max_turns: int | None = None
    # Extra rules folded into session _meta.rules (kept separate from the
    # system prompt override so operators can still append).
    rules: str | None = None
    # Per-turn wall-clock budget (seconds). None → env / DEFAULT_TURN_TIMEOUT_S.
    turn_timeout_s: float | None = None
    # When True (default), append GROK_TOOL_ADDENDUM (tool renames + spawn
    # routing). Set False for pure text one-shots (retry reviewer, monitor
    # narration, report JSON transform) — those must NOT be nudged to call
    # tools or they hang mid-turn with no tokens for the UI.
    append_tool_addendum: bool = True


def resolve_grok_bin() -> str:
    """Locate the `grok` binary. Prefer PATH, then common install locations."""
    found = shutil.which("grok")
    if found:
        return found
    candidates = [
        Path(os.environ.get("GROK_BIN", "")),
        Path("/root/.grok/bin/grok"),
        Path.home() / ".grok" / "bin" / "grok",
        Path("/usr/local/bin/grok"),
    ]
    for c in candidates:
        if c and c.is_file() and os.access(c, os.X_OK):
            return str(c)
    raise FileNotFoundError(
        "grok binary not found on PATH. Install Grok Build "
        "(curl -fsSL https://x.ai/cli/install.sh | bash) and/or mount "
        "HOST_GROK_HOME into the worker so /root/.grok/bin/grok is available."
    )


def install_kill_guard_hooks(cwd: str | Path) -> Path | None:
    """Install PreToolUse hooks that block self-killing shell commands.

    Hooks are written to the **global** Grok hooks dir
    (``$GROK_HOME/hooks`` or ``~/.grok/hooks``), which is always trusted.
    Project-local ``<cwd>/.grok/hooks`` requires folder trust and can
    stall an unattended ACP session waiting for approval — never use that
    path for automation.

    ``cwd`` is accepted for API compatibility but is not used as the
    install root.
    """
    grok_home = Path(os.environ.get("GROK_HOME") or (Path.home() / ".grok"))
    hooks_dir = grok_home / "hooks"
    try:
        hooks_dir.mkdir(parents=True, exist_ok=True)
        script = hooks_dir / "hextech_kill_guard.py"
        # Self-contained script so the hook process does not need PYTHONPATH
        # into /app/modules (worker layout varies).
        script.write_text(
            '''#!/usr/bin/env python3
import json, os, re, sys

_KILL_PROTECTED = ("python3", "python", "node", "claude", "grok", "rqworker", "rq",
                   "bash", "zsh", "dash", "sh")
_PKILL_FULL_RE = re.compile(r"\\bpkill\\b[^\\n;&|]*?(?:\\s-[a-zA-Z]*f|\\s--full)\\b", re.I)
_PROTECTED_KILL_RE = re.compile(
    r"\\b(?:pkill|killall)\\b[^\\n;&|]*?\\b(?:" + "|".join(_KILL_PROTECTED) + r")\\b", re.I)
_PGREP_FULL_RE = re.compile(r"\\bpgrep\\b[^\\n;&|]*?(?:\\s-[a-zA-Z]*f|\\s--full)\\b", re.I)
_MSG = (
    "BLOCKED: this would kill the job's own processes and abort the run. "
    "Use kill $PID / timeout / pkill -9 -x <basename> instead of pkill -f."
)

def reason(cmd: str):
    if not cmd:
        return None
    if _PKILL_FULL_RE.search(cmd) or _PROTECTED_KILL_RE.search(cmd):
        return _MSG
    if _PGREP_FULL_RE.search(cmd) and re.search(r"\\b(?:kill|xargs)\\b", cmd):
        return _MSG
    return None

def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)
    tool = data.get("tool_name") or data.get("toolName") or ""
    # Grok aliases Bash → run_terminal_command
    if tool not in ("Bash", "run_terminal_command", "bash", "Shell"):
        sys.exit(0)
    tin = data.get("tool_input") or data.get("toolInput") or {}
    cmd = tin.get("command") or tin.get("cmd") or ""
    r = reason(cmd)
    if not r:
        sys.exit(0)
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": r,
        }
    }
    print(json.dumps(out))
    sys.exit(0)

if __name__ == "__main__":
    main()
'''
        )
        script.chmod(0o755)
        # Stable name so re-runs overwrite rather than stack duplicates.
        (hooks_dir / "hextech-kill-guard.json").write_text(json.dumps({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash|run_terminal_command",
                        "hooks": [
                            {
                                "type": "command",
                                "command": str(script),
                                "timeout": 5,
                            }
                        ],
                    }
                ]
            }
        }, indent=2))
        return hooks_dir
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class GrokACPError(RuntimeError):
    pass


class GrokACPClient:
    """Long-lived ACP session over ``grok agent stdio``."""

    def __init__(self, options: GrokSessionOptions):
        self.options = options
        self.proc: asyncio.subprocess.Process | None = None
        self.session_id: str | None = options.resume
        self._rid = 0
        self._pending_prompt: str | None = None
        self._reader_task: asyncio.Task | None = None
        self._inbox: asyncio.Queue = asyncio.Queue()
        self._resp_waiters: dict[int, asyncio.Future] = {}
        # IDs of in-flight session/prompt calls — their responses go to the
        # inbox (streamed with notifications), not only to a Future.
        self._prompt_ids: set[int] = set()
        self._closed = False
        self._started_at = 0.0
        self._turn_count = 0
        self._last_usage: dict = {}

    async def __aenter__(self) -> "GrokACPClient":
        await self.start()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def start(self) -> None:
        if self.proc is not None:
            return
        grok = resolve_grok_bin()
        cwd = str(Path(self.options.cwd).resolve())
        Path(cwd).mkdir(parents=True, exist_ok=True)
        install_kill_guard_hooks(cwd)

        env = os.environ.copy()
        env.update({k: str(v) for k, v in (self.options.env or {}).items()})
        # Prefer project hooks under cwd; surface host auth.
        env.setdefault("HOME", env.get("HOME") or str(Path.home()))
        # Auto-update mid-job is hostile; disable for the agent process.
        env["GROK_NO_AUTO_UPDATE"] = env.get("GROK_NO_AUTO_UPDATE", "1")

        # Put ~/.grok/bin on PATH for the child (and any tools it shells out).
        grok_bin_dir = str(Path(grok).resolve().parent)
        env["PATH"] = grok_bin_dir + os.pathsep + env.get("PATH", "")

        # Global flags (auto-update) must precede the `agent` subcommand.
        cmd = [
            grok,
            "--no-auto-update",
            "agent",
            "--always-approve",
            "--no-leader",
        ]
        if self.options.model:
            cmd.extend(["--model", self.options.model])
        if self.options.effort:
            cmd.extend(["--effort", self.options.effort])
        cmd.append("stdio")

        self.proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
            limit=8 * 1024 * 1024,
        )
        self._started_at = time.time()
        self._reader_task = asyncio.create_task(self._read_loop())
        await self._initialize()
        if self.session_id:
            # Resume existing session when possible.
            try:
                await self._request("session/load", {
                    "sessionId": self.session_id,
                    "cwd": cwd,
                    "mcpServers": [],
                })
            except GrokACPError:
                # Fall through to a fresh session if load fails.
                self.session_id = None
        if not self.session_id:
            await self._create_session()

    async def close(self) -> None:
        self._closed = True
        if self.proc is None:
            return
        try:
            if self.proc.stdin and not self.proc.stdin.is_closing():
                self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self.proc.kill()
                await self.proc.wait()
        except ProcessLookupError:
            pass
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):
                pass
        self.proc = None

    async def query(self, prompt: str | list) -> None:
        """Queue a user turn. The next ``receive_response`` drains it."""
        if isinstance(prompt, list):
            # Already content blocks.
            text = "\n".join(
                (b.get("text") if isinstance(b, dict) else str(b))
                for b in prompt
            )
        else:
            text = str(prompt)
        self._pending_prompt = text

    async def receive_response(
        self,
        *,
        turn_timeout_s: float | None = None,
    ) -> AsyncIterator[Any]:
        """Send the pending prompt (if any) and yield messages until the turn ends.

        ``turn_timeout_s`` bounds a single turn. Resolution order:
        explicit arg → ``options.turn_timeout_s`` → env ``GROK_TURN_TIMEOUT_S``
        → ``DEFAULT_TURN_TIMEOUT_S`` (3600s).

        On timeout after real tool work we yield a *soft* end (is_error=False)
        so the orchestrator can inject a continue-turn rather than aborting
        the whole job as a hard SDK death (job 3c0e0edb73db: 600s hard
        timeout → fallback skeleton + no_flag despite solid analysis).
        """
        if self._pending_prompt is None:
            return
        prompt_text = self._pending_prompt
        self._pending_prompt = None
        if not self.session_id:
            raise GrokACPError("no session_id — start() did not create a session")

        if turn_timeout_s is None:
            turn_timeout_s = self.options.turn_timeout_s
        if turn_timeout_s is None:
            try:
                turn_timeout_s = float(
                    os.environ.get("GROK_TURN_TIMEOUT_S", str(DEFAULT_TURN_TIMEOUT_S))
                )
            except ValueError:
                turn_timeout_s = DEFAULT_TURN_TIMEOUT_S
        turn_timeout_s = float(turn_timeout_s)

        self._turn_count += 1
        t0 = time.time()

        # Emit a synthetic init SystemMessage once so capture_session_id works.
        yield SystemMessage({
            "subtype": "init",
            "session_id": self.session_id,
            "type": "system",
        })

        rid = await self._send_prompt(prompt_text)
        text_buf: list[str] = []
        # Coalesce token-sized agent_message_chunk events so the CTF run.log
        # does not get one line per subword (observed on job 3c0e0edb73db).
        stream_acc: list[str] = []
        tool_names: list[str] = []
        error = False
        stop_reason = None
        usage: dict = {}

        def _flush_stream_text() -> AssistantMessage | None:
            if not stream_acc:
                return None
            joined = "".join(stream_acc)
            stream_acc.clear()
            if not joined:
                return None
            text_buf.append(joined)
            return AssistantMessage([TextBlock(joined)])

        while True:
            remaining = turn_timeout_s - (time.time() - t0)
            if remaining <= 0:
                msg = _flush_stream_text()
                if msg is not None:
                    yield msg
                # Soft timeout: hard-error only if the turn never did real work.
                soft = bool(tool_names or text_buf)
                error = not soft
                # "turn_budget" is a soft stop the orchestrator can resume from.
                stop_reason = "timeout" if not soft else "turn_budget"
                yield AssistantMessage([TextBlock(
                    f"[grok turn time budget {turn_timeout_s:.0f}s reached"
                    + ("; yielding so orchestrator can continue next turn"
                       if soft else "; no tool activity — treating as error")
                    + "]"
                )])
                break
            try:
                item = await asyncio.wait_for(self._inbox.get(), timeout=remaining)
            except asyncio.TimeoutError:
                msg = _flush_stream_text()
                if msg is not None:
                    yield msg
                soft = bool(tool_names or text_buf)
                error = not soft
                stop_reason = "timeout" if not soft else "turn_budget"
                yield AssistantMessage([TextBlock(
                    f"[grok turn time budget {turn_timeout_s:.0f}s reached"
                    + ("; yielding so orchestrator can continue next turn"
                       if soft else "; no tool activity — treating as error")
                    + "]"
                )])
                break
            kind = item.get("kind")
            if kind == "notification":
                method = item.get("method")
                params = item.get("params") or {}
                if method == "session/update":
                    update = params.get("update") or params
                    su = update.get("sessionUpdate")
                    if su == "agent_message_chunk":
                        chunk = ((update.get("content") or {}).get("text")) or ""
                        if chunk:
                            stream_acc.append(chunk)
                            # Flush on sentence boundary or when the buffer is large
                            # enough to keep the live UI reasonably snappy.
                            buf = "".join(stream_acc)
                            if len(buf) >= 120 or buf.endswith(("\n", ". ", ".\n", "! ", "? ")):
                                msg = _flush_stream_text()
                                if msg is not None:
                                    yield msg
                    elif su == "agent_thought_chunk":
                        pass  # not forwarded as assistant text
                    elif su == "tool_call":
                        msg = _flush_stream_text()
                        if msg is not None:
                            yield msg
                        name = (
                            update.get("title")
                            or update.get("toolName")
                            or (update.get("kind") and f"tool:{update.get('kind')}")
                            or "tool"
                        )
                        tool_names.append(str(name))
                        tid = update.get("toolCallId") or update.get("tool_call_id") or ""
                        raw_in = update.get("rawInput") or update.get("input") or {}
                        if not isinstance(raw_in, dict):
                            raw_in = {"value": raw_in}
                        yield AssistantMessage([
                            ToolUseBlock(name=str(name), input=raw_in, id=str(tid))
                        ])
                    elif su == "tool_call_update":
                        # The tool's OUTCOME arrives here. This used to be a
                        # bare `pass`, which meant the orchestrator never saw a
                        # single tool result on the Grok path: TOOL_RESULT
                        # logging, the runaway detector and — the expensive one
                        # — the LIVE flag-candidate scan were all dead, because
                        # _extract_msg_text feeds that scan from
                        # "AssistantMessage TextBlocks + UserMessage tool-result
                        # content" and no UserMessage was ever emitted. A flag
                        # printed to a tool's stdout, which is how an exploit
                        # normally reports one, never reached the [FLAG?] box.
                        # Only terminal updates are forwarded; in-progress ones
                        # would duplicate a single call many times over.
                        _status = str(update.get("status") or "").lower()
                        if _status in ("completed", "failed", "error", "cancelled"):
                            _body = _tool_result_text(update)
                            if _body:
                                yield UserMessage([ToolResultBlock(
                                    content=_body,
                                    is_error=_status in ("failed", "error"),
                                    tool_use_id=str(
                                        update.get("toolCallId")
                                        or update.get("tool_call_id") or ""
                                    ),
                                )])
                continue

            if kind == "response" and item.get("id") == rid:
                msg = _flush_stream_text()
                if msg is not None:
                    yield msg
                body = item.get("data") or {}
                if "error" in body:
                    error = True
                    err = body["error"]
                    emsg = err.get("message") if isinstance(err, dict) else str(err)
                    yield AssistantMessage([TextBlock(f"[grok error] {emsg}")])
                    stop_reason = "error"
                else:
                    result = body.get("result") or {}
                    stop_reason = result.get("stopReason") or result.get("stop_reason")
                    meta = result.get("_meta") or {}
                    usage = meta.get("usage") or {
                        k: meta.get(k)
                        for k in (
                            "inputTokens", "outputTokens", "totalTokens",
                            "cachedReadTokens", "reasoningTokens",
                        )
                        if meta.get(k) is not None
                    }
                    self._last_usage = usage if isinstance(usage, dict) else {}
                    if not text_buf and tool_names:
                        yield AssistantMessage([
                            TextBlock(f"[tools: {', '.join(tool_names[:8])}]")
                        ])
                break

            if kind == "eof":
                msg = _flush_stream_text()
                if msg is not None:
                    yield msg
                error = True
                stop_reason = "eof"
                break

            if kind == "stderr_fatal":
                msg = _flush_stream_text()
                if msg is not None:
                    yield msg
                error = True
                stop_reason = "process_error"
                yield AssistantMessage([TextBlock(item.get("text", "grok process error"))])
                break

        duration_ms = int((time.time() - t0) * 1000)
        cost = None
        if isinstance(usage, dict) and usage.get("total_cost_usd") is not None:
            try:
                cost = float(usage["total_cost_usd"])
            except (TypeError, ValueError):
                cost = None

        yield ResultMessage(
            duration_ms=duration_ms,
            num_turns=self._turn_count,
            total_cost_usd=cost,
            is_error=error or (stop_reason or "").lower() in {
                "error", "eof", "process_error", "cancelled", "max_tokens", "timeout",
            },
            stop_reason=stop_reason,
            usage=usage if isinstance(usage, dict) else {},
            session_id=self.session_id,
            model_usage=_acp_usage_to_model_usage(
                usage if isinstance(usage, dict) else {},
                getattr(self.options, "model", None),
            ),
        )

    # ----- internals -------------------------------------------------------

    async def _read_loop(self) -> None:
        assert self.proc and self.proc.stdout
        try:
            while not self._closed:
                line = await self.proc.stdout.readline()
                if not line:
                    await self._inbox.put({"kind": "eof"})
                    # Fail any waiters.
                    for fut in list(self._resp_waiters.values()):
                        if not fut.done():
                            fut.set_exception(GrokACPError("grok agent stdout EOF"))
                    self._resp_waiters.clear()
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    # Non-JSON noise — ignore (some builds may print banners).
                    continue
                msg_id = data.get("id")
                if msg_id is not None and msg_id in self._prompt_ids:
                    # Prompt turn: stream result via inbox (with prior notifications).
                    self._prompt_ids.discard(msg_id)
                    self._resp_waiters.pop(msg_id, None)
                    await self._inbox.put({"kind": "response", "id": msg_id, "data": data})
                elif msg_id is not None and msg_id in self._resp_waiters:
                    # RPC helper (initialize / session/new): resolve Future only.
                    fut = self._resp_waiters.pop(msg_id)
                    if not fut.done():
                        fut.set_result(data)
                elif data.get("method"):
                    await self._inbox.put({
                        "kind": "notification",
                        "method": data.get("method"),
                        "params": data.get("params") or {},
                    })
                elif msg_id is not None:
                    # Orphan response — drop (do not poison the turn inbox).
                    pass
        except asyncio.CancelledError:
            raise
        except Exception as e:
            await self._inbox.put({
                "kind": "stderr_fatal",
                "text": f"reader died: {type(e).__name__}: {e}",
            })

    async def _request(self, method: str, params: dict | None = None, timeout: float = 60.0) -> dict:
        if not self.proc or not self.proc.stdin:
            raise GrokACPError("process not running")
        self._rid += 1
        mid = self._rid
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._resp_waiters[mid] = fut
        msg = {"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}}
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        await self.proc.stdin.drain()
        try:
            data = await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self._resp_waiters.pop(mid, None)
            raise GrokACPError(f"timeout waiting for {method} (id={mid})")
        if "error" in data:
            err = data["error"]
            raise GrokACPError(f"{method} error: {err}")
        return data.get("result") or {}

    async def _send_prompt(self, text: str) -> int:
        """Fire session/prompt without waiting; receive_response drains the result."""
        if not self.proc or not self.proc.stdin or not self.session_id:
            raise GrokACPError("not ready for prompt")
        self._rid += 1
        mid = self._rid
        self._prompt_ids.add(mid)

        msg = {
            "jsonrpc": "2.0",
            "id": mid,
            "method": "session/prompt",
            "params": {
                "sessionId": self.session_id,
                "prompt": [{"type": "text", "text": text}],
            },
        }
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        await self.proc.stdin.drain()
        return mid

    async def _initialize(self) -> None:
        # Do NOT advertise client-side fs/terminal capabilities. If we claim
        # readTextFile/writeTextFile/terminal, the agent routes those ops as
        # client requests that we never serve — tool turns hang until timeout.
        # With empty capabilities the agent uses its own in-process tools.
        await self._request("initialize", {
            "protocolVersion": 1,
            "clientCapabilities": {},
            "clientInfo": {"name": "hextech-ctf-tool", "version": "1.0"},
        }, timeout=30)

    async def _create_session(self) -> None:
        system = self.options.system_prompt or ""
        if (
            self.options.append_tool_addendum
            and GROK_TOOL_ADDENDUM not in system
        ):
            system = (system.rstrip() + "\n\n" + GROK_TOOL_ADDENDUM).strip()
        meta: dict[str, Any] = {
            "yoloMode": True,
            "systemPromptOverride": system,
        }
        if self.options.rules:
            meta["rules"] = self.options.rules
        # Expose add_dirs as a short rules note so the model knows reference paths.
        if self.options.add_dirs:
            dirs = ", ".join(self.options.add_dirs)
            extra = (
                f"Reference directories (read for challenge material; do NOT write "
                f"deliverables into them): {dirs}"
            )
            meta["rules"] = ((meta.get("rules") or "") + "\n" + extra).strip()

        result = await self._request("session/new", {
            "cwd": str(Path(self.options.cwd).resolve()),
            "mcpServers": [],
            "_meta": meta,
        }, timeout=60)
        sid = result.get("sessionId") or result.get("session_id")
        if not sid:
            raise GrokACPError(f"session/new returned no sessionId: {result!r}")
        self.session_id = sid


async def query_grok_once(
    *,
    prompt: str,
    cwd: str,
    system_prompt: str | None = None,
    model: str | None = None,
    effort: str | None = None,
    timeout_s: float = 300.0,
    append_tool_addendum: bool = False,
    allow_tools: bool = False,
) -> dict:
    """One-shot Grok turn for report / judge / pre-recon / reviewer helpers.

    Returns ``{"text": str, "session_id": str|None, "usage": dict, "error": str|None}``.

    ``append_tool_addendum`` defaults to **False** so pure-text helpers
    (retry reviewer, monitor, report JSON) are not nudged into tool use —
    CTF main sessions use ``GrokACPClient`` + ``GrokSessionOptions`` with
    the addendum left on (default True there).
    """
    from modules.agent_provider import default_model_for, default_effort_for

    opts = GrokSessionOptions(
        system_prompt=system_prompt or "You are a careful assistant. Be concise.",
        model=model or default_model_for("grok"),
        cwd=cwd,
        effort=effort or default_effort_for("grok"),
        append_tool_addendum=append_tool_addendum,
    )
    text_parts: list[str] = []
    err = None
    usage: dict = {}
    sid = None
    try:
        async with GrokACPClient(opts) as client:
            sid = client.session_id
            await client.query(prompt)

            async def _drain():
                nonlocal usage, sid, err
                async for msg in client.receive_response():
                    if isinstance(msg, AssistantMessage):
                        for b in msg.content or []:
                            # Role lockdown. On the Claude path these helpers
                            # run with allowed_tools=[] and a nine-entry
                            # disallowed_tools (modules/_monitor.py:285 for the
                            # narrator, modules/_common.py:2447 for the report
                            # phase) — a hard deny. Grok has no equivalent knob:
                            # the session is yoloMode with empty
                            # clientCapabilities, and `append_tool_addendum`
                            # only declines to NUDGE toward tools. So a role
                            # that is text-only on Claude was unrestricted here.
                            # This does not PREVENT the call — grok runs tools
                            # in-process and only notifies us afterwards — but
                            # it stops the turn and fails the helper instead of
                            # letting it quietly do tool work under a prompt
                            # that never sanctioned any. Real prevention needs
                            # a per-session permission mode; the existing hook
                            # mechanism is global to $GROK_HOME and cannot be
                            # scoped to one role.
                            if not allow_tools and type(b).__name__ == "ToolUseBlock":
                                err = (
                                    "tool_use_in_text_only_role: grok attempted "
                                    f"`{getattr(b, 'name', '?')}` in a helper that "
                                    "is text-only on the Claude path"
                                )
                                return
                            t = getattr(b, "text", None)
                            if t:
                                text_parts.append(t)
                    elif isinstance(msg, ResultMessage):
                        usage = msg.usage or {}
                        sid = msg.session_id or sid
                        if msg.is_error:
                            err = msg.stop_reason or "error"

            await asyncio.wait_for(_drain(), timeout=timeout_s)
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
    return {
        "text": "".join(text_parts),
        "session_id": sid,
        "usage": usage,
        "error": err,
    }
