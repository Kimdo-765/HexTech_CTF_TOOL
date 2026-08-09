"""Settings persistence shared by api + worker.

Settings are stored in /data/settings.json (mounted on both containers).
Precedence: settings file > env var > default.

Sensitive values (api keys, auth tokens) are returned masked from
get_settings_view() — full values stay on disk.
"""

from __future__ import annotations

import json
import math
import os
import threading
from pathlib import Path
from typing import Any  # noqa: F401

SETTINGS_PATH = Path(os.environ.get("SETTINGS_PATH", "/data/settings.json"))

# Allowed values for agent_provider. Keep in sync with the Settings UI and
# modules/agent_provider.py.
AGENT_PROVIDERS = ("claude", "grok", "gpt")

# (key, env_fallback, type, default)
SCHEMA: list[tuple[str, str | None, type, Any]] = [
    # Which coding-agent backend runs CTF jobs. "claude" = Claude Agent SDK
    # (current default). "grok" = Grok Build via ACP / headless (in progress).
    ("agent_provider", "AGENT_PROVIDER", str, "claude"),
    # OPTIONAL per-role backend override, e.g. {"judge": "claude"} while
    # agent_provider stays "gpt". Absent / empty means every role follows
    # agent_provider, which is byte-for-byte the pre-hybrid behaviour — the
    # scalar above is deliberately NOT replaced, because _monitor.py and the
    # retry chain read it as a plain string.
    ("agent_role_providers", None, dict, {}),
    ("anthropic_api_key", "ANTHROPIC_API_KEY", str, ""),
    ("claude_model", "CLAUDE_MODEL", str, "claude-opus-4-7"),
    # Global effort for Claude sessions (low/medium/high/xhigh/max). UI has
    # always exposed this; SCHEMA entry was missing so saves were dropped.
    ("claude_effort", "CLAUDE_EFFORT", str, ""),
    # xAI / Grok Build credentials + defaults (used when agent_provider=grok).
    ("xai_api_key", "XAI_API_KEY", str, ""),
    ("grok_model", "GROK_MODEL", str, "grok-build"),
    ("grok_effort", "GROK_EFFORT", str, ""),
    # GPT provider. Codex CLI + ChatGPT OAuth is the default; the direct
    # Responses API remains an explicit usage-billed fallback.
    ("gpt_runtime", "GPT_RUNTIME", str, "codex"),
    ("openai_api_key", "OPENAI_API_KEY", str, ""),
    ("gpt_model", "GPT_MODEL", str, "gpt-5.6-sol"),
    ("gpt_effort", "GPT_EFFORT", str, "medium"),
    ("auth_token", "AUTH_TOKEN", str, ""),
    ("job_ttl_days", "JOB_TTL_DAYS", int, 7),
    ("job_timeout_seconds", "JOB_TIMEOUT", int, 900),
    # Read-only in slot mode: concurrency is now the NUMBER OF worker-N
    # services in docker-compose.yml, and worker/runner.py forces 1 process per
    # slot container regardless of what is stored here. Kept in the schema so
    # an older single-container compose file still works.
    ("worker_concurrency", "WORKER_CONCURRENCY", int, 3),
    # Cgroup memory cap for EACH worker slot container, as a docker size string
    # ("4g", "4096m", or plain bytes). Restored 2026-07-29 after a real
    # `global_oom` (one python3 at 15.0 GB inside a 15.5 GB VM) froze the whole
    # WSL VM: the cap does not save a runaway job, it keeps the kill LOCAL to
    # the container instead of taking the host session down. Unlike every other
    # key here this one is NOT read at job start — it is a container-create
    # property — so PUT /api/settings applies it LIVE via the Docker API, and
    # docker-compose.yml reads WORKER_SLOT_MEM from .env as the boot default.
    #
    # RENAMED from worker_mem_limit / WORKER_MEM_LIMIT on the slot split, and
    # the rename is load-bearing, not cosmetic. That key meant "cap for the ONE
    # worker container" and both /data/settings.json and .env held 8g. Reusing
    # it would have silently reinterpreted 8g as PER SLOT, and the first
    # settings save would have pushed 8g onto every slot via `docker update` —
    # 16 GiB of cap inside a 15.99 GiB VM, i.e. exactly the unbounded condition
    # that froze WSL twice. A renamed key falls back to this safe default; a
    # reinterpreted one fails to 2x. The stale `worker_mem_limit` entry left in
    # /data/settings.json is inert: lookups iterate SCHEMA, so a key that is not
    # here is never read and never shown.
    ("worker_slot_mem", "WORKER_SLOT_MEM", str, "4g"),
    # Remove the containers and networks a job created once it reaches a
    # terminal status. Default ON: agent-started containers have no other
    # owner, and containers from 2026-06 were still running in 2026-08, each
    # holding a 2 GiB cgroup ceiling. Turn OFF to keep a failed job's challenge
    # stack up for debugging — the Containers tab can then clear it by hand.
    ("reap_job_containers", "REAP_JOB_CONTAINERS", bool, True),
    ("callback_url", "CALLBACK_URL", str, ""),
    # Operator spend budget (USD) for the top-bar "used / budget" usage pill.
    # 0 = no budget set → the pill shows cumulative spend only (no bar / %).
    # This is an OPERATOR budget, NOT the Claude account limit — a true
    # remaining-quota number isn't retrievable in the OAuth/headless path
    # (see the usage-widget feasibility notes); the pill reads existing
    # aggregate cost against this ceiling.
    ("budget_usd", "BUDGET_USD", float, 0.0),
    # Quality-gate judge that wraps auto_run exploit/solver execution
    # (pre-flight script review → post-mortem verdict). Each stage is one
    # short no-tools Claude call against LATEST_JUDGE_MODEL. Disable to
    # skip all judge calls and run the script with the plain runner
    # (saves ~2 Claude turns per auto_run job at the cost of losing
    # parse-error detection).
    #
    # A stall-detection stage used to be listed here as a third one. It is
    # excluded from v1 enforce and gated behind `enable_supervise`
    # (default False), so hang detection is NOT among the things this
    # setting buys — the hard timeout still covers it.
    ("enable_judge", "ENABLE_JUDGE", bool, True),
    # Tri-state successor to `enable_judge`. Empty means "derive from the
    # boolean", so existing settings keep meaning exactly what they meant:
    # False -> off, True -> enforce. `shadow` is reachable only by setting
    # this explicitly — a mode that changes what the operator sees should
    # never be entered by inference.
    ("judge_mode", "JUDGE_MODE", str, ""),
    # When True, every job's user_prompt is prepended with a short
    # paragraph listing same-module entries from the exploit library
    # (`/data/exploits/`, populated via POST /api/exploits/save) so
    # the agent can `cat /data/exploits/<id>/report.md` for insight on
    # similar chals (leak vector / FSOP variant / technique pick).
    # Default OFF — `heap_state_evolution_gap` memory warns against
    # broad prompt nudges from small libraries; only flip on after the
    # library has several curated entries the operator trusts.
    ("enable_exploit_library_hint", "ENABLE_EXPLOIT_LIBRARY_HINT", bool, False),
]
_MEM_SUFFIX = {"b": 1, "k": 1024, "m": 1024**2, "g": 1024**3}


def parse_mem_limit(value: Any) -> int:
    """Docker size string -> bytes. Accepts '12g', '8192m', '512K', or a plain
    byte count. Raises ValueError on anything else, so a typo in the UI is a
    400 rather than a silently-wrong cgroup limit."""
    s = str(value).strip().lower().replace("ib", "")
    if not s:
        raise ValueError("empty memory limit")
    mult = 1
    if s[-1] in _MEM_SUFFIX:
        mult = _MEM_SUFFIX[s[-1]]
        s = s[:-1].strip()
    try:
        n = float(s)
    except ValueError:
        raise ValueError(f"not a size: {value!r} (use e.g. '12g', '8192m')")
    # `float()` happily accepts 'inf' / 'nan'. `inf <= 0` is False, so an
    # infinity sailed past the positivity check and blew up in int() with
    # OverflowError — which the route catches as ValueError only, turning a
    # typo into an HTTP 500 instead of the promised 400.
    if not math.isfinite(n):
        raise ValueError(f"not a size: {value!r} (use e.g. '12g', '8192m')")
    if n <= 0:
        raise ValueError(f"memory limit must be positive: {value!r}")
    want = int(n * mult)
    # Upper bound. Without one, '1000g' on a 16 GB host was accepted, written
    # to the cgroup and reported as success — leaving the worker effectively
    # UNCAPPED, i.e. exactly the state the cap exists to prevent, while the UI
    # showed a reassuring number.
    total = _host_mem_total_bytes()
    if total and want > total:
        raise ValueError(
            f"{value!r} ({want:,} B) exceeds host RAM ({total:,} B) — that "
            f"leaves the container effectively uncapped"
        )
    return want


def _host_mem_total_bytes() -> int:
    """Host MemTotal in bytes, or 0 when unreadable (non-Linux, restricted)."""
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
    except Exception:
        pass
    return 0


_SECRET_KEYS = {
    "anthropic_api_key",
    "xai_api_key",
    "openai_api_key",
    "auth_token",
}

_lock = threading.Lock()


def _coerce(value: Any, typ: type) -> Any:
    """Cast `value` to `typ`, with sane handling for bool.

    Plain `bool("false")` returns True (any non-empty string is truthy).
    For settings that come from env vars or HTTP form data we want
    "false"/"0"/"no"/"off" → False, "true"/"1"/"yes"/"on" → True.
    Everything else falls back to `typ(value)`.
    """
    if typ is bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        s = str(value).strip().lower()
        if s in ("", "0", "false", "no", "off", "none", "null"):
            return False
        return True
    return typ(value)


def load_settings() -> dict[str, Any]:
    if not SETTINGS_PATH.exists():
        return {}
    try:
        return json.loads(SETTINGS_PATH.read_text())
    except Exception:
        return {}


def save_settings(d: dict[str, Any]) -> None:
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        tmp = SETTINGS_PATH.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(d, indent=2))
        tmp.replace(SETTINGS_PATH)


def get_setting(key: str) -> Any:
    settings = load_settings()
    for k, env_key, typ, default in SCHEMA:
        if k != key:
            continue
        v = settings.get(k)
        if v not in (None, ""):
            try:
                return _coerce(v, typ)
            except (TypeError, ValueError):
                return v
        if env_key:
            ev = os.environ.get(env_key, "")
            if ev != "":
                try:
                    return _coerce(ev, typ)
                except (TypeError, ValueError):
                    return ev
        return default
    return None


def apply_to_env() -> None:
    """Push current settings into the process env so libraries that read
    `os.environ["ANTHROPIC_API_KEY"]` (etc.) see them.

    Called by orchestrators at the start of each job — that way the user
    can change the key via the UI and the next job picks it up without a
    container restart.

    For ANTHROPIC_API_KEY / XAI_API_KEY / OPENAI_API_KEY: a placeholder value (e.g.
    "sk-ant-..." or a value ending in "...") is treated as unset so the
    agent falls back to OAuth / browser credentials on disk.
    """
    for key, env_key, typ, _ in SCHEMA:
        if not env_key:
            continue
        v = get_setting(key)
        if v in (None, ""):
            continue
        if key in ("anthropic_api_key", "xai_api_key", "openai_api_key"):
            sv = str(v)
            if sv.startswith("sk-ant-...") or sv.endswith("..."):
                os.environ.pop(env_key, None)
                continue
        os.environ[env_key] = str(v)


def has_claude_oauth() -> bool:
    """True if the worker container has a Claude Code OAuth credentials file
    (mounted from the host's ~/.claude). Used to detect whether claude.ai
    subscription auth is available even when no API key is configured.
    """
    candidates = [
        Path("/root/.claude/.credentials.json"),
        Path("/root/.claude/credentials.json"),
        Path.home() / ".claude" / ".credentials.json",
        Path.home() / ".claude" / "credentials.json",
    ]
    for c in candidates:
        try:
            if c.is_file() and c.stat().st_size > 0:
                return True
        except Exception:
            pass
    return False


def has_anthropic_api_key() -> bool:
    """True if a real (non-placeholder) Anthropic API key is configured."""
    v = str(get_setting("anthropic_api_key") or "")
    if not v:
        return False
    if v.startswith("sk-ant-...") or v.endswith("..."):
        return False
    return True


def has_claude_auth() -> bool:
    return has_anthropic_api_key() or has_claude_oauth()


def has_xai_api_key() -> bool:
    """True if a real (non-placeholder) xAI API key is configured."""
    v = str(get_setting("xai_api_key") or "")
    if not v:
        return False
    if v.endswith("..."):
        return False
    return True


def has_grok_auth_file() -> bool:
    """True if Grok CLI browser/OAuth credentials exist on disk.

    The worker may mount the host ``~/.grok`` (or equivalent) so
    ``grok login`` credentials work without stuffing XAI_API_KEY into
    settings. Paths mirror the Claude OAuth check.
    """
    candidates = [
        Path("/root/.grok/auth.json"),
        Path.home() / ".grok" / "auth.json",
        Path(os.environ.get("GROK_HOME", "") or "/nonexistent") / "auth.json",
    ]
    for c in candidates:
        try:
            if c.is_file() and c.stat().st_size > 0:
                return True
        except Exception:
            pass
    return False


def has_grok_auth() -> bool:
    return has_xai_api_key() or has_grok_auth_file()


def has_openai_api_key() -> bool:
    """True if a real (non-placeholder) OpenAI API key is configured."""
    v = str(get_setting("openai_api_key") or "")
    return bool(v and not v.endswith("...") and v not in {"sk-...", "sk-proj-..."})


def codex_auth_method() -> str:
    """Return the non-secret auth mode from Codex's cache, if available.

    The token payload is never returned or logged. Containers use file-backed
    auth because a host OS keyring cannot be mounted into Docker.
    """
    candidates = [
        Path(os.environ.get("CODEX_HOME", "") or "/nonexistent") / "auth.json",
        Path("/root/.codex/auth.json"),
        Path.home() / ".codex" / "auth.json",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        try:
            if not candidate.is_file() or candidate.stat().st_size <= 0:
                continue
            data = json.loads(candidate.read_text())
            mode = (
                str(data.get("auth_mode") or data.get("authMode") or "unknown")
                .strip()
                .lower()
            )
            return mode or "unknown"
        except Exception:
            continue
    return ""


def has_codex_auth_file() -> bool:
    return bool(codex_auth_method())


def has_codex_oauth() -> bool:
    """Whether a file-backed ChatGPT login is mounted for Codex CLI."""
    mode = codex_auth_method()
    return mode in {"chatgpt", "oauth", "chatgpt_oauth"}


def get_gpt_runtime() -> str:
    value = str(get_setting("gpt_runtime") or "codex").strip().lower()
    return value if value in {"codex", "responses"} else "codex"


def get_agent_provider() -> str:
    """Return the active agent backend: ``claude``, ``grok`` or ``gpt``.

    Unknown / empty values fall back to ``claude`` so a typo in settings
    never silently disables the only fully-wired path.
    """
    v = str(get_setting("agent_provider") or "claude").strip().lower()
    return v if v in AGENT_PROVIDERS else "claude"


JUDGE_MODES = ("off", "shadow", "enforce")


def get_judge_mode() -> str:
    """`off` | `shadow` | `enforce`.

    `judge_mode` wins when explicitly set; otherwise it is derived from the
    legacy boolean so no existing deployment changes behaviour by upgrading.
    `shadow` is deliberately NOT derivable — it runs the judge without letting
    it gate anything, and entering that by inference would leave an operator
    believing a gate is live when it is not.
    """
    raw = str(get_setting("judge_mode") or "").strip().lower()
    if raw in JUDGE_MODES:
        return raw
    legacy = get_setting("enable_judge")
    return "enforce" if (legacy is None or bool(legacy)) else "off"


# Stage 8 scope — operator decision, 2026-08-09. `enforce` is NOT global.
#
# The stage-7 stratified table (handoff turn 0069) could only measure
# discriminating power where BOTH outcome classes exist. That is pwn (8 capture
# / 8 negative) and web (3 / 3). rev (13 / 1) and crypto (6 / 0) have no
# meaningful negative class, so a judge that answers "success" every time scores
# full marks there — that is a measurement we failed to take, not a good result,
# and gating on it would be gating on nothing. web3 / misc / forensic have n<5.
#
# Deliberately a constant rather than a settings key: STATE.md's rule is that a
# new requirement has to displace an existing one or be approved, and the
# operator approved a scope, not a control surface.
JUDGE_ENFORCE_MODULES: tuple[str, ...] = ("pwn", "web")


def effective_judge_mode(mode: str, module: str) -> str:
    """The mode a job of `module` actually runs under.

    Out-of-scope modules fall to `shadow`, not `off`: they keep recording what
    the judge would have said, which is how the missing negative class for rev
    and crypto eventually gets collected. Only the GATING is scoped.

    Unknown or empty module never reaches enforce. "We could not tell which
    module this is" must not resolve to "gate it" — the caller cannot tell that
    case apart from a module the operator deliberately excluded.
    """
    m = str(mode or "").strip().lower()
    if m not in JUDGE_MODES:
        return "off"
    if m != "enforce":
        return m
    return "enforce" if str(module or "").strip().lower() in JUDGE_ENFORCE_MODULES else "shadow"


def get_agent_role_providers() -> dict[str, str]:
    """Per-role backend overrides from Settings, sanitized.

    Returns ``{role: provider}`` keeping only entries whose provider is a
    known id. A malformed value yields ``{}`` — an unreadable override must
    degrade to "every role follows agent_provider", never to a half-applied
    map. Role names are NOT validated here; the resolver owns that, so a
    future role does not need a settings_io release to be routable.
    """
    raw = get_setting("agent_role_providers")
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for role, provider in raw.items():
        r = str(role or "").strip().lower()
        p = str(provider or "").strip().lower()
        if r and p in AGENT_PROVIDERS:
            out[r] = p
    return out


def has_active_agent_auth() -> bool:
    """Auth available for whichever provider Settings currently selects."""
    provider = get_agent_provider()
    if provider == "grok":
        return has_grok_auth()
    if provider == "gpt":
        return (
            has_codex_oauth() if get_gpt_runtime() == "codex" else has_openai_api_key()
        )
    return has_claude_auth()


def mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}…{value[-4:]}"


def get_settings_view() -> dict[str, Any]:
    """Public view safe to send to the UI. Secrets are masked."""
    settings = load_settings()
    out: dict[str, Any] = {
        "claude_oauth_detected": has_claude_oauth(),
        "grok_auth_detected": has_grok_auth_file(),
        "codex_auth_detected": has_codex_auth_file(),
        "codex_oauth_detected": has_codex_oauth(),
        "codex_auth_method": codex_auth_method(),
        "agent_providers": list(AGENT_PROVIDERS),
    }
    for key, env_key, typ, default in SCHEMA:
        raw = settings.get(key)
        env_v = os.environ.get(env_key, "") if env_key else ""
        effective_raw = raw if raw not in (None, "") else env_v if env_v else default
        try:
            effective = (
                _coerce(effective_raw, typ)
                if effective_raw not in (None, "")
                else default
            )
        except (TypeError, ValueError):
            effective = effective_raw
        if key == "agent_provider":
            # Always expose a normalized value so the UI never has to
            # re-validate typos stored on disk.
            effective = str(effective or "claude").strip().lower()
            if effective not in AGENT_PROVIDERS:
                effective = "claude"
        if key == "gpt_runtime":
            effective = str(effective or "codex").strip().lower()
            if effective not in {"codex", "responses"}:
                effective = "codex"
        if key in _SECRET_KEYS:
            out[f"{key}_set"] = bool(raw)
            out[f"{key}_env_set"] = bool(env_v)
            out[f"{key}_masked"] = mask(str(raw or ""))
        else:
            out[key] = effective
            out[f"{key}_source"] = (
                "settings" if raw not in (None, "") else "env" if env_v else "default"
            )
    return out


def update_settings(patch: dict[str, Any]) -> dict[str, Any]:
    """Apply a patch. For each key in patch:
      - value is None or "" : clear the override (revert to env/default)
      - any other value     : set
    Keys not present in the patch dict are left untouched.
    """
    cur = load_settings()
    valid = {k for k, *_ in SCHEMA}
    for key, val in patch.items():
        if key not in valid:
            continue
        if val is None or (isinstance(val, str) and val == ""):
            cur.pop(key, None)
            continue
        if key == "agent_provider":
            v = str(val).strip().lower()
            if v not in AGENT_PROVIDERS:
                raise ValueError(
                    f"agent_provider must be one of {AGENT_PROVIDERS}, got {val!r}"
                )
            cur[key] = v
            continue
        if key == "gpt_runtime":
            v = str(val).strip().lower()
            if v not in {"codex", "responses"}:
                raise ValueError(
                    f"gpt_runtime must be one of ('codex', 'responses'), got {val!r}"
                )
            cur[key] = v
            continue
        for k, _, typ, _ in SCHEMA:
            if k == key:
                try:
                    cur[key] = _coerce(val, typ)
                except (TypeError, ValueError):
                    cur[key] = val
                break
    save_settings(cur)
    return get_settings_view()
