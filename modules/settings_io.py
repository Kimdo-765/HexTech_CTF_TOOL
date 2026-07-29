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

# (key, env_fallback, type, default)
SCHEMA: list[tuple[str, str | None, type, Any]] = [
    ("anthropic_api_key", "ANTHROPIC_API_KEY", str, ""),
    ("claude_model", "CLAUDE_MODEL", str, "claude-opus-4-7"),
    ("auth_token", "AUTH_TOKEN", str, ""),
    ("job_ttl_days", "JOB_TTL_DAYS", int, 7),
    ("job_timeout_seconds", "JOB_TIMEOUT", int, 900),
    ("worker_concurrency", "WORKER_CONCURRENCY", int, 3),
    # Cgroup memory cap for the worker container, as a docker size string
    # ("12g", "8192m", or plain bytes). Restored 2026-07-29 after a real
    # `global_oom` (one python3 at 15.0 GB inside a 15.5 GB VM) froze the whole
    # WSL VM: the cap does not save a runaway job, it keeps the kill LOCAL to
    # the container instead of taking the host session down. Unlike every other
    # key here this one is NOT read at job start — it is a container-create
    # property — so PUT /api/settings applies it LIVE via the Docker API, and
    # docker-compose.yml reads WORKER_MEM_LIMIT from .env as the boot default.
    ("worker_mem_limit", "WORKER_MEM_LIMIT", str, "12g"),
    ("callback_url", "CALLBACK_URL", str, ""),
    # Operator spend budget (USD) for the top-bar "used / budget" usage pill.
    # 0 = no budget set → the pill shows cumulative spend only (no bar / %).
    # This is an OPERATOR budget, NOT the Claude account limit — a true
    # remaining-quota number isn't retrievable in the OAuth/headless path
    # (see the usage-widget feasibility notes); the pill reads existing
    # aggregate cost against this ceiling.
    ("budget_usd", "BUDGET_USD", float, 0.0),
    # Quality-gate judge that wraps auto_run exploit/solver execution
    # (pre-flight script review → stall supervisor → post-mortem
    # verdict). Each stage is one short no-tools Claude call against
    # LATEST_JUDGE_MODEL. Disable to skip all judge calls and run the
    # script with the plain runner (saves ~3 Claude turns per auto_run
    # job at the cost of losing hang/parse-error detection).
    ("enable_judge", "ENABLE_JUDGE", bool, True),
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
_MEM_SUFFIX = {"b": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}


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


_SECRET_KEYS = {"anthropic_api_key", "auth_token"}

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

    For ANTHROPIC_API_KEY: a placeholder value (e.g. "sk-ant-...") is
    treated as unset so the SDK falls back to OAuth credentials.
    """
    for key, env_key, typ, _ in SCHEMA:
        if not env_key:
            continue
        v = get_setting(key)
        if v in (None, ""):
            continue
        if key == "anthropic_api_key":
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
    }
    for key, env_key, typ, default in SCHEMA:
        raw = settings.get(key)
        env_v = os.environ.get(env_key, "") if env_key else ""
        effective_raw = raw if raw not in (None, "") else env_v if env_v else default
        try:
            effective = _coerce(effective_raw, typ) if effective_raw not in (None, "") else default
        except (TypeError, ValueError):
            effective = effective_raw
        if key in _SECRET_KEYS:
            out[f"{key}_set"] = bool(raw)
            out[f"{key}_env_set"] = bool(env_v)
            out[f"{key}_masked"] = mask(str(raw or ""))
        else:
            out[key] = effective
            out[f"{key}_source"] = (
                "settings" if raw not in (None, "") else
                "env" if env_v else "default"
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
        for k, _, typ, _ in SCHEMA:
            if k == key:
                try:
                    cur[key] = _coerce(val, typ)
                except (TypeError, ValueError):
                    cur[key] = val
                break
    save_settings(cur)
    return get_settings_view()
