"""Agent-backend selection (Claude, Grok, or OpenAI Codex/GPT).

Settings ``agent_provider`` chooses which coding agent drives CTF jobs.
This module is the single place for:

  * normalizing the provider name
  * resolving the global default model / effort for that provider
  * checking auth readiness
  * recording the choice on job meta

Import resilience: long-lived RQ workers may still hold a pre-upgrade
``settings_io`` in ``sys.modules`` (no ``AGENT_PROVIDERS`` / ``has_grok_auth``).
We never hard-require those symbols at import time — fall back to local
definitions so a job does not die with ImportError before the operator
restarts the worker.
"""

from __future__ import annotations

from typing import Any

from modules.settings_io import get_setting, has_claude_auth

# Canonical provider ids. Duplicated (not imported) from settings_io so a
# stale in-memory settings_io from before the Grok work cannot break import.
AGENT_PROVIDERS = ("claude", "grok", "gpt")

# Prefer helpers from settings_io when present (current code); otherwise
# local fallbacks that read the same settings keys / auth files.
try:
    from modules.settings_io import get_agent_provider as _sio_get_agent_provider
except ImportError:  # pragma: no cover — stale worker process
    _sio_get_agent_provider = None  # type: ignore

try:
    from modules.settings_io import has_grok_auth as _sio_has_grok_auth
except ImportError:  # pragma: no cover
    _sio_has_grok_auth = None  # type: ignore

try:
    from modules.settings_io import has_openai_api_key as _sio_has_openai_api_key
except ImportError:  # pragma: no cover
    _sio_has_openai_api_key = None  # type: ignore

try:
    from modules.settings_io import has_codex_oauth as _sio_has_codex_oauth
except ImportError:  # pragma: no cover
    _sio_has_codex_oauth = None  # type: ignore

try:
    from modules.settings_io import get_gpt_runtime as _sio_get_gpt_runtime
except ImportError:  # pragma: no cover
    _sio_get_gpt_runtime = None  # type: ignore

# Runtime readiness. True once modules/grok_acp.py can drive main sessions.
GROK_RUNTIME_READY = True

DEFAULT_CLAUDE_MODEL = "claude-opus-4-7"
DEFAULT_GROK_MODEL = "grok-build"
DEFAULT_GPT_MODEL = "gpt-5.6-sol"

# Effort strings accepted by either backend (union). Unknown values are
# dropped at resolve time so a typo never reaches the CLI/SDK.
VALID_EFFORTS = frozenset(
    {
        "none",
        "minimal",
        "low",
        "medium",
        "high",
        "xhigh",
        "max",
    }
)


def normalize_provider(value: str | None) -> str:
    v = str(value or "").strip().lower()
    return v if v in AGENT_PROVIDERS else "claude"


def get_agent_provider() -> str:
    """Return the active agent backend: ``claude``, ``grok``, or ``gpt``."""
    if _sio_get_agent_provider is not None:
        try:
            return normalize_provider(_sio_get_agent_provider())
        except Exception:
            pass
    v = str(get_setting("agent_provider") or "claude").strip().lower()
    return v if v in AGENT_PROVIDERS else "claude"


def has_grok_auth() -> bool:
    if _sio_has_grok_auth is not None:
        try:
            return bool(_sio_has_grok_auth())
        except Exception:
            pass
    # Fallback: key in settings/env, or auth.json on disk.
    import os
    from pathlib import Path

    key = str(get_setting("xai_api_key") or os.environ.get("XAI_API_KEY") or "")
    if key and not key.endswith("..."):
        return True
    for c in (
        Path("/root/.grok/auth.json"),
        Path.home() / ".grok" / "auth.json",
        Path(os.environ.get("GROK_HOME", "") or "/nonexistent") / "auth.json",
    ):
        try:
            if c.is_file() and c.stat().st_size > 0:
                return True
        except Exception:
            pass
    return False


def has_openai_api_auth() -> bool:
    if _sio_has_openai_api_key is not None:
        try:
            return bool(_sio_has_openai_api_key())
        except Exception:
            pass
    import os

    key = str(get_setting("openai_api_key") or os.environ.get("OPENAI_API_KEY") or "")
    return bool(
        key and not key.endswith("...") and key not in {"sk-...", "sk-proj-..."}
    )


def get_gpt_runtime() -> str:
    if _sio_get_gpt_runtime is not None:
        try:
            value = str(_sio_get_gpt_runtime()).strip().lower()
            if value in {"codex", "responses"}:
                return value
        except Exception:
            pass
    value = str(get_setting("gpt_runtime") or "codex").strip().lower()
    return value if value in {"codex", "responses"} else "codex"


def has_codex_auth() -> bool:
    if _sio_has_codex_oauth is not None:
        try:
            return bool(_sio_has_codex_oauth())
        except Exception:
            pass
    import json
    import os
    from pathlib import Path

    for candidate in (
        Path(os.environ.get("CODEX_HOME", "") or "/nonexistent") / "auth.json",
        Path("/root/.codex/auth.json"),
        Path.home() / ".codex" / "auth.json",
    ):
        try:
            data = json.loads(candidate.read_text())
            mode = str(data.get("auth_mode") or data.get("authMode") or "").lower()
            if mode in {"chatgpt", "oauth", "chatgpt_oauth"}:
                return True
        except Exception:
            pass
    return False


def has_openai_auth() -> bool:
    """Auth readiness for the explicitly selected GPT runtime."""
    return has_codex_auth() if get_gpt_runtime() == "codex" else has_openai_api_auth()


def active_provider() -> str:
    return get_agent_provider()


def provider_display_name(provider: str | None = None) -> str:
    p = normalize_provider(provider or active_provider())
    return {
        "claude": "Claude (Agent SDK)",
        "grok": "Grok Build (ACP)",
        "gpt": (
            "OpenAI Codex (ChatGPT OAuth)"
            if get_gpt_runtime() == "codex"
            else "OpenAI GPT (Responses API)"
        ),
    }.get(p, p)


def has_provider_auth(provider: str | None = None) -> bool:
    p = normalize_provider(provider or active_provider())
    if p == "grok":
        return has_grok_auth()
    if p == "gpt":
        return has_openai_auth()
    return has_claude_auth()


def default_model_for(provider: str | None = None) -> str:
    """Global Settings default model for the given (or active) provider."""
    p = normalize_provider(provider or active_provider())
    if p == "grok":
        return str(get_setting("grok_model") or DEFAULT_GROK_MODEL)
    if p == "gpt":
        return str(get_setting("gpt_model") or DEFAULT_GPT_MODEL)
    return str(get_setting("claude_model") or DEFAULT_CLAUDE_MODEL)


def default_effort_for(provider: str | None = None) -> str | None:
    """Global Settings effort for the given (or active) provider, or None."""
    p = normalize_provider(provider or active_provider())
    key = {
        "grok": "grok_effort",
        "gpt": "gpt_effort",
    }.get(p, "claude_effort")
    raw = get_setting(key)
    if raw is None or str(raw).strip() == "":
        return None
    s = str(raw).strip().lower()
    return s if s in VALID_EFFORTS else None


def ensure_provider_ready(provider: str | None = None) -> str:
    """Validate that the selected provider can run a job.

    Returns the normalized provider name. Raises ``RuntimeError`` with an
    operator-facing message when auth or the selected runtime is missing.
    """
    p = normalize_provider(provider or active_provider())
    if p == "claude":
        if not has_claude_auth():
            raise RuntimeError(
                "agent_provider=claude but no Anthropic auth is configured. "
                "Set an API key in Settings or run `claude login` on the host "
                "so ~/.claude credentials are mounted into the worker."
            )
        return p

    if p == "gpt":
        runtime = get_gpt_runtime()
        if runtime == "codex":
            if not has_codex_auth():
                raise RuntimeError(
                    "agent_provider=gpt uses Codex OAuth, but no file-backed "
                    "ChatGPT login is mounted. Run `codex login` on the host "
                    "and set HOST_CODEX_HOME if it is not ~/.codex."
                )
            try:
                from modules.codex_cli import resolve_codex_bin

                resolve_codex_bin()
            except FileNotFoundError as e:
                raise RuntimeError(str(e)) from e
        else:
            if not has_openai_api_auth():
                raise RuntimeError(
                    "gpt_runtime=responses but no OpenAI API key is configured. "
                    "Set OPENAI_API_KEY in Settings or .env."
                )
            try:
                import openai  # noqa: F401
            except Exception as e:
                raise RuntimeError(
                    "gpt_runtime=responses is selected, but the OpenAI Python "
                    "SDK is not installed. Rebuild the api and worker images."
                ) from e
        return p

    # grok
    if not has_grok_auth():
        raise RuntimeError(
            "agent_provider=grok but no xAI/Grok auth is configured. "
            "Set an XAI API key in Settings or run `grok login` on the host "
            "and mount ~/.grok into the worker (HOST_GROK_HOME)."
        )
    if not GROK_RUNTIME_READY:
        raise RuntimeError(
            "agent_provider=grok is selected, but the Grok agent runtime is "
            "not wired into the main CTF session yet. Settings persistence "
            "and model resolution already work — switch back to Claude to "
            "run jobs, or continue the Grok ACP integration."
        )
    try:
        from modules.grok_acp import resolve_grok_bin

        resolve_grok_bin()
    except FileNotFoundError as e:
        raise RuntimeError(str(e)) from e
    return p


def provider_meta_fields(provider: str | None = None) -> dict[str, Any]:
    """Fields to stamp onto job meta so retries / UI show what ran."""
    p = normalize_provider(provider or active_provider())
    fields = {
        "agent_provider": p,
        "agent_provider_label": provider_display_name(p),
    }
    if p == "gpt":
        fields["gpt_runtime"] = get_gpt_runtime()
        # Snapshot the GPT preset used when the job starts. Timeline role cards
        # must not silently change if Settings is edited while an old job is
        # still running. This branch is GPT-only; Claude/Grok meta stays
        # exactly as before.
        try:
            from modules.model_presets import get_provider_store

            bucket = get_provider_store("gpt")
            active = str(bucket.get("active") or "")
            preset = (bucket.get("presets") or {}).get(active) or {}
            fields["gpt_preset"] = active
            fields["gpt_role_models"] = {
                role: str(preset.get(role) or "")
                for role in (
                    "main", "judge", "reviewer", "recon", "debugger",
                    "triage", "report",
                )
                if str(preset.get(role) or "").strip()
            }
            effort = str(preset.get("effort") or "").strip()
            if effort:
                fields["gpt_preset_effort"] = effort
        except Exception:
            pass
    return fields


def enrich_job_meta(
    meta: dict[str, Any], provider: str | None = None
) -> dict[str, Any]:
    """In-place stamp of provider fields onto a newly-created job meta dict."""
    meta.update(provider_meta_fields(provider))
    return meta


def is_claude_model_id(model: str | None) -> bool:
    m = (model or "").strip().lower()
    return m.startswith("claude") or m.startswith("anthropic")


def is_grok_model_id(model: str | None) -> bool:
    m = (model or "").strip().lower()
    return m.startswith("grok")


def is_gpt_model_id(model: str | None) -> bool:
    m = (model or "").strip().lower()
    return m.startswith(("gpt", "o1", "o3", "o4", "chatgpt"))


def coerce_model_for_provider(
    model: str | None,
    provider: str | None = None,
) -> str:
    """Force a model id that matches the selected backend.

    Never hand a model id from one known provider family to another.
    Empty / wrong-family ids fall back to that provider's Settings default.
    Used by judge / reviewer / report / monitor / forensic-misc so *every*
    agent role follows the operator's choice, not a leftover preset.
    """
    p = normalize_provider(provider or active_provider())
    m = (model or "").strip()
    if p == "grok":
        if not m or is_claude_model_id(m) or is_gpt_model_id(m):
            return default_model_for("grok")
        return m
    if p == "gpt":
        if not m or is_claude_model_id(m) or is_grok_model_id(m):
            return default_model_for("gpt")
        return m
    # claude
    if not m or is_grok_model_id(m) or is_gpt_model_id(m):
        return default_model_for("claude")
    return m


def provider_for_job(job_id: str | None = None) -> str:
    """Provider that should drive agents for this job.

    Prefer the value stamped on job meta at create time (so a mid-job
    Settings flip does not half-switch a running /retry chain), else the
    live Settings ``agent_provider``.
    """
    if job_id:
        try:
            from modules._common import read_meta

            meta = read_meta(job_id) or {}
            stamped = meta.get("agent_provider")
            if stamped:
                return normalize_provider(str(stamped))
        except Exception:
            pass
    return active_provider()
