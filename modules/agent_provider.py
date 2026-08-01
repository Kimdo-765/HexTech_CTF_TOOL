"""Agent-backend selection (Claude Agent SDK vs Grok Build).

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
AGENT_PROVIDERS = ("claude", "grok")

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

# Runtime readiness. True once modules/grok_acp.py can drive main sessions.
GROK_RUNTIME_READY = True

DEFAULT_CLAUDE_MODEL = "claude-opus-4-7"
DEFAULT_GROK_MODEL = "grok-build"

# Effort strings accepted by either backend (union). Unknown values are
# dropped at resolve time so a typo never reaches the CLI/SDK.
VALID_EFFORTS = frozenset({
    "none", "minimal", "low", "medium", "high", "xhigh", "max",
})


def normalize_provider(value: str | None) -> str:
    v = str(value or "").strip().lower()
    return v if v in AGENT_PROVIDERS else "claude"


def get_agent_provider() -> str:
    """Return the active agent backend: ``claude`` or ``grok``."""
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


def active_provider() -> str:
    return get_agent_provider()


def provider_display_name(provider: str | None = None) -> str:
    p = normalize_provider(provider or active_provider())
    return {
        "claude": "Claude (Agent SDK)",
        "grok": "Grok Build (ACP)",
    }.get(p, p)


def has_provider_auth(provider: str | None = None) -> bool:
    p = normalize_provider(provider or active_provider())
    if p == "grok":
        return has_grok_auth()
    return has_claude_auth()


def default_model_for(provider: str | None = None) -> str:
    """Global Settings default model for the given (or active) provider."""
    p = normalize_provider(provider or active_provider())
    if p == "grok":
        return str(get_setting("grok_model") or DEFAULT_GROK_MODEL)
    return str(get_setting("claude_model") or DEFAULT_CLAUDE_MODEL)


def default_effort_for(provider: str | None = None) -> str | None:
    """Global Settings effort for the given (or active) provider, or None."""
    p = normalize_provider(provider or active_provider())
    key = "grok_effort" if p == "grok" else "claude_effort"
    raw = get_setting(key)
    if raw is None or str(raw).strip() == "":
        return None
    s = str(raw).strip().lower()
    return s if s in VALID_EFFORTS else None


def ensure_provider_ready(provider: str | None = None) -> str:
    """Validate that the selected provider can run a job.

    Returns the normalized provider name. Raises ``RuntimeError`` with an
    operator-facing message when auth is missing or (for Grok) the runtime
    adapter is not yet implemented.
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
    return {
        "agent_provider": p,
        "agent_provider_label": provider_display_name(p),
    }


def enrich_job_meta(meta: dict[str, Any], provider: str | None = None) -> dict[str, Any]:
    """In-place stamp of provider fields onto a newly-created job meta dict."""
    meta.update(provider_meta_fields(provider))
    return meta


def is_claude_model_id(model: str | None) -> bool:
    m = (model or "").strip().lower()
    return m.startswith("claude") or m.startswith("anthropic")


def is_grok_model_id(model: str | None) -> bool:
    m = (model or "").strip().lower()
    return m.startswith("grok")


def coerce_model_for_provider(
    model: str | None,
    provider: str | None = None,
) -> str:
    """Force a model id that matches the selected backend.

    When ``agent_provider=grok``, never hand a ``claude-*`` id to Grok
    sessions (or the reverse). Empty / wrong-family ids fall back to that
    provider's Settings default. Used by judge / reviewer / report /
    monitor / forensic-misc so *every* agent role follows the operator's
    provider choice, not a leftover Claude preset.
    """
    p = normalize_provider(provider or active_provider())
    m = (model or "").strip()
    if p == "grok":
        if not m or is_claude_model_id(m):
            return default_model_for("grok")
        return m
    # claude
    if not m or is_grok_model_id(m):
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
