"""Provider-scoped, named per-role model presets.

Claude, Grok and GPT each keep an independent set of named presets and an
independent active selection.  A running role resolves only against the
active preset for its provider, so switching provider never leaks a model id
from another model family into the new job.

Stored in ``/data/model_presets.json`` (mounted on both api + worker), outside
the flat settings schema because this is nested operator-managed data.

Canonical shape (version 2)::

    {
      "version": 2,
      "providers": {
        "claude": {
          "active": "quality",
          "presets": {
            "quality": {"main": "claude-opus-5", "judge": "...", ...}
          }
        },
        "grok": {"active": "", "presets": {}},
        "gpt": {"active": "budget", "presets": {"budget": {...}}}
      }
    }

Version-1 files used the flat ``{"active": ..., "presets": ...}`` shape.
Recognizable model ids determine their provider; inherited/custom-only stores
fall back to the provider currently selected in Settings.  A legacy PUT
updates the currently selected provider only, preserving the other version-2
provider stores.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

MODEL_PRESETS_PATH = Path(
    os.environ.get("MODEL_PRESETS_PATH", "/data/model_presets.json")
)

MODEL_PROVIDERS: tuple[str, ...] = ("claude", "grok", "gpt")

# Roles the operator may pin to a model. Order = UI display order.
CONFIGURABLE_ROLES: tuple[str, ...] = (
    "main", "judge", "reviewer", "recon", "debugger", "triage", "report", "monitor",
)

# Union accepted by all providers. Provider-specific catalogs in the UI show
# the useful subset; the backend accepts the union so saved future model
# capabilities are not destroyed by an older server.
VALID_EFFORTS: tuple[str, ...] = (
    "none", "minimal", "low", "medium", "high", "xhigh", "max",
)

_lock = threading.Lock()


def _empty_provider_store() -> dict[str, Any]:
    return {"active": "", "presets": {}}


def _empty_store() -> dict[str, Any]:
    return {
        "version": 2,
        "providers": {provider: _empty_provider_store() for provider in MODEL_PROVIDERS},
    }


def _provider_name(provider: str | None = None) -> str:
    """Normalize an explicit provider or fall back to live Settings."""
    value = str(provider or "").strip().lower()
    if value in MODEL_PROVIDERS:
        return value
    try:
        from modules.agent_provider import active_provider

        value = str(active_provider() or "").strip().lower()
    except Exception:
        value = "claude"
    return value if value in MODEL_PROVIDERS else "claude"


def _normalize_provider_store(data: Any) -> dict[str, Any]:
    """Validate one provider's ``{active, presets}`` bucket."""
    if not isinstance(data, dict):
        return _empty_provider_store()
    presets_in = data.get("presets") or {}
    presets: dict[str, dict[str, str]] = {}
    if isinstance(presets_in, dict):
        for name, roles in presets_in.items():
            if not isinstance(name, str) or not name.strip():
                continue
            if not isinstance(roles, dict):
                continue
            clean: dict[str, str] = {}
            for role in CONFIGURABLE_ROLES:
                value = roles.get(role, "")
                clean[role] = (
                    str(value).strip() if value not in (None, "") else ""
                )
            effort = roles.get("effort", "")
            effort = (
                str(effort).strip().lower() if effort not in (None, "") else ""
            )
            clean["effort"] = effort if effort in VALID_EFFORTS else ""
            presets[name.strip()] = clean
    active = str(data.get("active") or "").strip()
    if active and active not in presets:
        active = ""
    return {"active": active, "presets": presets}


def _is_provider_store(data: Any) -> bool:
    return isinstance(data, dict) and (
        "providers" in data or data.get("version") == 2
    )


def _infer_legacy_provider(data: dict[str, Any]) -> str | None:
    """Infer a v1 store's provider from known model-id families.

    Most pre-v2 files contain Claude ids and should stay with Claude even if
    Settings happens to be on GPT during the upgrade. Unknown/custom-only or
    completely inherited presets remain ambiguous and fall back to Settings.
    """
    counts = {provider: 0 for provider in MODEL_PROVIDERS}
    presets = data.get("presets") or {}
    if not isinstance(presets, dict):
        return None
    for roles in presets.values():
        if not isinstance(roles, dict):
            continue
        for role in CONFIGURABLE_ROLES:
            model = str(roles.get(role) or "").strip().lower()
            if model.startswith(("claude", "anthropic")):
                counts["claude"] += 1
            elif model.startswith("grok"):
                counts["grok"] += 1
            elif model.startswith(("gpt", "chatgpt", "o1", "o3", "o4")):
                counts["gpt"] += 1
    highest = max(counts.values(), default=0)
    if highest <= 0:
        return None
    winners = [provider for provider, count in counts.items() if count == highest]
    return winners[0] if len(winners) == 1 else None


def _normalize(data: Any, legacy_provider: str | None = None) -> dict[str, Any]:
    """Coerce version-2 or legacy input into the canonical store shape."""
    out = _empty_store()
    if not isinstance(data, dict):
        return out
    if _is_provider_store(data):
        providers = data.get("providers")
        if not isinstance(providers, dict):
            return out
        for provider in MODEL_PROVIDERS:
            out["providers"][provider] = _normalize_provider_store(
                providers.get(provider)
            )
        return out

    # Legacy v1: the UI catalog followed the selected Settings provider, so
    # that provider is the only lossless place to migrate the flat bucket.
    provider = (
        _provider_name(legacy_provider)
        if legacy_provider is not None
        else (_infer_legacy_provider(data) or _provider_name())
    )
    out["providers"][provider] = _normalize_provider_store(data)
    return out


def load_store() -> dict[str, Any]:
    try:
        if MODEL_PRESETS_PATH.exists():
            return _normalize(json.loads(MODEL_PRESETS_PATH.read_text()))
    except Exception:
        pass
    return _empty_store()


def save_store(store: Any) -> dict[str, Any]:
    """Validate and atomically persist the store; return the stored view.

    Version-2 requests replace the complete store. A legacy flat request
    updates only the live provider bucket, so an old browser tab cannot erase
    presets already saved for the other providers.
    """
    if _is_provider_store(store):
        normalized = _normalize(store)
    else:
        provider = _provider_name()
        normalized = load_store()
        migrated = _normalize(store, legacy_provider=provider)
        normalized["providers"][provider] = migrated["providers"][provider]

    MODEL_PRESETS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        tmp = MODEL_PRESETS_PATH.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(normalized, indent=2))
        tmp.replace(MODEL_PRESETS_PATH)
    return normalized


def get_provider_store(provider: str | None = None) -> dict[str, Any]:
    """Return the normalized preset bucket for one provider."""
    selected = _provider_name(provider)
    return load_store()["providers"].get(selected) or _empty_provider_store()


def get_role_model(role: str, provider: str | None = None) -> str:
    """Model configured for ``role`` in the provider's active preset."""
    if role not in CONFIGURABLE_ROLES:
        return ""
    bucket = get_provider_store(provider)
    active = bucket.get("active") or ""
    if not active:
        return ""
    preset = (bucket.get("presets") or {}).get(active) or {}
    value = preset.get(role, "")
    return str(value).strip() if value else ""


def get_preset_effort(provider: str | None = None) -> str:
    """Effort pinned by the provider's active preset, or ``""``."""
    bucket = get_provider_store(provider)
    active = bucket.get("active") or ""
    if not active:
        return ""
    preset = (bucket.get("presets") or {}).get(active) or {}
    effort = str(preset.get("effort", "") or "").strip().lower()
    return effort if effort in VALID_EFFORTS else ""


def resolve_role_model(
    role: str,
    fallback: str,
    provider: str | None = None,
) -> str:
    """Active provider preset's role model, else ``fallback``.

    The result is coerced to the same provider family as a final safety net.
    Supplying ``provider`` is useful for work attached to an existing job;
    otherwise the current Settings provider is used.
    """
    selected = _provider_name(provider)
    try:
        configured = get_role_model(role, selected)
        resolved = configured or fallback
    except Exception:
        resolved = fallback
    try:
        from modules.agent_provider import coerce_model_for_provider

        return coerce_model_for_provider(resolved, selected)
    except Exception:
        return resolved


def view() -> dict[str, Any]:
    """Public UI view, including supported providers/roles/efforts."""
    store = load_store()
    store["model_providers"] = list(MODEL_PROVIDERS)
    store["configurable_roles"] = list(CONFIGURABLE_ROLES)
    store["valid_efforts"] = list(VALID_EFFORTS)
    return store
