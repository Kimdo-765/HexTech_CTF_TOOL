"""Named per-role model presets (operator-configurable).

The operator can save several NAMED presets — each mapping a small set of
non-main agent roles to a model id — and activate one at a time. A job in
flight resolves each configurable role's model against the ACTIVE preset;
an empty/absent entry means "inherit the role's existing default" (judge
follows main; report/monitor keep their cheap constant).

Stored in ``/data/model_presets.json`` (mounted on both api + worker),
deliberately kept OUT of the flat settings.json SCHEMA because it's a
nested structure the ``(key, env, type, default)`` schema can't hold
cleanly.

Shape::

    {
      "active": "max-quality",              # "" = no preset active
      "presets": {
        "max-quality": {"judge": "claude-opus-4-8", "report": "", "monitor": ""},
        "budget":      {"judge": "claude-sonnet-4-6",
                        "report": "claude-haiku-4-5",
                        "monitor": "claude-haiku-4-5"}
      }
    }

Only three roles are configurable — the ones that today either follow main
(``judge``, and via ``resolve_judge_model`` its prejudge / postjudge /
supervise / retry-reviewer family) or sit pinned on a cheap constant
(``report``, ``monitor``). ``main`` is deliberately excluded (that's the
per-job model picker / global ``claude_model`` setting); ``recon`` is
excluded because it shares its spawner's model for cache-prefix alignment.
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

# Roles the operator may pin to a model. Order = UI display order.
CONFIGURABLE_ROLES: tuple[str, ...] = ("judge", "report", "monitor")

_lock = threading.Lock()


def _empty_store() -> dict[str, Any]:
    return {"active": "", "presets": {}}


def _normalize(data: Any) -> dict[str, Any]:
    """Coerce arbitrary input into the canonical store shape.

    Drops malformed preset names / role maps, keeps only CONFIGURABLE_ROLES
    (each a stripped string; "" = inherit), and clears an ``active`` that
    doesn't name a surviving preset.
    """
    if not isinstance(data, dict):
        return _empty_store()
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
                v = roles.get(role, "")
                clean[role] = str(v).strip() if v not in (None, "") else ""
            presets[name.strip()] = clean
    active = str(data.get("active") or "").strip()
    if active and active not in presets:
        active = ""
    return {"active": active, "presets": presets}


def load_store() -> dict[str, Any]:
    try:
        if MODEL_PRESETS_PATH.exists():
            return _normalize(json.loads(MODEL_PRESETS_PATH.read_text()))
    except Exception:
        pass
    return _empty_store()


def save_store(store: Any) -> dict[str, Any]:
    """Validate + atomically persist the whole store; return the stored view."""
    norm = _normalize(store)
    MODEL_PRESETS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        tmp = MODEL_PRESETS_PATH.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(norm, indent=2))
        tmp.replace(MODEL_PRESETS_PATH)
    return norm


def get_role_model(role: str) -> str:
    """Model id configured for ``role`` in the ACTIVE preset.

    Returns "" when there's no active preset, the role is unset, or the role
    isn't configurable — the caller then keeps its existing default.
    """
    if role not in CONFIGURABLE_ROLES:
        return ""
    store = load_store()
    active = store.get("active") or ""
    if not active:
        return ""
    preset = (store.get("presets") or {}).get(active) or {}
    v = preset.get(role, "")
    return str(v).strip() if v else ""


def resolve_role_model(role: str, fallback: str) -> str:
    """Active preset's model for ``role``, else ``fallback`` (the role's
    existing default behavior). Never raises."""
    try:
        m = get_role_model(role)
        if m:
            return m
    except Exception:
        pass
    return fallback


def view() -> dict[str, Any]:
    """Public view for the UI: the store plus the configurable-role list."""
    store = load_store()
    store["configurable_roles"] = list(CONFIGURABLE_ROLES)
    return store
