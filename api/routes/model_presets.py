from fastapi import APIRouter, Request

from modules.model_presets import save_store, view

router = APIRouter()


@router.get("")
def get_model_presets():
    """Return all provider-scoped preset stores and UI metadata."""
    return view()


@router.put("")
async def put_model_presets(request: Request):
    """Replace the whole store.

    Version-2 body: ``{"version": 2, "providers": {"claude": {"active":
    ..., "presets": ...}, "grok": ..., "gpt": ...}}``. The UI manages add /
    rename / delete / activate client-side, then PUTs the result. Unknown
    providers and roles are dropped; malformed buckets normalize to empty.

    The legacy flat ``{"active": ..., "presets": ...}`` body remains
    accepted and updates only the provider currently selected in Settings.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    save_store(body)
    return view()
