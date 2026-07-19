from fastapi import APIRouter, Request

from modules.model_presets import save_store, view

router = APIRouter()


@router.get("")
def get_model_presets():
    """Return the whole store: {active, presets, configurable_roles}."""
    return view()


@router.put("")
async def put_model_presets(request: Request):
    """Replace the whole store.

    Body: ``{"active": "<name|>", "presets": {"<name>": {"judge": ...,
    "report": ..., "monitor": ...}}}``. The UI manages add / rename / delete
    / activate client-side, then PUTs the result. Unknown roles are dropped;
    an ``active`` that names no preset is cleared; malformed input yields an
    empty store rather than an error.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    save_store(body)
    return view()
