import os

from fastapi import APIRouter, HTTPException, Request

from modules.settings_io import (
    get_setting,
    get_settings_view,
    parse_mem_limit,
    update_settings,
)

router = APIRouter()

# Compose labels identify the worker without hard-coding the container name,
# which changes with the project prefix / replica index.
_COMPOSE_PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "hextech_ctf_tool")
_WORKER_FILTERS = {
    "label": [
        f"com.docker.compose.project={_COMPOSE_PROJECT}",
        "com.docker.compose.service=worker",
    ]
}


def _worker_container():
    """The running worker container, or None. Never raises — every caller
    treats "cannot reach docker" as "report it", not "fail the request"."""
    try:
        import docker

        client = docker.from_env()
        found = client.containers.list(filters=_WORKER_FILTERS)
        if found:
            return found[0]
        # Fall back to the conventional name when the labels are absent (a
        # container started by hand rather than by compose).
        return client.containers.get(f"{_COMPOSE_PROJECT}-worker-1")
    except Exception:
        return None


def worker_mem_live() -> dict:
    """What the worker's cgroup ACTUALLY has right now, plus current usage.

    The stored setting and the live value can legitimately diverge — a
    `docker compose up -d` recreate resets the container to the compose/.env
    default — so the UI shows both rather than implying the saved number is
    necessarily in force.
    """
    c = _worker_container()
    if c is None:
        return {"available": False}
    out: dict = {"available": True}
    try:
        hc = c.attrs.get("HostConfig") or {}
        out["limit_bytes"] = int(hc.get("Memory") or 0)
        out["swap_bytes"] = int(hc.get("MemorySwap") or 0)
    except Exception:
        return {"available": False}
    try:
        st = c.stats(stream=False)
        out["usage_bytes"] = int((st.get("memory_stats") or {}).get("usage") or 0)
    except Exception:
        out["usage_bytes"] = None
    return out


def _apply_worker_mem(value: str) -> dict:
    """Apply `value` to the LIVE worker cgroup via the Docker API.

    mem_limit is a container-CREATE property, so unlike every other setting
    this one would otherwise do nothing at all until the operator recreated
    the container. `docker update` changes it in place.

    Refuses a cap BELOW the container's current usage: the kernel would
    OOM-kill inside the container immediately, taking any running job with it.
    """
    want = parse_mem_limit(value)          # raises ValueError on a typo
    c = _worker_container()
    if c is None:
        return {"applied": False, "reason": "worker container not reachable"}

    usage = worker_mem_live().get("usage_bytes")
    if usage and want < usage:
        return {
            "applied": False,
            "reason": (
                f"refused: {value} ({want:,} B) is below the worker's CURRENT "
                f"usage ({usage:,} B). Applying it would OOM-kill the running "
                f"job immediately. Raise the limit, or wait for the job to end."
            ),
        }
    try:
        # memswap == mem on purpose: with mem alone Docker allows swap up to
        # 2x the cap, and slow swap thrash is the state that wedged the VM.
        c.update(mem_limit=want, memswap_limit=want)
    except Exception as e:
        return {"applied": False, "reason": f"{type(e).__name__}: {e}"}
    return {"applied": True, "limit_bytes": want}


@router.get("")
def get_settings():
    view = get_settings_view()
    view["worker_mem_live"] = worker_mem_live()
    return view


@router.put("")
async def put_settings(request: Request):
    """Body is a free-form JSON object. Allowed keys come from settings_io.SCHEMA;
    unknown keys are ignored. Pass null or '' for any key to clear it."""
    try:
        body = await request.json()
        if not isinstance(body, dict):
            body = {}
    except Exception:
        body = {}

    # Validate BEFORE persisting so a typo never reaches disk.
    if body.get("worker_mem_limit") not in (None, ""):
        try:
            parse_mem_limit(body["worker_mem_limit"])
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"worker_mem_limit: {e}")

    view = update_settings(body)

    # Container-create property → push it to the live cgroup too, otherwise
    # saving would appear to work and change nothing until a recreate.
    if "worker_mem_limit" in body:
        view["worker_mem_applied"] = _apply_worker_mem(
            str(get_setting("worker_mem_limit"))
        )
    view["worker_mem_live"] = worker_mem_live()
    return view
