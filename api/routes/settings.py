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
        ms = st.get("memory_stats") or {}
        out["usage_bytes"] = int(ms.get("usage") or 0)
        # `usage` (cgroup memory.current) counts RECLAIMABLE page cache, which
        # on a job that just read a 160 MB bundle is most of it. Sizing a cap
        # against that number refuses perfectly safe values. What actually
        # cannot be reclaimed under pressure is anon + slab — that is the floor
        # a cap has to clear.
        _s = ms.get("stats") or {}
        anon = int(_s.get("anon") or _s.get("rss") or 0)
        slab = int(_s.get("slab") or 0)
        out["unreclaimable_bytes"] = (anon + slab) or None
    except Exception:
        out["usage_bytes"] = None
        out["unreclaimable_bytes"] = None
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

    live = worker_mem_live()
    floor = live.get("unreclaimable_bytes") or live.get("usage_bytes")
    # 1.5x headroom, not ">= floor". A cap set AT the current footprint passes a
    # bare `want < usage` test and then OOM-kills on the very next allocation —
    # the exact outcome this gate claims to prevent, while reporting success.
    if floor and want < int(floor * 1.5):
        which = ("unreclaimable (anon+slab)"
                 if live.get("unreclaimable_bytes") else "current usage")
        return {
            "applied": False,
            "reason": (
                f"refused: {value} ({want:,} B) leaves no headroom over the "
                f"worker's {which} footprint ({floor:,} B). A cap at or just "
                f"above the live footprint OOM-kills the running job on its "
                f"next allocation. Use at least {int(floor * 1.5):,} B, or "
                f"wait for the job to end."
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
    # Live cgroup sample for the Settings "worker memory" row. Cheap enough
    # on GET that we always attach it; a docker-socket miss returns
    # {available: false} without raising.
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
    # The Docker SDK calls below are BLOCKING and `c.stats(stream=False)` costs
    # 1-2 s (the daemon takes two samples). On the single uvicorn loop that
    # froze every route and every SSE stream for seconds on each save, so the
    # blocking half runs in a worker thread.
    from starlette.concurrency import run_in_threadpool
    return await run_in_threadpool(_put_settings_sync, body)


def _put_settings_sync(body: dict):
    """Blocking half of PUT /api/settings — runs in the threadpool."""
    # Validate BEFORE persisting so a typo never reaches disk.
    if body.get("worker_mem_limit") not in (None, ""):
        try:
            parse_mem_limit(body["worker_mem_limit"])
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"worker_mem_limit: {e}")

    try:
        view = update_settings(body)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Container-create property → push it to the live cgroup too, otherwise
    # saving would appear to work and change nothing until a recreate.
    if "worker_mem_limit" in body:
        view["worker_mem_applied"] = _apply_worker_mem(
            str(get_setting("worker_mem_limit"))
        )
    view["worker_mem_live"] = worker_mem_live()
    return view
