import os
import re
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, HTTPException, Request

from modules.settings_io import (
    get_setting,
    get_settings_view,
    parse_mem_limit,
    update_settings,
)

router = APIRouter()

# Compose labels identify the worker slots without hard-coding container names.
_COMPOSE_PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "hextech_ctf_tool")
_PROJECT_FILTER = {"label": [f"com.docker.compose.project={_COMPOSE_PROJECT}"]}
# `worker-1`, `worker-2`, ... and bare `worker` for a pre-split compose file.
# Anchored so it can never pull in `worker-something-else`.
_WORKER_SERVICE_RE = re.compile(r"^worker(?:-\d+)?$")

# Fraction of VM RAM the worker slots may claim in TOTAL. The rest is kernel +
# dockerd + api + redis + the challenge containers the agent spawns, which are
# SIBLING cgroups (worker/docker_memguard.sh caps each at CHAL_CONTAINER_MEM,
# default 2g) and are therefore NOT charged to any slot.
_TOTAL_BUDGET_FRACTION = 0.70


def _host_mem_total() -> int:
    """Total RAM of the VM in bytes, or 0 if unreadable.

    /proc/meminfo inside a container reports the HOST's memory, not the
    container's cgroup limit — which is exactly what is wanted here: the
    question is whether the SUM of slot caps fits the machine.
    """
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
    except Exception:
        pass
    return 0


def _worker_containers() -> list:
    """Every running worker SLOT container, ordered by service name.

    Returns a LIST, not a single container. Under the slot split there are N of
    them and any code that picks one is either wrong or lying: the pre-split
    version filtered on `com.docker.compose.service=worker` and returned
    `found[0]`. That filter now matches nothing, but its name fallback
    (`get("<project>-worker-1")`) still resolves — because slot 1 pins exactly
    that container_name — so the old code would have reported ONE slot's cap as
    "the worker's" and silently ignored the others.

    Never raises — every caller treats "cannot reach docker" as "report it",
    not "fail the request".
    """
    try:
        import docker

        client = docker.from_env()
        found = []
        for c in client.containers.list(filters=_PROJECT_FILTER):
            svc = (c.labels or {}).get("com.docker.compose.service", "")
            if _WORKER_SERVICE_RE.match(svc):
                found.append((svc, c))
        if found:
            found.sort(key=lambda t: t[0])
            return [c for _, c in found]
        # Fall back to conventional names when the labels are absent (started
        # by hand rather than by compose). Probe a bounded range, not just -1.
        out = []
        for i in range(1, 9):
            try:
                out.append(client.containers.get(f"{_COMPOSE_PROJECT}-worker-{i}"))
            except Exception:
                break
        return out
    except Exception:
        return []


def _slot_label(c) -> str:
    """Human-facing slot id: the WORKER_SLOT env value when present, else the
    compose service name, else the container name."""
    try:
        env = (c.attrs.get("Config") or {}).get("Env") or []
        for kv in env:
            if kv.startswith("WORKER_SLOT="):
                v = kv.split("=", 1)[1].strip()
                if v:
                    return v
    except Exception:
        pass
    return (c.labels or {}).get("com.docker.compose.service") or getattr(c, "name", "?")


def _slot_mem(c) -> dict:
    """Live cgroup facts for one slot. `available` False on any docker error."""
    out: dict = {"name": getattr(c, "name", "?"), "slot": _slot_label(c)}
    try:
        hc = c.attrs.get("HostConfig") or {}
        out["limit_bytes"] = int(hc.get("Memory") or 0)
        out["swap_bytes"] = int(hc.get("MemorySwap") or 0)
    except Exception:
        out["available"] = False
        return out
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
    out["available"] = True
    return out


def worker_mem_live() -> dict:
    """What the worker slots' cgroups ACTUALLY have right now, plus usage.

    The stored setting and the live values can legitimately diverge — a
    `docker compose up -d` recreate resets each container to the compose/.env
    default — so the UI shows both rather than implying the saved number is
    necessarily in force.

    `limit_bytes` is the PER-SLOT cap (what the setting controls);
    `total_limit_bytes` and `usage_bytes` are sums across slots. When slots
    disagree on their cap, `limit_bytes` reports the SMALLEST and
    `limits_uniform` is False — the smallest is the one that will OOM first,
    so it is the honest single number to show.
    """
    cs = _worker_containers()
    if not cs:
        return {"available": False}
    # Sample slots CONCURRENTLY. `_slot_mem` spends its time inside
    # `c.stats(stream=False)`, which costs 1-2 s because the daemon takes two
    # samples to compute a delta — so the serial version cost 1-2 s PER SLOT.
    # At two slots that was ~4 s and merely annoying; at twelve it was 24 s,
    # measured, and since this runs on both GET and PUT /api/settings the Save
    # button sat there long enough to read as broken.
    #
    # These are independent daemon round-trips, so twelve of them take about as
    # long as one. api/routes/containers.py already samples its stats this way;
    # this is the same fix, applied to the module that missed it.
    if len(cs) > 1:
        with ThreadPoolExecutor(max_workers=min(16, len(cs))) as ex:
            slots = list(ex.map(_slot_mem, cs))
    else:
        slots = [_slot_mem(c) for c in cs]
    ok = [s for s in slots if s.get("available")]
    if not ok:
        return {"available": False}

    limits = [s.get("limit_bytes") or 0 for s in ok]
    usages = [s.get("usage_bytes") for s in ok]
    unrec = [s.get("unreclaimable_bytes") for s in ok]
    return {
        "available": True,
        "slots": slots,
        "slot_count": len(ok),
        "limit_bytes": min(limits) if limits else 0,
        "limits_uniform": len(set(limits)) <= 1,
        "total_limit_bytes": sum(limits),
        "usage_bytes": sum(u for u in usages if u) or None,
        "unreclaimable_bytes": sum(u for u in unrec if u) or None,
        "host_mem_total_bytes": _host_mem_total(),
    }


def _apply_worker_mem(value: str) -> dict:
    """Apply `value` as the PER-SLOT cap to every live worker cgroup.

    mem_limit is a container-CREATE property, so unlike every other setting
    this one would otherwise do nothing at all until the operator recreated the
    containers. `docker update` changes it in place.

    Two gates, both learned from real incidents:

      * Per slot — refuse a cap below that slot's current footprint. The
        kernel would OOM-kill inside it immediately, taking any running job.
      * In total — refuse when N x value would not fit the VM. This gate is
        new with the slot split and it is the one that matters: the value is
        now multiplied by the slot count, so a number that was safe for ONE
        container (8g) becomes 16 GiB inside a 15.99 GiB VM. That is precisely
        the unbounded-memory condition that froze WSL on 2026-07-29 and
        2026-08-01.
    """
    want = parse_mem_limit(value)          # raises ValueError on a typo
    cs = _worker_containers()
    if not cs:
        return {"applied": False, "reason": "no worker slot container reachable"}

    # --- total-budget gate ---------------------------------------------------
    host = _host_mem_total()
    total = want * len(cs)
    if host and total > int(host * _TOTAL_BUDGET_FRACTION):
        budget = int(host * _TOTAL_BUDGET_FRACTION)
        return {
            "applied": False,
            "reason": (
                f"refused: {value} ({want:,} B) x {len(cs)} slots = "
                f"{total:,} B, over the {int(_TOTAL_BUDGET_FRACTION * 100)}% "
                f"share of this VM's {host:,} B that worker slots may claim "
                f"({budget:,} B). The rest is kernel, dockerd, api, redis and "
                f"the challenge containers the agent spawns as siblings. "
                f"Per-slot maximum here is {budget // len(cs):,} B."
            ),
        }

    # --- per-slot headroom gate ---------------------------------------------
    # 1.5x headroom, not ">= floor". A cap set AT the current footprint passes a
    # bare `want < usage` test and then OOM-kills on the very next allocation —
    # the exact outcome this gate claims to prevent, while reporting success.
    #
    # Sampled concurrently, for the same reason worker_mem_live is: each
    # `_slot_mem` spends 1-2 s inside `c.stats(stream=False)`. This is the
    # SECOND such loop on the PUT path — parallelising only the other one left
    # Save still blocking ~23 s, so the commit that claimed to fix the Save
    # button had fixed half of it.
    #
    # The generator was lazy, so it stopped sampling at the first refusal; the
    # list is eager and samples all 12. That costs one extra ~2 s round of
    # already-parallel calls in the refusal case and saves ~21 s in every other
    # case, including every successful save.
    if len(cs) > 1:
        with ThreadPoolExecutor(max_workers=min(16, len(cs))) as _ex:
            _sampled = list(_ex.map(_slot_mem, cs))
    else:
        _sampled = [_slot_mem(c) for c in cs]
    for s in _sampled:
        if not s.get("available"):
            continue
        floor = s.get("unreclaimable_bytes") or s.get("usage_bytes")
        if floor and want < int(floor * 1.5):
            which = ("unreclaimable (anon+slab)"
                     if s.get("unreclaimable_bytes") else "current usage")
            return {
                "applied": False,
                "reason": (
                    f"refused: {value} ({want:,} B) leaves no headroom over "
                    f"slot {s.get('slot')}'s {which} footprint ({floor:,} B). "
                    f"A cap at or just above the live footprint OOM-kills that "
                    f"slot's running job on its next allocation. Use at least "
                    f"{int(floor * 1.5):,} B, or wait for the job to end."
                ),
            }

    applied, failed = [], []
    for c in cs:
        try:
            # memswap == mem on purpose: with mem alone Docker allows swap up
            # to 2x the cap, and slow swap thrash is the state that wedged the
            # VM.
            c.update(mem_limit=want, memswap_limit=want)
            applied.append(getattr(c, "name", "?"))
        except Exception as e:
            failed.append(f"{getattr(c, 'name', '?')}: {type(e).__name__}: {e}")
    if failed:
        # Partial application is reported as a failure with the detail, not
        # swallowed — an operator who sees "applied" must be able to trust that
        # EVERY slot took the new cap.
        return {
            "applied": False,
            "limit_bytes": want,
            "applied_to": applied,
            "reason": "; ".join(failed),
        }
    return {
        "applied": True,
        "limit_bytes": want,
        "slot_count": len(applied),
        "total_limit_bytes": want * len(applied),
        "applied_to": applied,
    }


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
    if body.get("worker_slot_mem") not in (None, ""):
        try:
            parse_mem_limit(body["worker_slot_mem"])
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"worker_slot_mem: {e}")

    try:
        view = update_settings(body)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Container-create property → push it to the live cgroup too, otherwise
    # saving would appear to work and change nothing until a recreate.
    if "worker_slot_mem" in body:
        view["worker_mem_applied"] = _apply_worker_mem(
            str(get_setting("worker_slot_mem"))
        )
    view["worker_mem_live"] = worker_mem_live()
    return view
