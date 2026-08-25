"""Container inventory + manual cleanup for the Containers tab.

WHY THIS EXISTS
Containers the AGENT starts from Bash (`docker run ...` for a challenge's own
stack) are siblings of the worker with no lifecycle owner. `_hard_stop_job`
reaps a job's siblings by the `hextech_ctf_tool_job_id` LABEL, which the
orchestrator sets on the containers IT spawns — but a container the agent
starts by hand carries no such label, so nothing ever removes it. Measured
2026-08-02: three containers from job fd844946db78 were still running 11-19 h
after that job had finished and its record had been deleted (protoss_na,
protoss_fd844946, db_fd844946 — 451 MiB between them, each holding a 2 GiB
cgroup reservation ceiling). This gives the operator eyes on that and a way to
clear it by hand.

SAFETY IS THE HARD PART, not the listing. Three rules, in decreasing severity:

  1. The api's OWN container can never be deleted. The DELETE handler runs
     INSIDE it, so removing it means the response never reaches the browser and
     the UI dies mid-click with no explanation. Refused at the route.
  2. A worker slot may be serving a job. Deleting it kills that job with no
     artifacts. Not blocked -- an operator clearing a wedged slot is a real
     need -- but the response says which job dies, and the UI confirms twice.
  3. A challenge container may belong to the job running RIGHT NOW. Those
     carry no label, so they are identified heuristically (name contains a
     running job's id, or created after a running job started). Surfaced as a
     warning, never as a block: a false positive must not stop a cleanup.
"""
from __future__ import annotations

import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query
from starlette.concurrency import run_in_threadpool

from api.storage import JOBS_DIR

router = APIRouter()

_COMPOSE_PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "hextech_ctf_tool")
_JOB_LABEL = "hextech_ctf_tool_job_id"
_ROLE_LABEL = "hextech_ctf_tool_role"

# Compose sets a container's hostname to its own short id unless the service
# declares `hostname:`. Verified against the live api container 2026-08-02
# (hostname f1f06c7e8a11 == short id f1f06c7e8a11). The compose-label match
# below is the fallback, because a WRONG self-id means the refuse-to-delete-
# self guard silently never fires -- the one failure this module must not have.
_SELF_HOSTNAME = socket.gethostname()


def _client():
    import docker

    return docker.from_env()


def _labels(c) -> dict:
    return getattr(c, "labels", None) or {}


def _svc(c) -> str:
    lab = _labels(c)
    if lab.get("com.docker.compose.project") != _COMPOSE_PROJECT:
        return ""
    return lab.get("com.docker.compose.service") or ""


def _is_self(c) -> bool:
    """True for the container this process runs in."""
    cid = getattr(c, "id", "") or ""
    if _SELF_HOSTNAME and cid.startswith(_SELF_HOSTNAME):
        return True
    return _svc(c) == "api"


def _image_name(c) -> str:
    """Best available image name, never raising.

    docker-py's `Container.image` is a property that calls the daemon and
    raises ImageNotFound if the image was pruned while the container lives on.
    `Config.Image` is recorded on the container itself and survives that.
    """
    try:
        img = c.image
        if img is not None and img.tags:
            return img.tags[0]
    except Exception:
        pass
    cfg = (c.attrs.get("Config") or {}) if getattr(c, "attrs", None) else {}
    return cfg.get("Image") or (c.attrs.get("Image") or "")[:19]


def _is_core_service(svc: str) -> bool:
    """True only for the LONG-LIVED stack services.

    "has a compose service label" is NOT the same as "is core", and treating
    them as equal was wrong: runner / decompiler / forensic / misc are
    `profiles: ["tools"]` services, so compose builds their images and the
    per-job containers spawned from them inherit
    `com.docker.compose.service=decompiler`. Two such containers (from jobs
    a15ff70a6ed5 and ef8c5eb95d15, dating to June and July) were being reported
    as `core` — i.e. as part of the stack the operator must not touch — when
    they are in fact abandoned per-job sandboxes, exactly what this tab is for.
    """
    return svc in ("api", "redis") or svc.startswith("worker")


def _category(c) -> str:
    """What KIND of container this is — the field the operator actually sorts
    on when deciding what is safe to remove."""
    lab = _labels(c)
    if _is_core_service(_svc(c)):
        return "core"                       # api / redis / worker-N
    if lab.get(_ROLE_LABEL) == "tunnel":
        return "tunnel"
    if lab.get(_JOB_LABEL):
        return "sandbox"                    # runner / decompiler / forensic / misc
    return "challenge"                      # agent-started; nothing reaps these


# Job ids are `uuid4().hex[:12]`, and agents habitually name a container after
# the job — either the full id (`chal_e994cf7cad22`) or its first 8
# (`protoss_fd844946`, `db_fd844946`). That is the ONLY attribution signal an
# unlabelled container has: measured 2026-08-02, none of the orphans carried a
# JOB_ID env var or a bind mount naming /data/jobs/<id>, and the jobs that made
# them had already been deleted, so their run.log was gone too.
_HEX_RUN = re.compile(r"(?<![0-9a-f])([0-9a-f]{8,12})(?![0-9a-f])")


def _job_from_name(name: str) -> str | None:
    """Job id guessed from a container name, or None.

    Explicitly a GUESS — it is surfaced as such rather than as fact, because an
    8-hex run is short enough to occur by accident (a container called
    `deadbeef` would match). The label set by worker/docker_memguard.sh is the
    authoritative source; this only exists for containers created before that
    labelling shipped.
    """
    for m in _HEX_RUN.finditer((name or "").lower()):
        tok = m.group(1)
        if len(tok) in (8, 12):
            return tok
    return None


def _running_jobs() -> list[dict]:
    """Jobs the UI would show as live, with just what the heuristics need."""
    import json

    out = []
    if not JOBS_DIR.exists():
        return out
    for d in JOBS_DIR.iterdir():
        f = d / "meta.json"
        if not f.is_file():
            continue
        try:
            m = json.loads(f.read_text())
        except Exception:
            continue
        if m.get("status") in ("running", "queued"):
            out.append({"id": m.get("id") or d.name,
                        "started_at": m.get("started_at") or "",
                        "worker_slot": str(m.get("worker_slot") or "")})
    return out


def _age_days(created: str) -> int | None:
    """Whole days since creation, or None. The single most useful column for
    triage: a container from six weeks ago is unambiguously garbage no matter
    which job made it."""
    t = _parse_ts(created)
    if not t:
        return None
    try:
        return max(0, (datetime.now(timezone.utc) - t).days)
    except Exception:
        return None


def _parse_ts(s: str):
    try:
        return datetime.fromisoformat((s or "").replace("Z", "+00:00"))
    except Exception:
        return None


def _stats_of(c) -> dict:
    """Memory + CPU for ONE running container.

    A non-running container is skipped by the caller: docker returns
    `memory_stats: {}` and a `cpu_stats` WITHOUT `system_cpu_usage` for it
    (verified), so every derived figure would be a KeyError or a divide by
    zero. Every field access here is still guarded — a container can exit
    between the list call and this one.
    """
    out: dict = {"mem_usage": None, "mem_limit": None, "mem_pct": None,
                 "cpu_pct": None}
    try:
        s = c.stats(stream=False)
    except Exception:
        return out
    ms = s.get("memory_stats") or {}
    usage = ms.get("usage")
    limit = ms.get("limit")
    if usage:
        # `usage` counts reclaimable page cache; anon+slab is what actually
        # cannot be freed under pressure. Report both so a big number that is
        # only cache does not read as a container about to OOM.
        st = ms.get("stats") or {}
        anon = st.get("anon") or st.get("rss") or 0
        slab = st.get("slab") or 0
        out["mem_usage"] = int(usage)
        out["mem_unreclaimable"] = int(anon) + int(slab) or None
    if limit:
        out["mem_limit"] = int(limit)
        if usage:
            out["mem_pct"] = round(100.0 * usage / limit, 1)

    cpu = s.get("cpu_stats") or {}
    pre = s.get("precpu_stats") or {}
    try:
        d_cpu = (cpu["cpu_usage"]["total_usage"]
                 - pre["cpu_usage"]["total_usage"])
        d_sys = cpu["system_cpu_usage"] - pre["system_cpu_usage"]
        n = cpu.get("online_cpus") or len(
            (cpu["cpu_usage"].get("percpu_usage") or [])) or 1
        if d_sys > 0 and d_cpu >= 0:
            out["cpu_pct"] = round(100.0 * d_cpu / d_sys * n, 1)
    except (KeyError, TypeError, ZeroDivisionError):
        pass          # first sample, or a container that is not running
    return out


def _list_sync(with_sizes: bool) -> dict:
    try:
        client = _client()
    except Exception as e:
        raise HTTPException(status_code=503,
                            detail=f"docker socket not reachable: {e}")

    try:
        containers = client.containers.list(all=True)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"docker list failed: {e}")

    # Sizes come from ONE API call for every container rather than per
    # container. Measured 0.13 s for 19 containers, so it is always on.
    sizes: dict[str, dict] = {}
    if with_sizes:
        try:
            for row in client.api.containers(all=True, size=True):
                sizes[row.get("Id", "")] = {
                    "size_rw": row.get("SizeRw"),
                    "size_rootfs": row.get("SizeRootFs"),
                }
        except Exception:
            pass

    running = [c for c in containers if getattr(c, "status", "") == "running"]
    stats: dict[str, dict] = {}
    if running:
        # ~1 s each sequentially (docker takes two samples); in parallel the
        # whole set costs about one sample. Route already runs off the loop.
        with ThreadPoolExecutor(max_workers=min(16, len(running))) as ex:
            for c, st in zip(running, ex.map(_stats_of, running)):
                stats[c.id] = st

    jobs = _running_jobs()
    job_ids = [j["id"] for j in jobs]
    earliest = min((_parse_ts(j["started_at"]) for j in jobs
                    if _parse_ts(j["started_at"])), default=None)

    out = []
    for c in containers:
        lab = _labels(c)
        cat = _category(c)
        svc = _svc(c)
        created = (c.attrs.get("Created") or "")[:19]
        item = {
            "id": (c.id or "")[:12],
            "name": c.name,
            # `c.image` is a PROPERTY that hits the daemon and raises
            # ImageNotFound when the image has been pruned out from under a
            # still-existing container — precisely the state a long-abandoned
            # challenge container ends up in, i.e. the rows this tab exists
            # for. Fall back to the id recorded on the container itself.
            "image": _image_name(c),
            "state": c.status,
            "status": (c.attrs.get("State") or {}).get("Status") or c.status,
            "created": created,
            "category": cat,
            "compose_service": svc or None,
            # Attribution, with its PROVENANCE — an operator deleting things
            # needs to know whether "job X" is a fact or a guess off the name.
            "job_id": lab.get(_JOB_LABEL) or _job_from_name(c.name),
            "job_source": ("label" if lab.get(_JOB_LABEL)
                           else ("name" if _job_from_name(c.name) else None)),
            "age_days": _age_days(c.attrs.get("Created") or ""),
            "mem_cap": ((c.attrs.get("HostConfig") or {}).get("Memory") or 0)
                       or None,
            "is_self": _is_self(c),
            **stats.get(c.id, {}),
            **sizes.get(c.id, {}),
        }

        # --- why deleting this might hurt -----------------------------------
        warn = None
        if item["is_self"]:
            warn = ("this is the api container serving this page — deleting it "
                    "would kill the UI mid-request")
        elif svc.startswith("worker") and _is_core_service(svc):
            on_slot = [j["id"] for j in jobs
                       if j["worker_slot"] and svc == f"worker-{j['worker_slot']}"]
            # Expose the mapping, don't just narrate it. A worker slot carries
            # no job LABEL (the label rides the challenge containers the agent
            # spawns), so `job_id` above is null for every slot and the
            # dashboard had no way to say which job a slot is busy with. The
            # answer is already computed here for the warning; publishing it as
            # a field beats making the UI re-derive slot->job from a second
            # /api/jobs fetch and a string match on the service name.
            item["slot_job_id"] = on_slot[0] if on_slot else None
            warn = (f"worker slot — currently running job {on_slot[0]}; "
                    f"deleting it kills that job"
                    if on_slot else
                    "worker slot — idle now, but a queued job can land on it")
        elif svc == "redis" and _is_core_service(svc):
            warn = "the job queue — deleting it loses queued jobs"
        elif (item["job_source"] == "label" and item["job_id"]
              and item["job_id"] in job_ids):
            warn = f"sandbox container for RUNNING job {item['job_id']}"
        elif cat == "challenge":
            # Agent-started containers carry no label, so this is a guess.
            # Deliberately a warning, never a block: a false positive must not
            # stop the operator from clearing real garbage.
            hit = next((j for j in job_ids
                        if j[:8] and j[:8] in (c.name or "")), None)
            if hit:
                warn = f"name matches RUNNING job {hit} — probably in use"
            elif earliest and _parse_ts(c.attrs.get("Created") or ""):
                if _parse_ts(c.attrs.get("Created")) >= earliest:
                    warn = ("started after the current job began — may belong "
                            "to it")
        item["warn"] = warn
        item["protected"] = bool(item["is_self"])
        out.append(item)

    order = {"challenge": 0, "sandbox": 1, "tunnel": 2, "core": 3}
    out.sort(key=lambda x: (order.get(x["category"], 9), x["name"] or ""))
    return {
        "containers": out,
        "running_jobs": job_ids,
        "counts": {k: sum(1 for x in out if x["category"] == k)
                   for k in ("challenge", "sandbox", "tunnel", "core")},
        "host_mem": _host_mem(),
    }


def _host_mem() -> dict:
    """Host RAM, for the dashboard's total-usage ring.

    /proc/meminfo inside a container reports the HOST's memory rather than this
    container's cgroup limit, which is what the ring wants: the question is how
    much of the MACHINE is gone, not how much of the api container.

    `used` is derived from MemAvailable, not from `total - free`. MemAvailable
    is the kernel's own estimate of what a new allocation could get, so page
    cache — which is reclaimable and routinely fills all remaining RAM — does
    not read as consumption. `total - free` would show a healthy machine at 95%
    and mean nothing, which is the same "warning colour is the normal state"
    failure the liveness chip was removed for (bc55640).

    Returned as bytes with `available: false` when unreadable, so the frontend
    can hide the ring rather than draw a ring of zeroes.
    """
    total = avail = 0
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1]) * 1024
                elif line.startswith("MemAvailable:"):
                    avail = int(line.split()[1]) * 1024
                if total and avail:
                    break
    except Exception:
        pass
    if not total:
        return {"available": False}
    return {
        "available": True,
        "total_bytes": total,
        "available_bytes": avail,
        "used_bytes": max(0, total - avail),
        "used_pct": round(100.0 * (total - avail) / total, 1) if avail else None,
    }


@router.get("")
async def list_containers(sizes: bool = Query(True)):
    """Every container on the daemon, categorised, with live memory/CPU/disk.

    Blocking docker calls all the way down (`stats` alone is ~1 s per
    container), so the whole thing runs off the event loop — the same lesson
    api/routes/settings.py learned when a 1-2 s stats call froze every route
    and every SSE stream for the duration.
    """
    return await run_in_threadpool(_list_sync, sizes)


# --------------------------------------------------------------- per-process
#
# TWO SOURCES, PICKED BY TRUST — not by capability.
#
# `docker top` asks the DAEMON to run ps on the host and filter to the
# container's pids. Nothing inside the container participates, so it is safe
# against any image. Its cost is precision: ps `%CPU` is cputime/elapsed over
# the process's WHOLE LIFE. Measured 2026-08-10 against a process pinned at one
# full core: ps said 34.4% while the process was using 99%. Sampling ps twice
# does not fix it either — ps exposes cumulative cpu time only in whole seconds
# (`times`), so a 1 s window quantises every process to 0% or ~99%; measured
# against a steady 30% load the two-sample figures were 0.0 / 49.8 / 33.2 /
# 0.0 / 49.8. Reconstructing finer cpu time from `%CPU * etimes` looks accurate
# on a young process (29.7-32.2% on that same 30% load) and then falls apart on
# an old one, because %CPU is rounded to 0.1%: for a 2394 s process the implied
# error bound over a 2 s window is +-119%. Workers run for hours. So: for a
# container we do not trust, CPU is reported as a LIFETIME AVERAGE and labelled
# as one, because that is the only honest number this source can produce.
#
# Reading /proc inside the container gives cpu time in clock ticks (10 ms), so
# a 1 s window is accurate regardless of process age — measured 31.1% against
# that same 30% load, and 0.0% for an idle 40-minute-old worker. But it needs
# `exec`, which RUNS A PROCESS INSIDE THE CONTAINER, and the container then
# supplies every byte we parse into the operator's dashboard.
#
# That is only acceptable where we own the image AND nothing untrusted runs in
# it, which is `core` (api / redis / worker-N) and nothing else. `challenge` is
# an arbitrary agent-started image — the whole reason this tab exists. And
# `sandbox` is NOT safe either despite being our image: the agent has root
# there and runs challenge binaries, so `/bin/sh` itself can have been replaced
# by the time we call it.
_PROC_SH = r"""getconf CLK_TCK 2>/dev/null || echo 100
getconf PAGESIZE 2>/dev/null || echo 4096
for p in /proc/[0-9]*; do
  [ -r "$p/stat" ] || continue
  printf '%s\t' "${p#/proc/}"
  tr '\0' ' ' < "$p/cmdline" 2>/dev/null
  printf '\t'
  cat "$p/stat" 2>/dev/null || echo
done"""

# /proc/<pid>/stat, counting from the field AFTER the ")" that closes comm.
# comm can contain spaces and parentheses, so the split is on the LAST ")".
_ST_STATE, _ST_PPID = 0, 1
_ST_UTIME, _ST_STIME = 11, 12
_ST_THREADS, _ST_RSS_PAGES = 17, 21


def _parse_proc_dump(out: str) -> tuple[int, int, dict]:
    lines = out.splitlines()
    try:
        hz = int(lines[0].strip()) or 100
        page = int(lines[1].strip()) or 4096
    except (IndexError, ValueError):
        return 100, 4096, {}
    procs: dict[str, dict] = {}
    for line in lines[2:]:
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        pid, cmdline, stat = parts[0], parts[1], parts[2]
        try:
            comm = stat.split("(", 1)[1].rsplit(")", 1)[0]
            f = stat.rsplit(")", 1)[1].split()
            procs[pid] = {
                "pid": int(pid),
                "ppid": int(f[_ST_PPID]),
                "state": f[_ST_STATE],
                "threads": int(f[_ST_THREADS]),
                "rss": int(f[_ST_RSS_PAGES]) * page,
                "ticks": int(f[_ST_UTIME]) + int(f[_ST_STIME]),
                # A kernel thread has an empty cmdline; its comm is the only
                # name it has, and [brackets] is how ps renders that.
                "cmd": cmdline.strip() or "[%s]" % comm,
            }
        except (IndexError, ValueError):
            continue
    return hz, page, procs


def _procs_via_exec(c, window: float) -> dict:
    """Two /proc samples `window` apart. Raises on any exec trouble."""
    def sample():
        res = c.exec_run(["sh", "-c", _PROC_SH])
        if res.exit_code != 0:
            raise RuntimeError("exec exit %s" % res.exit_code)
        return _parse_proc_dump(res.output.decode("utf-8", "replace")), time.time()

    (hz, page, first), t0 = sample()
    time.sleep(window)
    (hz, page, second), t1 = sample()
    dt = max(t1 - t0, 1e-6)

    rows = []
    for pid, p in second.items():
        prev = first.get(pid)
        # A process that appeared DURING the window has no baseline. Reporting
        # its lifetime ticks over our short window would read as a huge spike,
        # so its cpu is unknown rather than wrong.
        cpu = None
        if prev is not None:
            cpu = round(100.0 * ((p["ticks"] - prev["ticks"]) / hz) / dt, 1)
            if cpu < 0:            # pid reused inside the window
                cpu = None
        rows.append({k: p[k] for k in
                     ("pid", "ppid", "state", "threads", "rss", "cmd")}
                    | {"cpu_pct": cpu, "new": prev is None})
    return {"source": "proc", "cpu_is_lifetime_avg": False,
            "window_s": round(dt, 2), "clk_tck": hz, "page_size": page,
            "processes": rows}


# Asking ps for `pid` first keeps the daemon's own pid-filtering happy, and
# `args` last keeps the command (the only field with spaces) unambiguous to
# split on.
_TOP_ARGS = "-eo pid,ppid,user,pcpu,pmem,rss,etime,args"


def _procs_via_top(c) -> dict:
    t = c.top(ps_args=_TOP_ARGS)
    titles = t.get("Titles") or []
    ix = {n: i for i, n in enumerate(titles)}

    def cell(row, name, cast=None, default=None):
        i = ix.get(name)
        if i is None or i >= len(row):
            return default
        try:
            return cast(row[i]) if cast else row[i]
        except (TypeError, ValueError):
            return default

    rows = []
    for r in t.get("Processes") or []:
        rss_kib = cell(r, "RSS", int)
        rows.append({
            "pid": cell(r, "PID", int),
            "ppid": cell(r, "PPID", int),
            "user": cell(r, "USER"),
            "state": None,
            "threads": None,
            "rss": rss_kib * 1024 if rss_kib is not None else None,
            "cpu_pct": cell(r, "%CPU", float),
            "etime": cell(r, "ELAPSED"),
            "cmd": cell(r, "COMMAND", default=""),
            "new": False,
        })
    return {"source": "ps", "cpu_is_lifetime_avg": True,
            "window_s": None, "processes": rows}


def _processes_sync(cid: str, window: float) -> dict:
    try:
        c = _client().containers.get(cid)
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"no such container: {e}")

    cat = _category(c)
    out: dict = {"id": (c.id or "")[:12], "name": c.name, "category": cat,
                 "state": getattr(c, "status", ""),
                 "running": getattr(c, "status", "") == "running"}
    if not out["running"]:
        # `top` on a stopped container is a 409 from the daemon, not an empty
        # list, so this is an answer rather than an error path.
        out.update({"processes": [], "source": None,
                    "note": "container is not running — it has no processes."})
        return out

    stats = _stats_of(c)
    out.update({k: stats.get(k) for k in
                ("mem_usage", "mem_limit", "mem_unreclaimable", "cpu_pct")})

    if cat == "core":
        try:
            out.update(_procs_via_exec(c, window))
        except Exception as e:
            out.update(_procs_via_top(c))
            out["source_fallback"] = f"{type(e).__name__}: {e}"
    else:
        out.update(_procs_via_top(c))

    if out["source"] == "ps":
        out["source_note"] = (
            "read from the host with `docker top` — nothing runs inside the "
            "container. CPU is each process's average over its WHOLE LIFE, not "
            "its usage right now."
            + ("" if cat == "core" else
               " %s containers are not exec'd into: their image is not ours to "
               "trust." % cat))
    else:
        out["source_note"] = (
            "sampled from /proc inside the container over %.2fs — CPU is usage "
            "during that window." % out["window_s"])

    rss = [p["rss"] for p in out["processes"] if p.get("rss")]
    out["rss_sum"] = sum(rss) if rss else None
    # The two figures disagree in BOTH directions and neither is wrong. Measured
    # 2026-08-10: worker-1 cgroup 67.7 MB vs RSS sum 109.3 MB — five python
    # processes mapping one interpreter, and a shared page is counted once per
    # process that maps it while the cgroup counts it once. A busy probe went
    # the other way, cgroup 14.6 MB vs RSS sum 11.0 MB, because the cgroup also
    # holds page cache that no process has resident. Surfaced side by side WITH
    # the reason, because a reader who meets only one of them later will treat
    # the other as a bug.
    out["rss_sum_note"] = (
        "sum of per-process RSS. It can exceed the cgroup figure because a "
        "shared page is counted once per process that maps it, and it can fall "
        "below it because the cgroup also holds page cache.")
    return out


@router.get("/{cid}/processes")
async def container_processes(
    cid: str,
    window: float = Query(1.0, ge=0.2, le=5.0,
                          description="seconds between the two /proc samples"),
):
    """Processes inside ONE container, with per-process CPU and memory.

    One shot, deliberately: this costs a `stats` call plus either two execs and
    a `window`-long sleep, or a `top`. The containers list already refreshes at
    15 s because its own stats calls cost ~2 s; folding this into that poll
    would make an open detail row dominate every tick.
    """
    return await run_in_threadpool(_processes_sync, cid, window)


def _delete_sync(cid: str, force: bool) -> dict:
    try:
        client = _client()
        c = client.containers.get(cid)
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"no such container: {e}")

    if _is_self(c):
        # Hard refusal, not a confirm. This handler runs inside that container:
        # removing it means this response is never delivered and the operator
        # sees a dead page with no idea why.
        raise HTTPException(
            status_code=409,
            detail=("refusing to delete the api container that is serving this "
                    "request — the UI would die mid-click. Use "
                    "`docker compose up -d api` from the host if you need to "
                    "recreate it."),
        )

    name, svc, cat = c.name, _svc(c), _category(c)
    was_running = getattr(c, "status", "") == "running"
    try:
        c.remove(force=True, v=True)
    except Exception as e:
        raise HTTPException(status_code=500,
                            detail=f"{type(e).__name__}: {e}")
    return {"ok": True, "removed": name, "id": (c.id or "")[:12],
            "category": cat, "compose_service": svc or None,
            "was_running": was_running,
            # Only the long-lived services come back on `up -d`. A per-job
            # sandbox with a compose service label (profiles: ["tools"]) does
            # NOT, so promising a recreate there would be a lie.
            "note": ("compose will recreate this on the next `up -d`"
                     if _is_core_service(svc) else None)}


@router.delete("/{cid}")
async def delete_container(cid: str, force: bool = Query(True)):
    """Remove one container. `force` kills it first if it is running.

    Deliberately permissive apart from the self-delete guard: an operator
    clearing a wedged worker slot or a stuck challenge stack is a real need,
    and the list endpoint already tells the UI what each removal costs.
    """
    return await run_in_threadpool(_delete_sync, cid, force)
