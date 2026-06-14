"""Built-in OOB callback collector.

Lets the operator skip webhook.site / requestbin entirely:

  1. Run `./tunnel.sh` — a cloudflared quick-tunnel that auto-publishes
     its public URL into Settings → Callback URL (no ngrok interstitial,
     no manual copy). Or expose port 8000 with any tunnel yourself
     (`cloudflared tunnel --url http://localhost:8000`, ngrok, frp, ssh -R)
     and set the Callback URL by hand.
  2. Settings → Callback URL = `https://<tunnel-host>` (tunnel.sh sets this
     for you; the orchestrator appends `/api/collector/<job_id>` per job)
     OR set CALLBACK_URL to a sentinel like `__BUILTIN__/<job_id>` and
     have the exploit read `BUILTIN_COLLECTOR_BASE` from env.
  3. Anything the bot fetches under that path is logged to
     /data/jobs/<job_id>/callbacks.jsonl AND any flag-shaped string in
     the path/query/body is auto-extracted via scan_job_for_flags().
  4. For an ITERATIVE oracle (a boolean / LIKE-search leak that reveals
     the flag one char per round), the exploit reads back which
     conditional beacon fired via `GET /api/collector/<job_id>/_hits`
     (JSON of the logged beacons; a pure read — not itself logged).

This route is exempt from auth so external bots can hit it (and so the
sandboxed exploit can poll `/_hits`). The token is the job_id itself —
the operator should keep job IDs secret if they care about that.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from api.storage import JOBS_DIR, read_job_meta
from modules._common import scan_job_for_flags, write_meta

router = APIRouter()


@router.get("/{job_id}/_hits")
async def collector_hits(job_id: str, since: int = 0):
    """Read-back for an ITERATIVE oracle.

    Most OOB exfil is single-shot — the whole secret arrives in one
    beacon and the write path below extracts it server-side; the script
    never needs to read anything back. But a CSP-constrained boolean /
    LIKE-search leak reveals the flag one char per round and the exploit
    MUST learn which conditional beacon fired in order to extend the
    next round. This endpoint returns the beacons logged for the job so
    the exploit can poll for the round's marker.

    Pure read: it does NOT log itself as a beacon, does NOT scan for
    flags, and does NOT touch job status — so polling it can't pollute
    callbacks.jsonl or false-finish the job. The bot visit is async, so
    callers poll until the marker appears (or a timeout). `since=<n>`
    returns only hits at/after index n (a cheap cursor for tight loops).

    Defined ABOVE the catch-all `collect` so `/<job>/_hits` resolves
    here instead of being swallowed as a beacon path.
    """
    safe = Path(job_id).name
    jd = JOBS_DIR / safe
    log = jd / "callbacks.jsonl"
    hits: list[dict] = []
    if log.is_file():
        try:
            for line in log.read_text().splitlines():
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                hits.append({
                    "ts": r.get("ts"),
                    "method": r.get("method"),
                    "path": r.get("path"),
                    "query": r.get("query"),
                    "ua": (r.get("headers") or {}).get("user-agent", ""),
                })
        except OSError:
            pass
    sliced = hits[since:] if since > 0 else hits
    return JSONResponse({"count": len(hits), "since": since, "hits": sliced})


@router.api_route(
    "/{job_id}/{tail:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
)
@router.api_route(
    "/{job_id}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
)
async def collect(request: Request, job_id: str, tail: str = ""):
    safe = Path(job_id).name
    jd = JOBS_DIR / safe
    if not jd.is_dir():
        return PlainTextResponse("ok", status_code=200)

    body = b""
    try:
        body = await request.body()
    except Exception:
        pass

    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "method": request.method,
        "path": "/" + tail if tail else "/",
        "query": dict(request.query_params),
        "headers": {k: v for k, v in request.headers.items()
                    if k.lower() not in ("authorization", "cookie")},
        "client": request.client.host if request.client else None,
        "body": body[:8192].decode("utf-8", errors="replace"),
        "body_truncated": len(body) > 8192,
    }
    log = jd / "callbacks.jsonl"
    with log.open("a") as f:
        f.write(json.dumps(record) + "\n")

    # Re-scan for flags now that the callback might contain one
    flags = scan_job_for_flags(safe, extra_files=["callbacks.jsonl"])
    meta = read_job_meta(safe) or {}
    if flags and set(flags) != set(meta.get("flags") or []):
        write_meta(safe, flags=flags, status="finished")

    return PlainTextResponse("ok", status_code=200)
