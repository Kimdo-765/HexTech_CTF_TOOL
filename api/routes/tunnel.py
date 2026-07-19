"""cloudflared OOB quick-tunnel control (operator activate button + live status).

Runs cloudflared as a SIBLING container (not an api child) via the docker
socket — the same pattern api/routes/terminal.py uses — so the tunnel SURVIVES
api restarts (deploy.sh restarts the api even during a live job) and the public
``*.trycloudflare.com`` URL stays stable across redeploys. The tunnel points at
the api service (``http://api:8000`` on the compose network) and publishes its
public URL into ``settings.callback_url`` in-process via ``update_settings``
(no HTTP self-call). That URL becomes ``CALLBACK_URL`` → ``COLLECTOR_URL`` for
the next job's exploits (OOB beacons land on the built-in collector).

SECURITY: a quick-tunnel exposes the ENTIRE api (settings write, ``/api/terminal``
= interactive shell / RCE, job & flag reads) to the public internet.
``/api/collector/`` is auth-exempt (PUBLIC_PATHS) so OOB keeps working even with
auth on. The operator chose "warn-but-allow": activation is NOT hard-gated on
``auth_token``, but ``exposure_warning`` is set whenever no ``auth_token`` is
configured so the UI can warn loudly.

Anti-patterns avoided (memory ``cloudflared_oob_tunnel``): NO auto-restart of a
dead tunnel (Cloudflare rate-limits quick-tunnel creation) — the container runs
with no restart policy, so a dead tunnel stays dead and status reports it; the
operator re-rolls manually. Status probes REALITY (container state + an outbound
body=="ok" edge round-trip), never a stored flag.
"""
from __future__ import annotations

import re
import time

from fastapi import APIRouter

router = APIRouter()

CLOUDFLARED_IMAGE = "cloudflare/cloudflared:2026.6.0"
TUNNEL_NAME = "hextech_ctf_tool_tunnel"
COMPOSE_NETWORK = "hextech_ctf_tool_default"
TUNNEL_TARGET = "http://api:8000"
_TRYCF_RE = re.compile(r"https://[a-z0-9][a-z0-9.-]*\.trycloudflare\.com")
_ROLE_LABEL = "hextech_ctf_tool_role"
_PRIOR_LABEL = "hextech_ctf_tool_prior_callback_url"


def _client():
    import docker
    return docker.from_env()


def _get_container(client):
    """Return the tunnel container (any state) or None."""
    import docker
    try:
        return client.containers.get(TUNNEL_NAME)
    except docker.errors.NotFound:
        return None
    except Exception:
        return None


def _extract_url(container) -> str:
    """Last *.trycloudflare.com URL from the container logs (cloudflared prints
    the quick-tunnel URL to stderr)."""
    try:
        logs = container.logs(stdout=True, stderr=True).decode("utf-8", "replace")
    except Exception:
        return ""
    m = _TRYCF_RE.findall(logs)
    return m[-1] if m else ""


def _auth_configured() -> bool:
    from modules.settings_io import get_setting
    return bool(str(get_setting("auth_token") or "").strip())


def _probe_reachable(url: str, timeout: float = 3.0) -> bool:
    """Best-effort outbound e2e check THROUGH the public edge: the discriminator
    is the collector's literal body 'ok' (an HTML Cloudflare warm-up/error page
    is also HTTP 200, so status code alone lies). One shot, short timeout."""
    if not url:
        return False
    try:
        import requests  # bundled via docker-py
        r = requests.get(f"{url}/api/collector/_tunnelprobe/_p?c=PING", timeout=timeout)
        return r.text.strip() == "ok"
    except Exception:
        return False


def _status_payload(client=None, *, probe: bool = False) -> dict:
    from modules.settings_io import get_setting
    cb = str(get_setting("callback_url") or "")
    auth = _auth_configured()
    base = {
        "running": False,
        "url": "",
        "callback_url": cb,
        "url_published": False,
        "reachable": None,
        "auth_configured": auth,
        "exposure_warning": not auth,
        "image": CLOUDFLARED_IMAGE,
    }
    if client is None:
        try:
            client = _client()
        except Exception as e:
            base["error"] = f"docker unavailable: {e}"
            return base
    c = _get_container(client)
    if not c:
        return base
    try:
        c.reload()
    except Exception:
        pass
    running = getattr(c, "status", "") == "running"
    url = _extract_url(c) if running else ""
    base["running"] = running
    base["url"] = url
    base["url_published"] = bool(url and url == cb)
    if probe and running and url:
        base["reachable"] = _probe_reachable(url)
    return base


@router.get("/status")
def tunnel_status(probe: bool = False):
    """Live tunnel status. ?probe=1 adds the outbound body=='ok' edge check
    (slower, ~3s). Reflects REALITY (container state + logs), never a stored
    flag — callback_url persists in settings but the container dies on daemon
    restart, so a naive 'active' flag would lie."""
    st = _status_payload(probe=probe)
    # Re-sync drift: cloudflared can reconnect with a NEW URL mid-session. If the
    # live tunnel URL differs from what's published, re-publish it. This is NOT a
    # tunnel re-creation (no rate-limit concern) — just republishing a live URL.
    # Guard (like /stop): only overwrite callback_url when it's empty or itself a
    # trycloudflare URL, so an operator's manual VPS/collector URL is left intact.
    try:
        cb = st.get("callback_url") or ""
        if (st.get("running") and st.get("url") and st["url"] != cb
                and (not cb or _TRYCF_RE.match(cb))):
            from modules.settings_io import update_settings
            update_settings({"callback_url": st["url"]})
            st["callback_url"] = st["url"]
            st["url_published"] = True
    except Exception:
        pass
    return st


@router.post("/start")
def tunnel_start():
    """Spawn the cloudflared sibling container, wait for its public URL, publish
    it to callback_url. Idempotent (already-running → returns current status).
    Single-shot: on failure it does NOT auto-retry (rate-limit anti-pattern)."""
    from modules.settings_io import get_setting, update_settings
    try:
        client = _client()
    except Exception as e:
        return {"ok": False, "error": f"docker unavailable: {e}", **_status_payload()}

    existing = _get_container(client)
    if existing:
        try:
            existing.reload()
        except Exception:
            pass
        state = getattr(existing, "status", "")
        # Treat any NON-terminal state as up — including the transient "created"
        # window a concurrent /start races through. Only a genuinely terminal
        # (exited/dead) leftover is force-removed; force-removing a "created"
        # container would destroy an in-flight tunnel another /start is polling.
        if state in ("running", "created", "restarting"):
            st = _status_payload(client)
            st["ok"] = True
            st["note"] = "tunnel already running" if state == "running" else "tunnel already starting"
            return st
        try:
            existing.remove(force=True)
        except Exception:
            pass

    prior = str(get_setting("callback_url") or "")
    try:
        import docker
        container = client.containers.run(
            image=CLOUDFLARED_IMAGE,
            command=["tunnel", "--url", TUNNEL_TARGET, "--no-autoupdate"],
            name=TUNNEL_NAME,
            detach=True,
            network=COMPOSE_NETWORK,
            # No restart policy: a dead tunnel stays dead (status reports it) and
            # the operator re-rolls — never a self-heal loop (Cloudflare rate-limit).
            labels={_ROLE_LABEL: "tunnel", _PRIOR_LABEL: prior},
        )
    except docker.errors.ImageNotFound:
        return {"ok": False,
                "error": f"cloudflared image missing — pull it once: docker pull {CLOUDFLARED_IMAGE}",
                **_status_payload(client)}
    except Exception as e:
        return {"ok": False, "error": f"tunnel container failed to start: {e}", **_status_payload(client)}

    # Poll the container logs for the public URL (~30s), bail if it dies early.
    url = ""
    for _ in range(60):
        try:
            container.reload()
        except Exception:
            pass
        if getattr(container, "status", "") not in ("running", "created"):
            break
        url = _extract_url(container)
        if url:
            break
        time.sleep(0.5)

    if not url:
        return {"ok": False,
                "error": "no *.trycloudflare.com URL within 30s (Cloudflare rate-limit, or the "
                         "tunnel container died). Stop and re-roll — do not spam retries.",
                **_status_payload(client)}

    update_settings({"callback_url": url})
    st = _status_payload(client, probe=True)
    st["ok"] = True
    return st


@router.post("/stop")
def tunnel_stop():
    """Remove the tunnel container and undo our callback_url change. Idempotent
    (nothing running → no-op). Prefers CLEARING callback_url over restoring a
    stale dead prior tunnel URL; an operator-set non-tunnel URL is left intact."""
    from modules.settings_io import get_setting, update_settings
    try:
        client = _client()
    except Exception as e:
        return {"ok": False, "error": f"docker unavailable: {e}", **_status_payload()}
    c = _get_container(client)
    if not c:
        st = _status_payload(client)
        st["ok"] = True
        st["note"] = "no tunnel running"
        return st
    prior = (getattr(c, "labels", None) or {}).get(_PRIOR_LABEL, "")
    our_url = _extract_url(c)  # the URL THIS tunnel published, before we remove it
    try:
        c.remove(force=True)
    except Exception as e:
        return {"ok": False, "error": f"stop failed: {e}", **_status_payload(client)}
    # Only undo OUR OWN publish: touch callback_url only when it still equals the
    # URL this tunnel published (or, if we couldn't re-extract it, when it's some
    # trycloudflare URL). An operator's manual VPS/other URL is left untouched.
    cur = str(get_setting("callback_url") or "")
    if cur and (cur == our_url or (not our_url and _TRYCF_RE.match(cur))):
        # Restore the prior unless it was itself a (now-dead) trycloudflare tunnel.
        restore = "" if _TRYCF_RE.match(prior or "") else (prior or "")
        update_settings({"callback_url": restore})
    st = _status_payload(client)
    st["ok"] = True
    return st
