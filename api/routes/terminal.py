"""Web terminal — WebSocket → docker exec → xterm.js.

Opens an interactive bash inside a transient hextech_ctf_tool-runner container
with the requested job's directory mounted at /work. The user can edit /
re-run exploit.py, try ad-hoc payloads, install extra tools, etc.

Container is force-removed when the WebSocket closes.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path

import docker
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from modules.settings_io import get_setting

router = APIRouter()

RUNNER_IMAGE = "hextech_ctf_tool-runner"
DEFAULT_MEM = "2g"


def _host_path(job_id: str) -> str | None:
    host_root = os.environ.get("HOST_DATA_DIR", "").rstrip("/")
    if not host_root:
        return None
    return f"{host_root}/jobs/{job_id}"


def _check_token(ws: WebSocket) -> bool:
    """WebSocket auth — Starlette's BaseHTTPMiddleware doesn't cover WS, so
    we check the same token sources here."""
    expected = str(get_setting("auth_token") or "").strip()
    if not expected:
        return True
    provided = (
        ws.cookies.get("ctfmanager_token")
        or ws.query_params.get("token")
    )
    auth_h = ws.headers.get("authorization", "")
    if auth_h.lower().startswith("bearer "):
        provided = provided or auth_h[7:].strip()
    return provided == expected


@router.websocket("/ws/{job_id}")
async def terminal_ws(ws: WebSocket, job_id: str):
    if not _check_token(ws):
        await ws.close(code=4401)
        return

    safe_id = Path(job_id).name
    host_job = _host_path(safe_id)
    if not host_job:
        await ws.accept()
        await ws.send_text("\033[31m[err] HOST_DATA_DIR not configured.\033[0m\r\n")
        await ws.close()
        return

    if not Path(f"/data/jobs/{safe_id}").exists():
        await ws.accept()
        await ws.send_text(f"\033[31m[err] job {safe_id} does not exist.\033[0m\r\n")
        await ws.close()
        return

    await ws.accept()
    client = docker.from_env()
    try:
        container = client.containers.create(
            image=RUNNER_IMAGE,
            command=["/bin/bash"],
            tty=True,
            stdin_open=True,
            volumes={host_job: {"bind": "/work", "mode": "rw"}},
            working_dir="/work",
            mem_limit=DEFAULT_MEM,
            network_mode="bridge",
            environment={"TERM": "xterm-256color", "JOB_ID": safe_id},
            labels={
                "hextech_ctf_tool_job_id": safe_id,
                "hextech_ctf_tool_role": "terminal",
            },
        )
    except docker.errors.ImageNotFound:
        await ws.send_text(
            "\033[31m[err] runner image not built. Run:\r\n"
            "  docker compose --profile tools build runner\033[0m\r\n"
        )
        await ws.close()
        return
    except Exception as e:
        await ws.send_text(f"\033[31m[err] container create failed: {e}\033[0m\r\n")
        await ws.close()
        return

    try:
        container.start()
    except Exception as e:
        try:
            container.remove(force=True)
        except Exception:
            pass
        await ws.send_text(f"\033[31m[err] container start failed: {e}\033[0m\r\n")
        await ws.close()
        return

    sock = container.attach_socket(
        params={"stdin": 1, "stdout": 1, "stderr": 1, "stream": 1}
    )
    raw_sock = sock._sock if hasattr(sock, "_sock") else sock
    raw_sock.setblocking(False)

    loop = asyncio.get_event_loop()
    stop = asyncio.Event()

    async def container_to_ws():
        # Read from docker socket in a thread, push to WS via run_coroutine_threadsafe
        def reader():
            import select
            try:
                while not stop.is_set():
                    r, _, _ = select.select([raw_sock], [], [], 0.5)
                    if not r:
                        # check if container exited
                        try:
                            container.reload()
                            if container.status not in ("running", "created"):
                                break
                        except Exception:
                            break
                        continue
                    try:
                        data = raw_sock.recv(4096)
                    except (BlockingIOError, OSError):
                        continue
                    if not data:
                        break
                    fut = asyncio.run_coroutine_threadsafe(
                        ws.send_bytes(data), loop
                    )
                    try:
                        fut.result(timeout=5)
                    except Exception:
                        break
            finally:
                asyncio.run_coroutine_threadsafe(_set_stop(), loop)

        await asyncio.to_thread(reader)

    async def _set_stop():
        stop.set()

    async def ws_to_container():
        try:
            while not stop.is_set():
                msg = await ws.receive()
                if msg["type"] == "websocket.disconnect":
                    break
                data = msg.get("bytes")
                if data is None:
                    text = msg.get("text") or ""
                    if text.startswith("\x1bRESIZE:"):
                        # "\x1bRESIZE:cols,rows" → docker resize tty
                        try:
                            cols, rows = text[len("\x1bRESIZE:"):].split(",")
                            container.resize(int(rows), int(cols))
                        except Exception:
                            pass
                        continue
                    data = text.encode("utf-8")
                if not data:
                    continue
                try:
                    raw_sock.sendall(data)
                except Exception:
                    break
        except WebSocketDisconnect:
            pass
        finally:
            stop.set()

    try:
        await asyncio.gather(container_to_ws(), ws_to_container())
    except Exception:
        pass
    finally:
        try:
            container.stop(timeout=2)
        except Exception:
            pass
        try:
            container.remove(force=True)
        except Exception:
            pass
        try:
            await ws.close()
        except Exception:
            pass
