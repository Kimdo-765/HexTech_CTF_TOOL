import os
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from api.auth import TokenAuthMiddleware
from api.routes import jobs as jobs_routes
from api.routes import settings as settings_routes
from api.routes import collector as collector_routes
from api.routes import retry as retry_routes
from api.routes import terminal as terminal_routes
from api.routes import exploits as exploits_routes
from api.routes import (
    crypto_module,
    forensic_module,
    misc_module,
    pwn_module,
    rev_module,
    web_module,
)
from modules.settings_io import get_setting

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
(DATA_DIR / "uploads").mkdir(exist_ok=True)
(DATA_DIR / "jobs").mkdir(exist_ok=True)
(DATA_DIR / "exploits").mkdir(exist_ok=True)

WEB_UI_DIR = Path("/app/web-ui")

app = FastAPI(title="CTFmanager", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(TokenAuthMiddleware)


# Force browsers to revalidate the web-ui assets so a redeploy's new
# app.js / style.css / index.html is picked up immediately instead of a
# stale cached copy. `no-cache` still allows a cheap 304 via StaticFiles'
# ETag when the file is unchanged — it only forbids using the cached copy
# WITHOUT revalidating. Without this, the bind-mounted assets serve fresh
# from disk but the browser keeps running old JS after a deploy (observed:
# the +add-target button "not working" because the cached app.js predated
# its handler). Scoped to the document + /static so API responses are
# untouched.
_NOCACHE_PATHS = {"/", "/index.html", "/login", "/terminal"}


@app.middleware("http")
async def _revalidate_web_ui(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    if path in _NOCACHE_PATHS or path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache"
    return response


app.include_router(jobs_routes.router, prefix="/api/jobs", tags=["jobs"])
app.include_router(web_module.router, prefix="/api/modules/web", tags=["web"])
app.include_router(pwn_module.router, prefix="/api/modules/pwn", tags=["pwn"])
app.include_router(forensic_module.router, prefix="/api/modules/forensic", tags=["forensic"])
app.include_router(misc_module.router, prefix="/api/modules/misc", tags=["misc"])
app.include_router(crypto_module.router, prefix="/api/modules/crypto", tags=["crypto"])
app.include_router(rev_module.router, prefix="/api/modules/rev", tags=["rev"])
app.include_router(settings_routes.router, prefix="/api/settings", tags=["settings"])
app.include_router(terminal_routes.router, prefix="/api/terminal", tags=["terminal"])
app.include_router(collector_routes.router, prefix="/api/collector", tags=["collector"])
app.include_router(retry_routes.router, prefix="/api/jobs", tags=["jobs"])
app.include_router(exploits_routes.router, prefix="/api/exploits", tags=["exploits"])


@app.get("/api/health")
def health():
    return {"status": "ok", "auth_required": bool(str(get_setting("auth_token") or "").strip())}


@app.get("/api/modules")
def list_modules():
    return {
        "modules": [
            {"id": "web", "name": "Web Exploitation", "status": "available"},
            {"id": "pwn", "name": "Pwnable (ghiant)", "status": "available"},
            {"id": "forensic", "name": "Forensic", "status": "available"},
            {"id": "misc", "name": "Misc / Stego", "status": "available"},
            {"id": "crypto", "name": "Crypto", "status": "available"},
            {"id": "rev", "name": "Reversing (ghiant)", "status": "available"},
        ]
    }


@app.get("/login", response_class=FileResponse)
def login_page():
    return FileResponse(str(WEB_UI_DIR / "login.html"))


@app.post("/login")
def login_post(token: str = Form(...)):
    expected = str(get_setting("auth_token") or "").strip()
    if not expected:
        return RedirectResponse("/", status_code=303)
    if token != expected:
        return JSONResponse({"detail": "wrong token"}, status_code=401)
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(
        "ctfmanager_token", token,
        httponly=True, samesite="lax", max_age=30 * 24 * 3600,
    )
    return resp


@app.post("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("ctfmanager_token")
    return resp


if WEB_UI_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_UI_DIR)), name="static")

    @app.get("/")
    def index():
        return FileResponse(str(WEB_UI_DIR / "index.html"))

    @app.get("/terminal", response_class=FileResponse)
    def terminal_page():
        return FileResponse(str(WEB_UI_DIR / "terminal.html"))
