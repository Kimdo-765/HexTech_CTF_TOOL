import json
import os
import re
import shutil
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Split an operator target field into individual targets. Newlines are the
# documented separator (the UI target box is a textarea — one per line);
# commas are also accepted for the single-line retry/continue override inputs.
# A CTF target (`host:port`, `nc host port`, `http://host:port/path`) does not
# contain a raw comma, so comma-splitting is safe in practice.
_TARGET_SPLIT_RE = re.compile(r"[\r\n,]+")


def parse_targets(raw: Optional[str], *, limit: int = 32) -> list[str]:
    """Parse a raw target field into a deduped, order-preserving list.

    Empty / whitespace-only input → []. Each target is stripped; blanks are
    dropped; duplicates are collapsed (first occurrence wins). Capped at
    `limit` so a paste accident can't enqueue an unbounded list. The first
    element is the PRIMARY target (argv[1] / meta.target_url); the full list
    is exposed to the exploit via the TARGETS env var (see modules/_runner).
    """
    if not raw:
        return []
    out: list[str] = []
    for piece in _TARGET_SPLIT_RE.split(raw):
        t = piece.strip()
        if t and t not in out:
            out.append(t)
            if len(out) >= limit:
                break
    return out

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
JOBS_DIR = DATA_DIR / "jobs"
UPLOADS_DIR = DATA_DIR / "uploads"
# Operator-curated library of past exploits/solvers a future job can
# consult when stuck on technique / leak-vector choice. Filesystem-
# backed (no SQLite) so `tar -czf - data/exploits/` is a complete
# portable dump — see api/routes/exploits.py for export/import.
EXPLOITS_DIR = DATA_DIR / "exploits"


def exploit_dir(exploit_id: str) -> Path:
    return EXPLOITS_DIR / exploit_id


def new_job_id() -> str:
    return uuid.uuid4().hex[:12]


def job_dir(job_id: str) -> Path:
    p = JOBS_DIR / job_id
    p.mkdir(parents=True, exist_ok=True)
    return p


_TERMINAL_STATUSES = {"finished", "failed", "no_flag", "stopped"}


def write_job_meta(job_id: str, meta: dict[str, Any]) -> None:
    f = job_dir(job_id) / "meta.json"
    prev: dict[str, Any] = {}
    if f.exists():
        try:
            prev = json.loads(f.read_text())
        except Exception:
            prev = {}
    now_iso = datetime.now(timezone.utc).isoformat()
    # Auto-stamp lifecycle timestamps so the UI can show elapsed /
    # duration without each call site having to remember to set them.
    new_status = meta.get("status")
    if (
        new_status == "running"
        and not meta.get("started_at")
        and not prev.get("started_at")
    ):
        meta["started_at"] = now_iso
    if (
        new_status in _TERMINAL_STATUSES
        and not meta.get("finished_at")
        and not prev.get("finished_at")
    ):
        meta["finished_at"] = now_iso
    meta = {**meta, "updated_at": now_iso}
    f.write_text(json.dumps(meta, indent=2))


def read_job_meta(job_id: str) -> Optional[dict[str, Any]]:
    f = JOBS_DIR / job_id / "meta.json"
    if not f.exists():
        return None
    return json.loads(f.read_text())


def save_upload(job_id: str, filename: str, content: bytes) -> Path:
    src_dir = job_dir(job_id) / "src"
    src_dir.mkdir(exist_ok=True)
    target = src_dir / filename
    target.write_bytes(content)
    return target


def extract_if_archive(path: Path) -> Path:
    """If path is a zip, extract into a sibling dir and return that dir.
    Otherwise return the parent directory.
    """
    if path.suffix.lower() == ".zip":
        out = path.parent / "extracted"
        out.mkdir(exist_ok=True)
        with zipfile.ZipFile(path, "r") as zf:
            zf.extractall(out)
        return out
    return path.parent


def cleanup_job(job_id: str) -> None:
    p = JOBS_DIR / job_id
    if p.exists():
        shutil.rmtree(p)
