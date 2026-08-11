"""Dependency-light storage primitives shared by API and worker runtimes.

Keep this module limited to the standard library: worker containers mount the
``modules`` package, but intentionally do not mount the FastAPI ``api`` package.
"""

from __future__ import annotations

import os
import uuid
import zipfile
from pathlib import Path


DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
JOBS_DIR = DATA_DIR / "jobs"
UPLOADS_DIR = DATA_DIR / "uploads"


def new_job_id() -> str:
    return uuid.uuid4().hex[:12]


def extract_if_archive(path: Path) -> Path:
    """Extract a ZIP beside ``path``; otherwise return its parent directory."""

    if path.suffix.lower() == ".zip":
        out = path.parent / "extracted"
        out.mkdir(exist_ok=True)
        with zipfile.ZipFile(path, "r") as archive:
            archive.extractall(out)
        return out
    return path.parent


__all__ = [
    "DATA_DIR",
    "JOBS_DIR",
    "UPLOADS_DIR",
    "extract_if_archive",
    "new_job_id",
]
