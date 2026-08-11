#!/usr/bin/env python3
"""S3.5 worker-mount parity check for the hybrid RQ entrypoint.

The repository root contains ``api`` and therefore masks worker-only import
failures.  This check exposes only the directories mounted into the worker
container (``modules`` and ``worker``), then runs the shipped smoke probe in an
isolated Python process.

Run: python3 scripts/test_hybrid_runtime_parity.py
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
passed = failed = 0


def check(label: str, got, want=True) -> None:
    global passed, failed
    if got == want:
        passed += 1
        print(f"PASS  {label}")
    else:
        failed += 1
        print(f"FAIL  {label}\n      got  = {got!r}\n      want = {want!r}")


with tempfile.TemporaryDirectory(prefix="hybrid-runtime-parity-") as raw_tmp:
    runtime_root = Path(raw_tmp)
    (runtime_root / "modules").symlink_to(ROOT / "modules", target_is_directory=True)
    (runtime_root / "worker").symlink_to(ROOT / "worker", target_is_directory=True)

    probe = """
import importlib.util
import runpy
import sys

runtime_root = sys.argv[1]
sys.path.insert(0, runtime_root)
if importlib.util.find_spec("api") is not None:
    raise SystemExit("isolated worker surface unexpectedly exposes api")
runpy.run_module("worker.hybrid_smoke", run_name="__main__")
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", probe, str(runtime_root)],
        cwd="/tmp",
        text=True,
        capture_output=True,
        check=False,
    )

    check(
        "test_worker_mount_fixture_excludes_api_package",
        not (runtime_root / "api").exists(),
    )
    check("test_hybrid_entrypoint_imports_on_worker_mount_surface", result.returncode, 0)
    check(
        "test_named_worker_smoke_reaches_callable_entrypoint",
        "[hybrid_smoke] PASS" in result.stdout,
    )
    check(
        "test_failure_callback_imports_on_worker_mount_surface",
        "independent failure callback are importable and callable" in result.stdout,
    )

from api import storage as api_storage  # noqa: E402
from modules import _common as common_storage  # noqa: E402
from modules import storage as shared_storage  # noqa: E402
from modules.hybrid import coordinator as hybrid_coordinator  # noqa: E402
from modules.hybrid import worker as hybrid_worker  # noqa: E402

shared_names = (
    "JOBS_DIR",
    "UPLOADS_DIR",
    "extract_if_archive",
    "new_job_id",
)
check(
    "test_api_and_worker_import_the_same_shared_storage_objects",
    all(
        getattr(api_storage, name) is getattr(shared_storage, name)
        and getattr(hybrid_worker, name) is getattr(shared_storage, name)
        for name in shared_names
    ),
)
check(
    "test_api_common_worker_and_hybrid_callback_share_one_data_root",
    api_storage.DATA_DIR is shared_storage.DATA_DIR
    and api_storage.JOBS_DIR is shared_storage.JOBS_DIR
    and common_storage.DATA_DIR is shared_storage.DATA_DIR
    and common_storage.JOBS_DIR is shared_storage.JOBS_DIR
    and hybrid_worker.JOBS_DIR is shared_storage.JOBS_DIR
    and hybrid_coordinator.JOBS_DIR is shared_storage.JOBS_DIR,
)
if result.returncode != 0:
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)

print(f"hybrid-runtime-parity: {passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
