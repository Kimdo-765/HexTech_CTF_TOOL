#!/usr/bin/env python3
"""Import the hybrid RQ entrypoint in the actual worker Python environment.

Run inside a deployed worker container::

    python3 -m worker.hybrid_smoke
"""

from __future__ import annotations

import importlib
import sys


def main() -> int:
    try:
        worker = importlib.import_module("modules.hybrid.worker")
    except Exception as exc:
        print(
            f"[hybrid_smoke] import failed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1

    run_job = getattr(worker, "run_job", None)
    if not callable(run_job):
        print(
            "[hybrid_smoke] modules.hybrid.worker.run_job is not callable",
            file=sys.stderr,
        )
        return 1

    print(
        "[hybrid_smoke] PASS: modules.hybrid.worker.run_job is importable and callable"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
