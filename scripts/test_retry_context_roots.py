#!/usr/bin/env python3
"""Regression checks for reviewer context gathered from a live job + work dir.

The production function is extracted with ``ast`` so this stays runnable on a
host without FastAPI / claude-agent-sdk installed.
"""
from __future__ import annotations

import ast
import json
import re
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "modules" / "reviewer.py").read_text(encoding="utf-8")

PASSED = 0
FAILED = 0


def check(label: str, condition: bool, got: object = "") -> None:
    global PASSED, FAILED
    if condition:
        PASSED += 1
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got={got!r}")


def extract_gather_context():
    tree = ast.parse(SOURCE)
    wanted = {
        "RUN_LOG_CONTEXT_CHARS",
        "_REVIEW_SOURCE_CANDIDATES",
        "_REVIEW_SOURCE_LIMIT",
        "_HINT_REPLACEMENTS",
        "_sanitize_hint",
        "_gather_context",
    }
    nodes = []
    for node in tree.body:
        name = None
        if isinstance(node, ast.FunctionDef):
            name = node.name
        elif isinstance(node, ast.Assign):
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
            name = next((candidate for candidate in names if candidate in wanted), None)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            name = node.target.id
        if name in wanted:
            nodes.append(node)
    namespace = {"Path": Path, "json": json, "_re": re}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<production>", "exec"), namespace)
    return namespace["_gather_context"]


gather = extract_gather_context()

with tempfile.TemporaryDirectory(prefix="retry-context-roots-") as td:
    base = Path(td)
    job = base / "job"
    work = base / "work"
    job.mkdir()
    work.mkdir()

    (job / "meta.json").write_text(json.dumps({"module": "rev"}))
    (job / "run.log").write_text("JOB_ROOT_RUN_LOG")
    (job / "solver.py.stdout").write_text("JOB_ROOT_STDOUT")
    (work / "report.md").write_text("LIVE_WORK_REPORT")
    (work / "solver.py").write_text("LIVE_WORK_SOLVER")

    legacy = gather(job)
    single_root = gather(roots=(job,))
    check("legacy positional call is byte-identical to one explicit root", legacy == single_root)
    check("job-root-only context cannot see the live report", "LIVE_WORK_REPORT" not in single_root)

    live = gather(roots=(job, work))
    for marker in ("JOB_ROOT_RUN_LOG", "JOB_ROOT_STDOUT", "LIVE_WORK_REPORT", "LIVE_WORK_SOLVER"):
        check(f"two-root context includes {marker}", marker in live, live)

    (job / "report.md").write_text("COLLECTED_REPORT_WINS")
    first_wins = gather(roots=(job, work))
    check("the first root wins for an overlapping artifact", "COLLECTED_REPORT_WINS" in first_wins)
    check("a later duplicate is not appended", "LIVE_WORK_REPORT" not in first_wins)

print(f"{PASSED} checks, {FAILED} failed")
raise SystemExit(1 if FAILED else 0)
