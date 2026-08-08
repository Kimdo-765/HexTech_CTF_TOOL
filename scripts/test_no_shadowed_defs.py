#!/usr/bin/env python3
"""No module may define the same top-level name twice.

A second `def` of the same name silently wins, and the first becomes dead
code that still READS like the live one. That is worse than an unused
function: a mutation aimed at the visible copy changed nothing, and a
verification pass reported the contract as unbreakable when it was simply
untested. Two of these accumulated in modules/_judge.py during this work,
both from patch scripts that re-inserted a helper they had already written.

Cheap to check, and it closes the class rather than the two instances.
"""

from __future__ import annotations

import ast
import collections
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SCAN_DIRS = ("modules", "api", "worker")
SKIP_PARTS = {".venv", "node_modules", "__pycache__", ".git", ".pydeps"}

# A name may legitimately be bound more than once when the bindings are
# mutually exclusive — a try/except ImportError fallback, or a
# `if TYPE_CHECKING:` shim. Only bindings at the SAME nesting level and
# outside any conditional are compared, which is what ast.Module.body gives.

PASSED = 0
FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


def duplicate_top_level_defs(path: Path) -> list[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
    except SyntaxError:
        return []
    names = [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    return sorted(n for n, c in collections.Counter(names).items() if c > 1)


files = [
    p
    for d in SCAN_DIRS
    for p in (ROOT / d).rglob("*.py")
    if not SKIP_PARTS & set(p.parts)
]
check("there are modules to scan", len(files) > 20, True)

offenders = {}
for path in sorted(files):
    dups = duplicate_top_level_defs(path)
    if dups:
        offenders[str(path.relative_to(ROOT))] = dups

check("no module shadows its own top-level definitions", offenders, {})

# The detector must be able to fail — a checker that cannot report anything
# is indistinguishable from a clean codebase.
import tempfile  # noqa: E402

with tempfile.TemporaryDirectory() as td:
    probe = Path(td) / "probe.py"
    probe.write_text("def f():\n    return 1\n\n\ndef f():\n    return 2\n")
    check("the detector finds a planted duplicate", duplicate_top_level_defs(probe), ["f"])
    probe.write_text("def f():\n    return 1\n\n\ndef g():\n    return 2\n")
    check("...and reports nothing on a clean file", duplicate_top_level_defs(probe), [])
    probe.write_text("class C:\n    def m(self):\n        pass\n\n    def m(self):\n        pass\n")
    check(
        "nested redefinitions are NOT flagged (only top level is compared)",
        duplicate_top_level_defs(probe),
        [],
    )

print(f"== summary: {PASSED} passed, {FAILED} failed ==")
sys.exit(1 if FAILED else 0)
