#!/usr/bin/env python3
"""Regression checks for evidence-driven, non-overfit retry guidance.

This suite stays offline. It extracts the production prompt/context builders
with ``ast`` so it neither needs the API container's SDK dependencies nor
silently tests a reimplemented copy of the behavior.
"""
from __future__ import annotations

import ast
import json
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RETRY_PATH = ROOT / "modules" / "reviewer.py"
COMMON_PATH = ROOT / "modules" / "_common.py"
RETRY_SOURCE = RETRY_PATH.read_text()
COMMON_SOURCE = COMMON_PATH.read_text()

PASSED = 0
FAILED = 0


def check(label: str, condition: bool, got: object = "") -> None:
    global PASSED, FAILED
    if condition:
        PASSED += 1
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got={got!r}")


def _defines(node: ast.AST, names: set[str]) -> bool:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return node.name in names
    if isinstance(node, ast.Assign):
        return any(isinstance(t, ast.Name) and t.id in names for t in node.targets)
    if isinstance(node, ast.AnnAssign):
        return isinstance(node.target, ast.Name) and node.target.id in names
    return False


def _extract(source: str, names: set[str], namespace: dict) -> dict:
    tree = ast.parse(source)
    nodes = [node for node in tree.body if _defines(node, names)]
    found = {
        node.name if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        else node.target.id if isinstance(node, ast.AnnAssign)
        else next(t.id for t in node.targets if isinstance(t, ast.Name) and t.id in names)
        for node in nodes
    }
    missing = names - found
    if missing:
        raise AssertionError(f"production definitions not found: {sorted(missing)}")
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<production>", "exec"), namespace)
    return namespace


# ---------------------------------------------------------------------------
# Reviewer contract: diagnosis must expose evidence status and require novelty.
# ---------------------------------------------------------------------------
R = _extract(
    RETRY_SOURCE,
    {
        "_REVIEWER_PROMPT", "RUN_LOG_CONTEXT_CHARS",
        "_REVIEW_SOURCE_CANDIDATES", "_REVIEW_SOURCE_LIMIT",
        "_gather_context",
    },
    {"Path": Path, "json": json, "_sanitize_hint": lambda text: text},
)

prompt = R["_REVIEWER_PROMPT"]
for field in ("CLASS:", "VERIFIED:", "REFUTED:", "NEXT:", "PRESERVE:"):
    check(f"reviewer requires {field}", field in prompt)
check(
    "strategy retry requires materially distinct untested hypotheses",
    "2-3 hypotheses" in prompt and "materially distinct" in prompt,
)
check(
    "reviewer cannot promote an inference to an intended path",
    'Never call a route "intended", "required", or' in prompt,
)
check(
    "reviewer cannot replay a refuted branch without changed evidence",
    "Do not repeat a refuted branch unless new evidence" in prompt,
)
check(
    "reviewer prioritizes the real result over script polish",
    "real target result" in prompt and "non-working script cleaner" in prompt,
)


# ---------------------------------------------------------------------------
# Context routing: a Web retry must receive the authoritative PHP/JS chain.
# ---------------------------------------------------------------------------
with tempfile.TemporaryDirectory(prefix="retry-anti-overfit-") as td:
    job = Path(td)
    (job / "meta.json").write_text(json.dumps({"module": "web"}))
    (job / "report.md").write_text("UNVERIFIED_REPORT_THEORY")
    source_root = job / "src" / "extracted" / "Executable"
    html = source_root / "html"
    bot = source_root / "bot"
    html.mkdir(parents=True)
    bot.mkdir(parents=True)
    fixtures = {
        html / "index.php": "AUTHORITATIVE_INDEX_PHP",
        html / "flag.php": "AUTHORITATIVE_FLAG_PHP",
        html / "bot.php": "AUTHORITATIVE_BOT_PHP",
        bot / "bot.js": "AUTHORITATIVE_BOT_JS",
        source_root / "Dockerfile": "AUTHORITATIVE_DOCKERFILE",
        source_root / "main.c": "IRRELEVANT_PWN_SOURCE",
    }
    for path, body in fixtures.items():
        path.write_text(body)

    context = R["_gather_context"](job)
    for marker in (
        "AUTHORITATIVE_INDEX_PHP", "AUTHORITATIVE_FLAG_PHP",
        "AUTHORITATIVE_BOT_PHP", "AUTHORITATIVE_BOT_JS",
        "AUTHORITATIVE_DOCKERFILE",
    ):
        check(f"web reviewer context includes {marker}", marker in context)
    check(
        "web context excludes a module-irrelevant source when specific files exist",
        "IRRELEVANT_PWN_SOURCE" not in context,
    )
    source_sections = [
        line for line in context.splitlines() if line.startswith("=== src/")
    ]
    check(
        "authoritative source context remains bounded",
        len(source_sections) <= R["_REVIEW_SOURCE_LIMIT"],
        source_sections,
    )


# ---------------------------------------------------------------------------
# In-session redirect: distinguish a no-run prejudge from runtime evidence and
# force a strategy branch instead of polishing/deleting the same artifact.
# ---------------------------------------------------------------------------
C = _extract(
    COMMON_SOURCE,
    {"_format_postjudge_user_turn"},
    {"HEAP_FIX_HINTS": {}},
)
format_turn = C["_format_postjudge_user_turn"]
prejudge_turn = format_turn(
    attempt_idx=1,
    max_attempts=4,
    script_filename="exploit.py",
    sandbox_result={
        "judge": {
            "verdict": "prejudge_blocked",
            "next_action": "continue",
            "retry_hint": "current chain is unproven",
        }
    },
)
check(
    "prejudge feedback says the sandbox did not execute",
    "BEFORE SANDBOX EXECUTION" in prejudge_turn,
)
check(
    "prejudge feedback requires evidence audit",
    all(word in prejudge_turn for word in ("VERIFIED", "REFUTED", "UNTESTED")),
)
check(
    "strategy failure requires two materially different probes",
    "at least two materially different untested hypotheses" in prejudge_turn,
)
check(
    "artifact deletion is a last concession, not the first correction",
    "final\n     concession only after" in prejudge_turn,
)

runtime_turn = format_turn(
    attempt_idx=2,
    max_attempts=4,
    script_filename="exploit.py",
    sandbox_result={
        "stdout": "probe output",
        "judge": {"verdict": "retry", "next_action": "continue"},
    },
)
check(
    "real sandbox retry labels stdout/stderr as runtime evidence",
    "runtime evidence" in runtime_turn and "BEFORE SANDBOX" not in runtime_turn,
)

check(
    "prejudge redirect no longer unconditionally demands the same script",
    "re-ship the SAME script (do NOT start over)" not in COMMON_SOURCE,
)
check(
    "prejudge redirect contains the implementation-vs-strategy split",
    "IMPLEMENTATION defect (verified chain, broken code)" in COMMON_SOURCE
    and "STRATEGY/UNKNOWN defect" in COMMON_SOURCE,
)


print(f"== summary: {PASSED} passed, {FAILED} failed ==")
raise SystemExit(1 if FAILED else 0)
