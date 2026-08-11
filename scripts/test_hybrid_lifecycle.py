#!/usr/bin/env python3
"""S3 public hybrid lifecycle, accounting, cascade, UI, and mutation gate.

Run: python3 scripts/test_hybrid_lifecycle.py [--mutate NAME]

The production jobs route is compiled from its source text into an isolated
module. Mutations therefore alter the production implementation itself (in
memory only), while every check still runs to the final summary.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import types
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument(
    "--mutate",
    choices=(
        "expose-child", "double-cost", "drop-stop-cascade", "drop-delete-cascade",
        "drop-visibility-internal", "drop-visibility-parent",
        "drop-visibility-stage",
        "drop-membership-internal", "drop-membership-parent",
        "drop-membership-stage", "drop-membership-module",
        "drop-membership-all", "drop-evidence", "expose-retry",
    ),
)
args = parser.parse_args()

TMP = tempfile.TemporaryDirectory(prefix="hybrid-s3-")
DATA = Path(TMP.name) / "data"
JOBS = DATA / "jobs"
JOBS.mkdir(parents=True)
os.environ["DATA_DIR"] = str(DATA)
sys.path.insert(0, str(ROOT))

# The host-side regression shell intentionally has no FastAPI/RQ install. Load
# the route with the same small interface stubs used by the other source-level
# route harnesses; all lifecycle functions under test are plain Python.
fastapi = types.ModuleType("fastapi")


class HTTPException(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class APIRouter:
    def _decorator(self, *args, **kwargs):
        return lambda fn: fn

    get = post = delete = patch = _decorator


fastapi.APIRouter = APIRouter
fastapi.HTTPException = HTTPException
fastapi.Request = object
sys.modules["fastapi"] = fastapi

responses = types.ModuleType("fastapi.responses")


class Response:
    def __init__(self, content=None, *args, **kwargs):
        self.content = content


responses.FileResponse = Response
responses.PlainTextResponse = Response
responses.StreamingResponse = Response
sys.modules["fastapi.responses"] = responses

queue_module = types.ModuleType("api.queue")
queue_module.get_queue = lambda: None
queue_module.get_redis = lambda: None
sys.modules["api.queue"] = queue_module

PASSED = 0
FAILED = 0


def check(name: str, observed, expected) -> None:
    global PASSED, FAILED
    if observed == expected:
        PASSED += 1
        print(f"PASS {name}")
    else:
        FAILED += 1
        print(f"FAIL {name}: observed={observed!r} expected={expected!r}")


def replace_once(source: str, old: str, new: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"mutation anchor count for {old!r}: {count}")
    return source.replace(old, new, 1)


jobs_source = (ROOT / "api" / "routes" / "jobs.py").read_text(encoding="utf-8")
visibility_guard = (
    '        meta.get("internal") is True\n'
    '        and isinstance(meta.get("parent_job_id"), str)\n'
    '        and bool(meta.get("parent_job_id"))\n'
    '        and isinstance(meta.get("hybrid_stage"), int)\n'
)
visibility_mutants = {
    "drop-visibility-internal": visibility_guard.replace(
        'meta.get("internal") is True', "True", 1
    ),
    "drop-visibility-parent": visibility_guard.replace(
        'and isinstance(meta.get("parent_job_id"), str)\n'
        '        and bool(meta.get("parent_job_id"))',
        "and True",
        1,
    ),
    "drop-visibility-stage": visibility_guard.replace(
        'isinstance(meta.get("hybrid_stage"), int)', "True", 1
    ),
}
membership_guard = (
    '            child.get("internal") is True\n'
    '            and child.get("parent_job_id") == parent_job_id\n'
    '            and child.get("hybrid_stage") == stage.get("stage")\n'
    '            and child.get("module") == stage.get("module")\n'
)
membership_mutants = {
    "drop-membership-internal": membership_guard.replace(
        'child.get("internal") is True', "True", 1
    ),
    "drop-membership-parent": membership_guard.replace(
        'child.get("parent_job_id") == parent_job_id', "True", 1
    ),
    "drop-membership-stage": membership_guard.replace(
        'child.get("hybrid_stage") == stage.get("stage")', "True", 1
    ),
    "drop-membership-module": membership_guard.replace(
        'child.get("module") == stage.get("module")', "True", 1
    ),
    "drop-membership-all": "            True\n",
}
if args.mutate in visibility_mutants:
    jobs_source = replace_once(jobs_source, visibility_guard, visibility_mutants[args.mutate])
elif args.mutate in membership_mutants:
    jobs_source = replace_once(jobs_source, membership_guard, membership_mutants[args.mutate])
elif args.mutate == "expose-child":
    jobs_source = replace_once(
        jobs_source,
        'def _is_internal_hybrid_child(meta: dict) -> bool:\n    """The exact public-visibility predicate from the hybrid contract."""\n    return (',
        'def _is_internal_hybrid_child(meta: dict) -> bool:\n    """mutant"""\n    return False and (',
    )
elif args.mutate == "double-cost":
    jobs_source = replace_once(
        jobs_source,
        "        total_cost += child_cost\n",
        "        total_cost += child_cost * 2\n",
    )
elif args.mutate == "drop-stop-cascade":
    jobs_source = replace_once(
        jobs_source,
        "    for stage, child in _hybrid_children(safe, meta):\n",
        "    for stage, child in []:\n",
    )
elif args.mutate == "drop-delete-cascade":
    jobs_source = replace_once(
        jobs_source,
        "    for _, child in _hybrid_children(parent_job_id, parent_meta):\n",
        "    for _, child in []:\n",
    )

jobs_module = types.ModuleType("hybrid_jobs_route_under_test")
jobs_module.__file__ = str(ROOT / "api" / "routes" / "jobs.py")
exec(compile(jobs_source, jobs_module.__file__, "exec"), jobs_module.__dict__)
jobs_module.JOBS_DIR = JOBS
jobs_module.UPLOADS_DIR = DATA / "uploads"


def write_meta(job_id: str, meta: dict) -> None:
    directory = JOBS / job_id
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "meta.json").write_text(
        json.dumps({"id": job_id, **meta}, indent=2), encoding="utf-8"
    )


def read_meta(job_id: str) -> dict:
    return json.loads((JOBS / job_id / "meta.json").read_text(encoding="utf-8"))


PARENT = "aaaaaaaaaaaa"
ACTIVE = "bbbbbbbbbbbb"
TERMINAL = "cccccccccccc"
ORDINARY = "dddddddddddd"
MALFORMED = "eeeeeeeeeeee"
VISIBILITY_INTERNAL_MISMATCH = "e10000000001"
VISIBILITY_PARENT_MISMATCH = "e10000000002"
VISIBILITY_STAGE_MISMATCH = "e10000000003"


def seed_chain(*, parent_id: str = PARENT, active_id: str = ACTIVE, terminal_id: str = TERMINAL) -> None:
    evidence = [
        {
            "stage": 0,
            "module": "rev",
            "child_job_id": active_id,
            "value": "DH{weak_stage_a}",
            "provenance": {
                "field": "flags",
                "tier": "narrative",
                "sweep_suppressed": False,
            },
            "disposition": "unverified",
        },
        {
            "stage": 1,
            "module": "pwn",
            "child_job_id": terminal_id,
            "value": "DH{confirmed_stage_b}",
            "provenance": {
                "field": "flags",
                "tier": "marker",
                "sweep_suppressed": False,
            },
            "disposition": "confirmed",
        },
    ]
    write_meta(
        parent_id,
        {
            "module": "hybrid",
            "modules": ["rev", "pwn"],
            "status": "running",
            "flags": ["DH{confirmed_stage_b}"],
            "flag_candidates": ["DH{weak_stage_a}"],
            "hybrid": {
                "version": 1,
                "recipe": "rev-pwn",
                "active_stage": 0,
                "stages": [
                    {"stage": 0, "module": "rev", "child_job_id": active_id, "status": "queued"},
                    {"stage": 1, "module": "pwn", "child_job_id": terminal_id, "status": "queued"},
                ],
                "stage_flag_evidence": evidence,
            },
        },
    )
    write_meta(
        active_id,
        {
            "module": "rev",
            "status": "running",
            "internal": True,
            "parent_job_id": parent_id,
            "hybrid_stage": 0,
            "cost_usd": 1.25,
        },
    )
    write_meta(
        terminal_id,
        {
            "module": "pwn",
            "status": "finished",
            "internal": True,
            "parent_job_id": parent_id,
            "hybrid_stage": 1,
            "cost_usd": 0,
        },
    )
    (JOBS / terminal_id / "result.json").write_text(
        json.dumps({"cost_usd": 2.5}), encoding="utf-8"
    )


seed_chain()
write_meta(ORDINARY, {"module": "pwn", "status": "finished", "cost_usd": 4.0})
# `internal` alone is not the contract conjunction and must remain public.
write_meta(MALFORMED, {"module": "rev", "status": "failed", "internal": True})
# Each visibility fixture differs from a valid hidden child in exactly one
# field, so weakening any one predicate cannot silently hide an ordinary job.
write_meta(
    VISIBILITY_INTERNAL_MISMATCH,
    {
        "module": "rev",
        "status": "failed",
        "internal": False,
        "parent_job_id": PARENT,
        "hybrid_stage": 0,
    },
)
write_meta(
    VISIBILITY_PARENT_MISMATCH,
    {
        "module": "rev",
        "status": "failed",
        "internal": True,
        "parent_job_id": "",
        "hybrid_stage": 0,
    },
)
write_meta(
    VISIBILITY_STAGE_MISMATCH,
    {
        "module": "rev",
        "status": "failed",
        "internal": True,
        "parent_job_id": PARENT,
        "hybrid_stage": "0",
    },
)

# Avoid Redis during get_job. The route catches the synthetic failure exactly
# as it catches an unavailable queue in production.
jobs_module.get_queue = lambda: (_ for _ in ()).throw(RuntimeError("fixture queue disabled"))


# -------------------------------------------------------- list / detail / stats
listed = jobs_module.list_jobs()["jobs"]
listed_ids = [meta["id"] for meta in listed]
check(
    "test_public_list_hides_exact_internal_child_conjunction",
    set(listed_ids),
    {
        PARENT,
        ORDINARY,
        MALFORMED,
        VISIBILITY_INTERNAL_MISMATCH,
        VISIBILITY_PARENT_MISMATCH,
        VISIBILITY_STAGE_MISMATCH,
    },
)
check(
    "test_public_list_keeps_job_with_only_internal_mismatch",
    VISIBILITY_INTERNAL_MISMATCH in listed_ids,
    True,
)
check(
    "test_public_list_keeps_job_with_only_parent_mismatch",
    VISIBILITY_PARENT_MISMATCH in listed_ids,
    True,
)
check(
    "test_public_list_keeps_job_with_only_stage_mismatch",
    VISIBILITY_STAGE_MISMATCH in listed_ids,
    True,
)
parent_list = next((meta for meta in listed if meta["id"] == PARENT), {})
check("test_parent_list_sums_child_cost_once", parent_list.get("cost_usd"), 3.75)
check(
    "test_parent_list_overlays_live_child_stage_status",
    [stage.get("status") for stage in (parent_list.get("hybrid") or {}).get("stages", [])],
    ["running", "finished"],
)

stats = jobs_module.get_stats()
check("test_stats_count_public_jobs_only", stats["count"], 6)
check("test_stats_total_has_no_child_double_count", stats["total_cost_usd"], 7.75)
check("test_stats_attributes_chain_once_to_hybrid", stats["by_module"].get("hybrid"), {"count": 1, "cost_usd": 3.75})
check("test_stats_has_no_hidden_scalar_child_bucket", stats["by_module"].get("pwn"), {"count": 1, "cost_usd": 4.0})

detail = jobs_module.get_job(PARENT)
evidence = (detail.get("hybrid") or {}).get("stage_flag_evidence") or []
check("test_parent_detail_keeps_all_stage_evidence", len(evidence), 2)
check(
    "test_parent_detail_evidence_schema_and_provenance",
    [
        (
            row.get("stage"), row.get("module"), row.get("child_job_id"),
            (row.get("provenance") or {}).get("tier"),
            (row.get("provenance") or {}).get("field"), row.get("disposition"),
        )
        for row in evidence
    ],
    [
        (0, "rev", ACTIVE, "narrative", "flags", "unverified"),
        (1, "pwn", TERMINAL, "marker", "flags", "confirmed"),
    ],
)


# --------------------------------------------------------------- stop cascade
hard_stops: list[str] = []


def fake_hard_stop(job_id: str) -> dict:
    hard_stops.append(job_id)
    return {"fixture": job_id}


jobs_module._hard_stop_job = fake_hard_stop
stopped = jobs_module.stop_job(PARENT)
check("test_parent_stop_targets_parent_and_active_child_only", hard_stops, [PARENT, ACTIVE])
check("test_parent_stop_stamps_active_child_terminal", read_meta(ACTIVE)["status"], "stopped")
check("test_parent_stop_stamps_parent_terminal", read_meta(PARENT)["status"], "stopped")
check("test_parent_stop_reports_cascaded_child", [row["id"] for row in stopped["children_stopped"]], [ACTIVE])


# ------------------------------------------------------------- delete cascade
for path in list(JOBS.iterdir()):
    if path.is_dir():
        import shutil
        shutil.rmtree(path)
seed_chain()
hard_stops.clear()
(jobs_module.UPLOADS_DIR / PARENT).mkdir(parents=True)
(jobs_module.UPLOADS_DIR / PARENT / "challenge.zip").write_bytes(b"fixture")
deleted = jobs_module.delete_job(PARENT)
check("test_parent_delete_stops_parent_and_active_child", hard_stops, [PARENT, ACTIVE])
check("test_parent_delete_removes_parent_and_all_linked_children", [
    (JOBS / PARENT).exists(), (JOBS / ACTIVE).exists(), (JOBS / TERMINAL).exists()
], [False, False, False])
check("test_parent_delete_reports_both_children", [row["id"] for row in deleted["children_deleted"]], [ACTIVE, TERMINAL])
check("test_parent_delete_removes_separate_upload", (jobs_module.UPLOADS_DIR / PARENT).exists(), False)

# A forged stage id is never deletion authority without a matching child
# backlink/module/stage conjunction.
FORGED_PARENT = "111111111111"
FORGED_TARGET = "222222222222"
write_meta(FORGED_TARGET, {"module": "pwn", "status": "finished"})
write_meta(
    FORGED_PARENT,
    {
        "module": "hybrid",
        "status": "finished",
        "hybrid": {
            "stages": [
                {"stage": 0, "module": "rev", "child_job_id": FORGED_TARGET, "status": "finished"}
            ]
        },
    },
)
jobs_module.delete_job(FORGED_PARENT)
check("test_forged_stage_link_cannot_delete_unrelated_job", (JOBS / FORGED_TARGET).is_dir(), True)


def check_single_membership_mismatch(
    name: str, parent_id: str, target_id: str, child_override: dict
) -> None:
    child = {
        "module": "rev",
        "status": "finished",
        "internal": True,
        "parent_job_id": parent_id,
        "hybrid_stage": 0,
    }
    child.update(child_override)
    write_meta(target_id, child)
    write_meta(
        parent_id,
        {
            "module": "hybrid",
            "status": "finished",
            "hybrid": {
                "stages": [
                    {
                        "stage": 0,
                        "module": "rev",
                        "child_job_id": target_id,
                        "status": "finished",
                    }
                ]
            },
        },
    )
    jobs_module.delete_job(parent_id)
    check(name, (JOBS / target_id).is_dir(), True)


# Each fixture differs from a valid child link in exactly one field. This makes
# every deletion-authority predicate independently observable to mutation tests.
check_single_membership_mismatch(
    "test_delete_rejects_child_with_only_internal_mismatch",
    "f10000000001",
    "f20000000001",
    {"internal": False},
)
check_single_membership_mismatch(
    "test_delete_rejects_child_with_only_parent_mismatch",
    "f10000000002",
    "f20000000002",
    {"parent_job_id": "f30000000002"},
)
check_single_membership_mismatch(
    "test_delete_rejects_child_with_only_stage_mismatch",
    "f10000000003",
    "f20000000003",
    {"hybrid_stage": 1},
)
check_single_membership_mismatch(
    "test_delete_rejects_child_with_only_module_mismatch",
    "f10000000004",
    "f20000000004",
    {"module": "pwn"},
)

for path in list(JOBS.iterdir()):
    if path.is_dir():
        import shutil
        shutil.rmtree(path)
BULK_PARENT = "333333333333"
BULK_ACTIVE = "444444444444"
BULK_TERMINAL = "555555555555"
seed_chain(parent_id=BULK_PARENT, active_id=BULK_ACTIVE, terminal_id=BULK_TERMINAL)
hard_stops.clear()
bulk = jobs_module.bulk_delete_jobs(all=True)
check("test_bulk_delete_counts_only_public_parent", (bulk["deleted"], bulk["ids"]), (1, [BULK_PARENT]))
check(
    "test_bulk_parent_delete_removes_hidden_children",
    [(JOBS / job_id).exists() for job_id in (BULK_PARENT, BULK_ACTIVE, BULK_TERMINAL)],
    [False, False, False],
)


# ------------------------------------------------------------ UI / retry gate
app_source = (ROOT / "web-ui" / "app.js").read_text(encoding="utf-8")
if args.mutate == "drop-evidence":
    app_source = replace_once(
        app_source,
        "const evidence = Array.isArray(hybrid.stage_flag_evidence)",
        "const evidence = Array.isArray([])",
    )
elif args.mutate == "expose-retry":
    app_source = replace_once(
        app_source,
        'const isExploitableModule = ["web", "pwn", "crypto", "rev"].includes(job.module);',
        'const isExploitableModule = ["web", "pwn", "crypto", "rev", "hybrid"].includes(job.module);',
    )

check("test_ui_reads_canonical_stage_evidence", "Array.isArray(hybrid.stage_flag_evidence)" in app_source, True)
for label in ("stage", "module", "child id", "provenance tier / source", "disposition"):
    check(f"test_ui_names_stage_evidence_field_{label.replace(' ', '_').replace('/', '_')}", label in app_source, True)

module_match = re.search(
    r"const isExploitableModule = \[([^\]]+)\]\.includes\(job\.module\);",
    app_source,
)
retry_modules = set(re.findall(r'"([a-z0-9-]+)"', module_match.group(1))) if module_match else set()
check("test_hybrid_parent_retry_controls_are_not_exposed", retry_modules, {"web", "pwn", "crypto", "rev"})

retry_source = (ROOT / "api" / "routes" / "retry.py").read_text(encoding="utf-8")
check("test_scalar_retry_backend_does_not_accept_hybrid", '"hybrid"' in retry_source[retry_source.find("def _resubmit("):retry_source.find("def _continue_in_place(")], False)

readme = (ROOT / "README.md").read_text(encoding="utf-8")
check("test_parent_child_delete_policy_is_documented", "deletes **all** validated linked child directories" in readme, True)
check("test_retry_visibility_policy_is_documented", "Parent Retry/Continue/Resume controls stay" in readme, True)


print(
    f"hybrid-lifecycle: {PASSED} passed, {FAILED} failed; "
    f"mutation={args.mutate or 'none'}"
)
TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
