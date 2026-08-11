#!/usr/bin/env python3
"""S1 hybrid coordinator lifecycle, evidence, and isolated handoff contract.

Every check is named and the mutation modes alter the imported production
objects in this test process only.  A mutation that raises from a coordinator
call is contained by the affected check, so the remaining independent checks
still reach the summary.  ``predicate-tier`` mirrors the equivalent production
edit exactly, including its failure count.

Run: python3 scripts/test_hybrid_coordinator.py [--mutate NAME]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules.hybrid import coordinator as C


MUTATIONS = (
    "predicate-tier",
    "predicate-suppressed",
    "weak-promotion",
    "terminal-status",
    "drop-child-id",
    "drop-provenance",
    "allow-undeclared",
    "skip-hash",
    "copy-reference",
    "parent-artifact",
)

parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()


# Most mutations preserve call signatures and control flow so the full harness
# reaches summary.  predicate-tier is intentionally the exact semantic
# equivalent of replacing the production marker comparison with True; its
# completion behavior is part of the mutation/direct-edit parity check.
if args.mutate == "predicate-tier":
    C.is_confirmed_capture = lambda meta: (
        meta.get("status") == "finished"
        and bool(meta.get("flags"))
        and True
        and meta.get("flag_sweep_suppressed") is not True
    )
elif args.mutate == "predicate-suppressed":
    C.is_confirmed_capture = lambda meta: (
        meta.get("status") == "finished"
        and bool(meta.get("flags"))
        and meta.get("flag_provenance") == "marker"
    )
elif args.mutate == "weak-promotion":
    _real_project = C._project_evidence

    def _promote_weak(records):
        flags, candidates = _real_project(records)
        return flags + [v for v in candidates if v not in flags], []

    C._project_evidence = _promote_weak
elif args.mutate == "terminal-status":
    C._terminal_parent_status = lambda records: "finished"
elif args.mutate == "drop-child-id":
    _real_records = C._evidence_records

    def _without_child_id(*pos, **kw):
        records = _real_records(*pos, **kw)
        if pos and pos[0] == 1:
            for record in records:
                record.pop("child_job_id", None)
        return records

    C._evidence_records = _without_child_id
elif args.mutate == "drop-provenance":
    _real_records = C._evidence_records

    def _without_provenance(*pos, **kw):
        records = _real_records(*pos, **kw)
        if pos and pos[0] == 1:
            for record in records:
                record.pop("provenance", None)
        return records

    C._evidence_records = _without_provenance
elif args.mutate == "allow-undeclared":
    C._path_allowed = lambda relative: True
elif args.mutate == "skip-hash":
    C.HybridCoordinator.verify_handoff = lambda self, child: dict(
        self._read_meta(child).get("hybrid_handoff") or {}
    )
elif args.mutate == "copy-reference":
    _real_copy = C.HybridCoordinator._copy_handoff

    def _hardlink_copy(self, source_id, target_id, target_module, declared, candidates):
        manifest = _real_copy(
            self, source_id, target_id, target_module, declared, candidates
        )
        for entry in manifest["files"]:
            rel = Path(entry["path"])
            source = self._job_dir(source_id) / rel
            target = self._job_dir(target_id) / "handoff" / rel
            target.unlink()
            os.link(source, target)
        return manifest

    C.HybridCoordinator._copy_handoff = _hardlink_copy
elif args.mutate == "parent-artifact":
    _real_parent_write = C.HybridCoordinator._write_parent

    def _write_parent_artifact(self, parent_id, meta):
        _real_parent_write(self, parent_id, meta)
        if meta.get("status") in C.TERMINAL_STATUSES:
            (self._job_dir(parent_id) / "report.md").write_text(
                "leaked DH{parent_artifact_leak}\n", encoding="utf-8"
            )

    C.HybridCoordinator._write_parent = _write_parent_artifact


TMP = tempfile.TemporaryDirectory(prefix="hybrid-s1-")
JOBS = Path(TMP.name) / "jobs"
COORD = C.HybridCoordinator(JOBS)
PASSED = FAILED = 0


def check(label: str, got, want=True) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
    else:
        FAILED += 1
        print(f"FAIL  {label}\n      got  = {got!r}\n      want = {want!r}")


def expect_error(label: str, fn, error=C.HybridCoordinatorError) -> None:
    try:
        fn()
    except error:
        check(label, True)
    except Exception as exc:  # keep the mutation battery running to summary
        check(label, f"wrong exception: {type(exc).__name__}: {exc}", True)
    else:
        check(label, False)


CASE_FAILED = object()


def capture_case(label: str, fn):
    """Turn an unexpected exception from one check into a named failure."""

    try:
        return fn()
    except Exception as exc:  # keep later independent checks running to summary
        check(label, f"unexpected exception: {type(exc).__name__}: {exc}", True)
        return CASE_FAILED


def meta(job_id: str) -> dict:
    return json.loads((JOBS / job_id / "meta.json").read_text(encoding="utf-8"))


def update(job_id: str, **values) -> dict:
    value = meta(job_id)
    value.update(values)
    (JOBS / job_id / "meta.json").write_text(
        json.dumps(value, indent=2) + "\n", encoding="utf-8"
    )
    return value


_seq = 0


def ids(label: str) -> tuple[str, str, str]:
    global _seq
    _seq += 1
    base = f"{label}-{_seq}"
    return f"{base}-parent", f"{base}-a", f"{base}-b"


def start_chain(label: str, recipe="rev-pwn") -> tuple[str, str, str]:
    parent, first, second = ids(label)
    COORD.create_parent(parent, recipe, meta={"description": label})
    COORD.start(parent, first, child_meta={"description": f"{label}-stage-a"})
    return parent, first, second


def run_two_stage(label: str, first_result: dict, second_result: dict) -> tuple[dict, str, str, str]:
    parent, first, second = start_chain(label)
    update(first, **first_result)
    COORD.advance(parent, next_child_job_id=second)
    COORD.verify_handoff(second)
    update(second, **second_result)
    return COORD.advance(parent), parent, first, second


# ---------------------------------------------------------------- predicate
PREDICATE_ROWS = (
    ("marker", {"status": "finished", "flags": ["DH{m}"], "flag_provenance": "marker"}, True),
    ("runner_regex", {"status": "finished", "flags": ["DH{r}"], "flag_provenance": "runner_regex"}, False),
    ("narrative", {"status": "finished", "flags": ["DH{n}"], "flag_provenance": "narrative"}, False),
    ("provenance_absent", {"status": "finished", "flags": ["DH{x}"]}, False),
    ("suppressed_marker", {"status": "finished", "flags": ["DH{s}"], "flag_provenance": "marker", "flag_sweep_suppressed": True}, False),
    ("finished_no_flags", {"status": "finished", "flags": [], "flag_provenance": "marker"}, False),
    ("no_flag", {"status": "no_flag", "flags": [], "flag_provenance": "marker"}, False),
)
for name, row, expected in PREDICATE_ROWS:
    check(f"test_confirmed_predicate_{name}", C.is_confirmed_capture(row), expected)


# ------------------------------------------------------------------- schema
parent, first, _ = start_chain("schema", recipe="web-pwn")
pm, cm = meta(parent), meta(first)
check(
    "test_parent_schema_module_modules_hybrid",
    (pm["module"], pm["modules"], pm["hybrid"]["version"], pm["hybrid"]["recipe"]),
    ("hybrid", ["web", "pwn"], 1, "web-pwn"),
)
check(
    "test_parent_schema_active_stage_and_ordered_stages",
    (pm["status"], pm["hybrid"]["active_stage"], [(s["stage"], s["module"]) for s in pm["hybrid"]["stages"]]),
    ("running", 0, [(0, "web"), (1, "pwn")]),
)
check(
    "test_child_schema_scalar_internal_parent_stage",
    (cm["module"], cm["internal"], cm["parent_job_id"], cm["hybrid_stage"]),
    ("web", True, parent, 0),
)
expect_error(
    "test_recipe_allowlist_rejects_arbitrary_pair",
    lambda: COORD.create_parent("bad-recipe", "crypto-pwn"),
)
expect_error(
    "test_parent_reserved_schema_cannot_be_overridden",
    lambda: COORD.create_parent("bad-parent-fields", "rev-pwn", meta={"module": "pwn"}),
)
expect_error(
    "test_child_reserved_schema_cannot_be_overridden",
    lambda: (
        COORD.create_parent("bad-child-fields-p", "rev-pwn"),
        COORD.start("bad-child-fields-p", "bad-child-fields-a", child_meta={"internal": False}),
    ),
)


# ------------------------------------------------------- six terminal cases
p, a, _ = start_chain("a-confirmed")
update(
    a,
    status="finished",
    flags=["DH{a_confirmed}"],
    flag_candidates=["DH{stream_candidate}"],
    flag_provenance="marker",
    flag_sweep_suppressed=False,
)
result = COORD.advance(p)
check(
    "test_terminal_1_a_confirmed_skips_b",
    (result["status"], result["flags"], result["flag_candidates"], result["hybrid"]["stages"][1]["child_job_id"]),
    ("finished", ["DH{a_confirmed}"], ["DH{stream_candidate}"], None),
)

terminal_2 = capture_case(
    "test_terminal_2_a_weak_b_no_flag",
    lambda: run_two_stage(
        "weak-no-flag",
        {
            "status": "finished",
            "flags": ["DH{a_weak}"],
            "flag_provenance": "narrative",
        },
        {"status": "no_flag", "flags": []},
    ),
)
if terminal_2 is not CASE_FAILED:
    result, _, _, _ = terminal_2
    check(
        "test_terminal_2_a_weak_b_no_flag",
        (result["status"], result["flags"], result["flag_candidates"]),
        ("no_flag", [], ["DH{a_weak}"]),
    )

terminal_3 = capture_case(
    "test_terminal_3_a_weak_b_confirmed",
    lambda: run_two_stage(
        "weak-confirmed",
        {
            "status": "finished",
            "flags": ["DH{a_weak_2}"],
            "flag_provenance": "narrative",
        },
        {
            "status": "finished",
            "flags": ["DH{b_confirmed}"],
            "flag_provenance": "marker",
            "flag_sweep_suppressed": False,
        },
    ),
)
if terminal_3 is not CASE_FAILED:
    result, _, _, _ = terminal_3
    check(
        "test_terminal_3_a_weak_b_confirmed",
        (result["status"], result["flags"], result["flag_candidates"]),
        ("finished", ["DH{b_confirmed}"], ["DH{a_weak_2}"]),
    )

terminal_4 = capture_case(
    "test_terminal_4_both_weak_exhausts_as_no_flag",
    lambda: run_two_stage(
        "both-weak",
        {
            "status": "finished",
            "flags": ["DH{a_weak_3}"],
            "flag_provenance": "narrative",
        },
        {
            "status": "finished",
            "flags": ["DH{b_weak}"],
            "flag_provenance": "runner_regex",
        },
    ),
)
if terminal_4 is not CASE_FAILED:
    result, _, _, _ = terminal_4
    check(
        "test_terminal_4_both_weak_exhausts_as_no_flag",
        (result["status"], result["flags"], result["flag_candidates"]),
        ("no_flag", [], ["DH{a_weak_3}", "DH{b_weak}"]),
    )

result, _, _, _ = run_two_stage(
    "both-no-flag",
    {"status": "no_flag", "flags": []},
    {"status": "no_flag", "flags": []},
)
check(
    "test_terminal_5_both_no_flag_has_empty_evidence",
    (result["status"], result["flags"], result["flag_candidates"], result["hybrid"]["stage_flag_evidence"]),
    ("no_flag", [], [], []),
)

failure_observations = []
for where, status in (("a", "failed"), ("a", "stopped"), ("b", "failed"), ("b", "stopped")):
    if where == "a":
        fp, fa, _ = start_chain(f"{where}-{status}")
        update(fa, status=status, flags=[], flag_candidates=[f"DH{{{where}_{status}}}"])
        terminal = COORD.advance(fp)
    else:
        fp, fa, fb = start_chain(f"{where}-{status}")
        update(fa, status="no_flag", flags=[])
        COORD.advance(fp, next_child_job_id=fb)
        update(fb, status=status, flags=[], flag_candidates=[f"DH{{{where}_{status}}}"])
        terminal = COORD.advance(fp)
    failure_observations.append(
        (
            where,
            status,
            terminal["status"],
            terminal["flag_candidates"][-1]
            if terminal["flag_candidates"]
            else None,
        )
    )
check(
    "test_terminal_6_failed_stopped_propagate_and_keep_evidence",
    failure_observations,
    [
        ("a", "failed", "failed", "DH{a_failed}"),
        ("a", "stopped", "stopped", "DH{a_stopped}"),
        ("b", "failed", "failed", "DH{b_failed}"),
        ("b", "stopped", "stopped", "DH{b_stopped}"),
    ],
)


# ------------------------------------------------------- canonical evidence
same = "DH{same_across_stages}"
collision = capture_case(
    "test_cross_stage_same_value_projects_once_but_keeps_two_records",
    lambda: run_two_stage(
        "collision",
        {
            "status": "finished",
            "flags": [same],
            "flag_candidates": [same],
            "flag_provenance": "narrative",
        },
        {
            "status": "finished",
            "flags": [same],
            "flag_provenance": "marker",
            "flag_sweep_suppressed": False,
        },
    ),
)
if collision is not CASE_FAILED:
    result, _, first, second = collision
    records = result["hybrid"]["stage_flag_evidence"]
    check(
        "test_cross_stage_same_value_projects_once_but_keeps_two_records",
        (result["flags"], result["flag_candidates"], len(records)),
        ([same], [], 2),
    )
    check(
        "test_evidence_preserves_stage_module_child_and_disposition",
        [
            (
                r.get("stage"),
                r.get("module"),
                r.get("child_job_id"),
                r.get("disposition"),
            )
            for r in records
        ],
        [(0, "rev", first, "unverified"), (1, "pwn", second, "confirmed")],
    )
    check(
        "test_evidence_preserves_provenance_object",
        [r.get("provenance") for r in records],
        [
            {"field": "flags", "tier": "narrative", "sweep_suppressed": None},
            {"field": "flags", "tier": "marker", "sweep_suppressed": False},
        ],
    )

p, a, _ = start_chain("candidate-provenance")
update(a, status="failed", flags=[], flag_candidates=["DH{candidate_only}"])
candidate_result = COORD.advance(p)
candidate_record = candidate_result["hybrid"]["stage_flag_evidence"][0]
check(
    "test_candidate_record_uses_honest_null_provenance",
    candidate_record.get("provenance"),
    {"field": "flag_candidates", "tier": None, "sweep_suppressed": None},
)

snapshot_parent, snapshot_a, snapshot_b = start_chain("stage-snapshot")
update(
    snapshot_a,
    status="finished",
    flags=["DH{stage_a_weak_snapshot}"],
    flag_provenance="narrative",
)
snapshot_started = capture_case(
    "test_completed_stage_evidence_snapshot_is_not_reread_or_promoted",
    lambda: COORD.advance(snapshot_parent, next_child_job_id=snapshot_b),
)
if snapshot_started is not CASE_FAILED:
    # A terminal analyzer may still flush unrelated bookkeeping.  Even if its
    # evidence fields are corrupted later, the parent-owned completed-stage
    # snapshot must not silently change while B is running.
    update(
        snapshot_a,
        status="finished",
        flags=["DH{rewritten_as_confirmed}"],
        flag_provenance="marker",
        flag_sweep_suppressed=False,
    )
    update(snapshot_b, status="no_flag", flags=[])
    snapshot_result = COORD.advance(snapshot_parent)
    check(
        "test_completed_stage_evidence_snapshot_is_not_reread_or_promoted",
        (
            snapshot_result["status"],
            snapshot_result["flags"],
            snapshot_result["flag_candidates"],
            snapshot_result["hybrid"]["stage_flag_evidence"][0]["value"],
        ),
        (
            "no_flag",
            [],
            ["DH{stage_a_weak_snapshot}"],
            "DH{stage_a_weak_snapshot}",
        ),
    )


# ------------------------------------------------ parent meta-only boundary
p, a, b = start_chain("meta-only")
update(a, status="finished", flags=["DH{weak_parent_only}"], flag_provenance="narrative")
meta_only_started = capture_case(
    "test_parent_meta_only_lifecycle_reaches_second_stage",
    lambda: COORD.advance(p, next_child_job_id=b),
)
if meta_only_started is not CASE_FAILED:
    update(b, status="no_flag", flags=[])
    capture_case(
        "test_parent_meta_only_lifecycle_reaches_terminal",
        lambda: COORD.advance(p),
    )
parent_files = sorted(path.name for path in (JOBS / p).iterdir())
check("test_parent_directory_contains_meta_json_only", parent_files, ["meta.json"])

# Exercise the actual production scanner, not a local approximation.
from modules import _common as COMMON  # noqa: E402

COMMON.JOBS_DIR = JOBS
COMMON.job_dir = lambda job_id: JOBS / Path(job_id).name
check(
    "test_actual_scan_job_for_flags_parent_is_empty",
    COMMON.scan_job_for_flags(p),
    [],
)

extra_parent, _, _ = ids("parent-extra")
COORD.create_parent(extra_parent, "rev-pwn")
(JOBS / extra_parent / "report.md").write_text("DH{must_not_exist}\n", encoding="utf-8")
expect_error(
    "test_parent_artifact_boundary_rejects_preexisting_extra_file",
    lambda: COORD.start(extra_parent, "parent-extra-child"),
    C.HybridStateError,
)


# --------------------------------------------------------- manifest handoff
p, a, b = start_chain("handoff")
source = JOBS / a
(source / "report.md").write_text("report-A", encoding="utf-8")
(source / "findings.json").write_text('{"ok":true}\n', encoding="utf-8")
(source / "solver.py").write_text("print('solver')\n", encoding="utf-8")
(source / "decomp").mkdir()
(source / "decomp" / "main.c").write_text("int main(){}\n", encoding="utf-8")
(source / "src").mkdir()
(source / "src" / "challenge.bin").write_bytes(b"\x00\x01challenge")
(source / "secret.txt").write_text("never-copy", encoding="utf-8")
update(
    a,
    status="finished",
    flags=["DH{handoff_hypothesis}"],
    flag_provenance="narrative",
)
handoff_started = capture_case(
    "test_manifest_copies_only_declared_allowlisted_files",
    lambda: COORD.advance(
        p,
        next_child_job_id=b,
        handoff_paths=("report.md", "findings.json", "solver.py", "decomp", "src"),
    ),
)
if handoff_started is not CASE_FAILED:
    manifest = COORD.verify_handoff(b)
    manifest_paths = [entry["path"] for entry in manifest["files"]]
    check(
        "test_manifest_copies_only_declared_allowlisted_files",
        manifest_paths,
        [
            "decomp/main.c",
            "findings.json",
            "report.md",
            "solver.py",
            "src/challenge.bin",
        ],
    )
    check(
        "test_manifest_does_not_copy_undeclared_sibling",
        (JOBS / b / "handoff" / "secret.txt").exists(),
        False,
    )
    check(
        "test_manifest_hash_is_bound_into_parent_stage_and_child",
        (
            meta(p)["hybrid"]["stages"][0]["handoff_sha256"],
            meta(b)["hybrid_handoff"]["sha256"],
        ),
        (manifest["sha256"], manifest["sha256"]),
    )
    check(
        "test_manifest_carries_weak_value_provenance_and_source_child",
        manifest["unverified_flag_candidates"],
        [
            {
                "stage": 0,
                "module": "rev",
                "child_job_id": a,
                "value": "DH{handoff_hypothesis}",
                "provenance": {
                    "field": "flags",
                    "tier": "narrative",
                    "sweep_suppressed": None,
                },
                "disposition": "unverified",
            }
        ],
    )
    source_report_before = (source / "report.md").read_text(encoding="utf-8")
    target_report = JOBS / b / "handoff" / "report.md"
    check(
        "test_handoff_uses_distinct_files_not_shared_rw_inode",
        os.stat(source / "report.md").st_ino == os.stat(target_report).st_ino,
        False,
    )
    target_report.write_text(
        "report-B", encoding="utf-8"
    )  # same length, hash-only detection
    check(
        "test_handoff_target_mutation_does_not_change_source_snapshot",
        (source / "report.md").read_text(encoding="utf-8"),
        source_report_before,
    )
    expect_error(
        "test_manifest_detects_same_size_content_tamper_by_hash",
        lambda: COORD.verify_handoff(b),
        C.HandoffValidationError,
    )


def make_handoff(label: str) -> tuple[str, str, str]:
    hp, ha, hb = start_chain(label)
    (JOBS / ha / "report.md").write_text("report", encoding="utf-8")
    update(ha, status="no_flag", flags=[])
    COORD.advance(hp, next_child_job_id=hb, handoff_paths=("report.md",))
    return hp, ha, hb


_, _, extra_b = make_handoff("manifest-extra")
(JOBS / extra_b / "handoff" / "unlisted.txt").write_text("extra", encoding="utf-8")
expect_error(
    "test_manifest_rejects_unlisted_target_file",
    lambda: COORD.verify_handoff(extra_b),
    C.HandoffValidationError,
)

_, _, tampered_b = make_handoff("manifest-meta-tamper")
tampered = meta(tampered_b)
tampered["hybrid_handoff"]["sha256"] = "0" * 64
(JOBS / tampered_b / "meta.json").write_text(json.dumps(tampered), encoding="utf-8")
expect_error(
    "test_manifest_rejects_manifest_object_tamper",
    lambda: COORD.verify_handoff(tampered_b),
    C.HandoffValidationError,
)


def invalid_handoff(label: str, requested: tuple[str, ...], prepare=None) -> None:
    hp, ha, hb = start_chain(label)
    if prepare:
        prepare(JOBS / ha)
    update(ha, status="no_flag", flags=[])
    expect_error(
        f"test_manifest_rejects_{label}",
        lambda: COORD.advance(hp, next_child_job_id=hb, handoff_paths=requested),
        C.HandoffValidationError,
    )


invalid_handoff(
    "undeclared_file",
    ("secret.txt",),
    lambda d: (d / "secret.txt").write_text("secret", encoding="utf-8"),
)
invalid_handoff("absolute_path", ("/etc/passwd",))
invalid_handoff("parent_traversal", ("../meta.json",))


def prepare_symlink(directory: Path) -> None:
    (directory / "src").mkdir()
    (directory / "outside.txt").write_text("outside", encoding="utf-8")
    (directory / "src" / "link.txt").symlink_to(directory / "outside.txt")


invalid_handoff("symlink", ("src",), prepare_symlink)


def prepare_nested_symlink(directory: Path) -> None:
    (directory / "src").mkdir()
    (directory / "outside-dir").mkdir()
    (directory / "outside-dir" / "payload.bin").write_bytes(b"outside")
    (directory / "src" / "link").symlink_to(
        directory / "outside-dir", target_is_directory=True
    )


invalid_handoff(
    "nested_symlink_component",
    ("src/link/payload.bin",),
    prepare_nested_symlink,
)

sp, sa, _ = start_chain("shared-dir")
update(sa, status="no_flag", flags=[])
expect_error(
    "test_manifest_rejects_shared_rw_child_directory",
    lambda: COORD.advance(sp, next_child_job_id=sa),
    C.HandoffValidationError,
)


# ---------------------------------------------------------- state fail-close
np, na, _ = start_chain("nonterminal")
expect_error(
    "test_lifecycle_rejects_nonterminal_active_child",
    lambda: COORD.advance(np),
    C.HybridStateError,
)

xp, xa, _ = start_chain("crosslink")
update(xa, status="no_flag", parent_job_id="another-parent")
expect_error(
    "test_lifecycle_rejects_child_parent_crosslink",
    lambda: COORD.advance(xp, next_child_job_id="crosslink-b"),
    C.HybridStateError,
)


print(
    f"hybrid-coordinator: {PASSED} passed, {FAILED} failed; "
    f"mutation={args.mutate or 'none'}"
)
TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
