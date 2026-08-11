#!/usr/bin/env python3
"""S3.5 hybrid queue/worker completion and direct-source mutation battery.

The harness compiles the production worker source, runs its real coordinator
against isolated job directories, and replaces only the expensive scalar
analyzers with deterministic terminal-result fixtures.  Every lifecycle path
still traverses the production ``start -> scalar run_job -> advance`` wiring.

Run: python3 scripts/test_hybrid_worker.py [--mutate NAME]
"""

from __future__ import annotations

import argparse
import io
import json
import shutil
import sys
import tempfile
import types
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

MUTATIONS = (
    "none",
    "drop-start",
    "drop-stage-a",
    "invert-confirmed",
    "drop-handoff-verify",
    "drop-handoff-staging",
    "unsafe-handoff-root",
    "drop-empty-bin",
    "ignore-src-bundle-mismatch",
    "drop-stage-b",
    "drop-final-advance",
    "replace-web-runner",
    "drop-rev-zip-picker",
    "raise-stage-b-transition",
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS, default="none")
args = parser.parse_args()

passed = failed = 0


def check(label: str, got, want=True) -> None:
    global passed, failed
    if got == want:
        passed += 1
        print(f"PASS  {label}")
    else:
        failed += 1
        print(f"FAIL  {label}\n      got  = {got!r}\n      want = {want!r}")


def replace_once(source: str, old: str, new: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"mutation anchor count is {count}, expected 1: {old!r}")
    return source.replace(old, new, 1)


worker_path = ROOT / "modules" / "hybrid" / "worker.py"
worker_source = worker_path.read_text(encoding="utf-8")
if args.mutate == "drop-start":
    worker_source = replace_once(
        worker_source,
        '''        parent = coordinator.start(\n            parent_job_id,\n            first_child_job_id,\n            child_meta=_child_meta(\n                parent_job_id, parent, first_child_job_id, first_module\n            ),\n        )\n''',
        "        pass  # direct mutation: stage A is never created\n",
    )
elif args.mutate == "drop-stage-a":
    worker_source = replace_once(
        worker_source,
        '''            first_meta = _execute_child(\n                parent_job_id, parent, first_child_job_id, first_module\n            )\n''',
        "            first_meta = _read_meta(first_child_job_id)\n",
    )
elif args.mutate == "invert-confirmed":
    worker_source = replace_once(
        worker_source,
        "    if is_confirmed_capture(first_meta):\n",
        "    if not is_confirmed_capture(first_meta):\n",
    )
elif args.mutate == "drop-handoff-verify":
    worker_source = replace_once(
        worker_source,
        "        coordinator.verify_handoff(second_child_job_id)\n",
        "        pass  # direct mutation: handoff is not verified\n",
    )
elif args.mutate == "drop-handoff-staging":
    worker_source = replace_once(
        worker_source,
        "        _stage_verified_handoff(second_child_job_id)\n",
        "        pass  # direct mutation: handoff never reaches scalar cwd\n",
    )
elif args.mutate == "unsafe-handoff-root":
    worker_source = replace_once(
        worker_source,
        '    target = work_dir / "src" / "hybrid_handoff"\n',
        '    target = work_dir / "handoff"\n',
    )
elif args.mutate == "drop-empty-bin":
    worker_source = replace_once(
        worker_source,
        '''    if module in {"rev", "pwn"}:\n        # Scalar rev/pwn ingest creates bin/ even for remote-only jobs; their\n        # analyzers unconditionally copy that directory into the work tree.\n        (child_dir / "bin").mkdir(parents=True, exist_ok=True)\n''',
        "    pass  # direct mutation: remote-only scalar input dir is absent\n",
    )
elif args.mutate == "ignore-src-bundle-mismatch":
    worker_source = replace_once(
        worker_source,
        '''    if stored_path != expected_path:\n        raise HybridStateError("hybrid parent src_bundle is outside its upload directory")\n''',
        "    pass  # direct mutation: persisted source path is not checked\n",
    )
elif args.mutate == "drop-stage-b":
    worker_source = replace_once(
        worker_source,
        "        _execute_child(parent_job_id, parent, second_child_job_id, second_module)\n",
        "        _read_meta(second_child_job_id)\n",
    )
elif args.mutate == "drop-final-advance":
    worker_source = replace_once(
        worker_source,
        '''        _execute_child(parent_job_id, parent, second_child_job_id, second_module)\n        return coordinator.advance(parent_job_id)\n''',
        '''        _execute_child(parent_job_id, parent, second_child_job_id, second_module)\n        return _read_meta(parent_job_id)\n''',
    )
elif args.mutate == "replace-web-runner":
    worker_source = replace_once(
        worker_source,
        '    "web": "modules.web.analyzer.run_job",\n',
        '    "web": "modules.pwn.analyzer.run_job",\n',
    )
elif args.mutate == "drop-rev-zip-picker":
    worker_source = replace_once(
        worker_source,
        "    picked = _first_binary_in(bin_dir) or _largest_non_archive(bin_dir)\n",
        "    picked = None\n",
    )
elif args.mutate == "raise-stage-b-transition":
    worker_source = replace_once(
        worker_source,
        "        handoff_paths = _handoff_paths(first_child_job_id)\n",
        '        raise RuntimeError("injected stage-B transition failure")\n',
    )

worker_ns = {"__name__": "hybrid_worker_under_test"}
exec(compile(worker_source, str(worker_path), "exec"), worker_ns)
W = types.SimpleNamespace(**worker_ns)

from modules import _common as COMMON  # noqa: E402
from modules.hybrid.coordinator import HybridCoordinator  # noqa: E402


tmp = tempfile.TemporaryDirectory(prefix="hybrid-s35-")
DATA = Path(tmp.name)
JOBS = DATA / "jobs"
UPLOADS = DATA / "uploads"
JOBS.mkdir()
UPLOADS.mkdir()
W.JOBS_DIR = JOBS
W.UPLOADS_DIR = UPLOADS
worker_ns["JOBS_DIR"] = JOBS
worker_ns["UPLOADS_DIR"] = UPLOADS
COMMON.JOBS_DIR = JOBS
COMMON.job_dir = lambda job_id: JOBS / Path(job_id).name

id_counter = 0xA35000000000


def next_id() -> str:
    global id_counter
    id_counter += 1
    return f"{id_counter:012x}"


W.new_job_id = next_id
worker_ns["new_job_id"] = next_id
plans: dict[str, list[dict]] = {}
runner_calls: list[dict] = []
verified_children: set[str] = set()
verify_calls: list[str] = []
occupy_staging_for_children: set[str] = set()


def read_meta(job_id: str) -> dict:
    return json.loads((JOBS / job_id / "meta.json").read_text(encoding="utf-8"))


def write_meta(job_id: str, **values) -> dict:
    meta = read_meta(job_id)
    meta.update(values)
    (JOBS / job_id / "meta.json").write_text(
        json.dumps(meta, indent=2) + "\n", encoding="utf-8"
    )
    return meta


real_verify = HybridCoordinator.verify_handoff


def counted_verify(self, child_job_id):
    manifest = real_verify(self, child_job_id)
    verify_calls.append(child_job_id)
    verified_children.add(child_job_id)
    if child_job_id in occupy_staging_for_children:
        (JOBS / child_job_id / "work" / "src" / "hybrid_handoff").mkdir(
            parents=True
        )
    return manifest


HybridCoordinator.verify_handoff = counted_verify


def scalar_runner(module: str):
    def run(*positional):
        child_job_id = positional[0]
        child = read_meta(child_job_id)
        parent_job_id = child["parent_job_id"]
        stage = child["hybrid_stage"]
        plan = plans[parent_job_id][stage]
        handoff_ok = stage == 0 or (
            child_job_id in verified_children
            and (JOBS / child_job_id / "handoff").is_dir()
            and (JOBS / child_job_id / "work" / "src" / "hybrid_handoff").is_dir()
            and "prior-stage flag observation as an unverified hypothesis"
            in str(child.get("description") or "")
        )
        prior_report_isolated = stage == 0 or COMMON._deep_search_for(
            JOBS / child_job_id / "work", "report.md"
        ) is None
        runner_calls.append(
            {
                "parent": parent_job_id,
                "child": child_job_id,
                "stage": stage,
                "module": module,
                "args": positional,
                "auto_run_meta": child.get("auto_run"),
                "provider": child.get("agent_provider"),
                "handoff_ok": handoff_ok,
                "prior_report_isolated": prior_report_isolated,
                "input_dir_ready": module == "web"
                or (JOBS / child_job_id / "bin").is_dir(),
                "input_bytes": (
                    (
                        Path(positional[1]) / str(child.get("filename"))
                    ).read_bytes()
                    if module == "web"
                    and positional[1]
                    and child.get("filename")
                    and (Path(positional[1]) / str(child.get("filename"))).is_file()
                    else (
                        (JOBS / child_job_id / "bin" / str(child.get("filename"))).read_bytes()
                        if module in {"rev", "pwn"}
                        and child.get("filename")
                        and (JOBS / child_job_id / "bin" / str(child.get("filename"))).is_file()
                        else None
                    )
                ),
            }
        )
        if plan.get("raise"):
            raise RuntimeError(plan["raise"])
        if stage == 0 and plan.get("artifact"):
            (JOBS / child_job_id / "report.md").write_text(
                plan["artifact"] + "\n", encoding="utf-8"
            )
        if stage == 0 and plan.get("parent_extra"):
            (JOBS / parent_job_id / str(plan["parent_extra"])).write_text(
                "transition guard fixture\n", encoding="utf-8"
            )
        values = {
            key: value
            for key, value in plan.items()
            if key not in {"artifact", "parent_extra", "raise"}
        }
        write_meta(child_job_id, **values)
        return {"status": values.get("status")}

    return run


for module_name in ("web", "rev", "pwn"):
    fake = types.ModuleType(f"modules.{module_name}.analyzer")
    fake.run_job = scalar_runner(module_name)
    sys.modules[f"modules.{module_name}.analyzer"] = fake


def create_parent(
    plan: list[dict],
    *,
    recipe: str = "web-pwn",
    filename: str | None = None,
    content: bytes | None = None,
) -> str:
    parent_job_id = next_id()
    modules = recipe.split("-")
    source = None
    if filename is not None:
        upload_dir = UPLOADS / parent_job_id
        upload_dir.mkdir()
        source = upload_dir / filename
        source.write_bytes(content or b"")
    meta = {
        "filename": filename,
        "src_bundle": str(source) if source is not None else None,
        "description": "isolated S3.5 completion fixture",
        "flag_format": "DH{...}",
        "model": "fixture-model",
        "effort": "high",
        "job_timeout": 321,
        "inputs": {
            modules[0]: {
                "target_url" if modules[0] == "web" else "target": "stage-a.example",
                "target_urls" if modules[0] == "web" else "targets": ["stage-a.example"],
                "docker_challenge": False,
            },
            "pwn": {
                "target": "stage-b.example:31337",
                "targets": ["stage-b.example:31337"],
                "docker_challenge": False,
            },
        },
        "agent_provider": "fixture-provider",
        "agent_provider_label": "Fixture Provider",
        "agent_role_providers": {"judge": "gpt"},
    }
    HybridCoordinator(JOBS).create_parent(parent_job_id, recipe, meta=meta)
    plans[parent_job_id] = plan
    return parent_job_id


def run_case(label: str, plan: list[dict]) -> tuple[str, dict | None, str | None, int]:
    parent_job_id = create_parent(plan)
    before = len(runner_calls)
    try:
        result = W.run_job(parent_job_id)
        error = None
    except Exception as exc:
        result = None
        error = f"{type(exc).__name__}:{exc}"
    return parent_job_id, result, error, len(runner_calls) - before


MARKER_A = {
    "status": "finished",
    "flags": ["DH{stage_a_confirmed}"],
    "flag_provenance": "marker",
    "flag_sweep_suppressed": False,
}
WEAK_A = {
    "status": "finished",
    "flags": ["DH{stage_a_weak}"],
    "flag_provenance": "narrative",
    "artifact": "weak stage A report",
}
NO_FLAG = {"status": "no_flag", "flags": []}
MARKER_B = {
    "status": "finished",
    "flags": ["DH{stage_b_confirmed}"],
    "flag_provenance": "marker",
    "flag_sweep_suppressed": False,
}
WEAK_B = {
    "status": "finished",
    "flags": ["DH{stage_b_weak}"],
    "flag_provenance": "runner_regex",
}

case_specs = (
    ("a-confirmed-b-skipped", [MARKER_A], "finished", 1),
    ("a-weak-b-no-flag", [WEAK_A, NO_FLAG], "no_flag", 2),
    ("a-weak-b-confirmed", [WEAK_A, MARKER_B], "finished", 2),
    ("a-no-flag-b-confirmed", [NO_FLAG, MARKER_B], "finished", 2),
    ("a-weak-b-weak", [WEAK_A, WEAK_B], "no_flag", 2),
    ("a-no-flag-b-no-flag", [NO_FLAG, NO_FLAG], "no_flag", 2),
    ("a-failed", [{"status": "failed", "flags": []}], "failed", 1),
    ("a-stopped", [{"status": "stopped", "flags": []}], "stopped", 1),
    ("b-failed", [NO_FLAG, {"status": "failed", "flags": []}], "failed", 2),
    ("b-stopped", [NO_FLAG, {"status": "stopped", "flags": []}], "stopped", 2),
)

observed = []
completed_parents: list[str] = []
for label, plan, expected_status, expected_runs in case_specs:
    parent_id, result, error, run_count = run_case(label, plan)
    completed_parents.append(parent_id)
    disk = read_meta(parent_id)
    observed.append(
        (
            label,
            error,
            result.get("status") if isinstance(result, dict) else None,
            disk.get("status"),
            run_count,
            len([p for p in (JOBS / parent_id).iterdir()]),
        )
    )

check(
    "test_worker_observes_all_six_terminal_combinations_and_failure_stop_variants",
    observed,
    [
        (label, None, status, status, runs, 1)
        for label, _plan, status, runs in case_specs
    ],
)

live_shape_index = [spec[0] for spec in case_specs].index("a-no-flag-b-confirmed")
live_shape_meta = read_meta(completed_parents[live_shape_index])
check(
    "test_a_no_flag_b_confirmed_live_shape_is_named_and_finishes_after_two_runs",
    (
        observed[live_shape_index][1:5],
        live_shape_meta["flags"],
        [
            record["disposition"]
            for record in live_shape_meta["hybrid"]["stage_flag_evidence"]
        ],
    ),
    ((None, "finished", "finished", 2), ["DH{stage_b_confirmed}"], ["confirmed"]),
)

sample_parent = completed_parents[2]
sample_meta = read_meta(sample_parent)
check(
    "test_actual_two_stage_completion_projects_only_confirmed_stage_b_flag",
    (
        sample_meta["status"],
        sample_meta["flags"],
        sample_meta["flag_candidates"],
        [record["disposition"] for record in sample_meta["hybrid"]["stage_flag_evidence"]],
    ),
    (
        "finished",
        ["DH{stage_b_confirmed}"],
        ["DH{stage_a_weak}"],
        ["unverified", "confirmed"],
    ),
)
check(
    "test_parent_directories_remain_meta_json_only_during_real_worker_runs",
    [sorted(path.name for path in (JOBS / parent).iterdir()) for parent in completed_parents],
    [["meta.json"]] * len(completed_parents),
)
check(
    "test_actual_scan_job_for_flags_is_empty_for_every_completed_parent",
    [COMMON.scan_job_for_flags(parent) for parent in completed_parents],
    [[] for _ in completed_parents],
)

grouped_modules = {
    parent: [call["module"] for call in runner_calls if call["parent"] == parent]
    for parent in completed_parents
}
check(
    "test_worker_calls_existing_scalar_runners_in_strict_stage_order",
    [grouped_modules[parent] for parent in completed_parents],
    [["web"] if runs == 1 else ["web", "pwn"] for _label, _plan, _status, runs in case_specs],
)
check(
    "test_scalar_children_force_auto_run_inherit_provider_and_prepare_input_directory",
    [
        (
            call["auto_run_meta"],
            call["args"][-2],
            call["provider"],
            call["input_dir_ready"],
        )
        for call in runner_calls
    ],
    [(True, True, "fixture-provider", True)] * len(runner_calls),
)
second_stage_calls = [call for call in runner_calls if call["stage"] == 1]
check(
    "test_every_second_stage_runs_only_after_verified_handoff_is_staged_in_scalar_cwd",
    [call["handoff_ok"] for call in second_stage_calls],
    [True] * len(second_stage_calls),
)
check(
    "test_stage_a_report_is_excluded_from_stage_b_output_recovery",
    [call["prior_report_isolated"] for call in second_stage_calls],
    [True] * len(second_stage_calls),
)
check(
    "test_verify_handoff_runs_once_for_each_created_second_stage",
    len(verify_calls),
    len(second_stage_calls),
)
check(
    "test_worker_scalar_entrypoint_map_is_exact",
    W._SCALAR_RUNNERS,
    {
        "rev": "modules.rev.analyzer.run_job",
        "web": "modules.web.analyzer.run_job",
        "pwn": "modules.pwn.analyzer.run_job",
    },
)

rev_parent = create_parent([MARKER_A], recipe="rev-pwn")
rev_before = len(runner_calls)
try:
    rev_result = W.run_job(rev_parent)
    rev_error = None
except Exception as exc:
    rev_result = None
    rev_error = f"{type(exc).__name__}:{exc}"
rev_calls = runner_calls[rev_before:]
check(
    "test_remote_only_rev_recipe_uses_real_rev_entrypoint_with_empty_bin_directory",
    (
        rev_error,
        rev_result.get("status") if isinstance(rev_result, dict) else None,
        [call["module"] for call in rev_calls],
        [call["input_dir_ready"] for call in rev_calls],
        sorted(path.name for path in (JOBS / rev_parent).iterdir()),
        COMMON.scan_job_for_flags(rev_parent),
    ),
    (None, "finished", ["rev"], [True], ["meta.json"], []),
)

bundle_bytes = b"S3.5 shared challenge bundle\n"
bundle_parent = create_parent(
    [WEAK_A, MARKER_B], filename="challenge.bin", content=bundle_bytes
)
bundle_before = len(runner_calls)
try:
    bundle_result = W.run_job(bundle_parent)
    bundle_error = None
except Exception as exc:
    bundle_result = None
    bundle_error = f"{type(exc).__name__}:{exc}"
bundle_calls = runner_calls[bundle_before:]
check(
    "test_shared_upload_is_copied_to_web_src_and_pwn_bin_without_touching_parent",
    (
        bundle_error,
        bundle_result.get("status") if isinstance(bundle_result, dict) else None,
        [(call["module"], call["input_bytes"]) for call in bundle_calls],
        sorted(path.name for path in (JOBS / bundle_parent).iterdir()),
        COMMON.scan_job_for_flags(bundle_parent),
    ),
    (
        None,
        "finished",
        [("web", bundle_bytes), ("pwn", bundle_bytes)],
        ["meta.json"],
        [],
    ),
)

rev_binary = b"\x7fELF" + b"hybrid-rev-fixture" * 4
rev_archive_io = io.BytesIO()
with zipfile.ZipFile(rev_archive_io, "w") as archive:
    archive.writestr("nested/challenge.elf", rev_binary)
    archive.writestr("nested/readme.txt", "fixture")
rev_zip_parent = create_parent(
    [MARKER_A],
    recipe="rev-pwn",
    filename="challenge.zip",
    content=rev_archive_io.getvalue(),
)
rev_zip_before = len(runner_calls)
try:
    rev_zip_result = W.run_job(rev_zip_parent)
    rev_zip_error = None
except Exception as exc:
    rev_zip_result = None
    rev_zip_error = f"{type(exc).__name__}:{exc}"
rev_zip_calls = runner_calls[rev_zip_before:]
check(
    "test_rev_zip_uses_dependency_free_scalar_picker_and_flattens_selected_binary",
    (
        rev_zip_error,
        rev_zip_result.get("status") if isinstance(rev_zip_result, dict) else None,
        [
            (call["module"], call["args"][1], call["input_bytes"])
            for call in rev_zip_calls
        ],
    ),
    (None, "finished", [("rev", "challenge.elf", rev_binary)]),
)

# A scalar exception and a scalar return without terminal metadata both fail the
# hidden child first and then project that terminal failure onto the parent.
exception_parent, _, exception_error, _ = run_case(
    "scalar-exception", [{"raise": "fixture scalar boom"}]
)
check(
    "test_scalar_exception_marks_child_and_parent_failed_before_reraising",
    (exception_error, read_meta(exception_parent)["status"]),
    ("RuntimeError:fixture scalar boom", "failed"),
)
nonterminal_parent, _, nonterminal_error, _ = run_case(
    "scalar-nonterminal", [{"status": "running", "flags": []}]
)
check(
    "test_scalar_nonterminal_return_fails_closed_on_child_and_parent",
    (
        nonterminal_error is not None
        and "returned before writing a terminal status" in nonterminal_error,
        read_meta(nonterminal_parent)["status"],
    ),
    (True, "failed"),
)

# Failures before start, while creating stage B, and after stage B exists use a
# terminalization path that does not replay the transition guard that failed.
invalid_modules_parent = create_parent([NO_FLAG, NO_FLAG])
invalid_modules_meta = read_meta(invalid_modules_parent)
invalid_modules_meta["modules"] = ["web"]
(JOBS / invalid_modules_parent / "meta.json").write_text(
    json.dumps(invalid_modules_meta), encoding="utf-8"
)
try:
    W.run_job(invalid_modules_parent)
    invalid_modules_error = None
except Exception as exc:
    invalid_modules_error = f"{type(exc).__name__}:{exc}"
invalid_modules_disk = read_meta(invalid_modules_parent)
check(
    "test_module_shape_failure_terminalizes_queued_parent_with_original_error",
    (
        invalid_modules_error,
        invalid_modules_disk["status"],
        invalid_modules_disk.get("error"),
    ),
    (
        "HybridStateError:hybrid worker requires exactly two ordered modules",
        "failed",
        "hybrid worker requires exactly two ordered modules",
    ),
)

prestart_parent = create_parent([NO_FLAG, NO_FLAG])
prestart_meta = read_meta(prestart_parent)
del prestart_meta["inputs"]["web"]
(JOBS / prestart_parent / "meta.json").write_text(
    json.dumps(prestart_meta), encoding="utf-8"
)
try:
    W.run_job(prestart_parent)
    prestart_error = None
except Exception as exc:
    prestart_error = f"{type(exc).__name__}:{exc}"
prestart_disk = read_meta(prestart_parent)
check(
    "test_prestart_adapter_failure_terminalizes_queued_parent_with_original_error",
    (prestart_error, prestart_disk["status"], prestart_disk.get("error")),
    (
        "HybridStateError:hybrid parent has no scalar inputs for web",
        "failed",
        "hybrid parent has no scalar inputs for web",
    ),
)

transition_parent = create_parent([NO_FLAG, NO_FLAG])
transition_second_child = f"{id_counter + 2:012x}"
(JOBS / transition_second_child / "occupied").mkdir(parents=True)
try:
    W.run_job(transition_parent)
    transition_error = None
except Exception as exc:
    transition_error = f"{type(exc).__name__}:{exc}"
transition_disk = read_meta(transition_parent)
check(
    "test_stage_b_creation_guard_terminalizes_parent_without_replaying_advance",
    (
        transition_error,
        transition_disk["status"],
        transition_disk.get("error"),
        transition_disk.get("finished_at") is not None,
    ),
    (
        "HandoffValidationError:target child directory must be new and isolated",
        "failed",
        "target child directory must be new and isolated",
        True,
    ),
)
if not (JOBS / transition_second_child / "meta.json").is_file():
    shutil.rmtree(JOBS / transition_second_child, ignore_errors=True)

parent_guard_parent = create_parent(
    [{**NO_FLAG, "parent_extra": "unexpected-artifact"}, NO_FLAG]
)
try:
    W.run_job(parent_guard_parent)
    parent_guard_error = None
except Exception as exc:
    parent_guard_error = f"{type(exc).__name__}:{exc}"
parent_guard_disk = read_meta(parent_guard_parent)
check(
    "test_parent_directory_guard_terminalizes_without_replaying_same_guard",
    (
        parent_guard_error,
        parent_guard_disk["status"],
        parent_guard_disk.get("error"),
    ),
    (
        "HybridStateError:hybrid parent directory may contain only meta.json; "
        "found unexpected-artifact",
        "failed",
        "hybrid parent directory may contain only meta.json; found unexpected-artifact",
    ),
)

staging_parent = create_parent([NO_FLAG, NO_FLAG])
staging_second_child = f"{id_counter + 2:012x}"
occupy_staging_for_children.add(staging_second_child)
try:
    W.run_job(staging_parent)
    staging_error = None
except Exception as exc:
    staging_error = f"{type(exc).__name__}:{exc}"
occupy_staging_for_children.discard(staging_second_child)
staging_disk = read_meta(staging_parent)
staging_child_path = JOBS / staging_second_child / "meta.json"
staging_child_disk = read_meta(staging_second_child) if staging_child_path.is_file() else {}
check(
    "test_stage_b_staging_guard_fails_child_and_parent_without_masking_original_error",
    (
        staging_error,
        staging_child_disk.get("status"),
        staging_disk["status"],
        staging_disk.get("error"),
    ),
    (
        "HybridStateError:scalar work directory already contains a handoff",
        "failed",
        "failed",
        "scalar work directory already contains a handoff",
    ),
)

# The source path in metadata is not authority.  A filename-less parent with a
# stray src_bundle must fail before any scalar runner can read it.
outside = DATA / "outside.bin"
outside.write_bytes(b"must not be read")
bad_parent = create_parent([NO_FLAG])
bad = read_meta(bad_parent)
bad["src_bundle"] = str(outside)
(JOBS / bad_parent / "meta.json").write_text(json.dumps(bad), encoding="utf-8")
before_bad_calls = len(runner_calls)
try:
    W.run_job(bad_parent)
    bad_error = None
except Exception as exc:
    bad_error = f"{type(exc).__name__}:{exc}"
check(
    "test_src_bundle_without_safe_filename_fails_before_scalar_execution",
    (
        bad_error is not None and "src_bundle without filename" in bad_error,
        len(runner_calls) - before_bad_calls,
        read_meta(bad_parent)["status"],
    ),
    (True, 0, "failed"),
)

outside_parent = create_parent(
    [NO_FLAG], filename="challenge.bin", content=b"owned upload"
)
outside_meta = read_meta(outside_parent)
outside_meta["src_bundle"] = str(outside)
(JOBS / outside_parent / "meta.json").write_text(
    json.dumps(outside_meta), encoding="utf-8"
)
before_outside_calls = len(runner_calls)
try:
    W.run_job(outside_parent)
    outside_error = None
except Exception as exc:
    outside_error = f"{type(exc).__name__}:{exc}"
check(
    "test_src_bundle_outside_parent_upload_directory_fails_before_scalar_execution",
    (
        outside_error is not None
        and "src_bundle is outside its upload directory" in outside_error,
        len(runner_calls) - before_outside_calls,
        read_meta(outside_parent)["status"],
    ),
    (True, 0, "failed"),
)

check("test_mutation_suite_reaches_final_named_check", True, True)

tmp.cleanup()
print(f"hybrid-worker: {passed} passed, {failed} failed; mutation={args.mutate}")
raise SystemExit(1 if failed else 0)
