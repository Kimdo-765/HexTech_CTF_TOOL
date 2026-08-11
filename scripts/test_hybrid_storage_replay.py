#!/usr/bin/env python3
"""S4 hybrid library-save and legacy-replay isolation contract.

Every check is named.  ``--mutate`` rewrites and compiles the production source
in memory, so mutations exercise the shipped gate rather than a test double.
Unexpected exceptions become named failures and the harness still reaches its
final check and summary.

Run: python3 scripts/test_hybrid_storage_replay.py [--mutate NAME]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import tempfile
import types
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

MUTATIONS = (
    "no-confirmed-guard",
    "drop-module-guard",
    "skip-projection-match",
    "skip-duplicate-check",
    "curation-selects-child",
    "skip-child-parent-link",
    "allow-hybrid-parent",
    "allow-hybrid-child",
    "drop-child-internal-clause",
    "drop-child-parent-clause",
    "drop-child-stage-clause",
    "selection-bypasses-eligibility",
    "builder-bypasses-eligibility",
    "drop-child-summary-count",
)

parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()


def replace_once(source: str, old: str, new: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"mutation anchor count is {count}, expected 1: {old!r}")
    return source.replace(old, new, 1)


passed = 0
failed = 0


def check(label: str, got, want=True) -> None:
    global passed, failed
    if got == want:
        passed += 1
        print(f"PASS  {label}")
    else:
        failed += 1
        print(f"FAIL  {label}\n      got  = {got!r}\n      want = {want!r}")


CASE_FAILED = object()


def capture(label: str, fn):
    try:
        return fn()
    except Exception as exc:
        check(label, f"unexpected exception: {type(exc).__name__}: {exc}", True)
        return CASE_FAILED


# The host verification environment omits service-only dependencies.  Stub only
# those import boundaries; coordinator/storage and the mutated production
# modules below remain real.
def _missing(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is None
    except (ImportError, ValueError):
        return True


if _missing("docker"):
    docker = types.ModuleType("docker")
    docker.from_env = lambda *a, **k: None
    docker.DockerClient = type("DockerClient", (), {})
    docker_errors = types.ModuleType("docker.errors")
    for name in ("APIError", "NotFound", "ImageNotFound", "DockerException", "NullResource"):
        setattr(docker_errors, name, type(name, (Exception,), {}))
    docker_types = types.ModuleType("docker.types")
    docker_types.Mount = type("Mount", (), {"__init__": lambda self, **kw: None})
    docker.errors = docker_errors
    docker.types = docker_types
    sys.modules.update(
        {"docker": docker, "docker.errors": docker_errors, "docker.types": docker_types}
    )

if _missing("claude_agent_sdk"):
    sdk = types.ModuleType("claude_agent_sdk")
    for name in (
        "AssistantMessage",
        "ClaudeAgentOptions",
        "ResultMessage",
        "SystemMessage",
        "TextBlock",
        "ClaudeSDKClient",
        "UserMessage",
    ):
        setattr(sdk, name, type(name, (), {"__init__": lambda self, **kw: None}))

    async def _query(*_args, **_kwargs):
        if False:
            yield None

    sdk.query = _query
    sdk.HookMatcher = type("HookMatcher", (), {"__init__": lambda self, **kw: None})
    sdk.AgentDefinition = type("AgentDefinition", (), {"__init__": lambda self, **kw: None})
    sdk.create_sdk_mcp_server = lambda *a, **k: None
    sdk.tool = lambda *a, **k: (lambda fn: fn)
    sdk.project_key_for_directory = lambda *a, **k: ""
    sys.modules["claude_agent_sdk"] = sdk


fastapi = types.ModuleType("fastapi")


class HTTPException(Exception):
    def __init__(self, status_code: int, detail: str = ""):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


class APIRouter:
    def __getattr__(self, _name):
        return lambda *args, **kwargs: (lambda fn: fn)


class BaseModel:
    def __init__(self, **values):
        for name, value in self.__class__.__dict__.items():
            if not name.startswith("_") and not callable(value):
                setattr(self, name, value)
        for name, value in values.items():
            setattr(self, name, value)


fastapi.APIRouter = APIRouter
fastapi.HTTPException = HTTPException
fastapi.UploadFile = object
fastapi.File = lambda *args, **kwargs: None
fastapi.Form = lambda *args, **kwargs: None
responses = types.ModuleType("fastapi.responses")
responses.FileResponse = type("FileResponse", (), {})
responses.StreamingResponse = type("StreamingResponse", (), {})
pydantic = types.ModuleType("pydantic")
pydantic.BaseModel = BaseModel
pydantic.Field = lambda default=None, **kwargs: (
    kwargs["default_factory"]() if "default_factory" in kwargs else default
)
sys.modules.update(
    {"fastapi": fastapi, "fastapi.responses": responses, "pydantic": pydantic}
)


TMP = tempfile.TemporaryDirectory(prefix="hybrid-s4-")
DATA = Path(TMP.name)
JOBS = DATA / "jobs"
EXPLOITS = DATA / "exploits"
REPLAY_JOBS = DATA / "replay-jobs"
for directory in (JOBS, EXPLOITS, REPLAY_JOBS):
    directory.mkdir()
os.environ["REPLAY7_ROOT"] = str(DATA / "replay-root")

import api.storage as STORAGE  # noqa: E402
import modules as MODULES_PACKAGE  # noqa: E402
from modules import _common as COMMON  # noqa: E402
from modules.hybrid.coordinator import HybridCoordinator  # noqa: E402

STORAGE.JOBS_DIR = JOBS
STORAGE.EXPLOITS_DIR = EXPLOITS

scan_calls: list[str] = []


def tracked_scan(job_id: str) -> list[str]:
    scan_calls.append(job_id)
    return [f"DH{{scan_{job_id}}}"]


COMMON.scan_job_for_flags = tracked_scan


exploit_source = (ROOT / "api" / "routes" / "exploits.py").read_text(encoding="utf-8")
judge_source = (ROOT / "modules" / "judge_replay.py").read_text(encoding="utf-8")
stage7_source = (ROOT / "scripts" / "replay_stage7.py").read_text(encoding="utf-8")

if args.mutate == "no-confirmed-guard":
    exploit_source = replace_once(exploit_source, "    if not confirmed:\n", "    if False and not confirmed:\n")
elif args.mutate == "drop-module-guard":
    exploit_source = replace_once(
        exploit_source,
        '    if job_meta.get("module") == "hybrid":\n',
        '    if False and job_meta.get("module") == "hybrid":\n',
    )
elif args.mutate == "skip-projection-match":
    exploit_source = replace_once(
        exploit_source,
        "        and curated_unique\n        == [value for value in confirmed_projection if value in curated_unique]\n",
        "        and True\n",
    )
elif args.mutate == "skip-duplicate-check":
    exploit_source = replace_once(
        exploit_source,
        "        and len(curated_flags) == len(curated_unique)\n",
        "        and True\n",
    )
elif args.mutate == "curation-selects-child":
    exploit_source = replace_once(
        exploit_source,
        '        and bool(record.get("child_job_id"))\n',
        '        and bool(record.get("child_job_id"))\n        and record.get("value") in curated_unique\n',
    )
elif args.mutate == "skip-child-parent-link":
    exploit_source = replace_once(
        exploit_source,
        '        and child_meta.get("parent_job_id") == source_job_id\n',
        "        and True\n",
    )
elif args.mutate == "allow-hybrid-parent":
    judge_source = replace_once(
        judge_source,
        '    if meta.get("module") == "hybrid":\n',
        '    if False and meta.get("module") == "hybrid":\n',
    )
elif args.mutate == "allow-hybrid-child":
    judge_source = replace_once(
        judge_source,
        '        return False, "hybrid_child"\n',
        "        return True, None\n",
    )
elif args.mutate == "drop-child-internal-clause":
    judge_source = replace_once(
        judge_source,
        '        meta.get("internal") is True\n',
        "        True\n",
    )
elif args.mutate == "drop-child-parent-clause":
    judge_source = replace_once(
        judge_source,
        '        and isinstance(meta.get("parent_job_id"), str)\n        and bool(meta.get("parent_job_id"))\n',
        "        and True\n",
    )
elif args.mutate == "drop-child-stage-clause":
    judge_source = replace_once(
        judge_source,
        '        and isinstance(meta.get("hybrid_stage"), int)\n',
        "        and True\n",
    )
elif args.mutate == "selection-bypasses-eligibility":
    stage7_source = replace_once(
        stage7_source,
        '        if eligible and any(d.glob("*.stdout")):\n',
        '        if any(d.glob("*.stdout")):\n',
    )
elif args.mutate == "builder-bypasses-eligibility":
    judge_source = replace_once(
        judge_source,
        "    if not eligible:\n        return None\n",
        "    if False and not eligible:\n        return None\n",
    )
elif args.mutate == "drop-child-summary-count":
    stage7_source = replace_once(
        stage7_source,
        '            "hybrid_child": len(skipped_hybrid_child),\n',
        '            "hybrid_child": 0,\n',
    )


def load_source(name: str, source: str, filename: Path):
    module = types.ModuleType(name)
    module.__file__ = str(filename)
    module.__package__ = name.rpartition(".")[0]
    sys.modules[name] = module
    exec(compile(source, str(filename), "exec"), module.__dict__)
    return module


X = load_source("api.routes._s4_exploits", exploit_source, ROOT / "api/routes/exploits.py")
X.JOBS_DIR = JOBS
X.EXPLOITS_DIR = EXPLOITS
X.exploit_dir = lambda exploit_id: EXPLOITS / exploit_id

JR = load_source("modules._s4_judge_replay", judge_source, ROOT / "modules/judge_replay.py")
sys.modules["modules.judge_replay"] = JR
MODULES_PACKAGE.judge_replay = JR
R7 = load_source("scripts._s4_replay_stage7", stage7_source, ROOT / "scripts/replay_stage7.py")


COORD = HybridCoordinator(JOBS)
sequence = 0


def read_meta(job_id: str, *, root: Path = JOBS) -> dict:
    return json.loads((root / job_id / "meta.json").read_text(encoding="utf-8"))


def write_meta(job_id: str, meta: dict, *, root: Path = JOBS) -> None:
    (root / job_id / "meta.json").write_text(
        json.dumps(meta, indent=2) + "\n", encoding="utf-8"
    )


def valid_hybrid(label: str, *, curated=None):
    global sequence
    sequence += 1
    parent = f"{label}-{sequence}-parent"
    child = f"{label}-{sequence}-child"
    real = f"DH{{{label}_{sequence}_real}}"
    decoy = f"DH{{{label}_{sequence}_decoy}}"
    weak = f"DH{{{label}_{sequence}_weak}}"
    COORD.create_parent(
        parent,
        "rev-pwn",
        meta={"filename": f"{label}.zip", "target_url": "target:31337"},
    )
    COORD.start(parent, child)
    child_meta = read_meta(child)
    child_meta.update(
        status="finished",
        flags=[real, decoy],
        flag_candidates=[weak],
        flag_provenance="marker",
        flag_sweep_suppressed=False,
    )
    write_meta(child, child_meta)
    child_dir = JOBS / child
    (child_dir / "solver.py").write_text("print('child solver')\n", encoding="utf-8")
    (child_dir / "report.md").write_text("child report\n", encoding="utf-8")
    (child_dir / "findings.json").write_text(
        json.dumps({"solver_strategy": {"approach": "hybrid-child"}}),
        encoding="utf-8",
    )
    bin_dir = child_dir / "bin"
    bin_dir.mkdir()
    (bin_dir / "challenge").write_bytes(b"hybrid-binary")
    COORD.advance(parent)
    if curated is not None:
        parent_meta = read_meta(parent)
        parent_meta["flags"] = curated(real, decoy, weak)
        write_meta(parent, parent_meta)
    return parent, child, real, decoy, weak


def two_stage_confirmed_hybrid(label: str):
    """Match the live rev->pwn shape: A cannot confirm; B owns two records."""

    global sequence
    sequence += 1
    parent = f"{label}-{sequence}-parent"
    first = f"{label}-{sequence}-rev"
    second = f"{label}-{sequence}-pwn"
    first_flag = f"DH{{{label}_{sequence}_first}}"
    second_flag = f"DH{{{label}_{sequence}_second}}"
    COORD.create_parent(
        parent,
        "rev-pwn",
        meta={"filename": f"{label}.bin", "target_url": "target:31337"},
    )
    COORD.start(parent, first)
    first_meta = read_meta(first)
    first_meta.update(status="no_flag", flags=[], flag_candidates=[])
    write_meta(first, first_meta)
    COORD.advance(parent, next_child_job_id=second)
    COORD.verify_handoff(second)

    second_meta = read_meta(second)
    second_meta.update(
        status="finished",
        flags=[first_flag, second_flag],
        flag_candidates=[],
        flag_provenance="marker",
        flag_sweep_suppressed=False,
    )
    write_meta(second, second_meta)
    second_dir = JOBS / second
    (second_dir / "exploit.py").write_text("print('stage B exploit')\n", encoding="utf-8")
    (second_dir / "report.md").write_text("stage B report\n", encoding="utf-8")
    (second_dir / "findings.json").write_text(
        json.dumps({"solver_strategy": {"approach": "two-stage-pwn"}}),
        encoding="utf-8",
    )
    COORD.advance(parent)
    return parent, first, second, first_flag, second_flag


def save(parent: str):
    return X.save_exploit(X.SaveBody(job_id=parent))


def expect_400(label: str, parent: str, detail: str) -> None:
    try:
        save(parent)
    except HTTPException as exc:
        check(label, (exc.status_code, exc.detail), (400, detail))
    except Exception as exc:
        check(label, f"wrong exception: {type(exc).__name__}: {exc}", (400, detail))
    else:
        check(label, "save unexpectedly succeeded", (400, detail))


# ---------------------------------------------------------------- save gate
parent, child, real, decoy, weak = valid_hybrid("full")
full = capture("test_hybrid_full_projection_save_does_not_raise", lambda: save(parent))
if full is not CASE_FAILED:
    dest = EXPLOITS / full["id"]
    check(
        "test_hybrid_save_uses_parent_authority_and_child_artifacts",
        (
            full["source_job_id"],
            full["source_child_job_id"],
            full["module"],
            full["flags"],
            full["script_filename"],
            (dest / "solver.py").read_text(encoding="utf-8"),
            (dest / "report.md").read_text(encoding="utf-8"),
            full["technique_name"],
            full["binary_path_in_job"],
        ),
        (
            parent,
            child,
            "rev",
            [real, decoy],
            "solver.py",
            "print('child solver')\n",
            "child report\n",
            "hybrid-child",
            "bin/challenge",
        ),
    )
    check(
        "test_hybrid_parent_remains_meta_only_after_save",
        sorted(path.name for path in (JOBS / parent).iterdir()),
        ["meta.json"],
    )

parent, child, real, decoy, weak = valid_hybrid(
    "curated", curated=lambda _real, decoy, _weak: [decoy]
)
curated = capture("test_order_preserving_confirmed_subset_saves", lambda: save(parent))
if curated is not CASE_FAILED:
    check(
        "test_curation_does_not_change_artifact_child",
        (curated["flags"], curated["source_child_job_id"]),
        ([decoy], child),
    )

parent, _first, second, first_flag, second_flag = two_stage_confirmed_hybrid(
    "live-shape"
)
two_stage = capture(
    "test_two_stage_two_confirmed_projection_saves_before_reordering",
    lambda: save(parent),
)
if two_stage is not CASE_FAILED:
    parent_meta = read_meta(parent)
    confirmed = [
        record
        for record in parent_meta["hybrid"]["stage_flag_evidence"]
        if record.get("disposition") == "confirmed"
    ]
    check(
        "test_live_shape_has_two_ordered_confirmed_records_from_stage_b",
        (
            [(record["stage"], record["module"], record["child_job_id"], record["value"])
             for record in confirmed],
            two_stage["source_child_job_id"],
            two_stage["flags"],
        ),
        (
            [
                (1, "pwn", second, first_flag),
                (1, "pwn", second, second_flag),
            ],
            second,
            [first_flag, second_flag],
        ),
    )
    parent_meta["flags"] = [second_flag, first_flag]
    write_meta(parent, parent_meta)
    expect_400(
        "test_live_shape_two_confirmed_reordering_is_rejected",
        parent,
        "hybrid parent curated flags do not match canonical confirmed evidence",
    )

parent, _child, _real, _decoy, _weak = valid_hybrid(
    "empty", curated=lambda *_values: []
)
expect_400(
    "test_all_confirmed_flags_deleted_has_distinct_400",
    parent,
    "hybrid parent has no curated confirmed flag left to save",
)

for label, curated_fn in (
    ("outside", lambda real, _decoy, weak: [real, weak]),
    ("reordered", lambda real, decoy, _weak: [decoy, real]),
    ("duplicate", lambda real, _decoy, _weak: [real, real]),
    ("type", lambda real, _decoy, _weak: [real, 42]),
):
    parent, _child, _real, _decoy, _weak = valid_hybrid(label, curated=curated_fn)
    expect_400(
        f"test_{label}_curation_rejected_as_canonical_mismatch",
        parent,
        "hybrid parent curated flags do not match canonical confirmed evidence",
    )

parent, _child, real, _decoy, _weak = valid_hybrid("zero-child")
meta = read_meta(parent)
for record in meta["hybrid"]["stage_flag_evidence"]:
    if record.get("disposition") == "confirmed":
        record.pop("child_job_id", None)
write_meta(parent, meta)
expect_400(
    "test_zero_artifact_children_has_count_specific_400",
    parent,
    "hybrid parent confirmed evidence resolves to 0 artifact children; expected exactly 1",
)

parent, child, real, decoy, _weak = valid_hybrid(
    "two-child", curated=lambda real, _decoy, _weak: [real]
)
other = f"{parent}-other"
other_dir = JOBS / other
other_dir.mkdir()
write_meta(
    other,
    {
        "id": other,
        "module": "rev",
        "internal": True,
        "parent_job_id": parent,
        "hybrid_stage": 0,
    },
)
meta = read_meta(parent)
for record in meta["hybrid"]["stage_flag_evidence"]:
    if record.get("value") == decoy:
        record["child_job_id"] = other
write_meta(parent, meta)
expect_400(
    "test_two_artifact_children_rejected_before_curation_can_choose_one",
    parent,
    "hybrid parent confirmed evidence resolves to 2 artifact children; expected exactly 1",
)

parent, child, _real, _decoy, _weak = valid_hybrid("bad-link")
child_meta = read_meta(child)
child_meta["parent_job_id"] = "different-parent"
write_meta(child, child_meta)
expect_400(
    "test_artifact_child_parent_stage_module_link_is_required",
    parent,
    "hybrid parent confirmed artifact child does not match canonical evidence",
)

before_scan = len(scan_calls)
parent, _child, real, _decoy, weak = valid_hybrid("o3")
meta = read_meta(parent)
meta["hybrid"]["stage_flag_evidence"] = []
meta["flags"] = [real]
write_meta(parent, meta)
(JOBS / parent / "solver.py").write_text("print('parent leak')\n", encoding="utf-8")
(JOBS / parent / "report.md").write_text(f"weak {weak}\n", encoding="utf-8")
expect_400(
    "test_o3_confirmed_child_without_parent_record_is_not_rescanned_or_saved",
    parent,
    "hybrid parent has no canonical confirmed evidence to save",
)
check("test_o3_hybrid_rejection_calls_scanner_zero_times", len(scan_calls), before_scan)

before_scan = len(scan_calls)
parent, _child, real, _decoy, weak = valid_hybrid(
    "weak-injected", curated=lambda real, _decoy, weak: [real, weak]
)
expect_400(
    "test_unverified_value_in_meta_flags_is_not_promoted_by_save",
    parent,
    "hybrid parent curated flags do not match canonical confirmed evidence",
)
check("test_hybrid_canonical_gate_calls_scanner_zero_times", len(scan_calls), before_scan)


# ------------------------------------------------------ scalar compatibility
def scalar_job(label: str, flags: list[str]) -> str:
    job_id = f"scalar-{label}"
    directory = JOBS / job_id
    directory.mkdir()
    write_meta(
        job_id,
        {
            "id": job_id,
            "module": "pwn",
            "flags": flags,
            "filename": "scalar.zip",
            "target_url": "scalar:1",
        },
    )
    (directory / "exploit.py").write_text("print('scalar')\n", encoding="utf-8")
    (directory / "report.md").write_text("scalar report\n", encoding="utf-8")
    return job_id


before_scan = len(scan_calls)
scalar_curated_id = scalar_job("curated", ["DH{scalar_curated}"])
scalar_curated = capture("test_scalar_curated_save_does_not_raise", lambda: save(scalar_curated_id))
if scalar_curated is not CASE_FAILED:
    check(
        "test_scalar_curated_save_keeps_legacy_result_shape",
        (
            scalar_curated["source_job_id"],
            scalar_curated["module"],
            scalar_curated["script_filename"],
            scalar_curated["flags"],
            "source_child_job_id" in scalar_curated,
            sorted(path.name for path in (EXPLOITS / scalar_curated["id"]).iterdir()),
        ),
        (
            scalar_curated_id,
            "pwn",
            "exploit.py",
            ["DH{scalar_curated}"],
            False,
            ["exploit.py", "meta.json", "report.md"],
        ),
    )
check("test_scalar_curated_save_still_skips_scanner", len(scan_calls), before_scan)

scalar_scan_id = scalar_job("scan", [])
scalar_scan = capture("test_scalar_empty_meta_fallback_does_not_raise", lambda: save(scalar_scan_id))
if scalar_scan is not CASE_FAILED:
    check(
        "test_scalar_empty_meta_still_uses_legacy_scan_fallback",
        scalar_scan["flags"],
        [f"DH{{scan_{scalar_scan_id}}}"],
    )
check("test_scalar_empty_meta_calls_scanner_once", scan_calls[-1:], [scalar_scan_id])


# -------------------------------------------------------- replay eligibility
replay_coord = HybridCoordinator(REPLAY_JOBS)
replay_parent = "replay-parent"
replay_a = "replay-child-a"
replay_b = "replay-child-b"
replay_coord.create_parent(replay_parent, "rev-pwn")
replay_coord.start(replay_parent, replay_a)
a_meta = read_meta(replay_a, root=REPLAY_JOBS)
a_meta.update(status="no_flag", flags=[])
write_meta(replay_a, a_meta, root=REPLAY_JOBS)
replay_coord.advance(replay_parent, next_child_job_id=replay_b)


def replay_artifacts(job_id: str, meta: dict | None = None) -> None:
    directory = REPLAY_JOBS / job_id
    directory.mkdir(exist_ok=True)
    if meta is not None:
        write_meta(job_id, meta, root=REPLAY_JOBS)
    (directory / "solver.py").write_text("print('replay')\n", encoding="utf-8")
    (directory / "solver.py.stdout").write_text("out\n", encoding="utf-8")
    (directory / "solver.py.stderr").write_text("", encoding="utf-8")
    (directory / "events.jsonl").write_text(
        json.dumps({"phase": "run", "kind": "exit", "exit_code": 0}) + "\n",
        encoding="utf-8",
    )


for job_id in (replay_parent, replay_a, replay_b):
    replay_artifacts(job_id)
ordinary = "replay-ordinary"
replay_artifacts(
    ordinary,
    {"id": ordinary, "module": "pwn", "status": "finished", "target_url": "h:1"},
)
lookalikes = {
    "look-no-internal": {
        "id": "look-no-internal",
        "module": "rev",
        "internal": False,
        "parent_job_id": replay_parent,
        "hybrid_stage": 0,
    },
    "look-no-parent": {
        "id": "look-no-parent",
        "module": "rev",
        "internal": True,
        "hybrid_stage": 0,
    },
    "look-no-stage": {
        "id": "look-no-stage",
        "module": "rev",
        "internal": True,
        "parent_job_id": replay_parent,
    },
}
for job_id, meta in lookalikes.items():
    replay_artifacts(job_id, meta)
no_output = "replay-no-output"
(REPLAY_JOBS / no_output).mkdir()
write_meta(no_output, {"id": no_output, "module": "pwn"}, root=REPLAY_JOBS)

check(
    "test_replay_eligibility_rejects_actual_coordinator_parent",
    JR.replay_eligibility(REPLAY_JOBS / replay_parent),
    (False, "hybrid_parent"),
)
check(
    "test_replay_eligibility_rejects_both_actual_coordinator_children",
    [JR.replay_eligibility(REPLAY_JOBS / job_id) for job_id in (replay_a, replay_b)],
    [(False, "hybrid_child"), (False, "hybrid_child")],
)
check(
    "test_internal_parent_stage_child_predicate_requires_every_clause",
    [JR.replay_eligibility(REPLAY_JOBS / job_id) for job_id in lookalikes],
    [(True, None), (True, None), (True, None)],
)
check(
    "test_record_builder_itself_emits_zero_hybrid_chain_records",
    [JR.replay_inputs(REPLAY_JOBS / job_id) for job_id in (replay_parent, replay_a, replay_b)],
    [None, None, None],
)
check(
    "test_replayable_selects_ordinary_and_no_hybrid_chain_members",
    [path.name for path in R7.replayable(REPLAY_JOBS)],
    [*lookalikes, ordinary],
)

out_path = DATA / "replay-output" / "results.jsonl"
old_argv = sys.argv
sys.argv = [
    "replay_stage7.py",
    "--jobs-root",
    str(REPLAY_JOBS),
    "--scratch",
    str(DATA / "replay-output" / "scratch"),
    "--out",
    str(out_path),
    "--dry-run",
]
main_result = capture("test_stage7_dry_run_completes", R7.main)
sys.argv = old_argv
if main_result is not CASE_FAILED:
    check("test_stage7_dry_run_returns_success", main_result, 0)
    summary = json.loads((out_path.parent / "summary.json").read_text(encoding="utf-8"))
    check(
        "test_replay_summary_counts_each_exclusion_reason",
        (
            summary["replayed"],
            summary["skipped_by_reason"],
            summary["skipped_hybrid_parent"],
            summary["skipped_hybrid_child"],
        ),
        (
            4,
            {"no_sandbox_output": 1, "hybrid_parent": 1, "hybrid_child": 2},
            [replay_parent],
            [replay_a, replay_b],
        ),
    )

check("test_mutation_suite_reaches_final_named_check", True, True)

print(
    f"hybrid-storage-replay: {passed} passed, {failed} failed; "
    f"mutation={args.mutate or 'none'}"
)
TMP.cleanup()
raise SystemExit(1 if failed else 0)
