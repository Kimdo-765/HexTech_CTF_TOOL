#!/usr/bin/env python3
"""S2 hybrid ingest/API/UI contract and production-source mutation battery.

Every assertion has a name.  The mutation modes rewrite the production source
being compiled (or the shipped HTML being inspected), rather than weakening a
test double.  Unexpected route exceptions are converted into named failures so
the independent recipe, API, coordinator, scanner, registration, and UI checks
still reach the summary.

Run: python3 scripts/test_hybrid_ingest.py [--mutate NAME]
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import sys
import tempfile
import types
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

MUTATIONS = (
    "none",
    "upload-parent",
    "recipe-alias",
    "allow-live-fire",
    "drop-enqueue",
    "drop-failure-callback",
    "stale-buster",
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS, default="none")
args = parser.parse_args()

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


def replace_once(source: str, old: str, new: str) -> str:
    """Apply an exact production edit and fail loudly if the anchor drifted."""

    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"mutation anchor count is {count}, expected 1: {old!r}")
    return source.replace(old, new, 1)


# Import both real production functions before installing the route-only stubs.
from modules import _common as COMMON  # noqa: E402
from modules.hybrid import coordinator as HYBRID_COORDINATOR  # noqa: E402
from modules.hybrid.coordinator import HybridCoordinator  # noqa: E402


TMP = tempfile.TemporaryDirectory(prefix="hybrid-s2-")
DATA = Path(TMP.name)
JOBS = DATA / "jobs"
UPLOADS = DATA / "uploads"
JOBS.mkdir()
UPLOADS.mkdir()

# scan_job_for_flags must be the production function, but its filesystem root
# is redirected to the isolated fixture exactly as the S1 harness does.
COMMON.JOBS_DIR = JOBS
COMMON.job_dir = lambda job_id: JOBS / Path(job_id).name
HYBRID_COORDINATOR.JOBS_DIR = JOBS


# ---------------------------------------------------------------- route load
# Host test environments intentionally omit FastAPI/RQ.  Stub only the import
# boundary used by this route; the coordinator and scanner above stay real.
fastapi = types.ModuleType("fastapi")


class HTTPException(Exception):
    def __init__(self, status_code: int, detail: str = ""):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


class APIRouter:
    def post(self, _path: str):
        return lambda fn: fn


fastapi.APIRouter = APIRouter
fastapi.File = lambda default=None: default
fastapi.Form = lambda default=None, **_kwargs: default
fastapi.HTTPException = HTTPException
fastapi.UploadFile = object
sys.modules["fastapi"] = fastapi


rq = types.ModuleType("rq")


class Callback:
    def __init__(self, func, timeout=60):
        self.func = func
        self.timeout = timeout
        self.name = f"{func.__module__}.{func.__name__}"


rq.Callback = Callback
sys.modules["rq"] = rq

queue_module = types.ModuleType("api.queue")
queue_module.normalize_effort = lambda raw: (
    raw.strip().lower()
    if isinstance(raw, str) and raw.strip().lower() in {"low", "medium", "high", "xhigh", "max"}
    else None
)
queue_module.resolve_timeout = lambda value: value if value and value > 0 else 6000
queue_module.hard_timeout_for = lambda value: value * 4
enqueued = []


class Queue:
    def enqueue(self, function, *positional, **keywords):
        enqueued.append((function, positional, keywords))


queue_module.get_queue = Queue
sys.modules["api.queue"] = queue_module

job_ids = iter(("a10000000001", "a10000000002"))


def parse_targets(raw, *, limit=32):
    values = []
    for value in re.split(r"[\r\n,]+", raw or ""):
        value = value.strip()
        if value and value not in values:
            values.append(value)
            if len(values) >= limit:
                break
    return values


storage_module = types.ModuleType("api.storage")
storage_module.JOBS_DIR = JOBS
storage_module.UPLOADS_DIR = UPLOADS
storage_module.new_job_id = lambda: next(job_ids)
storage_module.parse_targets = parse_targets
storage_module.prepare_job_description = (
    lambda _job_id, description, _secret_key, _secret_value: description
)
sys.modules["api.storage"] = storage_module

enriched = []
agent_provider = types.ModuleType("modules.agent_provider")


def enrich_job_meta(meta, **kwargs):
    enriched.append(meta)
    meta["agent_provider"] = "fixture"
    return meta


agent_provider.enrich_job_meta = enrich_job_meta
sys.modules["modules.agent_provider"] = agent_provider

route_source = (ROOT / "api" / "routes" / "hybrid_module.py").read_text(
    encoding="utf-8"
)
if args.mutate == "upload-parent":
    route_source = replace_once(
        route_source,
        "upload_dir = UPLOADS_DIR / job_id",
        "upload_dir = JOBS_DIR / job_id",
    )
elif args.mutate == "recipe-alias":
    route_source = replace_once(
        route_source,
        '    "pwn-web": "web-pwn",\n}',
        '    "pwn-web": "web-pwn",\n    "rev-web": "rev-pwn",\n}',
    )
elif args.mutate == "allow-live-fire":
    route_source = replace_once(
        route_source,
        '    if "live-fire" in (raw or "").strip().lower() or "live-fire" in value:',
        "    if False:",
    )
elif args.mutate == "drop-enqueue":
    route_source = replace_once(
        route_source,
        '''    queue = get_queue()\n    queue.enqueue(\n        "modules.hybrid.worker.run_job",\n        job_id,\n        job_id=job_id,\n        job_timeout=hard_timeout_for(timeout),\n        on_failure=Callback(fail_parent_on_rq_failure, timeout=10),\n    )\n''',
        "",
    )
elif args.mutate == "drop-failure-callback":
    route_source = replace_once(
        route_source,
        "        on_failure=Callback(fail_parent_on_rq_failure, timeout=10),\n",
        "",
    )

route_ns = {"__name__": "hybrid_ingest_route_under_test"}
exec(
    compile(route_source, str(ROOT / "api" / "routes" / "hybrid_module.py"), "exec"),
    route_ns,
)
canonical_recipe = route_ns["_canonical_recipe"]
analyze_hybrid = route_ns["analyze_hybrid"]
recipe_aliases = route_ns["_RECIPE_ALIASES"]


# --------------------------------------------------------- recipe boundary
check(
    "test_recipe_alias_keys_are_exactly_the_supported_pairs",
    set(recipe_aliases),
    {"rev-pwn", "pwn-rev", "web-pwn", "pwn-web"},
)
check(
    "test_recipe_aliases_normalize_to_exactly_two_canonical_recipes",
    set(recipe_aliases.values()),
    {"rev-pwn", "web-pwn"},
)

for name, raw, expected in (
    ("reverse_rev_pwn", "pwn-rev", "rev-pwn"),
    ("reverse_web_pwn", "pwn-web", "web-pwn"),
    ("case_fold", "REV-PWN", "rev-pwn"),
    ("outer_whitespace", "  web-pwn  ", "web-pwn"),
):
    try:
        observed = canonical_recipe(raw)
    except Exception as exc:  # keep the mutation run alive to the summary
        observed = f"raised:{type(exc).__name__}:{exc}"
    check(f"test_recipe_normalizes_{name}", observed, expected)


def rejected(raw: str) -> tuple[int | None, str]:
    try:
        value = canonical_recipe(raw)
    except HTTPException as exc:
        return exc.status_code, exc.detail
    except Exception as exc:  # pragma: no cover - diagnostic mutation path
        return None, f"raised:{type(exc).__name__}:{exc}"
    return None, f"accepted:{value}"


check(
    "test_recipe_rejects_unsupported_pair_with_specific_reason",
    rejected("crypto-pwn"),
    (400, "unsupported hybrid recipe; allowed recipes are rev-pwn and web-pwn"),
)
check(
    "test_recipe_rejects_three_stages_with_specific_reason",
    rejected("rev-pwn-web"),
    (400, "hybrid recipe must contain exactly two stages"),
)
check(
    "test_recipe_rejects_live_fire_with_specific_reason",
    rejected("live-fire-pwn"),
    (400, "live-fire is a separate patch workflow and cannot be a hybrid stage"),
)
check(
    "test_recipe_rejects_empty_value_with_specific_reason",
    rejected("  "),
    (400, "hybrid recipe is required"),
)


# ----------------------------------------------------------- real endpoint
class Upload:
    def __init__(self, filename: str, content: bytes):
        self.filename = filename
        self._content = content

    async def read(self) -> bytes:
        return self._content


def submit(**overrides):
    values = {
        "recipe": "rev-pwn",
        "file": None,
        "description": "S2 fixture",
        "flag_format": "DH{...}",
        "model": "",
        "effort": "high",
        "job_timeout": 321,
        "rev_target": "rev.example:1337",
        "rev_docker": True,
        "web_target_url": None,
        "web_docker": False,
        "pwn_target": "pwn-a.example:31337\npwn-b.example:31338",
        "pwn_docker": False,
    }
    values.update(overrides)
    return asyncio.run(analyze_hybrid(**values))


upload_response = None
upload_error = None
try:
    upload_response = submit(file=Upload("challenge.zip", b"fixture-archive"))
except Exception as exc:  # a broken ingest becomes data, not an aborted suite
    upload_error = f"{type(exc).__name__}:{exc}"

check("test_uploaded_route_completes_parent_creation", upload_error, None)
upload_id = upload_response.get("job_id") if isinstance(upload_response, dict) else "a10000000001"
parent_dir = JOBS / upload_id
parent_files = sorted(path.name for path in parent_dir.iterdir()) if parent_dir.is_dir() else []
check(
    "test_uploaded_parent_directory_contains_meta_json_only",
    parent_files,
    ["meta.json"],
)
check(
    "test_upload_is_saved_outside_the_parent_directory",
    (UPLOADS / upload_id / "challenge.zip").read_bytes()
    if (UPLOADS / upload_id / "challenge.zip").is_file()
    else None,
    b"fixture-archive",
)
check(
    "test_actual_scan_job_for_flags_uploaded_parent_is_empty",
    COMMON.scan_job_for_flags(upload_id),
    [],
)

# A second, independent remote-only submit proves the route-created document
# is accepted by the actual coordinator even if the upload-path mutation broke
# the first case.
remote_response = None
remote_error = None
try:
    remote_response = submit(
        recipe="web-pwn",
        file=None,
        rev_target=None,
        rev_docker=False,
        web_target_url="https://web.example/one\nhttps://web.example/two",
        web_docker=True,
    )
except Exception as exc:
    remote_error = f"{type(exc).__name__}:{exc}"

check("test_remote_route_completes_parent_creation", remote_error, None)
remote_id = remote_response.get("job_id") if isinstance(remote_response, dict) else "a10000000002"
remote_meta_path = JOBS / remote_id / "meta.json"
remote_meta = (
    json.loads(remote_meta_path.read_text(encoding="utf-8"))
    if remote_meta_path.is_file()
    else {}
)
check(
    "test_route_meta_has_canonical_hybrid_schema",
    (
        remote_meta.get("module"),
        remote_meta.get("modules"),
        (remote_meta.get("hybrid") or {}).get("recipe"),
    ),
    ("hybrid", ["web", "pwn"], "web-pwn"),
)
check(
    "test_route_meta_preserves_ordered_scalar_inputs",
    remote_meta.get("inputs"),
    {
        "web": {
            "target_url": "https://web.example/one",
            "target_urls": ["https://web.example/one", "https://web.example/two"],
            "docker_challenge": True,
        },
        "pwn": {
            "target": "pwn-a.example:31337",
            "targets": ["pwn-a.example:31337", "pwn-b.example:31338"],
            "docker_challenge": False,
        },
    },
)
coordinator_read = None
try:
    started = HybridCoordinator(JOBS).start(remote_id, "a10000000003")
    coordinator_read = (
        started["status"],
        started["hybrid"]["stages"][0]["module"],
        sorted(path.name for path in (JOBS / remote_id).iterdir()),
    )
except Exception as exc:
    coordinator_read = f"raised:{type(exc).__name__}:{exc}"
check(
    "test_actual_coordinator_reads_and_starts_route_created_parent",
    coordinator_read,
    ("running", "web", ["meta.json"]),
)
check("test_route_calls_agent_provider_enrichment", len(enriched), 2)
check(
    "test_each_created_parent_is_enqueued_once_to_hybrid_worker",
    [
        (
            function,
            positional,
            keywords.get("job_id"),
            keywords.get("job_timeout"),
            getattr(keywords.get("on_failure"), "name", None),
            getattr(keywords.get("on_failure"), "timeout", None),
        )
        for function, positional, keywords in enqueued
    ],
    [
        (
            "modules.hybrid.worker.run_job",
            (upload_id,),
            upload_id,
            1284,
            "modules.hybrid.coordinator.fail_parent_on_rq_failure",
            10,
        ),
        (
            "modules.hybrid.worker.run_job",
            (remote_id,),
            remote_id,
            1284,
            "modules.hybrid.coordinator.fail_parent_on_rq_failure",
            10,
        ),
    ],
)

# RQ resolves the function before calling it.  Invoke only the separately
# stored failure callback, as RQ does after a nonexistent entrypoint fails, so
# this probe cannot accidentally get protection from run_job's own try/except.
rq_failure_error = ModuleNotFoundError(
    "No module named 'modules.missing_hybrid_entrypoint'"
)
failure_callback = enqueued[0][2].get("on_failure") if enqueued else None
callback_error = None
try:
    if failure_callback is None:
        callback_error = "missing failure callback"
    else:
        failure_callback.func(
            types.SimpleNamespace(id=upload_id),
            None,
            ModuleNotFoundError,
            rq_failure_error,
            None,
        )
except Exception as exc:
    callback_error = f"{type(exc).__name__}:{exc}"

failed_entrypoint_meta = (
    json.loads((JOBS / upload_id / "meta.json").read_text(encoding="utf-8"))
    if (JOBS / upload_id / "meta.json").is_file()
    else {}
)
check(
    "test_nonexistent_rq_entrypoint_callback_terminalizes_queued_hybrid_parent",
    (
        callback_error,
        failed_entrypoint_meta.get("status"),
        failed_entrypoint_meta.get("error"),
        isinstance(failed_entrypoint_meta.get("finished_at"), str),
    ),
    (
        None,
        "failed",
        "No module named 'modules.missing_hybrid_entrypoint'",
        True,
    ),
)


# --------------------------------------------------------- API/UI surface
html = (ROOT / "web-ui" / "index.html").read_text(encoding="utf-8")
app_js = (ROOT / "web-ui" / "app.js").read_text(encoding="utf-8")
style_bytes = (ROOT / "web-ui" / "style.css").read_bytes()
main_source = (ROOT / "api" / "main.py").read_text(encoding="utf-8")

asset_hash = hashlib.sha256()
asset_hash.update(app_js.encode())
asset_hash.update(style_bytes)
expected_buster = f"?v=a{asset_hash.hexdigest()[:8]}"
if args.mutate == "stale-buster":
    html = html.replace(expected_buster, "?v=a00000000")

check("test_hybrid_form_exists", 'id="hybrid-form"' in html, True)
check(
    "test_hybrid_form_shows_initial_execution_order",
    '<b>Execution order</b> rev → pwn' in html,
    True,
)
check(
    "test_hybrid_ui_renders_selected_execution_order",
    '"rev-pwn": ["rev", "pwn"]' in app_js
    and '"web-pwn": ["web", "pwn"]' in app_js
    and 'modules.join(" → ")' in app_js,
    True,
)
check(
    "test_hybrid_form_submits_to_hybrid_analyze_route",
    'submitJob(e.target, "/modules/hybrid/analyze")' in app_js,
    True,
)

job_form_ids = re.findall(
    r'<form id="((?:web|pwn|forensic|misc|crypto|web3|rev|hybrid|live-fire)-form)"',
    html,
)
check(
    "test_existing_job_forms_remain_and_hybrid_makes_nine",
    job_form_ids,
    [
        "web-form",
        "pwn-form",
        "forensic-form",
        "misc-form",
        "crypto-form",
        "web3-form",
        "rev-form",
        "hybrid-form",
        "live-fire-form",
    ],
)
check(
    "test_hybrid_route_is_registered_once",
    main_source.count(
        'app.include_router(hybrid_module.router, prefix="/api/modules/hybrid", tags=["hybrid"])'
    ),
    1,
)
module_ids = re.findall(
    r'\{"id": "(web|pwn|forensic|misc|crypto|rev|web3|hybrid|live-fire)"',
    main_source,
)
check(
    "test_existing_api_modules_remain_and_hybrid_makes_nine",
    module_ids,
    ["web", "pwn", "forensic", "misc", "crypto", "rev", "web3", "hybrid", "live-fire"],
)
check(
    "test_index_cache_buster_tracks_shipped_assets",
    expected_buster in html,
    True,
)
busters = re.findall(r'(?:style\.css|app\.js)\?v=([0-9a-z-]+)', html)
check(
    "test_style_and_script_cache_busters_match",
    len(busters) == 2 and len(set(busters)) == 1,
    True,
)
check("test_mutation_suite_reaches_final_named_check", True, True)

TMP.cleanup()
print(f"hybrid-ingest: {passed} passed, {failed} failed; mutation={args.mutate}")
raise SystemExit(1 if failed else 0)
