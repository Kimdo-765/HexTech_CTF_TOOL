#!/usr/bin/env python3
"""LF-5 API/worker contract, positive control, and bind-mount regression."""

from __future__ import annotations

import argparse
import asyncio
import inspect
import json
import stat
import sys
import tempfile
import types
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules import live_fire_job as live_job  # noqa: E402
from modules import live_fire_patch_loop as patch_loop  # noqa: E402
from modules import live_fire_provider as routing  # noqa: E402
from modules import live_fire_verifier as verifier  # noqa: E402


parser = argparse.ArgumentParser()
parser.add_argument(
    "--mutate", choices=("none", "form-route", "bind-mount"), default="none"
)
args = parser.parse_args()

passed = 0
failed = 0


def check(label, got, want=True):
    global passed, failed
    if got == want:
        passed += 1
        print(f"PASS  {label}")
    else:
        failed += 1
        print(f"FAIL  {label}\n      got  = {got!r}\n      want = {want!r}")


def source_zip(path: Path) -> Path:
    entries = {
        "Dockerfile": b"FROM python:3.11-alpine\nCOPY . /srv\n",
        "app.py": VULNERABLE.encode(),
        "public/hello.txt": b"hello-service\n",
        "secret.txt": b"FLAG{lf5-fixture}\n",
        "tests/test_app.py": b"# existing tests\n",
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            info = zipfile.ZipInfo(name, (2026, 8, 10, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
    return path


HEALTH = ("probe", "health")
BENIGN = ("probe", "benign")
EXISTING_TEST = ("probe", "existing-test")
ATTACK = ("probe", "attack")

CONTRACT = {
    "mitigation_class": "root-cause-fix",
    "start_command": [],
    "health_command": list(HEALTH),
    "verification_reserve_s": 20,
    "packaging_reserve_s": 10,
    "max_attempts": 2,
    "limits": {
        "cpus": 0.5,
        "memory": "128m",
        "pids": 32,
        "build_timeout_s": 2,
        "start_timeout_s": 1,
        "health_timeout_s": 1,
        "probe_timeout_s": 1,
        "tmpfs_size": "8m",
    },
    "probes": [
        {"name": "hello", "corpus": "benign", "command": list(BENIGN)},
        {
            "name": "existing-tests",
            "corpus": "benign",
            "command": list(EXISTING_TEST),
        },
        {
            "name": "path-traversal",
            "corpus": "attack",
            "command": list(ATTACK),
            "evidence_tier": "B",
            "attack_expectation": {
                "exit_code": 0,
                "stdout_contains": "FLAG{lf5-fixture}",
            },
        },
    ],
}

VULNERABLE = """from pathlib import Path
HEALTH_PATH = '/health'

ROOT = Path('/srv/public')
def read_file(name):
    return (ROOT / name).read_text()
"""

PATCHED = """from pathlib import Path
HEALTH_PATH = '/health'

ROOT = Path('/srv/public').resolve()
def read_file(name):
    target = (ROOT / name).resolve()
    if target != ROOT and ROOT not in target.parents:
        raise PermissionError('path escapes public root')
    return target.read_text()
"""


class RecordingRunner:
    def __init__(self):
        self.candidate_secure = False

    @staticmethod
    def _side(container):
        if "-o-svc" in container:
            return "original"
        if "-c-svc" in container:
            return "candidate"
        raise AssertionError(container)

    def run(self, argv, timeout_s):
        docker = tuple(argv[1:])
        if docker[0] == "build":
            context = Path(docker[-1])
            if context.name == "candidate":
                self.candidate_secure = "path escapes public root" in (
                    context / "app.py"
                ).read_text(encoding="utf-8")
            return verifier.CommandResult(0, stdout="built")
        if docker[:2] == ("network", "create"):
            return verifier.CommandResult(0, stdout="network")
        if docker[0] in {"create", "start"}:
            return verifier.CommandResult(0, stdout="started")
        if docker[0] == "exec":
            side = self._side(docker[1])
            probe = tuple(docker[2:])
            if probe in {HEALTH, BENIGN}:
                return verifier.CommandResult(0, stdout="hello-service\n")
            if probe == EXISTING_TEST:
                return verifier.CommandResult(0, stdout="tests passed\n")
            if probe == ATTACK:
                if side == "candidate" and self.candidate_secure:
                    return verifier.CommandResult(1, stderr="PermissionError")
                return verifier.CommandResult(0, stdout="FLAG{lf5-fixture}\n")
        if docker[:2] in {
            ("rm", "--force"),
            ("network", "rm"),
            ("image", "rm"),
        }:
            return verifier.CommandResult(0, stdout="removed")
        return verifier.CommandResult(127, stderr="unexpected docker command")


def runtime_factory():
    return verifier.DockerRuntime(runner=RecordingRunner())


def valid_finding():
    return patch_loop.VulnerabilityFinding(
        bug_class="path traversal",
        severity="high",
        path="app.py",
        line=6,
        root_cause="an untrusted relative path was joined without containment",
        attack_impact="the fixed attack reads a secret outside the public root",
        patch_description="resolve the requested path and reject targets outside ROOT",
        patch_reason="preserve public reads while blocking traversal",
        mitigation_class="root-cause-fix",
        evidence_tier="B",
    )


class PositiveInvoker:
    def invoke(self, call):
        if call.route.role == "main":
            (call.payload.candidate / "app.py").write_text(PATCHED, encoding="utf-8")
            value = patch_loop.ProviderResult(
                "success", "patched containment", (valid_finding(),), True
            )
        elif call.route.role == "reviewer":
            value = patch_loop.ReviewResult("use the machine evidence")
        else:
            value = patch_loop._render_report(
                call.payload.document, call.payload.findings, call.payload.diffs
            )
        return routing.AgentInvocationResult(value, routing.AgentUsage(model="fixture"))


def run_worker_case(base: Path, job_id: str, invoker):
    root = base / job_id
    root.mkdir()
    archive = source_zip(root / "input.zip")
    meta = {
        "id": job_id,
        "module": "live-fire",
        "status": "queued",
        "job_timeout": 100,
        "model": None,
        "live_fire_contract": CONTRACT,
        "agent_provider": "claude",
    }

    def read_meta(_job_id):
        return dict(meta)

    def write_meta(_job_id, **updates):
        meta.update(updates)
        (root / "meta.json").write_text(json.dumps(meta), encoding="utf-8")

    live_job.job_dir = lambda _job_id: root
    live_job.read_meta = read_meta
    live_job.write_meta = write_meta
    live_job.log_line = lambda _job_id, line: (root / "run.log").write_text(line)
    old_provider = routing._provider_for_role
    old_usage = routing._record_call_usage
    routing._provider_for_role = lambda _job_id, role: "claude"
    routing._record_call_usage = lambda call, result: None
    try:
        result = live_job.run_job(
            job_id,
            str(archive),
            invoker=invoker,
            runtime_factory=runtime_factory,
        )
    finally:
        routing._provider_for_role = old_provider
        routing._record_call_usage = old_usage
    return root, meta, result


# ------------------------------------------------------------------ API route
# Host test environments intentionally omit FastAPI/RQ. Stub only the imports
# used by this route, then call the real async endpoint function.
fastapi = types.ModuleType("fastapi")


class HTTPException(Exception):
    def __init__(self, status_code, detail):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


class APIRouter:
    def post(self, path):
        return lambda fn: fn


fastapi.APIRouter = APIRouter
fastapi.File = lambda default=None: default
fastapi.Form = lambda default=None: default
fastapi.HTTPException = HTTPException
fastapi.UploadFile = object
sys.modules["fastapi"] = fastapi

queue_calls = []


class FakeQueue:
    def enqueue(self, *positional, **keyword):
        queue_calls.append((positional, keyword))


queue_module = types.ModuleType("api.queue")
queue_module.get_queue = lambda: FakeQueue()
queue_module.hard_timeout_for = lambda timeout: timeout * 4
queue_module.normalize_effort = lambda effort: (effort or "").strip() or None
queue_module.resolve_timeout = lambda timeout: (
    timeout if timeout and timeout > 0 else 6000
)
sys.modules["api.queue"] = queue_module

saved_meta = {}
saved_uploads = []
storage_module = types.ModuleType("api.storage")
storage_module.new_job_id = lambda: "lf5route0001"
storage_module.save_upload = lambda job, name, content: (
    saved_uploads.append((job, name, content))
    or Path("/data/jobs") / job / "src" / name
)
storage_module.write_job_meta = lambda job, meta: saved_meta.update(meta)
sys.modules["api.storage"] = storage_module

agent_provider = types.ModuleType("modules.agent_provider")
agent_provider.enrich_job_meta = lambda meta: (
    meta.update(agent_provider="claude") or meta
)
sys.modules["modules.agent_provider"] = agent_provider

from api.routes import live_fire_module as route  # noqa: E402


class Upload:
    def __init__(self, filename, content):
        self.filename = filename
        self.content = content

    async def read(self):
        return self.content


with tempfile.TemporaryDirectory(prefix="live-fire-lf5-") as tmp:
    base = Path(tmp)
    archive = source_zip(base / "route.zip").read_bytes()
    response = asyncio.run(
        route.analyze_live_fire(
            Upload("../service.ZIP", archive),
            json.dumps(CONTRACT),
            "operator note",
            100,
            "",
            "high",
        )
    )
    check("ZIP submit returns its created job id", response["job_id"], "lf5route0001")
    check(
        "route stores only the basename shown to the operator",
        saved_meta["filename"],
        "service.ZIP",
    )
    check("route snapshots the live-fire module", saved_meta["module"], "live-fire")
    check("route snapshots the requested job timeout", saved_meta["job_timeout"], 100)
    check("route carries operator effort", saved_meta["effort"], "high")
    check(
        "route stores the validated verifier contract",
        saved_meta["live_fire_contract"]["max_attempts"],
        2,
    )
    check("route saves under a canonical input.zip", saved_uploads[0][1], "input.zip")
    check(
        "route enqueues the real worker entry point",
        queue_calls[0][0][0],
        "modules.live_fire_job.run_job",
    )
    check("RQ timeout derives from job_timeout", queue_calls[0][1]["job_timeout"], 400)

    try:
        asyncio.run(
            route.analyze_live_fire(
                Upload("not.zip", b"not a zip"),
                json.dumps(CONTRACT),
                None,
                100,
                None,
                None,
            )
        )
        invalid_rejected = False
    except HTTPException as exc:
        invalid_rejected = exc.status_code == 400
    check("invalid ZIP is rejected before job creation", invalid_rejected)

    positive_root, positive_meta, positive = run_worker_case(
        base, "lf5positive", PositiveInvoker()
    )
    check("positive worker reaches READY", positive["ready_to_deploy"], True)
    check("positive worker publishes evidence tier", positive["evidence_tiers"], ["B"])
    check("positive worker lifecycle finishes", positive_meta["status"], "finished")
    for artifact in ("patched.zip", "report.md", "verification.json"):
        check(
            f"positive worker emits separate {artifact}",
            (positive_root / artifact).is_file(),
        )
    check(
        "patched ZIP does not contain report.md",
        "report.md" in zipfile.ZipFile(positive_root / "patched.zip").namelist(),
        False,
    )

    diagnostic_root, diagnostic_meta, diagnostic = run_worker_case(
        base, "lf5diagnostic", live_job.DiagnosticInvoker()
    )
    check("diagnostic worker remains UNVERIFIED", diagnostic["ready_to_deploy"], False)
    check(
        "UNVERIFIED is a finished lifecycle, not a false job failure",
        diagnostic_meta["status"],
        "finished",
    )
    for artifact in ("patched.zip", "report.md", "verification.json"):
        check(
            f"UNVERIFIED worker retains diagnostic {artifact}",
            (diagnostic_root / artifact).is_file(),
        )


# ---------------------------------------------------------- form/route parity
html = (ROOT / "web-ui" / "index.html").read_text(encoding="utf-8")
panel = html.split('id="live-fire-form"', 1)[1].split("</form>", 1)[0]
form_fields = {
    token.split('name="', 1)[1].split('"', 1)[0]
    for token in panel.split("<")
    if 'name="' in token
}
route_fields = set(inspect.signature(route.analyze_live_fire).parameters)
if args.mutate == "form-route":
    route_fields.discard("verification")
check("live-fire form fields equal route parameters", form_fields, route_fields)


# ------------------------------------------------------------- bind mount ban
if args.mutate == "bind-mount":
    verifier.DockerRuntime._guard_no_bind_mount_args = staticmethod(lambda argv: None)
for mount_args in (
    ("create", "-v", "/data/jobs/x:/srv"),
    ("create", "-v/data/jobs/x:/srv"),
    ("create", "--volume=/data/jobs/x:/srv"),
    ("create", "--mount", "type=bind,src=/data/jobs/x,dst=/srv"),
    ("create", "--mount=type=bind,src=/data/jobs/x,dst=/srv"),
):
    try:
        verifier.DockerRuntime._guard_no_bind_mount_args(mount_args)
        mount_rejected = False
    except verifier.VerificationError:
        mount_rejected = True
    check(f"bind mount form {mount_args[1]} is rejected", mount_rejected)

recorded = []
original_guard = verifier.DockerRuntime._guard_no_bind_mount_args
verifier.DockerRuntime._guard_no_bind_mount_args = staticmethod(
    lambda argv: recorded.append(tuple(argv)) or original_guard(argv)
)
runtime = verifier.DockerRuntime(runner=RecordingRunner())
runtime.build_image(
    Path("/data/jobs/x/original"), "image", {}, verifier.ContainerLimits()
)
runtime.create_container(
    image="image",
    name="lf-o-svc",
    network="network",
    labels={},
    command=(),
    limits=verifier.ContainerLimits(),
)
check("normal build and create both cross the no-bind guard", len(recorded), 2)

print(f"\n== summary: {passed} passed, {failed} failed; mutation={args.mutate} ==")
raise SystemExit(1 if failed else 0)
