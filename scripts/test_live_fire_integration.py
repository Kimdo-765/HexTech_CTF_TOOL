#!/usr/bin/env python3
"""LF-6 API-to-artifact integration and adversarial mutation gate.

The normal run submits two independent stack fixtures through the real API
handler, executes the queued worker entry point, and reopens the resulting ZIP
with the LF-1 validator.  The remaining cases carry the LF-1 archive battery,
LF-2 SLA oracle, LF-3 source policy and time reservation, LF-4 routed roles,
and LF-5 artifact contract across that same worker boundary.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
import stat
import struct
import sys
import tempfile
import types
import warnings
import zipfile
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules import live_fire_job as live_job  # noqa: E402
from modules import live_fire_patch_loop as patch_loop  # noqa: E402
from modules import live_fire_provider as routing  # noqa: E402
from modules import live_fire_verifier as verifier  # noqa: E402
from modules import live_fire_workspace as workspace_module  # noqa: E402


parser = argparse.ArgumentParser()
parser.add_argument(
    "--mutate",
    choices=(
        "provider-link",
        "ingest-guard",
        "sla-gate",
        "deployment-policy",
        "time-reserve",
        "zip-reopen",
    ),
)
args = parser.parse_args()


# The mutation points are test-process monkeypatches.  Production contains no
# mutation switch, and every mutation keeps the pipeline runnable so failures
# identify a severed defense rather than a module import/crash.
if args.mutate == "provider-link":
    _real_routed_loop = live_job.run_routed_patch_loop

    def _disconnected_provider(
        job_id, workspace, output_dir, spec, invoker, **kwargs
    ):
        return _real_routed_loop(
            job_id,
            workspace,
            output_dir,
            spec,
            live_job.DiagnosticInvoker(),
            **kwargs,
        )

    live_job.run_routed_patch_loop = _disconnected_provider
elif args.mutate == "ingest-guard":
    workspace_module._guard_traversal = lambda raw_name: None
elif args.mutate == "sla-gate":
    _real_evaluate_probes = verifier._evaluate_probes

    def _ignore_sla(probes, original, candidate):
        sla, security = _real_evaluate_probes(probes, original, candidate)
        sla = dict(sla)
        sla["probes"] = [dict(row, passed=True, equal=True) for row in sla["probes"]]
        sla["passed"] = True
        return sla, security

    verifier._evaluate_probes = _ignore_sla
elif args.mutate == "deployment-policy":
    patch_loop._source_policy_errors = lambda ws, policy, diffs: []
elif args.mutate == "time-reserve":
    patch_loop._has_attempt_budget = lambda remaining, verification, packaging: True
elif args.mutate == "zip-reopen":
    _real_inspect_archive = workspace_module._inspect_archive

    def _skip_builder_reopen(archive, archive_path, limits):
        if Path(archive_path).name.startswith(".patched.zip.tmp-"):
            return None
        return _real_inspect_archive(archive, archive_path, limits)

    workspace_module._inspect_archive = _skip_builder_reopen


test_tmpdir = os.environ.get("LIVE_FIRE_TEST_TMPDIR") or None
TMP = tempfile.TemporaryDirectory(prefix="live-fire-integration-", dir=test_tmpdir)
BASE = Path(TMP.name)
P = F = 0


def check(label, got, want=True):
    global P, F
    if got == want:
        P += 1
    else:
        F += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


def make_writable(root: Path) -> None:
    if not root.exists():
        return
    for directory, dirnames, filenames in os.walk(
        root, topdown=False, followlinks=False
    ):
        for name in filenames:
            path = Path(directory) / name
            if not path.is_symlink():
                try:
                    path.chmod(0o600)
                except OSError:
                    pass
        for name in dirnames:
            path = Path(directory) / name
            if not path.is_symlink():
                try:
                    path.chmod(0o700)
                except OSError:
                    pass
        try:
            Path(directory).chmod(0o700)
        except OSError:
            pass


STAMP = (2026, 8, 10, 0, 0, 0)
HEALTH = ("probe", "health")
BENIGN = ("probe", "benign")
EXISTING_TEST = ("probe", "existing-test")
ATTACK = ("probe", "attack")


@dataclass(frozen=True)
class StackFixture:
    name: str
    source_path: str
    vulnerable: str
    patched: str
    secret: str
    stacks: tuple[str, ...]
    entrypoint: str


PYTHON = StackFixture(
    name="python",
    source_path="app.py",
    vulnerable="ROOT = '/srv/public'\ndef read_file(name):\n    return ROOT + '/' + name\n",
    patched=(
        "ROOT = '/srv/public'\nPATCHED_CONTAINMENT = True\n"
        "def read_file(name):\n    return ROOT + '/' + name\n"
    ),
    secret="FLAG{lf6-python}",
    stacks=("docker", "python"),
    entrypoint="app.py",
)
NODE = StackFixture(
    name="node",
    source_path="server.js",
    vulnerable=(
        "const ROOT = '/srv/public';\n"
        "function readFile(name) { return `${ROOT}/${name}`; }\n"
    ),
    patched=(
        "const ROOT = '/srv/public';\nconst PATCHED_CONTAINMENT = true;\n"
        "function readFile(name) { return `${ROOT}/${name}`; }\n"
    ),
    secret="FLAG{lf6-node}",
    stacks=("docker", "node"),
    entrypoint="server.js",
)


def zip_info(name: str, mode: int, *, compression=zipfile.ZIP_DEFLATED, extra=b""):
    info = zipfile.ZipInfo(name, STAMP)
    info.create_system = 3
    info.external_attr = (mode & 0xFFFF) << 16
    info.compress_type = compression
    info.extra = extra
    return info


def write_archive(path: Path, entries) -> bytes:
    with zipfile.ZipFile(path, "w") as archive:
        for info, payload in entries:
            archive.writestr(info, payload)
    return path.read_bytes()


def stack_archive(path: Path, fixture: StackFixture) -> bytes:
    entries = [
        (
            zip_info("Dockerfile", stat.S_IFREG | 0o644),
            b"FROM fixture:latest\nCOPY . /srv\n",
        ),
        (
            zip_info(fixture.source_path, stat.S_IFREG | 0o644),
            fixture.vulnerable.encode(),
        ),
        (zip_info("public/hello.txt", stat.S_IFREG | 0o644), b"hello-service\n"),
        (
            zip_info("secret.txt", stat.S_IFREG | 0o600),
            (fixture.secret + "\n").encode(),
        ),
        (zip_info("tests/regression.txt", stat.S_IFREG | 0o644), b"existing-tests\n"),
    ]
    if fixture.name == "node":
        entries.append(
            (
                zip_info("package.json", stat.S_IFREG | 0o644),
                b'{"scripts":{"start":"node server.js"}}\n',
            )
        )
    return write_archive(path, entries)


def contract(fixture: StackFixture) -> dict:
    return {
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
                "name": "fixed-attack",
                "corpus": "attack",
                "command": list(ATTACK),
                "evidence_tier": "B",
                "attack_expectation": {
                    "exit_code": 0,
                    "stdout_contains": fixture.secret,
                },
            },
        ],
    }


class Upload:
    def __init__(self, filename: str, content: bytes):
        self.filename = filename
        self.content = content

    async def read(self):
        return self.content


# Import the real API route with small host-only substitutes for FastAPI, RQ,
# and storage.  The route logic itself remains unchanged.
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

METAS: dict[str, dict] = {}
QUEUE: list[tuple[tuple, dict]] = []
NEXT_JOB_ID = ""


class FakeQueue:
    def enqueue(self, *positional, **keyword):
        QUEUE.append((positional, keyword))


queue_module = types.ModuleType("api.queue")
queue_module.get_queue = lambda: FakeQueue()
queue_module.hard_timeout_for = lambda timeout: timeout * 4
queue_module.normalize_effort = lambda effort: (effort or "").strip() or None
queue_module.resolve_timeout = lambda timeout: timeout if timeout and timeout > 0 else 6000
sys.modules["api.queue"] = queue_module


def save_upload(job_id, name, content):
    root = BASE / job_id
    root.mkdir(parents=True, exist_ok=True)
    target = root / name
    target.write_bytes(content)
    return target


storage_module = types.ModuleType("api.storage")
storage_module.new_job_id = lambda: NEXT_JOB_ID
storage_module.save_upload = save_upload
storage_module.write_job_meta = lambda job_id, meta: METAS.__setitem__(
    job_id, copy.deepcopy(meta)
)
sys.modules["api.storage"] = storage_module

route_agent_provider = types.ModuleType("modules.agent_provider")
route_agent_provider.enrich_job_meta = lambda meta: (
    meta.update(agent_provider="claude", agent_role_providers={}) or meta
)
sys.modules["modules.agent_provider"] = route_agent_provider

from api.routes import live_fire_module as route  # noqa: E402


def submit(job_id: str, archive: bytes, fixture: StackFixture = PYTHON) -> tuple[str, str]:
    global NEXT_JOB_ID
    NEXT_JOB_ID = job_id
    before = len(QUEUE)
    response = asyncio.run(
        route.analyze_live_fire(
            Upload(f"../{fixture.name}.ZIP", archive),
            json.dumps(contract(fixture)),
            f"LF-6 {fixture.name} fixture",
            100,
            "",
            "high",
        )
    )
    check(f"{job_id}: API returns queued job", response["job_id"], job_id)
    check(f"{job_id}: API enqueues exactly once", len(QUEUE) - before, 1)
    positional, keyword = QUEUE[-1]
    check(
        f"{job_id}: API queues production worker",
        positional[0],
        "modules.live_fire_job.run_job",
    )
    check(f"{job_id}: RQ timeout derives from contract", keyword["job_timeout"], 400)
    return positional[1], positional[2]


def _read_meta(job_id):
    return copy.deepcopy(METAS[job_id])


def _write_meta(job_id, **updates):
    METAS[job_id].update(updates)
    (BASE / job_id / "meta.json").write_text(
        json.dumps(METAS[job_id], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _log_line(job_id, line):
    with (BASE / job_id / "run.log").open("a", encoding="utf-8") as output:
        output.write(line)


live_job.job_dir = lambda job_id: BASE / job_id
live_job.read_meta = _read_meta
live_job.write_meta = _write_meta
live_job.log_line = _log_line
routing._provider_for_role = lambda job_id, role: "claude"
routing._record_call_usage = lambda call, result: None


class RecordingRunner:
    def __init__(self, fixture: StackFixture, *, candidate_drift=False):
        self.fixture = fixture
        self.candidate_drift = candidate_drift
        self.candidate_secure = False
        self.calls = []

    @staticmethod
    def _side(container):
        if "-o-svc" in container:
            return "original"
        if "-c-svc" in container:
            return "candidate"
        raise AssertionError(container)

    def run(self, argv, timeout_s):
        command = tuple(argv)
        self.calls.append(command)
        docker = command[1:]
        if docker[0] == "build":
            context = Path(docker[-1])
            if context.name == "candidate":
                body = (context / self.fixture.source_path).read_text(encoding="utf-8")
                self.candidate_secure = "PATCHED_CONTAINMENT" in body
            return verifier.CommandResult(0, stdout="built")
        if docker[:2] == ("network", "create"):
            return verifier.CommandResult(0, stdout="network")
        if docker[0] in {"create", "start"}:
            return verifier.CommandResult(0, stdout="started")
        if docker[0] == "exec":
            side = self._side(docker[1])
            probe = tuple(docker[2:])
            if probe == HEALTH:
                return verifier.CommandResult(0, stdout="healthy\n")
            if probe == BENIGN:
                output = (
                    "candidate-drift\n"
                    if side == "candidate" and self.candidate_drift
                    else "hello-service\n"
                )
                return verifier.CommandResult(0, stdout=output)
            if probe == EXISTING_TEST:
                return verifier.CommandResult(0, stdout="existing-tests\n")
            if probe == ATTACK:
                if side == "candidate" and self.candidate_secure:
                    return verifier.CommandResult(1, stderr="blocked")
                return verifier.CommandResult(0, stdout=self.fixture.secret + "\n")
        if docker[:2] in {
            ("rm", "--force"),
            ("network", "rm"),
            ("image", "rm"),
        }:
            return verifier.CommandResult(0, stdout="removed")
        return verifier.CommandResult(127, stderr="unexpected command")


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now


class FixtureInvoker:
    def __init__(
        self,
        fixture: StackFixture,
        *,
        deployment_change=False,
        reserve_case=False,
        clock: FakeClock | None = None,
    ):
        self.fixture = fixture
        self.deployment_change = deployment_change
        self.reserve_case = reserve_case
        self.clock = clock
        self.calls = []
        self.main_calls = 0

    def finding(self):
        return patch_loop.VulnerabilityFinding(
            bug_class="path traversal",
            severity="high",
            path=self.fixture.source_path,
            line=2,
            root_cause="untrusted input was joined without containment",
            attack_impact="the fixed attack exposed a secret outside the public root",
            patch_description="resolve and contain the requested path",
            patch_reason="preserve benign behavior while blocking traversal",
            mitigation_class="root-cause-fix",
            evidence_tier="B",
        )

    def invoke(self, call):
        self.calls.append(call)
        if call.route.role == "main":
            self.main_calls += 1
            if self.reserve_case and self.main_calls == 1:
                if self.clock is not None:
                    self.clock.now += 75
                value = patch_loop.ProviderResult("failure", "retry requested")
            else:
                (call.payload.candidate / self.fixture.source_path).write_text(
                    self.fixture.patched, encoding="utf-8"
                )
                if self.deployment_change:
                    (call.payload.candidate / "Dockerfile").write_text(
                        "FROM sidecar:latest\nCOPY . /srv\n", encoding="utf-8"
                    )
                value = patch_loop.ProviderResult(
                    "success",
                    "patched traversal",
                    (self.finding(),),
                    ready_recommendation=True,
                )
        elif call.route.role == "reviewer":
            value = patch_loop.ReviewResult("follow machine evidence", passed=True)
        else:
            value = patch_loop._render_report(
                call.payload.document, call.payload.findings, call.payload.diffs
            )
        return routing.AgentInvocationResult(
            value=value,
            usage=routing.AgentUsage(model="fixture-model"),
        )


def run_submitted(
    job_id: str,
    archive_path: str,
    invoker,
    fixture: StackFixture = PYTHON,
    *,
    candidate_drift=False,
    clock=None,
    ingest_limits=None,
):
    real_create_workspace = live_job.create_workspace
    if ingest_limits is not None:
        live_job.create_workspace = lambda archive, root: real_create_workspace(
            archive, root, limits=ingest_limits
        )
    try:
        return live_job.run_job(
            job_id,
            archive_path,
            invoker=invoker,
            runtime_factory=lambda: verifier.DockerRuntime(
                runner=RecordingRunner(fixture, candidate_drift=candidate_drift)
            ),
            clock=clock,
        )
    finally:
        live_job.create_workspace = real_create_workspace


# ① Two stack fixtures traverse API → ingest → provider → verifier → artifacts.
for fixture in (PYTHON, NODE):
    job_id = f"lf6-{fixture.name}"
    payload = stack_archive(BASE / f"{fixture.name}-source.zip", fixture)
    queued_job, archive_path = submit(job_id, payload, fixture)
    invoker = FixtureInvoker(fixture)
    result = run_submitted(queued_job, archive_path, invoker, fixture)
    root = BASE / job_id
    document = result["verification"]
    check(f"{fixture.name}: end-to-end reaches READY", result["ready_to_deploy"], True)
    check(f"{fixture.name}: lifecycle finishes", METAS[job_id]["status"], "finished")
    check(
        f"{fixture.name}: static stack crosses patch loop",
        document["static_discovery"]["stacks"],
        list(fixture.stacks),
    )
    check(
        f"{fixture.name}: entrypoint crosses discovery",
        document["static_discovery"]["entrypoints"],
        [fixture.entrypoint],
    )
    check(
        f"{fixture.name}: routed main/report roles execute",
        [call.route.role for call in invoker.calls],
        ["main", "report"],
    )
    check(
        f"{fixture.name}: API result publishes three artifacts",
        result["artifacts"],
        {
            "patched_zip": "patched.zip",
            "report": "report.md",
            "verification": "verification.json",
        },
    )
    check(
        f"{fixture.name}: three artifacts exist separately",
        all((root / name).is_file() for name in result["artifacts"].values()),
    )
    with zipfile.ZipFile(root / "patched.zip") as archive:
        check(
            f"{fixture.name}: patched ZIP carries provider change",
            archive.read(fixture.source_path).decode(),
            fixture.patched,
        )
        check(f"{fixture.name}: report stays outside ZIP", "report.md" in archive.namelist(), False)
    reopened = workspace_module.create_workspace(
        root / "patched.zip", root / "reopened-workspace"
    )
    check(
        f"{fixture.name}: output reopens with safe validator",
        (reopened.original / fixture.source_path).read_text(encoding="utf-8"),
        fixture.patched,
    )


ui_source = (ROOT / "web-ui" / "app.js").read_text(encoding="utf-8")
for artifact in ("patched.zip", "report.md", "verification.json"):
    check(
        f"UI exposes separate {artifact} download",
        f"/file/{artifact}" in ui_source,
        True,
    )


# ② Seven rejection classes and four ceilings enter through the API/worker path.
def unix_link_extra(target: str) -> bytes:
    payload = struct.pack("<IIHH", 0, 0, 1000, 1000) + os.fsencode(target)
    return struct.pack("<HH", 0x000D, len(payload)) + payload


malicious: list[tuple[str, bytes, str, workspace_module.ZipLimits | None]] = []
malicious.append(
    (
        "absolute",
        write_archive(
            BASE / "bad-absolute.zip",
            [(zip_info("/etc/passwd", stat.S_IFREG | 0o644), b"x")],
        ),
        "absolute-member",
        None,
    )
)
malicious.append(
    (
        "traversal",
        write_archive(
            BASE / "bad-traversal.zip",
            [(zip_info("../../outside", stat.S_IFREG | 0o644), b"x")],
        ),
        "traversal-member",
        None,
    )
)
nul_path = BASE / "bad-nul.zip"
nul_bytes = write_archive(
    nul_path, [(zip_info("nulXname.txt", stat.S_IFREG | 0o644), b"x")]
).replace(b"nulXname.txt", b"nul\x00name.txt")
malicious.append(("nul", nul_bytes, "nul-member", None))
malicious.append(
    (
        "duplicate",
        write_archive(
            BASE / "bad-duplicate.zip",
            [
                (zip_info("same.txt", stat.S_IFREG | 0o644), b"one"),
                (zip_info("same.txt", stat.S_IFREG | 0o644), b"two"),
            ],
        ),
        "duplicate-member",
        None,
    )
)
encrypted_path = BASE / "bad-encrypted.zip"
encrypted = bytearray(
    write_archive(
        encrypted_path,
        [(zip_info("secret", stat.S_IFREG | 0o600, compression=zipfile.ZIP_STORED), b"x")],
    )
)
for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
    offset = encrypted.find(signature)
    flags = struct.unpack_from("<H", encrypted, offset + flag_offset)[0]
    struct.pack_into("<H", encrypted, offset + flag_offset, flags | 1)
malicious.append(("encrypted", bytes(encrypted), "encrypted-member", None))
malicious.append(
    (
        "special",
        write_archive(
            BASE / "bad-special.zip",
            [(zip_info("fifo", stat.S_IFIFO | 0o644), b"x")],
        ),
        "special-file",
        None,
    )
)
malicious.append(
    (
        "link",
        write_archive(
            BASE / "bad-link.zip",
            [(zip_info("links/bad", stat.S_IFLNK | 0o777), b"../../outside")],
        ),
        "outside-link",
        None,
    )
)
malicious.append(
    (
        "member-limit",
        write_archive(
            BASE / "bad-member-limit.zip",
            [
                (zip_info(f"m{index}", stat.S_IFREG | 0o644, compression=zipfile.ZIP_STORED), b"x")
                for index in range(5)
            ],
        ),
        "member-limit",
        workspace_module.ZipLimits(4, 64, 128, 200),
    )
)
malicious.append(
    (
        "file-limit",
        write_archive(
            BASE / "bad-file-limit.zip",
            [(zip_info("large", stat.S_IFREG | 0o644, compression=zipfile.ZIP_STORED), b"x" * 65)],
        ),
        "file-size-limit",
        workspace_module.ZipLimits(4, 64, 128, 200),
    )
)
malicious.append(
    (
        "total-limit",
        write_archive(
            BASE / "bad-total-limit.zip",
            [
                (zip_info("one", stat.S_IFREG | 0o644, compression=zipfile.ZIP_STORED), b"x" * 60),
                (zip_info("two", stat.S_IFREG | 0o644, compression=zipfile.ZIP_STORED), b"y" * 60),
            ],
        ),
        "total-size-limit",
        workspace_module.ZipLimits(4, 64, 100, 200),
    )
)
malicious.append(
    (
        "ratio-limit",
        write_archive(
            BASE / "bad-ratio-limit.zip",
            [(zip_info("zeros", stat.S_IFREG | 0o644), b"0" * 64)],
        ),
        "compression-ratio-limit",
        workspace_module.ZipLimits(4, 64, 128, 2),
    )
)

for label, archive_bytes, expected_code, limits in malicious:
    job_id = f"lf6-bad-{label}"
    queued_job, archive_path = submit(job_id, archive_bytes)
    invoker = FixtureInvoker(PYTHON)
    try:
        run_submitted(
            queued_job,
            archive_path,
            invoker,
            ingest_limits=limits,
        )
    except workspace_module.LiveFireArchiveError as exc:
        observed = exc.code
    except Exception as exc:
        observed = f"unexpected:{type(exc).__name__}"
    else:
        observed = "accepted"
    check(f"malicious {label} is rejected end-to-end", observed, expected_code)
    check(f"malicious {label} fails worker lifecycle", METAS[job_id]["status"], "failed")
    check(f"malicious {label} never reaches provider", invoker.main_calls, 0)


# ③ An SLA-regressing patch remains UNVERIFIED despite blocking the attack.
sla_bytes = stack_archive(BASE / "sla-source.zip", PYTHON)
sla_job, sla_archive = submit("lf6-sla", sla_bytes)
sla_invoker = FixtureInvoker(PYTHON)
sla_result = run_submitted(
    sla_job,
    sla_archive,
    sla_invoker,
    candidate_drift=True,
)
check("SLA regression cannot be READY", sla_result["ready_to_deploy"], False)
check("SLA regression is explicit", sla_result["verification"]["sla_gate"]["passed"], False)
check("SLA case still blocks the attack", sla_result["verification"]["security_gate"]["passed"], True)


# ④ Deployment-layer/WAF-sidecar edits cannot pass the Q1(A) source boundary.
deployment_bytes = stack_archive(BASE / "deployment-source.zip", PYTHON)
deployment_job, deployment_archive = submit("lf6-deployment", deployment_bytes)
deployment_invoker = FixtureInvoker(PYTHON, deployment_change=True)
deployment_result = run_submitted(
    deployment_job, deployment_archive, deployment_invoker
)
check("deployment edit cannot be READY", deployment_result["ready_to_deploy"], False)
check(
    "deployment policy names Dockerfile",
    any(
        "Dockerfile" in error
        for error in deployment_result["verification"]["policy_gate"]["errors"]
    ),
    True,
)


# ⑤ The end-to-end worker preserves verification+packaging time, not a deadline.
reserve_bytes = stack_archive(BASE / "reserve-source.zip", PYTHON)
reserve_job, reserve_archive = submit("lf6-reserve", reserve_bytes)
reserve_clock = FakeClock()
reserve_invoker = FixtureInvoker(PYTHON, reserve_case=True, clock=reserve_clock)
reserve_result = run_submitted(
    reserve_job,
    reserve_archive,
    reserve_invoker,
    clock=reserve_clock,
)
check("reservation prevents a second main attempt", reserve_invoker.main_calls, 1)
check("reserved terminal result stays UNVERIFIED", reserve_result["ready_to_deploy"], False)
check(
    "reservation reason survives API result",
    any(
        "preserve verification" in risk
        for risk in reserve_result["verification"]["residual_risks"]
    ),
    True,
)


# ⑥ Double mutation: make the builder emit duplicate names, then prove that its
# own validator reopens and rejects the bad output before publication.
zip_bytes = stack_archive(BASE / "zip-reopen-source.zip", PYTHON)
zip_job, zip_archive = submit("lf6-zip-reopen", zip_bytes)
zip_invoker = FixtureInvoker(PYTHON)
real_zipinfo_from_manifest = workspace_module._zipinfo_from_manifest


def duplicate_builder_name(member):
    info = real_zipinfo_from_manifest(member)
    info.filename = "duplicate-builder-output"
    info.orig_filename = info.filename
    return info


workspace_module._zipinfo_from_manifest = duplicate_builder_name
try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        try:
            run_submitted(zip_job, zip_archive, zip_invoker)
        except workspace_module.LiveFireArchiveError as exc:
            zip_observed = exc.code
        except Exception as exc:
            zip_observed = f"unexpected:{type(exc).__name__}"
        else:
            zip_observed = "published"
finally:
    workspace_module._zipinfo_from_manifest = real_zipinfo_from_manifest
check("builder corruption is rejected by ZIP reopen", zip_observed, "duplicate-member")
check("rejected builder output is not published", (BASE / zip_job / "patched.zip").exists(), False)


print(f"== summary: {P} passed, {F} failed; mutation={args.mutate or 'none'} ==")
make_writable(BASE)
TMP.cleanup()
raise SystemExit(1 if F else 0)
