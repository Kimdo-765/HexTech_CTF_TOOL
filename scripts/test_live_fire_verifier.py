#!/usr/bin/env python3
"""Executable LF-2 gate and required differential-oracle mutations.

The default suite uses a recording Docker runner, so it checks every isolation
and network argument even on review hosts without a Docker daemon.  Pass
``--docker-smoke`` to additionally build and run the same vulnerable/patched
HTTP fixture in real containers.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules import live_fire_verifier as verifier  # noqa: E402
from modules import live_fire_workspace as workspace_module  # noqa: E402


parser = argparse.ArgumentParser()
parser.add_argument(
    "--mutate",
    choices=(
        "corpus-separation",
        "negative-control",
        "evidence-tier",
        "build-resource-limits",
    ),
)
parser.add_argument("--docker-smoke", action="store_true")
args = parser.parse_args()

if args.mutate == "corpus-separation":
    verifier._probe_corpus = lambda probe: "benign"
elif args.mutate == "negative-control":
    verifier._original_attack_reproduced = lambda probe, original: True
elif args.mutate == "evidence-tier":
    verifier._attack_result_tier = lambda probe: None
elif args.mutate == "build-resource-limits":

    def build_without_resource_limits(self, context, image, labels, limits):
        docker_args = ["build", "--network", verifier.BUILD_NETWORK, "--tag", image]
        for key, value in sorted(labels.items()):
            docker_args.extend(("--label", f"{key}={value}"))
        docker_args.append(str(context))
        return self._run(docker_args, limits.build_timeout_s)

    verifier.DockerRuntime.build_image = build_without_resource_limits


TMP = tempfile.TemporaryDirectory(prefix="live-fire-verifier-")
BASE = Path(TMP.name)
P = F = 0


def check(label, got, want):
    global P, F
    if got == want:
        P += 1
    else:
        F += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


def write_source_zip(path: Path) -> Path:
    dockerfile = b"""FROM python:3.11-alpine
WORKDIR /srv
COPY . /srv
CMD [\"python\", \"app.py\"]
"""
    vulnerable = b"""from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path('/srv/public')

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != '/file':
            self.send_error(404)
            return
        name = parse_qs(parsed.query).get('name', [''])[0]
        try:
            body = (ROOT / name).read_bytes()
        except OSError:
            self.send_error(404)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *values):
        pass

HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
"""
    entries = {
        "Dockerfile": dockerfile,
        "app.py": vulnerable,
        "public/hello.txt": b"hello-service\n",
        "secret.txt": b"FLAG{live-fire-fixture}\n",
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            info = zipfile.ZipInfo(name, (2026, 8, 8, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
    return path


def patch_candidate(workspace: workspace_module.LiveFireWorkspace) -> None:
    patched = """from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path('/srv/public').resolve()

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != '/file':
            self.send_error(404)
            return
        name = parse_qs(parsed.query).get('name', [''])[0]
        target = (ROOT / name).resolve()
        if target != ROOT and ROOT not in target.parents:
            self.send_error(403)
            return
        try:
            body = target.read_bytes()
        except OSError:
            self.send_error(404)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *values):
        pass

HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
"""
    (workspace.candidate / "app.py").write_text(patched, encoding="utf-8")


source_zip = write_source_zip(BASE / "fixture.zip")
workspace = workspace_module.create_workspace(source_zip, BASE / "workspace")
patch_candidate(workspace)

PYTHON_PROBE = (
    "python",
    "-c",
)
HEALTH_COMMAND = PYTHON_PROBE + (
    "import urllib.request; print(urllib.request.urlopen("
    "'http://127.0.0.1:8080/file?name=hello.txt').read().decode(), end='')",
)
BENIGN_COMMAND = HEALTH_COMMAND
ATTACK_COMMAND = PYTHON_PROBE + (
    "import urllib.request; print(urllib.request.urlopen("
    "'http://127.0.0.1:8080/file?name=../secret.txt').read().decode(), end='')",
)
MISS_COMMAND = PYTHON_PROBE + ("print('probe-missed-vulnerability')",)


def probes(attack_command=ATTACK_COMMAND):
    return (
        verifier.ProbeSpec("hello", "benign", BENIGN_COMMAND),
        verifier.ProbeSpec(
            "path-traversal",
            "attack",
            attack_command,
            evidence_tier="B",
            attack_expectation=verifier.AttackExpectation(
                exit_code=0, stdout_contains="FLAG{live-fire-fixture}"
            ),
        ),
    )


def spec_for(job_id: str, attack_command=ATTACK_COMMAND):
    return verifier.VerificationSpec(
        job_id=job_id,
        probes=probes(attack_command),
        mitigation_class="input-filter",
        health_command=HEALTH_COMMAND,
        limits=verifier.ContainerLimits(
            cpus=0.5,
            memory="128m",
            pids=32,
            build_timeout_s=5,
            start_timeout_s=2,
            health_timeout_s=2,
            probe_timeout_s=1,
            tmpfs_size="8m",
        ),
    )


class RecordingRunner:
    def __init__(self, *, build_failure=False, cleanup_failure=False):
        self.calls = []
        self.build_failure = build_failure
        self.cleanup_failure = cleanup_failure

    @staticmethod
    def _side(container):
        if "-o-svc" in container:
            return "original"
        if "-c-svc" in container:
            return "candidate"
        raise AssertionError(f"unrecognized container name: {container}")

    def run(self, argv, timeout_s):
        command = tuple(argv)
        self.calls.append((command, timeout_s))
        docker_args = command[1:]
        if docker_args[0] == "build":
            context = Path(docker_args[-1])
            if self.build_failure and context.name == "candidate":
                return verifier.CommandResult(17, stderr="candidate build failed")
            return verifier.CommandResult(0, stdout="built")
        if docker_args[:2] == ("network", "create"):
            return verifier.CommandResult(0, stdout="network")
        if docker_args[0] in {"create", "start"}:
            return verifier.CommandResult(0, stdout="started")
        if docker_args[0] == "exec":
            side = self._side(docker_args[1])
            probe_command = tuple(docker_args[2:])
            if probe_command == HEALTH_COMMAND or probe_command == BENIGN_COMMAND:
                return verifier.CommandResult(0, stdout="hello-service\n")
            if probe_command == ATTACK_COMMAND:
                if side == "original":
                    return verifier.CommandResult(0, stdout="FLAG{live-fire-fixture}\n")
                return verifier.CommandResult(1, stderr="HTTP Error 403: Forbidden")
            if probe_command == MISS_COMMAND:
                if side == "original":
                    return verifier.CommandResult(
                        0, stdout="probe-missed-vulnerability\n"
                    )
                return verifier.CommandResult(1, stderr="blocked for unrelated reason")
            return verifier.CommandResult(127, stderr="unknown probe")
        if docker_args[:2] in {("rm", "--force"), ("network", "rm")}:
            if self.cleanup_failure and docker_args[:2] == ("network", "rm"):
                return verifier.CommandResult(1, stderr="network busy")
            return verifier.CommandResult(0)
        if docker_args[:3] == ("image", "rm", "--force"):
            return verifier.CommandResult(0)
        raise AssertionError(f"unexpected Docker command: {command!r}")


class MissingDockerRunner:
    def run(self, argv, timeout_s):
        raise FileNotFoundError("docker CLI unavailable")


def run_fake(job_id, *, attack_command=ATTACK_COMMAND, runner=None):
    runner = runner or RecordingRunner()
    runtime = verifier.DockerRuntime(runner=runner)
    document = verifier.verify_workspace(
        workspace,
        spec_for(job_id, attack_command),
        BASE / f"{job_id}-verification.json",
        runtime=runtime,
    )
    return document, runner


# Required positive control: vulnerable original, patched candidate, unchanged SLA.
positive = None
positive_runner = None
try:
    positive, positive_runner = run_fake("positive")
except Exception as exc:
    check("positive control completes", f"error:{type(exc).__name__}:{exc}", "ready")
else:
    check("positive control is ready", positive["ready_to_deploy"], True)
    check("benign SLA stays equal", positive["sla_gate"]["passed"], True)
    check("attack regression is blocked", positive["security_gate"]["passed"], True)
    attack_row = positive["security_gate"]["probes"][0]
    check(
        "original attack negative control passes",
        attack_row["negative_control_passed"],
        True,
    )
    check("candidate attack behavior changes", attack_row["behavior_changed"], True)
    check("tier B is serialized on attack", attack_row["evidence_tier"], "B")
    check(
        "tier summary is serialized", positive["security_gate"]["evidence_tiers"], ["B"]
    )
    check(
        "mitigation class is serialized", positive["mitigation_class"], "input-filter"
    )
    disk = json.loads((BASE / "positive-verification.json").read_text(encoding="utf-8"))
    check("verification.json roundtrip", disk, positive)
    check(
        "verification schema accepts positive", verifier.validate_verification(disk), []
    )


# The fixed attack must really reproduce on original.  The candidate differs,
# but that is not enough when the original never exposed the expected flag.
try:
    missed, _ = run_fake("missed-negative-control", attack_command=MISS_COMMAND)
except Exception as exc:
    check("negative-control fixture completes", type(exc).__name__, "none")
else:
    missed_attack = missed["security_gate"]["probes"][0]
    check("missed original exploit is not ready", missed["ready_to_deploy"], False)
    check(
        "missed original exploit fails security",
        missed["security_gate"]["passed"],
        False,
    )
    check(
        "negative control records failure",
        missed_attack["negative_control_passed"],
        False,
    )


# A candidate build failure is evidence, never an exception or READY result.
try:
    failed_build, failed_build_runner = run_fake(
        "build-failure", runner=RecordingRunner(build_failure=True)
    )
except Exception as exc:
    check("build failure writes evidence", type(exc).__name__, "none")
else:
    check(
        "candidate build failure is fail-closed", failed_build["ready_to_deploy"], False
    )
    check(
        "candidate build gate records failure",
        failed_build["build_gate"]["passed"],
        False,
    )
    check(
        "failed build skips runtime networks",
        sum(
            call[0][1:3] == ("network", "create") for call in failed_build_runner.calls
        ),
        0,
    )


# Cleanup is a hard isolation gate, not a warning compatible with READY.
try:
    cleanup_failed, _ = run_fake(
        "cleanup-failure", runner=RecordingRunner(cleanup_failure=True)
    )
except Exception as exc:
    check("cleanup failure writes evidence", type(exc).__name__, "none")
else:
    check("cleanup failure is fail-closed", cleanup_failed["ready_to_deploy"], False)
    check("cleanup failure is recorded", bool(cleanup_failed["cleanup_errors"]), True)


# A host without Docker still gets a valid fail-closed verification document.
try:
    missing_docker, _ = run_fake("missing-docker", runner=MissingDockerRunner())
except Exception as exc:
    check("missing Docker writes evidence", type(exc).__name__, "none")
else:
    check("missing Docker is fail-closed", missing_docker["ready_to_deploy"], False)
    check("missing Docker failure is recorded", bool(missing_docker["errors"]), True)
    check(
        "missing Docker evidence validates",
        verifier.validate_verification(missing_docker),
        [],
    )


if positive_runner is not None:
    commands = [call[0] for call in positive_runner.calls]
    build_commands = [command for command in commands if command[1] == "build"]
    network_commands = [
        command for command in commands if command[1:3] == ("network", "create")
    ]
    create_commands = [command for command in commands if command[1] == "create"]
    check("both sides are built", len(build_commands), 2)
    check(
        "build phase explicitly allows dependency egress",
        all(
            "--network" in command
            and command[command.index("--network") + 1] == "default"
            for command in build_commands
        ),
        True,
    )
    check(
        "build phase sets CPU limits",
        all("--cpu-quota" in command for command in build_commands),
        True,
    )
    check(
        "build phase sets memory limits",
        all("--memory" in command for command in build_commands),
        True,
    )
    check(
        "build phase disables extra swap",
        all("--memory-swap" in command for command in build_commands),
        True,
    )
    check(
        "build phase sets process limits",
        all(
            "--ulimit" in command and any(part.startswith("nproc=") for part in command)
            for command in build_commands
        ),
        True,
    )
    check("each side gets a fresh internal network", len(network_commands), 2)
    check(
        "verification networks are internal",
        all("--internal" in command for command in network_commands),
        True,
    )
    check(
        "internal network names are unique",
        len({command[-1] for command in network_commands}),
        2,
    )
    check("each side gets a fresh container", len(create_commands), 2)
    container_names = [
        command[command.index("--name") + 1] for command in create_commands
    ]
    check("container names are unique", len(set(container_names)), 2)
    check(
        "runtime containers use internal networks",
        all(
            command[command.index("--network") + 1]
            in {item[-1] for item in network_commands}
            for command in create_commands
        ),
        True,
    )
    flattened = "\0".join(part for command in create_commands for part in command)
    check(
        "runtime passes no bind mount",
        any(flag in flattened.split("\0") for flag in ("-v", "--volume", "--mount")),
        False,
    )
    check(
        "runtime passes no privileged flag",
        "--privileged" in flattened.split("\0"),
        False,
    )
    check(
        "runtime passes no host network",
        "host"
        in [command[command.index("--network") + 1] for command in create_commands],
        False,
    )
    check(
        "runtime drops capabilities",
        all(
            "--cap-drop" in command and "ALL" in command for command in create_commands
        ),
        True,
    )
    check(
        "runtime sets CPU limits",
        all("--cpus" in command for command in create_commands),
        True,
    )
    check(
        "runtime sets memory limits",
        all("--memory" in command for command in create_commands),
        True,
    )
    check(
        "runtime sets PID limits",
        all("--pids-limit" in command for command in create_commands),
        True,
    )
    check(
        "job label reaches every build",
        all("hextech.live-fire.job=positive" in command for command in build_commands),
        True,
    )
    check(
        "job label reaches every container",
        all("hextech.live-fire.job=positive" in command for command in create_commands),
        True,
    )
    check(
        "both containers are force-cleaned",
        sum(command[1:4] == ("rm", "--force", "--volumes") for command in commands),
        2,
    )
    check(
        "both networks are cleaned",
        sum(command[1:3] == ("network", "rm") for command in commands),
        2,
    )
    check(
        "both temporary images are cleaned",
        sum(command[1:4] == ("image", "rm", "--force") for command in commands),
        2,
    )


# Schema-level tier enforcement is independent from evaluator construction.
if positive is not None:
    without_tier = json.loads(json.dumps(positive))
    without_tier["security_gate"]["probes"][0].pop("evidence_tier", None)
    check(
        "schema rejects missing evidence tier",
        any(
            "lacks evidence_tier" in error
            for error in verifier.validate_verification(without_tier)
        ),
        True,
    )
    bypass = json.loads(json.dumps(positive))
    bypass["sla_gate"]["passed"] = False
    bypass["ready_to_deploy"] = True
    check(
        "schema rejects READY bypassing a failed gate",
        any(
            "cannot bypass" in error for error in verifier.validate_verification(bypass)
        ),
        True,
    )


# Configuration rejects incomplete corpora and unproven attack evidence.
try:
    verifier.VerificationSpec(
        job_id="benign-only",
        probes=(verifier.ProbeSpec("hello", "benign", BENIGN_COMMAND),),
        mitigation_class="root-cause-fix",
    )
except verifier.VerificationError:
    check("benign-only corpus is rejected", True, True)
else:
    check("benign-only corpus is rejected", False, True)

try:
    verifier.ProbeSpec(
        "unproven-attack",
        "attack",
        ATTACK_COMMAND,
        attack_expectation=verifier.AttackExpectation(stdout_contains="FLAG"),
    )
except verifier.VerificationError:
    check("attack without evidence tier is rejected", True, True)
else:
    check("attack without evidence tier is rejected", False, True)


# Wall-clock enforcement belongs to the host-side orchestrator, never to the
# uploaded service.  Use a trusted tiny subprocess as the positive timeout probe.
timeout_result = verifier.SubprocessRunner().run(
    (sys.executable, "-c", "import time; time.sleep(2)"), 0.05
)
check("subprocess wall clock is enforced", timeout_result.timed_out, True)
check("timed-out process is killed", timeout_result.duration_ms < 1500, True)


def docker_available() -> bool:
    try:
        result = subprocess.run(
            ("docker", "info"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


if args.docker_smoke:
    if not docker_available():
        print("SKIP  real Docker smoke: Docker daemon unavailable")
    elif args.mutate:
        print("SKIP  real Docker smoke during mutation run")
    else:
        real_path = BASE / "docker-smoke-verification.json"
        try:
            real = verifier.verify_workspace(
                workspace,
                spec_for("docker-smoke"),
                real_path,
            )
        except Exception as exc:
            check(
                "real Docker fixture completes", f"{type(exc).__name__}: {exc}", "ready"
            )
        else:
            check(
                "real vulnerable/patched fixture is ready",
                real["ready_to_deploy"],
                True,
            )
            check(
                "real attack reproduces on original",
                real["security_gate"]["probes"][0]["negative_control_passed"],
                True,
            )
            check(
                "real attack is blocked on candidate",
                real["security_gate"]["probes"][0]["candidate_blocked"],
                True,
            )


print(f"== summary: {P} passed, {F} failed; mutation={args.mutate or 'none'} ==")
for directory, dirnames, filenames in os.walk(BASE, topdown=False, followlinks=False):
    for name in filenames:
        path = Path(directory) / name
        if not path.is_symlink():
            path.chmod(0o600)
    for name in dirnames:
        path = Path(directory) / name
        if not path.is_symlink():
            path.chmod(0o700)
    Path(directory).chmod(0o700)
TMP.cleanup()
raise SystemExit(1 if F else 0)
