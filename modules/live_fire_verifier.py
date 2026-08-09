"""Container-only differential verifier for live-fire patches.

The uploaded service is built by Docker and is never executed by the worker
host.  Builds use Docker's normal build network so dependency installation can
work.  Every verification side gets a fresh ``--internal`` network and a fresh
container; the runtime container receives no mounts, credentials, host paths,
or Docker socket.

The oracle is deliberately asymmetric:

* benign probes must have the same observable result for original/candidate;
* attack probes must match their exploit expectation on the original and stop
  matching it on the candidate.

That original-side attack check is a negative control.  Without it, a probe
which never exercised the vulnerability could incorrectly approve a patch.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, Sequence

from modules.live_fire_workspace import (
    LiveFireWorkspace,
    assert_original_unchanged,
    load_workspace,
)


VERIFICATION_SCHEMA = 1
BUILD_NETWORK = "default"
VERIFY_NETWORK_POSTURE = "egress-blocked-internal-network"
_OUTPUT_LIMIT = 256 * 1024
_SAFE_JOB_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
_SAFE_MEMORY = re.compile(r"^[1-9][0-9]*[kKmMgG]$")
_CORPORA = {"benign", "attack"}
_EVIDENCE_TIERS = {"A", "B"}
_MITIGATION_CLASSES = {"root-cause-fix", "input-filter", "mixed"}


class VerificationError(ValueError):
    """The verifier configuration or generated evidence is invalid."""


class DockerCommandError(RuntimeError):
    """A Docker lifecycle command failed before probes could run."""

    def __init__(self, phase: str, result: "CommandResult"):
        self.phase = phase
        self.result = result
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        super().__init__(f"{phase} failed with exit {result.exit_code}: {detail}")


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration_ms: int = 0

    def signature(self) -> tuple[int, str, str, bool]:
        """Return the stable behavior fields used by the SLA oracle."""

        return (self.exit_code, self.stdout, self.stderr, self.timed_out)

    def as_dict(self) -> dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "duration_ms": self.duration_ms,
        }


class CommandRunner(Protocol):
    def run(self, argv: Sequence[str], timeout_s: float) -> CommandResult:
        """Execute an orchestrator command without a shell."""


class SubprocessRunner:
    """Bounded-output, bounded-wall-clock command runner."""

    @staticmethod
    def _read_output(stream: Any) -> str:
        stream.seek(0)
        payload = stream.read(_OUTPUT_LIMIT + 1)
        truncated = len(payload) > _OUTPUT_LIMIT
        payload = payload[:_OUTPUT_LIMIT]
        text = payload.decode("utf-8", errors="replace")
        if truncated:
            text += "\n[output truncated]"
        return text

    def run(self, argv: Sequence[str], timeout_s: float) -> CommandResult:
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        started = time.monotonic()
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                shell=False,
                start_new_session=True,
            )
            timed_out = False
            try:
                exit_code = process.wait(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                exit_code = process.wait()
            duration_ms = int((time.monotonic() - started) * 1000)
            return CommandResult(
                exit_code=exit_code,
                stdout=self._read_output(stdout),
                stderr=self._read_output(stderr),
                timed_out=timed_out,
                duration_ms=duration_ms,
            )


@dataclass(frozen=True)
class ContainerLimits:
    cpus: float = 1.0
    memory: str = "512m"
    pids: int = 128
    build_timeout_s: float = 300.0
    start_timeout_s: float = 20.0
    health_timeout_s: float = 30.0
    probe_timeout_s: float = 10.0
    tmpfs_size: str = "64m"

    def __post_init__(self) -> None:
        if self.cpus <= 0:
            raise VerificationError("cpus must be positive")
        if not _SAFE_MEMORY.fullmatch(self.memory):
            raise VerificationError("memory must be a positive Docker size")
        if not _SAFE_MEMORY.fullmatch(self.tmpfs_size):
            raise VerificationError("tmpfs_size must be a positive Docker size")
        if self.pids < 1:
            raise VerificationError("pids must be positive")
        for field in (
            "build_timeout_s",
            "start_timeout_s",
            "health_timeout_s",
            "probe_timeout_s",
        ):
            if getattr(self, field) <= 0:
                raise VerificationError(f"{field} must be positive")

    def as_dict(self) -> dict[str, Any]:
        return {
            "cpus": self.cpus,
            "memory": self.memory,
            "pids": self.pids,
            "build_timeout_s": self.build_timeout_s,
            "start_timeout_s": self.start_timeout_s,
            "health_timeout_s": self.health_timeout_s,
            "probe_timeout_s": self.probe_timeout_s,
            "tmpfs_size": self.tmpfs_size,
        }


@dataclass(frozen=True)
class AttackExpectation:
    """The fixed exploit behavior which must be present on the original."""

    exit_code: int = 0
    stdout_contains: str | None = None
    stderr_contains: str | None = None

    def matches(self, result: CommandResult) -> bool:
        if result.timed_out or result.exit_code != self.exit_code:
            return False
        if (
            self.stdout_contains is not None
            and self.stdout_contains not in result.stdout
        ):
            return False
        if (
            self.stderr_contains is not None
            and self.stderr_contains not in result.stderr
        ):
            return False
        return True

    def as_dict(self) -> dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "stdout_contains": self.stdout_contains,
            "stderr_contains": self.stderr_contains,
        }


@dataclass(frozen=True)
class ProbeSpec:
    name: str
    corpus: str
    command: tuple[str, ...]
    evidence_tier: str | None = None
    attack_expectation: AttackExpectation | None = None

    def __post_init__(self) -> None:
        if not self.name or len(self.name) > 128 or "\x00" in self.name:
            raise VerificationError("probe name must be 1..128 non-NUL characters")
        if self.corpus not in _CORPORA:
            raise VerificationError("probe corpus must be benign or attack")
        if not self.command or any(not part or "\x00" in part for part in self.command):
            raise VerificationError("probe command must contain non-empty argv values")
        if self.corpus == "attack":
            if self.evidence_tier not in _EVIDENCE_TIERS:
                raise VerificationError("attack probe evidence_tier must be A or B")
            if self.attack_expectation is None:
                raise VerificationError("attack probe requires an original expectation")
        elif self.evidence_tier is not None or self.attack_expectation is not None:
            raise VerificationError("benign probes cannot carry attack evidence fields")


@dataclass(frozen=True)
class VerificationSpec:
    job_id: str
    probes: tuple[ProbeSpec, ...]
    mitigation_class: str
    start_command: tuple[str, ...] = ()
    health_command: tuple[str, ...] = ()
    limits: ContainerLimits = ContainerLimits()

    def __post_init__(self) -> None:
        if not _SAFE_JOB_ID.fullmatch(self.job_id):
            raise VerificationError(
                "job_id must be a lowercase Docker-safe identifier up to 63 chars"
            )
        if self.mitigation_class not in _MITIGATION_CLASSES:
            raise VerificationError("invalid mitigation_class")
        if not self.probes:
            raise VerificationError("at least one probe is required")
        names = [probe.name for probe in self.probes]
        if len(names) != len(set(names)):
            raise VerificationError("probe names must be unique")
        corpora = {_probe_corpus(probe) for probe in self.probes}
        if corpora != _CORPORA:
            raise VerificationError("both benign and attack corpora are required")
        for command in (self.start_command, self.health_command):
            if any(not part or "\x00" in part for part in command):
                raise VerificationError("start/health argv values must be non-empty")


def _probe_corpus(probe: ProbeSpec) -> str:
    """Mutation seam: corpus classification must stay asymmetric."""

    return probe.corpus


def _original_attack_reproduced(probe: ProbeSpec, original: CommandResult) -> bool:
    """Mutation seam for the original-side exploit negative control."""

    expectation = probe.attack_expectation
    return expectation is not None and expectation.matches(original)


def _attack_result_tier(probe: ProbeSpec) -> str | None:
    """Mutation seam: tier provenance must survive serialization."""

    return probe.evidence_tier


class DockerRuntime:
    """Small Docker CLI boundary with no user-controlled shell evaluation."""

    def __init__(
        self,
        runner: CommandRunner | None = None,
        docker_argv: tuple[str, ...] = ("docker",),
    ):
        if not docker_argv or any(not part for part in docker_argv):
            raise VerificationError("docker_argv cannot be empty")
        self.runner = runner or SubprocessRunner()
        self.docker_argv = docker_argv

    def _run(self, args: Sequence[str], timeout_s: float) -> CommandResult:
        return self.runner.run((*self.docker_argv, *args), timeout_s)

    @staticmethod
    def _guard_no_bind_mount_args(args: Sequence[str]) -> None:
        """Keep worker-visible paths out of daemon-side bind mount options.

        Build context is read by the worker's Docker CLI and sent as a tar
        stream.  A bind source, in contrast, is resolved by the host daemon;
        passing ``/data/jobs/...`` there silently crosses namespaces.
        """

        for part in args:
            if (
                part == "-v"
                or (part.startswith("-v") and not part.startswith("--"))
                or part == "--volume"
                or part.startswith("--volume=")
                or part == "--mount"
                or part.startswith("--mount=")
            ):
                raise VerificationError(
                    "live-fire verifier forbids Docker bind mount arguments"
                )

    @staticmethod
    def _require(phase: str, result: CommandResult) -> CommandResult:
        if result.exit_code != 0 or result.timed_out:
            raise DockerCommandError(phase, result)
        return result

    def build_image(
        self,
        context: Path,
        image: str,
        labels: dict[str, str],
        limits: ContainerLimits,
    ) -> CommandResult:
        cpu_period = 100_000
        cpu_quota = max(1_000, int(limits.cpus * cpu_period))
        args = [
            "build",
            "--network",
            BUILD_NETWORK,
            "--force-rm",
            "--no-cache",
            "--memory",
            limits.memory,
            "--memory-swap",
            limits.memory,
            "--cpu-period",
            str(cpu_period),
            "--cpu-quota",
            str(cpu_quota),
            "--ulimit",
            f"nproc={limits.pids}:{limits.pids}",
            "--tag",
            image,
        ]
        for key, value in sorted(labels.items()):
            args.extend(("--label", f"{key}={value}"))
        args.append(str(context))
        self._guard_no_bind_mount_args(args)
        return self._run(args, limits.build_timeout_s)

    def create_internal_network(
        self, name: str, labels: dict[str, str], timeout_s: float
    ) -> None:
        args = ["network", "create", "--internal"]
        for key, value in sorted(labels.items()):
            args.extend(("--label", f"{key}={value}"))
        args.append(name)
        self._require("network-create", self._run(args, timeout_s))

    def create_container(
        self,
        *,
        image: str,
        name: str,
        network: str,
        labels: dict[str, str],
        command: tuple[str, ...],
        limits: ContainerLimits,
    ) -> None:
        args = [
            "create",
            "--name",
            name,
            "--network",
            network,
            "--cpus",
            str(limits.cpus),
            "--memory",
            limits.memory,
            "--pids-limit",
            str(limits.pids),
            "--security-opt",
            "no-new-privileges:true",
            "--cap-drop",
            "ALL",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,size={limits.tmpfs_size}",
        ]
        for key, value in sorted(labels.items()):
            args.extend(("--label", f"{key}={value}"))
        self._guard_no_bind_mount_args(args)
        args.append(image)
        args.extend(command)
        self._require("container-create", self._run(args, limits.start_timeout_s))

    def start_container(self, name: str, timeout_s: float) -> None:
        self._require("container-start", self._run(("start", name), timeout_s))

    def exec_container(
        self, name: str, command: tuple[str, ...], timeout_s: float
    ) -> CommandResult:
        return self._run(("exec", name, *command), timeout_s)

    def wait_healthy(
        self,
        name: str,
        command: tuple[str, ...],
        limits: ContainerLimits,
    ) -> CommandResult:
        if not command:
            return CommandResult(0, stdout="health command not configured")
        deadline = time.monotonic() + limits.health_timeout_s
        last = CommandResult(1, stderr="health check did not run")
        while time.monotonic() < deadline:
            per_attempt = min(
                limits.probe_timeout_s, max(deadline - time.monotonic(), 0.1)
            )
            last = self.exec_container(name, command, per_attempt)
            if last.exit_code == 0 and not last.timed_out:
                return last
            time.sleep(min(0.2, max(deadline - time.monotonic(), 0)))
        return last

    def remove_container(self, name: str, timeout_s: float) -> CommandResult:
        return self._run(("rm", "--force", "--volumes", name), timeout_s)

    def remove_network(self, name: str, timeout_s: float) -> CommandResult:
        return self._run(("network", "rm", name), timeout_s)

    def remove_image(self, image: str, timeout_s: float) -> CommandResult:
        return self._run(("image", "rm", "--force", image), timeout_s)


def _phase_result(
    result: CommandResult | None, error: str | None = None
) -> dict[str, Any]:
    if result is None:
        return {"passed": False, "result": None, "error": error}
    return {
        "passed": result.exit_code == 0 and not result.timed_out and error is None,
        "result": result.as_dict(),
        "error": error,
    }


def _evaluate_probes(
    probes: tuple[ProbeSpec, ...],
    original: dict[str, CommandResult],
    candidate: dict[str, CommandResult],
) -> tuple[dict[str, Any], dict[str, Any]]:
    benign_rows: list[dict[str, Any]] = []
    attack_rows: list[dict[str, Any]] = []
    for probe in probes:
        original_result = original.get(probe.name)
        candidate_result = candidate.get(probe.name)
        if original_result is None or candidate_result is None:
            row = {
                "name": probe.name,
                "corpus": _probe_corpus(probe),
                "passed": False,
                "error": "probe did not run on both sides",
            }
            if _probe_corpus(probe) == "attack":
                row.update(
                    {
                        "evidence_tier": _attack_result_tier(probe),
                        "negative_control_passed": False,
                        "candidate_blocked": False,
                        "behavior_changed": False,
                    }
                )
                attack_rows.append(row)
            else:
                benign_rows.append(row)
            continue

        if _probe_corpus(probe) == "benign":
            same = original_result.signature() == candidate_result.signature()
            benign_rows.append(
                {
                    "name": probe.name,
                    "corpus": "benign",
                    "passed": same,
                    "equal": same,
                    "original": original_result.as_dict(),
                    "candidate": candidate_result.as_dict(),
                }
            )
            continue

        reproduced = _original_attack_reproduced(probe, original_result)
        expectation = probe.attack_expectation
        candidate_blocked = expectation is not None and not expectation.matches(
            candidate_result
        )
        changed = original_result.signature() != candidate_result.signature()
        attack_rows.append(
            {
                "name": probe.name,
                "corpus": "attack",
                "evidence_tier": _attack_result_tier(probe),
                "passed": reproduced and candidate_blocked and changed,
                "negative_control_passed": reproduced,
                "candidate_blocked": candidate_blocked,
                "behavior_changed": changed,
                "original_expectation": expectation.as_dict() if expectation else None,
                "original": original_result.as_dict(),
                "candidate": candidate_result.as_dict(),
            }
        )

    sla_gate = {
        "passed": bool(benign_rows) and all(row["passed"] for row in benign_rows),
        "oracle": "original-behavior-exact-match",
        "probes": benign_rows,
    }
    security_gate = {
        "passed": bool(attack_rows) and all(row["passed"] for row in attack_rows),
        "oracle": "original-reproduces-and-candidate-blocks",
        "evidence_tiers": sorted(
            {
                row["evidence_tier"]
                for row in attack_rows
                if row.get("evidence_tier") is not None
            }
        ),
        "probes": attack_rows,
    }
    return sla_gate, security_gate


def validate_verification(document: dict[str, Any]) -> list[str]:
    """Return schema/contract errors; an empty list means machine-usable evidence."""

    errors: list[str] = []
    if document.get("schema_version") != VERIFICATION_SCHEMA:
        errors.append("schema_version must match VERIFICATION_SCHEMA")
    if document.get("mitigation_class") not in _MITIGATION_CLASSES:
        errors.append("mitigation_class is missing or invalid")
    posture = document.get("network_posture")
    if not isinstance(posture, dict) or posture.get("build") != "egress-allowed":
        errors.append("build network posture must be egress-allowed")
    if (
        not isinstance(posture, dict)
        or posture.get("verification") != VERIFY_NETWORK_POSTURE
    ):
        errors.append("verification network posture must be egress blocked")

    gates = []
    for name in ("build_gate", "health_gate", "sla_gate", "security_gate"):
        gate = document.get(name)
        if not isinstance(gate, dict) or not isinstance(gate.get("passed"), bool):
            errors.append(f"{name}.passed must be boolean")
        else:
            gates.append(gate["passed"])

    sla_gate = document.get("sla_gate", {})
    benign = sla_gate.get("probes") if isinstance(sla_gate, dict) else None
    if not isinstance(benign, list) or not benign:
        errors.append("sla_gate requires at least one benign probe")
    elif any(
        not isinstance(row, dict) or row.get("corpus") != "benign" for row in benign
    ):
        errors.append("sla_gate contains a non-benign probe")
    elif sla_gate.get("passed") and any(
        row.get("passed") is not True for row in benign
    ):
        errors.append("sla_gate passed while a benign probe did not pass")

    security_gate = document.get("security_gate", {})
    attacks = security_gate.get("probes") if isinstance(security_gate, dict) else None
    tiers: set[str] = set()
    if not isinstance(attacks, list) or not attacks:
        errors.append("security_gate requires at least one attack probe")
    else:
        for row in attacks:
            if not isinstance(row, dict) or row.get("corpus") != "attack":
                errors.append("security_gate contains a non-attack probe")
                continue
            tier = row.get("evidence_tier")
            if tier not in _EVIDENCE_TIERS:
                errors.append(
                    f"attack probe {row.get('name')!r} lacks evidence_tier A/B"
                )
            else:
                tiers.add(tier)
            if not isinstance(row.get("negative_control_passed"), bool):
                errors.append(
                    f"attack probe {row.get('name')!r} lacks negative control result"
                )
            if not isinstance(row.get("candidate_blocked"), bool):
                errors.append(
                    f"attack probe {row.get('name')!r} lacks candidate result"
                )
            if not isinstance(row.get("behavior_changed"), bool):
                errors.append(
                    f"attack probe {row.get('name')!r} lacks differential result"
                )
            if not isinstance(row.get("passed"), bool):
                errors.append(f"attack probe {row.get('name')!r} lacks passed result")
        if isinstance(security_gate, dict) and security_gate.get(
            "evidence_tiers"
        ) != sorted(tiers):
            errors.append("security_gate.evidence_tiers does not match attack probes")
        if security_gate.get("passed") and any(
            not isinstance(row, dict) or row.get("passed") is not True
            for row in attacks
        ):
            errors.append("security_gate passed while an attack probe did not pass")

    ready = document.get("ready_to_deploy")
    if not isinstance(ready, bool):
        errors.append("ready_to_deploy must be boolean")
    elif ready and (len(gates) != 4 or not all(gates)):
        errors.append("ready_to_deploy cannot bypass a failed machine gate")
    elif ready and (document.get("errors") or document.get("cleanup_errors")):
        errors.append("ready_to_deploy cannot contain runtime or cleanup errors")
    return errors


def _write_verification(path: Path, document: dict[str, Any]) -> None:
    errors = validate_verification(document)
    if errors:
        raise VerificationError("invalid verification document: " + "; ".join(errors))
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(document, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def verify_workspace(
    workspace: LiveFireWorkspace | str | os.PathLike[str],
    spec: VerificationSpec,
    verification_path: str | os.PathLike[str],
    *,
    runtime: DockerRuntime | None = None,
) -> dict[str, Any]:
    """Build, isolate, compare, validate, and atomically write verification.json."""

    ws = (
        workspace
        if isinstance(workspace, LiveFireWorkspace)
        else load_workspace(workspace)
    )
    assert_original_unchanged(ws)
    docker = runtime or DockerRuntime()
    token = uuid.uuid4().hex[:10]
    labels = {
        "hextech.live-fire": "verification",
        "hextech.live-fire.job": spec.job_id,
    }
    images = {
        "original": f"hextech-live-fire:{spec.job_id}-{token}-original",
        "candidate": f"hextech-live-fire:{spec.job_id}-{token}-candidate",
    }
    contexts = {"original": ws.original, "candidate": ws.candidate}
    builds: dict[str, CommandResult] = {}
    health: dict[str, CommandResult] = {}
    observations: dict[str, dict[str, CommandResult]] = {
        "original": {},
        "candidate": {},
    }
    errors: list[str] = []
    cleanup_errors: list[str] = []

    try:
        for side in ("original", "candidate"):
            result = docker.build_image(
                contexts[side],
                images[side],
                {**labels, "hextech.live-fire.side": side},
                spec.limits,
            )
            builds[side] = result

        if all(
            result.exit_code == 0 and not result.timed_out for result in builds.values()
        ):
            for side in ("original", "candidate"):
                suffix = side[0]
                network = f"lf-{spec.job_id[:24]}-{token}-{suffix}-net"
                container = f"lf-{spec.job_id[:24]}-{token}-{suffix}-svc"
                side_labels = {**labels, "hextech.live-fire.side": side}
                network_attempted = False
                container_attempted = False
                try:
                    network_attempted = True
                    docker.create_internal_network(
                        network, side_labels, spec.limits.start_timeout_s
                    )
                    container_attempted = True
                    docker.create_container(
                        image=images[side],
                        name=container,
                        network=network,
                        labels=side_labels,
                        command=spec.start_command,
                        limits=spec.limits,
                    )
                    docker.start_container(container, spec.limits.start_timeout_s)
                    health[side] = docker.wait_healthy(
                        container, spec.health_command, spec.limits
                    )
                    if health[side].exit_code == 0 and not health[side].timed_out:
                        for probe in spec.probes:
                            observations[side][probe.name] = docker.exec_container(
                                container, probe.command, spec.limits.probe_timeout_s
                            )
                except (DockerCommandError, OSError) as exc:
                    errors.append(f"{side}:{exc}")
                finally:
                    if container_attempted:
                        try:
                            result = docker.remove_container(
                                container, spec.limits.start_timeout_s
                            )
                            if result.exit_code != 0:
                                cleanup_errors.append(
                                    f"container:{side}:{result.stderr.strip()}"
                                )
                        except OSError as exc:
                            cleanup_errors.append(f"container:{side}:{exc}")
                    if network_attempted:
                        try:
                            result = docker.remove_network(
                                network, spec.limits.start_timeout_s
                            )
                            if result.exit_code != 0:
                                cleanup_errors.append(
                                    f"network:{side}:{result.stderr.strip()}"
                                )
                        except OSError as exc:
                            cleanup_errors.append(f"network:{side}:{exc}")
        else:
            errors.append("build failed; verification execution skipped")
    except (OSError, DockerCommandError) as exc:
        errors.append(f"runtime:{exc}")
    finally:
        for side in ("original", "candidate"):
            if side in builds:
                try:
                    result = docker.remove_image(
                        images[side], spec.limits.start_timeout_s
                    )
                    if result.exit_code != 0:
                        cleanup_errors.append(f"image:{side}:{result.stderr.strip()}")
                except OSError as exc:
                    cleanup_errors.append(f"image:{side}:{exc}")

    assert_original_unchanged(ws)
    sla_gate, security_gate = _evaluate_probes(
        spec.probes, observations["original"], observations["candidate"]
    )
    build_gate = {
        "passed": len(builds) == 2
        and all(
            result.exit_code == 0 and not result.timed_out for result in builds.values()
        ),
        "network": "egress-allowed",
        "sides": {
            side: _phase_result(builds.get(side)) for side in ("original", "candidate")
        },
    }
    health_gate = {
        "passed": len(health) == 2
        and all(
            result.exit_code == 0 and not result.timed_out for result in health.values()
        ),
        "sides": {
            side: _phase_result(health.get(side), "health did not complete")
            for side in ("original", "candidate")
        },
    }
    ready = (
        build_gate["passed"]
        and health_gate["passed"]
        and sla_gate["passed"]
        and security_gate["passed"]
        and not errors
        and not cleanup_errors
    )
    document = {
        "schema_version": VERIFICATION_SCHEMA,
        "job_id": spec.job_id,
        "ready_to_deploy": ready,
        "input_sha256": ws.manifest["source_archive_sha256"],
        "original_tree_sha256": ws.original_digest,
        "mitigation_class": spec.mitigation_class,
        "network_posture": {
            "build": "egress-allowed",
            "verification": VERIFY_NETWORK_POSTURE,
        },
        "limits": spec.limits.as_dict(),
        "build_gate": build_gate,
        "health_gate": health_gate,
        "sla_gate": sla_gate,
        "security_gate": security_gate,
        "errors": errors,
        "cleanup_errors": cleanup_errors,
    }
    _write_verification(Path(verification_path), document)
    return document


__all__ = [
    "AttackExpectation",
    "CommandResult",
    "ContainerLimits",
    "DockerRuntime",
    "ProbeSpec",
    "SubprocessRunner",
    "VerificationError",
    "VerificationSpec",
    "validate_verification",
    "verify_workspace",
]
