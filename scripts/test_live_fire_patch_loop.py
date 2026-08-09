#!/usr/bin/env python3
"""Executable LF-3 patch-loop/report gate and required mutations."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules import live_fire_patch_loop as patch_loop  # noqa: E402
from modules import live_fire_verifier as verifier  # noqa: E402
from modules import live_fire_workspace as workspace_module  # noqa: E402


parser = argparse.ArgumentParser()
parser.add_argument(
    "--mutate",
    choices=(
        "source-policy",
        "time-reserve",
        "report-headings",
        "location-diff",
        "machine-precedence",
        "positive-control",
    ),
)
args = parser.parse_args()

if args.mutate == "source-policy":
    patch_loop._source_policy_errors = lambda ws, policy, diffs: []
elif args.mutate == "time-reserve":
    patch_loop._has_attempt_budget = lambda remaining, verification, packaging: True
elif args.mutate == "report-headings":
    patch_loop._missing_required_headings = lambda report: []
elif args.mutate == "location-diff":
    patch_loop._location_matches_diff = lambda finding, diffs: True
elif args.mutate == "machine-precedence":
    patch_loop._machine_gate_errors = lambda document: []


test_tmpdir = os.environ.get("LIVE_FIRE_TEST_TMPDIR") or None
TMP = tempfile.TemporaryDirectory(prefix="live-fire-patch-loop-", dir=test_tmpdir)
BASE = Path(TMP.name)
P = F = 0


def check(label, got, want):
    global P, F
    if got == want:
        P += 1
    else:
        F += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


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


def write_source_zip(path: Path) -> Path:
    entries = {
        "Dockerfile": b"FROM python:3.11-alpine\nCOPY . /srv\n",
        "app.py": VULNERABLE.encode(),
        "public/hello.txt": b"hello-service\n",
        "secret.txt": b"FLAG{lf3-fixture}\n",
        "tests/test_app.py": b"# existing tests\n",
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            info = zipfile.ZipInfo(name, (2026, 8, 9, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
    return path


fixture_number = 0


def fresh_workspace(label: str):
    global fixture_number
    fixture_number += 1
    root = BASE / f"{fixture_number:02d}-{label}"
    root.mkdir()
    source = write_source_zip(root / "input.zip")
    workspace = workspace_module.create_workspace(source, root / "workspace")
    return root, source, workspace


HEALTH = ("probe", "health")
BENIGN = ("probe", "benign")
EXISTING_TEST = ("probe", "existing-test")
ATTACK = ("probe", "attack")


def verification_spec(job_id: str):
    return verifier.VerificationSpec(
        job_id=job_id,
        probes=(
            verifier.ProbeSpec("hello", "benign", BENIGN),
            verifier.ProbeSpec("existing-tests", "benign", EXISTING_TEST),
            verifier.ProbeSpec(
                "path-traversal",
                "attack",
                ATTACK,
                evidence_tier="B",
                attack_expectation=verifier.AttackExpectation(
                    exit_code=0, stdout_contains="FLAG{lf3-fixture}"
                ),
            ),
        ),
        mitigation_class="root-cause-fix",
        health_command=HEALTH,
        limits=verifier.ContainerLimits(
            cpus=0.5,
            memory="128m",
            pids=32,
            build_timeout_s=2,
            start_timeout_s=1,
            health_timeout_s=1,
            probe_timeout_s=1,
            tmpfs_size="8m",
        ),
    )


class RecordingRunner:
    def __init__(self, *, defeat_candidate=False):
        self.defeat_candidate = defeat_candidate
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
        self.calls.append((command, timeout_s))
        docker = command[1:]
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
                blocked = (
                    side == "candidate"
                    and self.candidate_secure
                    and not self.defeat_candidate
                )
                if blocked:
                    return verifier.CommandResult(1, stderr="PermissionError")
                return verifier.CommandResult(0, stdout="FLAG{lf3-fixture}\n")
            return verifier.CommandResult(127, stderr="unknown probe")
        if docker[:2] in {
            ("rm", "--force"),
            ("network", "rm"),
            ("image", "rm"),
        }:
            return verifier.CommandResult(0, stdout="removed")
        return verifier.CommandResult(127, stderr="unexpected docker command")


def runtime_factory(*, defeat_candidate=False):
    return lambda: verifier.DockerRuntime(
        runner=RecordingRunner(defeat_candidate=defeat_candidate)
    )


def valid_finding(line=6):
    return patch_loop.VulnerabilityFinding(
        bug_class="path traversal",
        severity="high",
        path="app.py",
        line=line,
        root_cause="an untrusted relative path was joined without containment",
        attack_impact="the fixed attack reads a secret outside the public root",
        patch_description="resolve the requested path and reject targets outside ROOT",
        patch_reason="preserve public-file reads while blocking traversal",
        mitigation_class="root-cause-fix",
        evidence_tier="B",
    )


class ScriptedProvider:
    def __init__(
        self,
        statuses,
        *,
        invalid_line=False,
        deployment_change=False,
        test_change=False,
        clock=None,
    ):
        self.statuses = list(statuses)
        self.invalid_line = invalid_line
        self.deployment_change = deployment_change
        self.test_change = test_change
        self.clock = clock
        self.calls = []

    def attempt(self, context):
        self.calls.append(context)
        status = self.statuses[min(len(self.calls) - 1, len(self.statuses) - 1)]
        if self.clock is not None:
            self.clock.now += 75
        if status == "success":
            if args.mutate != "positive-control":
                (context.candidate / "app.py").write_text(PATCHED, encoding="utf-8")
            if self.deployment_change:
                (context.candidate / "Dockerfile").write_text(
                    "FROM python:3.12-alpine\nCOPY . /srv\n", encoding="utf-8"
                )
            if self.test_change:
                (context.candidate / "tests/test_app.py").write_text(
                    "# provider weakened existing tests\n", encoding="utf-8"
                )
            return patch_loop.ProviderResult(
                "success",
                "patched path containment",
                (valid_finding(999 if self.invalid_line else 6),),
                ready_recommendation=True,
            )
        return patch_loop.ProviderResult(
            status,
            f"deterministic {status}",
            (),
            ready_recommendation=status == "failure",
        )


class RecordingReviewer:
    def __init__(self):
        self.calls = []

    def review(self, context):
        self.calls.append(context)
        return patch_loop.ReviewResult(
            "apply containment in app.py and rerun the machine attack oracle",
            passed=True,
        )


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now


def run_case(
    label,
    statuses,
    *,
    invalid_line=False,
    deployment_change=False,
    test_change=False,
    defeat_candidate=False,
    clock=None,
    timeout=100,
    max_attempts=2,
):
    root, source, workspace = fresh_workspace(label)
    provider = ScriptedProvider(
        statuses,
        invalid_line=invalid_line,
        deployment_change=deployment_change,
        test_change=test_change,
        clock=clock,
    )
    reviewer = RecordingReviewer()
    result = patch_loop.run_patch_loop(
        workspace,
        root / "artifacts",
        patch_loop.PatchLoopSpec(
            verification=verification_spec(label.replace("_", "-")),
            job_timeout_s=timeout,
            verification_reserve_s=20,
            packaging_reserve_s=10,
            max_attempts=max_attempts,
        ),
        provider,
        reviewer,
        runtime_factory=runtime_factory(defeat_candidate=defeat_candidate),
        clock=clock,
    )
    return root, source, workspace, provider, reviewer, result


# ⑥ Positive end-to-end control and the three-artifact boundary.
root, source, workspace, provider, reviewer, positive = run_case(
    "positive", ["success"], max_attempts=1
)
doc = positive.verification
check("positive control is ready", doc["ready_to_deploy"], True)
check("positive provider status", doc["provider_status"], "success")
check("positive uses one attempt", doc["attempts"], 1)
check("reviewer cannot bless an already passing attempt", len(reviewer.calls), 0)
check("source policy passes", doc["policy_gate"]["passed"], True)
check("report schema passes", doc["report_gate"]["passed"], True)
check("ready result has no stale residual risk", doc["residual_risks"], [])
check(
    "all machine gates pass",
    [
        doc[name]["passed"]
        for name in ("build_gate", "health_gate", "sla_gate", "security_gate")
    ],
    [True] * 4,
)
check("changed path is machine derived", doc["changed_paths"], ["app.py"])
check(
    "mitigation_class is serialized",
    doc["vulnerabilities"][0]["mitigation_class"],
    "root-cause-fix",
)
check("evidence_tier is serialized", doc["vulnerabilities"][0]["evidence_tier"], "B")
check(
    "input hash is source archive", doc["input_sha256"], patch_loop._sha256_file(source)
)
check(
    "output hash is patched.zip",
    doc["output_sha256"],
    patch_loop._sha256_file(positive.artifacts.patched_zip),
)
check(
    "verification roundtrip",
    json.loads(positive.artifacts.verification.read_text()),
    doc,
)
report_text = positive.artifacts.report.read_text(encoding="utf-8")
check("report says ready", "ready_to_deploy: **true** (READY)" in report_text, True)
check(
    "report location is actual changed line",
    "- Source: `app.py:6`" in report_text,
    True,
)
check(
    "report has seven required headings",
    all(report_text.count(item) == 1 for item in patch_loop.REPORT_HEADINGS),
    True,
)
check(
    "report records mitigation class",
    "Mitigation class: `root-cause-fix`" in report_text,
    True,
)
check("report records evidence tier", "Evidence tier: `B`" in report_text, True)
check(
    "report explains how behavior changed",
    "how: resolve the requested path" in report_text,
    True,
)
check(
    "report explains why behavior changed",
    "why: preserve public-file reads" in report_text,
    True,
)
check(
    "report compares attack exits",
    "original exit=0, candidate exit=1" in report_text,
    True,
)
check("report compares SLA behavior", "hello:equal=True" in report_text, True)
check(
    "report compares existing tests", "existing-tests:equal=True" in report_text, True
)
check("static stack discovery", doc["static_discovery"]["stacks"], ["docker", "python"])
check("static entrypoint discovery", doc["static_discovery"]["entrypoints"], ["app.py"])
check("static build discovery", doc["static_discovery"]["build_files"], ["Dockerfile"])
check(
    "static test discovery",
    doc["static_discovery"]["test_paths"],
    ["tests/test_app.py"],
)
check("static health discovery", doc["static_discovery"]["health_hints"], ["app.py"])
with zipfile.ZipFile(positive.artifacts.patched_zip) as archive:
    names = archive.namelist()
    check(
        "patched ZIP keeps input layout",
        names,
        ["Dockerfile", "app.py", "public/hello.txt", "secret.txt", "tests/test_app.py"],
    )
    check(
        "patched ZIP carries the source patch", archive.read("app.py").decode(), PATCHED
    )
    check("report stays outside patched ZIP", "report.md" in names, False)
    check("verification stays outside patched ZIP", "verification.json" in names, False)
    check(
        "regression payload stays outside patched ZIP",
        any("regression" in name for name in names),
        False,
    )
check(
    "artifact directory has exactly three downloads",
    sorted(path.name for path in positive.artifacts.report.parent.iterdir()),
    ["patched.zip", "report.md", "verification.json"],
)


# Provider success/failure/timeout/refusal are deterministic and always flush artifacts.
for status in ("failure", "timeout", "refusal"):
    _, _, _, failed_provider, failed_reviewer, failed = run_case(
        f"provider-{status}", [status], max_attempts=1
    )
    check(f"{status} is fail closed", failed.verification["ready_to_deploy"], False)
    check(f"{status} status survives", failed.verification["provider_status"], status)
    check(f"{status} invokes one reviewer hint", len(failed_reviewer.calls), 1)
    check(
        f"{status} still emits all artifacts",
        all(
            path.is_file()
            for path in (
                failed.artifacts.patched_zip,
                failed.artifacts.report,
                failed.artifacts.verification,
            )
        ),
        True,
    )


# Failed machine evidence and diff are fed back once, then the next provider attempt succeeds.
_, _, _, feedback_provider, feedback_reviewer, feedback_result = run_case(
    "feedback", ["failure", "success"]
)
check(
    "failure feedback reaches the next attempt",
    feedback_provider.calls[1].feedback,
    ("apply containment in app.py and rerun the machine attack oracle",),
)
check(
    "failed attempt has machine evidence",
    bool(feedback_reviewer.calls[0].machine_errors),
    True,
)
check(
    "feedback loop reaches ready", feedback_result.verification["ready_to_deploy"], True
)
check(
    "attempt history keeps both outcomes",
    [row["provider_status"] for row in feedback_result.verification["attempt_records"]],
    ["failure", "success"],
)


# ① Source-only guard: an application patch plus Dockerfile edit is rolled back/fail closed.
_, _, _, source_provider, _, source_result = run_case(
    "source-policy", ["success"], deployment_change=True, max_attempts=1
)
check(
    "deployment-layer edit cannot be ready",
    source_result.verification["ready_to_deploy"],
    False,
)
check(
    "source policy names Dockerfile",
    any(
        "Dockerfile" in item
        for item in source_result.verification["policy_gate"]["errors"]
    ),
    True,
)
check(
    "forbidden attempt is rolled back before packaging",
    source_result.verification["changed_paths"],
    [],
)

_, _, _, _, _, test_tamper_result = run_case(
    "test-policy", ["success"], test_change=True, max_attempts=1
)
check(
    "existing test tampering cannot be ready",
    test_tamper_result.verification["ready_to_deploy"],
    False,
)
check(
    "test tampering is named by source policy",
    any(
        "tests/test_app.py" in item
        for item in test_tamper_result.verification["policy_gate"]["errors"]
    ),
    True,
)


# ② A new attempt never consumes the explicit verification+packaging reservation.
budget_clock = FakeClock()
_, _, _, budget_provider, _, budget_result = run_case(
    "time-reserve", ["failure", "success"], clock=budget_clock, timeout=100
)
check("time reserve prevents a second attempt", len(budget_provider.calls), 1)
check(
    "time-reserved terminal result stays unverified",
    budget_result.verification["ready_to_deploy"],
    False,
)
check(
    "reservation decision is reported",
    any(
        "preserve verification" in item
        for item in budget_result.verification["residual_risks"]
    ),
    True,
)

overrun_clock = FakeClock()
_, _, _, _, _, overrun_result = run_case(
    "provider-overrun",
    ["success"],
    clock=overrun_clock,
    timeout=100,
    max_attempts=1,
)
check(
    "provider overrun is coerced to timeout",
    overrun_result.verification["provider_status"],
    "timeout",
)
check(
    "provider overrun cannot be ready",
    overrun_result.verification["ready_to_deploy"],
    False,
)


# ③ Heading validation rejects a missing one even when other report content is intact.
missing_heading = report_text.replace(patch_loop.REPORT_HEADINGS[4], "## Build summary")
heading_errors = patch_loop.validate_report(
    missing_heading,
    doc,
    (valid_finding(),),
    patch_loop.candidate_diff(workspace),
)
check(
    "missing required heading is rejected",
    any("heading" in item for item in heading_errors),
    True,
)


# ④ A nonexistent candidate file:line can never produce READY.
_, _, _, _, _, location_result = run_case(
    "location-diff", ["success"], invalid_line=True, max_attempts=1
)
check(
    "nonexistent source location is fail closed",
    location_result.verification["ready_to_deploy"],
    False,
)
check(
    "location mismatch is explicit",
    any(
        "changed candidate line" in item
        for item in location_result.verification["report_gate"]["errors"]
    ),
    True,
)


# ⑤ Provider/reviewer PASS recommendations cannot override a failed attack oracle.
_, _, _, _, machine_reviewer, machine_result = run_case(
    "machine-precedence", ["success"], defeat_candidate=True, max_attempts=1
)
check(
    "LLM PASS cannot override machine failure",
    machine_result.verification["ready_to_deploy"],
    False,
)
check(
    "provider did recommend ready",
    machine_result.verification["provider_ready_recommendation"],
    True,
)
check(
    "reviewer PASS remains advisory",
    machine_reviewer.calls
    and machine_result.verification["attempt_records"][0]["reviewer"]["passed"],
    True,
)
check(
    "failed security gate stays visible",
    machine_result.verification["security_gate"]["passed"],
    False,
)


print(f"{P} passed, {F} failed")
TMP.cleanup()
raise SystemExit(1 if F else 0)
