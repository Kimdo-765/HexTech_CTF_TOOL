#!/usr/bin/env python3
"""Executable LF-4 routing/usage gate with required source mutations.

All provider calls go through ``ScriptedInvoker``.  No Claude, GPT, or Grok
client is created; the production routing snapshot and usage ledger are the
parts under test.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
import zipfile
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument(
    "--mutate",
    choices=(
        "role-override",
        "grok-drop",
        "usage-role",
        "usage-stage",
        "usage-attempt",
        "no-override",
    ),
)
args = parser.parse_args()

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

test_tmpdir = os.environ.get("LIVE_FIRE_TEST_TMPDIR") or None
TMP = tempfile.TemporaryDirectory(prefix="live-fire-provider-", dir=test_tmpdir)
BASE = Path(TMP.name)
DATA = BASE / "data"
(DATA / "jobs").mkdir(parents=True)
SETTINGS = DATA / "settings.json"
PRESETS = DATA / "model_presets.json"
SETTINGS.write_text("{}", encoding="utf-8")
PRESETS.write_text(
    json.dumps({"version": 2, "providers": {}}),
    encoding="utf-8",
)
os.environ["DATA_DIR"] = str(DATA)
os.environ["SETTINGS_PATH"] = str(SETTINGS)
os.environ["MODEL_PRESETS_PATH"] = str(PRESETS)
for key in ("AGENT_PROVIDER", "CLAUDE_MODEL", "GROK_MODEL", "GPT_MODEL"):
    os.environ.pop(key, None)

from modules import agent_provider as AP  # noqa: E402
from modules import live_fire_patch_loop as patch_loop  # noqa: E402
from modules import live_fire_provider as routing  # noqa: E402
from modules import live_fire_verifier as verifier  # noqa: E402
from modules import live_fire_workspace as workspace_module  # noqa: E402
from modules import usage_ledger as UL  # noqa: E402


if args.mutate == "role-override":

    def enrich_without_routes(meta, provider=None):
        meta.update(AP.provider_meta_fields(provider, include_routes=False))
        return meta

    AP.enrich_job_meta = enrich_without_routes
elif args.mutate == "grok-drop":
    AP.ROLE_TARGET_PROVIDERS = frozenset({"claude", "gpt", "grok"})
elif args.mutate == "no-override":
    original_provider_for_role = routing._provider_for_role

    def collapse_unrouted_roles(job_id, role):
        if role != "main":
            return "claude"
        return original_provider_for_role(job_id, role)

    routing._provider_for_role = collapse_unrouted_roles


if args.mutate in {"usage-role", "usage-stage", "usage-attempt"}:
    removed_dimension = args.mutate.removeprefix("usage-")
    original_record_call_usage = routing._record_call_usage

    def record_without_dimension(call, result):
        record = original_record_call_usage(call, result)
        if record is None:
            return None
        path = UL.ledger_path(call.job_id)
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        rows[-1].pop(removed_dimension, None)
        path.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
        record.pop(removed_dimension, None)
        return record

    routing._record_call_usage = record_without_dimension


P = F = 0


def check(label, got, want):
    global P, F
    if got == want:
        P += 1
    else:
        F += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


def set_settings(provider, routes=None):
    SETTINGS.write_text(
        json.dumps(
            {
                "agent_provider": provider,
                "agent_role_providers": routes or {},
                "claude_model": "claude-opus-4-7",
                "gpt_model": "gpt-5.6-sol",
                "grok_model": "grok-build",
                "gpt_runtime": "codex",
            }
        ),
        encoding="utf-8",
    )


def make_job(job_id, provider, routes=None):
    set_settings(provider, routes)
    meta = AP.enrich_job_meta({"id": job_id}, provider)
    job_root = DATA / "jobs" / job_id
    job_root.mkdir(exist_ok=True)
    (job_root / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return job_id, meta


def providers_for(job_id):
    return {
        role: route.provider
        for role, route in routing.resolve_live_fire_routes(job_id).items()
    }


# ① Single provider: all three roles stay on the whole-job provider.
for provider in ("claude", "gpt", "grok"):
    job, _ = make_job(f"single-{provider}", provider)
    check(
        f"single {provider} resolves main/reviewer/report together",
        providers_for(job),
        {"main": provider, "reviewer": provider, "report": provider},
    )
    base = AP.provider_for_job(job)
    for role, route in routing.resolve_live_fire_routes(job).items():
        check(
            f"no override {provider}/{role} equals provider_for_job",
            route.provider,
            base,
        )


# ② Hybrid routes only reviewer/report; main remains the scalar job provider.
for base, target in (("claude", "gpt"), ("gpt", "claude")):
    job, meta = make_job(
        f"hybrid-{base}-{target}",
        base,
        {"reviewer": target, "report": target},
    )
    check(
        f"hybrid {base}->{target} snapshot is stamped",
        meta.get("agent_role_providers"),
        {"reviewer": target, "report": target},
    )
    check(
        f"hybrid {base}->{target} routes only reviewer/report",
        providers_for(job),
        {"main": base, "reviewer": target, "report": target},
    )


# Grok remains whole-job only: invalid role targets are absent from the stamp.
grok_drop_job, grok_drop_meta = make_job(
    "grok-role-drop",
    "claude",
    {"reviewer": "grok", "report": "grok"},
)
check(
    "grok role targets are dropped from create-time meta",
    "agent_role_providers" in grok_drop_meta,
    False,
)
check(
    "dropped grok routes fall back to the whole-job provider",
    providers_for(grok_drop_job),
    {"main": "claude", "reviewer": "claude", "report": "claude"},
)


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


def write_source_zip(path):
    entries = {
        "Dockerfile": b"FROM python:3.11-alpine\nCOPY . /srv\n",
        "app.py": VULNERABLE.encode(),
        "public/hello.txt": b"hello-service\n",
        "secret.txt": b"FLAG{lf4-fixture}\n",
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


def verification_spec(job_id):
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
                    exit_code=0,
                    stdout_contains="FLAG{lf4-fixture}",
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
                return verifier.CommandResult(0, stdout="FLAG{lf4-fixture}\n")
            return verifier.CommandResult(127, stderr="unknown probe")
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
        patch_reason="preserve public-file reads while blocking traversal",
        mitigation_class="root-cause-fix",
        evidence_tier="B",
    )


class ScriptedInvoker:
    """Deterministic positive/feedback path; never constructs a real client."""

    def __init__(self, *, invalid_report=False):
        self.invalid_report = invalid_report
        self.calls = []
        self.main_calls = 0

    def invoke(self, call):
        self.calls.append(call)
        role = call.route.role
        if role == "main":
            self.main_calls += 1
            if self.main_calls == 1 and not self.invalid_report:
                value = patch_loop.ProviderResult("failure", "first patch needs review")
            else:
                (call.payload.candidate / "app.py").write_text(
                    PATCHED, encoding="utf-8"
                )
                value = patch_loop.ProviderResult(
                    "success",
                    "patched path containment",
                    (valid_finding(),),
                    ready_recommendation=True,
                )
        elif role == "reviewer":
            value = patch_loop.ReviewResult(
                "apply containment in app.py and rerun the machine oracle"
            )
        elif self.invalid_report:
            value = "free-form report with every required heading omitted"
        else:
            value = patch_loop._render_report(
                call.payload.document,
                call.payload.findings,
                call.payload.diffs,
            )
        return routing.AgentInvocationResult(
            value,
            routing.AgentUsage(
                model=call.route.model,
                tokens={"input_tokens": 10 + call.attempt, "output_tokens": 2},
            ),
        )


def run_routed_case(label, provider, routes, *, invalid_report=False):
    root = BASE / label
    root.mkdir()
    source = write_source_zip(root / "input.zip")
    workspace = workspace_module.create_workspace(source, root / "workspace")
    job, _ = make_job(
        label,
        provider,
        routes,
    )
    invoker = ScriptedInvoker(invalid_report=invalid_report)
    result = routing.run_routed_patch_loop(
        job,
        workspace,
        root / "artifacts",
        patch_loop.PatchLoopSpec(
            verification=verification_spec(job),
            job_timeout_s=100,
            verification_reserve_s=20,
            packaging_reserve_s=10,
            max_attempts=2,
        ),
        invoker,
        runtime_factory=runtime_factory,
    )
    return invoker, result


# ⑤ Positive single-provider execution uses the same full patch/review/report
# path for Claude, GPT, and Grok.  The invoker remains scripted in every case.
for single_provider in ("claude", "gpt", "grok"):
    single_job = f"single-run-{single_provider}"
    single_invoker, single_result = run_routed_case(
        single_job,
        single_provider,
        {},
    )
    check(
        f"single {single_provider} routed patch loop reaches READY",
        single_result.verification["ready_to_deploy"],
        True,
    )
    check(
        f"single {single_provider} executes every role on one provider",
        [call.route.provider for call in single_invoker.calls],
        [single_provider] * 4,
    )
    check(
        f"single {single_provider} usage stays on one provider",
        [row.get("provider") for row in UL.read_usage(single_job)],
        [single_provider] * 4,
    )


# ⑤ Positive routed run: feedback, second main attempt, and terminal report.
invoker, result = run_routed_case(
    "routed-positive",
    "claude",
    {"reviewer": "gpt", "report": "gpt"},
)
check("routed patch loop reaches READY", result.verification["ready_to_deploy"], True)
check(
    "actual calls use main then reviewer then main then report",
    [call.route.role for call in invoker.calls],
    ["main", "reviewer", "main", "report"],
)
check(
    "hybrid execution keeps main on Claude and reviewer/report on GPT",
    [call.route.provider for call in invoker.calls],
    ["claude", "gpt", "claude", "gpt"],
)
check(
    "the terminal report came through the report role",
    invoker.calls[-1].payload.document["provider_status"],
    "success",
)

rows = UL.read_usage("routed-positive")
check("one usage row per scripted invocation", len(rows), 4)
check(
    "usage rows preserve role",
    [row.get("role") for row in rows],
    ["main", "reviewer", "main", "report"],
)
check(
    "usage rows preserve stage",
    [row.get("stage") for row in rows],
    ["patch", "review", "patch", "report"],
)
check(
    "usage rows preserve per-role/stage attempt",
    [row.get("attempt") for row in rows],
    [1, 1, 2, 1],
)
check(
    "usage rows preserve provider",
    [row.get("provider") for row in rows],
    ["claude", "gpt", "claude", "gpt"],
)
check(
    "usage rows preserve the resolved model",
    [row.get("model") for row in rows],
    ["claude-opus-4-7", "gpt-5.6-sol", "claude-opus-4-7", "gpt-5.6-sol"],
)
for index, row in enumerate(rows, 1):
    check(
        f"usage row {index} has all five dimensions",
        all(
            row.get(axis) not in (None, "")
            for axis in ("provider", "model", "role", "stage", "attempt")
        ),
        True,
    )
check(
    "logical patch attempt is retained without replacing ledger attempt",
    [row.get("live_fire_attempt") for row in rows],
    [1, 1, 2, 2],
)


# A malformed routed report is fail-closed, but the three artifacts still flush
# and report.md falls back to the complete deterministic schema.
bad_invoker, bad_result = run_routed_case(
    "bad-report",
    "claude",
    {"reviewer": "gpt", "report": "gpt"},
    invalid_report=True,
)
check(
    "invalid report provider output cannot be READY",
    bad_result.verification["ready_to_deploy"],
    False,
)
check(
    "invalid report is named by report_gate",
    bad_result.verification["report_gate"]["passed"],
    False,
)
bad_report_text = bad_result.artifacts.report.read_text(encoding="utf-8")
check(
    "invalid report falls back to all required headings",
    all(bad_report_text.count(heading) == 1 for heading in patch_loop.REPORT_HEADINGS),
    True,
)
check(
    "failed report path still emits exactly three artifacts",
    sorted(path.name for path in bad_result.artifacts.report.parent.iterdir()),
    ["patched.zip", "report.md", "verification.json"],
)
check(
    "invalid report still records the report role invocation",
    [row.get("role") for row in UL.read_usage("bad-report")],
    ["main", "report"],
)


print(f"== summary: {P} passed, {F} failed; mutation={args.mutate or 'none'} ==")
TMP.cleanup()
raise SystemExit(1 if F else 0)
