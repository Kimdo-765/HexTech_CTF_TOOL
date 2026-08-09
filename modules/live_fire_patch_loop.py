"""Fail-closed provider patch loop and terminal artifacts for live-fire jobs.

LF-3 deliberately does not select or call a real model.  A caller supplies a
``PatchProvider`` and ``PatchReviewer``; LF-4 will adapt the production provider
router to those small boundaries.  This module owns everything that must not be
left to model prose: the writable surface, time reservation, machine-gate
precedence, report schema, source-location evidence, and final artifact split.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import time
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Protocol, Sequence

from modules.live_fire_verifier import (
    DockerRuntime,
    VerificationSpec,
    validate_verification,
    verify_workspace,
)
from modules.live_fire_workspace import (
    LiveFireWorkspace,
    assert_original_unchanged,
    build_patched_zip,
    load_workspace,
)


PATCH_LOOP_SCHEMA = 1
PROVIDER_STATUSES = {"success", "failure", "timeout", "refusal"}
MITIGATION_CLASSES = {"root-cause-fix", "input-filter", "mixed"}
EVIDENCE_TIERS = {"A", "B"}
SEVERITIES = {"critical", "high", "medium", "low"}

REPORT_HEADINGS = (
    "## 1. Summary",
    "## 2. Vulnerabilities",
    "## 3. Patch Changes",
    "## 4. Attack Reproduction",
    "## 5. Build, Test, and SLA",
    "## 6. Unverified Items and Residual Risk",
    "## 7. Artifact Integrity",
)

_SOURCE_SUFFIXES = (
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".css",
    ".cxx",
    ".ex",
    ".exs",
    ".fs",
    ".go",
    ".groovy",
    ".h",
    ".hh",
    ".hpp",
    ".html",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".kts",
    ".php",
    ".pl",
    ".pm",
    ".proto",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".scss",
    ".sh",
    ".sol",
    ".sql",
    ".svelte",
    ".swift",
    ".ts",
    ".tsx",
    ".vue",
)
_DEPENDENCY_FILES = {
    "cargo.lock",
    "cargo.toml",
    "composer.json",
    "composer.lock",
    "go.mod",
    "go.sum",
    "gradle.lockfile",
    "build.gradle",
    "build.gradle.kts",
    "gemfile",
    "gemfile.lock",
    "package-lock.json",
    "package.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
    "yarn.lock",
}
_DEPLOYMENT_NAMES = {
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "haproxy.cfg",
    "nginx.conf",
}
_DEPLOYMENT_PREFIXES = (".github/", "deploy/", "deployment/", "k8s/", "helm/")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:($|/)")


class PatchLoopError(ValueError):
    """The LF-3 configuration or generated evidence is unusable."""


class Clock(Protocol):
    def monotonic(self) -> float:
        """Return a monotonic timestamp."""


class SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()


@dataclass(frozen=True)
class VulnerabilityFinding:
    bug_class: str
    severity: str
    path: str
    line: int
    root_cause: str
    attack_impact: str
    patch_description: str
    patch_reason: str
    mitigation_class: str
    evidence_tier: str

    def __post_init__(self) -> None:
        for name in (
            "bug_class",
            "severity",
            "path",
            "root_cause",
            "attack_impact",
            "patch_description",
            "patch_reason",
            "mitigation_class",
            "evidence_tier",
        ):
            if not isinstance(getattr(self, name), str):
                raise PatchLoopError(f"finding {name} must be text")
        if (
            not isinstance(self.line, int)
            or isinstance(self.line, bool)
            or self.line < 1
        ):
            raise PatchLoopError("finding line must be a positive integer")


@dataclass(frozen=True)
class ProviderResult:
    status: str
    summary: str = ""
    findings: tuple[VulnerabilityFinding, ...] = ()
    ready_recommendation: bool = False

    def __post_init__(self) -> None:
        if self.status not in PROVIDER_STATUSES:
            raise PatchLoopError(f"invalid provider status: {self.status!r}")


@dataclass(frozen=True)
class PatchAttemptContext:
    candidate: Path
    attempt: int
    attempt_deadline: float
    discovery: "StaticDiscovery"
    feedback: tuple[str, ...]


class PatchProvider(Protocol):
    def attempt(self, context: PatchAttemptContext) -> ProviderResult:
        """Modify only ``context.candidate`` and return structured metadata."""


@dataclass(frozen=True)
class ReviewContext:
    attempt: int
    provider: ProviderResult
    diff: str
    policy_errors: tuple[str, ...]
    machine_errors: tuple[str, ...]
    report_errors: tuple[str, ...]
    verification: dict[str, Any]


@dataclass(frozen=True)
class ReviewResult:
    hint: str
    passed: bool = False


class PatchReviewer(Protocol):
    def review(self, context: ReviewContext) -> ReviewResult:
        """Return one actionable hint.  ``passed`` is advisory only."""


@dataclass(frozen=True)
class ReportContext:
    """Machine evidence supplied to the terminal report role.

    The report provider may turn this evidence into prose, but it cannot change
    the verification document, findings, or candidate diff.  Its output is
    validated below and a malformed report can never leave the job READY.
    """

    document: dict[str, Any]
    findings: tuple[VulnerabilityFinding, ...]
    diffs: tuple[DiffRecord, ...]


class PatchReporter(Protocol):
    def report(self, context: ReportContext) -> str:
        """Render the terminal report from immutable machine evidence."""


@dataclass(frozen=True)
class SourcePolicy:
    """Allowed application source/dependency surface for an immutable archive."""

    extra_allowed_paths: tuple[str, ...] = ()
    source_suffixes: tuple[str, ...] = _SOURCE_SUFFIXES
    dependency_files: frozenset[str] = field(
        default_factory=lambda: frozenset(_DEPENDENCY_FILES)
    )

    def allows(self, path: str) -> bool:
        normalized = PurePosixPath(path).as_posix()
        lower = normalized.lower()
        pure = PurePosixPath(lower)
        name = pure.name
        if name == "dockerfile" or name in _DEPLOYMENT_NAMES:
            return False
        if any(lower.startswith(prefix) for prefix in _DEPLOYMENT_PREFIXES):
            return False
        if any(part in {"test", "tests", "spec", "specs"} for part in pure.parts):
            return False
        if name.startswith(("test_", "spec_")):
            return False
        return (
            normalized in self.extra_allowed_paths
            or name in self.dependency_files
            or lower.endswith(self.source_suffixes)
        )


@dataclass(frozen=True)
class StaticDiscovery:
    stacks: tuple[str, ...]
    entrypoints: tuple[str, ...]
    build_files: tuple[str, ...]
    test_paths: tuple[str, ...]
    health_hints: tuple[str, ...]

    def as_dict(self) -> dict[str, list[str]]:
        return {
            "stacks": list(self.stacks),
            "entrypoints": list(self.entrypoints),
            "build_files": list(self.build_files),
            "test_paths": list(self.test_paths),
            "health_hints": list(self.health_hints),
        }


@dataclass(frozen=True)
class DiffRecord:
    path: str
    old_sha256: str
    new_sha256: str
    changed_lines: tuple[int, ...]
    candidate_line_count: int
    patch: str


@dataclass(frozen=True)
class PatchLoopSpec:
    verification: VerificationSpec
    job_timeout_s: float
    verification_reserve_s: float
    packaging_reserve_s: float
    max_attempts: int = 3
    source_policy: SourcePolicy = SourcePolicy()

    def __post_init__(self) -> None:
        if self.job_timeout_s <= 0:
            raise PatchLoopError("job_timeout_s must be positive")
        if self.verification_reserve_s <= 0:
            raise PatchLoopError("verification_reserve_s must be positive")
        if self.packaging_reserve_s <= 0:
            raise PatchLoopError("packaging_reserve_s must be positive")
        if self.verification_reserve_s + self.packaging_reserve_s >= self.job_timeout_s:
            raise PatchLoopError(
                "verification and packaging reserve must fit job timeout"
            )
        if self.max_attempts < 1:
            raise PatchLoopError("max_attempts must be positive")


@dataclass(frozen=True)
class PatchArtifacts:
    patched_zip: Path
    report: Path
    verification: Path


@dataclass(frozen=True)
class PatchRunResult:
    artifacts: PatchArtifacts
    verification: dict[str, Any]


RuntimeFactory = Callable[[], DockerRuntime]


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_paths(ws: LiveFireWorkspace) -> dict[str, dict[str, Any]]:
    return {member["path"]: member for member in ws.manifest["members"]}


def discover_service(
    workspace: LiveFireWorkspace | str | os.PathLike[str],
) -> StaticDiscovery:
    """Statically identify likely stack/build/test/health inputs without execution."""

    ws = (
        workspace
        if isinstance(workspace, LiveFireWorkspace)
        else load_workspace(workspace)
    )
    paths = tuple(sorted(_manifest_paths(ws)))
    lower = {path: path.lower() for path in paths}
    stacks: set[str] = set()
    if any(value.endswith(".py") for value in lower.values()):
        stacks.add("python")
    if any(value.endswith((".js", ".jsx", ".ts", ".tsx")) for value in lower.values()):
        stacks.add("node")
    if any(value.endswith(".go") for value in lower.values()):
        stacks.add("go")
    if any(value.endswith(".rs") for value in lower.values()):
        stacks.add("rust")
    if any(value.endswith((".c", ".cc", ".cpp", ".cxx")) for value in lower.values()):
        stacks.add("native")
    if any(PurePosixPath(value).name == "dockerfile" for value in lower.values()):
        stacks.add("docker")

    entry_names = {
        "app.py",
        "main.py",
        "server.py",
        "index.js",
        "server.js",
        "main.go",
        "main.rs",
        "entrypoint.sh",
        "run.sh",
    }
    build_names = {
        "dockerfile",
        "makefile",
        "cmakelists.txt",
        *_DEPENDENCY_FILES,
    }
    entrypoints = tuple(
        path for path in paths if PurePosixPath(lower[path]).name in entry_names
    )
    build_files = tuple(
        path for path in paths if PurePosixPath(lower[path]).name in build_names
    )
    test_paths = tuple(
        path
        for path in paths
        if any(
            part in {"test", "tests", "spec", "specs"}
            for part in PurePosixPath(lower[path]).parts
        )
        or PurePosixPath(lower[path]).name.startswith(("test_", "spec_"))
    )
    health_hints: list[str] = []
    for path in paths:
        member = _manifest_paths(ws)[path]
        if (
            member["kind"] != "regular"
            or member["compression"]["uncompressed_size"] > 1024 * 1024
        ):
            continue
        try:
            body = (ws.candidate / path).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        if re.search(r"(?i)(/health|healthcheck|readiness|liveness)", body):
            health_hints.append(path)
    return StaticDiscovery(
        tuple(sorted(stacks)),
        entrypoints,
        build_files,
        test_paths,
        tuple(health_hints),
    )


def _changed_line_numbers(
    old_lines: Sequence[str], new_lines: Sequence[str]
) -> tuple[int, ...]:
    changed: set[int] = set()
    matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
    for tag, _old_start, _old_end, new_start, new_end in matcher.get_opcodes():
        if tag == "equal":
            continue
        if new_start != new_end:
            changed.update(range(new_start + 1, new_end + 1))
        elif new_lines:
            changed.add(min(new_start + 1, len(new_lines)))
    return tuple(sorted(changed))


def candidate_diff(
    workspace: LiveFireWorkspace | str | os.PathLike[str],
) -> tuple[DiffRecord, ...]:
    """Return manifest-member content changes with candidate-side line evidence."""

    ws = (
        workspace
        if isinstance(workspace, LiveFireWorkspace)
        else load_workspace(workspace)
    )
    records: list[DiffRecord] = []
    for member in ws.manifest["members"]:
        if member["kind"] not in {"regular", "hardlink", "symlink"}:
            continue
        path = member["path"]
        original = ws.original / path
        candidate = ws.candidate / path
        try:
            if member["kind"] == "symlink":
                old_payload = os.fsencode(os.readlink(original))
                new_payload = os.fsencode(os.readlink(candidate))
            else:
                old_payload = original.read_bytes()
                new_payload = candidate.read_bytes()
        except OSError:
            continue
        if old_payload == new_payload:
            continue
        patch = ""
        changed_lines: tuple[int, ...] = ()
        line_count = 0
        try:
            old_text = old_payload.decode("utf-8")
            new_text = new_payload.decode("utf-8")
            old_lines = old_text.splitlines()
            new_lines = new_text.splitlines()
            line_count = len(new_lines)
            changed_lines = _changed_line_numbers(old_lines, new_lines)
            patch = "\n".join(
                difflib.unified_diff(
                    old_text.splitlines(),
                    new_text.splitlines(),
                    fromfile=f"a/{path}",
                    tofile=f"b/{path}",
                    lineterm="",
                )
            )
        except UnicodeDecodeError:
            patch = f"Binary files a/{path} and b/{path} differ"
        records.append(
            DiffRecord(
                path=path,
                old_sha256=_sha256_bytes(old_payload),
                new_sha256=_sha256_bytes(new_payload),
                changed_lines=changed_lines,
                candidate_line_count=line_count,
                patch=patch,
            )
        )
    return tuple(records)


def _candidate_inventory_errors(ws: LiveFireWorkspace) -> list[str]:
    members = _manifest_paths(ws)
    expected_dirs: set[str] = {""}
    for path, member in members.items():
        parts = PurePosixPath(path).parts
        expected_dirs.update("/".join(parts[:index]) for index in range(1, len(parts)))
        if member["kind"] == "directory":
            expected_dirs.add(path)

    errors: list[str] = []
    try:
        root_mode = ws.candidate.lstat().st_mode
    except OSError as exc:
        return [f"candidate root is unavailable: {exc}"]
    if not stat.S_ISDIR(root_mode):
        return ["candidate root is not a directory"]

    seen: set[str] = set()
    limits = ws.manifest["limits"]
    total_size = 0

    def visit(directory: Path, relative: PurePosixPath) -> None:
        nonlocal total_size
        try:
            entries = sorted(
                os.scandir(directory), key=lambda item: os.fsencode(item.name)
            )
        except OSError as exc:
            errors.append(f"cannot scan candidate {relative.as_posix() or '.'}: {exc}")
            return
        for entry in entries:
            child_rel = relative / entry.name
            path = child_rel.as_posix()
            seen.add(path)
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError as exc:
                errors.append(f"cannot stat candidate path {path!r}: {exc}")
                continue
            if stat.S_ISDIR(mode):
                if path not in expected_dirs:
                    errors.append(
                        f"added directory is outside the input manifest: {path}"
                    )
                visit(Path(entry.path), child_rel)
            elif path not in members:
                errors.append(f"added path is outside the input manifest: {path}")
            elif stat.S_ISREG(mode):
                if members[path]["kind"] not in {"regular", "hardlink"}:
                    errors.append(f"candidate type changed at {path}")
                if members[path]["kind"] == "regular":
                    if mode_size := entry.stat(follow_symlinks=False).st_size:
                        if mode_size > limits["max_file_uncompressed"]:
                            errors.append(f"candidate file exceeds size limit: {path}")
                        total_size += mode_size
            elif stat.S_ISLNK(mode):
                if members[path]["kind"] != "symlink":
                    errors.append(f"candidate type changed at {path}")
                else:
                    try:
                        target = os.readlink(entry.path)
                    except OSError as exc:
                        errors.append(f"cannot read candidate symlink {path!r}: {exc}")
                    else:
                        normalized = target.replace("\\", "/")
                        parts = list(PurePosixPath(path).parent.parts)
                        escapes = normalized.startswith("/") or bool(
                            _WINDOWS_DRIVE.match(normalized)
                        )
                        for part in PurePosixPath(normalized).parts:
                            if part in {"", "."}:
                                continue
                            if part == "..":
                                if not parts:
                                    escapes = True
                                    break
                                parts.pop()
                            else:
                                parts.append(part)
                        if escapes:
                            errors.append(
                                f"candidate symlink escapes the archive: {path}"
                            )
                        target_size = len(os.fsencode(target))
                        if target_size > limits["max_file_uncompressed"]:
                            errors.append(
                                f"candidate symlink exceeds size limit: {path}"
                            )
                        total_size += target_size
            else:
                errors.append(f"special candidate path is forbidden: {path}")

    visit(ws.candidate, PurePosixPath())
    for path in members:
        if path not in seen:
            errors.append(f"input manifest path was removed: {path}")
    if total_size > limits["max_total_uncompressed"]:
        errors.append("candidate tree exceeds total size limit")

    hardlink_groups: dict[str, set[str]] = {}
    for path, member in members.items():
        if member["kind"] == "hardlink":
            hardlink_groups.setdefault(
                member["link_resolved_path"], {member["link_resolved_path"]}
            ).add(path)
    allowed_by_inode: dict[tuple[int, int], set[str]] = {}
    for target, paths in hardlink_groups.items():
        try:
            metadata = (ws.candidate / target).lstat()
        except OSError as exc:
            errors.append(f"cannot stat hardlink target {target!r}: {exc}")
            continue
        allowed_by_inode[(metadata.st_dev, metadata.st_ino)] = paths
        for path in paths:
            try:
                linked = (ws.candidate / path).lstat()
            except OSError:
                continue
            if (linked.st_dev, linked.st_ino) != (metadata.st_dev, metadata.st_ino):
                errors.append(f"manifest hardlink relationship changed: {path}")
    for path, member in members.items():
        if member["kind"] != "regular":
            continue
        try:
            metadata = (ws.candidate / path).lstat()
        except OSError:
            continue
        if metadata.st_nlink <= 1:
            continue
        allowed = allowed_by_inode.get((metadata.st_dev, metadata.st_ino), set())
        if path not in allowed or metadata.st_nlink != len(allowed):
            errors.append(f"unexpected candidate hardlink: {path}")
    return errors


def _source_policy_errors(
    ws: LiveFireWorkspace, policy: SourcePolicy, diffs: tuple[DiffRecord, ...]
) -> list[str]:
    errors = _candidate_inventory_errors(ws)
    for record in diffs:
        if not policy.allows(record.path):
            errors.append(
                f"changed path is outside application source policy: {record.path}"
            )
    return errors


def _has_attempt_budget(
    remaining_s: float, verification_s: float, packaging_s: float
) -> bool:
    """Mutation seam for the anytime verification+packaging reservation."""

    return remaining_s > verification_s + packaging_s


def _machine_gate_errors(document: dict[str, Any]) -> list[str]:
    """Mutation seam: model recommendations cannot replace machine evidence."""

    errors = validate_verification(document)
    for name in ("build_gate", "health_gate", "sla_gate", "security_gate"):
        gate = document.get(name)
        if not isinstance(gate, dict) or gate.get("passed") is not True:
            errors.append(f"{name} did not pass")
    if document.get("errors"):
        errors.append("verification has runtime errors")
    if document.get("cleanup_errors"):
        errors.append("verification has cleanup errors")
    return sorted(set(errors))


def _location_matches_diff(
    finding: VulnerabilityFinding, diffs: tuple[DiffRecord, ...]
) -> bool:
    """Mutation seam for candidate ``file:line`` evidence."""

    for record in diffs:
        if record.path == finding.path:
            return (
                1 <= finding.line <= record.candidate_line_count
                and finding.line in record.changed_lines
            )
    return False


def _finding_errors(
    findings: tuple[VulnerabilityFinding, ...], diffs: tuple[DiffRecord, ...]
) -> list[str]:
    errors: list[str] = []
    for index, finding in enumerate(findings, 1):
        prefix = f"finding {index}"
        if not finding.bug_class.strip():
            errors.append(f"{prefix} lacks bug_class")
        if finding.severity not in SEVERITIES:
            errors.append(f"{prefix} has invalid severity")
        if finding.mitigation_class not in MITIGATION_CLASSES:
            errors.append(f"{prefix} has invalid mitigation_class")
        if finding.evidence_tier not in EVIDENCE_TIERS:
            errors.append(f"{prefix} has invalid evidence_tier")
        if not finding.root_cause.strip() or not finding.attack_impact.strip():
            errors.append(f"{prefix} lacks root cause or attack impact")
        if not finding.patch_description.strip() or not finding.patch_reason.strip():
            errors.append(f"{prefix} lacks patch description or reason")
        if not _location_matches_diff(finding, diffs):
            errors.append(
                f"{prefix} source location is not a changed candidate line: "
                f"{finding.path}:{finding.line}"
            )
    return errors


def _finding_evidence_errors(
    findings: tuple[VulnerabilityFinding, ...], document: dict[str, Any]
) -> list[str]:
    if not findings:
        return []
    classes = {finding.mitigation_class for finding in findings}
    expected_class = next(iter(classes)) if len(classes) == 1 else "mixed"
    errors: list[str] = []
    if document.get("mitigation_class") != expected_class:
        errors.append(
            "verification mitigation_class does not match vulnerability findings"
        )
    security = document.get("security_gate", {})
    tiers = security.get("evidence_tiers", []) if isinstance(security, dict) else []
    for finding in findings:
        if finding.evidence_tier not in tiers:
            errors.append(
                f"finding evidence_tier {finding.evidence_tier} lacks attack evidence"
            )
    return errors


def _missing_required_headings(report: str) -> list[str]:
    """Mutation seam for the seven-heading report schema."""

    return [heading for heading in REPORT_HEADINGS if report.count(heading) != 1]


def _safe_prose(value: Any) -> str:
    return " ".join(str(value).replace("`", "'").split()) or "not provided"


def _render_report(
    document: dict[str, Any],
    findings: tuple[VulnerabilityFinding, ...],
    diffs: tuple[DiffRecord, ...],
) -> str:
    status = "READY" if document.get("ready_to_deploy") is True else "UNVERIFIED"
    lines = [
        "# Live-fire Patch Report",
        "",
        REPORT_HEADINGS[0],
        "",
        f"Final ready_to_deploy: **{str(document.get('ready_to_deploy') is True).lower()}** ({status}).",
        f"Provider outcome: `{_safe_prose(document.get('provider_status'))}` after {document.get('attempts', 0)} attempt(s).",
        "",
        REPORT_HEADINGS[1],
        "",
    ]
    if findings:
        for index, finding in enumerate(findings, 1):
            lines.extend(
                [
                    f"### Vulnerability {index}",
                    "",
                    f"- Bug class: {_safe_prose(finding.bug_class)}",
                    f"- Severity: `{finding.severity}`",
                    f"- Source: `{finding.path}:{finding.line}`",
                    f"- Root cause: {_safe_prose(finding.root_cause)}",
                    f"- Attack impact: {_safe_prose(finding.attack_impact)}",
                    f"- Patch: {_safe_prose(finding.patch_description)}",
                    f"- Patch reason: {_safe_prose(finding.patch_reason)}",
                    f"- Mitigation class: `{finding.mitigation_class}`",
                    f"- Evidence tier: `{finding.evidence_tier}`",
                    "",
                ]
            )
    else:
        lines.extend(
            ["No source location was validated for this unverified result.", ""]
        )

    lines.extend([REPORT_HEADINGS[2], ""])
    if diffs:
        for record in diffs:
            changed = (
                ", ".join(str(line) for line in record.changed_lines) or "binary/none"
            )
            matching = [finding for finding in findings if finding.path == record.path]
            if matching:
                how = "; ".join(
                    _safe_prose(finding.patch_description) for finding in matching
                )
                why = "; ".join(
                    _safe_prose(finding.patch_reason) for finding in matching
                )
                lines.append(
                    f"- `{record.path}`: candidate changed lines {changed}; how: {how}; why: {why}."
                )
            else:
                lines.append(
                    f"- `{record.path}`: candidate changed lines {changed}; no validated change explanation."
                )
    else:
        lines.append("- No manifest member content changed.")

    security = document.get("security_gate", {})
    lines.extend(["", REPORT_HEADINGS[3], ""])
    attacks = security.get("probes", []) if isinstance(security, dict) else []
    if attacks:
        for row in attacks:
            if not isinstance(row, dict):
                continue
            original = row.get("original", {})
            candidate = row.get("candidate", {})
            lines.append(
                "- "
                f"`{_safe_prose(row.get('name'))}` (evidence tier `{_safe_prose(row.get('evidence_tier'))}`): "
                f"original reproduced={row.get('negative_control_passed') is True}; "
                f"candidate blocked={row.get('candidate_blocked') is True}; "
                f"passed={row.get('passed') is True}; "
                f"original exit={_safe_prose(original.get('exit_code'))}, "
                f"candidate exit={_safe_prose(candidate.get('exit_code'))}."
            )
    else:
        lines.append("- Attack regression did not produce machine evidence.")

    lines.extend(["", REPORT_HEADINGS[4], ""])
    for label, gate_name in (
        ("Build", "build_gate"),
        ("Health", "health_gate"),
        ("Existing test/SLA", "sla_gate"),
    ):
        gate = document.get(gate_name, {})
        passed = isinstance(gate, dict) and gate.get("passed") is True
        detail = ""
        if gate_name in {"build_gate", "health_gate"} and isinstance(gate, dict):
            sides = gate.get("sides", {})
            if isinstance(sides, dict):
                outcomes = []
                for side in ("original", "candidate"):
                    side_row = sides.get(side, {})
                    result = (
                        side_row.get("result", {}) if isinstance(side_row, dict) else {}
                    )
                    outcomes.append(
                        f"{side} exit={_safe_prose(result.get('exit_code'))}"
                    )
                detail = " " + ", ".join(outcomes) + "."
        elif gate_name == "sla_gate" and isinstance(gate, dict):
            probes = gate.get("probes", [])
            if isinstance(probes, list):
                comparisons = [
                    f"{_safe_prose(row.get('name'))}:equal={row.get('equal') is True}"
                    for row in probes
                    if isinstance(row, dict)
                ]
                detail = " " + ", ".join(comparisons) + "."
        lines.append(f"- {label}: passed={passed}.{detail}")

    lines.extend(["", REPORT_HEADINGS[5], ""])
    residual = document.get("residual_risks")
    if isinstance(residual, list) and residual:
        lines.extend(f"- {_safe_prose(item)}" for item in residual)
    else:
        lines.append("- No unverified item was recorded by the terminal phase.")

    lines.extend(
        [
            "",
            REPORT_HEADINGS[6],
            "",
            f"- Input SHA-256: `{_safe_prose(document.get('input_sha256'))}`",
            f"- Output SHA-256: `{_safe_prose(document.get('output_sha256'))}`",
            "- Changed files: "
            + (", ".join(f"`{record.path}`" for record in diffs) if diffs else "none"),
            "",
        ]
    )
    return "\n".join(lines)


_SOURCE_LINE = re.compile(r"^- Source: `([^`]+):([1-9][0-9]*)`$", re.MULTILINE)


def validate_report(
    report: str,
    document: dict[str, Any],
    findings: tuple[VulnerabilityFinding, ...],
    diffs: tuple[DiffRecord, ...],
) -> list[str]:
    errors = [
        f"missing or duplicate report heading: {item}"
        for item in _missing_required_headings(report)
    ]
    expected_ready = f"Final ready_to_deploy: **{str(document.get('ready_to_deploy') is True).lower()}**"
    if expected_ready not in report:
        errors.append("report ready_to_deploy summary does not match verification")
    locations = [(path, int(line)) for path, line in _SOURCE_LINE.findall(report)]
    expected_locations = [(finding.path, finding.line) for finding in findings]
    if locations != expected_locations:
        errors.append("report source locations do not match structured findings")
    errors.extend(_finding_errors(findings, diffs))
    errors.extend(_finding_evidence_errors(findings, document))
    for finding in findings:
        if f"- Mitigation class: `{finding.mitigation_class}`" not in report:
            errors.append("report lacks vulnerability mitigation_class")
        if f"- Evidence tier: `{finding.evidence_tier}`" not in report:
            errors.append("report lacks vulnerability evidence_tier")
    return sorted(set(errors))


def _write_text_atomic(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _write_json_atomic(path: Path, document: dict[str, Any]) -> None:
    _write_text_atomic(path, json.dumps(document, indent=2, sort_keys=True) + "\n")


def _copy_candidate_snapshot(ws: LiveFireWorkspace) -> tuple[Path, Path]:
    snapshot_root = Path(tempfile.mkdtemp(prefix=".lf3-snapshot-", dir=ws.root))
    snapshot = snapshot_root / "candidate"
    shutil.copytree(ws.candidate, snapshot, symlinks=True, copy_function=shutil.copy2)
    for member in ws.manifest["members"]:
        if member["kind"] != "hardlink":
            continue
        link = snapshot / member["path"]
        target = snapshot / member["link_resolved_path"]
        link.unlink()
        os.link(target, link, follow_symlinks=False)
    return snapshot_root, snapshot


def _remove_path(path: Path) -> None:
    if not os.path.lexists(path):
        return
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def _restore_candidate(
    ws: LiveFireWorkspace, snapshot_root: Path, snapshot: Path
) -> None:
    dirty = snapshot_root / "dirty-candidate"
    if os.path.lexists(ws.candidate):
        os.replace(ws.candidate, dirty)
    os.replace(snapshot, ws.candidate)
    _remove_path(dirty)


def _attempt_record(
    attempt: int,
    provider: ProviderResult,
    policy_errors: list[str],
    machine_errors: list[str],
    report_errors: list[str],
    diffs: tuple[DiffRecord, ...],
    reviewer: ReviewResult | None,
) -> dict[str, Any]:
    return {
        "attempt": attempt,
        "provider_status": provider.status,
        "provider_summary": provider.summary,
        "provider_ready_recommendation": provider.ready_recommendation,
        "changed_paths": [record.path for record in diffs],
        "policy_errors": policy_errors,
        "machine_errors": machine_errors,
        "report_errors": report_errors,
        "reviewer": None
        if reviewer is None
        else {"hint": reviewer.hint, "passed": reviewer.passed},
    }


def validate_patch_verification(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if document.get("patch_loop_schema") != PATCH_LOOP_SCHEMA:
        errors.append("patch_loop_schema is invalid")
    if document.get("provider_status") not in PROVIDER_STATUSES:
        errors.append("provider_status is invalid")
    for name in ("input_sha256", "output_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(document.get(name, ""))):
            errors.append(f"{name} is missing or invalid")
    if (
        not isinstance(document.get("attempts"), int)
        or document.get("attempts", -1) < 0
    ):
        errors.append("attempts must be a non-negative integer")
    for name in ("policy_gate", "report_gate"):
        gate = document.get(name)
        if not isinstance(gate, dict) or not isinstance(gate.get("passed"), bool):
            errors.append(f"{name}.passed must be boolean")
    if not isinstance(document.get("changed_paths"), list):
        errors.append("changed_paths must be a list")
    if document.get("ready_to_deploy") is True:
        if document.get("provider_status") != "success":
            errors.append("ready_to_deploy requires provider success")
        for name in ("policy_gate", "report_gate"):
            gate = document.get(name, {})
            if not isinstance(gate, dict) or gate.get("passed") is not True:
                errors.append(f"ready_to_deploy cannot bypass {name}")
        errors.extend(_machine_gate_errors(document))
    return sorted(set(errors))


def run_patch_loop(
    workspace: LiveFireWorkspace | str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    spec: PatchLoopSpec,
    provider: PatchProvider,
    reviewer: PatchReviewer,
    *,
    reporter: PatchReporter | None = None,
    runtime_factory: RuntimeFactory | None = None,
    clock: Clock | None = None,
) -> PatchRunResult:
    """Run bounded attempts and atomically flush the three LF artifacts."""

    ws = (
        workspace
        if isinstance(workspace, LiveFireWorkspace)
        else load_workspace(workspace)
    )
    assert_original_unchanged(ws)
    manifest_before = ws.manifest_path.read_bytes()
    output_root = Path(output_dir)
    output_resolved = output_root.resolve()
    for source_root in (ws.original.resolve(), ws.candidate.resolve()):
        if output_resolved == source_root or source_root in output_resolved.parents:
            raise PatchLoopError("terminal artifacts must stay outside source trees")
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = PatchArtifacts(
        patched_zip=output_root / "patched.zip",
        report=output_root / "report.md",
        verification=output_root / "verification.json",
    )
    active_clock = clock or SystemClock()
    deadline = active_clock.monotonic() + spec.job_timeout_s
    discovery = discover_service(ws)
    feedback: list[str] = []
    attempts: list[dict[str, Any]] = []
    last_provider = ProviderResult("failure", "no patch attempt started")
    last_verification: dict[str, Any] | None = None
    last_findings: tuple[VulnerabilityFinding, ...] = ()
    last_policy_errors: list[str] = []
    terminal_ready = False

    with tempfile.TemporaryDirectory(
        prefix=".lf3-verification-", dir=ws.root
    ) as attempt_tmp:
        attempt_root = Path(attempt_tmp)
        for attempt in range(1, spec.max_attempts + 1):
            remaining = deadline - active_clock.monotonic()
            if not _has_attempt_budget(
                remaining, spec.verification_reserve_s, spec.packaging_reserve_s
            ):
                feedback.append(
                    "new attempt skipped to preserve verification and packaging time"
                )
                break

            snapshot_root, snapshot = _copy_candidate_snapshot(ws)
            attempt_deadline = (
                deadline - spec.verification_reserve_s - spec.packaging_reserve_s
            )
            try:
                provider_result = provider.attempt(
                    PatchAttemptContext(
                        candidate=ws.candidate,
                        attempt=attempt,
                        attempt_deadline=attempt_deadline,
                        discovery=discovery,
                        feedback=tuple(feedback),
                    )
                )
            except TimeoutError as exc:
                provider_result = ProviderResult("timeout", str(exc))
            except Exception as exc:
                provider_result = ProviderResult("failure", f"provider error: {exc}")
            if (
                active_clock.monotonic() > attempt_deadline
                and provider_result.status == "success"
            ):
                provider_result = replace(
                    provider_result,
                    status="timeout",
                    summary="provider exceeded the reserved attempt deadline",
                    ready_recommendation=False,
                )

            assert_original_unchanged(ws)
            if ws.manifest_path.read_bytes() != manifest_before:
                _restore_candidate(ws, snapshot_root, snapshot)
                raise PatchLoopError(
                    "provider modified the immutable workspace manifest"
                )
            inventory_errors = _candidate_inventory_errors(ws)
            attempted_diffs = () if inventory_errors else candidate_diff(ws)
            policy_errors = _source_policy_errors(
                ws, spec.source_policy, attempted_diffs
            )
            if policy_errors:
                _restore_candidate(ws, snapshot_root, snapshot)
            _remove_path(snapshot_root)

            diffs = candidate_diff(ws)
            runtime = runtime_factory() if runtime_factory is not None else None
            verification_path = attempt_root / f"attempt-{attempt}.json"
            verification = verify_workspace(
                ws,
                spec.verification,
                verification_path,
                runtime=runtime,
            )
            machine_errors = _machine_gate_errors(verification)
            finding_errors = _finding_errors(provider_result.findings, diffs)
            report_errors = finding_errors + _finding_evidence_errors(
                provider_result.findings, verification
            )
            if provider_result.status == "success" and not provider_result.findings:
                report_errors.append(
                    "successful provider result has no vulnerability finding"
                )

            last_provider = provider_result
            last_verification = verification
            last_findings = provider_result.findings
            last_policy_errors = policy_errors
            terminal_ready = (
                provider_result.status == "success"
                and not policy_errors
                and not machine_errors
                and not report_errors
            )
            reviewer_result: ReviewResult | None = None
            if not terminal_ready:
                try:
                    reviewer_result = reviewer.review(
                        ReviewContext(
                            attempt=attempt,
                            provider=provider_result,
                            diff="\n".join(record.patch for record in attempted_diffs),
                            policy_errors=tuple(policy_errors),
                            machine_errors=tuple(machine_errors),
                            report_errors=tuple(report_errors),
                            verification=verification,
                        )
                    )
                except Exception as exc:
                    reviewer_result = ReviewResult(
                        f"reviewer unavailable; use machine evidence directly: {exc}"
                    )
                feedback.append(reviewer_result.hint)
            attempts.append(
                _attempt_record(
                    attempt,
                    provider_result,
                    policy_errors,
                    machine_errors,
                    report_errors,
                    attempted_diffs,
                    reviewer_result,
                )
            )
            if terminal_ready:
                break

        if last_verification is None:
            runtime = runtime_factory() if runtime_factory is not None else None
            last_verification = verify_workspace(
                ws,
                spec.verification,
                attempt_root / "terminal.json",
                runtime=runtime,
            )

    assert_original_unchanged(ws)
    if ws.manifest_path.read_bytes() != manifest_before:
        raise PatchLoopError("workspace manifest changed during patch loop")
    terminal_inventory_errors = _candidate_inventory_errors(ws)
    final_diffs = () if terminal_inventory_errors else candidate_diff(ws)
    terminal_policy_errors = _source_policy_errors(ws, spec.source_policy, final_diffs)
    if terminal_policy_errors:
        terminal_ready = False
        last_policy_errors = terminal_policy_errors

    build_patched_zip(ws, artifacts.patched_zip)
    output_sha = _sha256_file(artifacts.patched_zip)
    machine_errors = _machine_gate_errors(last_verification)
    finding_errors = _finding_errors(last_findings, final_diffs)
    residual_risks = sorted(
        set(
            ([] if terminal_ready else feedback)
            + last_policy_errors
            + machine_errors
            + finding_errors
            + (
                []
                if last_provider.status == "success"
                else [f"provider ended with {last_provider.status}"]
            )
        )
    )
    document = dict(last_verification)
    document.update(
        {
            "patch_loop_schema": PATCH_LOOP_SCHEMA,
            "ready_to_deploy": terminal_ready,
            "provider_status": last_provider.status,
            "provider_ready_recommendation": last_provider.ready_recommendation,
            "attempts": len(attempts),
            "attempt_records": attempts,
            "review_feedback": feedback,
            "changed_paths": [record.path for record in final_diffs],
            "static_discovery": discovery.as_dict(),
            "policy_gate": {
                "passed": not last_policy_errors,
                "errors": last_policy_errors,
            },
            "output_sha256": output_sha,
            "vulnerabilities": [finding.__dict__ for finding in last_findings],
            "residual_risks": residual_risks,
        }
    )

    if reporter is None:
        # LF-3 compatibility path: the deterministic renderer remains the
        # complete implementation when no routed report role was supplied.
        provisional_report = _render_report(document, last_findings, final_diffs)
        report_errors = validate_report(
            provisional_report, document, last_findings, final_diffs
        )
        document["report_gate"] = {
            "passed": not report_errors,
            "errors": report_errors,
        }
        document["ready_to_deploy"] = terminal_ready and not report_errors
        report = _render_report(document, last_findings, final_diffs)
        final_report_errors = validate_report(
            report, document, last_findings, final_diffs
        )
        if final_report_errors:
            document["report_gate"] = {
                "passed": False,
                "errors": final_report_errors,
            }
            document["ready_to_deploy"] = False
            report = _render_report(document, last_findings, final_diffs)
    else:
        # LF-4 path: invoke the snapshotted report role exactly once.  Report
        # prose is untrusted just like provider prose, so schema/location/
        # evidence validation remains authoritative.  On any failure we keep a
        # complete deterministic diagnostic report but preserve report_gate
        # failure and force READY false.
        try:
            report = reporter.report(
                ReportContext(
                    document=dict(document),
                    findings=last_findings,
                    diffs=final_diffs,
                )
            )
            if not isinstance(report, str):
                raise PatchLoopError("terminal report provider returned non-text")
            report_errors = validate_report(
                report, document, last_findings, final_diffs
            )
        except Exception as exc:
            report_errors = [f"terminal report provider failed: {exc}"]
            report = ""
        document["report_gate"] = {
            "passed": not report_errors,
            "errors": sorted(set(report_errors)),
        }
        document["ready_to_deploy"] = terminal_ready and not report_errors
        if report_errors:
            document["residual_risks"] = sorted(
                set(
                    list(document.get("residual_risks") or [])
                    + ["terminal report provider output failed validation"]
                )
            )
            report = _render_report(document, last_findings, final_diffs)
            fallback_errors = validate_report(
                report, document, last_findings, final_diffs
            )
            if fallback_errors:
                raise PatchLoopError(
                    "invalid deterministic report fallback: "
                    + "; ".join(fallback_errors)
                )

    verification_errors = validate_patch_verification(document)
    if verification_errors:
        raise PatchLoopError(
            "invalid terminal verification: " + "; ".join(verification_errors)
        )
    _write_text_atomic(artifacts.report, report)
    _write_json_atomic(artifacts.verification, document)
    return PatchRunResult(artifacts=artifacts, verification=document)


__all__ = [
    "DiffRecord",
    "PatchArtifacts",
    "PatchAttemptContext",
    "PatchLoopError",
    "PatchLoopSpec",
    "PatchProvider",
    "PatchReporter",
    "PatchReviewer",
    "PatchRunResult",
    "ProviderResult",
    "ReportContext",
    "ReviewContext",
    "ReviewResult",
    "SourcePolicy",
    "StaticDiscovery",
    "VulnerabilityFinding",
    "candidate_diff",
    "discover_service",
    "run_patch_loop",
    "validate_patch_verification",
    "validate_report",
]
