#!/usr/bin/env python3
"""Aggregate top-level pwn/rev outcomes by attempt and retry lineage.

This is an offline analysis tool.  It deliberately depends only on the Python
standard library and never imports the API or a module execution path.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_JOBS_DIR = ROOT / "data" / "jobs"
INCLUDED_MODULES = frozenset({"pwn", "rev"})
MANUAL_MARKER = "[manual-run]"
SUCCESS_TIER_MARKER = "marker"
SUCCESS_TIER_UNTRUSTED = "untrusted-tier"
SUCCESS_TIER_MISSING = "missing-provenance"
SUCCESS_TIER_ORDER = (
    SUCCESS_TIER_MARKER,
    SUCCESS_TIER_UNTRUSTED,
    SUCCESS_TIER_MISSING,
)
NONTERMINAL_STATUSES = frozenset({"queued", "running", "analyze", "analyzing"})

# Historical top-level jobs whose purpose was to validate the orchestration
# itself, not to solve an operator-submitted challenge.  The job metadata has
# no durable field for that distinction, so keep the corpus exception explicit
# and visible in the report rather than inferring it from a flag or filename.
POPULATION_EXCLUSIONS = {
    "9f9dad521117": "system-validation-live-test",
}

ENV_FAILURE_PATTERN = (
    r"Could not connect to (?:host )?[A-Za-z0-9.-]+\b"
    r"|remote QEMU gdb port remains occupied"
    r"|Failed to find an available port: Address already in use"
    r"|\bis down\b"
    r"|\bECONNREFUSED\b"
    r"|\brefuses TCP\b"
    r"|\boffline target\b"
)
ENV_LOG_RE = re.compile(
    ENV_FAILURE_PATTERN + r"|\bAddress in use\b",
    re.IGNORECASE,
)
ENV_STDERR_RE = re.compile(
    ENV_FAILURE_PATTERN,
    re.IGNORECASE,
)
HOST_PORT_RE = re.compile(r"([A-Za-z0-9.-]+:\d+)")
LOG_LINE_RE = re.compile(
    r"^\[(\d\d):(\d\d):(\d\d)\] \[([^]]+)\] ([^:]+):\s?(.*)$"
)
EXECUTION_SCRIPT_RE = re.compile(
    r"^(?:exploit|probe|solver|solver_smoke|sage_smoke)(?:\.[A-Za-z0-9_.-]+)?$",
    re.IGNORECASE,
)
REMOTE_CLIENTS = frozenset(
    {"curl", "nc", "ncat", "netcat", "qemu-system-x86_64", "socat", "ssh", "wget"}
)
RUNNER_OUTPUT_MARKERS = ("[runner:stderr]", "[runner:stdout]")
RUNNER_PREFLIGHT_UNREACHABLE_RE = re.compile(
    r"^\d+ unreachable before run \(.+\); reloading meta\.json$"
)
RUNNER_REPORT_READERS = frozenset({"cat", "sed"})
RUNNER_REPORT_TITLE = "# Why this run stopped"
RUNNER_REPORT_SECTION = "## Last sandbox run"
RUNNER_REPORT_TAIL_RE = re.compile(r"^\*\*(?:stderr|stdout) tail\*\*")
MARKDOWN_FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")
HARVEST_FAILURE_WARNING_RE = re.compile(
    r"^judge verdict=success but 0 flags harvested\b", re.IGNORECASE
)

# The mapping is intentionally data, not an implicit sequence of returns.
# P1 and P6c each fan out into more than one class.
RUNG_CLASS_MAP = {
    "P0": ("EXCLUDED_operator_stop",),
    "P1": ("HARN_stream_overflow", "HARN_sdk_transport"),
    "P2": ("POL_prejudge_blocked", "POL_aup_refusal"),
    "P3": ("RES_timeout",),
    "P4": ("ENV_target_unusable", "HARN_flag_harvest"),
    "P5": ("ENV_target_unusable", "CAP_solver_exhausted"),
    "P6a": ("ENV_target_unusable",),
    "P6b": ("ENV_target_unusable",),
    "P6c": ("HARN_no_events", "CAP_ran_no_flag", "CAP_solver_exhausted"),
    "P6d": ("CAP_solver_exhausted", "UNRESOLVED"),
}

REPORT_CLASS_ORDER = (
    "CAP_solver_exhausted",
    "ENV_target_unusable",
    "POL_prejudge_blocked",
    "HARN_flag_harvest",
    "HARN_sdk_transport",
    "HARN_stream_overflow",
    "POL_aup_refusal",
    "CAP_ran_no_flag",
)


class AggregationError(RuntimeError):
    """The snapshot cannot be aggregated without inventing provenance."""


@dataclass(frozen=True)
class Job:
    job_id: str
    directory: Path
    meta: dict[str, Any]
    events: tuple[dict[str, Any], ...]
    malformed_event_lines: tuple[int, ...]


@dataclass(frozen=True)
class Outcome:
    success: bool | None
    source: str
    status: str
    flags: int


@dataclass(frozen=True)
class Classification:
    job_id: str
    class_name: str
    rung: str
    evidence: str
    error_kind_state: str


@dataclass(frozen=True)
class Lineage:
    root: str
    final_failure: str
    class_name: str
    cost: Decimal


@dataclass(frozen=True)
class PopulationExclusion:
    job_id: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class AggregateResult:
    included: int
    successes: int
    nonsuccesses: int
    excluded: int
    failures: int
    lineages: int
    capability_lineages: int
    noncapability_lineages: int
    noncapability_percent: int
    skipped_counts: dict[str, int]
    source_counts: dict[str, int]
    source_successes: dict[str, int]
    success_tier_counts: dict[str, int]
    attempt_counts: dict[str, int]
    lineage_counts: dict[str, int]
    lineage_costs: dict[str, Decimal]
    rung_counts: dict[str, int]
    classifications: tuple[Classification, ...]
    lineage_rows: tuple[Lineage, ...]
    population_exclusions: tuple[PopulationExclusion, ...]
    retry_anomalies: tuple[str, ...]


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _read_events(path: Path) -> tuple[tuple[dict[str, Any], ...], tuple[int, ...]]:
    if not path.is_file():
        return (), ()
    events: list[dict[str, Any]] = []
    malformed_lines: list[int] = []
    for line_no, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise TypeError("event must be a JSON object")
            timestamp = _parse_time(event.get("ts"))
        except (json.JSONDecodeError, TypeError, ValueError):
            malformed_lines.append(line_no)
            continue
        if timestamp is None:
            malformed_lines.append(line_no)
            continue
        event["_line"] = line_no
        event["_dt"] = timestamp
        events.append(event)
    return tuple(events), tuple(malformed_lines)


def load_snapshot(jobs_dir: Path) -> dict[str, Job]:
    jobs: dict[str, Job] = {}
    for meta_path in sorted(jobs_dir.glob("*/meta.json")):
        meta = json.loads(meta_path.read_text(errors="replace"))
        job_id = str(meta.get("id") or meta_path.parent.name)
        if job_id in jobs:
            raise AggregationError(f"duplicate job id: {job_id}")
        events, malformed_event_lines = _read_events(meta_path.parent / "events.jsonl")
        jobs[job_id] = Job(
            job_id=job_id,
            directory=meta_path.parent,
            meta=meta,
            events=events,
            malformed_event_lines=malformed_event_lines,
        )
    return jobs


def population_exclusion_reasons(job: Job) -> tuple[str, ...]:
    reasons: list[str] = []
    module = job.meta.get("module")
    if module not in INCLUDED_MODULES:
        reasons.append(f"module={module!r}")
    if job.meta.get("internal"):
        reasons.append("internal")
    if job.meta.get("parent_job_id"):
        reasons.append(f"parent_job_id={job.meta['parent_job_id']}")
    if job.job_id in POPULATION_EXCLUSIONS:
        reasons.append(POPULATION_EXCLUSIONS[job.job_id])
    return tuple(reasons)


def is_included(job: Job) -> bool:
    return not population_exclusion_reasons(job)


def _terminal_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [event for event in events if event.get("phase") == "terminal"]


def _status_terminals(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        event
        for event in events
        if event.get("phase") == "terminal" and event.get("kind") == "status"
    ]


def _read_run_log(job: Job) -> str:
    path = job.directory / "run.log"
    return path.read_text(errors="replace") if path.is_file() else ""


def automatic_outcome(job: Job) -> Outcome:
    """Read the automatic outcome, retaining its terminal/legacy provenance."""
    if job.malformed_event_lines:
        return Outcome(False, "corrupt-events", "unresolved", 0)

    terminals = _status_terminals(job.events)
    if terminals:
        terminal = terminals[-1]
        status = str(terminal.get("status") or "")
        flags = int(terminal.get("flags") or 0)
        return Outcome(status == "finished" and flags > 0, "terminal", status, flags)

    run_log = _read_run_log(job)
    manual_marker = MANUAL_MARKER in run_log
    if manual_marker or job.meta.get("manual_run"):
        return Outcome(None, "unsafe-legacy-meta", "unresolved", 0)

    status = str(job.meta.get("status") or "")
    flags = len(job.meta.get("flags") or [])
    return Outcome(status == "finished" and flags > 0, "legacy-meta", status, flags)


def success_tier(job: Job) -> str:
    """Expose success evidence strength without changing the success decision."""
    provenance = job.meta.get("flag_provenance")
    if provenance is None:
        return SUCCESS_TIER_MISSING
    if provenance == SUCCESS_TIER_MARKER and job.meta.get("flag_trusted_tier") is True:
        return SUCCESS_TIER_MARKER
    return SUCCESS_TIER_UNTRUSTED


def event_window(job: Job) -> tuple[tuple[dict[str, Any], ...], datetime | None, datetime | None]:
    started = _parse_time(job.meta.get("started_at"))
    finished = _parse_time(job.meta.get("finished_at"))
    terminal_events = _terminal_events(job.events)

    if terminal_events:
        end = terminal_events[-1]["_dt"]
    elif finished is not None:
        end = finished + timedelta(seconds=60)
    else:
        end = None

    if started is None:
        selected = tuple(event for event in job.events if end is None or event["_dt"] <= end)
    elif end is None:
        selected = tuple(event for event in job.events if event["_dt"] >= started)
    else:
        selected = tuple(event for event in job.events if started <= event["_dt"] <= end)
    return selected, started, end


def _final_attempt(
    events: tuple[dict[str, Any], ...],
) -> tuple[str | None, dict[str, Any] | None, dict[str, Any] | None]:
    starts = [
        index
        for index, event in enumerate(events)
        if event.get("phase") == "run" and event.get("kind") == "start"
    ]
    if not starts:
        return None, None, None
    start_index = starts[-1]
    target = events[start_index].get("target")
    exit_event = None
    postjudge = None
    for event in events[start_index + 1 :]:
        if event.get("phase") == "run" and event.get("kind") == "start":
            break
        if event.get("phase") == "run" and event.get("kind") == "exit":
            exit_event = event
        elif event.get("phase") == "postjudge" and event.get("kind") == "verdict":
            postjudge = event
    return str(target) if target is not None else None, exit_event, postjudge


def error_kind_state(meta: dict[str, Any]) -> str:
    value = meta.get("error_kind")
    if value is None:
        return "null"
    return f"value:{value}"


def _stop_target(text: str) -> str | None:
    match = HOST_PORT_RE.search(text)
    return match.group(1) if match else None


def _timestamped_log_lines(
    job: Job, started: datetime | None, end: datetime | None
) -> list[tuple[int, str, str, str]]:
    """Return automatic, windowed run.log records as line/actor/kind/payload."""
    result: list[tuple[int, str, str, str]] = []
    previous = started
    for line_no, line in enumerate(_read_run_log(job).splitlines(), 1):
        if MANUAL_MARKER in line:
            break
        match = LOG_LINE_RE.match(line)
        if not match:
            continue
        hour, minute, second, actor, kind, payload = match.groups()

        if started is not None:
            timestamp = started.replace(
                hour=int(hour), minute=int(minute), second=int(second), microsecond=0
            )
            while previous is not None and timestamp < previous - timedelta(seconds=2):
                timestamp += timedelta(days=1)
            previous = timestamp
            if timestamp < started or (end is not None and timestamp > end):
                continue
        result.append((line_no, actor, kind, payload))
    return result


def _command_tokens(command: str) -> list[list[str]]:
    """Split shell text into simple commands without treating quoted pipes as syntax."""
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|\n")
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return []

    commands: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token and all(character in ";&|\n" for character in token):
            if current:
                commands.append(current)
                current = []
        else:
            current.append(token)
    if current:
        commands.append(current)
    return commands


def _unwrap_shell_command(command: str) -> str:
    """Return the script passed to a conventional `sh -c` wrapper when present."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return command
    if not tokens or Path(tokens[0]).name not in {"bash", "sh", "zsh"}:
        return command
    for index, token in enumerate(tokens[1:], 1):
        if token.startswith("-") and "c" in token and index + 1 < len(tokens):
            return tokens[index + 1]
    return command


def _bash_command(command_parts: list[str]) -> str:
    raw = "\n".join(command_parts)
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw
    if isinstance(payload, dict) and isinstance(payload.get("command"), str):
        return payload["command"]
    return raw


def _is_execution_command(command: str) -> bool:
    """Allow only commands that directly run a challenge or contact a target."""
    script = _unwrap_shell_command(command)
    inline_remote = re.search(
        r"\b(?:socket\.)?create_connection\s*\(|\b(?:pwn\.)?remote\s*\(", script
    )
    for tokens in _command_tokens(script):
        while tokens and (
            "=" in tokens[0] and not tokens[0].startswith(("./", "/"))
        ):
            tokens = tokens[1:]
        while tokens and Path(tokens[0]).name in {"command", "env", "sudo", "timeout"}:
            tokens = tokens[1:]
            while tokens and tokens[0].startswith("-"):
                tokens = tokens[1:]
        if not tokens:
            continue
        executable = Path(tokens[0]).name
        if executable in REMOTE_CLIENTS or executable.startswith("qemu-system-"):
            return True
        if EXECUTION_SCRIPT_RE.match(executable):
            return True
        if executable.startswith(("python", "pypy")):
            script_args = [Path(token).name for token in tokens[1:] if not token.startswith("-")]
            if any(EXECUTION_SCRIPT_RE.match(token) for token in script_args):
                return True
            if inline_remote is not None:
                return True
    return False


def _is_runner_report_read_command(command: str) -> bool:
    """Recognize a full read of the generated runner report, not arbitrary data output."""
    script = _unwrap_shell_command(command)
    for tokens in _command_tokens(script):
        while tokens and "=" in tokens[0] and not tokens[0].startswith(("./", "/")):
            tokens = tokens[1:]
        if not tokens:
            continue
        executable = Path(tokens[0]).name
        if executable not in RUNNER_REPORT_READERS:
            continue
        if any(Path(token).name == "WHY_STOPPED.md" for token in tokens[1:]):
            return True
    return False


def _markdown_fence(line: str) -> tuple[str, int, str] | None:
    """Return a Markdown fence's character, width, and trailing info string."""
    match = MARKDOWN_FENCE_RE.match(line)
    if match is None:
        return None
    marker, info = match.groups()
    return marker[0], len(marker), info


def _environment_log_evidence(
    job: Job, started: datetime | None, end: datetime | None
) -> tuple[int, str] | None:
    command_parts: list[str] = []
    command_is_bash = False
    runner_report_seen = False
    runner_report_section_seen = False
    runner_tail_armed = False
    runner_fence: tuple[str, int] | None = None
    for line_no, actor, kind, payload in _timestamped_log_lines(job, started, end):
        if (
            actor == "runner"
            and kind.startswith("target ")
            and RUNNER_PREFLIGHT_UNREACHABLE_RE.fullmatch(payload)
        ):
            return line_no, "runner target unreachable"
        if kind == "TOOL Bash":
            if not command_is_bash or payload.lstrip().startswith("{"):
                command_parts = []
            command_is_bash = True
            command_parts.append(payload)
            runner_report_seen = False
            runner_report_section_seen = False
            runner_tail_armed = False
            runner_fence = None
            continue
        if kind.startswith("TOOL ") and kind not in {"TOOL_RESULT", "TOOL_ERROR"}:
            command_parts = []
            command_is_bash = False
            runner_report_seen = False
            runner_report_section_seen = False
            runner_tail_armed = False
            runner_fence = None
            continue
        if kind not in {"TOOL_RESULT", "TOOL_ERROR"} and actor not in {
            "runner:stderr",
            "runner:stdout",
        }:
            runner_report_seen = False
            runner_report_section_seen = False
            runner_tail_armed = False
            runner_fence = None
            continue
        command = _bash_command(command_parts) if command_is_bash else ""
        is_runner_report_read = command_is_bash and _is_runner_report_read_command(command)
        if kind == "TOOL_RESULT" and is_runner_report_read:
            heading = payload.strip()
            if runner_fence is not None:
                fence = _markdown_fence(payload)
                if (
                    fence is not None
                    and fence[0] == runner_fence[0]
                    and fence[1] >= runner_fence[1]
                    and not fence[2].strip()
                ):
                    runner_fence = None
                    runner_tail_armed = False
            elif heading == RUNNER_REPORT_TITLE:
                runner_report_seen = True
                runner_report_section_seen = False
                runner_tail_armed = False
                runner_fence = None
            elif runner_report_seen and heading == RUNNER_REPORT_SECTION:
                runner_report_section_seen = True
                runner_tail_armed = False
                runner_fence = None
            elif runner_report_section_seen and runner_fence is None:
                fence = _markdown_fence(payload)
                if runner_tail_armed and fence is not None:
                    runner_fence = (fence[0], fence[1])
                    runner_tail_armed = False
                elif RUNNER_REPORT_TAIL_RE.match(heading):
                    runner_tail_armed = True
                elif heading.startswith("## "):
                    runner_report_seen = False
                    runner_report_section_seen = False
                    runner_tail_armed = False
        elif kind in {"TOOL_RESULT", "TOOL_ERROR"}:
            runner_report_seen = False
            runner_report_section_seen = False
            runner_tail_armed = False
            runner_fence = None
        match = ENV_LOG_RE.search(payload)
        if match is None:
            continue
        if actor in {"runner:stderr", "runner:stdout"} or any(
            marker in payload for marker in RUNNER_OUTPUT_MARKERS
        ) or runner_fence is not None:
            return line_no, match.group(0)
        if kind == "TOOL_ERROR":
            return line_no, match.group(0)
        if kind == "TOOL_RESULT" and not _is_execution_command(command):
            continue
        return line_no, match.group(0)
    return None


def _environment_stderr_evidence(
    job: Job, started: datetime | None, end: datetime | None
) -> str | None:
    if started is None or end is None:
        return None
    for stderr_path in sorted(job.directory.glob("*.stderr")):
        mtime = datetime.fromtimestamp(stderr_path.stat().st_mtime, tz=timezone.utc)
        if started <= mtime <= end and ENV_STDERR_RE.search(
            stderr_path.read_text(errors="replace")
        ):
            return stderr_path.name
    return None


def _flag_harvest_evidence(
    job: Job, started: datetime | None, end: datetime | None
) -> tuple[int, str] | None:
    """Return a trusted, windowed artifact confirming that flag harvest failed."""
    for line_no, actor, kind, payload in _timestamped_log_lines(job, started, end):
        if (
            actor == "orchestrator"
            and kind.startswith("WARNING turn ")
            and HARVEST_FAILURE_WARNING_RE.match(payload)
        ):
            return line_no, "orchestrator reported zero harvested flags"
    return None


def classify(job: Job, outcome: Outcome | None = None) -> Classification:
    outcome = outcome or automatic_outcome(job)
    events, started, end = event_window(job)
    meta = job.meta
    error = meta.get("error")
    kind_state = error_kind_state(meta)
    error_kind = meta.get("error_kind")
    stop = str(meta.get("judge_stop_reason") or "")

    def found(class_name: str, rung: str, evidence: str) -> Classification:
        if class_name not in RUNG_CLASS_MAP[rung]:
            raise AssertionError(f"undeclared rung mapping: {rung} -> {class_name}")
        return Classification(job.job_id, class_name, rung, evidence, kind_state)

    if job.malformed_event_lines:
        lines = ",".join(str(line_no) for line_no in job.malformed_event_lines)
        return found("UNRESOLVED", "P6d", f"malformed events.jsonl lines: {lines}")

    if outcome.status in NONTERMINAL_STATUSES:
        return found(
            "EXCLUDED_operator_stop",
            "P0",
            f"nonterminal-status={outcome.status}",
        )

    if outcome.status == "stopped" and not stop and (
        error is None or error_kind == "stopped_for_resume"
    ):
        reason = (
            "error_kind=stopped_for_resume"
            if error_kind == "stopped_for_resume"
            else "operator-stop-without-error"
        )
        return found("EXCLUDED_operator_stop", "P0", reason)

    p1_classification: tuple[str, str, str] | None = None
    if error:
        error_text = str(error)
        if "Separator is not found" in error_text:
            p1_classification = (
                "HARN_stream_overflow",
                "P1",
                "meta.error separator signature",
            )
        elif "SDK ResultMessage is_error" in error_text:
            p1_classification = (
                "HARN_sdk_transport",
                "P1",
                "meta.error SDK signature",
            )

    # A global meta scalar has no attempt provenance. Preserve P1 over other
    # global scalars, but defer it until every classifiable per-attempt artifact
    # has had a chance to speak.
    if p1_classification is None and error_kind == "policy_refusal":
        return found("POL_aup_refusal", "P2", "error_kind=policy_refusal")

    target, exit_event, postjudge = _final_attempt(events)
    has_run_attempt = any(
        event.get("phase") == "run" and event.get("kind") == "start"
        for event in events
    )
    if not has_run_attempt and any(
        event.get("phase") == "prejudge" and event.get("kind") == "blocked"
        for event in events
    ):
        return found("POL_prejudge_blocked", "P2", "windowed prejudge blocked")

    if any(
        event.get("phase") == "run"
        and event.get("kind") == "exit"
        and event.get("timeout") is True
        for event in events
    ):
        return found("RES_timeout", "P3", "windowed timeout")
    if p1_classification is None and error_kind == "timeout":
        return found("RES_timeout", "P3", "error_kind=timeout")

    if postjudge and postjudge.get("verdict") == "network_error":
        return found(
            "ENV_target_unusable", "P4", f"postjudge events.jsonl:{postjudge['_line']}"
        )
    harvest_evidence = _flag_harvest_evidence(job, started, end)
    if (
        postjudge
        and postjudge.get("verdict") == "success"
        and outcome.success is False
        and harvest_evidence is not None
    ):
        harvest_line, harvest_detail = harvest_evidence
        return found(
            "HARN_flag_harvest",
            "P4",
            f"postjudge success events.jsonl:{postjudge['_line']}; "
            f"run.log:{harvest_line}: {harvest_detail}",
        )

    scalar_target = _stop_target(stop)
    if scalar_target and target and scalar_target == target:
        if "ECONNREFUSED" in stop and "is down" in stop:
            return found("ENV_target_unusable", "P5", f"matching target {target}")
        if "0/10000 hits" in stop and "premise is false" in stop:
            return found("CAP_solver_exhausted", "P5", f"matching target {target}")

    log_evidence = _environment_log_evidence(job, started, end)
    if log_evidence is not None:
        line_no, matched = log_evidence
        return found("ENV_target_unusable", "P6a", f"run.log:{line_no}: {matched}")

    stderr_evidence = _environment_stderr_evidence(job, started, end)
    if stderr_evidence is not None:
        return found("ENV_target_unusable", "P6b", stderr_evidence)

    if p1_classification is not None:
        return found(*p1_classification)

    if "0/10000 hits" in stop and "premise is false" in stop:
        return found("CAP_solver_exhausted", "P6d", "unbound stop narrative")

    if exit_event is None:
        return found("HARN_no_events", "P6c", "no final run exit event")
    if exit_event.get("exit_code") == 0:
        return found("CAP_ran_no_flag", "P6c", "exit_code=0 without flag")
    return found(
        "CAP_solver_exhausted", "P6c", f"exit_code={exit_event.get('exit_code')}"
    )


def _root_of(job_id: str, jobs: dict[str, Job]) -> str:
    seen: set[str] = set()
    current = job_id
    while jobs[current].meta.get("retry_of"):
        if current in seen:
            raise AggregationError(f"retry cycle at {current}")
        seen.add(current)
        parent = str(jobs[current].meta["retry_of"])
        if parent not in jobs:
            raise AggregationError(f"missing retry parent {parent} for {current}")
        current = parent
    return current


def _lineages(
    failures: list[str],
    classifications: dict[str, Classification],
    jobs: dict[str, Job],
) -> tuple[Lineage, ...]:
    groups: dict[str, list[str]] = defaultdict(list)
    for job_id in failures:
        groups[_root_of(job_id, jobs)].append(job_id)

    rows: list[Lineage] = []
    for root, members in sorted(groups.items()):
        failure_parents = {str(jobs[job_id].meta.get("retry_of") or "") for job_id in members}
        final_failures = [job_id for job_id in members if job_id not in failure_parents]
        if len(final_failures) != 1:
            raise AggregationError(f"ambiguous final failure for {root}: {final_failures}")
        final_failure = final_failures[0]
        cost = sum(
            (
                Decimal(
                    str(
                        jobs[job_id].meta.get("cost_usd")
                        or jobs[job_id].meta.get("cost_usd_estimate")
                        or 0
                    )
                )
                for job_id in members
            ),
            Decimal("0"),
        )
        rows.append(
            Lineage(root, final_failure, classifications[final_failure].class_name, cost)
        )
    return tuple(rows)


def _retry_anomalies(included: dict[str, Job], jobs: dict[str, Job]) -> tuple[str, ...]:
    """Expose broken retry chains even when the affected job succeeded."""
    anomalies: list[str] = []
    for job_id in sorted(included):
        try:
            _root_of(job_id, jobs)
        except AggregationError as error:
            anomalies.append(f"{job_id}: {error}")
    return tuple(anomalies)


def aggregate(jobs_dir: Path) -> AggregateResult:
    jobs = load_snapshot(jobs_dir)
    missing_meta_with_events = sum(
        1
        for events_path in jobs_dir.glob("*/events.jsonl")
        if not (events_path.parent / "meta.json").is_file()
    )
    population_exclusions = tuple(
        PopulationExclusion(job_id, reasons)
        for job_id, job in sorted(jobs.items())
        if (reasons := population_exclusion_reasons(job))
    )
    included = {job_id: job for job_id, job in jobs.items() if is_included(job)}
    retry_anomalies = _retry_anomalies(included, jobs)
    outcomes = {job_id: automatic_outcome(job) for job_id, job in included.items()}
    unsafe = [job_id for job_id, outcome in outcomes.items() if outcome.success is None]
    if unsafe:
        raise AggregationError(
            "legacy meta is manual-run contaminated: " + ", ".join(sorted(unsafe))
        )

    successes = [job_id for job_id, outcome in outcomes.items() if outcome.success]
    nonsuccesses = [job_id for job_id, outcome in outcomes.items() if not outcome.success]
    classifications = {
        job_id: classify(included[job_id], outcomes[job_id]) for job_id in nonsuccesses
    }
    excluded = [
        job_id
        for job_id in nonsuccesses
        if classifications[job_id].class_name == "EXCLUDED_operator_stop"
    ]
    failures = [job_id for job_id in nonsuccesses if job_id not in excluded]
    unresolved = [
        job_id
        for job_id in failures
        if classifications[job_id].class_name in {"UNRESOLVED", "HARN_no_events"}
    ]
    if unresolved:
        raise AggregationError("unresolved failure classification: " + ", ".join(unresolved))

    lineage_rows = _lineages(failures, classifications, jobs)
    attempt_counts = Counter(classifications[job_id].class_name for job_id in failures)
    lineage_counts = Counter(row.class_name for row in lineage_rows)
    lineage_costs: dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
    for row in lineage_rows:
        lineage_costs[row.class_name] += row.cost
    rung_counts = Counter(classifications[job_id].rung for job_id in nonsuccesses)
    source_counts = Counter(outcome.source for outcome in outcomes.values())
    source_successes = Counter(
        outcome.source for outcome in outcomes.values() if outcome.success is True
    )
    success_tier_counts = Counter({tier: 0 for tier in SUCCESS_TIER_ORDER})
    success_tier_counts.update(success_tier(included[job_id]) for job_id in successes)
    capability = sum(1 for row in lineage_rows if row.class_name.startswith("CAP_"))
    noncapability = len(lineage_rows) - capability
    percent = round(100 * noncapability / len(lineage_rows)) if lineage_rows else 0

    return AggregateResult(
        included=len(included),
        successes=len(successes),
        nonsuccesses=len(nonsuccesses),
        excluded=len(excluded),
        failures=len(failures),
        lineages=len(lineage_rows),
        capability_lineages=capability,
        noncapability_lineages=noncapability,
        noncapability_percent=percent,
        skipped_counts={"missing-meta-with-events": missing_meta_with_events},
        source_counts=dict(sorted(source_counts.items())),
        source_successes=dict(sorted(source_successes.items())),
        success_tier_counts={
            tier: success_tier_counts[tier] for tier in SUCCESS_TIER_ORDER
        },
        attempt_counts=dict(sorted(attempt_counts.items())),
        lineage_counts=dict(sorted(lineage_counts.items())),
        lineage_costs=dict(sorted(lineage_costs.items())),
        rung_counts=dict(sorted(rung_counts.items())),
        classifications=tuple(classifications[job_id] for job_id in sorted(classifications)),
        lineage_rows=lineage_rows,
        population_exclusions=population_exclusions,
        retry_anomalies=retry_anomalies,
    )


def format_report(result: AggregateResult) -> str:
    terminal_total = result.source_counts.get("terminal", 0)
    terminal_success = result.source_successes.get("terminal", 0)
    legacy_total = result.source_counts.get("legacy-meta", 0)
    legacy_success = result.source_successes.get("legacy-meta", 0)
    success_tiers = [
        f"marker {result.success_tier_counts.get(SUCCESS_TIER_MARKER, 0)}",
        (
            "신뢰되지 않은 등급 "
            f"{result.success_tier_counts.get(SUCCESS_TIER_UNTRUSTED, 0)}"
        ),
    ]
    missing_provenance = result.success_tier_counts.get(SUCCESS_TIER_MISSING, 0)
    if missing_provenance:
        success_tiers.append(f"provenance 없음 {missing_provenance}")
    success_tier_summary = " · ".join(success_tiers)
    lines = [
        (
            f"자동 성공                {result.successes} / {result.included}        "
            f"({success_tier_summary}; terminal 판정 {terminal_total} 중 {terminal_success} + "
            f"legacy {legacy_total} 중 {legacy_success})"
        ),
        f"실패 모집단              {result.failures} attempt / {result.lineages} lineage",
        f"operator 중단 제외        {result.excluded} attempt",
        (
            f"모듈 역량 {result.capability_lineages} lineage · "
            f"비역량 {result.noncapability_lineages} lineage = "
            f"{result.noncapability_percent}%"
        ),
    ]
    missing_meta = result.skipped_counts.get("missing-meta-with-events", 0)
    if missing_meta:
        lines.append(
            f"입력 제외                 {missing_meta} directory "
            "(events.jsonl 있으나 meta.json 없음)"
        )
    if result.population_exclusions:
        lines.extend(["", f"모집단 경계 제외          {len(result.population_exclusions)} job"])
        lines.extend(
            f"  {row.job_id}  {', '.join(row.reasons)}"
            for row in result.population_exclusions
        )
    if result.retry_anomalies:
        lines.extend(["", f"retry 사슬 경고           {len(result.retry_anomalies)} job"])
        lines.extend(f"  {anomaly}" for anomaly in result.retry_anomalies)
    lines.extend(["", "클래스                    attempt  lineage   lineage 합산 $"])
    for class_name in REPORT_CLASS_ORDER:
        lines.append(
            f"{class_name:<27}{result.attempt_counts.get(class_name, 0):>3}"
            f"{result.lineage_counts.get(class_name, 0):>9}"
            f"{result.lineage_costs.get(class_name, Decimal('0')):>16.2f}"
        )
    stream_count = result.attempt_counts.get("HARN_stream_overflow", 0)
    sdk_count = result.attempt_counts.get("HARN_sdk_transport", 0)
    lines.extend(
        [
            "",
            (
                f"rung 별 판정 건수에서 P1 = {result.rung_counts.get('P1', 0)} "
                f"(stream {stream_count} + sdk {sdk_count})"
            ),
        ]
    )
    return "\n".join(lines)


def _json_default(value: object) -> object:
    if isinstance(value, Decimal):
        return f"{value:.2f}"
    raise TypeError(type(value).__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs-dir", type=Path, default=DEFAULT_JOBS_DIR)
    parser.add_argument("--json", action="store_true", help="emit full machine-readable detail")
    args = parser.parse_args(argv)
    result = aggregate(args.jobs_dir)
    if args.json:
        print(json.dumps(asdict(result), ensure_ascii=False, indent=2, default=_json_default))
    else:
        print(format_report(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
