#!/usr/bin/env python3
"""Regression and mutation suite for scripts/aggregate_hardening.py."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import fields, is_dataclass, replace
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PRODUCTION = ROOT / "scripts" / "aggregate_hardening.py"
JOBS = ROOT / "data" / "jobs"

EXPECTED_REPORT = """자동 성공                17 / 43        (marker 16 · 신뢰되지 않은 등급 1; terminal 판정 29 중 13 + legacy 14 중 4)
실패 모집단              22 attempt / 15 lineage
operator 중단 제외        4 attempt
모듈 역량 3 lineage · 비역량 12 lineage = 80%

모집단 경계 제외          21 job
  06bbe4399118  internal, parent_job_id=b163a93777ef
  0a730c17201d  internal, parent_job_id=4f8bc78a1290
  0da77e714895  module='crypto'
  26fd834c933c  module='web'
  375b7f150de2  module='hybrid'
  3b6bb6cf84e5  internal, parent_job_id=375b7f150de2
  47de39fd0c01  module='crypto'
  4f8bc78a1290  module='hybrid'
  5c3974d26ab4  module='crypto'
  5e0de4572503  module='web3'
  606175dde9d6  module='crypto'
  6f55fb7bedf8  internal, parent_job_id=b163a93777ef
  7db677b584b4  module='web'
  94d105ace230  module='crypto'
  9f9dad521117  system-validation-live-test
  a34b10c5e8e9  module='web'
  b163a93777ef  module='hybrid'
  bbb9d01f87c1  module='web'
  ca5234be1c27  module='forensic'
  cdcf04783148  module='misc'
  f4da417514f7  module='web'

retry 사슬 경고           1 job
  203e786eeda4: missing retry parent 9b8168b0ee29 for 203e786eeda4

클래스                    attempt  lineage   lineage 합산 $
CAP_solver_exhausted         4        2           20.01
ENV_target_unusable          9        6          247.28
POL_prejudge_blocked         2        1          117.92
HARN_flag_harvest            1        1           97.19
HARN_sdk_transport           2        1           20.31
HARN_stream_overflow         2        2            0.00
POL_aup_refusal              1        1           10.24
CAP_ran_no_flag              1        1           32.59

rung 별 판정 건수에서 P1 = 4 (stream 2 + sdk 2)"""

_NO_NUMERIC_VALUE = object()


def numeric_structure(value):
    """Recursively retain every numeric leaf without naming result fields."""
    if isinstance(value, bool):
        return _NO_NUMERIC_VALUE
    if isinstance(value, (int, float, Decimal)):
        return value
    if is_dataclass(value) and not isinstance(value, type):
        items = {}
        for field in fields(value):
            numeric = numeric_structure(getattr(value, field.name))
            if numeric is not _NO_NUMERIC_VALUE:
                items[field.name] = numeric
        return items if items else _NO_NUMERIC_VALUE
    if isinstance(value, dict):
        items = {}
        for key in sorted(value, key=str):
            numeric = numeric_structure(value[key])
            if numeric is not _NO_NUMERIC_VALUE:
                items[key] = numeric
        return items if items else _NO_NUMERIC_VALUE
    if isinstance(value, (tuple, list)):
        items = {}
        for index, item in enumerate(value):
            numeric = numeric_structure(item)
            if numeric is not _NO_NUMERIC_VALUE:
                items[index] = numeric
        return items if items else _NO_NUMERIC_VALUE
    return _NO_NUMERIC_VALUE


def numeric_paths(value, path=()):
    """Yield typed paths to every numeric leaf in a returned aggregate object."""
    if isinstance(value, bool):
        return
    if isinstance(value, (int, float, Decimal)):
        yield path
        return
    if is_dataclass(value) and not isinstance(value, type):
        for field in fields(value):
            yield from numeric_paths(
                getattr(value, field.name), path + (("field", field.name),)
            )
    elif isinstance(value, dict):
        for key in sorted(value, key=str):
            yield from numeric_paths(value[key], path + (("key", key),))
    elif isinstance(value, (tuple, list)):
        for index, item in enumerate(value):
            yield from numeric_paths(item, path + (("index", index),))


def mutate_numeric_path(value, target, path=()):
    """Rebuild a frozen aggregate result with exactly one numeric leaf changed."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float, Decimal)):
        return value + 1 if path == target else value
    if is_dataclass(value) and not isinstance(value, type):
        changes = {
            field.name: mutate_numeric_path(
                getattr(value, field.name), target, path + (("field", field.name),)
            )
            for field in fields(value)
        }
        return replace(value, **changes)
    if isinstance(value, dict):
        return {
            key: mutate_numeric_path(item, target, path + (("key", key),))
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return tuple(
            mutate_numeric_path(item, target, path + (("index", index),))
            for index, item in enumerate(value)
        )
    if isinstance(value, list):
        return [
            mutate_numeric_path(item, target, path + (("index", index),))
            for index, item in enumerate(value)
        ]
    return value


EXPECTED_NUMERIC_STRUCTURE = {
    "included": 43,
    "successes": 17,
    "nonsuccesses": 26,
    "excluded": 4,
    "failures": 22,
    "lineages": 15,
    "capability_lineages": 3,
    "noncapability_lineages": 12,
    "noncapability_percent": 80,
    "skipped_counts": {"missing-meta-with-events": 0},
    "source_counts": {"legacy-meta": 14, "terminal": 29},
    "source_successes": {"legacy-meta": 4, "terminal": 13},
    "success_tier_counts": {
        "marker": 16,
        "missing-provenance": 0,
        "untrusted-tier": 1,
    },
    "attempt_counts": {
        "CAP_ran_no_flag": 1,
        "CAP_solver_exhausted": 4,
        "ENV_target_unusable": 9,
        "HARN_flag_harvest": 1,
        "HARN_sdk_transport": 2,
        "HARN_stream_overflow": 2,
        "POL_aup_refusal": 1,
        "POL_prejudge_blocked": 2,
    },
    "lineage_counts": {
        "CAP_ran_no_flag": 1,
        "CAP_solver_exhausted": 2,
        "ENV_target_unusable": 6,
        "HARN_flag_harvest": 1,
        "HARN_sdk_transport": 1,
        "HARN_stream_overflow": 2,
        "POL_aup_refusal": 1,
        "POL_prejudge_blocked": 1,
    },
    "lineage_costs": {
        "CAP_ran_no_flag": Decimal("32.5856"),
        "CAP_solver_exhausted": Decimal("20.0117"),
        "ENV_target_unusable": Decimal("247.275755"),
        "HARN_flag_harvest": Decimal("97.1931"),
        "HARN_sdk_transport": Decimal("20.3129"),
        "HARN_stream_overflow": Decimal("0"),
        "POL_aup_refusal": Decimal("10.235610000000001"),
        "POL_prejudge_blocked": Decimal("117.9214"),
    },
    "rung_counts": {
        "P0": 4,
        "P1": 4,
        "P2": 3,
        "P4": 3,
        "P6a": 6,
        "P6b": 1,
        "P6c": 4,
        "P6d": 1,
    },
    "lineage_rows": {
        0: {"cost": Decimal("2.5252")},
        1: {"cost": Decimal("10.235610000000001")},
        2: {"cost": Decimal("93.7565")},
        3: {"cost": Decimal("0")},
        4: {"cost": Decimal("6.0927")},
        5: {"cost": Decimal("18.3608")},
        6: {"cost": Decimal("22.307955")},
        7: {"cost": Decimal("104.2326")},
        8: {"cost": Decimal("117.9214")},
        9: {"cost": Decimal("2.5509")},
        10: {"cost": Decimal("97.1931")},
        11: {"cost": Decimal("0")},
        12: {"cost": Decimal("32.5856")},
        13: {"cost": Decimal("17.4608")},
        14: {"cost": Decimal("20.3129")},
    },
}

EXPECTED_POPULATION_EXCLUSIONS = {
    "06bbe4399118": ("internal", "parent_job_id=b163a93777ef"),
    "0a730c17201d": ("internal", "parent_job_id=4f8bc78a1290"),
    "0da77e714895": ("module='crypto'",),
    "26fd834c933c": ("module='web'",),
    "375b7f150de2": ("module='hybrid'",),
    "3b6bb6cf84e5": ("internal", "parent_job_id=375b7f150de2"),
    "47de39fd0c01": ("module='crypto'",),
    "4f8bc78a1290": ("module='hybrid'",),
    "5c3974d26ab4": ("module='crypto'",),
    "5e0de4572503": ("module='web3'",),
    "606175dde9d6": ("module='crypto'",),
    "6f55fb7bedf8": ("internal", "parent_job_id=b163a93777ef"),
    "7db677b584b4": ("module='web'",),
    "94d105ace230": ("module='crypto'",),
    "9f9dad521117": ("system-validation-live-test",),
    "a34b10c5e8e9": ("module='web'",),
    "b163a93777ef": ("module='hybrid'",),
    "bbb9d01f87c1": ("module='web'",),
    "ca5234be1c27": ("module='forensic'",),
    "cdcf04783148": ("module='misc'",),
    "f4da417514f7": ("module='web'",),
}

EXPECTED_RETRY_ANOMALIES = (
    "203e786eeda4: missing retry parent 9b8168b0ee29 for 203e786eeda4",
)


def load_aggregator():
    path = Path(os.environ.get("HARDENING_AGGREGATOR_PATH", PRODUCTION))
    spec = importlib.util.spec_from_file_location("_hardening_aggregator_under_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


A = load_aggregator()


def event(ts: str, phase: str, kind: str, **extra: object) -> dict[str, object]:
    return {"ts": f"2026-01-01T{ts}+00:00", "phase": phase, "kind": kind, **extra}


class Fixture:
    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="hardening-aggregator-")
        self.jobs_dir = Path(self._tmp.name)

    def close(self) -> None:
        self._tmp.cleanup()

    def job(
        self,
        job_id: str,
        events: list[dict[str, object]],
        *,
        meta: dict[str, object] | None = None,
        run_log: str = "",
        stderr: str | None = None,
        stderr_time: str = "00:01:30",
        raw_events_suffix: str = "",
    ):
        directory = self.jobs_dir / job_id
        directory.mkdir()
        values: dict[str, object] = {
            "id": job_id,
            "module": "pwn",
            "status": "no_flag",
            "flags": [],
            "started_at": "2026-01-01T00:00:00+00:00",
            "finished_at": "2026-01-01T00:01:00+00:00",
            "error": None,
            "error_kind": None,
            "judge_stop_reason": None,
            "cost_usd_estimate": 1.0,
        }
        values.update(meta or {})
        (directory / "meta.json").write_text(json.dumps(values), encoding="utf-8")
        if events or raw_events_suffix:
            (directory / "events.jsonl").write_text(
                "".join(json.dumps(item) + "\n" for item in events) + raw_events_suffix,
                encoding="utf-8",
            )
        if run_log:
            (directory / "run.log").write_text(run_log, encoding="utf-8")
        if stderr is not None:
            stderr_path = directory / "exploit.py.stderr"
            stderr_path.write_text(stderr, encoding="utf-8")
            stamp = datetime.fromisoformat(f"2026-01-01T{stderr_time}+00:00").timestamp()
            os.utime(stderr_path, (stamp, stamp))
        return A.load_snapshot(self.jobs_dir)[job_id]


class FixtureTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()

    def tearDown(self) -> None:
        self.fixture.close()


class AcceptanceTests(FixtureTestCase):
    def test_D4_only_allowlisted_execution_sources_are_environment_evidence(self) -> None:
        terminal_events = [
            event("00:00:20", "run", "start", target="live.example:1"),
            event("00:00:30", "run", "exit", exit_code=1, timeout=False),
            event("00:01:00", "terminal", "status", status="no_flag", flags=0),
        ]

        for index, command in enumerate(
            ("grep -r ECONNREFUSED ./notes.txt", "cat notes.txt", "sed -n '1,20p' notes.txt")
        ):
            with self.subTest(rejected_command=command):
                block = json.dumps({"command": command})
                job = self.fixture.job(
                    f"d4read{index}",
                    terminal_events,
                    run_log=(
                        f"[00:00:10] [main] TOOL Bash: {block}\n"
                        "[00:00:11] [main] TOOL_RESULT: connect failed: ECONNREFUSED\n"
                    ),
                )
                result = A.classify(job)
                self.assertEqual(
                    (result.class_name, result.rung), ("CAP_solver_exhausted", "P6c")
                )

        accepted_logs = {
            "tool_error": (
                "[00:00:10] [main] TOOL Bash: "
                + json.dumps({"command": "grep -r ECONNREFUSED ./notes.txt"})
                + "\n[00:00:11] [main] TOOL_ERROR: connect failed: ECONNREFUSED\n"
            ),
            "runner_stderr": "[00:00:11] [runner:stderr] connect failed: ECONNREFUSED\n",
            "execution_result": (
                "[00:00:10] [main] TOOL Bash: "
                + json.dumps({"command": "python3 exploit.py live.example:1"})
                + "\n[00:00:11] [main] TOOL_RESULT: connect failed: ECONNREFUSED\n"
            ),
        }
        for source, run_log in accepted_logs.items():
            with self.subTest(accepted_source=source):
                job = self.fixture.job(f"d4{source}", terminal_events, run_log=run_log)
                result = A.classify(job)
                self.assertEqual(
                    (result.class_name, result.rung), ("ENV_target_unusable", "P6a")
                )

    def test_current_runner_preflight_unreachable_is_environment_evidence(self) -> None:
        terminal_events = [
            event("00:00:20", "run", "start", target="dead.example:31337"),
            event("00:00:30", "run", "exit", exit_code=1, timeout=False),
            event("00:01:00", "terminal", "status", status="no_flag", flags=0),
        ]
        reasons = (
            "DNS: [Errno -2] Name or service not known",
            "ConnectionRefusedError: [Errno 111] Connection refused",
        )
        for index, reason in enumerate(reasons):
            with self.subTest(reason=reason):
                job = self.fixture.job(
                    f"runnerpreflight{index}",
                    terminal_events,
                    run_log=(
                        "[00:00:25] [runner] target dead.example:31337 "
                        f"unreachable before run ({reason}); reloading meta.json\n"
                    ),
                )
                result = A.classify(job)
                self.assertEqual(
                    (result.class_name, result.rung, result.evidence),
                    ("ENV_target_unusable", "P6a", "run.log:1: runner target unreachable"),
                )

    def test_D2_confirmed_flag_harvest_failure_supersedes_earlier_block(self) -> None:
        job = self.fixture.job(
            "harvestmismatch",
            [
                event("00:00:10", "prejudge", "blocked", severity="high"),
                event("00:00:20", "run", "start", target="live.example:1"),
                event("00:00:30", "run", "exit", exit_code=1, timeout=False),
                event(
                    "00:00:40",
                    "postjudge",
                    "verdict",
                    verdict="success",
                    next_action="stop",
                ),
                event("00:01:00", "terminal", "status", status="no_flag", flags=0),
            ],
            run_log=(
                "[00:00:41] [orchestrator] WARNING turn 2: "
                "judge verdict=success but 0 flags harvested — check solver stdout\n"
            ),
        )
        result = A.classify(job)
        self.assertEqual(
            (result.class_name, result.rung, result.evidence),
            (
                "HARN_flag_harvest",
                "P4",
                "postjudge success events.jsonl:4; run.log:1: "
                "orchestrator reported zero harvested flags",
            ),
        )

    def test_D2_postjudge_success_without_artifact_confirmation_falls_through(self) -> None:
        job = self.fixture.job(
            "unconfirmedharvest",
            [
                event("00:00:20", "run", "start", target="live.example:1"),
                event("00:00:30", "run", "exit", exit_code=1, timeout=False),
                event(
                    "00:00:40",
                    "postjudge",
                    "verdict",
                    verdict="success",
                    next_action="stop",
                ),
                event("00:01:00", "terminal", "status", status="no_flag", flags=0),
            ],
        )
        result = A.classify(job)
        self.assertEqual(
            (result.class_name, result.rung), ("CAP_solver_exhausted", "P6c")
        )

    def test_D1_global_scalar_yields_only_to_classifiable_attempt_evidence(self) -> None:
        terminal = event("00:01:00", "terminal", "status", status="no_flag", flags=0)
        error = "SDK ResultMessage is_error (transport failure); no artifact"
        cases = (
            (
                "postjudge",
                [
                    event("00:00:20", "run", "start", target="dead.example:1"),
                    event("00:00:30", "run", "exit", exit_code=1, timeout=False),
                    event(
                        "00:00:40",
                        "postjudge",
                        "verdict",
                        verdict="network_error",
                    ),
                    terminal,
                ],
                "",
                ("ENV_target_unusable", "P4"),
            ),
            (
                "runlog",
                [
                    event("00:00:20", "run", "start", target="dead.example:1"),
                    event("00:00:30", "run", "exit", exit_code=1, timeout=False),
                    terminal,
                ],
                "[00:00:25] [runner:stderr] connect failed: ECONNREFUSED\n",
                ("ENV_target_unusable", "P6a"),
            ),
            (
                "partial",
                [
                    event("00:00:20", "run", "start", target="live.example:1"),
                    event("00:00:30", "run", "exit", exit_code=1, timeout=False),
                    event(
                        "00:00:40", "postjudge", "verdict", verdict="partial"
                    ),
                    terminal,
                ],
                "",
                ("HARN_sdk_transport", "P1"),
            ),
        )
        for label, events, run_log, expected in cases:
            with self.subTest(label=label):
                job = self.fixture.job(
                    f"d1scalar{label}",
                    events,
                    meta={"error": error, "error_kind": "timeout"},
                    run_log=run_log,
                )
                result = A.classify(job)
                self.assertEqual((result.class_name, result.rung), expected)

    def test_prejudge_block_without_a_run_remains_policy(self) -> None:
        job = self.fixture.job(
            "blockedwithoutattempt",
            [
                event("00:00:10", "prejudge", "blocked", severity="high"),
                event("00:01:00", "terminal", "status", status="no_flag", flags=0),
            ],
        )
        result = A.classify(job)
        self.assertEqual((result.class_name, result.rung), ("POL_prejudge_blocked", "P2"))

    def test_D8_relayed_runner_report_block_is_execution_evidence(self) -> None:
        job = self.fixture.job(
            "d8report",
            [
                event("00:00:20", "run", "start", target="live.example:1"),
                event("00:00:30", "run", "exit", exit_code=1, timeout=False),
                event("00:01:00", "terminal", "status", status="no_flag", flags=0),
            ],
            run_log=(
                "[00:00:10] [main] TOOL Bash: "
                + json.dumps({"command": "sed -n '1,220p' WHY_STOPPED.md"})
                + "\n[00:00:11] [main] TOOL_RESULT: # Why this run stopped\n"
                "[00:00:11] [main] TOOL_RESULT: ## Last sandbox run\n"
                "[00:00:11] [main] TOOL_RESULT: **stderr tail** (last 1500 B):\n"
                "[00:00:11] [main] TOOL_RESULT: ```\n"
                "[00:00:11] [main] TOOL_RESULT: connect failed: ECONNREFUSED\n"
                "[00:00:11] [main] TOOL_RESULT: ```\n"
                "[00:00:11] [main] TOOL_RESULT: ## Recommended next steps\n"
            ),
        )
        result = A.classify(job)
        self.assertEqual((result.class_name, result.rung), ("ENV_target_unusable", "P6a"))
        self.assertEqual(result.evidence, "run.log:6: ECONNREFUSED")

    def test_F1_truncated_runner_report_does_not_admit_following_data(self) -> None:
        job = self.fixture.job(
            "f1cut",
            [
                event("00:00:20", "run", "start", target="live.example:1"),
                event("00:00:30", "run", "exit", exit_code=1, timeout=False),
                event("00:01:00", "terminal", "status", status="no_flag", flags=0),
            ],
            run_log=(
                "[00:00:10] [main] TOOL Bash: "
                + json.dumps(
                    {"command": "sed -n '1,35p' WHY_STOPPED.md; cat notes.txt"}
                )
                + "\n[00:00:11] [main] TOOL_RESULT: # Why this run stopped\n"
                "[00:00:11] [main] TOOL_RESULT: ## Last sandbox run\n"
                "[00:00:11] [main] TOOL_RESULT: **stderr tail** (last 1500 B):\n"
                "[00:00:11] [main] TOOL_RESULT: unrelated data follows the truncation\n"
                "[00:00:11] [main] TOOL_RESULT: connect failed: ECONNREFUSED\n"
            ),
        )
        result = A.classify(job)
        self.assertEqual((result.class_name, result.rung), ("CAP_solver_exhausted", "P6c"))

    def test_F1_heading_inside_fenced_runner_output_does_not_end_evidence(self) -> None:
        job = self.fixture.job(
            "f1heading",
            [
                event("00:00:20", "run", "start", target="live.example:1"),
                event("00:00:30", "run", "exit", exit_code=1, timeout=False),
                event("00:01:00", "terminal", "status", status="no_flag", flags=0),
            ],
            run_log=(
                "[00:00:10] [main] TOOL Bash: "
                + json.dumps({"command": "cat WHY_STOPPED.md"})
                + "\n[00:00:11] [main] TOOL_RESULT: # Why this run stopped\n"
                "[00:00:11] [main] TOOL_RESULT: ## Last sandbox run\n"
                "[00:00:11] [main] TOOL_RESULT: **stderr tail** (last 1500 B):\n"
                "[00:00:11] [main] TOOL_RESULT: ```text\n"
                "[00:00:11] [main] TOOL_RESULT: ## challenge-emitted heading\n"
                "[00:00:11] [main] TOOL_RESULT: connect failed: ECONNREFUSED\n"
                "[00:00:11] [main] TOOL_RESULT: ```\n"
            ),
        )
        result = A.classify(job)
        self.assertEqual((result.class_name, result.rung), ("ENV_target_unusable", "P6a"))

    def test_D8_data_read_marker_text_does_not_open_runner_report_block(self) -> None:
        terminal_events = [
            event("00:00:20", "run", "start", target="live.example:1"),
            event("00:00:30", "run", "exit", exit_code=1, timeout=False),
            event("00:01:00", "terminal", "status", status="no_flag", flags=0),
        ]
        for index, command in enumerate(
            (
                "strings WHY_STOPPED.md",
                "grep -A10 'Last sandbox run' WHY_STOPPED.md",
            )
        ):
            with self.subTest(rejected_command=command):
                job = self.fixture.job(
                    f"d8read{index}",
                    terminal_events,
                    run_log=(
                        "[00:00:10] [main] TOOL Bash: "
                        + json.dumps({"command": command})
                        + "\n[00:00:11] [main] TOOL_RESULT: # Why this run stopped\n"
                        "[00:00:11] [main] TOOL_RESULT: ## Last sandbox run\n"
                        "[00:00:11] [main] TOOL_RESULT: **stderr tail** (last 1500 B):\n"
                        "[00:00:11] [main] TOOL_RESULT: ```\n"
                        "[00:00:11] [main] TOOL_RESULT: connect failed: ECONNREFUSED\n"
                        "[00:00:11] [main] TOOL_RESULT: ```\n"
                    ),
                )
                result = A.classify(job)
                self.assertEqual(
                    (result.class_name, result.rung), ("CAP_solver_exhausted", "P6c")
                )

    def test_D8_runner_report_block_ends_at_the_next_section(self) -> None:
        job = self.fixture.job(
            "d8section",
            [
                event("00:00:20", "run", "start", target="live.example:1"),
                event("00:00:30", "run", "exit", exit_code=1, timeout=False),
                event("00:01:00", "terminal", "status", status="no_flag", flags=0),
            ],
            run_log=(
                "[00:00:10] [main] TOOL Bash: "
                + json.dumps({"command": "cat WHY_STOPPED.md"})
                + "\n[00:00:11] [main] TOOL_RESULT: # Why this run stopped\n"
                "[00:00:11] [main] TOOL_RESULT: ## Last sandbox run\n"
                "[00:00:11] [main] TOOL_RESULT: **stderr tail** (last 1500 B):\n"
                "[00:00:11] [main] TOOL_RESULT: ```\n"
                "[00:00:11] [main] TOOL_RESULT: no environment failure here\n"
                "[00:00:11] [main] TOOL_RESULT: ```\n"
                "[00:00:11] [main] TOOL_RESULT: ## Recommended next steps\n"
                "[00:00:11] [main] TOOL_RESULT: **stderr tail** (untrusted text):\n"
                "[00:00:11] [main] TOOL_RESULT: ```\n"
                "[00:00:11] [main] TOOL_RESULT: connect failed: ECONNREFUSED\n"
                "[00:00:11] [main] TOOL_RESULT: ```\n"
            ),
        )
        result = A.classify(job)
        self.assertEqual((result.class_name, result.rung), ("CAP_solver_exhausted", "P6c"))

    def test_F3_shell_newline_is_an_execution_command_separator(self) -> None:
        terminal_events = [
            event("00:00:20", "run", "start", target="live.example:1"),
            event("00:00:30", "run", "exit", exit_code=1, timeout=False),
            event("00:01:00", "terminal", "status", status="no_flag", flags=0),
        ]
        for label, separator in (("and", " && "), ("semicolon", "; "), ("newline", "\n")):
            with self.subTest(separator=label):
                command = f"cd /tmp{separator}python3 exploit.py live.example:1"
                self.assertTrue(A._is_execution_command(command))
                job = self.fixture.job(
                    f"f3{label}",
                    terminal_events,
                    run_log=(
                        "[00:00:10] [main] TOOL Bash: "
                        + json.dumps({"command": command})
                        + "\n[00:00:11] [main] TOOL_RESULT: connect failed: ECONNREFUSED\n"
                    ),
                )
                result = A.classify(job)
                self.assertEqual(
                    (result.class_name, result.rung), ("ENV_target_unusable", "P6a")
                )

    def test_D6_malformed_terminal_event_is_unresolved(self) -> None:
        self.fixture.job(
            "d6",
            [
                event("00:00:20", "run", "start", target="live.example:1"),
                event("00:00:30", "run", "exit", exit_code=1, timeout=False),
            ],
            meta={"status": "finished", "flags": ["FLAG"]},
            raw_events_suffix='{"ts":"2026-01-01T00:01:00+00:00","phase":"terminal"',
        )
        with self.assertRaisesRegex(
            A.AggregationError, r"unresolved failure classification: d6"
        ):
            A.aggregate(self.fixture.jobs_dir)

    def test_D7_event_artifact_without_meta_is_reported(self) -> None:
        self.fixture.job(
            "d7valid",
            [event("00:01:00", "terminal", "status", status="finished", flags=1)],
            meta={"status": "finished", "flags": ["FLAG"]},
        )
        missing = self.fixture.jobs_dir / "d7missing"
        missing.mkdir()
        (missing / "events.jsonl").write_text(
            json.dumps(event("00:01:00", "terminal", "status", status="no_flag", flags=0))
            + "\n",
            encoding="utf-8",
        )

        result = A.aggregate(self.fixture.jobs_dir)
        self.assertEqual(result.skipped_counts, {"missing-meta-with-events": 1})
        self.assertIn(
            "입력 제외                 1 directory (events.jsonl 있으나 meta.json 없음)",
            A.format_report(result),
        )

    def test_D1_remote_connection_failure_is_platform_agnostic_for_stderr(self) -> None:
        job = self.fixture.job(
            "d1",
            [
                event("00:00:20", "run", "start", target="ctf.example.org:31337"),
                event("00:00:30", "run", "exit", exit_code=1, timeout=False),
                event("00:01:00", "terminal", "status", status="no_flag", flags=0),
            ],
            stderr="Could not connect to ctf.example.org on port 31337\n",
            stderr_time="00:00:40",
        )
        result = A.classify(job)
        self.assertEqual((result.class_name, result.rung), ("ENV_target_unusable", "P6b"))

    def test_D1_general_outage_signatures_apply_to_logs_and_stderr(self) -> None:
        signatures = (
            "Could not connect to ctf.example.org on port 31337",
            "Remote instance ctf.example.org:31337 is down",
            "connect failed: ECONNREFUSED",
            "remote endpoint refuses TCP connections",
            "offline target detected",
        )
        for matcher in (A.ENV_LOG_RE, A.ENV_STDERR_RE):
            with self.subTest(pattern=matcher.pattern):
                self.assertNotIn("dreamhack", matcher.pattern.lower())
                for signature in signatures:
                    self.assertIsNotNone(matcher.search(signature), signature)

    def test_I1_manual_run_events_are_cut_at_the_last_automatic_terminal(self) -> None:
        job = self.fixture.job(
            "i1",
            [
                event("00:00:30", "run", "start", target="live.example:1"),
                event("00:00:40", "run", "exit", exit_code=1, timeout=False),
                event("00:01:00", "terminal", "status", status="no_flag", flags=0),
                event("00:02:00", "run", "start", target="dead.example:2"),
                event("00:02:10", "run", "exit", exit_code=0, timeout=False),
                event("00:02:20", "postjudge", "verdict", verdict="network_error"),
            ],
            run_log="[00:02:00] [manual-run] executing exploit.py\n",
        )
        result = A.classify(job)
        self.assertEqual((result.class_name, result.rung), ("CAP_solver_exhausted", "P6c"))

    def test_I1_run_log_is_cut_at_the_manual_marker_itself(self) -> None:
        job = self.fixture.job(
            "i1log",
            [],
            run_log=(
                "[00:00:10] [manual-run] executing exploit.py\n"
                "[00:00:11] [main] TOOL_RESULT: Address in use\n"
            ),
        )
        self.assertIsNone(A._environment_log_evidence(job, None, None))

    def test_I2_stderr_overwritten_after_the_window_is_rejected(self) -> None:
        job = self.fixture.job(
            "i2",
            [
                event("00:00:30", "run", "start", target="live.example:1"),
                event("00:00:40", "run", "exit", exit_code=1, timeout=False),
                event("00:01:00", "terminal", "status", status="no_flag", flags=0),
            ],
            stderr="Could not connect to host3.dreamhack.games\n",
            stderr_time="00:02:00",
        )
        result = A.classify(job)
        self.assertEqual((result.class_name, result.rung), ("CAP_solver_exhausted", "P6c"))

    def test_I3_terminal_after_finished_at_keeps_the_jobs_own_events(self) -> None:
        job = self.fixture.job(
            "i3",
            [
                event("00:02:20", "run", "start", target="live.example:1"),
                event("00:02:30", "run", "exit", exit_code=0, timeout=False),
                event("00:03:00", "terminal", "status", status="no_flag", flags=0),
            ],
        )
        result = A.classify(job)
        self.assertEqual((result.class_name, result.rung), ("CAP_ran_no_flag", "P6c"))

    def test_I4_latest_terminal_selects_the_latest_multi_cycle_attempt(self) -> None:
        job = self.fixture.job(
            "i4",
            [
                event("00:00:20", "run", "start", target="old.example:1"),
                event("00:00:30", "run", "exit", exit_code=1, timeout=False),
                event("00:00:40", "terminal", "status", status="no_flag", flags=0),
                event("00:01:20", "run", "start", target="new.example:2"),
                event("00:01:30", "run", "exit", exit_code=0, timeout=False),
                event("00:01:40", "terminal", "status", status="no_flag", flags=0),
            ],
        )
        result = A.classify(job)
        self.assertEqual((result.class_name, result.rung), ("CAP_ran_no_flag", "P6c"))

    def test_I4_population_gate_uses_the_latest_status_terminal(self) -> None:
        job = self.fixture.job(
            "i4population",
            [
                event("00:00:20", "terminal", "status", status="finished", flags=1),
                event("00:01:00", "terminal", "status", status="no_flag", flags=0),
            ],
        )
        outcome = A.automatic_outcome(job)
        self.assertEqual(
            (outcome.success, outcome.source, outcome.status, outcome.flags),
            (False, "terminal", "no_flag", 0),
        )

    def test_I5_data_read_tool_result_is_not_execution_evidence(self) -> None:
        job = self.fixture.job(
            "i5",
            [
                event("00:00:20", "run", "start", target="live.example:1"),
                event("00:00:30", "run", "exit", exit_code=1, timeout=False),
                event("00:01:00", "terminal", "status", status="no_flag", flags=0),
            ],
            run_log=(
                "[00:00:10] [main] TOOL Bash: {\n"
                "[00:00:10] [main] TOOL Bash:   \"command\": \"strings ./bin/chal\"\n"
                "[00:00:10] [main] TOOL Bash: }\n"
                "[00:00:11] [main] TOOL_RESULT: Address in use\n"
            ),
        )
        result = A.classify(job)
        self.assertEqual((result.class_name, result.rung), ("CAP_solver_exhausted", "P6c"))

    def test_I5_each_new_bash_block_gets_its_own_result_scope(self) -> None:
        job = self.fixture.job(
            "i5scope",
            [
                event("00:00:40", "run", "start", target="dead.example:1"),
                event("00:00:50", "run", "exit", exit_code=1, timeout=False),
                event("00:01:00", "terminal", "status", status="no_flag", flags=0),
            ],
            run_log=(
                "[00:00:10] [main] TOOL Bash: {\n"
                "[00:00:10] [main] TOOL Bash:   \"command\": \"/usr/bin/strings ./chal\"\n"
                "[00:00:10] [main] TOOL Bash: }\n"
                "[00:00:11] [main] TOOL_RESULT: Address in use\n"
                "[00:00:20] [main] TOOL Bash: {\n"
                "[00:00:20] [main] TOOL Bash:   \"command\": \"python probe.py\"\n"
                "[00:00:20] [main] TOOL Bash: }\n"
                "[00:00:21] [main] TOOL_RESULT: remote QEMU gdb port remains occupied\n"
            ),
        )
        result = A.classify(job)
        self.assertEqual((result.class_name, result.rung), ("ENV_target_unusable", "P6a"))

    def test_I6_hostless_stop_reason_uses_the_named_P6d_residual(self) -> None:
        job = self.fixture.job(
            "i6",
            [
                event("00:00:20", "run", "start", target="live.example:1"),
                event("00:00:30", "run", "exit", exit_code=0, timeout=False),
                event("00:01:00", "terminal", "status", status="no_flag", flags=0),
            ],
            meta={
                "judge_stop_reason": "0/10000 hits; the 2MiB premise is false remotely"
            },
        )
        result = A.classify(job)
        self.assertEqual((result.class_name, result.rung), ("CAP_solver_exhausted", "P6d"))

    def test_I7_legacy_fallback_records_safe_source(self) -> None:
        safe = self.fixture.job(
            "i7safe",
            [],
            meta={"status": "finished", "flags": ["FLAG"]},
        )
        safe_outcome = A.automatic_outcome(safe)
        self.assertEqual((safe_outcome.success, safe_outcome.source), (True, "legacy-meta"))

    def test_success_tier_breakdown_preserves_untrusted_and_missing_provenance(self) -> None:
        terminal = [
            event("00:00:30", "terminal", "status", status="finished", flags=1)
        ]
        cases = {
            "trusted-marker": {"flag_provenance": "marker", "flag_trusted_tier": True},
            "untrusted-marker": {
                "flag_provenance": "marker",
                "flag_trusted_tier": False,
            },
            "runner-regex": {
                "flag_provenance": "runner_regex",
                "flag_trusted_tier": True,
            },
            "missing-provenance": {},
        }
        for job_id, provenance in cases.items():
            self.fixture.job(job_id, terminal, meta=provenance)

        result = A.aggregate(self.fixture.jobs_dir)
        self.assertEqual(result.successes, 4)
        self.assertEqual(
            result.success_tier_counts,
            {"marker": 1, "untrusted-tier": 2, "missing-provenance": 1},
        )
        self.assertEqual(
            A.format_report(result).splitlines()[0],
            "자동 성공                4 / 4        "
            "(marker 1 · 신뢰되지 않은 등급 2 · provenance 없음 1; "
            "terminal 판정 4 중 4 + legacy 0 중 0)",
        )

    def test_I7_legacy_fallback_rejects_run_log_manual_marker(self) -> None:
        unsafe = self.fixture.job(
            "i7marker",
            [],
            meta={"status": "finished", "flags": ["FLAG"]},
            run_log="[00:02:00] [manual-run] executing exploit.py\n",
        )
        unsafe_outcome = A.automatic_outcome(unsafe)
        self.assertEqual(
            (unsafe_outcome.success, unsafe_outcome.source), (None, "unsafe-legacy-meta")
        )

    def test_I7_legacy_fallback_rejects_meta_manual_run_flag(self) -> None:
        unsafe = self.fixture.job(
            "i7meta",
            [],
            meta={"status": "finished", "flags": ["FLAG"], "manual_run": True},
        )
        unsafe_outcome = A.automatic_outcome(unsafe)
        self.assertEqual(
            (unsafe_outcome.success, unsafe_outcome.source), (None, "unsafe-legacy-meta")
        )

    def test_P5_stale_scalar_target_does_not_override_the_final_attempt(self) -> None:
        job = self.fixture.job(
            "stale",
            [
                event("00:00:20", "run", "start", target="live.example:222"),
                event("00:00:30", "run", "exit", exit_code=1, timeout=False),
                event("00:01:00", "terminal", "status", status="no_flag", flags=0),
            ],
            meta={
                "judge_stop_reason": (
                    "Remote instance stale.example:111 is down (ECONNREFUSED)"
                )
            },
        )
        result = A.classify(job)
        self.assertEqual((result.class_name, result.rung), ("CAP_solver_exhausted", "P6c"))

    def test_null_and_literal_unknown_error_kinds_remain_distinct(self) -> None:
        self.assertEqual(A.error_kind_state({"error_kind": None}), "null")
        self.assertEqual(A.error_kind_state({}), "null")
        self.assertEqual(A.error_kind_state({"error_kind": "unknown"}), "value:unknown")

    def test_rung_to_class_fanout_is_explicit(self) -> None:
        self.assertEqual(
            A.RUNG_CLASS_MAP["P1"], ("HARN_stream_overflow", "HARN_sdk_transport")
        )
        self.assertEqual(
            A.RUNG_CLASS_MAP["P4"], ("ENV_target_unusable", "HARN_flag_harvest")
        )
        self.assertEqual(
            A.RUNG_CLASS_MAP["P6c"],
            ("HARN_no_events", "CAP_ran_no_flag", "CAP_solver_exhausted"),
        )


class ProductionSnapshotTests(unittest.TestCase):
    def test_population_boundary_and_retry_anomalies_are_explicit(self) -> None:
        result = A.aggregate(JOBS)
        self.assertEqual(
            {row.job_id: row.reasons for row in result.population_exclusions},
            EXPECTED_POPULATION_EXCLUSIONS,
        )
        self.assertEqual(result.retry_anomalies, EXPECTED_RETRY_ANOMALIES)

    def test_D1_only_the_provenance_conflict_leaves_production_P1(self) -> None:
        result = A.aggregate(JOBS)
        p1_jobs = {
            row.job_id: row.class_name
            for row in result.classifications
            if row.rung == "P1"
        }
        self.assertEqual(
            p1_jobs,
            {
                "4971dc03c3a6": "HARN_sdk_transport",
                "c9c6dee657b0": "HARN_stream_overflow",
                "d8ddf193f523": "HARN_stream_overflow",
                "deb3a308a2aa": "HARN_sdk_transport",
            },
        )

    def test_success_tier_breakdown_is_structured_and_machine_readable(self) -> None:
        result = A.aggregate(JOBS)
        expected = {"marker": 16, "untrusted-tier": 1, "missing-provenance": 0}
        self.assertEqual(result.success_tier_counts, expected)
        completed = subprocess.run(
            [sys.executable, str(PRODUCTION), "--jobs-dir", str(JOBS), "--json"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))
        self.assertEqual(json.loads(completed.stdout)["success_tier_counts"], expected)

    def test_D5_authoritative_structure_is_exact(self) -> None:
        result = A.aggregate(JOBS)
        encoded_path = os.environ.get("HARDENING_NUMERIC_MUTATION_PATH")
        if encoded_path:
            target = tuple(tuple(component) for component in json.loads(encoded_path))
            result = mutate_numeric_path(result, target)
        self.assertEqual(numeric_structure(result), EXPECTED_NUMERIC_STRUCTURE)
        restored = next(
            row for row in result.classifications if row.job_id == "3a64d16a243b"
        )
        self.assertEqual(
            (restored.class_name, restored.rung, restored.evidence),
            (
                "ENV_target_unusable",
                "P6a",
                "run.log:71: remote QEMU gdb port remains occupied",
            ),
        )
        corrected = {
            row.job_id: (row.class_name, row.rung, row.evidence)
            for row in result.classifications
            if row.job_id
            in {"121e8725dbf4", "4df962049a35", "6685e3e65add", "848292223226"}
        }
        self.assertEqual(
            corrected,
            {
                "121e8725dbf4": (
                    "HARN_flag_harvest",
                    "P4",
                    "postjudge success events.jsonl:8; run.log:3827: "
                    "orchestrator reported zero harvested flags",
                ),
                "4df962049a35": (
                    "ENV_target_unusable",
                    "P6a",
                    "run.log:988: runner target unreachable",
                ),
                "6685e3e65add": (
                    "ENV_target_unusable",
                    "P6a",
                    "run.log:541: runner target unreachable",
                ),
                "848292223226": (
                    "ENV_target_unusable",
                    "P4",
                    "postjudge events.jsonl:4",
                ),
            },
        )

    def test_authoritative_table_is_byte_identical(self) -> None:
        result = A.aggregate(JOBS)
        self.assertEqual(A.format_report(result), EXPECTED_REPORT)
        completed = subprocess.run(
            [sys.executable, str(PRODUCTION), "--jobs-dir", str(JOBS)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))
        self.assertEqual(completed.stdout, (EXPECTED_REPORT + "\n").encode())


MUTATIONS = {
    "D1": (
        r'r"Could not connect to (?:host )?[A-Za-z0-9.-]+\b"',
        r'r"Could not connect to host3\.dreamhack\.games\b"',
        "AcceptanceTests.test_D1_remote_connection_failure_is_platform_agnostic_for_stderr",
    ),
    "I1": (
        'if started <= event["_dt"] <= end',
        'if started <= event["_dt"]',
        "AcceptanceTests.test_I1_manual_run_events_are_cut_at_the_last_automatic_terminal",
    ),
    "I2": (
        "if started <= mtime <= end and ENV_STDERR_RE.search(",
        "if started <= mtime and ENV_STDERR_RE.search(",
        "AcceptanceTests.test_I2_stderr_overwritten_after_the_window_is_rejected",
    ),
    "I3": (
        "if terminal_events:\n        end = terminal_events[-1][\"_dt\"]",
        "if False and terminal_events:\n        end = terminal_events[-1][\"_dt\"]",
        "AcceptanceTests.test_I3_terminal_after_finished_at_keeps_the_jobs_own_events",
    ),
    "I4_window": (
        'end = terminal_events[-1]["_dt"]',
        'end = terminal_events[0]["_dt"]',
        "AcceptanceTests.test_I4_latest_terminal_selects_the_latest_multi_cycle_attempt",
    ),
    "I4_population": (
        "terminal = terminals[-1]",
        "terminal = terminals[0]",
        "AcceptanceTests.test_I4_population_gate_uses_the_latest_status_terminal",
    ),
    "D4": (
        'if kind == "TOOL_RESULT" and not _is_execution_command(command):',
        'if kind == "TOOL_RESULT" and False:',
        "AcceptanceTests.test_D4_only_allowlisted_execution_sources_are_environment_evidence",
    ),
    "D5": (
        "successes=len(successes),",
        "successes=999,",
        "ProductionSnapshotTests.test_D5_authoritative_structure_is_exact",
    ),
    "D5_new_numeric_field": (
        "    retry_anomalies: tuple[str, ...]\n\n\ndef _parse_time",
        "    retry_anomalies: tuple[str, ...]\n"
        "    future_numeric_field: int = 0\n\n\ndef _parse_time",
        "ProductionSnapshotTests.test_D5_authoritative_structure_is_exact",
    ),
    "D6": (
        "except (json.JSONDecodeError, TypeError, ValueError):\n"
        "            malformed_lines.append(line_no)",
        "except (json.JSONDecodeError, TypeError, ValueError):\n            pass",
        "AcceptanceTests.test_D6_malformed_terminal_event_is_unresolved",
    ),
    "D7": (
        'if not (events_path.parent / "meta.json").is_file()',
        "if False",
        "AcceptanceTests.test_D7_event_artifact_without_meta_is_reported",
    ),
    "population_validation_exclusion": (
        '"9f9dad521117": "system-validation-live-test"',
        '"ffffffffffff": "system-validation-live-test"',
        "ProductionSnapshotTests.test_population_boundary_and_retry_anomalies_are_explicit",
    ),
    "population_exclusion_reporting": (
        "population_exclusions=population_exclusions,",
        "population_exclusions=(),",
        "ProductionSnapshotTests.test_population_boundary_and_retry_anomalies_are_explicit",
    ),
    "retry_anomaly_reporting": (
        "retry_anomalies = _retry_anomalies(included, jobs)",
        "retry_anomalies = ()",
        "ProductionSnapshotTests.test_population_boundary_and_retry_anomalies_are_explicit",
    ),
    "D8_relayed_report": (
        "elif RUNNER_REPORT_TAIL_RE.match(heading):",
        "elif False and RUNNER_REPORT_TAIL_RE.match(heading):",
        "AcceptanceTests.test_D8_relayed_runner_report_block_is_execution_evidence",
    ),
    "D8_data_read_boundary": (
        "if executable not in RUNNER_REPORT_READERS:",
        "if False:",
        "AcceptanceTests.test_D8_data_read_marker_text_does_not_open_runner_report_block",
    ),
    "D8_report_section_end": (
        'elif heading.startswith("## "):\n'
        "                    runner_report_seen = False",
        'elif False and heading.startswith("## "):\n'
        "                    runner_report_seen = False",
        "AcceptanceTests.test_D8_runner_report_block_ends_at_the_next_section",
    ),
    "F1_cut_boundary": (
        ") or runner_fence is not None:",
        ") or runner_fence is not None or runner_tail_armed:",
        "AcceptanceTests.test_F1_truncated_runner_report_does_not_admit_following_data",
    ),
    "F1_fenced_heading": (
        "if runner_fence is not None:\n                fence = _markdown_fence(payload)",
        "if runner_fence is not None and heading.startswith(\"## \"):\n"
        "                runner_fence = None\n"
        "            elif runner_fence is not None:\n"
        "                fence = _markdown_fence(payload)",
        "AcceptanceTests.test_F1_heading_inside_fenced_runner_output_does_not_end_evidence",
    ),
    "F3_newline_separator": (
        'lexer.whitespace = " \\t\\r"',
        'lexer.whitespace = " \\t\\r\\n"',
        "AcceptanceTests.test_F3_shell_newline_is_an_execution_command_separator",
    ),
    "I6": (
        "if scalar_target and target and scalar_target == target:",
        "if stop and target:",
        "AcceptanceTests.test_I6_hostless_stop_reason_uses_the_named_P6d_residual",
    ),
    "I7_manual_marker": (
        'if manual_marker or job.meta.get("manual_run"):',
        'if False or job.meta.get("manual_run"):',
        "AcceptanceTests.test_I7_legacy_fallback_rejects_run_log_manual_marker",
    ),
    "I7_meta_manual_run": (
        'if manual_marker or job.meta.get("manual_run"):',
        "if manual_marker or False:",
        "AcceptanceTests.test_I7_legacy_fallback_rejects_meta_manual_run_flag",
    ),
    "current_runner_preflight": (
        '            actor == "runner"\n            and kind.startswith("target ")',
        '            False\n            and kind.startswith("target ")',
        "AcceptanceTests.test_current_runner_preflight_unreachable_is_environment_evidence",
    ),
    "current_final_attempt_over_block": (
        "if not has_run_attempt and any(",
        "if any(",
        "AcceptanceTests.test_D2_confirmed_flag_harvest_failure_supersedes_earlier_block",
    ),
    "D1_global_scalar_precedence": (
        'if p1_classification is None and error_kind == "policy_refusal":',
        'if p1_classification is not None:\n'
        '        return found(*p1_classification)\n'
        '    if p1_classification is None and error_kind == "policy_refusal":',
        "AcceptanceTests.test_D1_global_scalar_yields_only_to_classifiable_attempt_evidence",
    ),
    "D2_harvest_confirmation": (
        "and harvest_evidence is not None",
        "and True",
        "AcceptanceTests.test_D2_postjudge_success_without_artifact_confirmation_falls_through",
    ),
}


class MutationCampaignTests(unittest.TestCase):
    def test_all_targeted_production_mutations_are_caught(self) -> None:
        source = PRODUCTION.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix="hardening-mutants-") as tmp:
            for label, (old, new, test_name) in MUTATIONS.items():
                with self.subTest(label=label):
                    self.assertEqual(source.count(old), 1, f"mutation point {label} drifted")
                    mutant = Path(tmp) / f"aggregate_hardening_{label}.py"
                    mutant.write_text(source.replace(old, new, 1), encoding="utf-8")
                    env = os.environ.copy()
                    env["HARDENING_AGGREGATOR_PATH"] = str(mutant)
                    completed = subprocess.run(
                        [sys.executable, str(Path(__file__).resolve()), test_name],
                        cwd=ROOT,
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    self.assertNotEqual(
                        completed.returncode,
                        0,
                        f"{label} mutant survived {test_name}:\n"
                        + completed.stdout.decode(errors="replace")
                        + completed.stderr.decode(errors="replace"),
                    )

    def test_D5_each_numeric_result_field_mutation_is_caught(self) -> None:
        result = A.aggregate(JOBS)
        paths = list(numeric_paths(result))
        self.assertGreater(len(paths), 16)
        for path in paths:
            with self.subTest(path=path):
                env = os.environ.copy()
                env["HARDENING_NUMERIC_MUTATION_PATH"] = json.dumps(path)
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(Path(__file__).resolve()),
                        "ProductionSnapshotTests.test_D5_authoritative_structure_is_exact",
                    ],
                    cwd=ROOT,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertNotEqual(
                    completed.returncode,
                    0,
                    f"numeric mutant survived at {path}:\n"
                    + completed.stdout.decode(errors="replace")
                    + completed.stderr.decode(errors="replace"),
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
