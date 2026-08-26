#!/usr/bin/env python3
"""Executable contract for the Codex per-turn timeout control surface."""
from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PASSED = 0
FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got={got!r}\n        want={want!r}")


def env_value(path: Path, name: str) -> str | None:
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == name:
            return value.strip()
    return None


def compose_config() -> dict:
    commands: list[list[str]] = []
    docker = shutil.which("docker")
    if docker:
        commands.append([docker, "compose"])
    snap_plugin = Path("/snap/docker/current/usr/libexec/docker/cli-plugins/docker-compose")
    if snap_plugin.is_file():
        commands.append([str(snap_plugin)])
    errors = []
    for prefix in commands:
        proc = subprocess.run(
            [
                *prefix,
                "--env-file",
                str(ROOT / ".env.example"),
                "config",
                "--format",
                "json",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        if proc.returncode == 0:
            return json.loads(proc.stdout)
        errors.append(f"{' '.join(prefix)}: {proc.stderr.strip()}")
    raise RuntimeError("no working Compose config renderer: " + "; ".join(errors))


env_path = ROOT / ".env"
if env_path.is_file():
    check(
        "deployed env exposes the Codex turn fallback",
        env_value(env_path, "CODEX_TURN_TIMEOUT_S"),
        "3600",
    )
else:
    print("SKIP  deployed env timeout (.env is gitignored; not in this tree)")
check(
    "example env documents the Codex turn fallback",
    env_value(ROOT / ".env.example", "CODEX_TURN_TIMEOUT_S"),
    "3600",
)

config = compose_config()
worker_services = sorted(
    name for name in config["services"] if re.fullmatch(r"worker-\d+", name)
)
check("Compose exposes worker slots", bool(worker_services), True)
for service in worker_services:
    check(
        f"Compose passes the turn ceiling to {service}",
        config["services"][service]["environment"].get("CODEX_TURN_TIMEOUT_S"),
        "3600",
    )

from modules import _common, codex_cli, settings_io  # noqa: E402

check(
    "structured Codex timeout maps to the shared timeout category",
    _common.classify_stop_reason("timeout"),
    "timeout",
)

old_read_meta = _common.read_meta
try:
    _common.read_meta = lambda _job_id: {"job_timeout": 9_999_999}
    check(
        "main turn inherits a larger per-job timeout",
        _common.job_turn_timeout_s("historical-timeout"),
        9_999_999.0,
    )
    _common.read_meta = lambda _job_id: {"job_timeout": 900}
    check(
        "main turn retains the 30-minute floor",
        _common.job_turn_timeout_s("short-job"),
        1800.0,
    )
    _common.read_meta = lambda _job_id: {"job_timeout": "invalid"}
    check(
        "malformed job metadata falls back safely",
        _common.job_turn_timeout_s("bad-meta"),
        1800.0,
    )
finally:
    _common.read_meta = old_read_meta


class OptionsCallVisitor(ast.NodeVisitor):
    def __init__(self, relative_path: str):
        self.relative_path = relative_path
        self.function = "<module>"
        self.calls: list[tuple[str, str, str, str | None]] = []

    def _visit_function(self, node) -> None:
        previous = self.function
        self.function = node.name
        self.generic_visit(node)
        self.function = previous

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr
        else:
            name = ""
        canonical = {"_GSO": "GrokSessionOptions"}.get(name, name)
        if canonical in {"GptSessionOptions", "GrokSessionOptions"}:
            timeout_kw = next(
                (kw.value for kw in node.keywords if kw.arg == "turn_timeout_s"),
                None,
            )
            self.calls.append(
                (
                    self.relative_path,
                    self.function,
                    canonical,
                    ast.unparse(timeout_kw) if timeout_kw is not None else None,
                )
            )
        self.generic_visit(node)


option_calls: list[tuple[str, str, str, str | None]] = []
for source_path in sorted((ROOT / "modules").rglob("*.py")):
    relative = str(source_path.relative_to(ROOT))
    visitor = OptionsCallVisitor(relative)
    visitor.visit(ast.parse(source_path.read_text(encoding="utf-8")))
    option_calls.extend(visitor.calls)

approved_fallbacks = {
    ("modules/_common.py", "run_pre_recon", "GptSessionOptions"),
    ("modules/_common.py", "run_pre_recon", "GrokSessionOptions"),
    ("modules/_judge.py", "_run_judge_turn", "GptSessionOptions"),
    ("modules/_judge.py", "_run_judge_turn", "GrokSessionOptions"),
    ("modules/grok_acp.py", "query_grok_once", "GrokSessionOptions"),
}
observed_fallbacks = {
    (path, function, constructor)
    for path, function, constructor, timeout in option_calls
    if timeout is None
}
check(
    "every constructor without a turn budget is an explicit auxiliary exception",
    observed_fallbacks,
    approved_fallbacks,
)

main_one_shot_timeouts = {
    (path, constructor): timeout
    for path, function, constructor, timeout in option_calls
    if path in {
        "modules/misc/orchestrator.py",
        "modules/forensic/orchestrator.py",
    }
    and function == "_claude_summary"
}
check(
    "misc/forensic GPT and Grok main adapters share the job-derived budget",
    main_one_shot_timeouts,
    {
        ("modules/misc/orchestrator.py", "GptSessionOptions"):
            "turn_timeout_s",
        ("modules/misc/orchestrator.py", "GrokSessionOptions"):
            "turn_timeout_s",
        ("modules/forensic/orchestrator.py", "GptSessionOptions"):
            "turn_timeout_s",
        ("modules/forensic/orchestrator.py", "GrokSessionOptions"):
            "turn_timeout_s",
    },
)

old_path = settings_io.SETTINGS_PATH
old_env = os.environ.get("CODEX_TURN_TIMEOUT_S")
settings_tmp = tempfile.TemporaryDirectory(prefix="turn-timeout-settings-")
try:
    settings_io.SETTINGS_PATH = Path(settings_tmp.name) / "settings.json"
    os.environ.pop("CODEX_TURN_TIMEOUT_S", None)
    check("Settings default is visible", settings_io.get_setting("codex_turn_timeout_seconds"), 3600)
    check(
        "Settings view identifies the default source",
        settings_io.get_settings_view().get("codex_turn_timeout_seconds_source"),
        "default",
    )

    os.environ["CODEX_TURN_TIMEOUT_S"] = "7200"
    check("env overrides the default", settings_io.get_setting("codex_turn_timeout_seconds"), 7200)
    check(
        "Settings view identifies the env source",
        settings_io.get_settings_view().get("codex_turn_timeout_seconds_source"),
        "env",
    )

    settings_io.update_settings({"codex_turn_timeout_seconds": 10800})
    check("saved Settings override env", settings_io.get_setting("codex_turn_timeout_seconds"), 10800)
    check(
        "Settings view identifies the persisted source",
        settings_io.get_settings_view().get("codex_turn_timeout_seconds_source"),
        "settings",
    )
    settings_io.apply_to_env()
    check("apply_to_env reaches the Codex CLI env", os.environ.get("CODEX_TURN_TIMEOUT_S"), "10800")
    check(
        "Codex parser consumes the applied value",
        codex_cli._positive_timeout(os.environ["CODEX_TURN_TIMEOUT_S"]),
        10800.0,
    )

    for bad in (0, -1, 1.5, True, "not-a-number"):
        try:
            settings_io.update_settings({"codex_turn_timeout_seconds": bad})
        except ValueError:
            rejected = True
        else:
            rejected = False
        check(f"Settings rejects invalid timeout {bad!r}", rejected, True)
finally:
    settings_io.SETTINGS_PATH = old_path
    if old_env is None:
        os.environ.pop("CODEX_TURN_TIMEOUT_S", None)
    else:
        os.environ["CODEX_TURN_TIMEOUT_S"] = old_env
    settings_tmp.cleanup()

print(f"{PASSED} checks, {FAILED} failed")
raise SystemExit(1 if FAILED else 0)
