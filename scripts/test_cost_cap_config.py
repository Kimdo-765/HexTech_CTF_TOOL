#!/usr/bin/env python3
"""Executable contract for the COST_CAP_USD path into worker code."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
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
    # A snap wrapper may be unusable in a restricted shell even though its
    # standalone Compose plugin can still render config without daemon access.
    snap_plugin = Path("/snap/docker/current/usr/libexec/docker/cli-plugins/docker-compose")
    if snap_plugin.is_file():
        commands.append([str(snap_plugin)])
    errors = []
    for prefix in commands:
        proc = subprocess.run(
            [*prefix, "config", "--format", "json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        if proc.returncode == 0:
            return json.loads(proc.stdout)
        errors.append(f"{' '.join(prefix)}: {proc.stderr.strip()}")
    raise RuntimeError("no working Compose config renderer: " + "; ".join(errors))


# `.env` is gitignored, so it exists on a deployed host and NOWHERE else — not
# in a fresh clone, not in a git worktree. Requiring it made this suite fail
# everywhere except the one machine it was written on, which is the opposite of
# what a regression test is for. The deployed value is checked when the file is
# there and reported as absent when it is not; the guarantee that survives
# either way is Compose's own default, asserted below.
env_path = ROOT / ".env"
if env_path.is_file():
    check("deployed env arms the cap", env_value(env_path, "COST_CAP_USD"), "40")
else:
    print("SKIP  deployed env arms the cap (.env is gitignored; not in this tree)")
example = env_value(ROOT / ".env.example", "COST_CAP_USD")
check("example env documents the same cap", example, "40")

# `docker-compose.yml` declares `env_file: .env` at the service level, and
# `.env` is gitignored — so `compose config` cannot render in a fresh clone or
# a git worktree, and this suite failed before reaching a single assertion.
# `--env-file` does not help: that flag chooses the substitution source, while
# `env_file:` demands the file itself. Materialise one from `.env.example` for
# the duration when the deployed file is absent; the two ship the same
# COST_CAP_USD, so the rendered worker environment is the one under test.
_tmp_env = None
if not (ROOT / ".env").is_file():
    _tmp_env = ROOT / ".env"
    _tmp_env.write_text((ROOT / ".env.example").read_text())
    print("NOTE  .env absent (gitignored); rendered from .env.example for this run")
try:
    config = compose_config()
finally:
    if _tmp_env is not None:
        _tmp_env.unlink(missing_ok=True)
for service in ("worker-1", "worker-2"):
    check(
        f"Compose passes the cap to {service}",
        config["services"][service]["environment"].get("COST_CAP_USD"),
        "40",
    )

# Run the actual modules._common reader used by the worker-side circuit breaker
# under the environment Compose resolved.
worker_env = dict(os.environ)
worker_env.update(config["services"]["worker-1"]["environment"])
probe = subprocess.run(
    [
        sys.executable,
        "-c",
        "import json; "
        "from modules._common import DEFAULT_COST_CAP_USD, cost_cap_usd; "
        "print(json.dumps({'read': cost_cap_usd(), "
        "'default': DEFAULT_COST_CAP_USD}))",
    ],
    cwd=ROOT,
    env=worker_env,
    text=True,
    capture_output=True,
)
check("worker-side modules import succeeds", probe.returncode, 0)
if probe.returncode == 0:
    observed = json.loads(probe.stdout)
    check("worker-side code reads the resolved cap", observed["read"], 40.0)
    check("worker-side fallback matches the deployment", observed["default"], 40.0)
else:
    print(probe.stderr)

print(f"{PASSED} checks, {FAILED} failed")
raise SystemExit(1 if FAILED else 0)
