#!/usr/bin/env python3
"""Executable contract for the COST_CAP_USD path into worker code.

WHAT THIS PINS — and what it deliberately stopped pinning

It used to assert the deployed number was "40". That is a setting, not a
property: when the operator disabled the cap on 2026-08-29 (COST_CAP_USD=0,
part of removing the redirect/cost budgets so a run is bounded by having
nothing new to try rather than by a counter) five checks went red without a
single thing being broken. Worse, those failures were evidence the wiring was
FINE — the 0 had travelled .env -> compose -> worker code intact, which is
exactly what the suite exists to guarantee.

So the assertions are now:

  1. the value reaches worker code UNDISTORTED, whatever it is — the expected
     value is read from .env/.env.example rather than written here, so
     changing the deployment does not require editing this file;
  2. 0 genuinely disables the breaker — `cost_cap_usd()` returns <= 0 and
     `_maybe_cost_cap` returns before spending anything. A disable switch
     nobody exercises is how you discover it never worked.
"""
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
example = env_value(ROOT / ".env.example", "COST_CAP_USD")
check("example env declares a cap value", example is not None, True)
if env_path.is_file():
    deployed = env_value(env_path, "COST_CAP_USD")
    check("deployed env declares a cap value", deployed is not None, True)
    check("deployed and example agree", deployed, example)
    EXPECT = deployed
else:
    print("SKIP  deployed env (.env is gitignored; not in this tree)")
    EXPECT = example

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
        f"Compose passes the cap to {service} undistorted",
        config["services"][service]["environment"].get("COST_CAP_USD"),
        EXPECT,
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
    check("worker-side code reads the resolved cap",
          observed["read"], float(EXPECT))
    check("the built-in fallback is a real number, not the deployment",
          isinstance(observed["default"], float) and observed["default"] > 0,
          True)
    # The disable switch, exercised rather than assumed. `_maybe_cost_cap`
    # returns as soon as `cost_cap_usd() <= 0`, so a 0 must resolve to 0.0 and
    # nothing downstream may substitute the default back in.
    zero_env = dict(worker_env)
    zero_env["COST_CAP_USD"] = "0"
    zprobe = subprocess.run(
        [sys.executable, "-c",
         "from modules._common import cost_cap_usd; print(cost_cap_usd())"],
        cwd=ROOT, env=zero_env, text=True, capture_output=True,
    )
    check("COST_CAP_USD=0 resolves to 0 (the breaker's disable path)",
          zprobe.returncode == 0 and float(zprobe.stdout.strip()) <= 0, True)
    junk_env = dict(worker_env)
    junk_env["COST_CAP_USD"] = "not-a-number"
    jprobe = subprocess.run(
        [sys.executable, "-c",
         "from modules._common import cost_cap_usd, DEFAULT_COST_CAP_USD; "
         "print(cost_cap_usd() == DEFAULT_COST_CAP_USD)"],
        cwd=ROOT, env=junk_env, text=True, capture_output=True,
    )
    check("an unparseable value falls back rather than disabling silently",
          jprobe.returncode == 0 and jprobe.stdout.strip() == "True", True)
else:
    print(probe.stderr)

common_source = (ROOT / "modules" / "_common.py").read_text(encoding="utf-8")
check(
    "worker breaker counts both external billed roles",
    'roles={"judge", "reviewer"}' in common_source,
    True,
)

print(f"{PASSED} checks, {FAILED} failed")
raise SystemExit(1 if FAILED else 0)
