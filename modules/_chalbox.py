"""Build the challenge's OWN container so its engine is reachable locally.

THE PROBLEM, measured on the msgbox kernel lineage (five jobs):

  chal/Dockerfile   FROM ubuntu:24.04 ; apt install qemu-system-x86  -> 8.2.2
  worker            Debian 13                                        -> 10.0.11
  chal/run.sh       exec qemu-system-x86_64 ...   <- invoked BY NAME

The launcher calls the engine by name, so PATH decides which binary runs, and
on the worker PATH resolves to a build two major versions from the one holding
the flag.  An agent that copies the challenge's launcher perfectly still tests
on the wrong machine.

That is not a hypothetical divergence.  The iPXE option-ROM base printed at
boot differs between them, and the challenge container's value matches the
REMOTE's exactly:

  worker                  PMM+0EFC6D30
  chal container / remote PMM+0EFCAE00

A prompt cannot fix this.  The guidance was fixed first (modules/pwn/prompts.py
now says the accelerator is part of the machine and the emulator is a version),
and job 2a4ecbec367b still ran 12 of its 19 boots on the worker's qemu — the
actor doing the booting was a subagent, and modules/codex_cli.py's own comment
records why it never saw that guidance: "Child agents do not automatically
receive the main agent's developer prompt."

So the fix has to sit below the prompt.  This module makes the image; the
PATH shim (worker/chal_engine_shim.sh) makes every invocation use it.

WHAT THIS IS NOT: a general "run everything in the container" mechanism.  The
trigger is deliberately narrow — the challenge's own launcher must invoke an
engine this module knows how to relocate.  Measured over the corpus, 37 jobs
carry docker_challenge=true but only 4 touch qemu-system, and those 4 are this
lineage.  Gating on the checkbox would build 37 images to help 4.

Stdlib only, and imports nothing from ``api.*``: the worker container has no
``api/`` mount and such an import dies at RQ load time.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import threading
from pathlib import Path

# Engines the shim can relocate.  Kept explicit rather than "anything the
# launcher calls": a shim for `python3` would shadow the worker's own
# interpreter — /usr/local/bin/python3 is the one carrying pwntools — and a
# challenge image that happens to contain python3 would silently capture the
# agent's tooling.  qemu-system-* is safe precisely because it is a dedicated
# challenge engine with exactly one caller.
RELOCATABLE_ENGINES = ("qemu-system-x86_64", "qemu-system-i386",
                       "qemu-system-aarch64", "qemu-system-arm")

_STATE_DIRNAME = ".chalbox"
_STATE_FILE = "state.json"

# Launcher scripts a bundle might ship.  The point is to read what the
# CHALLENGE runs, not to guess from the Dockerfile alone: bc257's Dockerfile
# installs qemu-system-x86 but its CMD is a socat that execs run.py, which
# execs run.sh, which is where `qemu-system-x86_64` actually appears.
_LAUNCHER_GLOBS = ("*.sh", "*.py", "Dockerfile", "docker-compose.yml",
                   "docker-compose.yaml")


def image_name(job_id: str) -> str:
    """Deterministic per-job tag.  The shim derives the same name."""
    return "chal_%s" % re.sub(r"[^A-Za-z0-9_.-]", "", str(job_id))[:64]


def state_dir(work_dir) -> Path:
    return Path(work_dir) / _STATE_DIRNAME


def read_state(work_dir) -> dict:
    """The build's recorded outcome, or {} when nothing has been written.

    Never raises: every consumer treats an unreadable state as "no image",
    which degrades to using the worker's own engine — today's behaviour.
    """
    try:
        raw = (state_dir(work_dir) / _STATE_FILE).read_text()
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_state(work_dir, payload: dict) -> None:
    d = state_dir(work_dir)
    try:
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / (_STATE_FILE + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=1))
        tmp.replace(d / _STATE_FILE)
    except OSError:
        pass


def find_build_context(job_root, work_dir) -> Path | None:
    """The directory holding the challenge's Dockerfile, or None.

    Checks a fixed list rather than walking: a recursive scan of a job root
    can reach carve/extract output, and building THAT would hand docker
    untrusted recovered content.  docker_challenge_block's comment records
    that hazard for the forensic case; this module simply never walks.
    """
    job_root = Path(job_root)
    work_dir = Path(work_dir)
    # Ordered most-specific first. work/chal is pwn's autoboot unpack target
    # and is where the shapes that matter actually put the bundle.
    candidates = (
        work_dir / "chal",
        job_root / "chal",
        job_root / "bin",
        job_root / "src",
        job_root,
    )
    for base in candidates:
        try:
            if (base / "Dockerfile").is_file():
                return base
        except OSError:
            continue
    return None


def launcher_engines(context: Path) -> list:
    """Engines the challenge's OWN launchers invoke, as bare names.

    Reads the launcher scripts rather than the Dockerfile's package list: a
    bundle can install an engine it never runs, and — the case that matters —
    can run one through two levels of exec that no package name reveals.
    """
    found = []
    try:
        names = sorted(p for g in _LAUNCHER_GLOBS for p in context.glob(g))
    except OSError:
        return found
    for path in names[:24]:
        try:
            if path.stat().st_size > 512_000:
                continue
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for engine in RELOCATABLE_ENGINES:
            if engine in text and engine not in found:
                found.append(engine)
    return found


def should_build(job_root, work_dir) -> tuple:
    """(context, engines) when this bundle is worth containerising, else (None, []).

    Both halves must hold: a Dockerfile to build, AND a launcher that invokes
    an engine the shim can relocate.  A Dockerfile alone is not enough — that
    is the 37-vs-4 gap.
    """
    ctx = find_build_context(job_root, work_dir)
    if ctx is None:
        return None, []
    engines = launcher_engines(ctx)
    return (ctx, engines) if engines else (None, [])


def _docker_bin() -> str:
    return os.environ.get("CHALBOX_DOCKER", "docker")


def build_image(job_id: str, context: Path, engines, log_fn=None,
                timeout: int = 900) -> dict:
    """Build the challenge image.  Returns the state dict it also persists.

    Never raises.  A failed build is recorded and the run continues on the
    worker's own engine, which is exactly today's behaviour.
    """
    def _log(msg: str) -> None:
        if log_fn:
            try:
                log_fn(msg)
            except Exception:
                pass

    img = image_name(job_id)
    state = {"image": img, "context": str(context),
             "engines": list(engines), "status": "building"}
    _write_state(context.parent if context.name == "chal" else context, state)
    try:
        proc = subprocess.run(
            [_docker_bin(), "build", "-t", img, str(context)],
            capture_output=True, text=True, timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001 — a build never fails a job
        state.update(status="error", detail="%s: %s" % (type(exc).__name__, exc))
        _log("[chalbox] challenge image build could not run (%s) — the run "
             "continues on the worker's own engine" % type(exc).__name__)
        return state
    tail = ((proc.stderr or "") + (proc.stdout or ""))[-600:]
    if proc.returncode != 0:
        state.update(status="failed", detail=tail)
        _log("[chalbox] challenge image build FAILED (exit %d) — the run "
             "continues on the worker's own engine, so any claim about "
             "engine behaviour is about the worker's build, not the "
             "target's" % proc.returncode)
        return state
    state.update(status="ready", detail="")
    _log("[chalbox] built %s from %s — %s now runs inside the challenge's own "
         "image, matching the engine the target runs"
         % (img, context, ", ".join(engines)))
    return state


def build_in_background(job_id: str, job_root, work_dir, log_fn=None):
    """Start the build off the critical path, or do nothing.

    Returns the Thread when one was started, else None.  Deliberately fired at
    job start rather than lazily on first use: a cold build is minutes, and an
    agent's first boot is often wrapped in `timeout 30`, so a lazy build would
    eat the very call it exists to fix.
    """
    ctx, engines = should_build(job_root, work_dir)
    if ctx is None:
        return None

    def _run():
        state = build_image(job_id, ctx, engines, log_fn=log_fn)
        _write_state(Path(work_dir), state)

    _write_state(Path(work_dir), {"image": image_name(job_id),
                                  "context": str(ctx),
                                  "engines": list(engines),
                                  "status": "building"})
    t = threading.Thread(target=_run, name="chalbox-build", daemon=True)
    t.start()
    return t


def remove_image(job_id: str, log_fn=None) -> bool:
    """Drop the per-job tag at job end.

    Repo-wide there was NO `docker rmi` anywhere before this: images only
    existed when an agent chose to build one, so nothing accumulated. Building
    automatically changes that, and an image per job is ~850 MB.

    This removes the TAG, not the layers — which is why a retry on the same
    bundle rebuilds in milliseconds. Never prune the builder cache here; that
    would trade a fast retry for disk the layers were already sharing.
    """
    img = image_name(job_id)
    try:
        proc = subprocess.run([_docker_bin(), "rmi", "-f", img],
                              capture_output=True, text=True, timeout=120)
    except Exception:  # noqa: BLE001
        return False
    ok = proc.returncode == 0
    if ok and log_fn:
        try:
            log_fn("[chalbox] removed image %s (layers stay cached, so a "
                   "retry rebuilds in milliseconds)" % img)
        except Exception:
            pass
    return ok
