"""Memory dump triage via Volatility 3.

Runs a curated plugin set per detected OS and writes per-plugin JSON.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Callable

WIN_PLUGINS = [
    "windows.info",
    "windows.pslist",
    "windows.pstree",
    "windows.cmdline",
    "windows.netscan",
    "windows.netstat",
    "windows.dlllist",
    "windows.handles",
    "windows.malfind",
    "windows.hashdump",
    "windows.lsadump",
    "windows.registry.hivelist",
    "windows.registry.userassist",
    "windows.consoles",   # console screen BUFFERS (command output) — classic flag spot
    "windows.cmdscan",    # COMMAND_HISTORY (typed commands) — classic flag spot
]

LINUX_PLUGINS = [
    "linux.banner",
    "linux.pslist",
    "linux.pstree",
    "linux.bash",
    "linux.lsmod",
    "linux.lsof",
    "linux.psaux",
    "linux.sockstat",
    "linux.envars",
]


def _run(cmd: list[str], log_fn: Callable[[str], None], timeout: int = 300) -> tuple[int, str, str]:
    log_fn(f"$ {' '.join(cmd)}")
    # Per-op timeout so ONE hung/pathological plugin (a corrupt dump, an
    # unresolved PDB fetch) can't block until the whole-container wall
    # (FORENSIC_TIMEOUT_S) fires and kills the job + every remaining plugin.
    # rc=124 flows into the caller's existing rc!=0 branch → recorded + SKIPPED,
    # and each completed plugin's JSON is already written to disk incrementally.
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return cp.returncode, cp.stdout, cp.stderr
    except subprocess.TimeoutExpired:
        log_fn(f"[timeout] {cmd[0]} …{cmd[-1]} exceeded {timeout}s — skipping")
        return 124, "", f"timed out after {timeout}s"
    except Exception as e:  # tool missing / spawn failure — record + continue
        log_fn(f"[error] {cmd[0]} …{cmd[-1]}: {e!r}")
        return 1, "", str(e)


def _detect_os(image: Path, log_fn) -> str:
    """Probe windows.info first (fastest reliable detector)."""
    rc, out, _ = _run(
        ["vol", "-q", "-f", str(image), "-r", "json","windows.info"],
        log_fn,
    )
    if rc == 0 and out.strip().startswith("["):
        return "windows"
    rc, out, _ = _run(
        ["vol", "-q", "-f", str(image), "-r", "json","linux.banner"],
        log_fn,
    )
    if rc == 0 and out.strip().startswith("["):
        return "linux"
    return "unknown"


def process_memory(
    image: Path,
    out_dir: Path,
    target_os: str,
    log_fn: Callable[[str], None],
) -> dict:
    vol_out = out_dir / "volatility"
    vol_out.mkdir(parents=True, exist_ok=True)

    if target_os == "auto":
        target_os = _detect_os(image, log_fn)
    log_fn(f"memory target_os: {target_os}")

    plugins = WIN_PLUGINS if target_os == "windows" else LINUX_PLUGINS if target_os == "linux" else []
    summary = {"target_os": target_os, "plugins": {}}

    for plugin in plugins:
        rc, out, err = _run(
            ["vol", "-q", "-f", str(image), "-r", "json",plugin],
            log_fn,
        )
        plugin_file = vol_out / f"{plugin}.json"
        if rc == 0 and out.strip():
            try:
                parsed = json.loads(out)
                plugin_file.write_text(json.dumps(parsed, indent=2, default=str))
                summary["plugins"][plugin] = {"rc": 0, "rows": len(parsed) if isinstance(parsed, list) else 1}
            except json.JSONDecodeError:
                plugin_file.write_text(out)
                summary["plugins"][plugin] = {"rc": 0, "rows": None, "note": "non-json output"}
        else:
            summary["plugins"][plugin] = {"rc": rc, "stderr_tail": err[-300:]}

    return summary
