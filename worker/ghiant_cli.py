#!/usr/bin/env python3
"""ghiant — agent-callable Ghidra wrapper.

Two subcommands the agent can call from Bash inside the worker
container:

    ghiant <binary> [outdir]
        Full decompile. Spawns the decompiler sibling container,
        analyzes the binary if needed (otherwise reuses cached
        project), writes per-function .c files to <outdir> (default
        ./decomp/). Result is on disk, durable across SDK turns.

    ghiant xrefs <binary> <symbol_or_addr> [--limit N]
        Cross-reference query against the cached Ghidra project. If
        no cache exists yet it bootstraps a full analysis first.
        Subsequent xrefs calls reuse the project and finish in
        seconds. Prints a JSON object on stdout with the resolved
        target + a list of {from, ref_type, function, function_addr}
        entries. Default --limit 50.

Both subcommands require JOB_ID in env (set by the orchestrator).
The binary path may be absolute (must be under /data/jobs/<JOB_ID>/)
or relative to cwd; the wrapper resolves it.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, "/app")

from modules.pwn.decompile import run_decompiler, run_decompiler_xrefs


USAGE = (
    "usage: ghiant <binary> [outdir]\n"
    "       ghiant xrefs <binary> <symbol_or_addr> [--limit N]\n"
)


def _resolve_binary(arg: str, job_root: Path) -> Path:
    raw = Path(arg)
    binary = (raw if raw.is_absolute() else (Path.cwd() / raw)).resolve()
    if not binary.is_file():
        sys.stderr.write(f"binary not found: {binary}\n")
        sys.exit(2)
    try:
        binary.relative_to(job_root)
    except ValueError:
        sys.stderr.write(
            f"binary must be under job dir ({job_root}); got {binary}\n"
        )
        sys.exit(2)
    return binary


def _binary_rel(binary: Path, job_root: Path) -> str:
    return str(binary.relative_to(job_root))


def cmd_decomp(job_id: str, job_root: Path, argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="ghiant")
    parser.add_argument("binary")
    parser.add_argument("outdir", nargs="?", default=None)
    ns = parser.parse_args(argv)

    binary = _resolve_binary(ns.binary, job_root)
    out_dir = (
        Path(ns.outdir).resolve() if ns.outdir
        else (Path.cwd() / "decomp")
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    binary_rel = _binary_rel(binary, job_root)
    print(
        f"[ghiant] decompiling {binary_rel} (this can take 1–3 min on first call; "
        f"subsequent calls reuse the cached project) ...",
        file=sys.stderr, flush=True,
    )
    try:
        decomp_dir, _logs = run_decompiler(job_id, binary_rel)
    except Exception as e:
        sys.stderr.write(f"[ghiant] decompiler failed: {e}\n")
        return 1

    count = 0
    for f in decomp_dir.glob("*.c"):
        dst = out_dir / f.name
        if f.resolve() != dst.resolve():
            shutil.copy(f, dst)
        count += 1
    if count == 0:
        sys.stderr.write("[ghiant] no .c files produced\n")
        return 1

    print(f"[ghiant] {count} functions decompiled to {out_dir}", flush=True)
    print("[ghiant] tip: grep for sinks, e.g.:", flush=True)
    print(f"  grep -lE 'gets|strcpy|sprintf|scanf' {out_dir}/*.c", flush=True)
    print("[ghiant] cross-reference queries: ghiant xrefs <bin> <sym|addr>", flush=True)
    return 0


def cmd_xrefs(job_id: str, job_root: Path, argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="ghiant xrefs")
    parser.add_argument("binary")
    parser.add_argument(
        "target",
        help="Symbol name (e.g. main, vuln) or hex address (e.g. 0x401120)",
    )
    parser.add_argument("--limit", type=int, default=50)
    ns = parser.parse_args(argv)

    binary = _resolve_binary(ns.binary, job_root)
    binary_rel = _binary_rel(binary, job_root)

    print(
        f"[ghiant xrefs] querying {ns.target!r} in {binary_rel} ...",
        file=sys.stderr, flush=True,
    )
    try:
        payload, _logs = run_decompiler_xrefs(
            job_id, binary_rel, ns.target, limit=ns.limit,
        )
    except Exception as e:
        sys.stderr.write(f"[ghiant xrefs] failed: {e}\n")
        return 1

    # Pretty-print the JSON to stdout so the agent can read it directly
    # from the Bash tool result. The on-disk copy at
    # <jobdir>/.ghidra_proj/xrefs.json is overwritten on each call;
    # printing here makes the result visible without a separate Read.
    print(json.dumps(payload, indent=2))

    if payload.get("kind") is None:
        sys.stderr.write(
            f"[ghiant xrefs] target {ns.target!r} did not resolve as symbol "
            f"or address — is the binary stripped, or is the symbol mangled?\n"
        )
        return 1

    found = payload.get("found", 0)
    shown = payload.get("shown", 0)
    sys.stderr.write(
        f"[ghiant xrefs] found {found}, shown {shown}"
        + (" (truncated)" if payload.get("truncated") else "")
        + "\n"
    )
    return 0


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        sys.stderr.write(USAGE)
        return 2

    job_id = os.environ.get("JOB_ID", "")
    if not job_id:
        sys.stderr.write("JOB_ID env not set; ghiant must be run inside an agent job.\n")
        return 2

    job_root = Path(f"/data/jobs/{job_id}").resolve()
    if not job_root.is_dir():
        sys.stderr.write(f"job dir not found: {job_root}\n")
        return 2

    # Subcommand dispatch. If the first arg is a known verb, treat the
    # rest as that subcommand's args; otherwise it's the legacy decomp
    # form `ghiant <binary> [outdir]`.
    head = sys.argv[1]
    rest = sys.argv[2:]
    if head == "xrefs":
        return cmd_xrefs(job_id, job_root, rest)
    if head == "decomp":
        return cmd_decomp(job_id, job_root, rest)
    return cmd_decomp(job_id, job_root, sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
