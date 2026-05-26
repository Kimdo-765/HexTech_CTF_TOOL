#!/usr/bin/env python3
"""heap-probe — gdb harness that emits a JSON timeline of heap state.

Standardizes the "alloc / free a bunch, dump tcache + fastbin + unsorted
at each breakpoint" recipe the debugger subagent re-wrote on every call.
Lets the agent ask "what's the heap state at each free?" in ONE Bash
call instead of a hand-rolled gdb session.

Usage:

    heap-probe ./bin/prob \\
        --input /tmp/menu.in \\
        --break "free+8" \\
        --break "vuln+0x42" \\
        --dump tcache,fastbin,unsorted,chunks,vmmap \\
        --max-hits 20 \\
        --out /tmp/heap_state.json

Outputs JSON:

    {"events": [
        {"pc": "0x4011a4", "function": "free", "hit": 1,
         "dumps": {"tcache": "<gef raw>", "fastbin": "<gef raw>", ...}},
        ...
    ], "hits": 7}

The --dump tokens map to GEF commands:
    tcache    → heap bins tcache
    fastbin   → heap bins fastbin
    unsorted  → heap bins unsorted
    small     → heap bins small
    large     → heap bins large
    chunks    → heap chunks
    vmmap     → vmmap
    regs      → info registers
    <other>   → passed verbatim as `gdb.execute(<other>, to_string=True)`

Use --gdb gdb-multiarch for aarch64 / arm chals. The harness sources
GEF via /etc/gdb/gdbinit (autoloaded in the worker image).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


# Embedded gdb-python harness — written to /tmp and run via `gdb -x`.
# Reads its parameters from HEAP_PROBE_* env vars so we don't have to
# escape complex breakpoint targets through gdb's command-line parser.
_GDB_HARNESS = r"""
import gdb, json, os, sys

EVENTS = []
DUMPS = [d.strip() for d in os.environ.get("HEAP_PROBE_DUMPS", "tcache").split(",") if d.strip()]
MAX_HITS = int(os.environ.get("HEAP_PROBE_MAX_HITS", "20"))
INPUT_FILE = os.environ.get("HEAP_PROBE_INPUT", "")
BREAKS = [b.strip() for b in os.environ.get("HEAP_PROBE_BREAKS", "").split(";;") if b.strip()]
OUT = os.environ.get("HEAP_PROBE_OUT", "/tmp/heap_state.json")


def _safe(cmd: str) -> str:
    try:
        return gdb.execute(cmd, to_string=True) or ""
    except gdb.error as e:
        return f"<gdb.error: {e}>"
    except Exception as e:
        return f"<exception: {type(e).__name__}: {e}>"


_safe("set pagination off")
_safe("set confirm off")
_safe("set print pretty off")
# Disable color escapes so the captured strings are clean.
_safe("set style enabled off")


for bp in BREAKS:
    _safe(f"b *{bp}")


def _alive() -> bool:
    try:
        inf = gdb.selected_inferior()
        return bool(inf and inf.pid != 0)
    except Exception:
        return False


_DUMP_CMD = {
    "tcache":   "heap bins tcache",
    "fastbin":  "heap bins fastbin",
    "unsorted": "heap bins unsorted",
    "small":    "heap bins small",
    "large":    "heap bins large",
    "chunks":   "heap chunks",
    "vmmap":    "vmmap",
    "regs":     "info registers",
}


# Initial run. `gdb.execute("r")` blocks until stop event.
run_cmd = "r"
if INPUT_FILE:
    run_cmd = f"r < {INPUT_FILE}"
try:
    gdb.execute(run_cmd)
except gdb.error:
    # Program exited without hitting any breakpoint, or run failed.
    pass


hits = 0
while hits < MAX_HITS and _alive():
    try:
        frame = gdb.selected_frame()
        pc = int(frame.pc())
    except Exception:
        break
    sym_name = None
    try:
        sym = frame.function()
        sym_name = sym.print_name if sym else None
    except Exception:
        pass

    event = {
        "pc": hex(pc),
        "function": sym_name,
        "hit": hits + 1,
        "dumps": {},
    }
    for d in DUMPS:
        cmd = _DUMP_CMD.get(d, d)  # unrecognized token → raw gdb command
        event["dumps"][d] = _safe(cmd)
    EVENTS.append(event)
    hits += 1
    try:
        gdb.execute("c")
    except gdb.error:
        break


payload = {"events": EVENTS, "hits": hits}
try:
    with open(OUT, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"[heap-probe] wrote {len(EVENTS)} event(s) to {OUT}")
except Exception as e:
    print(f"[heap-probe] failed to write {OUT}: {e}", file=sys.stderr)
    print(json.dumps(payload))


try:
    gdb.execute("quit")
except Exception:
    pass
"""


def main() -> int:
    ap = argparse.ArgumentParser(prog="heap-probe", description=__doc__)
    ap.add_argument("binary", help="Path to the (patchelf'd) binary")
    ap.add_argument(
        "--input", "-i",
        help="Path to a file whose contents become the binary's stdin. "
             "Use sequential menu inputs separated by newlines.",
    )
    ap.add_argument(
        "--break", "-b", action="append", default=[], dest="breaks",
        metavar="TARGET",
        help="Breakpoint target. Repeatable. Accepts any form `b *...` "
             "understands: `main+0x42`, `0x4011a4`, `free`, "
             "`'libc.so.6'::__libc_free`, etc.",
    )
    ap.add_argument(
        "--dump", "-d", default="tcache,fastbin,unsorted",
        help="Comma-separated dump tokens. Known: tcache, fastbin, "
             "unsorted, small, large, chunks, vmmap, regs. Anything "
             "else is passed verbatim to `gdb.execute(..., to_string=True)`.",
    )
    ap.add_argument(
        "--max-hits", type=int, default=20,
        help="Cap on breakpoint hits before forcing exit (default 20).",
    )
    ap.add_argument(
        "--out", "-o", default="/tmp/heap_state.json",
        help="JSON timeline destination (default /tmp/heap_state.json).",
    )
    ap.add_argument(
        "--gdb", default="gdb",
        help="gdb binary. Use `gdb-multiarch` for foreign-arch ELFs.",
    )
    args = ap.parse_args()

    if not args.breaks:
        sys.stderr.write(
            "heap-probe: at least one --break is required. Use "
            "`--break 'free+8'` or `--break 0x4011a4`.\n"
        )
        return 2

    bin_path = Path(args.binary).resolve()
    if not bin_path.is_file():
        sys.stderr.write(f"heap-probe: binary {bin_path} not found\n")
        return 1

    if args.input:
        in_path = Path(args.input).resolve()
        if not in_path.is_file():
            sys.stderr.write(f"heap-probe: input {in_path} not found\n")
            return 1
        input_str = str(in_path)
    else:
        input_str = ""

    # Drop the harness into a temp file. We DON'T delete it on success
    # so the agent can re-run by hand if the JSON capture failed.
    with tempfile.NamedTemporaryFile(
        "w", suffix="_heap_probe.py", delete=False,
    ) as fh:
        fh.write(_GDB_HARNESS)
        script_path = fh.name

    env = os.environ.copy()
    env["HEAP_PROBE_DUMPS"] = args.dump
    env["HEAP_PROBE_MAX_HITS"] = str(args.max_hits)
    env["HEAP_PROBE_INPUT"] = input_str
    env["HEAP_PROBE_BREAKS"] = ";;".join(args.breaks)
    env["HEAP_PROBE_OUT"] = args.out

    cmd = [
        args.gdb, "-batch", "-nh",
        "-ex", "set pagination off",
        "-x", script_path,
        str(bin_path),
    ]
    try:
        res = subprocess.run(cmd, env=env, text=True)
    except FileNotFoundError:
        sys.stderr.write(
            f"heap-probe: {args.gdb} not found. Install gdb (or "
            f"gdb-multiarch for foreign-arch chals).\n"
        )
        return 127

    # If the harness wrote the JSON, echo it to stdout so callers
    # that don't want to read a file get the payload anyway.
    out_path = Path(args.out)
    if out_path.is_file():
        sys.stdout.write(out_path.read_text())
        if not sys.stdout.isatty():
            sys.stdout.write("\n")
    return res.returncode


if __name__ == "__main__":
    sys.exit(main())
