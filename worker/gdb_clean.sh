#!/usr/bin/env bash
# gdb-clean — gdb -batch wrapper that strips GEF's per-invocation banner
# and ANSI color codes from stdout/stderr.
#
# WHY: the debugger subagent runs `gdb -batch -x probe.py` dozens of times
# per session. Each invocation prepends:
#   GEF for linux ready, type `gef` to start, `gef config` to configure
#   90 commands loaded and 5 functions added for GDB 16.3 in 0.00ms ...
# plus xterm-256 escape sequences. That's ~1 KB of pure noise per call
# that the model has to skim through. Job eb616a1eb830 (debugger#2) burned
# ~52 lines of log on these alone. This wrapper folds the same args into
# gdb but post-processes stdout+stderr to drop those.
#
# USAGE:
#   gdb-clean -nh -batch -x probe.py
#   gdb-clean ./binary < input
#   GDB_BIN=/usr/bin/gdb-multiarch gdb-clean -batch -ex 'file ./bin/user' …
#   gdb-multiarch-clean -batch …        # same thing via the $0 shorthand
# Anything you'd pass to `gdb` works. ANSI/banner stripping is unconditional.
#
# If you NEED the banner (rare), call /usr/bin/gdb directly.
#
# FOREIGN ARCHITECTURES: this used to `exec /usr/bin/gdb` unconditionally,
# so a RISC-V / ARM / MIPS target — exactly the case that needs
# gdb-multiarch — had no clean wrapper at all and the agent got GEF's
# banner instead of its disassembly (job 62531f9da538, recon#1 05:19:18:
# `gdb-multiarch -batch … -ex 'disassemble ecall' | head -60` came back as
# the banner, costing a retry). Resolve the underlying gdb instead.

set -o pipefail

# Which gdb to wrap: explicit $GDB_BIN wins, else derive from how we were
# invoked (gdb-multiarch-clean -> gdb-multiarch), else plain gdb.
_gdb="${GDB_BIN:-}"
if [ -z "$_gdb" ]; then
    case "${0##*/}" in
        *multiarch*) _gdb=/usr/bin/gdb-multiarch ;;
        *)           _gdb=/usr/bin/gdb ;;
    esac
fi
if [ ! -x "$_gdb" ]; then
    echo "gdb-clean: $_gdb is not executable" >&2
    exit 127
fi

# Forward all args to gdb. Output is sanitized via two filters:
#   1. sed strips
#        - ANSI CSI sequences (color, cursor moves)
#        - OSC sequences
#        - bare readline prompt-ignore markers \x01 / \x02 that GEF
#          emits around colorized fragments even under `-batch` (gdb
#          16.3 + GEF 2025; without this strip "^GEF" never matches
#          because the line starts with \x01\x02G).
#   2. grep -v drops GEF's banner lines + the boot stats line that
#      starts with "<N> commands loaded".
exec "$_gdb" "$@" 2>&1 | \
    sed -r 's/\x1b\[[0-9;]*[mGKHfABCDEFsuJ]//g; s/\x1b\][^\x07]*\x07//g; s/[\x01\x02]//g' | \
    grep -Ev '^(GEF for linux ready|[0-9]+ commands loaded and [0-9]+ functions added|\[!\] To get gef-extras)' || true
