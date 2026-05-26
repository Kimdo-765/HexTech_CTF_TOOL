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
# Anything you'd pass to `gdb` works. ANSI/banner stripping is unconditional.
#
# If you NEED the banner (rare), call /usr/bin/gdb directly.

set -o pipefail

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
exec /usr/bin/gdb "$@" 2>&1 | \
    sed -r 's/\x1b\[[0-9;]*[mGKHfABCDEFsuJ]//g; s/\x1b\][^\x07]*\x07//g; s/[\x01\x02]//g' | \
    grep -Ev '^(GEF for linux ready|[0-9]+ commands loaded and [0-9]+ functions added|\[!\] To get gef-extras)' || true
