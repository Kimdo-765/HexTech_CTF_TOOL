# gdb-init.py — GEF context-off + quiet defaults for batch debugger runs.
#
# Source this FIRST in every probe script so the per-step `context` panel
# (registers + stack + code + trace, ~30 lines per breakpoint hit) is
# suppressed. The debugger subagent gets terse, structured output instead
# of a wall of pretty-printed framebuffer dumps it didn't ask for.
#
# Usage in a probe.py:
#   import gdb
#   gdb.execute("source /opt/scaffold/gdb-init.py")
#   gdb.execute("file ./chal")
#   # ... your breakpoints + dumps ...
#
# Or via the CLI:
#   gdb-clean -nh -batch -x /opt/scaffold/gdb-init.py -x probe.py

import gdb

# Core gdb quietness.
for cmd in (
    "set pagination off",
    "set confirm off",
    "set verbose off",
    "set print pretty off",
    "set print elements 32",
    "set logging redirect on",
    "set height 0",
    "set width 0",
):
    try:
        gdb.execute(cmd, to_string=False)
    except gdb.error:
        pass

# GEF: kill the auto-context panel + tone the rest down. These are
# no-ops if GEF wasn't autoloaded (e.g. `GDB_NO_GEF=1`).
for cmd in (
    # Hide the per-step context block entirely. Individual `gef ...`
    # commands still work on demand; we just don't want them printed
    # on every stop.
    "gef config context.enable False",
    "gef config context.show_registers False",
    "gef config context.show_stack False",
    "gef config context.show_code False",
    "gef config context.show_args False",
    "gef config context.show_threads False",
    "gef config context.show_trace False",
    "gef config context.show_extra False",
    # Telescope: clamp depth so manual dumps stay readable.
    "gef config context.nb_lines_stack 6",
    "gef config context.nb_lines_code 4",
    # Suppress GEF's per-startup "Loaded 90 commands" if it's printed
    # mid-session (rare with `-batch` but cheap to silence).
    "gef config gef.show_deprecation_warnings False",
):
    try:
        gdb.execute(cmd, to_string=False)
    except gdb.error:
        pass

# Sentinel so probes can verify the init ran.
gdb.execute('echo [gdb-init] ready\\n')
