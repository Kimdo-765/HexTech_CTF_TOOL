Heap-pwn exploit scaffolds.

The worker image installs this directory at `/opt/scaffold/`. From the
agent's cwd (the job work dir) copy one as a starting point:

    cp /opt/scaffold/heap_menu.py    ./exploit.py    # menu-driven heap
    cp /opt/scaffold/fsop_wfile.py   ./fsop.py       # FSOP wfile_jumps builder (import)
    cp /opt/scaffold/tcache_poison.py ./tcp.py       # tcache helper (import)
    cp /opt/scaffold/aslr_retry.py    ./aslr.py      # ASLR-retry loop (import)
    cp /opt/scaffold/race_toctou.py   ./race.py      # server-side TOCTOU race (import)

Each scaffold loads `./.chal-libs/libc_profile.json` when present so
version-specific feature flags (safe_linking, tcache_key, hooks_alive)
are read instead of rediscovered. If the chal is non-menu (e.g. single-
shot BoF, custom protocol), do NOT contort it into a scaffold — write
from scratch instead.

Files
-----
heap_menu.py       — menu wrappers (alloc/free/edit/show) + libc-base
                     validation + safe-link + libc_profile.json loader.
                     The most common starting point.
fsop_wfile.py      — _IO_FILE_plus / _IO_wide_data / _wide_vtable
                     builders. Encodes the "vtable LAST" invariant.
                     Import from your exploit.
tcache_poison.py   — safe_link() + alignment_ok() + needs_key_bypass()
                     that branch on libc_profile.json. Import from your
                     exploit.
aslr_retry.py      — aslr_retry(exploit_one, ...) wrapper for the 1/16
                     nibble-race chains. Import + wrap your main fn.
race_toctou.py     — pre-open + barrier + tight sendall pattern for
                     server-side TOCTOU races (counter increment,
                     freelist link, dup-fd). `race_burst` fires one
                     attempt; `race_sweep` brackets inter_send_us
                     across many rounds. Required when remote is
                     single-CPU and TCP-handshake jitter would
                     otherwise dwarf the race window.
