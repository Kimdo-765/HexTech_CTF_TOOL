"""libc-version-keyed RCE path catalog for heap exploitation.

Used by `modules.pwn.analyzer._build_pre_recon_prompt` to inject a
ready-made shortlist of canonical RCE targets into the pre-recon
prompt. Without it the main agent re-derives version-specific facts
("does glibc 2.23 have vtable check?", "is tcache safe-linking
xor-encoded here?") from scratch every job — observed cost on job
4a6bd25a0d1d: main spent ~30 min on FSOP analysis and still missed
the canonical 2.23 path (_IO_2_1_stdout_ vtable hijack — no check
on this version).

Each entry is one candidate RCE end-of-chain, ordered easiest first.
Version keys match by major.minor; lookup picks the largest catalog
key ≤ detected version (so glibc 2.31 inherits 2.27 entries when
no 2.31 entry exists).
"""

from __future__ import annotations


LIBC_RCE_PATHS: dict[str, list[dict[str, str]]] = {
    "2.23": [
        {
            "target": "__free_hook = system",
            "method": (
                "fastbin dup → arbitrary alloc at __free_hook; "
                "then free(chunk containing '/bin/sh')"
            ),
            "prereq": (
                "fastbin dup or any arbitrary 8-byte write on libc page; "
                "libc-base leak"
            ),
            "notes": (
                "Hooks alive on 2.23. One-shot win once write primitive "
                "lands; no FSOP or ROP required."
            ),
        },
        {
            "target": "__malloc_hook = one_gadget",
            "method": (
                "fastbin dup → arbitrary alloc at __malloc_hook-0x23 "
                "(0x7f size byte inside libc); overwrite hook with "
                "one_gadget; trigger via any malloc()"
            ),
            "prereq": "fastbin dup; libc-base leak",
            "notes": (
                "glibc 2.23 one_gadgets have very weak constraints — "
                "candidates 0x45216 / 0x4526a / 0xf02a4 / 0xf1147. "
                "Pick by rsp/r12 state at trigger site."
            ),
        },
        {
            "target": "_IO_2_1_stdout_ vtable hijack (FSOP)",
            "method": (
                "fastbin alloc at stdout-0x33 (uses 0x7f byte inside "
                "_IO_2_1_stdout_ as the fake-chunk size header); "
                "overwrite vtable to point at fake jump table whose "
                "__overflow slot is one_gadget; trigger via puts/printf"
            ),
            "prereq": "fastbin dup; libc-base leak",
            "notes": (
                "NO vtable check on 2.23 (the check was introduced in "
                "2.24). THIS IS THE CANONICAL FSOP for this version — "
                "do NOT confuse with House of Apple / wfile_jumps "
                "(those are for 2.34+ after hooks were removed)."
            ),
        },
        {
            "target": "unsorted-bin attack",
            "method": (
                "free an unsorted-size chunk then edit its bk to "
                "(target - 0x10); next allocation of same size writes "
                "main_arena address into target QWORD"
            ),
            "prereq": (
                "free-then-edit on unsorted-size chunk (size > 0x80); "
                "target must accept a large libc address as its value"
            ),
            "notes": (
                "Use to corrupt global_max_fast (then any size becomes "
                "fastbin-eligible) or _IO_list_all (FSOP via "
                "_IO_flush_all_lockp at abort/exit)."
            ),
        },
        {
            "target": "House of Orange",
            "method": (
                "overwrite top-chunk size header to a value that "
                "passes glibc's sanity check but is too small for the "
                "next request → glibc frees the top chunk into "
                "unsorted bin → leak + _IO_list_all corruption via "
                "subsequent unsorted-bin attack → abort triggers "
                "_IO_flush_all_lockp → system('/bin/sh')"
            ),
            "prereq": (
                "OOB write reaching top-chunk size field (heap "
                "overflow past the active chunk); ability to trigger "
                "an exit/abort path that flushes stdio"
            ),
            "notes": (
                "Useful when there is NO free() primitive available "
                "but you can overflow the top chunk. Postjudge on "
                "job 4a6bd25a0d1d explicitly recommended this path."
            ),
        },
    ],
    "2.27": [
        {
            "target": "tcache poison → __free_hook = system",
            "method": (
                "double-free in tcache (no tcache_key check before "
                "2.29); next two allocs of same size — first reads "
                "back the poisoned fd, second lands at __free_hook"
            ),
            "prereq": "1× UAF or double-free; libc-base leak",
            "notes": (
                "EASIEST version. No fastbin 0x7f abuse needed because "
                "tcache has no size check on alloc. Hooks still alive."
            ),
        },
        {
            "target": "tcache poison → __malloc_hook = one_gadget",
            "method": "same as above; target __malloc_hook instead",
            "prereq": "same",
            "notes": (
                "Use when register/stack state at trigger suits "
                "one_gadget better than free('/bin/sh')."
            ),
        },
    ],
    "2.29": [
        {
            "target": "tcache poison → __free_hook (tcache_key bypass)",
            "method": (
                "tcache_key check requires the slot's key field to be "
                "cleared before re-freeing — alloc one chunk from the "
                "poisoned tcache slot to clear key, then re-free"
            ),
            "prereq": (
                "tcache UAF + ability to allocate 2× from same slot; "
                "libc-base leak"
            ),
            "notes": "tcache_key check added 2.29. Otherwise as 2.27.",
        },
    ],
    "2.32": [
        {
            "target": "tcache poison with safe_linking",
            "method": (
                "leak heap-base; encode fd as "
                "(target ^ (heap_base >> 12)); poison tcache slot with "
                "encoded fd; alloc lands at target"
            ),
            "prereq": (
                "BOTH heap-base AND libc-base leaks; tcache UAF or "
                "double-free with tcache_key bypass"
            ),
            "notes": (
                "safe_linking introduced 2.32. Need heap leak now "
                "(prior versions didn't). All earlier paths still work "
                "once xor-encoding is applied to fd writes."
            ),
        },
    ],
    "2.34": [
        {
            "target": "House of Apple 2 / _IO_wfile_jumps",
            "method": (
                "forge FILE struct with custom _wide_data + _vtable "
                "pointing into _IO_wfile_jumps; trigger "
                "_IO_wfile_overflow via fflush/exit; chain into "
                "setcontext or system"
            ),
            "prereq": (
                "libc-base leak; arbitrary write at a libc page "
                "(typically via tcache poison or large-bin attack)"
            ),
            "notes": (
                "Hooks REMOVED in 2.34. FSOP via wfile_jumps is the "
                "modern canonical path. Do NOT try __free_hook / "
                "__malloc_hook — they no longer exist."
            ),
        },
        {
            "target": "ROP via setcontext / mprotect",
            "method": (
                "overwrite a thread-local exit handler or "
                "_IO_2_1_stderr_._lock with controlled stack; pivot "
                "via setcontext+0x3d; ROP through mprotect → shellcode"
            ),
            "prereq": "stack leak; arbitrary write",
            "notes": "Fallback when FSOP path is patched/hardened.",
        },
    ],
}


# FSOP-as-leak catalog. Job 37b33d2a741b's chal had setvbuf(stdout,
# _IONBF) which led judge#1 to rule out _IO_write_base manipulation
# ("not flushed under unbuffered"). The official solver showed that a
# crafted `_flags` magic + write_ptr LSB trick DOES leak even under
# _IONBF — the unbuffered branch still emits when _flags has the right
# bits AND write_ptr > write_base. This catalog documents the magic
# values + main_arena→stdout distance so future runs surface the
# possibility before the conservative ruling.
LIBC_LEAK_VIA_FSOP: dict[str, dict[str, object]] = {
    # glibc 2.27..2.33 — _IO_2_1_stdout_ at libc + (offset varies per
    # version, but main_arena→stdout distance is stable per build).
    # main_arena.bins[0] (= main_arena+0x60) is the typical libc
    # address surfaced on the heap via unsorted-bin fd/bk.
    "2.27": {
        "stdout_flags_magic": 0xfbad1800,
        "magic_meaning": (
            "_IO_MAGIC (0xfbad0000) | _IO_USER_BUF (0x1) "
            "| _IO_NO_WRITES (0x8) — emits buffer even under _IONBF "
            "because the unbuffered-write path checks magic, not the "
            "_IO_UNBUFFERED bit"
        ),
        "write_ptr_lsb_zero": True,
        "main_arena_to_stdout_typical": (
            "ubuntu 18.04 libc-2.27: ~0xa00. main_arena.bins[0] = "
            "main_arena+0x60; stdout = main_arena + (~0xa00-0x60). "
            "Verify with `p (uint64_t)stdout - (uint64_t)&main_arena` "
            "in gdb against the chal's bundled libc."
        ),
    },
    "2.34": {
        "stdout_flags_magic": 0xfbad1800,
        "magic_meaning": "Same as 2.27 — magic survives across versions.",
        "write_ptr_lsb_zero": True,
        "main_arena_to_stdout_typical": (
            "ubuntu 22.04 libc-2.35: ~0xa00. Same calculation."
        ),
    },
    "2.39": {
        "stdout_flags_magic": 0xfbad1800,
        "magic_meaning": "Same magic.",
        "write_ptr_lsb_zero": True,
        "main_arena_to_stdout_typical": (
            "ubuntu 24.04 libc-2.39: 0xb00 (verified on job "
            "37b33d2a741b — official solver computes "
            "stdout - main_arena = 0xb00). main_arena.bins[0] = "
            "main_arena + 0x60; the unsorted-bin chunk fd/bk reach "
            "this address."
        ),
    },
}


def render_fsop_leak_table(libc_version: str | None) -> str:
    """Render the FSOP-as-leak entry for the pre-recon prompt.

    When unsorted-bin attack / hook-overwrite leak channels look
    blocked, the FSOP-leak path (write_base/write_ptr corruption via
    a long-range single OOB write) is often the next viable vector
    on modern glibc. This block puts the canonical magic in front
    of pre-recon so it doesn't have to derive it from web searches
    (which the main agent can't run anyway under subagent isolation).

    The trick: heap typically has main_arena.bins[0] (= main_arena
    + 0x60) sitting in an unsorted-bin chunk's fd. If you can forge
    that as a fake std::string._M_p, a memcpy of length
    (main_arena_to_stdout + sizeof(_IO_FILE_plus)) spans from
    main_arena across to stdout — single OOB write touches all of
    main_arena and the stdout FILE struct.
    """
    if not libc_version:
        return ""
    target_key = _pick_key_leak(libc_version)
    if not target_key:
        return ""
    e = LIBC_LEAK_VIA_FSOP[target_key]
    return (
        f"FSOP-AS-LEAK TABLE — glibc {target_key} (matched against "
        f"detected {libc_version}). Consider this BEFORE concluding "
        f"'no leak channel'. Especially when:\n"
        f"  - stdout is _IONBF (setvbuf(_, NULL, _IONBF, 0)) — the\n"
        f"    naive ruling 'unbuffered ⇒ no write_base trick' is WRONG\n"
        f"    when the magic below is used.\n"
        f"  - heap surfaces a libc pointer in unsorted-bin fd/bk =\n"
        f"    main_arena.bins[0] (= main_arena+0x60).\n"
        f"  - the OOB write primitive lets you control the byte\n"
        f"    LENGTH (e.g. cin >> name has no cap).\n\n"
        f"Magic for `_IO_2_1_stdout_._flags`:\n"
        f"  0x{e['stdout_flags_magic']:x}  ← {e['magic_meaning']}\n"
        f"write_ptr LSB → 0x00 (keep write_ptr > write_base while\n"
        f"forcing flush at an aligned offset).\n\n"
        f"Distance: {e['main_arena_to_stdout_typical']}\n\n"
        f"Leak shape: forge fake std::string with _M_p = main_arena.bins[0];\n"
        f"send a name of length ≥ (main_arena_to_stdout + 0x40); the\n"
        f"memcpy fills main_arena…stdout with crafted bytes; next cout\n"
        f"emits the buffer (leak observable). Then a second OOB write\n"
        f"on the same fake-string slot lands an FSOP _IO_wfile_jumps\n"
        f"chain (see RCE TARGET TABLE)."
    )


def _pick_key_leak(version: str) -> str | None:
    """Largest catalog key ≤ version (semver-style)."""
    try:
        v_tup = _parse(version)
    except Exception:
        return None
    best: str | None = None
    best_tup: tuple[int, int] = (0, 0)
    for k in LIBC_LEAK_VIA_FSOP:
        try:
            k_tup = _parse(k)
        except Exception:
            continue
        if k_tup <= v_tup and k_tup >= best_tup:
            best = k
            best_tup = k_tup
    return best


def render_rce_table(libc_version: str | None) -> str:
    """Render an RCE candidate block for the pre-recon prompt.

    Picks the largest catalog key ≤ libc_version (so 2.31 → 2.27
    entries apply). Returns the empty string when no version is
    given or no key matches; caller can drop the section entirely.
    """
    if not libc_version:
        return ""
    target_key = _pick_key(libc_version)
    if not target_key:
        return ""
    paths = LIBC_RCE_PATHS[target_key]
    lines = [
        f"RCE TARGET TABLE — canonical end-of-chain candidates for "
        f"glibc {target_key} (matched against detected "
        f"{libc_version}). Pick ONE that the PRIMITIVES section can "
        f"actually feed; pivot to next entry if a prerequisite fails "
        f"empirically. DO NOT propose a target outside this list "
        f"unless you have explicit evidence the version-specific "
        f"facts here are wrong:"
    ]
    for i, p in enumerate(paths, 1):
        lines.append(
            f"  [{i}] {p['target']}\n"
            f"      method  : {p['method']}\n"
            f"      prereq  : {p['prereq']}\n"
            f"      notes   : {p['notes']}"
        )
    return "\n".join(lines)


def _pick_key(version: str) -> str | None:
    """Return the largest catalog key ≤ `version` (major.minor compare)."""
    try:
        v_tup = _parse(version)
    except Exception:
        return None
    best: str | None = None
    best_tup: tuple[int, int] = (0, 0)
    for k in LIBC_RCE_PATHS:
        try:
            k_tup = _parse(k)
        except Exception:
            continue
        if k_tup <= v_tup and k_tup >= best_tup:
            best = k
            best_tup = k_tup
    return best


def _parse(v: str) -> tuple[int, int]:
    parts = v.split(".")
    return (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
