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
