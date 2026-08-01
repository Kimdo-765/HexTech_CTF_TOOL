import asyncio
import json
import os
import re
import shutil
import signal
import subprocess
import time
import tempfile
import traceback
from pathlib import Path
from typing import Optional

import anyio

from modules._common import (
    cleanup_job_processes,
    collect_outputs,
    extract_cost,
    prior_session_cost,
    job_dir,
    log_line,
    make_main_session_options,
    load_cached_pre_recon,
    module_autoboot,
    js_engine_block,
    prior_work_dirs,
    read_meta,
    resolve_effort,
    resolve_main_model,
    run_main_agent_session,
    run_pre_recon,
    run_report_phase,
    scan_job_for_flags,
    store_pre_recon_cache,
    write_meta,
)
from modules._events import emit_event
from modules._runner import attempt_sandbox_run
from modules.pwn.libc_targets import render_fsop_leak_table, render_rce_table
from modules.pwn.prompts import SYSTEM_PROMPT, build_user_prompt, looks_heap_advanced
from modules.settings_io import apply_to_env, get_setting


# Filename patterns that ARE standard shipped libraries — anything NOT
# matching these is treated as a chal-author-supplied custom .so and
# becomes a primary attack surface. The list is conservative on purpose:
# we'd rather flag a real glibc helper as "custom" once than miss a
# chal-shipped wrapper whose exported functions hide the primitive.
_STANDARD_LIB_PREFIXES = (
    "libc.so", "libc-",            # glibc
    "ld-linux", "ld-musl",         # dynamic loaders
    "libm.so", "libm-",            # libm
    "libdl.so", "libdl-",          # libdl
    "libpthread.so", "libpthread-",
    "librt.so", "librt-",
    "libresolv.so", "libresolv-",
    "libnsl.so", "libnsl-",
    "libutil.so", "libutil-",
    "libcrypt.so", "libcrypt-",
    "libnss_",                     # NSS plugins
    "libgcc_s.so",
    "libstdc++.so",
    # OpenSSL (libcrypto / libssl). Job 44dd25365173 shipped
    # libcrypto.so.3 in ./.chal-libs/; the prior heuristic
    # misclassified it as a chal-author wrapper, autoboot's custom-lib
    # Ghidra decomp burned 2m40s and wrote 9706 .c files (500KB+ on
    # disk) for a stock OpenSSL build. OpenSSL is part of the chal's
    # runtime, not its attack surface. If a chal's bug really IS inside
    # a custom OpenSSL fork the operator can rebuild with the
    # offending name (e.g. `libcrypto_patched.so.3`) and recon will
    # still flag it as non-standard.
    "libcrypto.so", "libcrypto-",
    "libssl.so", "libssl-",
)


def _is_standard_libname(name: str) -> bool:
    n = name.lower()
    return any(n.startswith(p) for p in _STANDARD_LIB_PREFIXES)


# Section titles the heap_advanced pre-recon prompt mandates. Pre-recon
# agents have a tendency to silently drop sections they decide are "not
# relevant" — observed across 4 consecutive jobs (96cd1092b992 →
# 636e5084da2b → 44dd25365173 → 7220cb10b2db) where the prompt asked for
# MANDATORY SECTION HEADERS but reply contained 0 of the 4 new sections.
# When any are absent we respawn the recon ONCE with an explicit reminder.
_HEAP_MANDATORY_SECTIONS = (
    "INT-OVERFLOW ANALYSIS",
    "HEAP STATE MATRIX",
    "ENV-AWARE PATHS",
    "RCE TARGET TABLE",
)


def _missing_pre_recon_sections(reply: str, mandatory: tuple[str, ...]) -> list[str]:
    """Return mandatory section titles absent from the recon reply.

    Substring match — pre-recon may quote a title inside a code block or
    Markdown header, so we don't require a specific format. Order is
    preserved (matches `mandatory`) so the respawn message hints at the
    sections the recon should add first.
    """
    return [s for s in mandatory if s not in reply]


# Work-tree signals that promote a chal to heap_advanced even when the
# operator's description is empty. Job 583e3dd12421 (glibc 2.39 +
# vector<string> OOB chal) shipped with description="" so the
# description-only `_looks_heap_advanced` returned False, which disabled
# both the mandatory HEAP STATE MATRIX / INT-OVERFLOW / ENV-AWARE / RCE
# TABLE sections in pre-recon AND the auto-respawn safety net for them.
# The chal was unambiguously heap-pwn (libstdc++ on heap + FSOP target
# + verified=true OOB write primitive in chain.json) — the heuristic
# just couldn't see it because it only looked at the description string.
_HEAP_SOURCE_KEYWORDS = (
    # C heap APIs
    "malloc", "calloc", "realloc", "free(",
    # C++ heap APIs and STL types whose backing storage hits the heap
    "operator new", "new ", "delete ", "delete[]",
    "std::vector", "std::string", "std::map", "std::deque",
    "std::list", "std::unordered_map", "basic_string",
    # heap-pwn keywords directly in source / comments
    "fastbin", "tcache", "unsorted", "_IO_FILE", "_IO_2_1",
    "__free_hook", "__malloc_hook", "vtable",
)


def _heap_signals_present(work_dir: Path, custom_libs: list[str]) -> bool:
    """Multi-signal heap-advanced detection for chals with empty/sparse
    descriptions. Any one of the following promotes heap_kw to True:

      1. Custom chal libraries detected (libsalloc.so etc.) — wrappers
         around malloc/free are nearly always the chal's attack surface.
      2. C++ heap stdlib shipped in .chal-libs (libstdc++.so.6 present)
         AND libc_profile.json was generated — strong hint the chal
         binary links against C++ heap-aware containers.
      3. chal source directory (./chal/) contains files with heap
         keywords: malloc/free/operator new/vector/string/tcache/FSOP
         markers. Detected via lightweight grep on .c/.cc/.cpp/.h/.hpp
         files (limited to chal/ tree to avoid scanning the world).

    Read-only, ~50ms worst case; results cached only on the caller side.
    """
    if custom_libs:
        return True

    chal_libs = work_dir / ".chal-libs"
    libstdcxx_present = any(
        (chal_libs / n).is_file()
        for n in ("libstdc++.so.6", "libstdc++.so")
    )
    profile_present = (chal_libs / "libc_profile.json").is_file()
    if libstdcxx_present and profile_present:
        return True

    chal_dir = work_dir / "chal"
    if chal_dir.is_dir():
        src_exts = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".S"}
        try:
            for p in chal_dir.rglob("*"):
                if not p.is_file() or p.suffix not in src_exts:
                    continue
                # Files in chal/ are small (chal source); read fully.
                try:
                    text = p.read_text(errors="ignore")
                except OSError:
                    continue
                low = text.lower()
                if any(kw.lower() in low for kw in _HEAP_SOURCE_KEYWORDS):
                    return True
        except Exception:
            pass

    return False


def _read_libc_version(work_dir: Path) -> str | None:
    """Pull glibc major.minor from libc_profile.json (chal-libc-fix output).

    Returns None if the profile is missing or unparseable; caller should
    treat that as "version-unknown" and skip version-specific prompt
    injection rather than guessing.
    """
    profile = work_dir / ".chal-libs" / "libc_profile.json"
    if not profile.is_file():
        return None
    try:
        data = json.loads(profile.read_text())
    except Exception:
        return None
    v = data.get("version")
    return str(v) if v else None


def _detect_custom_libs(work_dir: Path) -> list[str]:
    """Scan ./.chal-libs/ for chal-author-supplied .so files.

    Returns the bare filenames of any .so whose name doesn't match a
    standard glibc / ld / libgcc / libstdc++ pattern. These are the
    files whose EXPORTS are the most likely place to find the
    challenge's primitive — chal authors who ship a custom .so almost
    always do so because they've wrapped a standard libc function with
    additional checks, side effects, or alternate semantics, and ONE
    of those wrappers has a bug.

    Examples observed in the wild:
      libsalloc.so          (wraps malloc/free with canary checks)
      safe_io.so            (wraps read/write with bounds checks)
      chal_alloc.so         (custom slab allocator with header bug)
      sandbox.so            (LD_PRELOAD wrapper around open/execve)

    Returns sorted list of bare filenames. Empty list when only
    standard libs are staged (most jobs).
    """
    out: list[str] = []
    libs_dir = work_dir / ".chal-libs"
    if not libs_dir.is_dir():
        return out
    try:
        for p in libs_dir.iterdir():
            if not p.is_file():
                continue
            n = p.name
            # Skip non-.so files (libc_profile.json, ld scripts, etc.)
            if ".so" not in n.lower():
                continue
            if _is_standard_libname(n):
                continue
            out.append(n)
    except OSError:
        pass
    return sorted(out)


def _build_pre_recon_prompt(
    *,
    binary_name: str,
    target: str | None,
    heap_advanced: bool,
    chal_unpacked: bool,
    custom_libs: list[str] | None = None,
    libc_version: str | None = None,
    js_engine: bool = False,
) -> str:
    """Build the prompt for the orchestrator-driven recon subagent that
    runs BEFORE main's first turn. Recon's job: static-map the binary so
    main starts with a ready inventory instead of doing its own objdump
    walk."""
    parts: list[str] = []
    parts.append(
        "STATIC TRIAGE REQUEST (pre-flight for the main exploit writer)."
    )
    parts.append(
        f"BINARY: ./bin/{binary_name}"
        + (f"   (cwd = work dir; ./.chal-libs/ holds the chal libs)"
           if chal_unpacked else "")
    )
    if target:
        parts.append(f"REMOTE: {target}")
    if js_engine:
        # autoboot skipped the ghidra pre-bake for this job precisely because
        # a multi-MB engine build exhausts the decompiler's 4 GB / 900 s
        # budget — telling recon to run it here reintroduces the exact cost
        # the early return exists to avoid.
        parts.append(
            "This is a PREBUILT JAVASCRIPT ENGINE (d8 / js / jsc), not a "
            "chal-authored binary. DO NOT run `ghiant` on it and do not try "
            "to decompile it — a multi-MB engine build exhausts the "
            "decompiler and produces nothing usable. `./prob`, "
            "`./.chal-libs/libc_profile.json` and `./decomp/` do NOT exist "
            "for this job. Triage from `./V8_PREFLIGHT.md` (already written: "
            "version, exposed globals, build config, the patch split), the "
            "challenge's own patch/source, and by RUNNING the engine."
        )
    else:
        parts.append(
            "If `./decomp/` is missing, run `ghiant ./bin/" + binary_name + "` "
            "ONCE to populate it (the project is cached under "
            "./.ghidra_proj/ so subsequent reads are fast)."
        )
    parts.append(
        "REPLY as compact bullets. Be terse — but COMPLETENESS OF THE "
        "SECTIONS BEATS BREVITY: never drop or merge a requested section to "
        "save space. A missing section makes the orchestrator re-run this "
        "entire recon from scratch, which costs far more than a long reply. "
        "(A full heap-chal answer runs ~15-20 KB; that is expected, not a "
        "problem. Spend the length on the tables and specifics below, not on "
        "prose.)\n"
        "Sections:\n"
        "  ARCH         — `file` summary in one line\n"
        "  PROTECTIONS  — checksec: RELRO / Stack / NX / PIE\n"
        "  LIBC         — `./.chal-libs/libc_profile.json` version + "
        "any blacklisted_techniques (read libc_profile.json if present)\n"
        "  FUNCTIONS    — names + sizes of the user-controllable funcs "
        "(main, menu handlers, parsers). Ignore stdlib stubs.\n"
        "  CANDIDATES   — ranked HIGH/MED/LOW with bug class + file:line\n"
        "                 e.g. `HIGH heap.UAF — secure_free@b21 frees "
        "without unsetting the dangling ptr` (be specific)\n"
        "  PRIMITIVES   — for each HIGH: what the attacker writes / reads / "
        "controls (8 bytes at canary? full chunk? size field?)\n"
        "  NOT_NEEDED   — explicit list of standard techniques / artifacts "
        "this chal does NOT require, with one-line reason each. Examples: "
        "\"host glibc heap exploit — chal is RISC-V emulator, host heap "
        "irrelevant\", \"libc.so.6 leak — flag is plaintext on filesystem, "
        "no RCE needed\", \"chal-libc-fix — chal ships static binary\". "
        "The main agent treats these as forbidden detours unless you "
        "later supply explicit counter-evidence. Lying-by-omission here "
        "(silently \"forgetting\" to mention something is unneeded) costs "
        "main 5–30 min of irrelevant analysis per item.\n"
    )
    if heap_advanced:
        parts.append(
            "HEAP CHAL — ALSO report:\n"
            "  ALLOC/FREE SIG — secure_malloc / secure_free header layout "
            "(in-band size, canary location, freelist pointer mangling?)\n"
            "  HOOKS_ALIVE   — confirm libc_profile.json's `hooks_alive` "
            "matches the actual libc (cross-check on __free_hook offset).\n"
            "  RECOMMENDED CHAIN — pick ONE from libc_profile.json's "
            "recommended_techniques given the primitives above. "
            "HARD CONSTRAINT: every step of the chain MUST be performable "
            "using ONLY the capabilities you listed in PRIMITIVES. Before "
            "you write each step, check the PRIMITIVES section and quote "
            "the specific capability that enables it (e.g. \"step 2 uses "
            "the AAR from PRIMITIVES line 1\"). Do NOT propose a step that "
            "requires a capability you did not enumerate — e.g. if "
            "PRIMITIVES says \"payload-only, no header access / no OOB\", "
            "you MUST NOT recommend \"corrupt the size field\" or "
            "\"escape to unsorted bin via size overwrite\". If no standard "
            "chain fits the primitives, write \"NO STANDARD CHAIN FITS — "
            "primitives lack X\" and stop; the main agent will design a "
            "custom chain rather than chase a contradictory recipe."
        )
        # Phase 2 + 3 lite — heap state-evolution matrix. The single
        # most common pre-recon failure mode is concluding "no leak
        # primitive" after testing only R0 (fresh process) — primitives
        # often unlock in later heap states (sbrk extension, post-
        # consolidate). This forces recon to mark untested cells as ?
        # instead of ✗, preserving them as open hypotheses for main.
        # Job 4a6bd25a0d1d was a textbook miss: R0 leak test produced
        # 0 bytes for sizes 0x10..0x400, concluded "blocked", but the
        # real path required R5 (post-consolidate after huge sbrk
        # extension) to make secure_malloc(-8) safe.
        parts.append(
            "HEAP STATE MATRIX (mandatory before any 'blocked' "
            "conclusion):\n"
            "  States to enumerate:\n"
            "    R0  fresh process, no allocations yet\n"
            "    R1  fastbin populated (alloc+free cycle, sizes "
            "≤ 0x80 for glibc 2.23, ≤ 0x408 for 2.27+ tcache)\n"
            "    R2  R1 + unsorted-range alloc/free (size 0x90..0x420)\n"
            "    R3  R2 + large-bin alloc (size ≥ 0x420 on 2.23)\n"
            "    R4  sbrk-extended heap (many small allocs forcing "
            "brk growth — verify by allocating N small chunks until "
            "sbrk advances ≥ 0x100000)\n"
            "    R5  R4 + huge alloc + free (triggers "
            "malloc_consolidate; usually REQUIRES "
            "vm.overcommit_memory=1 on the target)\n"
            "    R6  mmap region (alloc ≥ mmap_threshold ~0x20000); "
            "usually DEAD-END for fake-chunk attacks — note then "
            "skip\n"
            "\n  Primitives to probe in each non-skip state:\n"
            "    read-OOB | write-OOB | fd/bk leak (free→show) | "
            "UAF | integer-edge (size in {-1, INT_MIN, INT_MAX, 0, "
            "0x80000000})\n"
            "\n  Fill a 6×5 grid in your reply (R0..R5 × 5 prims). "
            "Each cell:\n"
            "    ✓  empirically verified working in this state\n"
            "    ✗  empirically verified blocked in this state\n"
            "    ?  not yet tested (open hypothesis for main)\n"
            "\n  HARD RULE: 'No leak primitive' / 'No write "
            "primitive' conclusion requires every cell in that "
            "column to be ✗ (NOT ?). Untested cells (?) block the "
            "negative conclusion at TWO levels:\n"
            "    (a) pre-recon (you): cannot conclude 'blocked' "
            "while ? cells remain in the relevant column.\n"
            "    (b) MAIN AGENT: when it receives this matrix it "
            "MUST sandbox-probe at least one ? cell in the critical "
            "columns (esp. int-edge × R4/R5) before declaring the "
            "chain unreachable. A probe is a small pwntools script "
            "that either flips the cell to ✓ (chain unlock found) "
            "or ✗ (confirmed dead).\n"
            "  PRIORITY HINT: if the chal env declares "
            "vm.overcommit_memory=1 (see ENV-AWARE PATHS below) the "
            "int-edge × R5 cell (wrap-size primitive AFTER "
            "sbrk-extended heap + malloc_consolidate trigger) is the "
            "single most common unlock for libsalloc-style wrappers. "
            "Job 7ad50a878e91 marked it ? and concluded 'blocked' "
            "without probing — main must NOT repeat that mistake."
        )
        # ENV-AWARE PATHS — chal-description kernel knobs reopen
        # branches that local-default-kernel testing would mark
        # blocked. Job 4a6bd25a0d1d had vm.overcommit_memory=1 in
        # the description; pre-recon ignored it and concluded
        # "big-positive secure_malloc(n) → OOM → __abort" which is
        # FALSE on overcommit=1 (mmap succeeds, no OOM). Worker
        # container has overcommit=1 too, but the test was never
        # run — the conclusion was inferred from default-kernel
        # assumptions. This block forces such inferences to be
        # named so main can challenge them.
        parts.append(
            "ENV-AWARE PATHS — START by scanning the chal "
            "description text FIRST (it may be Korean / Japanese / "
            "etc., but sysctl phrases like 'vm.overcommit_memory' "
            "are universal across languages). THEN scan "
            "./chal/Dockerfile and deploy scripts. Watch for: "
            "vm.overcommit_memory, mmap_min_addr, "
            "transparent_hugepage, ulimit -v, sysctl, "
            "kernel.randomize_va_space.\n"
            "  PRECEDENCE RULE: description sysctl > Dockerfile "
            "sysctl. If description says 'sysctl "
            "vm.overcommit_memory=1' but the Dockerfile doesn't "
            "bake it in, the DESCRIPTION wins — operator deploys "
            "the live server with that knob set regardless of what "
            "the Dockerfile contains. 'No knobs in the Dockerfile' "
            "is NOT sufficient evidence of default-kernel env. "
            "Job 7ad50a878e91 made exactly this mistake: pre-recon "
            "scanned only the Dockerfile, concluded 'no overcommit "
            "knobs', and downstream int-edge × R5 was abandoned.\n"
            "  For each knob mentioned, name explicitly which "
            "alloc/free branches it reopens vs default kernel — "
            "e.g. 'overcommit=1 → malloc(>1GB) succeeds via "
            "anonymous mmap (would return NULL on default "
            "kernel)'. If you marked any primitive ✗ in the matrix "
            "WITHOUT testing on the target env knob, downgrade the "
            "cell to ENV-UNTESTED rather than ✗. Do NOT conclude "
            "'blocked' based on default-kernel inference when the "
            "target runs under non-default knobs."
        )
        # Tier 1.5 E — int-overflow / wrap analysis correctness.
        # Recurring failure: pre-recon sees `malloc(uintN(size + K))`
        # in a custom allocator, mentally simulates `size=-N` on a
        # default kernel, observes the canary-write address would
        # land at p+~4GB (unmapped) and concludes "SEGV / UNUSABLE".
        # That conclusion is FALSE when the target has
        # vm.overcommit_memory=1 AND the chain has staged enough
        # heap growth (R4-R5) to bring the canary-write address
        # inside a mapped region. Both jobs 4a6bd25a0d1d and
        # 7ad50a878e91 hit this exact trap.
        parts.append(
            "INT-OVERFLOW / WRAP ANALYSIS — When a custom "
            "allocator does `malloc(uintN(user_size + K))` with a "
            "narrower type than user_size:\n"
            "  - Do NOT conclude 'SEGV', 'OOM', 'unusable' or "
            "'DoS-only' from default-kernel reasoning alone. The "
            "wrap branch routinely succeeds via anonymous mmap "
            "when vm.overcommit_memory=1.\n"
            "  - The wrap primitive typically pairs with "
            "sbrk-extension (R4) and malloc_consolidate trigger "
            "(R5) to become safe: many small allocs first → heap "
            "grows past 0x100000000 → huge alloc + free triggers "
            "malloc_consolidate → THEN a wrap-size alloc's "
            "canary-write address lands inside the now-mapped "
            "multi-GB region → no fault. Mechanically this is "
            "int-overflow + fastbin dup + FSOP — some chal authors "
            "call it 'house of pumpkin' colloquially, but that "
            "phrase is NOT a recognized named technique — don't chase "
            "the label; the mechanism above is the real thing.\n"
            "  - If the target env knob state is unknown OR "
            "matches the wrap-success premise (overcommit=1), "
            "mark int-edge × R4/R5 cells as ENV-UNTESTED (NOT "
            "✗), AND add an explicit int-overflow path entry to "
            "CANDIDATES so main pursues it.\n"
            "  - The claim 'wrap-size canary write goes to p+~4GB "
            "→ SEGV' is a default-env claim. Either validate it "
            "by testing under the target's actual env, or mark it "
            "ENV-UNTESTED and let main probe."
        )
        # Phase 6 — libc-version-keyed RCE catalog. Without this main
        # re-derives version-specific FSOP facts from scratch every
        # job. The table also names the canonical 2.23 path
        # (_IO_2_1_stdout_ vtable hijack — no vtable check on this
        # version) that main missed on job 4a6bd25a0d1d.
        rce_table = render_rce_table(libc_version)
        if rce_table:
            parts.append(rce_table)
        # Tier 2 fix (job 37b33d2a741b) — official solver used a
        # crafted `_IO_2_1_stdout_._flags = 0xfbad1800` magic to leak
        # libc EVEN under setvbuf(stdout, _IONBF). judge#1 incorrectly
        # ruled this out as "_IONBF ⇒ no write_base trick". The
        # FSOP-AS-LEAK catalog surfaces the magic + main_arena→stdout
        # distance up front so pre-recon doesn't repeat the conservative
        # ruling. Companion to RCE TARGET TABLE — this is the LEAK
        # half of the FSOP toolchain.
        fsop_leak_table = render_fsop_leak_table(libc_version)
        if fsop_leak_table:
            parts.append(fsop_leak_table)
        # MMAP_THRESHOLD dynamic-adjustment trick. Job 37b33d2a741b's
        # nextsize-NULL trap (large unsorted-bin chunk's fd_nextsize /
        # bk_nextsize zeroed by free → reinterpreted std::string sees
        # capacity=0 → operator= takes realloc path → free(libc) →
        # abort) IS bypassable: glibc updates mp_.mmap_threshold on
        # free of an mmap'd chunk, so allocating + freeing two large
        # chunks (>= 0x20000) raises the threshold past the chunk
        # size you actually want in unsorted bin. The next alloc of
        # that "huge but now below threshold" size goes to brk and
        # lands in unsorted bin WITHOUT the large-bin-sort path that
        # zeroes nextsize. main on 37b33d2a741b mentioned smallbin
        # tcache-fill workaround in passing but never tried this
        # mmap_threshold trick; official solver uses it as the first
        # 6 lines of the exploit.
        parts.append(
            "MMAP_THRESHOLD DYNAMIC-ADJUSTMENT TRICK (heap-pwn:\n"
            "  nextsize-NULL trap bypass; glibc 2.27+)\n"
            "  When a chunk in unsorted bin has size >= "
            "MIN_LARGE_SIZE (= 0x420 on x86_64), free() zeroes "
            "`fd_nextsize` / `bk_nextsize` at user_offsets 0x10..0x20.\n"
            "  Any later reinterpretation of that chunk as a struct "
            "with fields at those offsets (notably std::string's "
            "`_M_capacity` at offset 0x10) reads 0 — capacity=0 then "
            "triggers a realloc path on assignment, often free()-ing\n"
            "  a libc-address pointer that was forged as `_M_p`. The\n"
            "  resulting abort kills the chain.\n"
            "\n"
            "  BYPASS: glibc keeps `mp_.mmap_threshold` adaptive — on\n"
            "  free of an mmap'd chunk, the policy may increase the\n"
            "  threshold up to `DEFAULT_MMAP_THRESHOLD_MAX` (default "
            "0x2000000 on 64-bit). After this bump, subsequent allocs\n"
            "  of size N below the new threshold go to brk instead of\n"
            "  mmap → they land in unsorted bin (when size >= "
            "MIN_LARGE_SIZE) WITHOUT first being sorted into a large\n"
            "  bin (no nextsize zeroing path on that branch).\n"
            "\n"
            "  Recipe (verified by official solver on glibc 2.39):\n"
            "    1. alloc(0x20000); free  ← mmap chunk, then freed\n"
            "    2. alloc(0x10);   free  ← unrelated, keeps state\n"
            "    3. alloc(0x20000); free  ← raises mp_.mmap_threshold\n"
            "    4. alloc(0x30000); free  ← bumps threshold further\n"
            "    5. now allocate the target-size chunk (e.g. 0x790) —\n"
            "       it goes to brk, lands in unsorted bin with "
            "fd_nextsize/bk_nextsize NOT zeroed.\n"
            "\n"
            "  Try this BEFORE concluding 'capacity-NULL trap blocks\n"
            "  AAW'. The smallbin-via-tcache-fill workaround is also\n"
            "  viable but mmap_threshold trick is shorter and more\n"
            "  reliable across libc versions."
        )
        # FSOP magic / leak-via-buffered-output note. This magic comes
        # from the local catalog / the target's own libc (exact + version-
        # matched); web research is available to supplement but local is
        # authoritative.
        parts.append(
            "FSOP-LEAK NOTE:\n"
            "  If chal source calls `setvbuf(stdout, NULL, _IONBF, 0)`\n"
            "  AND an OOB primitive can reach `_IO_2_1_stdout_`\n"
            "  (typically via an unsorted-bin chunk's fd/bk = "
            "main_arena.bins[0] = main_arena + 0x60), this is a classic\n"
            "  FSOP libc leak: overwrite `_flags` with a buffered-output\n"
            "  magic (e.g. `0xfbad1800`) so the next puts/printf dumps\n"
            "  buffer contents. Take the exact `_flags` magic + the\n"
            "  per-version main_arena→stdout offset from the pre-recon\n"
            "  FSOP-AS-LEAK TABLE / local libc KB; if the version isn't\n"
            "  covered, read the `_IO_FILE` layout straight out of the\n"
            "  target's own libc with gdb / readelf. The local libc + this\n"
            "  table are authoritative; web research is available but is\n"
            "  rarely needed for a version-keyed offset."
        )
    if custom_libs:
        # Chal author shipped non-standard .so files. THIS IS THE FIRST
        # PLACE TO LOOK for primitives — wrapper functions almost always
        # encode the bug (int-overflow on size, signed-vs-unsigned compare,
        # off-by-one, missing length cap, side-effect at unexpected offset).
        # Treating them as "just wrappers" is a known way to miss the chal.
        lib_list = ", ".join(custom_libs)
        decomp_dir_list = ", ".join(
            f"./decomp_{Path(l).stem.replace('.', '_')}/"
            for l in custom_libs
        )
        parts.append(
            f"CUSTOM CHAL LIBRARY DETECTED: ./.chal-libs/{{{lib_list}}}\n"
            "These are NOT standard glibc/ld/libgcc/libstdc++ — the chal "
            "author shipped them deliberately and they almost certainly "
            "contain the primary attack surface (wrapped malloc/free, "
            "wrapped read/write, custom integrity checks, sandbox shims, "
            "etc.). ALSO report:\n"
            "  CUSTOM_EXPORTS — for each custom .so, list every exported "
            "function (`nm -D ./.chal-libs/<n>.so | grep ' T '`).\n"
            "  DIVERGENCES   — for each export that shadows a standard "
            "libc symbol (malloc, free, read, write, printf, strcpy, "
            "memcpy, snprintf, alloca, …), name the precise divergence "
            "from POSIX/glibc semantics. Look for:\n"
            "    · integer type mismatches (size is uint32 + 0x10 → "
            "int-overflow primitive)\n"
            "    · signed-vs-unsigned compares on user-controlled values\n"
            "    · side effects vanilla doesn't do (canary writes at "
            "chunk+size+N, page-mapping at fixed addresses, …)\n"
            "    · missing bounds checks (no length cap on read-like "
            "wrappers → BOF)\n"
            "    · error-path divergence (abort vs return NULL vs "
            "silent continue — each enables a different primitive)\n"
            "  PRIMITIVES_IN_LIB — for each divergence, the smallest "
            "input that triggers a useful primitive (`wrapper(-8)` → "
            "OOB canary write, `wrapper(0xfffffff0)` → 0-byte memset, "
            "etc.). cite <lib>:<addr>.\n"
            "DO NOT skip this section. Even when the binary's own "
            "code looks straightforward, the bug is usually inside one "
            "of these wrappers."
        )
        # Tier 1.8 — MANDATORY decomp cite for custom libs. nm + objdump
        # give the wrapper's SURFACE (symbols, branch addresses); they
        # do NOT show post-condition refresh logic, hidden integer
        # promotions, struct layouts, or implicit invariants. Job
        # 64f02a22106a SIGBUS'd because libsalloc's secure_edit has a
        # post-write canary refresh that re-reads size_lo/size_hi from
        # user_ptr[0..7]; a long edit payload trashes those fields and
        # the next op faults inside the refresh path. The debugger
        # subagent eventually found this by tracing 40 asm instructions
        # across two functions. The decompiled C says it in 3 lines.
        # autoboot now auto-runs `ghiant` on every custom .so so the
        # decomp is on disk before pre-recon starts.
        parts.append(
            f"CUSTOM LIB DECOMPILATION (autoboot-prefetched at "
            f"{decomp_dir_list}):\n"
            "  ALL claims about wrapper internals (DIVERGENCES, "
            "PRIMITIVES_IN_LIB, ALLOC/FREE SIG, integer arithmetic, "
            "post-op refresh, struct layouts) MUST be backed by a "
            "QUOTED line from the decompiled C in the autoboot decomp "
            "dir above. nm/objdump/strings are evidence of SURFACE; "
            "decompiled C is evidence of BEHAVIOR.\n"
            "  PROCESS for each wrapper export:\n"
            "    1. Read the corresponding ./decomp_<lib>/<FUN_*>.c "
            "(filename matches the function offset; use Bash `grep -l "
            "<symbol_name> ./decomp_<lib>/*.c` if you can't tell which).\n"
            "    2. Map the C to the export name via nm -D or its "
            "ghiant default name (FUN_<offset>).\n"
            "    3. Quote the EXACT lines that establish the primitive "
            "(integer math, branch predicate, refresh write address, "
            "etc.) in your DIVERGENCES / PRIMITIVES_IN_LIB section.\n"
            "    4. If decomp omits a critical detail (Ghidra sometimes "
            "loses signed/unsigned annotations), supplement with the "
            "corresponding asm — but always START from decomp.\n"
            "  HIDDEN-CONSTRAINT TRAPS to look for (the things disasm "
            "shows after 40 lines of trace and decomp shows in 3):\n"
            "    · post-write refresh that re-reads chunk metadata "
            "from the same buffer the wrapper just wrote into "
            "(libsalloc.secure_edit + secure_free __heap_chk_fail call "
            "— observed on job 64f02a22106a: long edit payload trashes "
            "size_lo/hi, next op faults)\n"
            "    · pre-free memset whose count derives from a user-"
            "writable size field (allows 0-byte memset bypass when "
            "size wraps to 0)\n"
            "    · integrity check predicates that silently return on "
            "mismatch vs abort vs return-NULL (different bypass shapes)\n"
            "    · canary refresh that uses size from header (so a "
            "header-corrupting overflow KILLS the slot for future ops)\n"
            "  FAILURE MODE this prevents: 'wrapper(-8) → SEGV / OOM' "
            "single-line dismissals based on assumed surface behavior. "
            "If decomp shows the actual control flow, the assumed "
            "failure usually has a survival path."
        )
    parts.append(
        "DO NOT propose exploit code. DO NOT speculate. Facts only. "
        "Cite file:line / file:addr for every claim."
    )
    if heap_advanced:
        # Tier 1.7 #3 — mandatory section gate. pre-recon often
        # receives Tier 1.5 prompt blocks but silently omits whole
        # sections from the reply when the agent decides the section
        # is "not relevant". Job 96cd1092b992: pre_recon got the
        # INT-OVERFLOW block but reply contained 0 occurrences of
        # the phrase, so main never saw the int-edge × R5 unlock
        # framing the operator memory specifically warned about.
        # Require explicit section headers so omission becomes
        # detectable in the reply.
        parts.append(
            "MANDATORY SECTION HEADERS — your reply MUST contain "
            "EVERY one of these section titles as a literal string, "
            "EVEN IF the body is just 'N/A — <one-line reason>'. "
            "Silent omission is the most common pre-recon failure "
            "mode: main never gets the framing and re-derives "
            "(or skips) the analysis from scratch.\n"
            "  Required headers (verbatim, case-sensitive):\n"
            "    ARCH\n"
            "    PROTECTIONS\n"
            "    LIBC\n"
            "    FUNCTIONS\n"
            "    CANDIDATES\n"
            "    PRIMITIVES\n"
            "    NOT_NEEDED\n"
            "    ALLOC/FREE SIG\n"
            "    HOOKS_ALIVE\n"
            "    RECOMMENDED CHAIN\n"
            "    HEAP STATE MATRIX\n"
            "    ENV-AWARE PATHS\n"
            "    INT-OVERFLOW ANALYSIS\n"
            "    RCE TARGET TABLE\n"
            "  For headers where you genuinely have nothing to add "
            "(e.g. no integer arithmetic anywhere in the wrappers), "
            "the body MUST start with 'N/A — ' so reviewers can tell "
            "you considered it vs. forgot it."
        )
    return "\n\n".join(parts)


def _autodecomp_custom_libs(
    custom_libs: list[str], work_dir: Path, job_id: str
) -> dict[str, Path]:
    """Run ghiant once per chal-author-supplied .so so the decompiled C
    is on disk before pre-recon starts.

    Without this, pre-recon analyzes wrappers via nm -D + objdump
    (surface API only) and silently misses internal mechanics. Job
    64f02a22106a hit SIGBUS because libsalloc.so's secure_edit
    performs a POST-WRITE canary refresh that reads size_lo/size_hi
    from user_ptr[0..7] — a long edit payload trashes those bytes
    and the NEXT op faults. The behavior is 3 lines of decompiled C
    but requires tracing 40 instructions across two functions in
    disasm to see.

    Returns a {libname: decomp_dir_path} map (for AUTOBOOT.md). One
    decomp dir per custom .so, sibling to ./decomp/ which holds the
    main binary's decomp.
    """
    if not custom_libs:
        return {}
    chal_libs = work_dir / ".chal-libs"
    out_map: dict[str, Path] = {}
    for libname in custom_libs:
        src = chal_libs / libname
        if not src.is_file():
            continue
        stem = src.name.replace(".so", "").replace(".", "_")
        out_dir = work_dir / f"decomp_{stem}"
        if out_dir.is_dir() and any(out_dir.glob("*.c")):
            log_line(
                job_id,
                f"[autoboot] custom-lib decomp cache hit: "
                f"./{out_dir.name}/ ({sum(1 for _ in out_dir.glob('*.c'))} .c)"
            )
            out_map[libname] = out_dir
            continue
        out_dir.mkdir(parents=True, exist_ok=True)
        log_line(
            job_id,
            f"[autoboot] decompiling {libname} → ./{out_dir.name}/ "
            f"(1–3 min cold; pre-recon + main get decompiled C "
            f"instead of disasm-only)"
        )
        env = os.environ.copy()
        env["JOB_ID"] = job_id
        try:
            res = subprocess.run(
                ["ghiant", str(src), str(out_dir)],
                cwd=str(work_dir),
                env=env,
                capture_output=True, text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            log_line(
                job_id,
                f"[autoboot] {libname} decomp TIMEOUT (300s) — "
                f"pre-recon will fall back to disasm"
            )
            continue
        except Exception as e:
            log_line(
                job_id,
                f"[autoboot] {libname} decomp ERROR: {e} — "
                f"pre-recon will fall back to disasm"
            )
            continue
        if res.returncode == 0:
            count = sum(1 for _ in out_dir.glob("*.c"))
            log_line(
                job_id,
                f"[autoboot] {libname}: {count} functions decompiled "
                f"to ./{out_dir.name}/"
            )
            out_map[libname] = out_dir
        else:
            tail = (res.stderr or "")[-200:].replace("\n", " | ")
            log_line(
                job_id,
                f"[autoboot] {libname} decomp FAILED rc={res.returncode}: "
                f"{tail}"
            )
    return out_map


def _is_shared_lib(p: Path) -> bool:
    n = p.name.lower()
    return (
        n.startswith("libc")
        or n.startswith("ld-")
        or n.startswith("ld.")
        or ".so" in n
    )


# ELF e_type values worth staging as "a binary the agent might run":
# ET_EXEC (2) and ET_DYN (3, PIE + shared objects).
#
# ET_REL (1) is a relocatable object — a challenge that ships its BUILD
# TREE carries thousands (job 5cb4ecb67214's V8 bundle: 1899 `.o` under
# deploy/out/obj/ vs 5 real binaries), and flattening those into ./bin/
# buries the challenge and makes the largest-ELF pick meaningless. But
# ET_REL is NOT dead weight in general: a Linux kernel MODULE (`.ko`) is
# ET_REL and IS the challenge in a kernel-pwn job. So drop ET_REL only on
# the compiler-output suffixes, never on the type alone.
_ELF_STAGE_TYPES = (2, 3)
_ELF_BUILD_OBJECT_SUFFIXES = (".o", ".obj", ".lo", ".a", ".la")


def _elf_kind(p: Path) -> int | None:
    """ELF ``e_type`` of `p`, or None when it isn't an ELF.

    Reads 18 bytes. The previous magic check was ``f.read_bytes()[:4]``,
    which pulled EVERY candidate file fully into memory to look at four
    bytes — 244 MB across 1904 files on the V8 bundle above.
    """
    try:
        with p.open("rb") as fh:
            head = fh.read(18)
    except Exception:
        return None
    if len(head) < 18 or head[:4] != b"\x7fELF":
        return None
    # EI_DATA (byte 5): 1 = little-endian, 2 = big-endian.
    endian = "big" if head[5] == 2 else "little"
    return int.from_bytes(head[16:18], endian)


# --- JS-engine (browser-pwn) bundles ---------------------------------------
# A JS-engine challenge ships a PREBUILT engine shell (d8 / js / jsc) whose
# runtime data sits NEXT TO the binary. d8 resolves `snapshot_blob.bin`
# relative to the argv[0] DIRECTORY, so the plain ELF-only flatten yields a
# ./bin/d8 that cannot start at all:
#     Failed to open startup resource './snapshot_blob.bin'.
# (verified against job 5cb4ecb67214's bundle — a bare copy dies, a copy
# WITH its siblings runs). Detection anchors on that data file rather than
# on the binary's name, so a renamed shell still resolves.
#
# ANCHOR is `snapshot_blob.bin` ALONE. `icudtl.dat` was in this tuple and had
# to come out: it is ICU data shipped by Chromium, Electron, Node, Flutter and
# Qt-WebEngine — an ordinary pwn bundle that vendors any of those trips it,
# and because this tuple gates SUPPRESSION (no chal-libc-fix, no ghiant, other
# ELFs dropped from ./bin/) a false positive silently degrades a normal job.
# It also did not match `_common._JS_ENGINE_ANCHORS`, so the suppressive half
# fired while the explanatory prompt block stayed silent. icudtl.dat is still
# COPIED — it is a non-ELF sibling like any other — it just cannot elect a
# directory to be an engine build.
_JS_ENGINE_DATA = ("snapshot_blob.bin",)
_JS_ENGINE_NAMES = ("d8", "js", "jsc", "js_shell", "chakra", "ch", "spidermonkey")
# Vendored third-party trees. A challenge that npm-installs Electron, or ships
# a headless-Chrome bot, buries a real `snapshot_blob.bin` in here — which used
# to elect that directory as "the engine build" for the whole job.
_VENDOR_DIRS = {"node_modules", "vendor", "third_party", "bower_components",
                "site-packages", ".git", "__pycache__"}
# Marker recording WHICH binary the extraction step identified as the engine.
# _staged_js_engine used to RE-DERIVE this over the flattened ./bin/ as
# "largest ELF not in a 5-name list", so any bundle that merely CONTAINED an
# anchor could hand the title to the real challenge binary (proven by an A/B
# differing only by a zero-byte file). Identification now happens once, where
# the directory structure is still intact, and is read back from here.
_JS_ENGINE_MARKER = ".js_engine"
# Build tools that live in the same out/ dir as the engine AND are bigger
# than it (mksnapshot 49 MB vs d8 37 MB) — the largest-ELF heuristic picks
# them, and then every downstream step analyses the wrong binary.
_JS_ENGINE_BUILD_TOOLS = (
    "mksnapshot", "torque", "gen-regexp-special-case",
    "bytecode_builtins_list_generator", "v8_build_config",
)
# A V8 out/ dir also holds test binaries that DWARF the shell — cctest and
# unittests are ~7 MB against a 158 KB stripped d8 — so "largest ELF that is
# not one of five hard-coded names" handed the title to a test runner
# whenever the shell had been renamed. Substring markers instead of an
# ever-growing exact-name list.
_JS_ENGINE_TOOL_MARKERS = (
    "test", "fuzz", "bench", "gen", "mkgrokdump", "snapshot", "torque",
)


def _looks_like_build_tool(name: str) -> bool:
    n = name.lower()
    return (n in _JS_ENGINE_BUILD_TOOLS
            or any(m in n for m in _JS_ENGINE_TOOL_MARKERS))
# Caps on the non-ELF siblings copied next to the engine — per file and in
# aggregate. icudtl.dat is ~10 MB; anything far beyond that is build spoil,
# not runtime data, and without the aggregate cap a bundle could make autoboot
# duplicate an unbounded amount of data into ./bin/.
_JS_SIBLING_MAX_BYTES = 48 * 1024 * 1024
_JS_SIBLING_TOTAL_MAX_BYTES = 256 * 1024 * 1024


def _js_engine_dir(elfs: list[Path], root: Path | None = None) -> Path | None:
    """Directory of a JS-engine build among `elfs`, or None.

    The VENDOR prune lives here, not in `_scan`: a challenge that npm-installs
    Electron (or ships a headless-Chrome bot, or a venv) buries a real
    `snapshot_blob.bin` in `node_modules/`, and letting that directory get
    ELECTED turns an ordinary pwn job into a browser-pwn job. Pruning those
    paths in `_scan` instead was too wide — it removed the files from ELF
    DISCOVERY altogether, so a chal shipping its custom `.so` under a venv's
    site-packages lost it from `./.chal-libs/` (this repo's own notes call a
    chal-supplied `.so` the attack surface) and a binary under `vendor/` left
    `./bin/` empty. Vendored trees are still staged; they just cannot claim to
    be the engine.
    """
    for e in elfs:
        d = e.parent
        if root is not None:
            try:
                if any(p in _VENDOR_DIRS for p in d.relative_to(root).parts):
                    continue
            except ValueError:
                pass
        if any((d / n).is_file() for n in _JS_ENGINE_DATA):
            return d
    return None


def _pick_js_engine(elfs: list[Path], engine_dir: Path) -> Path | None:
    """The engine shell inside `engine_dir` — by name when recognisable,
    else the largest binary that is NOT a known build tool."""
    same = [e for e in elfs if e.parent == engine_dir]
    named = [e for e in same if e.name in _JS_ENGINE_NAMES]
    # Shared libraries can never BE the shell. A component build puts a
    # libv8.so next to the engine that is far bigger than it, so with a
    # renamed shell the size fallback elected the LIBRARY as "the engine" and
    # then dropped the real shell as a co-located binary — ./bin/ ended up
    # holding nothing but snapshot_blob.bin.
    pool = named or [
        e for e in same
        if not _is_shared_lib(e) and not _looks_like_build_tool(e.name)
    ]
    return max(pool, key=lambda p: p.stat().st_size) if pool else None


def _staged_js_engine(staged_bin: Path) -> Path | None:
    """The JS-engine shell staged in ``./bin/``, or None.

    This gates SUPPRESSION (skip chal-libc-fix + the ghidra pre-bake), so it
    is deliberately STRICTER than the guidance-only detector in _common: it
    accepts only (a) the binary the extraction step recorded in the
    ``.js_engine`` marker, or (b) a file whose NAME is a known engine shell
    sitting next to the anchor. There is no "largest ELF wins" fallback —
    that fallback let one stray ``snapshot_blob.bin`` anywhere in a bundle
    promote an ordinary challenge binary to "the engine" and silently cost
    the job its libc profile.
    """
    try:
        entries = [p for p in staged_bin.iterdir() if p.is_file()]
    except Exception:
        return None

    def _safe(p: Path) -> Path | None:
        # Never hand back a symlink or anything resolving outside ./bin/:
        # the caller chmods it 0755 and EXECUTES it.
        try:
            if p.is_symlink():
                return None
            rp = p.resolve()
            rp.relative_to(staged_bin.resolve())
        except Exception:
            return None
        return p if _elf_kind(p) in _ELF_STAGE_TYPES else None

    marker = staged_bin.parent / _JS_ENGINE_MARKER
    if marker.is_file():
        try:
            recorded = marker.read_text().strip()
        except Exception:
            recorded = ""
        if recorded and "/" not in recorded and recorded not in (".", ".."):
            got = _safe(staged_bin / recorded)
            if got is not None:
                return got

    if not any(p.name in _JS_ENGINE_DATA for p in entries):
        return None
    named = [p for p in entries if p.name in _JS_ENGINE_NAMES and _safe(p)]
    if not named:
        return None
    return max(named, key=lambda p: p.stat().st_size)


def _find_elf_or_unzip(staged_bin: Path, work_dir: Path, log_fn) -> list[Path]:
    """Find ELF binaries in `staged_bin`. If only zip/tar bundles are
    present (the standard Dreamhack / HackTheBox shape), unzip the first
    bundle into <work_dir>/chal/ and rescan there. After a successful
    unpack the originating bundle is removed from ``staged_bin`` and the
    discovered ELFs are flattened into ``staged_bin`` (so the agent's
    ``./bin/<name>`` references resolve directly) and any glibc / ld /
    chal-supplied ``lib*.so*`` files are pre-staged into
    ``<work_dir>/.chal-libs/`` so the subsequent ``chal-libc-fix`` takes
    the "physical libs bundled" fast path instead of falling back to
    a docker-pull base image fetch.

    Returns the list of ELFs found at their final ``staged_bin`` paths.
    """
    elfs: list[Path] = []
    # Mutable counter so the nested _scan can report how many relocatable
    # object files it dropped (a build-tree bundle drops thousands).
    skipped_rel = [0]

    def _scan(d: Path) -> list[Path]:
        out: list[Path] = []
        try:
            for f in d.rglob("*"):
                # Never flatten/stage out of a `*_extracted/` tree — that's
                # where _stage_libs_from_debs unpacks a glibc .deb (and where
                # an agent's manual `dpkg-deb -x libc_extracted/` lands). Its
                # .so files are staged by _stage_libs_from_debs with the
                # _is_standard_libname filter; scanning them here would let
                # the UNFILTERED .so → .chal-libs copy below re-stage glibc
                # internals (libmvec/libanl/...) and reintroduce the
                # custom-lib Ghidra flood on /retry.
                try:
                    rel_parts = f.relative_to(d).parts
                except ValueError:
                    rel_parts = ()
                if any(p.endswith("_extracted") for p in rel_parts):
                    continue
                if not f.is_file():
                    continue
                kind = _elf_kind(f)
                if kind is None:
                    continue
                if (kind not in _ELF_STAGE_TYPES
                        and f.suffix.lower() in _ELF_BUILD_OBJECT_SUFFIXES):
                    skipped_rel[0] += 1
                    continue
                out.append(f)
        except Exception as e:
            log_fn(f"[autoboot] scan {d} failed: {e}")
        return out

    found = _scan(staged_bin)
    if found:
        elfs.extend(found)
        return elfs

    # No raw ELF — look for archives and unpack one.
    bundles: list[Path] = []
    try:
        for f in staged_bin.iterdir():
            if not f.is_file():
                continue
            n = f.name.lower()
            if (n.endswith(".zip") or n.endswith(".tar")
                    or n.endswith(".tar.gz") or n.endswith(".tgz")
                    or n.endswith(".tar.xz") or n.endswith(".tar.bz2")):
                bundles.append(f)
    except Exception:
        pass
    if not bundles:
        log_fn("[autoboot] no ELF and no bundle found in ./bin/ — skipping")
        return []
    bundle = bundles[0]
    out_dir = work_dir / "chal"
    out_dir.mkdir(parents=True, exist_ok=True)
    log_fn(f"[autoboot] unpacking {bundle.name} → {out_dir}")
    try:
        if bundle.name.lower().endswith(".zip"):
            import zipfile
            with zipfile.ZipFile(bundle) as zf:
                zf.extractall(out_dir)
        else:
            import tarfile
            with tarfile.open(bundle) as tf:
                # _safe_extract_tar, not tf.extractall: on 3.12 the default
                # extraction_filter is still `fully_trusted`, so an absolute
                # or `../` member escapes work/chal into /data (host-mounted)
                # or /root/.claude. The hardened helper already existed in
                # this file and was used by the .deb path only.
                _safe_extract_tar(tf, out_dir)
    except Exception as e:
        log_fn(f"[autoboot] bundle unpack failed: {e}")
        return []
    # Bundle unpacked successfully → drop the archive so ``./bin/`` only
    # holds binaries the agent should look at. Otherwise the agent sees
    # the .zip on its first ``ls ./bin/`` and wastes 3-4 turns
    # re-extracting (observed live on 5963af004fdc).
    try:
        bundle.unlink()
        log_fn(f"[autoboot] removed bundle {bundle.name} from ./bin/")
    except OSError as e:
        log_fn(f"[autoboot] could not remove bundle: {e}")

    extracted_elfs = _scan(out_dir)
    if skipped_rel[0]:
        log_fn(
            f"[autoboot] skipped {skipped_rel[0]} relocatable object file(s) "
            f"(.o / ET_REL) — build tree, not challenge binaries"
        )
    if not extracted_elfs:
        log_fn(f"[autoboot] bundle {bundle.name} contained no ELF")
        return []

    # A JS-engine build (d8 / js / jsc + snapshot_blob.bin) is staged as a
    # UNIT: the engine plus the non-ELF siblings it loads at startup, and
    # NONE of the co-located build tools. Flattening the engine alone
    # produces a ./bin/d8 that cannot start (see _JS_ENGINE_DATA).
    engine_dir = _js_engine_dir(extracted_elfs, out_dir)
    engine = _pick_js_engine(extracted_elfs, engine_dir) if engine_dir else None
    if engine is not None:
        dropped = [
            e.name for e in extracted_elfs
            if e.parent == engine_dir and e != engine
        ]
        log_fn(
            f"[autoboot] JS-engine build detected: {engine.name} in "
            f"{engine_dir.name}/"
            + (f" — not staging co-located {', '.join(sorted(dropped))}"
               if dropped else "")
        )

    # Split into challenge binaries (non-.so) and shared libs. Flatten
    # the binaries into staged_bin so the prompt's ./bin/<name> path
    # resolves; copy the .so / ld-* libs into .chal-libs so chal-libc-fix
    # can take the bundled-libs fast path without needing JOB_ID +
    # HOST_DATA_DIR for a docker-pull fallback.
    chal_libs_dir = work_dir / ".chal-libs"
    flattened: list[Path] = []
    engine_libs: list[str] = []
    for src in extracted_elfs:
        if engine is not None and src.parent == engine_dir and src != engine:
            # A component build (is_component_build=true) puts libv8.so /
            # libv8_libbase.so beside the shell, and SpiderMonkey ships
            # libmozglue / libnspr4 — all resolved through rpath $ORIGIN, so
            # they must land NEXT TO the engine in ./bin/, not in .chal-libs.
            # Dropping them produced a ./bin/<engine> that dies in the loader:
            # exactly the unstartable-engine bug this path exists to prevent.
            if _is_shared_lib(src):
                try:
                    dst = staged_bin / src.name
                    if not dst.exists():
                        shutil.copy2(src, dst)
                        dst.chmod(0o755)
                        engine_libs.append(src.name)
                except Exception as e:
                    log_fn(f"[autoboot] engine lib {src.name} failed: {e}")
            continue
        try:
            if _is_shared_lib(src):
                chal_libs_dir.mkdir(parents=True, exist_ok=True)
                # libc-2.23.so → keep as libc.so.6 alias the linker expects
                target_name = src.name
                if target_name.startswith("libc-") and target_name.endswith(".so"):
                    alias = chal_libs_dir / "libc.so.6"
                    if not alias.exists():
                        shutil.copy2(src, alias)
                        alias.chmod(0o755)
                dst = chal_libs_dir / target_name
                if not dst.exists():
                    shutil.copy2(src, dst)
                    dst.chmod(0o755)
            else:
                dst = staged_bin / src.name
                if not dst.exists() or dst.stat().st_size != src.stat().st_size:
                    shutil.copy2(src, dst)
                    dst.chmod(0o755)
                flattened.append(dst)
        except Exception as e:
            log_fn(f"[autoboot] flatten {src.name} failed: {e}")

    # Runtime data the engine loads from its OWN directory. Copied AFTER
    # the ELF flatten so ./bin/<engine> is self-sufficient.
    if engine is not None:
        staged_siblings: list[str] = []
        budget = _JS_SIBLING_TOTAL_MAX_BYTES
        for sib in sorted(engine_dir.iterdir()):
            if sib.is_symlink():
                continue          # never follow a bundle-supplied symlink
            if not sib.is_file() or _elf_kind(sib) is not None:
                continue
            if sib.name.startswith("."):
                continue  # .ninja_deps / .ninja_log — build state, not runtime
            try:
                size = sib.stat().st_size
                if size > _JS_SIBLING_MAX_BYTES or size > budget:
                    continue
                dst = staged_bin / sib.name
                # NEVER clobber a challenge binary flattened from another
                # directory: this loop runs after the ELF flatten, and a
                # 7-byte `chall` text file in the engine dir used to silently
                # replace the real ./bin/chall.
                if dst.exists() and _elf_kind(dst) is not None:
                    log_fn(
                        f"[autoboot] engine sibling {sib.name} NOT staged — "
                        f"would overwrite the ELF already at ./bin/{sib.name}"
                    )
                    continue
                if not dst.exists() or dst.stat().st_size != size:
                    shutil.copy2(sib, dst)
                budget -= size
                staged_siblings.append(sib.name)
            except Exception as e:
                log_fn(f"[autoboot] engine sibling {sib.name} failed: {e}")
        if staged_siblings:
            log_fn(
                f"[autoboot] staged engine runtime data into ./bin/: "
                f"{', '.join(staged_siblings)}"
            )
        if engine_libs:
            log_fn(
                f"[autoboot] staged engine shared libs next to it: "
                f"{', '.join(sorted(engine_libs))}"
            )
        # Record the identification while the tree structure is still intact;
        # _staged_js_engine reads this back instead of re-deriving.
        try:
            (work_dir / _JS_ENGINE_MARKER).write_text(engine.name)
        except Exception as e:
            log_fn(f"[autoboot] could not record engine marker: {e}")

    if flattened:
        log_fn(
            f"[autoboot] flattened {len(flattened)} binary/binaries into "
            f"./bin/: {', '.join(p.name for p in flattened)}"
        )
    if chal_libs_dir.is_dir():
        libs = sorted(p.name for p in chal_libs_dir.iterdir() if p.is_file())
        if libs:
            log_fn(
                f"[autoboot] pre-staged libs into ./.chal-libs/: "
                f"{', '.join(libs)}"
            )

    elfs.extend(flattened or extracted_elfs)
    return elfs


_DIFF_TARGET_RE = re.compile(r"^(?:\+\+\+|---)\s+(?:[ab]/)?(\S+)")
# The shell's own sources. `src/d8/` is the post-7.5 layout; before that (and
# the oob-v8-era builds are the commonest V8 vintage in CTF) the shell was the
# FLAT `src/d8.cc` / `src/d8-posix.cc` / `src/d8.h`. Matching only the
# directory form classified those files' hunks as CANDIDATE BUG — the exact
# inversion this split exists to prevent, reintroduced for older engines.
_D8_PATH_RE = re.compile(r"(?:^|/)src/d8(?:/|\.|-)")

# Caps on what CHALLENGE-CONTROLLED bytes may contribute to V8_PREFLIGHT.md.
_PROBE_MAX_CHARS = 2000
_PROBE_MAX_OUTPUT_BYTES = 16 * 1024 * 1024
_PATCH_MAX_BYTES = 2 * 1024 * 1024      # per patch file read
_BUG_RENDER_MAX = 8000
_D8_RENDER_MAX = 4000
_HARDENING_LIST_MAX = 40                # filenames listed before eliding


def _kill_process_group(proc) -> None:
    """SIGKILL the child's whole process group (it was started with
    start_new_session, so its pgid == its pid). Falls back to killing the
    direct child if the group is already gone."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _reap_engine_processes(engine: Path, log_fn) -> int:
    """SIGKILL any process still running THIS exact engine binary.

    A probe's grandchild that called ``setsid()`` escapes the process group,
    so killpg cannot reach it and it accumulates in the long-lived worker for
    the rest of the job. This is a PRECISE sweep — it resolves
    ``/proc/<pid>/exe`` and kills only processes whose executable IS the
    engine we just ran, never a name match — and it runs at autoboot, before
    the agent exists, so nothing legitimate can be running that binary yet.
    """
    killed = 0
    try:
        target = engine.resolve()
        me = os.getpid()
    except Exception:
        return 0
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid == me:
            continue
        try:
            if Path(f"/proc/{pid}/exe").resolve() != target:
                continue
            os.kill(pid, signal.SIGKILL)
            killed += 1
        except Exception:
            continue
    if killed:
        log_fn(
            f"[autoboot] reaped {killed} leftover {engine.name} process(es) "
            f"from the preflight probes"
        )
    return killed


def _fence_safe(s: str) -> str:
    """Neutralise text that would ESCAPE the markdown code fence it is about
    to be pasted into. V8_PREFLIGHT.md is presented to the agent as "fact,
    not speculation", so a challenge binary (or a .patch) that prints a
    closing fence could continue as authoritative prose — prompt injection
    into the agent's own orientation document."""
    return s.replace("```", "'''")


def _has_body(lines: list[str]) -> bool:
    """True once an open diff record has both its `+++` header and a hunk —
    i.e. the next `--- ` belongs to the NEXT file, not to this one."""
    return (any(ln.startswith("+++ ") for ln in lines)
            and any(ln.startswith("@@") for ln in lines))


def _split_engine_patch(text: str) -> tuple[list[str], list[tuple[str, str]]]:
    """Split a unified diff into (candidate-bug chunks, d8-side entries).

    A JS-engine challenge ships ONE patch that does two things: it introduces
    the bug (``src/compiler/``, ``src/objects/``, ``src/builtins/`` …) and it
    strips d8's escape hatches (``src/d8/`` — os.system / read / load /
    Realm). The second part is bulk: on job 5cb4ecb67214 the load-bearing hunk
    (a two-line ``JSCallTyper`` change) is 1 of 3 files and ~4 % of the diff.

    Returns ``(bug_chunks, [(path, chunk), ...])``. The d8 side keeps its FULL
    text: "src/d8 is never the bug" is a useful prior, not a fact — a
    challenge whose bug is a custom builtin added to ``d8.cc`` is a mainstream
    construction, and the earlier version reduced that patch to a bare
    filename under a heading that said it was NOT the bug. The caller decides
    how much to render.

    Record boundaries accepted: ``diff --git``, ``diff --cc`` (merge), quilt
    ``Index:``, and a bare ``--- `` header (plain ``diff -u`` / ``diff -Naur``
    output, which has no git line at all — previously the parser produced
    nothing for those and the caller still logged "split").
    """
    bug: list[str] = []
    hardening: list[tuple[str, str]] = []
    current: list[str] = []
    target = ""

    def _flush() -> None:
        nonlocal current, target
        if not current:
            return
        chunk = "\n".join(current)
        # Path evidence from EVERY header line in the chunk, not just `+++`:
        # a file DELETION (the commonest d8 hardening move) emits
        # `+++ /dev/null`, which used to send the whole hunk to the bug side.
        paths = [target] + _DIFF_TARGET_RE.findall(chunk)
        paths = [p for p in paths if p and p != "/dev/null"]
        if any(_D8_PATH_RE.search(p) for p in paths):
            hardening.append((paths[0] if paths else "(unknown)", chunk))
        else:
            bug.append(chunk)
        current = []
        target = ""

    saw_git = False
    for line in text.splitlines():
        if line.startswith("diff --git ") or line.startswith("diff --cc "):
            saw_git = True
            _flush()
            current = [line]
            m = _DIFF_TARGET_RE.match("+++ " + line.split()[-1])
            target = m.group(1) if m else ""
            continue
        if line.startswith("Index: "):
            _flush()
            current = [line]
            target = line[len("Index: "):].strip()
            continue
        # A bare `--- a/x` opens a record when there is no open one, AND when
        # the open one already has a BODY (its own `+++` plus at least one
        # `@@`). Requiring `not current` meant a plain multi-file `diff -u`
        # merged every file into the FIRST record: a patch whose bug sat in
        # src/objects/ behind a src/d8/ entry was swallowed whole into the
        # hardening side and "CANDIDATE BUG" rendered empty.
        if line.startswith("--- ") and (not current or _has_body(current)):
            _flush()
            m = _DIFF_TARGET_RE.match(line)
            current = [line]
            target = m.group(1) if m else ""
            continue
        if current:
            current.append(line)
    _flush()
    del saw_git
    return bug, hardening


def _js_engine_preflight(
    engine: Path, work_dir: Path, search_root: Path | None, log_fn,
) -> Path | None:
    """Deterministic, no-LLM orientation for a JS-engine challenge →
    ``<work_dir>/V8_PREFLIGHT.md``.

    Every fact here cost the agent a turn on job 5cb4ecb67214: the engine
    was not executable (zip upload drops the mode bits), ``--version`` and
    ``--print-all-flags`` are not d8 flags, and the globals inventory (what
    the patch REMOVED) plus the bug-vs-hardening patch split decide the
    whole approach. Best-effort — any probe that fails is reported as such
    and never blocks the run.
    """
    md: list[str] = [
        "# JS-engine preflight (deterministic — no model in the loop)",
        "",
        f"Engine: `./bin/{engine.name}`  ({engine.stat().st_size:,} bytes)",
        "",
    ]

    def _probe(label: str, args: list[str], *, timeout: int = 25,
               max_chars: int = _PROBE_MAX_CHARS) -> str:
        # Capture to a FILE, not a pipe, and poll.
        #
        # With stdout=PIPE, communicate() waits for EOF on the pipe — which a
        # double-forked grandchild keeps open. A hostile "engine" whose direct
        # child exited in 10 ms still burnt the full timeout (measured: 94 s
        # across three probes) and then the second communicate() also timed
        # out, so the captured output was thrown away entirely. Polling
        # proc.poll() notices the real exit in <=0.1 s, and watching the file's
        # size bounds how much an engine that prints forever can write to disk.
        #
        # Residual, accepted and NOT claimed fixed: a grandchild that calls
        # setsid() leaves the group and survives the killpg. Killing that
        # needs a PID namespace; the container is the boundary, and the agent
        # runs this binary itself minutes later anyway.
        proc = None
        try:
            with tempfile.TemporaryFile(mode="w+b") as fh:
                proc = subprocess.Popen(
                    [str(engine), *args],
                    cwd=str(engine.parent), stdout=fh,
                    stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )
                deadline = time.monotonic() + timeout
                note = ""
                while True:
                    rc = proc.poll()
                    if rc is not None:
                        break
                    if time.monotonic() > deadline:
                        _kill_process_group(proc)
                        note = f"\n(TIMED OUT after {timeout}s — group killed)"
                        rc = None
                        break
                    try:
                        if os.fstat(fh.fileno()).st_size > _PROBE_MAX_OUTPUT_BYTES:
                            _kill_process_group(proc)
                            note = "\n(output cap hit — killed)"
                            rc = None
                            break
                    except OSError:
                        pass
                    time.sleep(0.05)
                try:
                    fh.seek(0)
                    raw = fh.read(max_chars * 4 + 64)
                except Exception:
                    raw = b""
            text = raw.decode("utf-8", errors="replace")
            # SAY when the slice cut something. The globals probe emits one
            # long sorted line whose TAIL is exactly the lowercase d8 helpers
            # the section exists to enumerate, so a silent cut removed the
            # answer while the surrounding prose still told the agent that
            # anything absent from the list is closed.
            if len(text) > max_chars:
                text = text[:max_chars] + f"\n(TRUNCATED at {max_chars} chars)"
            out = _fence_safe(text.strip() + note)
            return out or f"(no output, rc={rc})"
        except Exception as e:
            if proc is not None:
                _kill_process_group(proc)
            return f"(probe failed: {e})"
        finally:
            del label

    try:
        engine.chmod(0o755)
    except Exception:
        pass

    md += [
        "## Version",
        "```",
        _probe("version", ["-e", "print(version())"]),
        "```",
        "",
        "## Globals actually exposed by THIS build",
        "The patch usually DELETES d8 helpers (`read`, `load`, `readline`,",
        "`writeFile`, `os.*`, `Realm`) so the trivial file-read / command-exec",
        "escapes are closed. Anything missing here is closed; anything present",
        "(`WebAssembly`, `Worker`, `SharedArrayBuffer`, `Atomics`) is in scope.",
        "```",
        _probe("globals", [
            "-e",
            "print(Object.getOwnPropertyNames(globalThis).sort().join(', '))",
        ], max_chars=8000),
        "```",
        "",
        "## --allow-natives-syntax (LOCAL triage only)",
        "If this prints `ok`, %DebugPrint / %OptimizeFunctionOnNextCall /",
        "%SystemBreak work LOCALLY. The REMOTE service almost never passes the",
        "flag — every primitive must be re-derived with plain warm-up loops",
        "before it goes into the exploit.",
        "```",
        _probe("natives", ["--allow-natives-syntax", "-e",
                           "function f(){}; %PrepareFunctionForOptimization(f);"
                           " %OptimizeFunctionOnNextCall(f); f(); print('ok')"]),
        "```",
        "",
    ]

    roots = [r for r in (search_root, work_dir / "chal") if r and r.is_dir()]
    # The same file is routinely reachable through two roots (./src/ holds
    # the operator's upload, ./work/chal/ the unpacked copy). Dedupe on
    # (name, size) so the report doesn't print a patch twice.
    seen: set[tuple[str, int]] = set()

    def _find(names: tuple[str, ...], suffixes: tuple[str, ...] = ()) -> list[Path]:
        hits: list[Path] = []
        for root in roots:
            try:
                for f in root.rglob("*"):
                    if not f.is_file():
                        continue
                    if not (f.name in names or (
                        suffixes and f.name.endswith(suffixes)
                    )):
                        continue
                    key = (f.name, f.stat().st_size)
                    if key in seen:
                        continue
                    seen.add(key)
                    hits.append(f)
            except Exception:
                continue
        return hits[:4]

    for cfg in _find(("args.gn", "v8_build_config.json")):
        try:
            body = cfg.read_text(errors="replace")[:1500]
        except Exception:
            continue
        md += [f"## Build config — `{cfg.name}`", "```",
               _fence_safe(body.strip()), "```", ""]

    def _render(chunks: list[str], budget: int) -> str:
        """Join `chunks` under a byte budget and say HONESTLY what was cut —
        a bare '… (truncated)' let whole files vanish while the heading still
        claimed the reader had seen the bug side."""
        kept, used, dropped = [], 0, 0
        for c in chunks:
            if used + len(c) > budget and kept:
                dropped += 1
                continue
            kept.append(c[:budget])
            used += len(c)
        body = _fence_safe("\n\n".join(kept))
        if dropped:
            body += (
                f"\n\n… {dropped} further file entr"
                f"{'y' if dropped == 1 else 'ies'} OMITTED for length — "
                f"read the patch file itself for the rest."
            )
        return body

    patches = _find((), (".patch", ".diff"))
    split_ok = 0
    for p in patches:
        try:
            if p.stat().st_size > _PATCH_MAX_BYTES:
                md += [f"## Patch `{p.name}`",
                       f"({p.stat().st_size:,} bytes — too large to split here; "
                       f"read it directly.)", ""]
                continue
            # utf-8-sig: a BOM on the first line stopped `diff --git` from
            # matching, silently dropping the patch's first file entry.
            text = p.read_text(encoding="utf-8-sig", errors="replace")
        except Exception:
            continue
        bug, hardening = _split_engine_patch(text)
        if bug or hardening:
            split_ok += 1
        md += [f"## Patch `{p.name}` — split by intent", ""]
        if bug:
            md += [
                "**CANDIDATE BUG — the engine-internals side of the patch. "
                "This is the most likely thing you are meant to exploit:**",
                "```diff", _render(bug, _BUG_RENDER_MAX), "```", "",
            ]
        if hardening:
            names = [h[0] for h in hardening]
            shown = names[:_HARDENING_LIST_MAX]
            md += [
                f"`src/d8/` side, {len(names)} file(s): "
                + ", ".join(f"`{n}`" for n in shown)
                + ("" if len(names) == len(shown)
                   else f" … +{len(names) - len(shown)} more"),
                "",
                "This is USUALLY attack-surface removal (deleting `os.system`, "
                "`read`, `load`, `Realm`) rather than the bug — but NOT always: "
                "a challenge whose bug is a custom builtin ADDED to `d8.cc` is a "
                "standard construction. Read it, especially if the bug side "
                "above is empty or looks inert:",
                "```diff",
                _render([h[1] for h in hardening],
                        _D8_RENDER_MAX if bug else _BUG_RENDER_MAX),
                "```", "",
            ]
        if not bug and not hardening:
            md += [
                "(this file did not parse as a unified diff — read it directly)",
                "",
            ]

    _reap_engine_processes(engine, log_fn)

    out = work_dir / "V8_PREFLIGHT.md"
    try:
        out.write_text("\n".join(md))
    except Exception as e:
        log_fn(f"[autoboot] V8_PREFLIGHT.md write failed: {e}")
        return None
    log_fn(
        f"[autoboot] wrote V8_PREFLIGHT.md ({out.stat().st_size} B; "
        f"{split_ok}/{len(patches)} patch file(s) split)"
    )
    return out


def _libc_version(libc: Path | None) -> str | None:
    """Extract glibc major.minor from a libc.so's version banner via
    `strings`. Returns None on any failure (best-effort; used only for a
    diagnostic warning, never for control flow)."""
    if not libc:
        return None
    try:
        out = subprocess.run(
            ["strings", str(libc)], capture_output=True, text=True,
            timeout=30, check=False,
        ).stdout
    except Exception:
        return None
    m = re.search(r"GNU C Library.*?(?:version|GLIBC)\s*(\d+\.\d+)", out)
    return m.group(1) if m else None


def _safe_extract_tar(tf, dest: Path) -> None:
    """Extract a tarfile into dest, rejecting members whose resolved path
    escapes dest (path-traversal guard). Used by the ar/tar .deb fallback
    instead of tarfile's `filter="data"` — the latter aborts the whole
    archive on the absolute-path symlinks glibc ships, which we don't
    need (staging follows the real versioned files, not the symlinks)."""
    dest = dest.resolve()
    base = str(dest) + os.sep
    for m in tf.getmembers():
        target = (dest / m.name).resolve()
        if str(target) != str(dest) and not str(target).startswith(base):
            continue
        tf.extract(m, dest)


def _extract_deb(deb: Path, dest: Path, log_fn) -> bool:
    """Extract a .deb's data payload into ``dest``. Primary path is
    ``dpkg-deb -x`` (canonical; handles xz/gz/zst uniformly and preserves
    the symlinks glibc ships — libc.so.6 -> libc-X.Y.so, ld-linux-*.so.2
    -> ld-X.Y.so). Falls back to ``ar x`` + tarfile when dpkg-deb is
    absent. Returns True on success."""
    dest.mkdir(parents=True, exist_ok=True)
    try:
        res = subprocess.run(
            ["dpkg-deb", "-x", str(deb), str(dest)],
            capture_output=True, text=True, timeout=180, check=False,
        )
        if res.returncode == 0:
            return True
        log_fn(
            f"[autoboot] dpkg-deb -x {deb.name} exited {res.returncode}: "
            f"{(res.stderr or '').strip()[:160]}"
        )
    except FileNotFoundError:
        pass  # dpkg-deb not installed — try the ar fallback below.
    except Exception as e:
        log_fn(f"[autoboot] dpkg-deb -x {deb.name} failed: {e}")

    # Fallback: unpack the outer `ar` archive, extract its data.tar.* via
    # tarfile (autodetects gz/bz2/xz). Zstd-compressed payloads are left
    # to dpkg-deb (present on the worker); this covers the era-relevant
    # libc debs (2.27/2.31/2.35 = data.tar.xz).
    try:
        import glob as _glob
        import tarfile
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            res = subprocess.run(
                ["ar", "x", str(deb.resolve())],
                cwd=td, capture_output=True, text=True, timeout=180,
                check=False,
            )
            if res.returncode != 0:
                log_fn(
                    f"[autoboot] ar x {deb.name} failed: "
                    f"{(res.stderr or '').strip()[:160]}"
                )
                return False
            members = sorted(_glob.glob(os.path.join(td, "data.tar*")))
            if not members:
                log_fn(f"[autoboot] {deb.name}: no data.tar.* after ar x")
                return False
            # NB: not tarfile's `filter="data"` — it aborts the whole
            # extraction on the absolute-path symlinks glibc ships
            # (lib64/ld-linux-*.so.2 -> /lib/.../ld-X.Y.so). We only
            # follow the real versioned files during staging, so a manual
            # traversal guard (member-name only) is both sufficient and
            # tolerant of those symlinks.
            with tarfile.open(members[0], mode="r:*") as tf:
                _safe_extract_tar(tf, dest)
        return True
    except Exception as e:
        log_fn(f"[autoboot] .deb ar/tar fallback failed for {deb.name}: {e}")
        return False


def _stage_glibc_from_tree(tree: Path, chal_libs_dir: Path, log_fn) -> list[str]:
    """Copy the glibc + ld loader + standard aux libs from an extracted
    .deb tree into ``.chal-libs/``. Only libs ``_is_standard_libname``
    recognises are staged — libc.so.6, libc-X.Y.so, ld-linux-*.so.*,
    libm/libdl/libpthread/librt/libresolv/libnsl/libutil/libcrypt/libnss_*
    — so glibc internals with non-standard names (libmvec, libanl,
    libBrokenLocale, libSegFault, ld-X.Y.so) are NOT staged and thus can't
    be misread as chal-author custom libraries by ``_detect_custom_libs``
    (the OpenSSL/libcrypto misclassification lesson, job 44dd25365173).
    Follows symlinks (glibc ships libc.so.6 / ld-linux-*.so.2 as symlinks
    to the real versioned file — ``is_file()`` + ``copy2`` both follow).
    Never clobbers an already-staged file. Returns new basenames staged."""
    staged: list[str] = []
    try:
        entries = sorted(tree.rglob("*"))
    except Exception:
        return staged
    for f in entries:
        try:
            if not f.is_file():  # follows symlinks; skips dirs/broken links
                continue
        except OSError:
            continue
        n = f.name
        if ".so" not in n.lower():
            continue
        if not _is_standard_libname(n):
            continue
        chal_libs_dir.mkdir(parents=True, exist_ok=True)
        dst = chal_libs_dir / n
        if dst.exists():
            continue
        try:
            shutil.copy2(f, dst)  # follows the symlink -> real content
            dst.chmod(0o755)
            staged.append(n)
        except Exception as e:
            log_fn(f"[autoboot] stage {n} from .deb failed: {e}")
    return staged


def _stage_libs_from_debs(work_dir: Path, log_fn) -> list[str]:
    """Auto-extract any glibc .deb bundled with the challenge and pre-stage
    the libc + ld loader it ships into ``./.chal-libs/``.

    Dreamhack-style pwn chals often ship the exact deploy glibc as a .deb
    (e.g. ``libc6_2.27-3ubuntu1.2_amd64.deb``, job a5d51c5b8217). find_pair
    / chal-libc-fix can only see loose ``libc.so.6`` + ``ld-linux-*`` files
    — they can't look inside the .deb's ``ar`` archive — so without this
    the agent has to ``dpkg-deb -x`` by hand before it can get correct
    heap/FSOP/one_gadget offsets. Runs in autoboot BEFORE ``chal-libc-fix``
    so its Priority-0 fast path (``.chal-libs/libc.so.6`` +
    ``ld-linux-*.so.*`` present) short-circuits on the staged libs.

    Best-effort: any failure is logged and swallowed. Returns the list of
    newly-staged lib basenames."""
    # Collect glibc .deb files bundled with the chal. Name-prefilter to
    # libc/glibc so an unrelated package .deb isn't needlessly extracted.
    seen: set[Path] = set()
    debs: list[Path] = []
    for root, recursive in ((work_dir / "bin", True),
                            (work_dir / "chal", True),
                            (work_dir, False)):
        if not root.is_dir():
            continue
        try:
            it = root.rglob("*.deb") if recursive else root.glob("*.deb")
        except Exception:
            continue
        for p in it:
            try:
                rp = p.resolve()
            except Exception:
                continue
            if not p.is_file() or rp in seen:
                continue
            low = p.name.lower()
            if "libc" not in low and "glibc" not in low:
                log_fn(
                    f"[autoboot] skipping non-glibc .deb {p.name} "
                    f"(name has no libc/glibc marker)"
                )
                continue
            seen.add(rp)
            debs.append(p)
    if not debs:
        return []

    chal_libs_dir = work_dir / ".chal-libs"
    pre_existing_libc = chal_libs_dir / "libc.so.6"
    had_libc = pre_existing_libc.is_file()

    staged: list[str] = []
    deb_libc: Path | None = None
    for deb in debs:
        dest = deb.parent / (deb.stem + "_extracted")
        already = dest.is_dir() and any(dest.rglob("libc.so.6"))
        if not already:
            try:
                rel = dest.relative_to(work_dir)
            except ValueError:
                rel = dest.name
            log_fn(f"[autoboot] extracting libc from {deb.name} -> ./{rel}/")
            if not _extract_deb(deb, dest, log_fn):
                log_fn(f"[autoboot] .deb extraction failed for {deb.name}; skipping")
                continue
        staged.extend(_stage_glibc_from_tree(dest, chal_libs_dir, log_fn))
        if deb_libc is None:
            deb_libc = next(iter(dest.rglob("libc.so.6")), None) or next(
                iter(dest.rglob("libc-*.so")), None
            )

    if staged:
        log_fn(
            f"[autoboot] pre-staged from .deb into ./.chal-libs/: "
            f"{', '.join(staged)}"
        )

    # A loose libc was already staged (e.g. bundled alongside the .deb) and
    # we did NOT clobber it. If the .deb — the authoritative deploy libc —
    # ships a different glibc version, surface it: a wrong-libc silent miss
    # is the recurring expensive class (remote SIGSEGV, job 8806b284d740).
    if had_libc and deb_libc is not None:
        v_staged = _libc_version(pre_existing_libc)
        v_deb = _libc_version(deb_libc)
        if v_staged and v_deb and v_staged != v_deb:
            log_fn(
                f"[autoboot] WARNING: ./.chal-libs/libc.so.6 was already "
                f"staged as glibc {v_staged} (kept), but {debs[0].name} "
                f"ships glibc {v_deb} — the .deb is the deploy libc. If "
                f"remote offsets look wrong, replace .chal-libs/libc.so.6 "
                f"with the .deb build."
            )
    return staged


def _autobootstrap_libc(
    staged_bin: Path,
    work_dir: Path,
    log_fn,
    *,
    job_id: str,
    timeout_s: int = 180,
) -> tuple[Path | None, str | None]:
    """Run `chal-libc-fix` against the first ELF in <staged_bin> BEFORE the
    agent starts, so ./.chal-libs/libc_profile.json is always on disk when
    the agent enters its first turn.

    Returns ``(profile_path, elf_basename)``:
      - ``profile_path`` — path to libc_profile.json on success, else None.
      - ``elf_basename`` — basename of the canonical chal ELF inside
        ``./bin/`` (e.g. ``chall``) so the caller can use it as
        ``binary_name`` in the agent prompt. Mismatched / missing means
        autoboot couldn't pick a canonical binary; caller falls back to
        the upload filename.

    Why: models repeatedly dove into decompile analysis and never
    looped back to step 5 of the workflow (chal-libc-fix). With the
    profile missing, the rest of the heap pipeline (scaffold templates,
    heap-probe, judge failure_code matrix) operates on absent data.
    Pre-baking it shifts the pipeline from model-action-dependent to
    deterministic.

    .zip / .tar bundles (Dreamhack standard) are auto-unpacked into
    <work_dir>/chal/ first; the discovered ELFs are flattened into
    ``./bin/`` and any chal-supplied libc/ld/.so files are pre-staged
    into ``./.chal-libs/`` (see ``_find_elf_or_unzip``).

    Best-effort: any failure is logged and swallowed; the agent can still
    try chal-libc-fix manually from its prompt.
    """
    elf_candidates = _find_elf_or_unzip(staged_bin, work_dir, log_fn)
    # A chal may ship its deploy glibc as a .deb (Dreamhack style, job
    # a5d51c5b8217) that find_pair/chal-libc-fix can't see inside. Auto-
    # extract + pre-stage libc/ld into ./.chal-libs/ HERE — before the
    # chal-libc-fix subprocess below, whose Priority-0 fast path then
    # short-circuits on the staged pair. Runs even with no local ELF.
    try:
        _stage_libs_from_debs(work_dir, log_fn)
    except Exception as e:
        log_fn(f"[autoboot] .deb libc pre-stage failed (non-fatal): {e}")
    if not elf_candidates:
        log_fn("[autoboot] no ELF found in ./bin/ — skipping chal-libc-fix")
        return (None, None)
    # A JS-engine shell is a self-contained multi-hundred-MB C++ build, not
    # a chal-authored ELF: patchelf'ing it against a bundled glibc is
    # meaningless (it ships no libc), the libc_profile heap catalogue does
    # not apply, and `ghiant` on a 37 MB binary exhausts the decompiler's
    # 4 GB / 900 s budget without producing anything usable. Hand the engine
    # back as the canonical binary and skip the ELF-shaped pre-bake.
    engine = _staged_js_engine(staged_bin)
    if engine is not None:
        log_fn(
            f"[autoboot] JS-engine shell ./bin/{engine.name} — skipping "
            f"chal-libc-fix + ghiant pre-bake (see V8_PREFLIGHT.md)"
        )
        return (None, engine.name)
    # Pick the largest ELF inside ./bin/ as the canonical chal — small
    # auxiliary binaries (helpers, libsalloc-style wrappers) sort below
    # the real challenge by size.
    bin_elfs = [
        e for e in elf_candidates if e.parent.resolve() == staged_bin.resolve()
    ]
    if not bin_elfs:
        bin_elfs = elf_candidates
    bin_elfs.sort(key=lambda p: p.stat().st_size, reverse=True)
    elf = bin_elfs[0]
    elf_basename = elf.name if elf.parent.resolve() == staged_bin.resolve() else None

    # /retry + /resume copy prev_jd/work → new_jd/work, which brings the
    # patchelf'd prob and the chal-libs profile with it. chal-libc-fix
    # is deterministic for a given binary, so re-running it just to
    # produce identical bytes is ~5-15 s of wasted subprocess time.
    # Skip when both artifacts are present from the prior run.
    profile = work_dir / ".chal-libs" / "libc_profile.json"
    prob = work_dir / "prob"
    if profile.is_file() and prob.is_file():
        log_fn(
            f"[autoboot] libc_profile.json + prob cached from prior "
            f"run ({profile.stat().st_size} B) — skip chal-libc-fix"
        )
        return (profile, elf_basename)

    try:
        if not prob.exists() or prob.stat().st_size != elf.stat().st_size:
            shutil.copy2(elf, prob)
            prob.chmod(0o755)
    except Exception as e:
        log_fn(f"[autoboot] could not stage ./prob: {e}")
        return (None, elf_basename)
    cmd = ["chal-libc-fix", str(prob)]
    log_fn(f"[autoboot] running: {' '.join(cmd)}")
    # Inherit worker env + force-set JOB_ID / HOST_DATA_DIR. chal-libc-fix
    # uses these to bind-mount the job dir into a sibling docker for
    # base-image extraction; without them it aborts before pulling and
    # the binary runs against the wrong libc. JOB_ID isn't in the worker
    # env at autoboot time because it's per-job, and HOST_DATA_DIR may
    # be absent if compose env_file is misconfigured — set both.
    env = os.environ.copy()
    env["JOB_ID"] = job_id
    host_data_dir = os.environ.get("HOST_DATA_DIR") or ""
    if host_data_dir:
        env["HOST_DATA_DIR"] = host_data_dir
    # Same terminfo silencing the agent SDK gets — chal-libc-fix shells
    # out to pwntools' ELF helper which otherwise prints a
    # `_curses.error: setupterm: could not find terminfo database`
    # warning on every invocation (worker container has no terminfo).
    # PWNLIB_SILENT is intentionally NOT set here: it would also gag
    # any pwntools diagnostic emitted by chal-libc-fix's ELF analysis,
    # which is the most useful breadcrumb when autoboot misbehaves.
    env.setdefault("TERM", "xterm")
    env.setdefault("PWNLIB_NOTERM", "1")
    try:
        res = subprocess.run(
            cmd, cwd=str(work_dir), env=env,
            capture_output=True, text=True, timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        log_fn(f"[autoboot] chal-libc-fix timed out after {timeout_s}s")
        return (None, elf_basename)
    except FileNotFoundError:
        log_fn("[autoboot] chal-libc-fix not on PATH (build is older than the patch)")
        return (None, elf_basename)
    except Exception as e:
        log_fn(f"[autoboot] chal-libc-fix spawn failed: {e}")
        return (None, elf_basename)
    for line in (res.stdout or "").splitlines()[-12:]:
        log_fn(f"[autoboot] {line}")
    for line in (res.stderr or "").splitlines()[-6:]:
        log_fn(f"[autoboot] STDERR: {line}")
    profile = work_dir / ".chal-libs" / "libc_profile.json"
    if profile.is_file():
        log_fn(f"[autoboot] libc_profile.json ready ({profile.stat().st_size} B)")
        return (profile, elf_basename)
    log_fn(
        f"[autoboot] chal-libc-fix exited {res.returncode} but no "
        f"libc_profile.json — likely musl/distroless. Agent falls back to "
        f"worker libc."
    )
    return (None, elf_basename)


async def _run_agent(
    job_id: str,
    binary_name: str,
    bin_dir: Path,
    target: Optional[str],
    description: Optional[str],
    auto_run: bool,
    model_override: Optional[str] = None,
) -> dict:
    work_dir = job_dir(job_id) / "work"
    work_dir.mkdir(exist_ok=True)

    staged_bin = work_dir / "bin"
    if staged_bin.exists():
        shutil.rmtree(staged_bin)
    shutil.copytree(bin_dir, staged_bin)
    # Make sure the binary inside the staged dir is executable
    for f in staged_bin.iterdir():
        try:
            f.chmod(0o755)
        except Exception:
            pass

    # Pre-bake ./.chal-libs/libc_profile.json BEFORE the agent's first
    # turn. Models historically skipped this step and the rest of the
    # heap pipeline (scaffold templates, heap-probe, judge failure
    # matrix) became dead code as a result. Doing it here makes the
    # profile data deterministic; the agent only has to READ it.
    _profile, autoboot_elf_name = _autobootstrap_libc(
        staged_bin, work_dir, lambda s: log_line(job_id, s),
        job_id=job_id,
    )

    # If autoboot flattened a zip + discovered the real ELF, prefer that
    # name in the user prompt over the .zip filename the user uploaded.
    # ``./bin/<binary_name>`` references in the prompt then resolve to
    # the actual challenge instead of confusing the agent with a zip
    # path (observed live on 5963af004fdc).
    effective_binary_name = autoboot_elf_name or binary_name
    chal_unpacked = (work_dir / "chal").is_dir()

    # JS-engine challenge → deterministic preflight before turn 1.
    js_engine = _staged_js_engine(staged_bin)
    if js_engine is not None:
        try:
            _js_engine_preflight(
                js_engine, work_dir, job_dir(job_id) / "src",
                lambda s: log_line(job_id, s),
            )
        except Exception as e:
            log_line(job_id, f"[autoboot] JS-engine preflight failed: {e}")
    # Detect chal-author-supplied .so files in .chal-libs/. When present
    # they almost always contain the primitive — surface to pre-recon
    # so the static-triage prompt explicitly asks recon to enumerate
    # each export and identify divergences from standard libc semantics.
    custom_libs = _detect_custom_libs(work_dir)
    custom_lib_decomps: dict[str, Path] = {}
    if custom_libs:
        log_line(
            job_id,
            f"[autoboot] custom chal libraries detected: "
            f"{', '.join(custom_libs)} — pre-recon will require "
            f"export-by-export divergence analysis"
        )
        custom_lib_decomps = _autodecomp_custom_libs(
            custom_libs, work_dir, job_id
        )

    # Item 5 — light autoboot summary breadcrumb. Captures heavy
    # autoboot outputs (effective binary name, custom libs, libc
    # profile presence) into ./AUTOBOOT.md so subagents read the same
    # baseline orientation regardless of which spawn they are.
    libc_profile = work_dir / ".chal-libs" / "libc_profile.json"
    custom_decomp_paths = (
        ", ".join(f"./{p.name}/" for p in custom_lib_decomps.values())
        if custom_lib_decomps else "(none)"
    )
    module_autoboot(
        "pwn", work_dir, lambda s: log_line(job_id, s),
        extras={
            "effective_binary": effective_binary_name or "(none)",
            "chal_unpacked": str(chal_unpacked),
            "custom_libs": ", ".join(custom_libs) if custom_libs else "(none)",
            "custom_lib_decomp_paths": custom_decomp_paths,
            "libc_profile_present": libc_profile.is_file(),
            "decomp_pre_baked": (work_dir / "decomp").is_dir(),
        },
    )

    model = resolve_main_model(model_override)
    resume_sid = read_meta(job_id).get("resume_session_id")
    # Heap detection up-front so the orchestrator's scaffold-missing
    # trip-wire (SCAFFOLD_NUDGE in run_main_agent_session) can fire
    # only when relevant.
    desc_match = looks_heap_advanced(description or "")
    work_match = _heap_signals_present(work_dir, custom_libs)
    heap_kw = desc_match or work_match
    summary: dict = {
        "messages": 0, "tool_calls": 0, "model": model,
        "heap_chal": True,                       # pwn module default
        "heap_chal_keyword_match": heap_kw,
        "heap_chal_signal_source": (
            "description+work" if (desc_match and work_match)
            else "description" if desc_match
            else "work-tree" if work_match
            else "none"
        ),
    }
    if work_match and not desc_match:
        log_line(
            job_id,
            f"[autoboot] heap_advanced=True via WORK-TREE signal "
            f"(description empty/no-keyword; custom_libs / libstdc++ / "
            f"chal source heap keywords promoted classification)"
        )
    options = make_main_session_options(
        job_id=job_id,
        work_dir=work_dir,
        model=model,
        system_prompt=SYSTEM_PROMPT,
        base_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
        summary=summary,
        resume_sid=resume_sid,
        effort=resolve_effort(read_meta(job_id).get("effort")),
    )
    # Auto-pre-recon — let recon do the static triage BEFORE main's
    # first turn so main starts with the 2 KB summary in its prompt
    # instead of having to decide "should I delegate?". Skip for
    # remote-only jobs (no binary to map) and for retries where main
    # is resuming a prior session (has its own context to lean on).
    recon_reply = ""
    if effective_binary_name and not resume_sid:
        # /retry + /resume copy prev_jd/work → new_jd/work
        # (api/routes/retry.py:_resubmit, carry_work=True). When the
        # binary hasn't changed the static-triage facts haven't either,
        # so a spawn (~$0.50, 2–6 min) is pure waste. The cache only
        # short-circuits the spawn inside the case we'd already run.
        recon_reply = load_cached_pre_recon(
            work_dir, lambda s: log_line(job_id, s),
            retry_of=read_meta(job_id).get("retry_of"),
        )
        if not recon_reply:
            recon_question = _build_pre_recon_prompt(
                binary_name=effective_binary_name,
                target=target,
                heap_advanced=heap_kw,
                chal_unpacked=chal_unpacked,
                custom_libs=custom_libs,
                libc_version=_read_libc_version(work_dir),
                js_engine=js_engine is not None,
            )
            log_line(job_id, "[pre-recon] spawning static-triage recon subagent")
            recon_reply = await run_pre_recon(
                job_id=job_id,
                work_dir=work_dir,
                model=model,
                prompt=recon_question,
                log_fn=lambda s: log_line(job_id, s),
            )
            # Verify mandatory heap sections actually landed. Across
            # jobs 96cd1092b992 → 7220cb10b2db pre-recon kept silently
            # dropping INT-OVERFLOW ANALYSIS / HEAP STATE MATRIX /
            # ENV-AWARE PATHS / RCE TARGET TABLE despite the prompt
            # marking them mandatory. One automated respawn with an
            # explicit "you missed these" message is cheaper than a
            # downstream main session re-deriving the same facts.
            if heap_kw and recon_reply is not None:
                missing = _missing_pre_recon_sections(
                    recon_reply, _HEAP_MANDATORY_SECTIONS,
                )
                # Degraded-reply detector. Two distinct failure modes get
                # collapsed here:
                #   (a) text exists but mandatory section titles absent
                #       (= model truncation / forgot prompt structure)
                #   (b) reply suspiciously short (< 300 chars) — usually
                #       means the recon SDK call hit a transient API
                #       error (529 Overloaded / rate-limit) BEFORE
                #       producing useful output. run_pre_recon swallows
                #       these and returns the partial.
                # Either is enough to trigger a retry; we don't gate the
                # backoff on (a) vs (b).
                _MIN_USEFUL_LEN = 300
                degraded = (
                    bool(missing)
                    or len((recon_reply or "").strip()) < _MIN_USEFUL_LEN
                )
                if degraded:
                    # Robust respawn — up to 4 attempts with exponential
                    # backoff. Concrete incident 2026-05-25 (job
                    # bfce7f3e0c11): respawn-ONCE hit 529 Overloaded
                    # immediately ($0.0048, 0 useful text), and the
                    # downstream main session got only 139 chars of
                    # recon → burned ~30 turns on self-grounding. 529s
                    # typically clear within 30-60s, so a short backoff
                    # ladder recovers most of them. The bracket
                    # (5/15/30/60s) keeps total worst-case spend under
                    # ~2 minutes of wall time.
                    MAX_RESPAWN = 4
                    BACKOFF_S = (5, 15, 30, 60)
                    respawn_prompt = (
                        recon_question
                        + "\n\n=== RESPAWN — PRIOR REPLY DEGRADED ===\n"
                        + (
                            "Your previous reply did NOT contain the "
                            "following MANDATORY section titles:\n"
                            + "\n".join(f"  - {s}" for s in missing) + "\n"
                            if missing else
                            "Your previous reply was too short to be "
                            "useful (likely a transient API error). "
                            "Re-emit the full recon report.\n"
                        )
                        + "Include each section as a literal heading; "
                        "body may be 'N/A — <one-line reason>' when "
                        "genuinely not applicable, but the title MUST "
                        "appear so the main agent's downstream logic can "
                        "detect it. Re-emit the FULL recon report (not "
                        "just the missing sections)."
                    )
                    succeeded = False
                    for attempt in range(MAX_RESPAWN):
                        if attempt > 0:
                            delay = BACKOFF_S[min(attempt - 1, len(BACKOFF_S) - 1)]
                            log_line(
                                job_id,
                                f"[pre-recon] backoff {delay}s before "
                                f"respawn attempt {attempt + 1}/"
                                f"{MAX_RESPAWN}"
                            )
                            await asyncio.sleep(delay)
                        log_line(
                            job_id,
                            f"[pre-recon] respawn attempt "
                            f"{attempt + 1}/{MAX_RESPAWN} "
                            f"(missing={missing or 'N/A'}, "
                            f"len={len((recon_reply or '').strip())})"
                        )
                        candidate = await run_pre_recon(
                            job_id=job_id,
                            work_dir=work_dir,
                            model=model,
                            prompt=respawn_prompt,
                            log_fn=lambda s: log_line(job_id, s),
                        )
                        cand_missing = _missing_pre_recon_sections(
                            candidate, _HEAP_MANDATORY_SECTIONS,
                        )
                        cand_len = len((candidate or "").strip())
                        cand_degraded = (
                            bool(cand_missing) or cand_len < _MIN_USEFUL_LEN
                        )
                        if not cand_degraded:
                            recon_reply = candidate
                            log_line(
                                job_id,
                                f"[pre-recon] respawn {attempt + 1} "
                                f"succeeded ({cand_len} chars, all "
                                f"mandatory sections present)"
                            )
                            succeeded = True
                            break
                        # Keep the longest non-empty candidate as a
                        # fallback — sometimes attempt 3 is shorter
                        # than attempt 1 because of throttling.
                        if cand_len > len((recon_reply or "").strip()):
                            recon_reply = candidate
                            missing = cand_missing
                        log_line(
                            job_id,
                            f"[pre-recon] respawn {attempt + 1} still "
                            f"degraded (missing={cand_missing}, "
                            f"len={cand_len}) — retrying"
                        )
                    if not succeeded:
                        log_line(
                            job_id,
                            f"[pre-recon] respawn EXHAUSTED after "
                            f"{MAX_RESPAWN} attempts — accepting best "
                            f"partial reply ({len((recon_reply or '').strip())} "
                            f"chars). Main starts with degraded recon "
                            f"— operator may need to /retry with hint."
                        )
            store_pre_recon_cache(
                work_dir, recon_reply, lambda s: log_line(job_id, s),
            )
        if recon_reply:
            log_line(
                job_id,
                f"[pre-recon] reply ready ({len(recon_reply)} chars) "
                f"— prepending to main user_prompt",
            )
        else:
            log_line(
                job_id,
                "[pre-recon] empty reply — main starts without "
                "pre-recon context (will need to delegate itself)",
            )

    # Build user_prompt AFTER pre-recon so we can tell main which
    # artifacts already exist on disk (./decomp/ populated by recon's
    # ghiant calls, ./.ghidra_proj/ cache, libc_profile.json) — main
    # would otherwise re-run ghiant or walk .text from scratch.
    decomp_dir = work_dir / "decomp"
    decomp_ready = decomp_dir.is_dir() and any(decomp_dir.glob("*.c"))
    decomp_files: list[str] = []
    if decomp_ready:
        try:
            decomp_files = sorted(p.name for p in decomp_dir.glob("*.c"))[:40]
        except OSError:
            decomp_files = []
    user_prompt = build_user_prompt(
        effective_binary_name, target, description, auto_run,
        chal_unpacked=chal_unpacked,
        decomp_ready=decomp_ready,
        decomp_files=decomp_files,
        custom_libs=custom_libs,
    )
    from modules._prompts import build_target_directive
    _mt_block = build_target_directive(target, read_meta(job_id).get("target_urls"))
    if _mt_block:
        user_prompt = user_prompt + "\n\n" + _mt_block
    # Browser-pwn: a prebuilt JS engine in the bundle makes the whole
    # ELF/ROP/heap playbook above inapplicable. Returns "" for every
    # ordinary pwn job (anchored on snapshot_blob.bin).
    _js_block = js_engine_block(job_id)
    if _js_block:
        user_prompt = user_prompt + "\n\n" + _js_block

    if recon_reply:
        user_prompt = (
            "PRE-RECON COMPLETED — the orchestrator already ran a "
            "recon subagent on your behalf. Its summary is below. START "
            "from this; do not re-run the same triage yourself. Spawn "
            "recon AGAIN for follow-up questions if needed.\n\n"
            "==== RECON REPLY ===="
            f"\n{recon_reply}\n"
            "==== END RECON ====\n\n"
        ) + user_prompt

    from modules._common import build_exploit_library_hint
    _lib_hint = build_exploit_library_hint("pwn")
    if _lib_hint:
        user_prompt = _lib_hint + "\n\n" + user_prompt

    from modules.agent_provider import active_provider, provider_display_name
    log_line(
        job_id,
        f"Launching {provider_display_name(active_provider())} agent (model={model})",
    )
    if resume_sid:
        log_line(job_id, f"Forking prior Claude session {resume_sid[:8]}…")


    sandbox_result: Optional[dict] = None

    def _sandbox_for(script_name: str) -> Optional[dict]:
        # attempt_sandbox_run is sync; the helper calls it via anyio.to_thread.
        # Pass the accumulated retry-hint history so postjudge can
        # detect "I'm about to repeat myself" and stop the loop.
        return attempt_sandbox_run(
            job_id, script_name, target, lambda s: log_line(job_id, s),
            prior_hints=list(summary.get("judge_hints", [])),
        )

    try:
        sandbox_result = await run_main_agent_session(
            job_id,
            options=options,
            initial_prompt=user_prompt,
            summary=summary,
            work_dir=work_dir,
            artifact_names=("exploit.py",),
            auto_run=auto_run,
            sandbox_runner=_sandbox_for,
            log_fn=lambda s: log_line(job_id, s),
        )
        # Terminal REPORT phase (cookbook-pattern): stateless query()
        # with NO tools and a minimal system_prompt converts the
        # main agent's prose (report.md + exploit.py) into a strict-
        # schema findings.json. Keeping the schema OUT of main's
        # SYSTEM_PROMPT is the whole point — it's structured-output
        # post-processing, not part of the investigation loop.
        # Best-effort: any failure is logged + swallowed; downstream
        # validate_findings tolerates missing/empty files.
        try:
            # Don't pass main's model — report phase defaults to sonnet
            # (REPORT_PHASE_MODEL). Pure transformation doesn't need opus.
            await run_report_phase(
                job_id=job_id,
                work_dir=work_dir,
                model=model,  # report follows main's model (per-job)
                log_fn=lambda s: log_line(job_id, s),
                chal_name_hint=(effective_binary_name or binary_name or ""),
            )
        except Exception as e:
            log_line(
                job_id,
                f"[report] phase raised {type(e).__name__}: {e} — "
                f"continuing without findings.json",
            )
    finally:
        # Kill leftover qemu / gdbserver background processes the
        # debugger subagent backgrounded with `& ; sleep ...`. Without
        # this they live forever in the worker container, leaking
        # ~300 MB RSS per qemu kernel-pwn run + holding port forwards
        # (e.g. :18000 from a prior chal) that the NEXT job needs.
        # Comm-anchored matching (`pkill -x`) is required: the SDK
        # passes our system_prompt to the bundled claude CLI as argv,
        # so `pkill -f` would self-kill the agent.
        cleanup_job_processes(lambda s: log_line(job_id, s))
        # Carry artifacts up to the job dir. Runs in `finally` so any
        # abrupt exit (RQ stop / Stop&Resume / SIGTERM-with-grace) still
        # flushes the agent's exploit.py / report.md / findings.json /
        # THREAT_MODEL.md into <jobdir>/, where
        # the API's file links look. Wrapped in its own try/except so a
        # copy failure can't mask the real agent error in summary.
        try:
            fallback_dirs = prior_work_dirs(job_id)
            found = collect_outputs(
                work_dir,
                ["exploit.py", "report.md", "findings.json",
                 "THREAT_MODEL.md"],
                fallback_dirs=fallback_dirs,
                log_fn=lambda s: log_line(job_id, s),
            )
            summary["exploit_present"] = "exploit.py" in found
            summary["report_present"] = "report.md" in found
            summary["decomp_used"] = (work_dir / "decomp").exists()
            if summary["decomp_used"]:
                try:
                    summary["decomp_function_count"] = len(list((work_dir / "decomp").glob("*.c")))
                except Exception:
                    pass
            jd = job_dir(job_id)
            for name, src in found.items():
                target_path = jd / name
                if src.resolve() != target_path.resolve():
                    target_path.write_bytes(src.read_bytes())
                # Mirror into work_dir so the next /retry's carry step
                # picks up the freshest version, not the stale carry-copy.
                work_target = work_dir / name
                if src.resolve() != work_target.resolve():
                    work_target.write_bytes(src.read_bytes())
        except Exception as carry_err:
            log_line(job_id, f"CARRY_ERROR: {carry_err}")
    summary["sandbox"] = sandbox_result
    return summary


def run_job(
    job_id: str,
    binary_rel: Optional[str],
    target: Optional[str],
    description: Optional[str],
    auto_run: bool,
    model_override: Optional[str] = None,
) -> dict:
    jd = job_dir(job_id)
    bin_dir = jd / "bin"
    binary_name = Path(binary_rel).name if binary_rel else None

    apply_to_env()
    write_meta(job_id, status="running", stage="analyze")
    try:
        agent_summary = anyio.run(
            _run_agent, job_id, binary_name, bin_dir, target, description, auto_run,
            model_override,
        )
        cost = extract_cost(agent_summary)
        # + earlier sessions (stop -> continue reuses the job id)
        cost += prior_session_cost(job_id)

        # Sandbox+judge already happened inside the agent session loop;
        # the helper stashed the LAST sandbox_result on the summary.
        sandbox_result = agent_summary.pop("sandbox", None)

        flags = scan_job_for_flags(job_id, sandbox_result=sandbox_result)
        agent_err = agent_summary.get("agent_error")
        agent_err_kind = agent_summary.get("agent_error_kind")
        if agent_err and not agent_summary.get("exploit_present"):
            final_status = "failed"
        elif not flags:
            final_status = "no_flag"
        else:
            final_status = "finished"
        result = {
            "agent": agent_summary,
            "cost_usd": cost,
            "sandbox": sandbox_result,
            "flags": flags,
            "agent_error": agent_err,
            "agent_error_kind": agent_err_kind,
        }
        (jd / "result.json").write_text(json.dumps(result, indent=2))
        write_meta(job_id, status=final_status, stage="done", cost_usd=cost,
                   model=agent_summary.get("model"),
                   flags=flags,
                   error=agent_err,
                   error_kind=agent_err_kind,
                   exploit_present=agent_summary.get("exploit_present", False),
                   decomp_used=agent_summary.get("decomp_used", False))
        emit_event(job_id, "terminal", "status", status=final_status,
                   flags=len(flags), cost_usd=cost)
        return result
    except Exception as e:
        log_line(job_id, f"ERROR: {e}\n{traceback.format_exc()}")
        write_meta(job_id, status="failed", error=str(e))
        emit_event(job_id, "terminal", "status", status="failed", error=str(e))
        raise
