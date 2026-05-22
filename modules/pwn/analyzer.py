import asyncio
import json
import os
import shutil
import subprocess
import traceback
from pathlib import Path
from typing import Optional

import anyio

from modules._common import (
    cleanup_job_processes,
    collect_outputs,
    extract_cost,
    job_dir,
    log_line,
    make_main_session_options,
    load_cached_pre_recon,
    module_autoboot,
    prior_work_dirs,
    read_meta,
    run_main_agent_session,
    run_pre_recon,
    run_report_phase,
    scan_job_for_flags,
    store_pre_recon_cache,
    soft_timeout_watchdog,
    write_meta,
)
from modules._runner import attempt_sandbox_run
from modules.pwn.libc_targets import render_rce_table
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
)


def _is_standard_libname(name: str) -> bool:
    n = name.lower()
    return any(n.startswith(p) for p in _STANDARD_LIB_PREFIXES)


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
) -> str:
    """Build the prompt for the orchestrator-driven recon subagent that
    runs BEFORE main's first turn. Recon's job: static-map the binary
    so main starts with a 2 KB inventory instead of having to do its
    own objdump walk."""
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
    parts.append(
        "If `./decomp/` is missing, run `ghiant ./bin/" + binary_name + "` "
        "ONCE to populate it (the project is cached under "
        "./.ghidra_proj/ so subsequent reads are fast)."
    )
    parts.append(
        "REPLY in ≤2 KB, as compact bullets, with these sections:\n"
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
            "phrase is NOT a recognized technique in the heap "
            "exploit catalog (do not search for it as if it were).\n"
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
    if custom_libs:
        # Chal author shipped non-standard .so files. THIS IS THE FIRST
        # PLACE TO LOOK for primitives — wrapper functions almost always
        # encode the bug (int-overflow on size, signed-vs-unsigned compare,
        # off-by-one, missing length cap, side-effect at unexpected offset).
        # Treating them as "just wrappers" is a known way to miss the chal.
        lib_list = ", ".join(custom_libs)
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
    parts.append(
        "DO NOT propose exploit code. DO NOT speculate. Facts only. "
        "Cite file:line / file:addr for every claim."
    )
    return "\n\n".join(parts)


def _is_shared_lib(p: Path) -> bool:
    n = p.name.lower()
    return (
        n.startswith("libc")
        or n.startswith("ld-")
        or n.startswith("ld.")
        or ".so" in n
    )


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

    def _scan(d: Path) -> list[Path]:
        out: list[Path] = []
        try:
            for f in d.rglob("*"):
                if not f.is_file():
                    continue
                try:
                    head = f.read_bytes()[:4]
                except Exception:
                    continue
                if head == b"\x7fELF":
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
                tf.extractall(out_dir)
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
    if not extracted_elfs:
        log_fn(f"[autoboot] bundle {bundle.name} contained no ELF")
        return []

    # Split into challenge binaries (non-.so) and shared libs. Flatten
    # the binaries into staged_bin so the prompt's ./bin/<name> path
    # resolves; copy the .so / ld-* libs into .chal-libs so chal-libc-fix
    # can take the bundled-libs fast path without needing JOB_ID +
    # HOST_DATA_DIR for a docker-pull fallback.
    chal_libs_dir = work_dir / ".chal-libs"
    flattened: list[Path] = []
    for src in extracted_elfs:
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
    if not elf_candidates:
        log_fn("[autoboot] no ELF found in ./bin/ — skipping chal-libc-fix")
        return (None, None)
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
    # Detect chal-author-supplied .so files in .chal-libs/. When present
    # they almost always contain the primitive — surface to pre-recon
    # so the static-triage prompt explicitly asks recon to enumerate
    # each export and identify divergences from standard libc semantics.
    custom_libs = _detect_custom_libs(work_dir)
    if custom_libs:
        log_line(
            job_id,
            f"[autoboot] custom chal libraries detected: "
            f"{', '.join(custom_libs)} — pre-recon will require "
            f"export-by-export divergence analysis"
        )

    # Item 5 — light autoboot summary breadcrumb. Captures heavy
    # autoboot outputs (effective binary name, custom libs, libc
    # profile presence) into ./AUTOBOOT.md so subagents read the same
    # baseline orientation regardless of which spawn they are.
    libc_profile = work_dir / ".chal-libs" / "libc_profile.json"
    module_autoboot(
        "pwn", work_dir, lambda s: log_line(job_id, s),
        extras={
            "effective_binary": effective_binary_name or "(none)",
            "chal_unpacked": str(chal_unpacked),
            "custom_libs": ", ".join(custom_libs) if custom_libs else "(none)",
            "libc_profile_present": libc_profile.is_file(),
            "decomp_pre_baked": (work_dir / "decomp").is_dir(),
        },
    )

    model = model_override or str(get_setting("claude_model") or "claude-opus-4-7")
    resume_sid = read_meta(job_id).get("resume_session_id")
    # Heap detection up-front so the orchestrator's scaffold-missing
    # trip-wire (SCAFFOLD_NUDGE in run_main_agent_session) can fire
    # only when relevant.
    heap_kw = looks_heap_advanced(description or "")
    summary: dict = {
        "messages": 0, "tool_calls": 0, "model": model,
        "heap_chal": True,                       # pwn module default
        "heap_chal_keyword_match": heap_kw,
    }
    options = make_main_session_options(
        job_id=job_id,
        work_dir=work_dir,
        model=model,
        system_prompt=SYSTEM_PROMPT,
        base_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
        summary=summary,
        resume_sid=resume_sid,
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
            )
            log_line(job_id, "[pre-recon] spawning static-triage recon subagent")
            recon_reply = await run_pre_recon(
                job_id=job_id,
                work_dir=work_dir,
                model=model,
                prompt=recon_question,
                log_fn=lambda s: log_line(job_id, s),
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

    log_line(job_id, f"Launching Claude agent (model={model})")
    if resume_sid:
        log_line(job_id, f"Forking prior Claude session {resume_sid[:8]}…")

    soft_timeout = int(read_meta(job_id).get("job_timeout") or 0)
    watchdog = asyncio.create_task(soft_timeout_watchdog(job_id, soft_timeout))

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
        watchdog.cancel()
        # Kill leftover qemu / gdbserver background processes the
        # debugger subagent backgrounded with `& ; sleep ...`. Without
        # this they live forever in the worker container, leaking
        # ~300 MB RSS per qemu kernel-pwn run + holding port forwards
        # (e.g. :18000 from a prior chal) that the NEXT job needs.
        # Comm-anchored matching (`pkill -x`) is required: the SDK
        # passes our system_prompt to the bundled claude CLI as argv,
        # so `pkill -f` would self-kill the agent.
        cleanup_job_processes(lambda s: log_line(job_id, s))
        if read_meta(job_id).get("awaiting_decision"):
            write_meta(job_id, awaiting_decision=False)
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
                 "THREAT_MODEL.md", "WHY_STOPPED.md"],
                fallback_dirs=fallback_dirs,
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

        # Sandbox+judge already happened inside the agent session loop;
        # the helper stashed the LAST sandbox_result on the summary.
        sandbox_result = agent_summary.pop("sandbox", None)

        flags = scan_job_for_flags(job_id)
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
        return result
    except Exception as e:
        log_line(job_id, f"ERROR: {e}\n{traceback.format_exc()}")
        write_meta(job_id, status="failed", error=str(e))
        raise
