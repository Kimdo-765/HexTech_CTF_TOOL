#!/usr/bin/env python3
"""chal-libc-fix — make a CTF binary load the same libc/ld-linux it
will run against on the remote, by patchelf'ing its interpreter +
RUNPATH to a copy of the chal's own libraries.

Why: dynamic analysis on the worker container's system libc (Debian
glibc 2.41 at the time of writing) gives misleading offsets for any
challenge built against a different libc. Heap layout, FSOP vtable
addresses, one_gadget offsets, even basic struct sizes shift between
glibc versions. The remote service ships its own libc + ld.so via
Dockerfile / docker-compose / a `lib/` directory bundled with the
challenge — we want the debugger session to use those.

What it does:
  1. Locates the chal's libc.so.6 + ld-linux-* by walking the
     challenge bundle. Hints in priority order:
       - Dockerfile `COPY libc-X.YZ.so /...` lines
       - docker-compose.yml volume mounts of a libs/ dir
       - any `lib/` or `libs/` or `glibc/` directory containing both
         libc.so.6 (or libc-*.so) and ld-linux-*
       - any directory with libc.so.6 + ld-linux-* siblings
  2. Stages those libs under <jobdir>/work/.chal-libs/ if not already
     there. Worker has the source dir read-only via stage_bin step.
  3. patchelf's the binary in place:
       --set-interpreter <staged ld-linux>
       --set-rpath        <staged libs dir>     (replaces RUNPATH)
  4. Prints a summary: detected libc version, paths, gdb-ready cmd.

Idempotent: if the binary's interpreter already points at the staged
ld and the libs dir is on RUNPATH, it just reports the current state
and exits 0.

Usage (called by the debugger subagent from Bash):
    chal-libc-fix <binary>                   # auto-detect from cwd
    chal-libc-fix <binary> --libs <dir>      # explicit libs dir
    chal-libc-fix <binary> --keep-original   # backs up to <bin>.orig

Exit codes:
    0   success (or already patched)
    1   no libc/ld pair found anywhere
    2   patchelf failed
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


STAGE_DIRNAME = ".chal-libs"
PROFILE_FILENAME = "libc_profile.json"


def _run(cmd: list[str], check: bool = True) -> str:
    res = subprocess.run(cmd, capture_output=True, text=True)
    if check and res.returncode != 0:
        sys.stderr.write(f"[chal-libc-fix] cmd failed: {' '.join(cmd)}\n")
        sys.stderr.write(res.stderr)
        sys.exit(2)
    return res.stdout


def detect_libc_version(libc: Path) -> str | None:
    try:
        out = subprocess.run(
            ["strings", str(libc)], capture_output=True, text=True, check=False,
        ).stdout
    except Exception:
        return None
    for line in out.splitlines():
        m = re.search(r"GNU C Library .*?(?:GLIBC|version)\s*([\d.]+)", line)
        if m:
            return m.group(1)
        m = re.match(r"GLIBC ([\d.]+)$", line.strip())
        if m:
            return m.group(1)
    return None


def find_pair(root: Path) -> tuple[Path, Path] | None:
    """Walk root looking for a directory that contains BOTH libc.so.6
    (or libc-*.so) AND a ld-linux-*.so.*. Return (libc, ld) on hit.
    Skips well-known noisy dirs. ``.chal-libs`` is checked LAST so
    that a freshly-bundled libc from the upload wins over a previously
    cached staging dir, but the staging dir is still seen if it's all
    we have — important when the pwn analyzer's _find_elf_or_unzip
    pre-stages libs there (and only there) before chal-libc-fix runs.
    """
    skip = {".git", "__pycache__", "node_modules"}
    chal_libs_hit: tuple[Path, Path] | None = None
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in skip]
        libc = None
        ld = None
        for n in files:
            if n == "libc.so.6" or re.fullmatch(r"libc-[\d.]+\.so", n):
                libc = Path(d) / n
            if re.match(r"ld-linux", n) or re.match(r"ld-[\d.]+\.so", n):
                ld = Path(d) / n
        if libc and ld:
            # Defer .chal-libs hits — let any bundled libs win first.
            # The pre-stage path will pick it up after the walk.
            if Path(d).name == ".chal-libs":
                chal_libs_hit = (libc, ld)
                continue
            return libc, ld
    return chal_libs_hit


def parse_dockerfile_from(root: Path) -> str | None:
    """Return the first non-`scratch` FROM image found in any Dockerfile
    under root (e.g. 'ubuntu:18.04', 'python:3.10-slim',
    'gcr.io/distroless/cc'). Used as a last-resort source when the
    chal bundle ships a Dockerfile but no physical libc + ld pair.
    """
    for d, _, files in os.walk(root):
        for n in files:
            if n.lower() != "dockerfile" and not n.lower().startswith("dockerfile."):
                continue
            try:
                txt = (Path(d) / n).read_text(errors="replace")
            except Exception:
                continue
            for m in re.finditer(
                r"^\s*FROM\s+(?:--\S+\s+)?(\S+)",
                txt, re.MULTILINE | re.IGNORECASE,
            ):
                img = m.group(1).strip()
                if img.lower() == "scratch":
                    continue
                # Skip lines whose target is a multi-stage alias
                # ("FROM build AS final" — `build` isn't a real image).
                # Heuristic: real image refs have a `:` (tag) or `/`
                # (registry/repo) or are in a small set of canonical
                # tagless names. Plain unqualified words like "build"
                # almost never are real image refs in CTF chals.
                if (":" in img) or ("/" in img):
                    return img
                if img.lower() in {
                    "alpine", "ubuntu", "debian", "fedora", "centos",
                    "python", "node", "golang", "rust", "openjdk",
                    "busybox", "archlinux",
                }:
                    return img
    return None


def binary_needed(binary: Path) -> list[str]:
    """DT_NEEDED entries (the .so SONAMES the binary directly links
    against). Order is preserved from readelf output.
    """
    try:
        out = subprocess.run(
            ["readelf", "-d", str(binary)],
            capture_output=True, text=True, check=False,
        ).stdout
    except Exception:
        return []
    needed: list[str] = []
    for line in out.splitlines():
        m = re.search(r"\(NEEDED\)\s+Shared library:\s*\[([^\]]+)\]", line)
        if m:
            needed.append(m.group(1))
    return needed


def binary_interpreter(binary: Path) -> str | None:
    """PT_INTERP — the path the binary expects ld.so to live at."""
    try:
        out = subprocess.run(
            ["readelf", "-l", str(binary)],
            capture_output=True, text=True, check=False,
        ).stdout
    except Exception:
        return None
    m = re.search(r"\[Requesting program interpreter:\s*([^\]]+)\]", out)
    return m.group(1).strip() if m else None


# Strict shell-safety filters so a malicious SONAME / interp path can't
# break out of the docker run script we hand to the chal image.
_SAFE_LIB_RE = re.compile(r"^[A-Za-z0-9._+\-]+$")
_SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9./_+\-]+$")


def extract_from_image(image: str, binary: Path, stage_dir: Path) -> bool:
    """Pull the Dockerfile's FROM image and copy libc + ld + every
    DT_NEEDED .so the binary references INTO `stage_dir` (which is
    bind-mounted to the chal container as /out via the host docker
    socket). Returns True on success.

    Layout assumption: stage_dir lives under
    /data/jobs/<JOB_ID>/... so we can translate it to a host path via
    HOST_DATA_DIR for the bind mount.
    """
    host_root = os.environ.get("HOST_DATA_DIR", "").rstrip("/")
    job_id = os.environ.get("JOB_ID", "")
    if not host_root or not job_id:
        sys.stderr.write(
            "[chal-libc-fix] HOST_DATA_DIR / JOB_ID not set on worker — "
            "cannot bind-mount into chal container. Image extraction "
            "skipped.\n"
        )
        return False

    job_root = Path(f"/data/jobs/{job_id}")
    try:
        rel = stage_dir.resolve().relative_to(job_root.resolve())
    except ValueError:
        sys.stderr.write(
            f"[chal-libc-fix] stage_dir {stage_dir} not under "
            f"{job_root} — cannot translate to host path; image "
            "extraction skipped.\n"
        )
        return False
    host_stage = f"{host_root}/jobs/{job_id}/{rel}"
    stage_dir.mkdir(parents=True, exist_ok=True)

    needed = binary_needed(binary)
    if "libc.so.6" not in needed:
        # Always grab libc explicitly even if the binary's NEEDED list
        # somehow elides it (some odd toolchains).
        needed.append("libc.so.6")
    interp = binary_interpreter(binary) or "/lib64/ld-linux-x86-64.so.2"

    bad = [n for n in needed if not _SAFE_LIB_RE.match(n)]
    if bad:
        sys.stderr.write(
            f"[chal-libc-fix] suspicious lib names {bad}; aborting "
            "extraction.\n"
        )
        return False
    if not _SAFE_PATH_RE.match(interp):
        sys.stderr.write(
            f"[chal-libc-fix] suspicious interpreter path "
            f"{interp!r}; aborting extraction.\n"
        )
        return False

    # Multi-arch interpreter fallbacks. We try the binary's own
    # PT_INTERP first; if the chal image has it at a different path,
    # walk a small list of conventional locations.
    interp_candidates = [
        interp,
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/ld-linux-x86-64.so.2",
        "/lib/ld-linux-aarch64.so.1",
        "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
        "/lib/ld-linux-armhf.so.3",
        "/lib/arm-linux-gnueabihf/ld-linux-armhf.so.3",
        "/lib/ld-linux.so.2",
        "/lib/i386-linux-gnu/ld-linux.so.2",
    ]
    interp_csv = " ".join(interp_candidates)
    libs_csv = " ".join(needed)

    # Shell script that runs inside the chal image. Uses ldconfig to
    # resolve each SONAME → real path; falls back to a small list of
    # conventional multiarch dirs if ldconfig isn't present (e.g.
    # alpine/musl, distroless). `cp -L` follows symlinks so we get
    # the actual binary, named with its SONAME so DT_NEEDED resolves.
    script = (
        "set -e\n"
        "mkdir -p /out\n"
        "echo \"[image] /etc/os-release:\"\n"
        "head -3 /etc/os-release 2>/dev/null || true\n"
        f"for libname in {libs_csv}; do\n"
        "  p=$(ldconfig -p 2>/dev/null | awk -v lib=\"$libname\" '$1==lib {print $NF; exit}')\n"
        "  if [ -z \"$p\" ]; then\n"
        "    for d in /lib/x86_64-linux-gnu /lib64 /lib /usr/lib/x86_64-linux-gnu /usr/lib /lib/aarch64-linux-gnu /usr/lib/aarch64-linux-gnu /lib/arm-linux-gnueabihf /usr/lib/arm-linux-gnueabihf /lib/i386-linux-gnu /usr/lib/i386-linux-gnu; do\n"
        "      if [ -e \"$d/$libname\" ]; then p=\"$d/$libname\"; break; fi\n"
        "    done\n"
        "  fi\n"
        "  if [ -n \"$p\" ] && [ -e \"$p\" ]; then\n"
        "    cp -L \"$p\" \"/out/$libname\" 2>/dev/null || cp \"$p\" \"/out/$libname\"\n"
        "    echo \"[image] copied $libname  <-  $p\"\n"
        "  else\n"
        "    echo \"[image] WARN: $libname not found in image\" 1>&2\n"
        "  fi\n"
        "done\n"
        f"for ld in {interp_csv}; do\n"
        "  if [ -e \"$ld\" ]; then\n"
        "    bn=$(basename \"$ld\")\n"
        "    cp -L \"$ld\" \"/out/$bn\" 2>/dev/null || cp \"$ld\" \"/out/$bn\"\n"
        "    echo \"[image] copied interpreter $ld -> /out/$bn\"\n"
        "    break\n"
        "  fi\n"
        "done\n"
        "ls -la /out\n"
    )

    print(f"[chal-libc-fix] pulling image: {image}", flush=True)
    pull = subprocess.run(
        ["docker", "pull", image], capture_output=True, text=True,
    )
    if pull.returncode != 0:
        # The image might already be local; print the error and try
        # `docker run` anyway. If neither works we'll exit cleanly.
        sys.stderr.write(
            "[chal-libc-fix] docker pull failed (image may still be "
            f"locally cached — trying anyway): "
            f"{pull.stderr.strip()[:200]}\n"
        )

    print(
        f"[chal-libc-fix] extracting libc/ld/NEEDED libs from {image} "
        f"into {stage_dir} ...",
        flush=True,
    )
    res = subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{host_stage}:/out",
            "--entrypoint", "sh",
            image,
            "-c", script,
        ],
        capture_output=True, text=True,
    )
    if res.stdout:
        sys.stdout.write(res.stdout)
    if res.stderr:
        sys.stderr.write(res.stderr)
    if res.returncode != 0:
        sys.stderr.write(
            f"[chal-libc-fix] docker run exited {res.returncode}; "
            "extraction failed.\n"
        )
        return False
    return True


def parse_dockerfile_libc(root: Path) -> tuple[Path, Path] | None:
    """Best-effort parse of any Dockerfile in `root` for a `COPY` line
    naming the libc the chal runs against. Returns the resolved
    (libc, ld) pair when both can be found relative to the Dockerfile,
    otherwise None.
    """
    candidates: list[Path] = []
    for d, _, files in os.walk(root):
        for n in files:
            if n.lower() in ("dockerfile",) or n.lower().startswith("dockerfile."):
                candidates.append(Path(d) / n)
    for df in candidates:
        try:
            txt = df.read_text(errors="replace")
        except Exception:
            continue
        # Heuristic: scan for `COPY <src> ...` of *.so / libc / ld file.
        copy_re = re.compile(r"^\s*COPY\s+(?:--\S+\s+)?(\S+)\s+(\S+)", re.MULTILINE)
        srcs = []
        for m in copy_re.finditer(txt):
            src = m.group(1)
            if any(tok in src for tok in ("libc", "ld-", "ld.so", "lib/", "libs/", "glibc")):
                srcs.append(src)
        if not srcs:
            continue
        # Resolve src paths relative to the Dockerfile directory.
        df_dir = df.parent
        for src in srcs:
            cand_dir = (df_dir / src).resolve()
            if cand_dir.is_dir():
                pair = find_pair(cand_dir)
                if pair:
                    return pair
            elif cand_dir.is_file() and "libc" in cand_dir.name:
                # Single libc file copied; look for ld-* next to it.
                ld_pair = None
                for sib in cand_dir.parent.iterdir():
                    if re.match(r"ld-linux|ld-[\d.]+\.so", sib.name):
                        ld_pair = sib
                        break
                if ld_pair:
                    return cand_dir, ld_pair
    return None


def stage_libs(libc: Path, ld: Path, jobdir: Path) -> tuple[Path, Path, Path]:
    """Copy libc + ld + every .so from libc's directory into a stable
    staging dir under <jobdir>/work/.chal-libs/. Returns
    (staged_libs_dir, staged_libc, staged_ld).
    """
    work = jobdir / "work"
    if not work.is_dir():
        work = jobdir
    stage = work / STAGE_DIRNAME
    stage.mkdir(parents=True, exist_ok=True)
    # Copy every .so* sibling of libc — common in Dreamhack style
    # bundles where libpthread, libdl, libm etc all need to come along.
    src_dir = libc.parent
    for sib in src_dir.iterdir():
        if sib.is_file() and (sib.suffix == ".so"
                              or ".so." in sib.name
                              or sib.name.startswith(("libc", "ld-"))):
            dst = stage / sib.name
            if not dst.exists() or dst.stat().st_size != sib.stat().st_size:
                shutil.copy2(sib, dst)
    # ld can live in a different dir (sometimes /lib64/) — copy explicitly.
    if not (stage / ld.name).exists():
        shutil.copy2(ld, stage / ld.name)
    return stage, stage / libc.name, stage / ld.name


def _version_tuple(version: str | None) -> list[int] | None:
    if not version:
        return None
    m = re.match(r"^(\d+)\.(\d+)", version)
    if not m:
        return None
    return [int(m.group(1)), int(m.group(2))]


def _binary_arch(elf: Path) -> str:
    try:
        out = subprocess.run(
            ["readelf", "-h", str(elf)],
            capture_output=True, text=True, check=False,
        ).stdout
    except Exception:
        return "unknown"
    m = re.search(r"Machine:\s+(.*)", out)
    if not m:
        return "unknown"
    machine = m.group(1).strip()
    if "X86-64" in machine:
        return "x86_64"
    if "AArch64" in machine:
        return "aarch64"
    if "ARM" in machine:
        return "arm"
    if "Intel 80386" in machine or "Intel 80386" in machine:
        return "i386"
    return machine


_TARGET_SYMBOLS = (
    "system", "execve", "dup2", "read", "write", "exit",
    "_IO_2_1_stdout_", "_IO_2_1_stderr_", "_IO_2_1_stdin_",
    "_IO_list_all", "_IO_wfile_jumps", "_IO_str_jumps",
    "__free_hook", "__malloc_hook", "__realloc_hook",
    "environ", "_rtld_global", "_rtld_global_ro",
    "__libc_argv", "stdin", "stdout", "stderr",
)


def _extract_symbols(libc: Path) -> dict:
    """Use pwntools ELF if available, otherwise fall back to `nm -D` parsing.
    Returns dict[name -> "0x..." | None]; on outright failure returns
    {"_error": "<reason>"} so the profile is still emitted with a
    diagnostic instead of silently lacking the symbols block.
    """
    try:
        # Suppress pwntools log spam — it pollutes our stdout otherwise.
        import logging as _logging
        _logging.disable(_logging.CRITICAL)
        from pwn import ELF
        e = ELF(str(libc), checksec=False)
        out: dict = {}
        for sym in _TARGET_SYMBOLS:
            v = e.symbols.get(sym)
            out[sym] = hex(v) if isinstance(v, int) and v > 0 else None
        try:
            sh = next(e.search(b"/bin/sh\x00"))
            out["/bin/sh"] = hex(sh)
        except StopIteration:
            out["/bin/sh"] = None
        return out
    except Exception as ex:
        # Fall back to nm -D so we at least catch the public symbols.
        try:
            res = subprocess.run(
                ["nm", "-D", str(libc)],
                capture_output=True, text=True, check=False,
            ).stdout
        except Exception:
            return {"_error": str(ex)[:200]}
        out = {sym: None for sym in _TARGET_SYMBOLS}
        out["/bin/sh"] = None
        for line in res.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            addr_hex, _kind, name = parts[0], parts[1], parts[-1]
            if name in out and re.fullmatch(r"[0-9a-fA-F]+", addr_hex):
                out[name] = "0x" + addr_hex.lstrip("0").lower() or "0x0"
        return out


_ONE_GADGET_HEAD = re.compile(r"^(0x[0-9a-f]+)\s+(.*)$")


def _extract_one_gadget(libc: Path) -> list[dict]:
    """Run one_gadget and parse human output into list[{offset, exec, constraints}].
    Returns [] if the gem isn't available or parsing fails.
    """
    try:
        res = subprocess.run(
            ["one_gadget", str(libc)],
            capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        return []
    if res.returncode != 0:
        return []
    gadgets: list[dict] = []
    current: dict | None = None
    in_constraints = False
    for raw in res.stdout.splitlines():
        line = raw.rstrip()
        m = _ONE_GADGET_HEAD.match(line)
        if m:
            if current:
                gadgets.append(current)
            current = {
                "offset": m.group(1),
                "exec": m.group(2).strip(),
                "constraints": [],
            }
            in_constraints = False
            continue
        stripped = line.strip()
        if not stripped:
            in_constraints = False
            continue
        if stripped.lower().startswith("constraints"):
            in_constraints = True
            continue
        if in_constraints and current is not None:
            current["constraints"].append(stripped)
    if current:
        gadgets.append(current)
    return gadgets


def _derive_features(version_tuple: list[int] | None) -> dict:
    """Map glibc (major, minor) → tcache/FSOP/hook feature flags.

    All booleans default to None when the version couldn't be detected
    so the agent knows the answer is unknown and must verify manually.
    """
    if not version_tuple or len(version_tuple) < 2:
        return {
            "safe_linking": None,
            "tcache_key": None,
            "tcache_present": None,
            "hooks_alive": None,
            "io_str_jumps_finish_patched": None,
            "preferred_fsop_chain": "unknown — identify glibc version first",
            "recommended_techniques": [],
            "blacklisted_techniques": [],
        }
    major, minor = version_tuple[0], version_tuple[1]
    if (major, minor) < (2, 26):
        v_floor = "pre-2.26"
    else:
        v_floor = f"{major}.{minor}"
    safe_linking = (major, minor) >= (2, 32)
    tcache_key = (major, minor) >= (2, 35)
    tcache_present = (major, minor) >= (2, 26)
    hooks_alive = (major, minor) < (2, 34)
    str_finish_patched = (major, minor) >= (2, 37)

    recommend: list[str] = []
    blacklist: list[str] = []
    fsop = ""

    if tcache_present:
        recommend.append("tcache poison" + (
            " — write target ^ (heap_chunk>>12) (safe-linking XOR)"
            if safe_linking else " — write raw target (no XOR)"
        ))
        if tcache_key:
            recommend.append(
                "tcache key bypass — overwrite tcache_perthread_struct[i].key "
                "via UAF / overlap before double-free"
            )
    if hooks_alive:
        recommend.append("__free_hook / __malloc_hook overwrite (simplest win)")
    else:
        blacklist.append("__free_hook / __malloc_hook (removed in glibc 2.34)")
    recommend.append("unsorted bin attack → libc leak from main_arena.bins")
    recommend.append("large-bin attack (house of orange / botcake / einherjar)")

    if not hooks_alive and not str_finish_patched:
        fsop = "_IO_str_jumps __finish chain (cheap; valid on 2.34-2.36)"
        recommend.append("FSOP via _IO_str_jumps __finish (vtable[12])")
    elif str_finish_patched:
        fsop = "_IO_wfile_jumps overflow → _IO_wdoallocbuf → _wide_vtable->__doallocate"
        recommend.append("FSOP via _IO_wfile_jumps + _wide_data crafted chain")
        blacklist.append("_IO_str_jumps __finish (patched in glibc 2.37)")
    else:
        fsop = "__free_hook / __malloc_hook (hooks still alive on this version)"

    return {
        "version_floor": v_floor,
        "safe_linking": safe_linking,
        "tcache_key": tcache_key,
        "tcache_present": tcache_present,
        "hooks_alive": hooks_alive,
        "io_str_jumps_finish_patched": str_finish_patched,
        "preferred_fsop_chain": fsop,
        "recommended_techniques": recommend,
        "blacklisted_techniques": blacklist,
    }


_HOW2HEAP_ROOT = Path("/opt/how2heap")


def _how2heap_techniques(version_tuple: list[int] | None) -> dict:
    """Return {dir, techniques: [name, ...]} of how2heap PoCs that
    apply to this glibc version. Snaps to the highest available
    version_dir <= the chal's version so a 2.40 chal still gets the
    2.39 corpus when 2.40 isn't shipped. Best-effort: returns
    `{"available": False, ...}` if /opt/how2heap is missing.
    """
    if not _HOW2HEAP_ROOT.is_dir():
        return {"available": False, "reason": "/opt/how2heap missing in image"}
    try:
        dirs = sorted(
            (d for d in _HOW2HEAP_ROOT.iterdir()
             if d.is_dir() and d.name.startswith("glibc_")),
            key=lambda d: tuple(int(x) for x in d.name[len("glibc_"):].split(".")),
        )
    except Exception:
        return {"available": False, "reason": "scan failed"}
    if not dirs:
        return {"available": False, "reason": "no glibc_* dirs under /opt/how2heap"}
    target = None
    if version_tuple and len(version_tuple) >= 2:
        major, minor = version_tuple[0], version_tuple[1]
        target = (major, minor)
        chosen = None
        for d in dirs:
            try:
                d_tuple = tuple(int(x) for x in d.name[len("glibc_"):].split("."))
            except Exception:
                continue
            if d_tuple <= target:
                chosen = d
            else:
                break
        if chosen is None:
            chosen = dirs[0]  # below the corpus' floor — use oldest
    else:
        chosen = dirs[-1]
    techniques: list[str] = []
    try:
        for f in chosen.iterdir():
            if f.suffix == ".c":
                techniques.append(f.stem)
    except Exception:
        pass
    techniques.sort()
    return {
        "available": True,
        "dir": str(chosen),
        "techniques": techniques,
        "matched_version": chosen.name[len("glibc_"):],
        "corpus_floor": dirs[0].name[len("glibc_"):],
        "corpus_ceiling": dirs[-1].name[len("glibc_"):],
    }


def emit_profile(
    stage_dir: Path,
    libc: Path,
    ld: Path,
    binary: Path,
    version: str | None,
) -> Path | None:
    """Write <stage_dir>/libc_profile.json synthesising version-derived
    feature flags + symbol/one_gadget extracts. Best-effort: any failure
    inside is swallowed so the patchelf workflow itself stays robust.
    """
    try:
        v_tuple = _version_tuple(version)
        features = _derive_features(v_tuple)
        symbols = _extract_symbols(libc)
        one_gadget = _extract_one_gadget(libc)
        how2heap = _how2heap_techniques(v_tuple)
        profile = {
            "schema_version": 2,  # +how2heap field
            "version": version,
            "version_tuple": v_tuple,
            "arch": _binary_arch(binary),
            "libc_path": str(libc),
            "ld_path": str(ld),
            "binary_path": str(binary),
            **features,
            "symbols": symbols,
            "one_gadget": one_gadget,
            "how2heap": how2heap,
        }
        out = stage_dir / PROFILE_FILENAME
        out.write_text(json.dumps(profile, indent=2))
        return out
    except Exception as e:
        sys.stderr.write(
            f"[chal-libc-fix] profile emit failed (non-fatal): {e}\n"
        )
        return None


def already_patched(binary: Path, staged_ld: Path, stage_dir: Path) -> bool:
    interp = _run(["patchelf", "--print-interpreter", str(binary)], check=False).strip()
    rpath = _run(["patchelf", "--print-rpath", str(binary)], check=False).strip()
    return interp == str(staged_ld) and str(stage_dir) in rpath


def patch_binary(binary: Path, staged_ld: Path, stage_dir: Path) -> None:
    _run(["patchelf", "--set-interpreter", str(staged_ld), str(binary)])
    _run(["patchelf", "--set-rpath", str(stage_dir), str(binary)])


def main() -> int:
    ap = argparse.ArgumentParser(prog="chal-libc-fix")
    ap.add_argument("binary")
    ap.add_argument("--libs", help="Explicit directory containing libc + ld")
    ap.add_argument(
        "--root",
        help="Where to search for the chal's bundled libs (default: cwd)",
    )
    ap.add_argument(
        "--keep-original", action="store_true",
        help="Backup the binary to <binary>.orig before patching",
    )
    ap.add_argument(
        "--no-image", action="store_true",
        help="Skip the Dockerfile FROM image extraction fallback "
             "(when no physical libs are bundled in the chal). Use "
             "this if you want to fail fast instead of pulling images.",
    )
    args = ap.parse_args()

    binary = Path(args.binary).resolve()
    if not binary.is_file():
        sys.stderr.write(f"binary not found: {binary}\n")
        return 1

    job_id = os.environ.get("JOB_ID", "")
    if job_id:
        jobdir = Path(f"/data/jobs/{job_id}")
    else:
        jobdir = Path.cwd()
    search_root = Path(args.root).resolve() if args.root else jobdir

    # Compute the stage dir up front — image-extraction path drops files
    # directly into it, then the stage_libs step at the bottom is a no-op
    # when we detect that.
    work = jobdir / "work"
    if not work.is_dir():
        work = jobdir
    stage_target = work / STAGE_DIRNAME

    if args.libs:
        libs_dir = Path(args.libs).resolve()
        pair = find_pair(libs_dir) or None
        if not pair:
            sys.stderr.write(
                f"--libs {libs_dir} did not contain libc.so.6 + ld-linux-*; "
                "nothing to patch.\n"
            )
            return 1
        libc, ld = pair
    else:
        # Priority 0: caller (e.g. the pwn analyzer's _find_elf_or_unzip)
        # already pre-staged a libc + ld pair into ./.chal-libs/. Use it
        # as-is and skip the bundle walk / docker-pull entirely — this
        # is the fast path for the modern Dreamhack flow where the
        # orchestrator handles unpacking before chal-libc-fix runs.
        pair = None
        if stage_target.is_dir():
            staged_libc = stage_target / "libc.so.6"
            staged_ld_candidates = sorted(stage_target.glob("ld-linux-*.so.*"))
            if staged_libc.is_file() and staged_ld_candidates:
                pair = (staged_libc, staged_ld_candidates[0])
                print(
                    f"[chal-libc-fix] using libs already staged at: "
                    f"{stage_target}",
                    flush=True,
                )
        # Priority 1: Dockerfile COPY → physical libs in bundle.
        if not pair:
            pair = parse_dockerfile_libc(search_root)
        # Priority 2: any libc+ld pair anywhere under search root.
        if not pair:
            pair = find_pair(search_root)
        # Priority 3 (NEW): pull the Dockerfile's FROM image and copy
        # libc/ld + the binary's NEEDED libs out of it. This is the
        # common Dreamhack / HackTheBox case: bundle = Dockerfile +
        # binary, libs only exist inside the base image.
        if not pair and not args.no_image:
            base_image = parse_dockerfile_from(search_root)
            if base_image:
                print(
                    f"[chal-libc-fix] no physical libs bundled — falling "
                    f"back to base-image extraction (FROM {base_image})",
                    flush=True,
                )
                if extract_from_image(base_image, binary, stage_target):
                    pair = find_pair(stage_target)
                    if not pair:
                        sys.stderr.write(
                            "[chal-libc-fix] image extraction completed "
                            "but no libc.so.6 + ld-linux pair found in "
                            f"{stage_target}. Likely a musl/distroless "
                            "base; not patching.\n"
                        )
                        return 1
        if not pair:
            sys.stderr.write(
                f"[chal-libc-fix] no libc.so.6 + ld-linux pair found "
                f"under {search_root} and no base image to fall back "
                "on. Binary will run against the worker's system libc "
                "— heap/FSOP offsets may be wrong. Pass --libs <dir> "
                "if the chal supplies a libc somewhere unconventional.\n"
            )
            return 1
        libc, ld = pair

    version = detect_libc_version(libc)
    print(f"[chal-libc-fix] detected libc: {libc}", flush=True)
    print(f"[chal-libc-fix] detected ld:   {ld}", flush=True)
    if version:
        print(f"[chal-libc-fix] glibc version: {version}", flush=True)

    # If image extraction already populated stage_target, skip the
    # stage_libs copy step (libs are already in the right place).
    if libc.parent.resolve() == stage_target.resolve():
        stage = stage_target
        staged_libc, staged_ld = libc, ld
        print(f"[chal-libc-fix] using pre-staged libs at: {stage}", flush=True)
    else:
        stage, staged_libc, staged_ld = stage_libs(libc, ld, jobdir)
        print(f"[chal-libc-fix] staged at: {stage}", flush=True)

    if already_patched(binary, staged_ld, stage):
        print(f"[chal-libc-fix] {binary} already patched; nothing to do", flush=True)
    else:
        if args.keep_original:
            backup = binary.with_suffix(binary.suffix + ".orig")
            if not backup.exists():
                shutil.copy2(binary, backup)
                print(f"[chal-libc-fix] backed up to {backup}", flush=True)
        patch_binary(binary, staged_ld, stage)
        print(
            f"[chal-libc-fix] patched: interpreter -> {staged_ld}, "
            f"rpath -> {stage}",
            flush=True,
        )

    # The patched binary's DT_RUNPATH points at `stage`, so plain
    # invocation just works — no LD_LIBRARY_PATH needed (and exporting
    # it would also redirect /bin/sh, which gdb spawns internally,
    # breaking the session).
    print("[chal-libc-fix] gdb-ready (no env tweaks needed):", flush=True)
    print(f"  gdb {binary}", flush=True)
    print(f"  ./{binary.name}     # runs against staged libc directly", flush=True)

    # Emit libc_profile.json — version-derived feature flags + symbols
    # + one_gadget. Consumed by the main agent / judge / exploit.py so
    # the version → technique mapping is structured data, not text
    # rediscovery on every turn. Best-effort: emit failure is non-fatal.
    profile_path = emit_profile(stage, staged_libc, staged_ld, binary, version)
    if profile_path:
        print(
            f"[chal-libc-fix] profile: {profile_path} "
            f"(version={version or 'unknown'})",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
