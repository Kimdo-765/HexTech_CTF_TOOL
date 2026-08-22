FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Baseline build / fetch chain.
    curl wget git ca-certificates gnupg lsb-release \
    gcc g++ make pkg-config python3-dev \
    file binutils \
    libgmp-dev libmpfr-dev libmpc-dev libssl-dev libffi-dev \
    # Archive tools the agent often calls from Bash (zips inside source
    # uploads, nested archives, prebuilt CTF distributions, etc.). The
    # Python zipfile fallback in api/storage.py only handles the initial
    # upload — anything the agent unpacks itself needs the CLI.
    unzip zip p7zip-full xz-utils bzip2 tar \
    # Light editing / inspection helpers commonly used by the agent.
    less jq xxd vim-tiny nano \
    # ripgrep: the agent reaches for `rg` when grepping a source tree and
    # got "command not found" on a real analysis command in an independent
    # web lineage — not inside a challenge container, in the worker itself.
    # grep exists, but the agent does not fall back to it; it retries rg.
    ripgrep \
    # --- Pwn / Rev: dynamic analysis + reverse engineering ---
    # (radare2 isn't in the slim base's apt; for full reversing the
    # decompiler sibling image already has Ghidra.)
    gdb gdb-multiarch strace ltrace patchelf \
    qemu-user-static \
    # A JRE, not a JDK. Two independent lineages asked for one: job
    # 974f165f1249 (Minecraft r.0.0.mca region file) hit
    # `java: command not found`, and 0716 had already held
    # default-jre-headless pending exactly this second lineage. Game data,
    # datapacks, .class files and most NBT tooling live in the JVM
    # ecosystem; that job worked around it by hand-writing an NBT decoder,
    # which is not always available as an escape.
    default-jre-headless \
    # Full-system QEMU for KERNEL pwn: boot a challenge's own bzImage /
    # vmlinuz + rootfs under qemu-system-x86_64. With `-enable-kvm` (host
    # /dev/kvm passed through by start.sh's generated compose override) the
    # guest runs the CHALLENGE's real kernel at near-native speed with
    # `-s -S` gdb-attach — true fidelity for that chal's kernel, unlike the
    # shared host kernel a container sees. qemu-utils = qemu-img for
    # building / converting the rootfs image. (aarch64 full-system would run
    # under TCG only on this x86 host, so we ship the x86 system target.)
    qemu-system-x86 qemu-utils \
    # UPX unpacker (Tier A) — the single most common PE/ELF packer in
    # CTF; `upx -d` restores the original image before any static pass.
    upx-ucl \
    # Cross-arch binutils — objdump/readelf/nm for foreign-arch ELFs
    # (very common in CTF VMs / firmware images). Without these the
    # native objdump prints "UNKNOWN architecture" and the agent has
    # to hand-roll byte-level disassembly.
    binutils-aarch64-linux-gnu binutils-arm-linux-gnueabi \
    # cpio — initrd / firmware rootfs extraction. The slim base
    # leaves it out; without it the agent ad-libs a Python parser.
    cpio \
    # Ruby is here only to provide the `one_gadget` gem (the standard
    # libc one-gadget RCE finder used in nearly every modern pwn
    # writeup). gem install runs in the next RUN.
    ruby ruby-dev \
    # --- Web: HTTP probing, scanning, sqli ---
    # (whatweb pulls Ruby + a flaky upstream deb; skip — agent has
    # plenty with curl + nmap + sqlmap + Bash heuristics.)
    nmap netcat-openbsd socat dnsutils iputils-ping \
    sqlmap \
    # --- Crypto: handy alongside pwntools / pycryptodome ---
    openssl \
    # --- Forensic / Misc: media + signature inspection ---
    libimage-exiftool-perl \
    yara \
 && rm -rf /var/lib/apt/lists/*

# Node.js + the Claude Code and Codex CLIs. Codex is used by the GPT provider's
# default ChatGPT OAuth runtime (``codex exec --json``).
# Claude is PINNED to >=2.1.156 — the version that fixes
# the deterministic opus-4-8 thinking-block API 400 (see the bundle-removal step
# after pip install below, and memory sdk_bundled_cli_thinking_400). The SDK is
# made to use THIS system CLI, not its own stale bundled copy.
ARG CODEX_CLI_VERSION=0.147.0
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/* \
 && npm install -g @anthropic-ai/claude-code@2.1.158 \
                   "@openai/codex@${CODEX_CLI_VERSION}" \
 && echo "Codex CLI = $(codex --version 2>&1)"

# Docker CLI (so worker can spawn sibling containers via the mounted socket)
RUN install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/debian/gpg \
        -o /etc/apt/keyrings/docker.asc \
 && chmod a+r /etc/apt/keyrings/docker.asc \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
        > /etc/apt/sources.list.d/docker.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends docker-ce-cli \
 && rm -rf /var/lib/apt/lists/*

COPY worker/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# claude-agent-sdk ships a BUNDLED `claude` CLI (claude_agent_sdk/_bundled/
# claude) and its subprocess transport prefers it over $PATH. That bundle LAGS
# the npm release — SDK 0.2.87 bundles CLI 2.1.150, which STILL hits the
# deterministic API 400 "thinking/redacted_thinking blocks ... cannot be
# modified" on opus-4-8 + extended thinking (fixed in CLI 2.1.156; proven via
# resume A/B: 2.1.150->400, 2.1.158->ok). Delete the stale bundle so the SDK
# falls through to the npm-installed system CLI pinned above (>=2.1.156).
# Drop this once a published SDK bundles >=2.1.156. memory: sdk_bundled_cli_thinking_400.
RUN find /usr -type f -path "*/claude_agent_sdk/_bundled/claude" -delete 2>/dev/null; \
    echo "SDK bundled CLI removed; system CLI = $(command -v claude) / $(claude --version 2>&1)"

# angr — installed in an isolated layer, no-deps from system pip so the
# core requirements.txt resolver can't be blocked by angr's pinned
# unicorn rc (which conflicts with our capstone>=5). The `|| true`
# guarantees that a broken angr release on PyPI cannot break the
# entire worker image — the agent just won't have symbolic execution
# until the conflict is fixed upstream. Pinned to a known-good
# release that brings its own resolved dep tree.
ARG ANGR_VERSION=9.2.214
RUN pip install --no-cache-dir "angr==${ANGR_VERSION}" 2>&1 | tail -5 || true \
 && python3 -c "import angr; print('angr OK', angr.__version__)" 2>&1 \
   || echo "[WARN] angr install failed; symbolic-execution tooling unavailable"

# ============================================================================
# Windows / .NET reverse-engineering (Tier B).  *** UNVERIFIED — authored
# without a Docker build available (WSL integration was down); every step is
# isolated with `|| true` / `|| echo WARN` exactly like the angr layer above,
# so a failed resolve can NEVER break the worker image — the tool is simply
# absent until a build confirms it. Validate each `... OK` line on the first
# real build, then this banner comes off. ***
#
# floss (FLARE) — recover obfuscated / stack / tight strings from PE & ELF
# that a plain `strings` misses (decoded keys, hidden flags). Pulls vivisect;
# isolated so its dep tree can't disturb capstone/unicorn.
RUN pip install --no-cache-dir flare-floss 2>&1 | tail -3 || true \
 && (command -v floss >/dev/null 2>&1 && echo "floss OK $(floss --version 2>&1 | head -1)" \
     || echo "[WARN] floss unavailable")

# mono — run .NET Framework (4.x) assemblies on Linux (`mono foo.exe`, no Wine
# needed) and disassemble IL (`ikdasm` / `monodis`). Debian `mono-complete`.
RUN apt-get update \
 && apt-get install -y --no-install-recommends mono-complete 2>&1 | tail -3 || true \
 ; rm -rf /var/lib/apt/lists/* \
 ; (command -v mono >/dev/null 2>&1 && echo "mono OK $(mono --version 2>&1 | head -1)" \
     || echo "[WARN] mono unavailable")

# .NET SDK + ilspycmd — decompile managed PE to near-source C# (ICSharpCode
# ILSpy) and run modern .NET (5+) assemblies (`dotnet foo.dll`). The SDK is
# heavy (~700 MB); IF that bloat is unacceptable on the always-on worker, the
# documented FALLBACK is to move ilspycmd into the per-job `decompiler`
# sibling image (already carrying Ghidra/JDK weight) and keep only `mono`
# here. ilspycmd is PINNED to 8.2.x: the unpinned `dotnet tool install`
# grabs the newest (10.x, net10-targeted) which fails on the 8.0 SDK with
# "DotnetToolSettings.xml not found" — pin the tool to the SDK's TFM
# (verified in a throwaway). Isolated || true.
ARG DOTNET_CHANNEL=8.0
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
# libicu is REQUIRED first: .NET aborts on startup without an ICU package
# ("Couldn't find a valid ICU package installed") — verified in a throwaway.
# The versioned name tracks the Debian release (bookworm=libicu72,
# trixie=libicu76, …) so pick the highest libicuNN apt offers rather than
# hard-coding a number that breaks on the next base-image bump. Inside this
# isolated layer so a miss still can't break the worker (RUN is WARN-masked).
RUN ( apt-get update && apt-get install -y --no-install-recommends \
        "$(apt-cache search '^libicu[0-9]' | awk '{print $1}' | sort -V | tail -1)" 2>&1 | tail -2 ; rm -rf /var/lib/apt/lists/* ) \
 ; ( curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh 2>/dev/null \
     && bash /tmp/dotnet-install.sh --channel "${DOTNET_CHANNEL}" --install-dir /usr/share/dotnet 2>&1 | tail -3 \
     && ln -sf /usr/share/dotnet/dotnet /usr/local/bin/dotnet \
     && dotnet tool install --global ilspycmd --version 8.2.0.7535 2>&1 | tail -3 \
     && ln -sf /root/.dotnet/tools/ilspycmd /usr/local/bin/ilspycmd \
     && (command -v ilspycmd >/dev/null 2>&1 && echo "ilspycmd OK" || echo "[WARN] ilspycmd unavailable") ) \
   || echo "[WARN] .NET / ilspycmd install failed; managed-PE C# decompile unavailable"
# DOTNET_ROOT must point at the script-installed location: a framework-
# dependent global tool (ilspycmd) resolves its runtime via DOTNET_ROOT, and
# dotnet-install.sh's /usr/share/dotnet isn't a registered path — without
# this, `ilspycmd` aborts with "You must install or update .NET to run this
# application" (verified in a throwaway).
ENV DOTNET_ROOT=/usr/share/dotnet
# ilspycmd 8.2's apphost targets an OLDER major (net6) than the 8.0 runtime
# the SDK ships; default roll-forward (Minor, within the same major) can't
# bridge that, so the tool aborts "You must install or update .NET". Allow
# rolling forward across majors so the installed runtime satisfies any tool
# TFM regardless of channel (verified in a throwaway).
ENV DOTNET_ROLL_FORWARD=LatestMajor
ENV PATH=/usr/local/bin:/root/.dotnet/tools:/usr/share/dotnet:$PATH
# ============================================================================

# ============================================================================
# Windows native-PE DYNAMIC execution / hooking (Tier C).  Wine runs a REAL
# Windows PE headlessly — x64 via `wine`, x86 via wine32:i386 — under a virtual
# X display, so a GUI challenge that DRAWS its flag (GDI / GDI+) can be rendered
# and screenshotted, and its Windows-API calls traced live. This is the
# executable substrate that the Unicorn / angr emulation path can only
# approximate (emulation has no real Win32 runtime → heap/GDI state must be
# hand-reconstructed; running under Wine gives it for free).
#
#   * wine 10 + wine32:i386  — 64- AND 32-bit PE support (both common in CTF).
#   * xvfb / xvfb-run + xauth — headless X server; a GUI PE won't render at all
#     without a display, so Wine alone does NOT deliver the "screenshot the
#     drawn flag" use case — these are mandatory, not optional.
#   * imagemagick `import` / `convert` — screenshot the rendered Wine window.
#   * WINDOWS-API HOOK is Wine's BUILT-IN relay tracer, not frida:
#         WINEDEBUG=+relay,+gdiplus  xvfb-run wine app.exe
#     traces cross-DLL calls (GdipDrawLineI args, etc.) with zero extra tooling.
#     (frida — added below — is for NATIVE-LINUX-ELF instrumentation; under Wine
#     it would hook Wine's gdiplus *shim*, not a real DLL, so it is the weak leg
#     of the Windows-hook story. Use +relay for Wine, frida for ELF.)
#
# Validated on the trixie base in a throwaway: wine + wine32:i386 install clean,
# `wine --version` has no wine32-missing warning, the syswow64 (32-bit)
# subsystem is present, an x64 console PE runs under `xvfb-run wine`,
# gdiplus.dll is in the prefix, and +relay emits call traces. Isolated with
# `|| true` / WARN-mask exactly like the angr / floss / .NET layers so a bad
# wine release can NEVER break the worker image — the tool is simply absent
# until a build confirms it. The prefix is NOT baked (saves ~770 MB); the first
# wine-using job in a container's lifetime inits it once (~10-15 s) and it then
# persists for that container. WINEDLLOVERRIDES suppresses the mono/gecko
# install prompt so that first init can't hang a job under headless Xvfb.
ENV WINEPREFIX=/root/.wine WINEARCH=win64 WINEDEBUG=-all \
    WINEDLLOVERRIDES="mscoree,mshtml="
# wine64 is REQUIRED even for a 64-bit-only workload: on Debian trixie the bare
# `wine` metapackage + wine32:i386 defaults its loader to 32-bit, so the prefix
# is created as a WIN32 install and every x64 PE aborts with "WINEARCH set to
# win64 but '<prefix>' is a 32-bit installation" (caught by the hooking smoke
# test — the x64 GdipDrawLineI PE wouldn't run, +relay stayed empty). Adding
# wine64 provisions the 64-bit runtime so the prefix comes up #arch=win64 with a
# syswow64 subsystem → runs BOTH 64- and 32-bit PEs (WoW64). The wine64 package
# no longer ships a distinct `wine64` binary in wine 10 (one dispatcher) — it is
# the RUNTIME that matters. Verified in a throwaway: with wine64 the PE runs and
# +relay captures GdipDrawLineI(g,pen,20,10,20,70)… with exact stroke coords.
RUN dpkg --add-architecture i386 \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      wine wine64 wine32:i386 xvfb xauth x11-utils imagemagick 2>&1 | tail -8 || true \
 ; rm -rf /var/lib/apt/lists/* \
 ; ( command -v wine >/dev/null 2>&1 \
     && echo "wine OK $(wine --version 2>&1 | head -1) [win64 prefix inits on first use]" \
     || echo "[WARN] wine unavailable; native-PE dynamic execution disabled" )

# frida — dynamic instrumentation for NATIVE Linux ELF processes: attach to a
# running binary, hook functions / library exports, trace calls, and patch
# memory at runtime. Fills the worker's live-hooking gap for Linux rev / pwn
# (the Windows-PE-under-Wine hook path is Wine's +relay tracer above, NOT this).
# Prebuilt manylinux wheels — clean install, no capstone / unicorn conflict
# (validated in a throwaway: frida 17.x + frida-tools CLIs). Isolated || true so
# a bad release can't break the pip resolver, matching the angr / floss layers.
RUN pip install --no-cache-dir frida frida-tools 2>&1 | tail -3 || true \
 && ( python3 -c "import frida" 2>/dev/null \
      && echo "frida OK $(frida --version 2>&1 | head -1)" \
      || echo "[WARN] frida unavailable" )

# one_gadget — finds libc one-shot RCE gadgets (constraints + offset).
# Standard tool the pwn agent reaches for after locating libc; cheaper
# than building a full ROP chain when one_gadget conditions hold.
RUN gem install --no-document one_gadget

# redress — Go-binary aware reverse tooling (https://github.com/goretk/redress).
# Ghidra 12 already ships Go runtime type databases for 1.15-1.23 in
# /opt/ghidra/Ghidra/Features/Base/data/typeinfo/golang/, so ghiant
# decompiles named Go binaries fine. redress complements that for
# stripped Go binaries: `redress info` reads the Go pclntab to recover
# Go version + module + package list even when symbols are stripped,
# and `redress symbols` lists `package.func` names that nm misses.
# amd64-only (upstream ships no arm64 binary); on non-amd64 hosts the
# Go pwn/rev path falls back to ghiant alone.
ARG REDRESS_VERSION=v1.2.65
RUN ARCH=$(dpkg --print-architecture) \
 && if [ "$ARCH" = "amd64" ]; then \
        curl -fsSL "https://github.com/goretk/redress/releases/download/${REDRESS_VERSION}/redress-${REDRESS_VERSION}-linux-amd64.tar.gz" \
             -o /tmp/redress.tar.gz \
         && tar -C /usr/local/bin --strip-components=1 \
                -xzf /tmp/redress.tar.gz "redress-${REDRESS_VERSION}/redress" \
         && chmod +x /usr/local/bin/redress \
         && rm -f /tmp/redress.tar.gz \
         && echo "redress installed: $(redress --version 2>&1 | head -1)"; \
    else \
        echo "redress: skipping install on $ARCH (no upstream binary)"; \
    fi

# GEF — modern gdb plugin (heap visualizer, vmmap, pattern, checksec,
# ROP helpers, ARM/MIPS/PowerPC support). Single Python file, no
# heavy deps — the right default for a debugger subagent. GEF covers
# 95% of CTF dynamic analysis. Source it conditionally so `gdb -nx`
# still gets a clean default-gdb shell.
#
# pwndbg can be installed alongside as an OPTIONAL alternative; toggle
# at runtime via `GDB_USE_PWNDBG=1`. Useful when GEF's tcache /
# fastbin output is hard to parse (pwndbg's `bins` / `vis_heap_chunks`
# is more visual). Defaults OFF so the build doesn't regress for users
# who don't care.
#
# The `rm -f /root/.gdbinit` below is load-bearing, not tidiness: pwndbg's
# setup.sh appends `source /opt/pwndbg/gdbinit.py` there, which DEFEATS the
# GDB_USE_PWNDBG switch — /etc/gdb/gdbinit loads GEF, then ~/.gdbinit loads
# pwndbg on top of it regardless, and pwndbg's command registration then hits
# an AssertionError on a name GEF already owns. Measured in the live worker:
# a bare `gdb-multiarch -batch` emitted 37 lines (GEF banner + a 33-line
# Python traceback) against 4 lines with -nx, and 6 clean lines with
# GDB_NO_GEF=1. That noise landed in every agent tool result. The file's only
# content is that one source line, so dropping it leaves /etc/gdb/gdbinit as
# the single loader the switch actually controls.
ARG INSTALL_PWNDBG=1
RUN curl -fsSL https://gef.blah.cat/py -o /opt/gef.py \
 && if [ "$INSTALL_PWNDBG" = "1" ]; then \
        echo "[pwndbg] installing alongside GEF (opt-in via GDB_USE_PWNDBG=1)"; \
        git clone --depth 1 https://github.com/pwndbg/pwndbg /opt/pwndbg \
         && (cd /opt/pwndbg && ./setup.sh) \
        || { \
            echo "[WARN] pwndbg install failed; GEF will be the only plugin" 1>&2; \
            rm -rf /opt/pwndbg; \
        }; \
        rm -f /root/.gdbinit; \
    fi \
 && printf '%s\n' \
        '# Auto-load GEF (default) or pwndbg when GDB_USE_PWNDBG=1.' \
        '# Disable both with GDB_NO_GEF=1 or `gdb -nx`.' \
        'python' \
        'import os' \
        'if not os.environ.get("GDB_NO_GEF"):' \
        '    if (os.environ.get("GDB_USE_PWNDBG")' \
        '            and os.path.isfile("/opt/pwndbg/gdbinit.py")):' \
        '        gdb.execute("source /opt/pwndbg/gdbinit.py")' \
        '    else:' \
        '        gdb.execute("source /opt/gef.py")' \
        'end' \
    > /etc/gdb/gdbinit \
 && echo "GEF at /opt/gef.py; pwndbg at /opt/pwndbg (if installed). autoloaded via /etc/gdb/gdbinit"

COPY worker /app/worker

# Expose ghiant as a Bash command so the agent can invoke decompilation
# on demand instead of forcing it as a pre-step.
RUN ln -sf /app/worker/ghiant_cli.py /usr/local/bin/ghiant \
 && chmod +x /app/worker/ghiant_cli.py

# Expose `chal-libc-fix` as a Bash command — patchelf wrapper that
# scans the challenge bundle for a Dockerfile / Makefile / docker-
# compose.yml that names the libc + ld-linux pair the chal really
# runs against, and rewrites the binary's interpreter / RUNPATH to
# load THAT libc instead of the worker's system libc. The debugger
# subagent calls this before any gdb session so dynamic analysis
# matches remote behavior.
RUN ln -sf /app/worker/chal_libc_fix.py /usr/local/bin/chal-libc-fix \
 && chmod +x /app/worker/chal_libc_fix.py

# Expose `heap-probe` — gdb harness that dumps tcache / fastbin /
# unsorted / chunks at each breakpoint hit as a JSON timeline. Lets
# the debugger subagent answer "what does the heap look like after N
# alloc/free?" in ONE Bash call instead of an ad-hoc gdb session.
RUN ln -sf /app/worker/heap_probe.py /usr/local/bin/heap-probe \
 && chmod +x /app/worker/heap_probe.py

# Expose `gdb-clean` — gdb wrapper that strips GEF's per-invocation
# banner (~1 KB of "X commands loaded and Y functions added" + ANSI
# color codes) so the debugger subagent gets clean, terse output.
# Source `gdb-init.py` first inside a probe to additionally disable
# GEF's auto-printed context panel on every stop.
# `docker` shim — injects --memory into an uncapped `docker run`/`create`.
# /usr/local/bin precedes /usr/bin on the worker PATH, so this wins. The worker
# cgroup does NOT bound sibling containers, and an uncapped chal image took the
# whole WSL VM down on 2026-08-01 (job 0ddd62708d39). See the script header.
RUN ln -sf /app/worker/docker_memguard.sh /usr/local/bin/docker \
 && chmod +x /app/worker/docker_memguard.sh

RUN ln -sf /app/worker/gdb_clean.sh /usr/local/bin/gdb-clean \
 && ln -sf /app/worker/gdb_clean.sh /usr/local/bin/gdb-multiarch-clean \
 && chmod +x /app/worker/gdb_clean.sh \
 && mkdir -p /opt/scaffold \
 && ln -sf /app/worker/gdb_init.py /opt/scaffold/gdb-init.py

# Copy-paste exploit scaffolds for heap-pwn chals. The main agent does
# `cp /opt/scaffold/heap_menu.py ./exploit.py` and edits the TODOs.
# Scaffolds load ./.chal-libs/libc_profile.json automatically, so the
# version-matrix branching is data-driven instead of prose-driven.
COPY scaffold /opt/scaffold
# Importable, not just present. `/opt` is on no sys.path, so the three import
# lines the pwn prompt hands the agent —
#     from scaffold.tcache_poison import safe_link, key_bypass_needed
# — raised ModuleNotFoundError here and in the runner alike: the section that
# exists to stop agents rewriting heap primitives from scratch died on its own
# first line.
#
# Symlink into site-packages, NOT `ENV PYTHONPATH=/opt`: this same /opt holds
# gef.py, pwndbg/ and how2heap/, and adding it to the path makes `import gef`
# resolve to the GEF gdb plugin (verified in the built image). One name is
# exposed; /opt/scaffold stays the source for `cp /opt/scaffold/heap_menu.py`.
# runner/Dockerfile does the same — keep the two in lockstep.
RUN ln -sfn /opt/scaffold \
      "$(python3 -c 'import site; print(site.getsitepackages()[0])')/scaffold" \
 && python3 -c "\
from scaffold.tcache_poison import safe_link, alignment_ok, key_bypass_needed; \
from scaffold.aslr_retry import aslr_retry; \
from scaffold.fsop_wfile import build_full_chain; \
print('scaffold importable in worker (no sys.path juggling)')"

# shellphish/how2heap — canonical glibc-version-keyed PoC corpus for
# every well-known heap technique (fastbin_dup, house_of_*,
# tcache_poisoning, unsafe_unlink, large_bin_attack, etc.). Cloned at
# build time so the agent can read the EXACT PoC source for the chal's
# detected glibc version (matched against ./.chal-libs/libc_profile.json
# `version_tuple`). Source-only — we don't compile or run any of the
# PoCs, just reference them as known-good chain templates.
RUN git clone --depth 1 https://github.com/shellphish/how2heap.git /opt/how2heap \
 && rm -rf /opt/how2heap/.git \
 && echo "how2heap: $(ls -d /opt/how2heap/glibc_* | wc -l) glibc-version dirs, $(find /opt/how2heap/glibc_* -name '*.c' | wc -l) PoCs"

# fpylll + cysignals — lattice reduction (LLL/BKZ), GSO, enumeration. The one
# heavy-crypto capability class the symbolic stack (z3/sympy/gmpy2) genuinely
# cannot cover in-container: Coppersmith small-roots, Hidden-Number-Problem
# (biased-nonce ECDSA), LWE/knapsack, and any "build a lattice, LLL-reduce,
# read off the short vector" CTF attack. Strictly better than reaching for the
# separate SageMath runner for these (no multi-GB image, no cross-container
# hop). Both ship cp312 manylinux wheels — NO compilation, NO apt deps beyond
# the base (validated in a throwaway on bare python:3.12-slim: install is
# wheel-only and a 6x6 LLL.reduction runs). cysignals is fpylll's runtime dep
# and is NOT auto-pulled by the fpylll wheel, so it is listed explicitly.
# Isolated + WARN-masked exactly like the angr / frida layers so a bad release
# can never break the worker image — lattice tooling is simply absent until a
# build confirms it. Placed last so it can't invalidate the expensive layers
# above on a rebuild.
RUN pip install --no-cache-dir cysignals fpylll 2>&1 | tail -3 || true \
 && ( python3 -c "from fpylll import IntegerMatrix, LLL, GSO, Enumeration; import fpylll; print('fpylll OK', fpylll.__version__)" \
      || echo "[WARN] fpylll unavailable; lattice (LLL/BKZ/Coppersmith) tooling disabled" )

# ---------------------------------------------------------------- web3 -----
# Foundry — forge (build/test Solidity), cast (the RPC swiss-army knife:
# call/send/storage/sig/keccak/abi-decode) and anvil (a local chain, and a FORK
# of a remote one). This is the whole toolchain for both shapes of Web3
# challenge: a local `Setup.sol` you deploy and break, and a remote instance
# you drive over RPC.
#
# Binaries are copied out and ~/.foundry deleted: the installer leaves ~446 MB
# of download cache behind, of which only these three (184 MB) are needed, and
# `chisel` (a Solidity REPL, 42 MB) has no place in a non-interactive agent.
# Pinned like everything else here — a toolchain that moves under the prompt is
# the failure this repo keeps re-learning.
#
# MUST stay in lockstep with runner/Dockerfile: the agent develops here and its
# exploit is auto-run THERE, so a `cast` call that works in development and is
# missing in the sandbox is a job that dies at exit with 0 bytes of stdout.
ARG FOUNDRY_VERSION=v1.7.1
RUN curl -fsSL https://foundry.paradigm.xyz | bash \
 && /root/.foundry/bin/foundryup -i "${FOUNDRY_VERSION}" \
 && cp /root/.foundry/bin/forge /root/.foundry/bin/cast /root/.foundry/bin/anvil \
       /usr/local/bin/ \
 && rm -rf /root/.foundry \
 && forge --version && cast --version && anvil --version

# web3.py + the eth-* stack for Python exploits, and slither for static
# analysis of the contract source (reentrancy, unchecked calls, access
# control). slither is isolated + WARN-masked like the angr / fpylll layers: a
# bad release must not be able to break the image, and its absence only costs
# one analysis route.
RUN pip install --no-cache-dir web3==7.16.0 eth-abi==5.2.0 eth-account==0.13.7 \
 && python3 -c "from web3 import Web3; assert Web3.keccak(text='transfer(address,uint256)').hex().startswith('a9059cbb'), 'keccak wrong'; print('web3 OK')"
RUN pip install --no-cache-dir slither-analyzer==0.11.6 2>&1 | tail -3 || true \
 && ( slither --version >/dev/null 2>&1 && echo "slither OK $(slither --version 2>&1 | head -1)" \
      || echo "[WARN] slither unavailable; Solidity static analysis disabled" )

# ---------------------------------------------------------------------------
# Added 2026-08-22 after auditing the day's run logs for what agents reached
# for and did not find. Each group names its evidence; nothing here is on the
# list merely because it is standard CTF tooling.
# ---------------------------------------------------------------------------

# A BROWSER — selenium has been installed all along with nothing to drive.
# There was no chromium, no chrome and no puppeteer/playwright cache in this
# image, so three independent lineages apt-installed google-chrome-stable INTO
# the challenge image to get one, and the bot-visits-your-URL class (job
# daee7ea287d4, bot/bot.js + bot.php) had no way to reproduce the bot locally.
# chromium-driver is the matching webdriver, so selenium does not need a
# version-matching dance. Callers must pass --no-sandbox: chromium's sandbox
# needs privileges this container deliberately does not have.
RUN apt-get update && apt-get install -y --no-install-recommends \
      chromium chromium-driver \
 && rm -rf /var/lib/apt/lists/* \
 && chromium --headless --no-sandbox --disable-gpu --dump-dom about:blank >/dev/null 2>&1 \
 && echo "chromium OK $(chromium --version 2>&1 | head -1)" \
 && echo "chromedriver OK $(chromedriver --version 2>&1 | head -1)"

# PCAP — job ee0bb8c866cf (rev) worked on a .pcap and reached for tshark. It
# was in neither this image nor the forensic sibling, so there was nowhere to
# go. tshark's postinst asks whether non-superusers may capture; preseed it to
# `false` or the build hangs on an interactive prompt.
#
# wabt gives wasm2wat / wat2wasm / wasm-objdump: WebAssembly shows up in both
# web and rev challenges and there was no way to read a .wasm at all.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" \
      | debconf-set-selections \
 && DEBIAN_FRONTEND=noninteractive apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      tshark tcpdump wabt \
 && rm -rf /var/lib/apt/lists/* \
 && tshark --version >/dev/null 2>&1 && echo "tshark OK $(tshark --version 2>&1 | head -1)" \
 && tcpdump --version >/dev/null 2>&1 && echo "tcpdump OK" \
 && echo "wabt OK $(wasm2wat --version 2>&1 | head -1)"

# ffuf — content discovery against a remote web target. sqlmap was here and a
# directory/endpoint fuzzer was not, and job 7398c17bf7dd reached for ffuf by
# name. Not in bookworm's apt, so it comes from the pinned release tarball.
#
# The wordlist is NOT an extra: a fuzzer with nothing to fuzz from is the same
# half-tool as selenium with no browser, which is the defect this whole block
# exists to fix. dirb is ~2 MB and is here for its common.txt only.
ARG FFUF_VERSION=2.1.0
RUN ( curl -fsSL -o /tmp/ffuf.tar.gz \
        "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" \
      && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf \
      && rm -f /tmp/ffuf.tar.gz \
      && chmod +x /usr/local/bin/ffuf \
      && echo "ffuf OK $(ffuf -V 2>&1 | head -1)" ) \
    || echo "[WARN] ffuf unavailable; web content discovery falls back to curl loops"
RUN apt-get update && apt-get install -y --no-install-recommends dirb \
 && rm -rf /var/lib/apt/lists/* \
 && test -s /usr/share/dirb/wordlists/common.txt \
 && echo "wordlist OK /usr/share/dirb/wordlists/common.txt ($(wc -l < /usr/share/dirb/wordlists/common.txt) entries)"

# seccomp-tools — dumps a binary's seccomp-bpf filter as readable rules. The
# pwn agent otherwise hand-decodes the BPF program from a disassembly. Native
# extension; ruby-dev is already installed above for one_gadget.
RUN ( gem install --no-document seccomp-tools \
      && echo "seccomp-tools OK $(seccomp-tools --version 2>&1 | head -1)" ) \
    || echo "[WARN] seccomp-tools unavailable; seccomp filters must be read by hand"

# volatility3 — memory-image forensics, referenced by job fddaec60c2a7 and
# present in no image at all. Symbol tables for Windows profiles are fetched at
# run time, so a network-less run only has the Linux/Mac paths.
#
# scapy — packet crafting and pcap manipulation from Python, the companion to
# tshark for anything that has to SEND rather than read.
#
# keystone-engine — the assembler counterpart to capstone, which was already
# here. pwntools' asm() covers the common cases; keystone covers the ones where
# a raw architecture/mode pair is needed without pwntools' opinions.
RUN pip install --no-cache-dir volatility3 scapy keystone-engine 2>&1 | tail -3 \
 && python3 -c "import scapy.all, keystone; print('scapy OK', scapy.all.conf.version); print('keystone OK')" \
 && ( vol --help >/dev/null 2>&1 || python3 -m volatility3 --help >/dev/null 2>&1 ) \
 && echo "volatility3 OK"

ENV PYTHONPATH=/app

CMD ["python", "-m", "worker.runner"]
