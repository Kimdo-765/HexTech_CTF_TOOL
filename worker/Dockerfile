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
    # --- Pwn / Rev: dynamic analysis + reverse engineering ---
    # (radare2 isn't in the slim base's apt; for full reversing the
    # decompiler sibling image already has Ghidra.)
    gdb gdb-multiarch strace ltrace patchelf \
    qemu-user-static \
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

# Node.js + the Claude Code CLI. PINNED to >=2.1.156 — the version that fixes
# the deterministic opus-4-8 thinking-block API 400 (see the bundle-removal step
# after pip install below, and memory sdk_bundled_cli_thinking_400). The SDK is
# made to use THIS system CLI, not its own stale bundled copy.
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/* \
 && npm install -g @anthropic-ai/claude-code@2.1.158

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
# here. Isolated || true.
ARG DOTNET_CHANNEL=8.0
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh 2>/dev/null \
 && bash /tmp/dotnet-install.sh --channel "${DOTNET_CHANNEL}" --install-dir /usr/share/dotnet 2>&1 | tail -3 \
 && ln -sf /usr/share/dotnet/dotnet /usr/local/bin/dotnet \
 && dotnet tool install --global ilspycmd 2>&1 | tail -3 \
 && ln -sf /root/.dotnet/tools/ilspycmd /usr/local/bin/ilspycmd \
 && (command -v ilspycmd >/dev/null 2>&1 && echo "ilspycmd OK" || echo "[WARN] ilspycmd unavailable") \
 || echo "[WARN] .NET / ilspycmd install failed; managed-PE C# decompile unavailable"
ENV PATH=/usr/local/bin:/root/.dotnet/tools:$PATH
# ============================================================================

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
RUN ln -sf /app/worker/gdb_clean.sh /usr/local/bin/gdb-clean \
 && chmod +x /app/worker/gdb_clean.sh \
 && mkdir -p /opt/scaffold \
 && ln -sf /app/worker/gdb_init.py /opt/scaffold/gdb-init.py

# Copy-paste exploit scaffolds for heap-pwn chals. The main agent does
# `cp /opt/scaffold/heap_menu.py ./exploit.py` and edits the TODOs.
# Scaffolds load ./.chal-libs/libc_profile.json automatically, so the
# version-matrix branching is data-driven instead of prose-driven.
COPY scaffold /opt/scaffold

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

ENV PYTHONPATH=/app

CMD ["python", "-m", "worker.runner"]
