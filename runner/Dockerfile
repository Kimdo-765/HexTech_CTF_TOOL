FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libgmp-dev libmpfr-dev libmpc-dev \
    binutils file curl \
    # git: foundryup hard-requires it and exits "need 'git'" without ever
    # fetching a binary (the worker image had it incidentally; this one did
    # not, so the Foundry layer below failed here and only here).
    git \
    build-essential cpp \
    gdb qemu-user-static ltrace strace \
    bash less vim-tiny nano \
 && rm -rf /var/lib/apt/lists/*
# build-essential (was bare `gcc`): the gcc DRIVER alone cannot compile anything
# here. Debian's gcc only *Recommends* libc6-dev, and this apt line uses
# --no-install-recommends, so the stock image had /usr/bin/gcc but NO
# /usr/include/stdio.h and no Scrt1.o/crti.o — `which gcc` SUCCEEDS while the
# smallest hello-world dies on "stdio.h: No such file or directory" (and even an
# include-free main() fails at link). Job e1b933afc137 (web+rev hybrid) lost an
# already-captured flag to exactly this: main built a native decrypt harness with
# gcc in the WORKER (which has the headers), the auto-run recompile in the RUNNER
# failed, exploit.py exited 1, and the job ended no_flag with the REAL flag
# stranded in meta.flag_candidates. Verified counterfactual: installing the
# toolchain in an ephemeral runner and rebuilding that job's own harness.c against
# its own ciphertext yields decrypt_ret=1 and the correct DH{...}. build-essential
# also brings g++ and make, which were BOTH absent — the same bug was one C++
# harness away from recurring with a different symptom (FileNotFoundError).
# cpp stays explicit: pwntools asm()/shellcraft shells out to `cpp` (preprocess) then `as`.
# Without cpp, asm() raises FileNotFoundError before the exploit ever connects —
# job a15ff70a6ed5 captured the real flag from work/ but its auto-run crashed here
# (cpp missing), so the genuine flag never reached the trusted exploit.py.stdout.
# gdb/qemu-user-static/ltrace/strace: rev (and some pwn) solvers dynamically
# TRACE or EMULATE the target at auto-run — the worker has these but the runner
# didn't, so a solver validated in the worker crashed here on FileNotFoundError
# and the job ended no_flag (job bedf6b58bfd2: a VM-rev solver shelled out to
# `gdb`, absent → 2.6s crash → judge STOP). Same dev/run-parity rationale as the
# fpylll block below. (unicorn/capstone come in via the pip deps.)

RUN pip install --no-cache-dir \
    pwntools==4.13.0 \
    pycryptodome==3.21.0 \
    gmpy2==2.2.1 \
    sympy==1.13.3 \
    z3-solver==4.13.4.0 \
    # SMT beyond z3. crypto/rev DO auto-run their solver here, so unlike
    # the forensic parsers these must exist in both images — a solver the
    # worker could write and the runner cannot execute is the dev/run
    # parity bug this file keeps re-learning. Unpinned for the reason
    # given in worker/requirements.txt: invented pins broke the build.
    pyboolector cvc5 \
    ecdsa==0.19.0 \
    requests==2.32.3 \
    httpx==0.27.2 \
    numpy==2.5.1
# numpy: same version as worker/requirements.txt, and it must stay that way —
# this pair is the parity. It was in NEITHER image, which is how job
# 46bc4387edff came to `pip install numpy` into worker-2's live container on
# 2026-08-03; that install persisted, and on 2026-08-05 job 06f3a326d453 drew
# the same slot, found numpy importable, and spent 61 turns / $23.43 on a UOV
# forgery whose line 33 was `import numpy as np`. Here it died at import with
# exit 1 and 0 bytes of stdout, none of the attack executed. Agents reach for
# numpy unprompted on GF(2^k) linear algebra and blob reshaping; the fix is to
# have it in both images, not to hope they avoid it.

# fpylll + cysignals — lattice reduction (LLL/BKZ) so a lattice solver.py the
# agent writes in the worker actually RUNS here in the sandbox-validation
# container too (worker and runner must have the same crypto capability or the
# final sandbox run fails on a missing import). cp312 manylinux wheels, no
# compilation / apt deps (throwaway-validated). Isolated so a bad release can't
# break the runner image — a lattice solver just won't validate until fixed.
RUN pip install --no-cache-dir cysignals fpylll 2>&1 | tail -3 || true \
 && ( python3 -c "from fpylll import LLL, IntegerMatrix; print('fpylll OK in runner')" \
      || echo "[WARN] fpylll unavailable in runner" )

# Heap-pwn scaffolds — same tree the worker bakes at /opt/scaffold so an
# exploit that does `sys.path.insert(0, "/opt"); from scaffold.tcache_poison
# import …` (what pwn prompts teach, and what the SCAFFOLD_NUDGE pushes)
# survives auto-run. Without this, agent-side validation in the worker passes
# and the orchestrator sandbox dies on ModuleNotFoundError: No module named
# 'scaffold' with stdout 0 B (job ddcd69cc259c: working local chain, runner
# crash on import line 15, status=no_flag). Dev/run parity: worker Dockerfile
# already `COPY scaffold /opt/scaffold`; keep the two images in lockstep.
COPY scaffold /opt/scaffold
# …and make it IMPORTABLE, which copying it never did. `/opt` is on no
# sys.path in either image, so `from scaffold.X import Y` — the exact three
# lines modules/pwn/prompts.py hands the agent — raised ModuleNotFoundError in
# the worker AND here. The prompt was teaching an import that could not work.
#
# A symlink into site-packages rather than `ENV PYTHONPATH=/opt`: /opt also
# holds gef.py, pwndbg/ and how2heap/ in the worker image, and putting it on
# the path makes `import gef` resolve to the GEF gdb plugin (verified). This
# exposes exactly one name, `scaffold`, and keeps /opt/scaffold as the single
# source for the `cp /opt/scaffold/heap_menu.py ./exploit.py` workflow.
RUN ln -sfn /opt/scaffold \
      "$(python3 -c 'import site; print(site.getsitepackages()[0])')/scaffold" \
 && python3 -c "\
from scaffold.tcache_poison import safe_link, alignment_ok, key_bypass_needed; \
from scaffold.aslr_retry import aslr_retry; \
from scaffold.fsop_wfile import build_full_chain; \
print('scaffold importable in runner (no sys.path juggling)')"

# ---------------------------------------------------------------- web3 -----
# The SAME three Foundry binaries and the same pinned web3 stack as
# worker/Dockerfile, for the reason every other block in this file exists: the
# agent develops in the worker and its exploit is auto-run HERE. A `cast call`
# or `import web3` that resolves in development and not in the sandbox is a
# solver that dies at import with 0 bytes of stdout and a job that reads
# no_flag — the numpy incident (job 06f3a326d453) in a different costume.
#
# Keep the version pins identical to the worker's. slither is NOT installed
# here: it is a source-analysis tool the agent runs while reasoning, never
# something a shipped exploit shells out to.
ARG FOUNDRY_VERSION=v1.7.1
RUN curl -fsSL https://foundry.paradigm.xyz | bash \
 && /root/.foundry/bin/foundryup -i "${FOUNDRY_VERSION}" \
 && cp /root/.foundry/bin/forge /root/.foundry/bin/cast /root/.foundry/bin/anvil \
       /usr/local/bin/ \
 && rm -rf /root/.foundry \
 && forge --version && cast --version && anvil --version

RUN pip install --no-cache-dir web3==7.16.0 eth-abi==5.2.0 eth-account==0.13.7 \
 && python3 -c "from web3 import Web3; assert Web3.keccak(text='transfer(address,uint256)').hex().startswith('a9059cbb'), 'keccak wrong'; print('web3 OK in runner')"

WORKDIR /work
# Default to bash so the web terminal works; orchestrators set their
# own command (`python3 /work/exploit.py ...` or `sage ...`) via
# `command=[...]` and that takes precedence.
CMD ["bash"]
