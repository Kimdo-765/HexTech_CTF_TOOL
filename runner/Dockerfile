FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libgmp-dev libmpfr-dev libmpc-dev \
    binutils file curl \
    gcc cpp \
    bash less vim-tiny nano \
 && rm -rf /var/lib/apt/lists/*
# gcc/cpp: pwntools asm()/shellcraft shells out to `cpp` (preprocess) then `as`.
# Without cpp, asm() raises FileNotFoundError before the exploit ever connects —
# job a15ff70a6ed5 captured the real flag from work/ but its auto-run crashed here
# (cpp missing), so the genuine flag never reached the trusted exploit.py.stdout.

RUN pip install --no-cache-dir \
    pwntools==4.13.0 \
    pycryptodome==3.21.0 \
    gmpy2==2.2.1 \
    sympy==1.13.3 \
    z3-solver==4.13.4.0 \
    ecdsa==0.19.0 \
    requests==2.32.3 \
    httpx==0.27.2

# fpylll + cysignals — lattice reduction (LLL/BKZ) so a lattice solver.py the
# agent writes in the worker actually RUNS here in the sandbox-validation
# container too (worker and runner must have the same crypto capability or the
# final sandbox run fails on a missing import). cp312 manylinux wheels, no
# compilation / apt deps (throwaway-validated). Isolated so a bad release can't
# break the runner image — a lattice solver just won't validate until fixed.
RUN pip install --no-cache-dir cysignals fpylll 2>&1 | tail -3 || true \
 && ( python3 -c "from fpylll import LLL, IntegerMatrix; print('fpylll OK in runner')" \
      || echo "[WARN] fpylll unavailable in runner" )

WORKDIR /work
# Default to bash so the web terminal works; orchestrators set their
# own command (`python3 /work/exploit.py ...` or `sage ...`) via
# `command=[...]` and that takes precedence.
CMD ["bash"]
