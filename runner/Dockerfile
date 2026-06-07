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

WORKDIR /work
# Default to bash so the web terminal works; orchestrators set their
# own command (`python3 /work/exploit.py ...` or `sage ...`) via
# `command=[...]` and that takes precedence.
CMD ["bash"]
