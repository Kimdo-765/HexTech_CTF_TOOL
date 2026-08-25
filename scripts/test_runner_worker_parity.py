#!/usr/bin/env python3
"""The solver must execute in the environment it was developed in.

Run: python3 scripts/test_runner_worker_parity.py

THE FAILURE THIS PREVENTS

An agent develops a solver inside the worker container, the solver is executed
by run_in_sandbox inside a SEPARATE container, and anything present in the
first and missing from the second turns a working solve into a no_flag at the
last step. It has happened three times:

    gcc present but libc6-dev absent   compilation failed in the runner only
    gdb absent                         a rev solver's fixed-address oracle
                                       silently diverged run-to-run
    measured 2026-08-25                angr, ghiant, qemu-system-x86_64, wine,
                                       node, patchelf, nc, socat, unzip, xxd

Each was fixed by adding one package to a second Dockerfile. Each time the two
files drifted again, because keeping a 137-line and a 556-line Dockerfile in
tool-for-tool agreement by hand is not a thing that stays done.

RUNNER_IMAGE now names the worker image, so there is one image and it cannot
drift from itself. This file exists to keep that true.

WHY THIS IS NOT A TAUTOLOGY

Asserting "the two names are equal" would pass trivially and prove nothing —
someone can point RUNNER_IMAGE back at a slim image tomorrow and the names
would still be equal to themselves. So the checks are:

  1. the name is defined EXACTLY ONCE in the repo (a second copy is how the
     web terminal quietly ran a different image from the sandbox), and
  2. the image RUNNER_IMAGE names actually CONTAINS the tools, probed by
     running them. That is the check that fails if the constant is ever
     repointed at something smaller.

Check 2 needs docker. Where docker is unreachable it is SKIPPED loudly rather
than silently passing — a parity suite that goes green because it could not
look is worse than no suite.
"""
from __future__ import annotations

import ast
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

checks = 0
fails = 0
skipped = 0


def chk(label, cond, got=None):
    global checks, fails
    checks += 1
    if cond:
        print("PASS  %s" % label)
    else:
        fails += 1
        print("FAIL  %s\n        got=%r" % (label, got))


def skip(label, why):
    global skipped
    skipped += 1
    print("SKIP  %s — %s" % (label, why))


def section(name):
    print("\n--- %s %s" % (name, "-" * max(0, 56 - len(name))))


# ------------------------------------------------------- 1. single source
section("the image name has exactly one definition")
defs = []
# Scan TRACKED files only. `rglob("*.py")` walks data/jobs/** too — thousands of
# agent-authored scripts, one of which contains null bytes and makes ast.parse
# raise ValueError (not SyntaxError, so a narrow except let it escape). Those
# files are job artifacts, not source, and cannot define this constant. This
# also handles the nested-worktree case for free: a worktree's files are not
# tracked in the tree that contains it.
_tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "*.py"],
                          capture_output=True, text=True)
_files = [ROOT / f for f in _tracked.stdout.split()] if _tracked.returncode == 0 \
    else sorted(ROOT.rglob("*.py"))
for p in _files:
    if not p.is_file() or p.parent.name == "scripts":
        continue
    try:
        tree = ast.parse(p.read_text(errors="replace"))
    except (SyntaxError, ValueError, OSError):
        continue
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", "") == "RUNNER_IMAGE" for t in node.targets):
            defs.append("%s:%d" % (p.relative_to(ROOT), node.lineno))
chk("RUNNER_IMAGE is assigned in exactly one module", len(defs) == 1, defs)
chk("...and that module is modules/_runner.py",
    defs and defs[0].startswith("modules/_runner.py"), defs)

src = (ROOT / "modules/_runner.py").read_text()
ns: dict = {}
for line in src.splitlines():
    if line.startswith("RUNNER_IMAGE") or line.startswith("SAGE_IMAGE"):
        exec(line, ns)
image = ns.get("RUNNER_IMAGE")
chk("RUNNER_IMAGE names the worker image",
    image == "hextech_ctf_tool-worker", image)

# the compose service that builds it must exist, or the name points at nothing
compose = (ROOT / "docker-compose.yml").read_text()
chk("compose builds an image by that name",
    "image: %s" % image in compose, image)

# the web terminal must not have re-declared it
term = (ROOT / "api/routes/terminal.py").read_text()
chk("the web terminal imports the constant instead of redeclaring it",
    "from modules._runner import RUNNER_IMAGE" in term)

# ------------------------------------------------------- 2. the tools exist
section("the named image really carries the toolchain")

# Tools an agent can reach in the worker and a solver may therefore shell out
# to. Each entry is a (name, probe) pair; probes are `command -v` for binaries
# and `python3 -c "import X"` for modules.
BINS = ["gcc", "g++", "ld", "make", "gdb", "objdump", "readelf", "strings",
        "nm", "file", "xxd", "patchelf", "strace", "ltrace", "unzip", "nc",
        "socat", "node", "openssl", "cast",
        "qemu-x86_64", "qemu-system-x86_64", "wine", "ghiant"]
MODS = ["pwn", "Crypto", "sympy", "numpy", "z3", "angr", "unicorn", "capstone",
        "gmpy2", "elftools", "requests", "web3"]

docker_bin = None
for cand in ("/snap/bin/docker", shutil.which("docker") or ""):
    if not cand:
        continue
    try:
        out = subprocess.run([cand, "image", "inspect", image],
                             capture_output=True, timeout=60)
        if out.returncode == 0:
            docker_bin = cand
            break
    except Exception:
        continue

if docker_bin is None:
    skip("toolchain probe", "no docker CLI can see image %r "
         "(the PATH docker in WSL is often a Docker-Desktop wrapper)" % image)
else:
    probe = "\n".join(
        ['for b in %s; do command -v "$b" >/dev/null 2>&1 && echo "Y $b" '
         '|| echo "n $b"; done' % " ".join(BINS + ["__ctl_missing__"])]
        + ['python3 -c "import %s" >/dev/null 2>&1 && echo "Y %s" || echo "n %s"'
           % (m, m, m) for m in MODS + ["__ctl_missing_mod__"]]
    )
    run = subprocess.run(
        [docker_bin, "run", "--rm", "--entrypoint", "sh", image, "-c", probe],
        capture_output=True, text=True, timeout=600)
    have = {}
    for line in run.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2:
            have[parts[1]] = (parts[0] == "Y")

    # instrument first: if a name that cannot exist reports present, every
    # other answer is worthless.
    bogus = [c for c in ("__ctl_missing__", "__ctl_missing_mod__") if have.get(c)]
    chk("the probe reports absent things as absent", not bogus, bogus)
    chk("the probe returned a result for every entry",
        len(have) == len(BINS) + len(MODS) + 2, len(have))

    if not bogus and have:
        missing_b = [b for b in BINS if not have.get(b)]
        missing_m = [m for m in MODS if not have.get(m)]
        chk("every binary the agent can develop against is present",
            not missing_b, missing_b)
        chk("every python module the agent can develop against is present",
            not missing_m, missing_m)

print("")
print("%d checks, %d failed, %d skipped" % (checks, fails, skipped))
sys.exit(1 if fails else 0)
