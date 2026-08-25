#!/usr/bin/env python3
"""No single job may take the whole host's CPU.

Run: python3 scripts/test_worker_cpu_limit.py

THE FAILURE THIS PREVENTS

RAM was capped per worker slot from the first day; CPU was not, and nothing
made the asymmetry visible until it cost something. Measured 2026-08-25 during
a nine-job batch:

    worker-3   2467% CPU   32-core host   load average 45.8
    rev job 0a22d7fa7919 had fanned its own search into 36 processes

Nothing was misbehaving. An agent parallelising its own brute force is the
intended behaviour; there was simply no ceiling on it, so one job starved the
other eight while the operator watched the dashboard.

A cap on one container is not a cap. This repo starts containers from three
different places, and every one of them can take every core:

    the worker slot         docker-compose.yml `cpus:`
    the docker-py SDK       modules/_runner.py (the sandbox), the Ghidra
                            decompiler x2, forensic, misc, worker/misc_recarve,
                            and the web terminal — each a SIBLING of the slot,
                            outside its cgroup, invisible to the CLI shim
    the agent's own `docker run`   worker/docker_memguard.sh

The SDK list is not written out below. An earlier version of this file named
three of those files by hand and missed worker/misc_recarve.py while asserting
the set was complete, so the omission read as a decision. The check enumerates
every `containers.run` / `containers.create` call by AST instead.

WHY THIS IS NOT A TAUTOLOGY

Asserting "the constant is 8" would pass forever while the value reached no
container. So every check below follows the value to the place that enforces
it: the rendered compose service, the kwarg actually handed to docker-py, and
the argv the shim really execs. The parser is exercised against the real
cgroup spellings, including the uncapped one that must NOT be read as zero.
"""
from __future__ import annotations

import ast
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

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


# ------------------------------------------------- 1. the worker slot itself
section("the worker slot declares a CPU cap")

compose = (ROOT / "docker-compose.yml").read_text()
chk("compose sets cpus on the shared worker template",
    "cpus: ${WORKER_SLOT_CPUS:-8}" in compose)
# The template is what makes it uniform; a per-service copy is how eleven slots
# end up capped and one does not.
chk("cpus is declared ONCE, in the template, not per slot",
    compose.count("cpus: ${WORKER_SLOT_CPUS") == 1,
    compose.count("cpus: ${WORKER_SLOT_CPUS"))
chk("the shim's CPU default is passed into the worker environment",
    "CHAL_CONTAINER_CPUS: ${CHAL_CONTAINER_CPUS:-8}" in compose)

# ------------------------------------------------------------ 2. the runner
section("the runner inherits the slot's cap instead of running free")

runner_src = (ROOT / "modules/_runner.py").read_text()
tree = ast.parse(runner_src)

defaults = [n for n in tree.body
            if isinstance(n, ast.Assign)
            and any(getattr(t, "id", "") == "DEFAULT_CPUS" for t in n.targets)]
chk("modules/_runner.py defines DEFAULT_CPUS", len(defaults) == 1, len(defaults))
if defaults:
    chk("...and it is 8", ast.literal_eval(defaults[0].value) == 8,
        ast.literal_eval(defaults[0].value))

fn = next((n for n in tree.body
           if isinstance(n, ast.FunctionDef) and n.name == "_parent_slot_cpus"),
          None)
chk("_parent_slot_cpus exists", fn is not None)

sandbox = next((n for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == "run_in_sandbox"),
               None)
chk("run_in_sandbox exists", sandbox is not None)
if sandbox:
    argnames = [a.arg for a in sandbox.args.args + sandbox.args.kwonlyargs]
    chk("run_in_sandbox takes nano_cpus", "nano_cpus" in argnames, argnames)

# The kwarg has to reach docker-py, not merely exist. Find the containers.run
# call and confirm nano_cpus is among the keywords passed.
run_kwargs = []
for node in ast.walk(tree):
    if (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "run"
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == "containers"):
        run_kwargs = [k.arg for k in node.keywords]
        break
chk("containers.run is handed nano_cpus", "nano_cpus" in run_kwargs, run_kwargs)
chk("...alongside mem_limit, so the two cannot drift apart",
    "mem_limit" in run_kwargs, run_kwargs)
# Inheriting the parent's SIZE while dropping its SWAP POLICY is a half-inherit,
# and it shipped that way: observed live 2026-08-25, runners on a 4 GiB rev slot
# came up with mem=4096MiB and swap allowance 8192MiB while the parent slot had
# 4096/4096. Docker grants 2x swap whenever memswap is omitted, and slow swap
# thrash is the state that wedged this VM twice.
chk("...and memswap_limit, so the runner cannot swap past its parent",
    "memswap_limit" in run_kwargs, run_kwargs)

# ------------------------------------------------- 3. the cgroup parser
section("cpu.max is parsed correctly, uncapped included")

sys.path.insert(0, str(ROOT))
try:
    from modules._runner import _parent_slot_cpus  # noqa: E402
except Exception as e:  # docker sdk missing in a bare env
    _parent_slot_cpus = None
    skip("cpu.max parser", "modules._runner not importable here (%s)" % e)

if _parent_slot_cpus is not None:
    CASES = [
        # (file contents, expected nano_cpus)
        ("800000 100000\n", 8_000_000_000),   # the shipped 8-CPU cap
        ("100000 100000\n", 1_000_000_000),
        ("50000 100000\n", 500_000_000),      # fractional CPU
        ("max 100000\n", None),               # UNCAPPED — must not read as 0
        ("", None),
        ("garbage\n", None),
        ("0 100000\n", None),                 # nonsense quota
        ("800000 0\n", None),                 # nonsense period
    ]
    with tempfile.TemporaryDirectory() as td:
        for i, (body, want) in enumerate(CASES):
            p = os.path.join(td, "cpu.max.%d" % i)
            with open(p, "w") as fh:
                fh.write(body)
            got = _parent_slot_cpus(p)
            chk("cpu.max %-16r -> %r" % (body.strip(), want), got == want, got)
        chk("a missing cpu.max is None, not a crash",
            _parent_slot_cpus(os.path.join(td, "does-not-exist")) is None)

# ------------------------------------ 3b. EVERY other container this repo starts
section("every container this repo starts, enumerated not listed")

# This section used to name three files. It missed worker/misc_recarve.py — a
# per-job container created straight through the SDK — and the docstring above
# it claimed the set was complete, so the omission read as a decision. A
# hand-written list cannot notice the site nobody thought of, so enumerate the
# call sites instead and require every one of them to be either capped or
# explicitly excused.
#
# EXCUSED, with the reason, because "capped or listed" is only a real gate if
# the list is short and argued:
#   api/routes/tunnel.py — cloudflared. Not per-job and not agent-driven: one
#   operator-rolled tunnel process for the whole stack, started from Settings,
#   with no restart policy. It cannot be multiplied by a job, which is the
#   property everything else here is bounded for.
UNCAPPED_BY_DESIGN = {"api/routes/tunnel.py"}

# `git ls-files` is preferred because it skips data/jobs/**, which holds
# thousands of agent-authored scripts (one with null bytes that makes ast.parse
# raise ValueError, not SyntaxError). But it returns NOTHING when this suite
# runs inside the worker image: a worktree's `.git` is a file pointing at a
# path outside the mount. That produced an empty file list, which made every
# check below pass over zero sites — a green sweep that had looked at nothing.
# Fall back to a walk that excludes the same directories by name.
_SKIP_DIRS = {"data", ".git", ".claude", "__pycache__", "node_modules", "venv"}
_tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "*.py"],
                          capture_output=True, text=True)
_pyfiles = _tracked.stdout.split() if _tracked.returncode == 0 else []
if not _pyfiles:
    _pyfiles = [p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*.py")
                if not _SKIP_DIRS & set(p.relative_to(ROOT).parts)]
chk("the container-site sweep found python files to scan", len(_pyfiles) > 50,
    len(_pyfiles))

sites = []
for rel in _pyfiles:
    try:
        t = ast.parse((ROOT / rel).read_text(errors="replace"))
    except (SyntaxError, ValueError, OSError):
        continue
    for node in ast.walk(t):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("run", "create")
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "containers"):
            sites.append((rel, node.lineno, [k.arg for k in node.keywords]))

chk("the sweep found every known container site (>=8)", len(sites) >= 8,
    len(sites))

_missing_cpu = [(r, l) for r, l, kw in sites
                if "nano_cpus" not in kw and r not in UNCAPPED_BY_DESIGN]
chk("every container site passes nano_cpus, or is excused by name",
    not _missing_cpu, _missing_cpu)

# Inheriting a memory SIZE while dropping the swap POLICY is the half-inherit
# 0dff12c fixed for the runner. Docker grants 2x swap whenever memswap is
# omitted, and slow swap thrash is what wedged this VM twice.
_missing_swap = [(r, l) for r, l, kw in sites
                 if "mem_limit" in kw and "memswap_limit" not in kw]
chk("every site that sets mem_limit also sets memswap_limit", not _missing_swap,
    _missing_swap)

_excused_present = [r for r in UNCAPPED_BY_DESIGN
                    if any(s[0] == r for s in sites)]
chk("the excuse list has not gone stale — every excused file still starts a "
    "container", sorted(_excused_present), sorted(UNCAPPED_BY_DESIGN))

# The shared helper is what stops the decompiler being capped at something the
# sandbox is not.
for rel, _l, kw in sites:
    if "nano_cpus" not in kw or rel in ("modules/_runner.py",
                                        "api/routes/terminal.py"):
        continue
    src = (ROOT / rel).read_text()
    chk("%s uses the shared helper, not a local constant" % rel,
        "from modules._runner import runner_nano_cpus" in src, rel)

# ------------------------------------------------------- 4. the web terminal
section("the web terminal is a runner too")

term = (ROOT / "api/routes/terminal.py").read_text()
chk("terminal.py imports the shared default rather than inventing one",
    "from modules._runner import RUNNER_IMAGE, DEFAULT_CPUS" in term)
chk("terminal container is created with nano_cpus",
    "nano_cpus=DEFAULT_NANO_CPUS" in term)

# --------------------------------------------- 5. the agent's own containers
section("the docker shim caps what the AGENT starts")

shim = ROOT / "worker/docker_memguard.sh"
chk("shim exists", shim.is_file())

if shim.is_file():
    if not shutil.which("bash"):
        skip("shim behaviour", "no bash on PATH")
    else:
        with tempfile.TemporaryDirectory() as td:
            rec = os.path.join(td, "fake-docker")
            out = os.path.join(td, "argv")
            with open(rec, "w") as fh:
                fh.write('#!/usr/bin/env bash\nprintf "%s\\n" "$@" > ' + out + "\n")
            os.chmod(rec, 0o755)

            def run_shim(args, env_extra):
                env = dict(os.environ)
                env["DOCKER_MEMGUARD_REAL"] = rec
                env.pop("JOB_ID", None)
                env.update(env_extra)
                subprocess.run(["bash", str(shim)] + args,
                               env=env, capture_output=True, timeout=30)
                with open(out) as fh:
                    return [l.rstrip("\n") for l in fh]

            argv = run_shim(["run", "img", "cmd"],
                            {"CHAL_CONTAINER_MEM": "2g",
                             "CHAL_CONTAINER_CPUS": "8"})
            chk("a bare `docker run` gains --cpus", "--cpus" in argv, argv)
            if "--cpus" in argv:
                chk("...with the configured value",
                    argv[argv.index("--cpus") + 1] == "8", argv)
            chk("...and still gains --memory", "--memory" in argv, argv)
            # The injection sits right after the subcommand so the CALLER's own
            # later flag wins (verified on docker 29.6.1: `--cpus 1 --cpus 4`
            # yields cpu.max 400000/100000).
            chk("injection lands immediately after the subcommand",
                argv[0] == "run" and "--cpus" in argv[1:6], argv[:8])

            argv = run_shim(["run", "img", "cmd"],
                            {"CHAL_CONTAINER_MEM": "2g",
                             "CHAL_CONTAINER_CPUS": "0"})
            chk("CHAL_CONTAINER_CPUS=0 disables only the CPU cap",
                "--cpus" not in argv and "--memory" in argv, argv)

            argv = run_shim(["run", "img", "cmd"],
                            {"CHAL_CONTAINER_MEM": "0",
                             "CHAL_CONTAINER_CPUS": "8"})
            chk("CHAL_CONTAINER_MEM=0 no longer disables the CPU cap",
                "--cpus" in argv and "--memory" not in argv, argv)

            argv = run_shim(["run", "img", "cmd"],
                            {"CHAL_CONTAINER_MEM": "0",
                             "CHAL_CONTAINER_CPUS": "0"})
            chk("both at 0 is a complete pass-through",
                argv == ["run", "img", "cmd"], argv)

            # `docker container run` is the same operation as `docker run`,
            # and it used to walk straight past the guard: the first non-flag
            # argument is `container`, which matched neither arm of the case.
            argv = run_shim(["container", "run", "img", "cmd"],
                            {"CHAL_CONTAINER_MEM": "2g",
                             "CHAL_CONTAINER_CPUS": "8"})
            chk("REGRESSION: `docker container run` is capped too",
                "--cpus" in argv and "--memory" in argv, argv)
            chk("  ...with the flags after `run`, not after `container`",
                argv[:2] == ["container", "run"] and "--cpus" in argv[2:6],
                argv[:8])
            argv = run_shim(["container", "create", "img"],
                            {"CHAL_CONTAINER_MEM": "2g",
                             "CHAL_CONTAINER_CPUS": "8"})
            chk("  ...and so is `docker container create`",
                "--cpus" in argv and "--memory" in argv, argv)
            argv = run_shim(["container", "ls"],
                            {"CHAL_CONTAINER_MEM": "2g",
                             "CHAL_CONTAINER_CPUS": "8"})
            chk("  ...while `docker container ls` is passed through unchanged",
                argv == ["container", "ls"], argv)

            # Subcommands other than run/create must be untouched, or the shim
            # starts corrupting `docker ps`.
            argv = run_shim(["ps", "-a"],
                            {"CHAL_CONTAINER_MEM": "2g",
                             "CHAL_CONTAINER_CPUS": "8"})
            chk("`docker ps` is passed through unchanged",
                argv == ["ps", "-a"], argv)

print("")
print("%d checks, %d failed, %d skipped" % (checks, fails, skipped))
sys.exit(1 if fails else 0)
