#!/usr/bin/env python3
"""Regression suite for dev/run parity: the crash hint and the prompt warning.

Run inside the worker (needs the module's dependency tree):

    docker cp modules <worker>:/tmp/rp/modules
    docker cp scripts/test_runner_parity.py <worker>:/tmp/rp/t.py
    docker exec <worker> sh -c 'cd /tmp/rp && python3 t.py'

THE INCIDENT — job 06f3a326d453 (crypto, UOV forgery, 61 turns, $23.43, 1h50m)

    solver.py:33          import numpy as np
    runner exit_code      1
    runner stdout         0 bytes
    runner stderr         ModuleNotFoundError: No module named 'numpy'

None of the attack executed. Three things had to line up:

1. CONTAINER DRIFT. Both worker slots run one image, but job 46bc4387edff ran
   `pip install numpy` inside worker-2's LIVE container on 2026-08-03. It
   persisted. Two days later this job landed on slot 2, found numpy importable,
   and built an hour of work on it. worker-1 still has no numpy — so a job's
   environment depended on which slot it drew.
2. NO PARITY CHECK REACHED IT. `worker.solver_smoke` exists precisely for this
   ("a solver that shells out to a tool present in the worker but absent in the
   runner crashes at auto-run and the job ends no_flag") but was named only in
   modules/rev/prompts.py. Crypto heard about `sage_smoke`, which does not
   apply to a .py solver.
3. NO RETRY. Auto-retry continues only while it holds a `retry_hint`, and the
   only producer was the LLM judge. `enable_judge` is off — an operator
   setting — so the loop stopped at turn 0 with verdict=None on the most
   mechanically fixable failure there is.

Fixes under test: a deterministic hint for crashes the runner's own stderr
diagnoses, and the parity warning moved into the shared _TOOLS_BASE.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_results: list[bool] = []


def chk(label: str, cond: bool, got: object = "") -> None:
    _results.append(bool(cond))
    print(("PASS  " if cond else "FAIL  ") + label + ("" if cond else f"  | got={got!r}"))


def section(name: str) -> None:
    print("\n--- " + name + " " + "-" * max(0, 56 - len(name)))


def main() -> int:
    sys.path.insert(0, str(ROOT))
    import modules._common as C

    chk("runner_crash_hint is importable", hasattr(C, "runner_crash_hint"))
    if not hasattr(C, "runner_crash_hint"):
        print(f"\n{len(_results)} checks, 1 failed")
        return 1
    hint = C.runner_crash_hint

    NUMPY_ERR = ("Traceback (most recent call last):\n"
                 '  File "/data/jobs/x/work/solver.py", line 33, in <module>\n'
                 "    import numpy as np\n"
                 "ModuleNotFoundError: No module named 'numpy'\n")

    # ------------------------------------------------------- the real case
    section("the incident, from the job's own result.json")
    real = ROOT / "data" / "jobs" / "06f3a326d453" / "result.json"
    alt = Path("/data/jobs/06f3a326d453/result.json")
    src = real if real.is_file() else (alt if alt.is_file() else None)
    if src is None:
        chk("(job artifacts not mounted here — using a replica)", True)
        sandbox = {"exit_code": 1, "stdout": "", "stderr": NUMPY_ERR}
    else:
        sandbox = json.loads(src.read_text())["sandbox"]
    h = hint(sandbox)
    chk("a hint IS produced", bool(h), h[:80])
    chk("it names the missing module", "numpy" in h)
    chk("REGRESSION: it explains WHY the worker disagreed — otherwise the "
        "agent re-ships the same import",
        "pip" in h and "does NOT exist in the runner" in h, h[:400])
    chk("it points at the parity checker", "worker.solver_smoke" in h)
    chk("...and forbids re-shipping before that passes", "Do NOT re-ship" in h)

    # A ModuleNotFoundError can happen after partial output or inside a late
    # import. The hint must report what the runner observed, not always claim
    # that stdout was empty and none of the attack ran.
    partial = hint({
        "exit_code": 1,
        "stdout": "partial attack output",
        "stderr": "ModuleNotFoundError: No module named 'elftools'",
    })
    chk("non-empty stdout is measured instead of called empty",
        "stdout 21 characters" in partial and "empty stdout" not in partial,
        partial[:180])
    chk("the import name is not blindly used as the PyPI package name",
        "pip install --target ./.pydeps elftools" not in partial
        and "elftools` is provided by `pyelftools" in partial, partial[-500:])

    # ------------------------------------------------------- other classes
    section("other mechanically-diagnosable crashes")
    # These four strings were CAPTURED from the runner image, not invented. Its
    # /bin/sh is dash, which says "not found" where bash says "command not
    # found" and omits the "/bin/" prefix when exec'd directly. A first version
    # of the matcher required the bash spelling and so recognised only the form
    # the runner does not use by default.
    for label, err in (
        ("dash, exec'd directly",      "sh: 1: gdb: not found\n"),
        ("dash, via shell=True",       "/bin/sh: 1: gdb: not found\n"),
        ("bash",                       "bash: line 1: gdb: command not found\n"),
        ("ambiguous Python ENOENT",
         "FileNotFoundError: [Errno 2] No such file or directory: 'gdb'"),
    ):
        h2 = hint({"exit_code": 127, "stderr": err})
        chk(f"  actionable crash hint — {label}", bool(h2) and "gdb" in h2, h2[:70])

    # FileNotFoundError does not identify the failed operation: open(path) and
    # subprocess([argv0]) have the same final exception text.  The deterministic
    # producer must not invent a missing-tool provenance from that spelling.
    for path in ("output.txt", "./helper.sh", "/home/worker/cache.bin"):
        path_hint = hint({
            "exit_code": 1,
            "stderr": (
                "Traceback (most recent call last):\n"
                "  File 'solver.py', line 7, in <module>\n"
                f"FileNotFoundError: [Errno 2] No such file or directory: '{path}'"
            ),
        })
        chk(f"  ENOENT stays operation-neutral — {path}",
            "does NOT distinguish an executable lookup from a missing data path"
            in path_hint
            and "runner sandbox has no" not in path_hint.lower(), path_hint[:240])

    # Prefer the last matching failure.  Solvers routinely print a caught tool
    # probe before a later, fatal data-file ENOENT.
    multi_hint = hint({
        "exit_code": 1,
        "stderr": (
            "FileNotFoundError: [Errno 2] No such file or directory: 'gdb'\n"
            "fallback selected\n"
            "FileNotFoundError: [Errno 2] No such file or directory: 'dump.bin'\n"
        ),
    })
    chk("  the last ENOENT is the one diagnosed",
        "`dump.bin`" in multi_hint and "ENOENT for `gdb`" not in multi_hint,
        multi_hint[:240])

    shell_hint = hint({"exit_code": 127, "stderr": "sh: 1: cast: not found\n"})
    chk("  shell command lookup remains unambiguous",
        "could not execute command/path `cast`" in shell_hint)
    for tool in ("java", "forge/cast/anvil", "git", "curl"):
        chk(f"  binary inventory includes runner tool {tool}", tool in shell_hint)
    for tool in ("chromium", "tshark", "wasm2wat", "ffuf", "seccomp-tools"):
        chk(f"  binary inventory identifies worker-only tool {tool}", tool in shell_hint)

    # ---------------------------------------------------------- must NOT fire
    section("it must stay OUT of the judge's territory")
    chk("a clean exit yields nothing", hint({"exit_code": 0, "stderr": NUMPY_ERR}) == "")
    chk("a non-crash (None) yields nothing", hint({"exit_code": None, "stderr": ""}) == "")
    chk("an empty result yields nothing", hint({}) == "" and hint(None) == "")
    chk("REGRESSION: a wrong-answer failure is NOT hinted — that needs "
        "judgment about the attack, which this must never pretend to have",
        hint({"exit_code": 1, "stderr": "AssertionError: signature did not verify"}) == "",
        hint({"exit_code": 1, "stderr": "AssertionError: signature did not verify"}))
    chk("a timeout is not hinted either",
        hint({"exit_code": 124, "stderr": "timed out after 300s"}) == "")
    chk("REGRESSION: prejudge_blocked is skipped — the sandbox never ran, so "
        "its stderr describes nothing",
        hint({"exit_code": 1, "stderr": NUMPY_ERR, "error": "prejudge_blocked"}) == "")
    chk("judge_aborted likewise",
        hint({"exit_code": 1, "stderr": NUMPY_ERR, "judge_aborted": True}) == "")

    # ------------------------------------------------------------- wiring
    section("wiring — it must reach the loop that stops")
    src_txt = (ROOT / "modules" / "_common.py").read_text()
    tail = src_txt.split("postjudge produced no retry_hint")[0]
    chk("the crash hint is consulted BEFORE the give-up branch",
        "runner_crash_hint(last_sandbox)" in tail, tail[-400:])
    chk("...and it populates retry_hint, which is what the loop gates on",
        "retry_hint = _crash_hint" in src_txt)
    chk("REGRESSION: it synthesizes a judge dict, so the existing inject path "
        "carries it verbatim like the prejudge redirect does",
        '"verdict": "runner_crash"' in src_txt)

    # ------------------------------------------------------------ prompts
    section("every module is warned, not just rev")
    import importlib
    for m in ("crypto", "pwn", "rev", "web", "misc", "forensic"):
        try:
            sp = getattr(importlib.import_module(f"modules.{m}.prompts"),
                         "SYSTEM_PROMPT", "") or ""
        except Exception as e:  # noqa: BLE001
            chk(f"  {m} prompt imports", False, str(e)[:60])
            continue
        chk(f"  {m} names solver_smoke", "solver_smoke" in sp)
        chk(f"  {m} says the runner is a different container",
            "NOT THE ONE THAT RUNS YOUR SOLVER" in sp)
    chk("REGRESSION: the warning lives in the SHARED base, so a new module "
        "inherits it instead of being forgotten",
        "NOT THE ONE THAT RUNS YOUR SOLVER"
        in (ROOT / "modules" / "_prompts.py").read_text().split("TOOLS_WEB")[0])

    # ------------------------------------------------- the --target recipe
    section("the escape hatch must be the one that actually crosses over")
    # A plain `pip install` lands in the worker only AND persists for the next
    # job on that slot — both halves of what broke 06f3a326d453. The prompt has
    # to offer something that works, or the agent will just do the wrong thing
    # again. `--target` + sys.path does cross: the sandbox mounts the job dir at
    # the same path with work/ as cwd, and both images share one Python base, so
    # even compiled wheels load (verified end-to-end with a C-extension package).
    base = (ROOT / "modules" / "_prompts.py").read_text().split("TOOLS_WEB")[0]
    chk("the shared block offers a way to add a library",
        "pip install --target ./.pydeps" in base, base[-200:])
    chk("REGRESSION: the solver is told to build the path from __file__, not "
        "from a relative './.pydeps' that only resolves in one cwd",
        "os.path.dirname(os.path.abspath(__file__))" in base)
    chk("...and to insert it on sys.path", "sys.path.insert(0," in base)
    chk("REGRESSION: it says a venv does NOT work — `source activate` changes "
        "the agent's shell and the sandbox never sees it",
        "NOT a virtualenv" in base and "never" in base.split("NOT a virtualenv")[1][:400])
    chk("it explains the persistence half of the problem too",
        "PERSISTS" in base or "persists" in base)
    chk("the chosen directory avoids the name this repo already overloads "
        "(_VENDOR_DIRS elects/skips 'vendor')",
        "./.pydeps" in base and "--target ./vendor" not in base)
    chk("the shared prompt distinguishes import and distribution names",
        "PyPI DISTRIBUTION name" in base and "elftools" in base
        and "pyelftools" in base)

    # Every package advertised by the deterministic hint is explicitly present
    # in runner/Dockerfile; optional packages must also retain their masked
    # installation semantics. This compares the shipped producer with the image
    # definition instead of trusting two hand-written lists independently.
    section("the advertised runner inventory matches the Dockerfile")
    runner_df = (ROOT / "runner" / "Dockerfile").read_text()
    inventory_hint = hint({"exit_code": 1, "stderr": NUMPY_ERR})
    for package in (
        "pwntools", "pycryptodome", "gmpy2", "sympy", "z3-solver",
        "pyboolector", "cvc5", "ecdsa", "requests", "httpx", "numpy",
        "web3", "eth-abi", "eth-account",
    ):
        chk(f"  {package} is both advertised and installed",
            package in inventory_hint and package in runner_df)
    chk("  scaffold is both advertised and copied into the image",
        "`scaffold` package" in inventory_hint and "COPY scaffold /opt/scaffold" in runner_df)
    fpy_block = runner_df.split("# fpylll + cysignals", 1)[1].split(
        "# Heap-pwn scaffolds", 1)[0]
    chk("  fpylll/cysignals are accurately labelled best-effort",
        "fpylll/cysignals are best-effort" in inventory_hint
        and "pip install --no-cache-dir cysignals fpylll" in fpy_block
        and "|| true" in fpy_block)
    worker_from = (ROOT / "worker" / "Dockerfile").read_text().splitlines()[0]
    runner_from = runner_df.splitlines()[0]
    chk("  compiled-wheel parity claim has the same Python base",
        worker_from == runner_from == "FROM python:3.12-slim",
        (worker_from, runner_from))

    failed = [r for r in _results if not r]
    print(f"\n{len(_results)} checks, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
