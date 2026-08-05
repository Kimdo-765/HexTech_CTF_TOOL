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
        ("subprocess with list argv",
         "FileNotFoundError: [Errno 2] No such file or directory: 'gdb'"),
    ):
        h2 = hint({"exit_code": 127, "stderr": err})
        chk(f"  missing binary — {label}", bool(h2) and "gdb" in h2, h2[:70])

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

    failed = [r for r in _results if not r]
    print(f"\n{len(_results)} checks, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
