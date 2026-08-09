#!/usr/bin/env python3
"""Dev-time SMOKE run of a solver in the REAL runner sandbox (dev/run parity).

The agent develops in the WORKER container, but its solver is auto-run in the
SEPARATE runner sandbox (hextech_ctf_tool-runner, or the sagemath image for
.sage). The two are NOT identical: gdb / qemu-user / ltrace / strace and some
libraries may exist in one but not the other. A solver that shells out to a tool
present in the worker but absent in the runner crashes at auto-run with
FileNotFoundError and the job ends no_flag — job bedf6b58bfd2 was a VM-rev solver
that used `gdb` (present in the worker, absent in the runner then) and died in
2.6s, after which the judge voted STOP.

This wrapper runs your solver in the SAME sandbox auto-run uses, so you SEE the
runner's real environment (missing tools, available libs like unicorn/capstone,
and the true wall time vs the runner timeout) BEFORE you finalize — then fix the
invocation or switch approach (e.g. emulate with unicorn instead of shelling out
to gdb). It is the general, all-module analog of `worker.sage_smoke`.

USAGE (from the agent's Bash; cwd = the job work dir):
    python3 -m worker.solver_smoke <script> [solver-args...] [--timeout N]

`<script>` is a BARE filename in your work dir (solver.py / exploit.py /
solver.sage — a .sage runs in the Sage sandbox, anything else in the default
runner). Prints wall seconds, exit_code, timeout/killed flags, and stdout+stderr
tail. Read-only w.r.t. job STATE (no judge stage, no meta writes) — it just
spawns the sandbox exactly like auto-run.
"""
import os
import sys
import time


def _usage(msg: str = "") -> int:
    if msg:
        print(f"[solver_smoke] {msg}", file=sys.stderr)
    print(
        "usage: python3 -m worker.solver_smoke <script> [args...] [--timeout N]",
        file=sys.stderr,
    )
    return 2


def _clip(s: str, head: int = 1500, tail: int = 1500) -> str:
    s = s or ""
    if len(s) <= head + tail:
        return s
    return s[:head] + "\n...[clipped]...\n" + s[-tail:]


def main(argv: list[str]) -> int:
    args = list(argv)
    timeout_s = 300
    positional: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--timeout":
            if i + 1 >= len(args):
                return _usage("--timeout needs a value")
            try:
                timeout_s = int(args[i + 1])
            except ValueError:
                return _usage(f"--timeout value not an int: {args[i + 1]!r}")
            i += 2
            continue
        if a.startswith("--timeout="):
            try:
                timeout_s = int(a.split("=", 1)[1])
            except ValueError:
                return _usage(f"--timeout value not an int: {a!r}")
            i += 1
            continue
        positional.append(a)
        i += 1

    if not positional:
        return _usage("no script given")
    script = positional[0]
    solver_args = positional[1:]

    job_id = os.environ.get("JOB_ID", "").strip()
    if not job_id:
        return _usage("JOB_ID env not set — run this from the job's agent Bash")

    # Pin repo root ahead of cwd (mirrors sage_smoke): `-m` puts the work dir on
    # sys.path[0], and a challenge that ships a top-level modules/ could shadow
    # the real runner import.
    _repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if not sys.path or sys.path[0] != _repo_root:
        sys.path.insert(0, _repo_root)

    try:
        from modules._runner import run_in_sandbox, SAGE_IMAGE, RUNNER_IMAGE
    except Exception as e:  # pragma: no cover
        print(f"[solver_smoke] cannot import runner: {e!r}", file=sys.stderr)
        return 1

    use_sage = script.endswith(".sage")
    image = SAGE_IMAGE if use_sage else RUNNER_IMAGE
    print(
        f"[solver_smoke] job={job_id} script={script} args={solver_args} "
        f"timeout={timeout_s}s image={image} (the SAME sandbox auto-run uses)",
        flush=True,
    )

    t0 = time.time()
    try:
        res = run_in_sandbox(
            job_id,
            script,
            args=solver_args,
            use_sage=use_sage,
            timeout_s=timeout_s,
            enable_supervise=False,
            log_fn=lambda m: print(f"[solver_smoke:runner] {m}", flush=True),
        )
    except Exception as e:
        print(f"[solver_smoke] FAILED to spawn after {time.time() - t0:.1f}s: {e!r}",
              file=sys.stderr)
        return 1
    dt = time.time() - t0

    print("=" * 60, flush=True)
    print(
        f"[solver_smoke] WALL = {dt:.2f}s  exit_code = {res.get('exit_code')}  "
        f"timeout = {bool(res.get('timeout'))}  "
        f"killed = {bool(res.get('killed_by_supervise'))}",
        flush=True,
    )
    print("--- stdout (head+tail) ---", flush=True)
    print(_clip(res.get("stdout")), flush=True)
    err = (res.get("stderr") or "").strip()
    if err:
        print("--- stderr (head+tail) ---", flush=True)
        print(_clip(res.get("stderr")), flush=True)
    print("=" * 60, flush=True)
    print(
        "[solver_smoke] This IS the auto-run environment. A FileNotFoundError "
        "here means a tool exists in your worker but NOT the runner — change the "
        "invocation or switch approach BEFORE ship (gdb/qemu-user/ltrace/strace "
        "ARE in the runner now; unicorn/capstone too). A timeout here means it "
        "won't fit the auto-run wall either.",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
