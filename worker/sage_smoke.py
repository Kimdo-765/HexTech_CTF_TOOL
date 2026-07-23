#!/usr/bin/env python3
"""Dev-time SMOKE / timing harness for a `.sage` solver.

WHY THIS EXISTS
---------------
SageMath is NOT installed in the worker container (`sage: command not
found`); a `.sage` solver only ever runs inside the separate
`sagemath/sagemath` sandbox the runner spawns at auto-run time. So the
main agent normally SHIPS a Sage solver whose single most expensive step
(a Groebner basis / variety / resultant / small_roots) it has never once
executed — and finds out only in production whether that step fits the
challenge's per-round time budget. Job c1edf9e91910 (McNie rank-metric):
a per-stage Groebner over GF(2^19) blew a ~7 s/stage server alarm, was
never timed before ship, and the job captured no flag.

This wrapper lets the agent MEASURE that step during development by
running the `.sage` in the SAME sandbox the runner uses — identical
container image, `--user 0:0`, HOST_DATA_DIR bind at the same absolute
path, workdir, TMPDIR — so it reproduces auto-run timing exactly and
dodges the uid-1001 preparse EACCES the runner already solves. It REUSES
`modules._runner.run_in_sandbox`; it does not re-implement the docker
incantation.

USAGE (from the agent's Bash; cwd = the job work dir)
-----------------------------------------------------
    python3 -m worker.sage_smoke <script.sage> [solver-args...] [--timeout N]

`<script.sage>` is a BARE filename that already exists in your work dir.
For a remote-oracle / multi-stage challenge do NOT point this at the live
target: it is often one-shot / rate-limited, and it measures network I/O
rather than the decisive math step. Instead build a LOCAL synthetic
single-instance harness (`bench.sage`) from the known parameters and time
THAT — one solve, no network.

Prints a compact report: wall seconds, exit_code, timeout / killed flags,
and head+tail of stdout/stderr. Read-only w.r.t. job STATE (no judge
stage, no meta writes; it only spawns the sandbox, exactly like auto-run).
"""
import os
import sys
import time


def _usage(msg: str = "") -> int:
    if msg:
        print(f"[sage_smoke] {msg}", file=sys.stderr)
    print(
        "usage: python3 -m worker.sage_smoke <script.sage> "
        "[solver-args...] [--timeout N]",
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

    # `python3 -m worker.sage_smoke` (the mandated invocation) puts the agent's
    # cwd — the job WORK DIR — on sys.path[0]. If a challenge's extracted source
    # ships a top-level `modules/` package it would shadow the real /app/modules
    # and break `import modules._runner`. Pin the repo root (this file's
    # grandparent, e.g. /app) AHEAD of cwd so the import always resolves to the
    # runner, never to challenge source.
    _repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if not sys.path or sys.path[0] != _repo_root:
        sys.path.insert(0, _repo_root)

    try:
        from modules._runner import run_in_sandbox, SAGE_IMAGE
    except Exception as e:  # pragma: no cover - import wiring
        print(f"[sage_smoke] cannot import runner: {e!r}", file=sys.stderr)
        return 1

    print(
        f"[sage_smoke] job={job_id} script={script} args={solver_args} "
        f"timeout={timeout_s}s image={SAGE_IMAGE}",
        flush=True,
    )
    print(
        "[sage_smoke] NOTE: spins the SAME Sage sandbox the runner uses; a "
        "missing image auto-pulls (~2 GB, slow ONCE — pre-pull via "
        "`./start.sh --with-sage`).",
        flush=True,
    )

    t0 = time.time()
    try:
        res = run_in_sandbox(
            job_id,
            script,
            args=solver_args,
            use_sage=True,
            timeout_s=timeout_s,
            enable_judge=False,
            log_fn=lambda m: print(f"[sage_smoke:runner] {m}", flush=True),
        )
    except Exception as e:
        elapsed = time.time() - t0
        print(
            f"[sage_smoke] FAILED to spawn after {elapsed:.1f}s: {e!r}",
            file=sys.stderr,
        )
        return 1
    elapsed = time.time() - t0

    print("=" * 60, flush=True)
    print(f"[sage_smoke] WALL = {elapsed:.2f}s", flush=True)
    print(f"[sage_smoke] exit_code = {res.get('exit_code')}", flush=True)
    print(
        f"[sage_smoke] timeout = {bool(res.get('timeout'))}  "
        f"killed_by_supervise = {bool(res.get('killed_by_supervise'))}",
        flush=True,
    )
    if res.get("timeout"):
        print(
            f"[sage_smoke] WARNING: the {timeout_s}s hard timeout FIRED — the "
            "step did NOT finish; true runtime is LONGER. If a per-round budget "
            "is smaller than this, CHANGE THE METHOD (do not just raise the "
            "alarm).",
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
        f"[sage_smoke] DECIDE: is {elapsed:.2f}s per solve within the "
        "challenge's per-round budget (server alarm / number of stages)? If "
        "not, the method is wrong — switch it before shipping.",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
