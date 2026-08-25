"""Sandboxed exploit/solver execution helper.

After a Claude agent has produced exploit.py / solver.py, the orchestrator
calls run_in_sandbox() to execute the script inside the hextech_ctf_tool-runner
container instead of the worker. This isolates network and resources from
the worker that holds the docker socket and the API key.

The runner image must be built once via:
    docker compose --profile tools build runner

When the judge GATES a run, attempt_sandbox_run() is wrapped by two
short Claude judge calls defined in modules._judge:

  pre   — review the script BEFORE the container starts. Severity=high
          aborts the run with a `prejudge_blocked` reason.
  post  — categorize the result (success / partial / hung /
          parse_error / network_error / crash / timeout / unknown)
          and produce a retry-ready hint.

A third stage exists and is NOT wired to that gate:

  during— ONE stall-detection call when the container has emitted no
          new output for 60s while still alive; it can KILL the
          container. Excluded from v1 enforce by the agreed scope, and
          it has its own flag (`enable_supervise`, default False) so
          that exclusion cannot be undone by accident. Its evidence is
          the live container's stalled output, which no post-hoc shadow
          can reconstruct — so it is the one stage never measured, and
          the only one that kills.

Whether pre/post gate at all is per JOB, not global: see
`_judge_mode_for_job`. Off or shadow reverts to plain blocking wait.
"""
from __future__ import annotations

import errno
import os
import re
import socket
import time
import uuid
from pathlib import Path
from typing import Optional

import docker

try:
    from docker.errors import NotFound as _DockerNotFound
except ImportError:  # lightweight test doubles need not provide docker.errors
    class _DockerNotFound(Exception):
        pass

from modules import _judge
from modules._events import emit_event
from modules.settings_io import get_setting

# The solver executes in the SAME IMAGE the agent developed in.
#
# This was `hextech_ctf_tool-runner`, a separate 2.16 GB image maintained
# alongside the 8.64 GB worker. Keeping two Dockerfiles (137 lines vs 556) in
# tool-for-tool agreement by hand has now failed three times, each time as a
# solver that worked in development and died at auto-run:
#   * gcc present, libc6-dev absent  -> compilation failed in the runner only
#   * gdb absent                     -> a rev solver's fixed-address oracle
#                                       silently diverged
#   * measured 2026-08-25            -> angr, ghiant, qemu-system-x86_64, wine,
#                                       node, patchelf, nc, socat, unzip, xxd
#                                       all present in the worker, absent here
# One image cannot drift from itself, which is the only fix that stays fixed.
#
# Verified before switching: the worker image is a SUPERSET — it carries
# /opt/scaffold, the web3/eth stack, cysignals/fpylll and cast, i.e. everything
# the runner image provided. `/work` is the one path it lacks, and that is
# irrelevant because run_in_sandbox passes `working_dir` explicitly. An angr
# solver was executed through it under the runner's own seccomp profile.
#
# ISOLATION IS UNCHANGED, and that is the part worth being careful about. The
# boundary that matters here was never image size: the runner gets NO
# docker.sock (so the docker CLI this image carries is inert), the same
# targeted seccomp profile, and none of the credential mounts — those ride on
# the worker CONTAINER, not in the image.
RUNNER_IMAGE = "hextech_ctf_tool-worker"
SAGE_IMAGE = "sagemath/sagemath:latest"
DEFAULT_TIMEOUT_S = 300
# crypto `.sage` solvers legitimately run for many minutes: a Gröbner basis /
# resultant / small_roots over a large modulus is compute-heavy AND silent
# (prints a start banner, then nothing until it returns). The 300s default
# kills them mid-computation — job 4e1be4f76c96's e=257 bivariate GB over a
# 2047-bit Zmod(N) was cut at the 301s hard timeout with only its start banner
# emitted. This path gets a 6000s (100-min) ceiling. It's a CEILING, not a
# fixed wait: fast sage runs (EC group ops, discrete_log) still exit the instant
# they finish and pay nothing. The 2g mem_limit OOM-kills a memory-blowup GB
# long before this, and Singular GB is deterministic (terminates or exhausts
# memory — it does not spin), so the worst realistic case is "runs long, then
# finishes or hits the ceiling" — exactly the budget this is meant to grant.
# The full 6000s applies ONLY to an OFFLINE solve (no remote target): a
# REMOTE-timed crypto oracle (job 4fc37cfcd04a: McNie, "20 stages / 150s total")
# drops the connection at its own window, so runner time past that is pure waste
# — remote crypto sage gets CRYPTO_SAGE_REMOTE_TIMEOUT_S, a generous backstop
# that still can't clip a solver the server itself would let finish.
CRYPTO_SAGE_TIMEOUT_S = 6000
CRYPTO_SAGE_REMOTE_TIMEOUT_S = 900
# web solvers routinely wait on slow round-trips the 300s default clips:
# an XSS/SSRF bot fetch + OOB callback settle, a multi-request chain, or a
# slow brute-force against a rate-limited endpoint. Give the whole web path
# a 3000s (50-min) ceiling. Like the crypto-sage ceiling it's a CEILING, not
# a fixed wait — a fast web solve exits the instant it finishes and pays
# nothing; the hard timeout still bounds a genuinely stuck run. (The stall
# watchdog used to be named here too — it is off in v1, see `enable_supervise`.)
WEB_TIMEOUT_S = 3000
DEFAULT_MEM = "2g"


def _parent_slot_mem() -> Optional[int]:
    """This worker slot's OWN live cap, in bytes, or None if unreadable.

    The runner is a SIBLING container, not a child: the daemon creates it
    outside the slot's cgroup, so its memory is charged to the VM and never to
    the slot. That is exactly why a fixed `DEFAULT_MEM` drifted from the slot —
    the operator could set slots to 8g and the runner would still OOM a solver
    at 2g, or set slots to 2g and the runner would quietly hold more than its
    parent.

    Reading `memory.max` rather than the setting is deliberate. The setting is
    what the operator asked for; the cgroup is what this slot actually has right
    now, including a dynamic expansion or an OOM escalation. Matching the live
    value is what "same as the parent worker" means while the cap moves.

    `memory.max` reads as the literal string `max` on an uncapped cgroup, which
    `_read_int` returns None for — the caller then falls back to DEFAULT_MEM
    rather than handing docker an unlimited runner.
    """
    try:
        from modules.worker_mem import _read_int
        v = _read_int("memory.max")
    except Exception:
        return None
    return v if (v and v > 0) else None


DEFAULT_CPUS = 8


def _parent_slot_cpus(cpu_max_path: str = "/sys/fs/cgroup/cpu.max") -> Optional[int]:
    """This worker slot's OWN live CPU cap, in docker NanoCpus, or None.

    Same reasoning as `_parent_slot_mem`: the runner is a SIBLING container, so
    its CPU time is charged to the VM and never to the slot. A runner with no
    cap can take every core on the host while its own parent is limited to
    eight — which is the asymmetry the slot cap exists to remove, just moved
    one container along.

    cgroup v2 spells this `cpu.max` as two fields, `<quota> <period>`, both in
    microseconds, where quota is the literal string `max` when uncapped. Cores
    = quota / period; docker wants NanoCpus = cores * 1e9. `cpu.max` is NOT an
    integer file, so `worker_mem._read_int` cannot read it — parsing it here is
    deliberate, not a duplicate of that helper.

    Returns None when uncapped or unreadable, and the caller then falls back to
    DEFAULT_CPUS rather than handing docker an unlimited runner.

    `cpu_max_path` exists so the parser can be tested against real cgroup
    spellings without a container; production never passes it.
    """
    try:
        raw = Path(cpu_max_path).read_text().split()
    except Exception:
        return None
    if len(raw) != 2 or raw[0] == "max":
        return None
    try:
        quota, period = int(raw[0]), int(raw[1])
    except ValueError:
        return None
    if quota <= 0 or period <= 0:
        return None
    return int(quota / period * 1_000_000_000)

# S1-ENV scope is deliberately narrow.  Missing/unknown modules never widen
# into the gate, and signatures are added only from observed production data.
REMOTE_TARGET_GATE_MODULES: tuple[str, ...] = ("pwn", "rev")
_BROKEN_TARGET_BANNER_SIGNATURES: tuple[bytes, ...] = (
    b"failed to find an available port: address already in use",
)

# Targeted seccomp profile = the Docker default + one addition: personality()
# with ADDR_NO_RANDOMIZE (0x40000, and its |base combinations) so gdb /
# `setarch -R` can disable per-inferior ASLR for rev dynamic-analysis solvers.
# The default profile EPERMs that personality() arg, which silently breaks a
# fixed-address gdb/setarch oracle validated in the worker (dev/run parity —
# see rev_runner_devrun_parity). This REPLACES an earlier seccomp=unconfined
# (f829f4b): an adversarial test showed unconfined re-exposed unprivileged
# user namespaces (unshare(NEWUSER) — the classic kernel-LPE amplifier) to the
# agent-authored code the runner executes as root, and the runner — unlike the
# worker — mounts NO docker.sock, so it is the isolation-relevant container.
# This profile keeps unshare(NEWUSER)/keyctl/bpf/userfaultfd BLOCKED while
# still allowing the one personality() value gdb needs (empirically verified).
# docker-py sends the profile CONTENT (not a path) to the daemon, so read it
# here; if it is somehow missing we fall back to the daemon DEFAULT profile
# (None) — safe (gdb-ASLR-off silently reverts to broken) rather than
# unconfined.
_SECCOMP_GDB_ASLR_PATH = Path(__file__).resolve().parent / "seccomp_gdb_aslr.json"
try:
    _SECCOMP_GDB_ASLR = _SECCOMP_GDB_ASLR_PATH.read_text()
except OSError:
    _SECCOMP_GDB_ASLR = None


def _resolve_sandbox_timeout(module, use_sage, override, has_target) -> int:
    """Resolve the sandbox HARD-timeout (seconds) for one run.

    Two module paths are widened past the 300s default:
      * crypto `.sage`, NO target (offline GB/resultant/LLL) → CRYPTO_SAGE_TIMEOUT_S
        (6000s) — a local algebraic solve can legitimately run many minutes.
      * crypto `.sage`, WITH a remote target → CRYPTO_SAGE_REMOTE_TIMEOUT_S
        (900s) — the server's per-connection window bounds it regardless, so a
        100-min ceiling is pointless (job 4fc37cfcd04a burned the full 6000s
        producing zero output against a 150s server budget).
      * web (any run) → WEB_TIMEOUT_S (3000s) — bot fetch + OOB callback settle,
        multi-request chains, and rate-limited brute force routinely outlast 300s.
    An explicit `exploit_timeout_seconds` override is honored up to the branch's
    cap (CRYPTO_SAGE_TIMEOUT_S on crypto-sage, WEB_TIMEOUT_S on web) so an
    operator can lift or lower it within that ceiling. EVERY other path — all
    non-web / non-crypto-sage python3 runs — keeps the historical 300s default /
    1800s override cap byte-for-byte. `override` is meta.exploit_timeout_seconds
    (None / str / int / junk; ≤0 or unparseable → ignored); `has_target` is
    bool(target) at the call site.
    """
    is_crypto_sage = (module == "crypto") and bool(use_sage)
    if is_crypto_sage:
        base = CRYPTO_SAGE_REMOTE_TIMEOUT_S if has_target else CRYPTO_SAGE_TIMEOUT_S
        cap = CRYPTO_SAGE_TIMEOUT_S
    elif module == "web":
        base = WEB_TIMEOUT_S
        cap = WEB_TIMEOUT_S
    else:
        base = DEFAULT_TIMEOUT_S
        cap = 1800
    if override is not None:
        try:
            ov = int(override)
        except (TypeError, ValueError):
            ov = 0
        if ov > 0:
            return min(ov, cap)
    return base

# How long can the container go without emitting any new stdout/stderr
# before we ask the judge whether to kill it.
SUPERVISE_STALL_S = 60
# For SHORT runs the supervise call is single-shot (conservative cost mode):
# ask once, then only the hard timeout can stop it. For LONG runs (crypto-sage
# offline = 6000s) that one-shot leaves a genuinely-stuck solve to burn the full
# 100 min in silence (job 4fc37cfcd04a). So when timeout_s exceeds
# SUPERVISE_PERIODIC_THRESHOLD_S we RE-ASK the judge every
# SUPERVISE_REASK_INTERVAL_S of continued silence — each re-ask hands the judge a
# larger stall duration, so it can decide the run is infeasible and kill early
# (~min, not ~100min). A run that emits output (per-stage progress — crypto
# solvers are prompted to) resets the silence clock and never triggers a re-ask.
SUPERVISE_PERIODIC_THRESHOLD_S = 1800
SUPERVISE_REASK_INTERVAL_S = 300
# Polling cadence inside _wait_with_supervise. Cheap on docker-py.
_POLL_INTERVAL_S = 2.0
# A solver normally writes newline-terminated progress, but a flushed progress
# indicator is allowed to omit the newline. Keep ordinary lines intact and only
# split a genuinely long partial line so live logging cannot retain an
# unbounded second copy of container output in the worker process.
_LIVE_LOG_PARTIAL_CHUNK_BYTES = 4096
# ``Container.logs(timestamps=True)`` prefixes each record with the daemon's
# UTC RFC3339Nano timestamp. Docker pads the fractional part to nine digits, so
# the captured bytes are directly sortable without losing nanosecond precision.
_DOCKER_LOG_TIMESTAMP_RE = re.compile(
    rb"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z) "
    rb"(?P<payload>.*)$"
)


def _host_path(job_id: str) -> str:
    host_root = os.environ.get("HOST_DATA_DIR")
    if not host_root:
        raise RuntimeError("HOST_DATA_DIR not set on worker")
    return f"{host_root.rstrip('/')}/jobs/{job_id}"


def _judge_mode() -> str:
    """`off` | `shadow` | `enforce`. See settings_io.get_judge_mode()."""
    try:
        from modules.settings_io import get_judge_mode

        return get_judge_mode()
    except Exception:
        return "enforce"


def _postjudge_extra(
    target_note: str,
    res: dict,
    prior_hints: list[str] | None,
) -> str:
    """The `extra_context` postjudge is judged WITH.

    Shared rather than inlined in the enforce branch, because shadow has to
    record the identical string. Built separately, the two drift and the
    shadow verdict is scored on a prompt the gate never saw.
    """
    extra = ""
    if target_note:
        # Surface pre-run target reachability notes to postjudge FIRST so its
        # verdict can distinguish "remote was down" (network_error, operator
        # must refresh instance) from "script's own bug" (parse_error, retry
        # will help).
        extra = target_note + "\n"
    if res.get("timeout"):
        extra += "(runner timeout fired before container exit)\n"
    elif res.get("killed_by_supervise"):
        extra += (
            "(supervise judge killed the container due to stalled output)\n"
        )
    if prior_hints:
        # Attach the retry-hint history so judge can detect "I'm about to
        # repeat myself" — the strongest signal for next_action=stop. Each
        # entry is one of the judge's prior postjudge_retry_hints (already
        # capped at ~600 chars upstream).
        extra += (
            "\nPRIOR RETRY HINTS (this job has already iterated "
            f"{len(prior_hints)} time(s); your new hint MUST NOT "
            "rhyme with these — if it does, next_action=stop):\n"
        )
        for i, h in enumerate(prior_hints, 1):
            if h:
                extra += f"  #{i}: {h[:300]}\n"
    return extra


def _judge_gates(mode: str) -> bool:
    """Does THIS mode let the judge's verdicts gate the run?

    Takes the mode rather than reading it, so a caller that needs both the
    mode and the gate answers them from ONE snapshot. Reading twice lets a
    settings change land in between and produce a pair that never existed —
    enforce's gating together with shadow's recording, in one attempt.
    """
    return str(mode) == "enforce"


def _judge_enabled() -> bool:
    """True when the judge's verdicts actually GATE the run.

    Shadow is deliberately False here: it records what the judge would have
    said and gates nothing, so every branch that reads this keeps behaving
    exactly as it does with the judge off. That identity is the whole basis
    for comparing a shadow job against the recorded outcome.
    """
    return _judge_gates(_judge_mode())


def _judge_mode_for_job(job_id: str) -> str:
    """The effective mode for THIS job — `enforce` is scoped by module.

    Stage 8 (operator decision, 2026-08-09) enforces on pwn and web only; see
    `settings_io.JUDGE_ENFORCE_MODULES` for why those two and nobody else. An
    out-of-scope module under a global `enforce` runs as `shadow`: it still
    records, it just does not gate.

    The module is read HERE, with the mode, and once. `meta` is the same place
    `agent_role_providers` is snapshotted at create time and for the same
    reason — a per-stage re-read lets the answer drift inside a single attempt,
    and half of this branch's defects have been two reads of one fact.

    Every failure path returns `shadow`, never `enforce` — and "every" has to
    include the settings read, which is the part that was got wrong first.
    `_judge_mode()`'s own `except` returns `"enforce"`: a defensible fail-open
    while the mode was global, and not defensible with a scope, because a
    filesystem error arriving as the string "enforce" is indistinguishable from
    an operator who chose it. Paired with a readable pwn meta that turned a
    broken settings file into a live gate. Not knowing the mode, or the module,
    has to mean not gating.
    """
    try:
        from modules._common import read_meta
        from modules.settings_io import effective_judge_mode, get_judge_mode

        # `get_judge_mode()` directly, NOT `_judge_mode()`. That wrapper
        # swallows a settings failure and answers "enforce", so by the time the
        # value arrives here a broken read is indistinguishable from an
        # operator who typed enforce — and combined with a perfectly readable
        # pwn meta it produced a real gate out of a filesystem error. Reading
        # inside this try is what lets the failure stay a failure.
        mode = get_judge_mode()
        if mode != "enforce":
            return mode
        return effective_judge_mode(mode, (read_meta(job_id) or {}).get("module") or "")
    except Exception:
        # Anything at all — settings, meta, import — resolves here, and it
        # resolves to shadow. Note this deliberately differs from
        # `_judge_mode()`'s legacy fallback: on a failure we do not know the
        # operator's mode OR the job's module, and neither unknown may widen
        # the gate. Shadow is the only answer that gates nothing while still
        # recording.
        return "shadow"


def _decode_live_sandbox_record(
    raw: bytes,
) -> tuple[bytes | None, bytes, bytes]:
    """Return ``(timestamp, payload, prefix)`` for one Docker log record.

    The fallback accepts an unprefixed record defensively. Normal Docker reads
    always match because the caller requests ``timestamps=True``; retaining a
    fallback keeps an unexpected daemon response visible instead of dropping
    solver output.
    """
    match = _DOCKER_LOG_TIMESTAMP_RE.match(raw)
    if match is None:
        return None, raw, b""
    return (
        match.group("timestamp"),
        match.group("payload"),
        raw[:match.start("payload")],
    )


def _collect_live_sandbox_delta(
    stream: str,
    snapshot: bytes,
    state: dict,
    *,
    flush: bool = False,
) -> list[tuple[bytes | None, str, bytes]]:
    """Collect unseen timestamped records from one Docker log stream.

    ``container.logs()`` returns the whole stream on every poll. ``state``
    therefore carries a byte cursor and an unterminated-line buffer per stream,
    making repeated snapshots idempotent. The caller merges the returned
    ``(timestamp, stream, payload)`` events before exposing them to ``run.log``.
    """
    offset_key = f"{stream}_offset"
    pending_key = f"{stream}_pending"
    previous = int(state.get(offset_key, 0))

    # A Docker log rotation can make the visible snapshot shorter. Do not
    # replay its surviving tail (which would duplicate raw-log lines); adopt the
    # new end as the cursor and resume with subsequent bytes.
    if len(snapshot) < previous:
        state[offset_key] = len(snapshot)
        state[pending_key] = b""
        return []

    delta = snapshot[previous:]
    state[offset_key] = len(snapshot)
    pending = state.get(pending_key, b"") + delta
    events: list[tuple[bytes | None, str, bytes]] = []

    complete = pending.split(b"\n")
    pending = complete.pop()
    for raw in complete:
        timestamp, payload, _prefix = _decode_live_sandbox_record(raw)
        if payload.endswith(b"\r"):
            payload = payload[:-1]
        events.append((timestamp, stream, payload))

    # A script can flush without a newline. Preserve prompt visibility without
    # letting one binary/no-newline stream grow this buffer indefinitely.
    while pending:
        timestamp, payload, prefix = _decode_live_sandbox_record(pending)
        if len(payload) < _LIVE_LOG_PARTIAL_CHUNK_BYTES:
            break
        events.append((timestamp, stream, payload[:_LIVE_LOG_PARTIAL_CHUNK_BYTES]))
        # Keep the timestamp on the retained fragment so its eventual event
        # remains sortable and the prefix never leaks into user-visible text.
        pending = prefix + payload[_LIVE_LOG_PARTIAL_CHUNK_BYTES:]

    if flush and pending:
        timestamp, payload, _prefix = _decode_live_sandbox_record(pending)
        events.append((timestamp, stream, payload))
        pending = b""
    state[pending_key] = pending
    return events


def _order_live_sandbox_events(
    events: list[tuple[bytes | None, str, bytes]],
) -> list[tuple[bytes | None, str, bytes]]:
    """Merge stdout/stderr events by Docker's nanosecond timestamp.

    A malformed/unprefixed response has no trustworthy cross-stream ordering;
    in that defensive fallback, retain fetch order rather than inventing one.
    Python's stable sort preserves fetch order for the vanishingly unlikely
    case of equal daemon timestamps.
    """
    if any(timestamp is None for timestamp, _stream, _payload in events):
        return events
    return sorted(events, key=lambda event: event[0])


def _forward_live_sandbox_logs(
    container,
    state: dict,
    log_fn,
    *,
    flush: bool = False,
) -> tuple[bool, int]:
    """Fetch and forward new stdout/stderr bytes from a runner container.

    Returns ``(all_fetches_ok, combined_size)`` so the existing stall detector
    can use the same two snapshots instead of issuing a third Docker log read.
    A failed fetch never advances that stream's cursor.
    """
    all_ok = True
    combined_size = 0
    snapshots: dict[str, bytes] = {}
    for stream in ("stdout", "stderr"):
        try:
            snapshot = container.logs(
                stdout=(stream == "stdout"),
                stderr=(stream == "stderr"),
                timestamps=True,
            )
            if isinstance(snapshot, str):
                snapshot = snapshot.encode("utf-8", errors="replace")
        except Exception:
            all_ok = False
            continue
        combined_size += len(snapshot)
        snapshots[stream] = snapshot

    # If one stream failed, advancing or emitting the other would make it
    # impossible to place the missing stream's older records correctly on the
    # next successful poll. Retry both from their existing cursors instead.
    if not all_ok:
        return False, combined_size

    events: list[tuple[bytes | None, str, bytes]] = []
    for stream in ("stdout", "stderr"):
        events.extend(_collect_live_sandbox_delta(
            stream, snapshots[stream], state, flush=flush,
        ))
    for _timestamp, stream, payload in _order_live_sandbox_events(events):
        log_fn(f"[runner:{stream}] {payload.decode('utf-8', errors='replace')}")
    return all_ok, combined_size


def _wait_with_supervise(
    container,
    *,
    timeout_s: int,
    job_dir_path: Path,
    script_rel: str,
    log_fn,
    enable_supervise: bool,
) -> dict:
    """Block until the container exits, the timeout fires, or the
    supervise judge votes kill.

    Returns a dict matching docker-py's `container.wait()` plus optional
    fields:
      StatusCode             — container exit code, or -1 if unknown
      timeout (bool)         — True if timeout_s elapsed before exit
      container_disappeared  — True if Docker reports a 404/NotFound
      killed_by_supervise    — True if the supervise judge killed it
      supervise              — dict from supervise_run_once when called
    """
    start = time.time()
    last_size = 0
    last_change = start
    # None until the first supervise call. Periodic re-ask (long runs only)
    # keys off the elapsed time since this timestamp; short runs stay one-shot.
    last_supervise: float | None = None
    periodic = timeout_s > SUPERVISE_PERIODIC_THRESHOLD_S
    supervise_result: dict | None = None
    live_log_state: dict = {}

    while True:
        # Has the container exited?
        try:
            container.reload()
            status = container.status
        except _DockerNotFound:
            status = "disappeared"
        except Exception:
            status = "unknown"

        # Forward output before examining terminal state. A short-lived solver
        # can print and exit between two polls; fetching only while it is alive
        # loses exactly that final output from the live raw log.
        log_fetch_ok, current_size = _forward_live_sandbox_logs(
            container,
            live_log_state,
            log_fn,
            flush=(status in {"exited", "disappeared"}),
        )

        if status == "disappeared":
            log_fn("[runner] container disappeared (Docker 404) — stopping wait")
            return {
                "StatusCode": -1,
                "container_disappeared": True,
                "supervise": supervise_result,
            }

        if status == "exited":
            try:
                rc = container.wait(timeout=2)
            except Exception:
                rc = {"StatusCode": -1}
            if supervise_result is not None:
                rc["supervise"] = supervise_result
            return rc

        # Hard timeout — kill and return.
        elapsed = time.time() - start
        if elapsed > timeout_s:
            log_fn(f"[runner] timeout after {int(elapsed)}s — killing container")
            try:
                container.kill()
            except Exception:
                pass
            _forward_live_sandbox_logs(
                container, live_log_state, log_fn, flush=True,
            )
            return {
                "StatusCode": -1,
                "timeout": True,
                "supervise": supervise_result,
            }

        # Stall detection on combined log byte-length. If the docker
        # socket hiccups and `container.logs()` raises, we have no
        # signal — treat it as "we don't know" by refreshing
        # `last_change`. Otherwise a string of fetch failures would
        # falsely register as a 60s stall and burn one supervise judge
        # call against an empty buffer.
        if not log_fetch_ok:
            last_change = time.time()
        elif current_size != last_size:
            last_size = current_size
            last_change = time.time()
        elif (
            enable_supervise
            and (time.time() - last_change) > SUPERVISE_STALL_S
            and (
                last_supervise is None  # first ask (always) — one-shot for short runs
                or (periodic
                    and (time.time() - last_supervise) > SUPERVISE_REASK_INTERVAL_S)
            )
        ):
            stall_real = int(time.time() - last_change)
            _reask = last_supervise is not None
            log_fn(
                f"[runner] no output for {stall_real}s while alive — "
                f"{'RE-asking' if _reask else 'asking'} judge whether to kill"
            )
            try:
                out_tail = container.logs(stdout=True, stderr=False).decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                out_tail = ""
            try:
                err_tail = container.logs(stdout=False, stderr=True).decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                err_tail = ""
            try:
                supervise_result = _judge.supervise_run_once(
                    job_dir_path,
                    script_rel,
                    stall_real,
                    out_tail[-4096:],
                    err_tail[-4096:],
                    log_fn,
                )
            except Exception as e:
                log_fn(f"[judge] supervise failed: {e}")
                supervise_result = {"action": "continue", "reason": str(e)}
            last_supervise = time.time()
            if supervise_result.get("action") == "kill":
                try:
                    container.kill()
                except Exception:
                    pass
                _forward_live_sandbox_logs(
                    container, live_log_state, log_fn, flush=True,
                )
                return {
                    "StatusCode": -1,
                    "killed_by_supervise": True,
                    "supervise": supervise_result,
                }

        time.sleep(_POLL_INTERVAL_S)


def run_in_sandbox(
    job_id: str,
    script_rel: str,
    args: list[str] | None = None,
    image: str = RUNNER_IMAGE,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    # None -> match the parent slot's LIVE cap (see _parent_slot_mem), falling
    # back to DEFAULT_MEM when the cgroup is unreadable or uncapped. Callers
    # that pass a value keep it: forensic, misc and the decompiler each size
    # their runner deliberately and must not be dragged along by the slot.
    mem_limit: str | int | None = None,
    # None -> match the parent slot's LIVE CPU cap (see _parent_slot_cpus),
    # falling back to DEFAULT_CPUS when the cgroup is unreadable or uncapped.
    # Same contract as mem_limit: an explicit value from a caller wins.
    nano_cpus: int | None = None,
    network: str = "bridge",
    use_sage: bool = False,
    *,
    log_fn=None,
    enable_supervise: bool = False,
) -> dict:
    """Execute the agent's script inside the runner container against the
    SAME absolute paths the worker used.

    Layout (load-bearing for patched-libc binaries):

      host  ${HOST_DATA_DIR}/jobs/<id>            ←──┐
                                                     │ bind-mount,
                                                     │ same path
      runner /data/jobs/<id>                       ←──┘ both sides

    cwd inside the runner is `/data/jobs/<id>/work` — same dir the agent
    was working in. That makes `./bin/<name>` resolve to the patched copy
    in the work tree, and — critically — makes the binary's PT_INTERP
    (baked by chal-libc-fix as `/data/jobs/<id>/work/.chal-libs/ld-…`)
    resolve from the runner's filesystem too. Without matching paths the
    kernel can't find the interpreter and spawning the patched binary
    fails with the classic misleading `No such file or directory`.

    When `enable_supervise` is True the wait loop calls
    `modules._judge.supervise_run_once` after SUPERVISE_STALL_S of
    silence. Pre/post judge calls happen in attempt_sandbox_run, not
    here, so this flag is ONLY about the during-run gate — it used to be
    named `enable_judge`, which read as "the judge is on" and let the
    pre/post decision switch on a container kill by accident.

    Returns: {exit_code, stdout, stderr, stdout_truncated_to,
              timeout?, container_disappeared?, killed_by_supervise?, supervise?}.
    """
    args = args or []
    if mem_limit is None:
        _parent = _parent_slot_mem()
        mem_limit = _parent if _parent else DEFAULT_MEM
        if log_fn and _parent:
            try:
                log_fn("[runner] mem_limit %d B (matching this worker slot)"
                       % _parent)
            except Exception:
                pass
    if nano_cpus is None:
        _pcpu = _parent_slot_cpus()
        nano_cpus = _pcpu if _pcpu else DEFAULT_CPUS * 1_000_000_000
        if log_fn:
            try:
                log_fn("[runner] cpus %.2g (%s)"
                       % (nano_cpus / 1e9,
                          "matching this worker slot" if _pcpu
                          else "slot cgroup uncapped/unreadable, using default"))
            except Exception:
                pass
    # Mount the host's jobroot at the SAME absolute path the worker uses,
    # then chdir into the work-tree. Anywhere PT_INTERP / DT_RPATH was
    # baked with `/data/jobs/<id>/work/…` now resolves identically in
    # the runner.
    mount_root = f"/data/jobs/{job_id}"
    workdir = f"{mount_root}/work"
    run_user = None
    if use_sage:
        image = SAGE_IMAGE
        cmd = ["sage", f"{workdir}/{script_rel}", *args]
        # sagemath/sagemath ships `USER sage` (uid 1001), but the work tree is
        # root:root 0755 (created by the uid-0 worker). Before ANY solver line
        # runs, `sage <script>.sage` preparses it and writes solver.sage.py via
        # tempfile.mkstemp(dir=os.path.dirname(realpath(script))) = the work
        # dir itself (NOT TMPDIR, which sage ignores here) → EACCES as uid 1001,
        # solver never executes, stdout 0 bytes (job 4cc7f5dad29b, the first
        # ever production sage run, died exactly here). The python3 runner image
        # has NO USER directive and ALREADY runs as root, so running sage as
        # uid 0 MATCHES that existing posture (does not widen it) and is the one
        # fix agnostic to WHERE preparse writes (top-level work/, a load()ed
        # sub-.sage's dir, a future layout). Verified end-to-end: root-owned
        # 0755 work dir + this + the real solver.sage → preparse succeeds and
        # E.order() runs. Only the sage branch sets run_user, so the python3
        # containers.run() kwargs stay byte-identical (see Edit 3).
        run_user = "0:0"
    else:
        cmd = ["python3", f"{workdir}/{script_rel}", *args]

    # Forward CALLBACK_URL + COLLECTOR_BASE so exploits have a stable
    # OOB channel. CALLBACK_URL is the operator-supplied tunnel
    # (cloudflared quick-tunnel via ./tunnel.sh, or a VPS); the agent
    # should append `/api/collector/<JOB_ID>` to it so the built-in
    # collector endpoint receives the callback,
    # auto-extracts any flag in the URL, and updates the job status.
    env: dict[str, str] = {
        "PYTHONUNBUFFERED": "1",
        "JOB_ID": job_id,
    }
    cb = os.environ.get("CALLBACK_URL", "").strip()
    if cb:
        env["CALLBACK_URL"] = cb
        env["COLLECTOR_URL"] = f"{cb.rstrip('/')}/api/collector/{job_id}"

    # Per-job scratch dir inside the sandbox. Lives under the work tree
    # at /data/jobs/<id>/work/tmp/ — same path the agent sees in the
    # worker, so any tempfile path the agent generated during the run
    # remains valid when the solver replays it in the sandbox.
    _sandbox_tmp = f"{workdir}/tmp"
    env["TMPDIR"] = _sandbox_tmp
    env["TMP"]    = _sandbox_tmp
    env["TEMP"]   = _sandbox_tmp
    if use_sage:
        # `--user 0:0` (Edit 1/3) overrides the image's `USER sage`, so HOME
        # would otherwise be unset for root. Pin it to the image's prebuilt,
        # populated DOT_SAGE parent (/home/sage/.sage) so Sage doesn't re-init
        # its startup cache. Root can read/write that uid-1001-owned dir fine.
        # Not load-bearing — the observed worst case without this is a slower
        # first run, not a failure — but it keeps the sage run warm. Guarded by
        # use_sage so the python3 env stays byte-identical.
        env["HOME"] = "/home/sage"

    # Multi-target jobs: argv[1] carries the PRIMARY target (back-compat —
    # every shipped exploit reads one host:port from argv). Expose the FULL
    # operator list via the TARGETS env var (primary first, one per line) so a
    # new-style exploit can fail over across mirrored instances or address
    # several services in a chain. Primary-first + dedup so a mid-run target
    # refresh (args[0] swapped from a now-live meta value) still leads. Only
    # set when there are ≥2 distinct targets — single-target runs are unchanged.
    try:
        from modules._common import read_meta as _read_meta_t
        _meta_targets = (_read_meta_t(job_id) or {}).get("target_urls") or []
    except Exception:
        _meta_targets = []
    _all_targets: list[str] = []
    for _t in ([args[0]] if args else []) + list(_meta_targets):
        if _t and _t not in _all_targets:
            _all_targets.append(_t)
    if len(_all_targets) >= 2:
        env["TARGETS"] = "\n".join(_all_targets)
    from modules.job_secrets import read_job_secrets

    env.update(read_job_secrets(job_id))

    client = docker.from_env()
    container = client.containers.run(
        image=image,
        command=cmd,
        # Bind-mount the host's jobroot at the WORKER's absolute path so
        # /data/jobs/<id>/work/.chal-libs/… (baked into patched ELFs) is
        # the same path on both sides.
        volumes={_host_path(job_id): {"bind": mount_root, "mode": "rw"}},
        working_dir=workdir,
        mem_limit=mem_limit,
        # memswap == mem, the same way the slot sets it (worker_mem.apply_cap
        # and compose both do). With mem_limit alone docker grants swap up to
        # 2x the cap, and slow swap thrash is the state that wedged this VM
        # twice -- an equal value buys a fast clean kill instead. Inheriting
        # the parent's SIZE while dropping its SWAP POLICY was a half-inherit:
        # observed live 2026-08-25, runners on a 4 GiB rev slot came up with
        # `mem=4096MiB swap허용=8192MiB` while the parent had 4096/4096.
        memswap_limit=mem_limit,
        nano_cpus=nano_cpus,
        network_mode=network,
        environment=env,
        stdout=True,
        stderr=True,
        detach=True,
        # Dev/run parity: a rev solver validated in the worker under gdb with
        # ASLR disabled (personality(ADDR_NO_RANDOMIZE)) would SILENTLY diverge
        # at auto-run if the runner kept the stock seccomp profile — ASLR back
        # on → addresses move → a fixed-address gdb/setarch oracle fails or
        # returns the wrong answer. We grant EXACTLY that one personality()
        # value via the targeted _SECCOMP_GDB_ASLR profile (Docker default +
        # ADDR_NO_RANDOMIZE), NOT seccomp=unconfined — the latter re-exposed
        # unprivileged user namespaces to agent-authored code on the
        # docker.sock-less isolation container (see the profile comment above).
        # Fall back to the daemon default (None) if the profile file is missing.
        security_opt=(
            ["seccomp=" + _SECCOMP_GDB_ASLR] if _SECCOMP_GDB_ASLR else None
        ),
        labels={"hextech_ctf_tool_job_id": job_id, "hextech_ctf_tool_role": "runner"},
        # Only the sage path sets a user (uid 0, so preparse can write the
        # root:root 0755 work dir). When run_user is None (python3 path) no
        # `user` kwarg is passed → the call is byte-identical to before, zero
        # blast radius. This is the single chokepoint: run_in_sandbox is the
        # only caller of containers.run.
        **({"user": run_user} if run_user else {}),
    )
    exit_code = -1
    out = b""
    err = b""
    timeout_hit = False
    container_disappeared = False
    killed_by_supervise = False
    supervise_payload: dict | None = None
    job_dir_path = Path(f"/data/jobs/{job_id}")
    _log = log_fn or (lambda _msg: None)

    try:
        result = _wait_with_supervise(
            container,
            timeout_s=timeout_s,
            job_dir_path=job_dir_path,
            script_rel=script_rel,
            log_fn=_log,
            enable_supervise=enable_supervise,
        )
        exit_code = int(result.get("StatusCode", -1))
        timeout_hit = bool(result.get("timeout", False))
        container_disappeared = bool(result.get("container_disappeared", False))
        killed_by_supervise = bool(result.get("killed_by_supervise", False))
        supervise_payload = result.get("supervise")
        # A vanished container has no logs endpoint to query.  The wait loop
        # already attempted its final live-log flush; asking again here would
        # merely re-raise the same NotFound and erase the useful return marker.
        if not container_disappeared:
            out = container.logs(stdout=True, stderr=False)
            err = container.logs(stdout=False, stderr=True)
    finally:
        try:
            container.remove(force=True, v=True)
        except Exception:
            pass

    out_s = out.decode("utf-8", errors="replace")
    err_s = err.decode("utf-8", errors="replace")
    MAX = 64 * 1024
    payload: dict = {
        "exit_code": exit_code,
        "stdout": out_s[-MAX:],
        "stderr": err_s[-MAX:],
        "truncated_to": MAX,
        "image": image,
    }
    if timeout_hit:
        payload["timeout"] = True
    if container_disappeared:
        payload["container_disappeared"] = True
    if killed_by_supervise:
        payload["killed_by_supervise"] = True
    if supervise_payload:
        payload["supervise"] = supervise_payload
    return payload


def _ping_target(target: str, *, timeout: float = 3.0) -> tuple[bool, str]:
    """Pre-run TCP reachability probe for `host:port` targets.

    Returns (ok, detail). `ok=True` means a TCP connect succeeded inside
    `timeout` seconds. `detail` is a short human-readable note that goes
    into the log on failure (e.g. "ConnectionRefusedError",
    "timed out", "Name or service not known") — empty on success.

    A successful TCP connect doesn't guarantee the wrapper protocol
    speaks the language we expect, but it cleanly distinguishes the
    "remote instance expired / never up" failure mode (job c410, 753cb832)
    from a genuine script bug. The cost is ≤ `timeout` seconds added
    to prejudge; on remote-only chals this also pre-warms DNS.
    """
    if not target or ":" not in target:
        return True, ""
    host, _, port_s = target.rpartition(":")
    try:
        port = int(port_s)
    except ValueError:
        return True, ""
    if not host or port <= 0 or port > 65535:
        return True, ""
    try:
        # Creating the socket was outside the guard, so on a host that denies
        # it outright (a hardened container, a restricted CI box) a PermissionError
        # escaped a probe whose entire contract is warn-not-fail and took
        # attempt_sandbox_run down with it.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
    except OSError as e:
        return True, f"(reachability probe unavailable: {type(e).__name__}: {e})"
    try:
        s.connect((host, port))
    except socket.gaierror as e:
        return False, f"DNS: {e}"
    except (socket.timeout, TimeoutError):
        return False, f"connect timed out after {timeout}s"
    except OSError as e:
        return False, f"{type(e).__name__}: {e}"
    finally:
        try:
            s.close()
        except OSError:
            pass
    return True, ""


def _remote_target_gate_probe(
    target: str,
    *,
    connect_timeout: float = 3.0,
    banner_timeout: float = 0.25,
) -> tuple[bool, str, str]:
    """Return ``(blocked, kind, detail)`` for one registered ``host:port``.

    The blocking surface is intentionally smaller than a general health
    check: a definite DNS miss, a failed TCP connection, or an observed
    production failure signature.  A successful connection with no banner,
    an unknown banner, and banner-read errors all pass.  That bias is
    deliberate because blocking a healthy job is worse than preserving the
    old behaviour for a target this probe cannot classify.
    """
    host, sep, port_s = str(target or "").strip().rpartition(":")
    if not sep or not host:
        return True, "invalid_target", "expected host:port"
    try:
        port = int(port_s)
    except ValueError:
        return True, "invalid_target", f"invalid port {port_s!r}"
    if port <= 0 or port > 65535:
        return True, "invalid_target", f"port out of range: {port}"

    try:
        sock = socket.create_connection((host, port), timeout=connect_timeout)
    except socket.gaierror as exc:
        # EAI_NONAME is the stable NXDOMAIN/invalid-name case.  Temporary
        # resolver failures (EAI_AGAIN) are probe failures, not evidence that
        # the registered instance is dead, so they fail open below.
        if exc.errno == getattr(socket, "EAI_NONAME", -2):
            return True, "dns_nxdomain", f"DNS: {exc}"
        return False, "probe_error", f"temporary DNS failure: {exc}"
    except (socket.timeout, TimeoutError) as exc:
        return True, "tcp_failure", f"connect timed out: {exc}"
    except OSError as exc:
        network_failures = {
            errno.ECONNREFUSED,
            errno.ECONNRESET,
            errno.ETIMEDOUT,
            errno.EHOSTUNREACH,
            errno.ENETUNREACH,
        }
        if exc.errno in network_failures:
            return True, "tcp_failure", f"{type(exc).__name__}: {exc}"
        return False, "probe_error", f"{type(exc).__name__}: {exc}"

    try:
        sock.settimeout(banner_timeout)
        try:
            banner = sock.recv(4096)
        except (socket.timeout, TimeoutError, OSError):
            # A silent service is the required healthy positive control; a
            # banner read is classification evidence only when bytes arrive.
            return False, "reachable", "TCP connected; no classified banner"
    finally:
        try:
            sock.close()
        except OSError:
            pass

    lowered = banner.lower()
    for signature in _BROKEN_TARGET_BANNER_SIGNATURES:
        if signature in lowered:
            return True, "known_broken_banner", signature.decode("ascii")
    return False, "reachable", "TCP connected; banner not classified"


def remote_target_start_gate(
    job_id: str,
    module: str,
    target: Optional[str],
    log_fn,
    *,
    manual: bool = False,
) -> dict | None:
    """Gate remote pwn/rev jobs before any agent or pre-recon starts.

    ``None`` means proceed.  A dict is an agent-summary-shaped terminal result
    that the module orchestrator records as ``target_unusable`` without
    launching an agent.  Probe/configuration failures fail open.  Operator
    manual runs never apply the gate; when it is enabled they leave an explicit
    bypass warning and continue to the historical warn-only sandbox preflight.
    """
    try:
        enabled = bool(get_setting("enable_remote_target_gate"))
    except Exception as exc:
        log_fn(
            f"[target-gate] probe unavailable (settings: "
            f"{type(exc).__name__}: {exc}) — proceeding"
        )
        return None
    if not enabled:
        return None

    normalized_module = str(module or "").strip().lower()
    if normalized_module not in REMOTE_TARGET_GATE_MODULES:
        return None
    normalized_target = str(target or "").strip()
    if not normalized_target:
        return None
    if manual:
        log_fn(
            f"[target-gate] WARNING: operator manual-run bypass for "
            f"{normalized_target}; automatic start gate not applied"
        )
        return None

    try:
        blocked, kind, detail = _remote_target_gate_probe(normalized_target)
    except Exception as exc:
        log_fn(
            f"[target-gate] probe raised {type(exc).__name__}: {exc} "
            f"— proceeding"
        )
        return None
    if not blocked:
        if kind == "probe_error":
            log_fn(f"[target-gate] probe unavailable ({detail}) — proceeding")
        return None

    message = (
        f"remote target {normalized_target!r} is unusable at job start "
        f"({kind}: {detail}); operator must register a live target and retry"
    )
    log_fn(f"[target-gate] BLOCKED before agent start: {message}")
    return {
        "messages": 0,
        "tool_calls": 0,
        "agent_error": message,
        "agent_error_kind": "target_unusable",
        "target_gate": {
            "status": "blocked",
            "module": normalized_module,
            "target": normalized_target,
            "reason": kind,
            "detail": detail,
        },
        "sandbox": None,
    }


def _refresh_target_from_meta(
    job_id: str, prev_target: Optional[str], log_fn,
) -> tuple[Optional[str], bool]:
    """Re-read meta.json and return its current `target_url`.

    Used after `_ping_target` fails: dreamhack instances expire fast,
    and the operator may have already pushed a new `host:port` into
    the job metadata between the agent's analysis and the orchestrator
    sandbox run. Returns (new_target, changed). `changed=True` means
    the value differs from `prev_target` and the caller should re-ping
    with the refreshed value before deciding to STOP.
    """
    try:
        # Local import to avoid a top-level cycle (_common imports
        # nothing from _runner, but it does import the SDK which is
        # heavier than this helper needs at module-load time).
        from modules._common import read_meta
    except Exception as e:  # pragma: no cover — defensive
        log_fn(f"[runner] meta reload failed (import): {e}")
        return prev_target, False
    try:
        meta = read_meta(job_id) or {}
    except Exception as e:
        log_fn(f"[runner] meta reload failed (read): {e}")
        return prev_target, False
    new_target = meta.get("target_url") or None
    if new_target == prev_target:
        return new_target, False
    log_fn(
        f"[runner] meta.json target_url refreshed: "
        f"{prev_target!r} -> {new_target!r}"
    )
    return new_target, True


def attempt_sandbox_run(
    job_id: str,
    script_filename: str,
    target: Optional[str],
    log_fn,
    use_sage: bool = False,
    prior_hints: list[str] | None = None,
) -> dict | None:
    """Helper for orchestrators that always copy the produced script to the
    job root. Runs <jobdir>/<script_filename> with target as argv if given.

    When this job's effective mode gates (`_judge_mode_for_job`), wraps
    the run with two judge stages:

      pre  — abort BEFORE the container starts if the judge flags a
             severity=high issue. Returned dict has keys
             {error, prejudge, judge_aborted=True} so the orchestrator
             can record a structured failure.
      post — verdict + retry hint merged into the returned dict under
             the `judge` key.

    The stall watchdog inside run_in_sandbox is deliberately NOT one of
    them — `enable_supervise=False` is passed explicitly below.
    """
    work_dir = Path(f"/data/jobs/{job_id}")
    # Script lives in the agent's work tree (jobroot/work/<script>) so
    # ./bin/<name> resolves to the PATCHED copy in work/bin/. If a
    # caller carried the script up to jobroot only (legacy layout),
    # fall back to that — but the patched-libc path won't be valid
    # for those, since chal-libc-fix only patches the work-tree copy.
    work_tree = work_dir / "work"
    if (work_tree / script_filename).exists():
        pass
    elif (work_dir / script_filename).exists():
        log_fn(
            f"[runner] {script_filename} only found at jobroot, not "
            "in work/ — patched libc binaries in ./bin/ will not be "
            "reachable; copying into work/ for the sandbox run"
        )
        try:
            work_tree.mkdir(parents=True, exist_ok=True)
            (work_tree / script_filename).write_bytes(
                (work_dir / script_filename).read_bytes()
            )
        except OSError as e:
            log_fn(f"[runner] copy-into-work failed: {e}")
            return None
    else:
        log_fn(f"[runner] {script_filename} missing, cannot auto-run")
        return None

    # Per-job scratch dir for sandboxed exploit. Lives inside the work
    # tree at /data/jobs/<id>/work/tmp/ so the runner's TMPDIR points at
    # a path that's valid in both worker and runner. Cleanup is implicit
    # via job DELETE rmtree on /data/jobs/<id>/.
    (work_tree / "tmp").mkdir(parents=True, exist_ok=True)

    # ONE read, both answers derived from it. Two reads let a settings change
    # land between them, and the pair that comes out never existed as a
    # configuration: enforce's gating with shadow's recording, same attempt.
    # Scoped, not global: `enforce` gates only the modules stage 8 could
    # actually measure. Everything downstream — the gate, the cycle id, both
    # shadow recording sites — reads THIS value, never the raw setting. A
    # comparison left against the global would give an out-of-scope job
    # `cycle_id=""`, which `_cycle_state` folds into the legacy job-wide
    # bucket, and attempt 1's refusal would silence attempt 2's healthy
    # postjudge all over again (turn 0073, D21).
    judge_mode = _judge_mode_for_job(job_id)
    enable_judge = _judge_gates(judge_mode)
    # One id per ATTEMPT. prejudge -> supervise -> postjudge share a judge
    # session within a cycle, so "this stage's prerequisite" is a question
    # about the cycle, not about the job. Keyed job-wide, one attempt's
    # unevaluable prejudge silenced the NEXT attempt's healthy postjudge.
    cycle_id = uuid.uuid4().hex[:12] if judge_mode == "shadow" else ""

    # ---------- Stage 0: target reachability probe ----------
    # If the chal is remote-targeted, do a single TCP connect ping
    # BEFORE the runner spawns. dreamhack-style chal instances expire
    # while the agent is still doing static analysis (jobs 753cb832 +
    # c410 spent 1h+ analyzing and the instance was gone by the time
    # the sandbox tried to connect). On ping failure we reload meta.json
    # and try the refreshed value once — the operator may have already
    # registered a new `host:port` for this job. If both pings fail,
    # we let the run proceed but stash a note into the prejudge log
    # and postjudge `extra_context` so the verdict can cite "remote
    # was down at run start" instead of mis-blaming the script.
    target_note = ""
    # Proactively prefer live meta.json target_url over the argv-captured
    # value. Retry route reads meta target_url at /retry time and pins it
    # into the queued job's argv (api/routes/retry.py:473). If the
    # operator updates the target between /retry and the sandbox-run
    # (e.g. dreamhack instance rotated), the argv has the stale value
    # but meta has been refreshed externally. Reading meta first means
    # we don't burn an unconditional ping on the known-stale address.
    if target and ":" in target:
        try:
            live_target, changed_at_start = _refresh_target_from_meta(
                job_id, target, log_fn,
            )
        except Exception as e:
            log_fn(f"[runner] proactive meta target reload failed: {e}")
            live_target, changed_at_start = target, False
        if changed_at_start and live_target and ":" in live_target:
            target = live_target
    if target and ":" in target:
        ok, detail = _ping_target(target)
        if not ok:
            log_fn(
                f"[runner] target {target} unreachable before run "
                f"({detail}); reloading meta.json"
            )
            new_target, changed = _refresh_target_from_meta(
                job_id, target, log_fn,
            )
            if changed and new_target and ":" in new_target:
                ok2, detail2 = _ping_target(new_target)
                if ok2:
                    log_fn(
                        f"[runner] refreshed target {new_target} reachable "
                        f"— using it for this run"
                    )
                    target = new_target
                    target_note = (
                        f"NOTE: meta.json target_url was refreshed mid-run "
                        f"from a now-unreachable value to {new_target!r}. "
                        f"The script is being invoked with the refreshed "
                        f"value."
                    )
                else:
                    log_fn(
                        f"[runner] refreshed target {new_target} also "
                        f"unreachable ({detail2}) — proceeding with "
                        f"{new_target} so postjudge sees a real exit_code"
                    )
                    target = new_target
                    target_note = (
                        f"NOTE: both the original ({detail}) and the "
                        f"meta-refreshed target ({new_target!r}, {detail2}) "
                        f"failed a TCP connect ping before the run. If "
                        f"the script reports network_error / EOF, the "
                        f"remote instance is likely expired — operator "
                        f"should re-register a live `host:port` in "
                        f"meta.json and /retry, not push main onto a new "
                        f"vuln class."
                    )
            else:
                log_fn(
                    f"[runner] meta.json target unchanged ({target}) and "
                    f"still unreachable — running anyway so the script's "
                    f"own EOF/timeout handler surfaces to postjudge"
                )
                target_note = (
                    f"NOTE: target {target!r} failed TCP connect ping "
                    f"({detail}) before the run started and meta.json "
                    f"has no fresher value. If postjudge sees "
                    f"network_error / EOF, the remote is genuinely down "
                    f"— operator must refresh the instance, no script "
                    f"fix will help."
                )

    # The judge stages share one session via session_id resume, and it is
    # PROVIDER-LOCAL: after a failover the next stage resumes the other
    # backend's sid, not a Claude one.
    # `prejudge_script` writes a sid into _judge._session_ids; postjudge
    # clears it on its happy path. If anything between the two raises
    # before postjudge fires, the sid would otherwise leak into the
    # module-level dict for the worker process's lifetime. Wrap in
    # try/finally so cleanup is unconditional.
    try:
        # ---------- Stage 1: prejudge (ship gate) ----------
        # Decision power was previously advisory ("main owns the gate"),
        # but the gate stack added between 2026-05-20 and 2026-05-23
        # (Phase 9 self-defeat regex, Phase 8 chain.json critical,
        # Tier 1.7 flag_likelihood<0.2) all converge on severity=high
        # for cases the LLM judge itself rates as guaranteed-fail. On
        # job 7f903a8e152b prejudge correctly emitted flag_likelihood=
        # 0.02 + severity=high but the "running anyway" branch let the
        # sandbox run, wasting one cycle on an exploit the LLM said
        # cannot capture the flag. Severity=high now blocks ship; main
        # already has its own internal JUDGE GATE turn before this
        # point, and postjudge still backstops anything that slips
        # through with severity≤med.
        prejudge: dict | None = None
        if judge_mode == "shadow":
            # INPUTS ONLY. Calling the judge here would lengthen every run and
            # leave a shadow job incomparable with the control it exists to be
            # compared against; the verdicts are produced after the run.
            from modules import judge_shadow

            judge_shadow.record_input(
                job_id, "prejudge",
                {
                    "cycle_id": cycle_id,
                    "script_rel": script_filename, "target": target,
                    # The retry loop rewrites the script between attempts and
                    # report.md / chain.json keep moving too — and prejudge
                    # reads all three. The path alone does not identify what
                    # the gate reviewed.
                    **judge_shadow.prejudge_fingerprint(work_dir, script_filename),
                },
            )
        if enable_judge:
            try:
                prejudge = _judge.prejudge_script(
                    work_dir, script_filename, target, log_fn,
                )
            except Exception as e:
                log_fn(f"[judge] prejudge failed: {e}")
                prejudge = {
                    "ok": True,
                    "severity": "low",
                    "issues": [],
                    "raw": "",
                    "error": str(e),
                }
            emit_event(
                job_id, "prejudge", "result",
                ok=bool(prejudge.get("ok")) if prejudge else None,
                severity=(prejudge or {}).get("severity"),
                target_liveness=(prejudge or {}).get("target_liveness"),
                issues=len((prejudge or {}).get("issues") or []),
            )
            if _judge.prejudge_blocks_ship(prejudge):
                log_fn(
                    f"[runner] prejudge BLOCKED ship: severity=high, "
                    f"{len(prejudge.get('issues') or [])} issues — "
                    f"sandbox NOT spawned (operator should /retry "
                    f"onto a different chain). Top issues: "
                    f"{(prejudge.get('issues') or [])[:2]}"
                )
                emit_event(
                    job_id, "prejudge", "blocked",
                    severity="high",
                    issues=len(prejudge.get("issues") or []),
                )
                return {
                    "error": "prejudge_blocked",
                    "prejudge": prejudge,
                    "judge_aborted": True,
                    # Calling attempt_sandbox_run is not the same as spawning
                    # its container.  The outer loop needs this structured bit
                    # to distinguish two prejudge blocks / zero real runs from
                    # a block that followed useful execution evidence.
                    "sandbox_started": False,
                    "judge_mode": judge_mode,
                }

        # ---------- Stage 2: actual run ----------
        args = [target] if target else []
        # Sandbox hard-timeout. Base 300s (capped-1800s override) for every
        # path EXCEPT crypto `.sage`, which gets a 6000s ceiling — a Gröbner /
        # resultant / small_roots run is legitimately many minutes and silent
        # (job 4e1be4f76c96 was cut at 301s mid-GB). Per-job override via
        # meta.json `exploit_timeout_seconds` (retry-driven heap exploits —
        # job aa86e561: 24 attempts × ~25s ≈ 10 min — need more than the base).
        # See _resolve_sandbox_timeout for the exact clamp.
        per_job_timeout = DEFAULT_TIMEOUT_S
        try:
            from modules._common import read_meta as _read_meta
            _m = _read_meta(job_id) or {}
            per_job_timeout = _resolve_sandbox_timeout(
                _m.get("module"), use_sage,
                _m.get("exploit_timeout_seconds"), bool(target),
            )
            if per_job_timeout != DEFAULT_TIMEOUT_S:
                log_fn(
                    f"[runner] sandbox timeout: {per_job_timeout}s "
                    f"(module={_m.get('module')}, sage={use_sage}, "
                    f"remote={bool(target)}, "
                    f"override={_m.get('exploit_timeout_seconds')})"
                )
        except Exception as e:
            log_fn(f"[runner] timeout resolve failed: {e}; using "
                   f"{DEFAULT_TIMEOUT_S}s")
        log_fn(
            f"[runner] executing {script_filename} "
            f"(target={target}, sage={use_sage}, judge={enable_judge}, "
            f"timeout={per_job_timeout}s) ..."
        )
        emit_event(
            job_id, "run", "start",
            script=script_filename, target=target,
            timeout_s=per_job_timeout,
        )
        try:
            res = run_in_sandbox(
                job_id, script_filename, args=args, use_sage=use_sage,
                log_fn=log_fn,
                # NOT `enable_judge`. supervise is excluded from v1 enforce by
                # the agreed scope, on two grounds that both still hold: its
                # evidence is the stalled output of a LIVE container, which no
                # post-hoc shadow can reconstruct, so it is the one gate stage
                # 7 could not measure at all — and it is the only one that
                # KILLS. Hardest to verify, largest blast radius. Wiring it to
                # the same flag as prejudge/postjudge meant flipping Settings
                # to enforce handed container lifetime to an unevaluated gate.
                enable_supervise=False,
                timeout_s=per_job_timeout,
            )
            # These are attempt facts, not verdicts.  Preserve them even when
            # no postjudge runs (off/shadow), so the outer retry loop can name
            # the correct terminal state without reverse-engineering a missing
            # `judge` dict.
            res["sandbox_started"] = True
            res["judge_mode"] = judge_mode
        except Exception as e:
            log_fn(f"[runner] failed to spawn sandbox: {e}")
            emit_event(job_id, "run", "spawn_failed", error=str(e))
            return {
                "error": str(e), "prejudge": prejudge,
                "sandbox_started": False, "judge_mode": judge_mode,
            }

        log_fn(
            f"[runner] exit_code={res['exit_code']}; "
            f"stdout {len(res['stdout'])}B / stderr {len(res['stderr'])}B"
        )
        emit_event(
            job_id, "run", "exit",
            exit_code=res.get("exit_code"),
            stdout_bytes=len(res.get("stdout") or ""),
            stderr_bytes=len(res.get("stderr") or ""),
            timeout=bool(res.get("timeout")),
            killed_by_supervise=bool(res.get("killed_by_supervise")),
        )

        # Write logs to job dir (unchanged contract for downstream tools).
        (work_dir / f"{script_filename}.stdout").write_text(res["stdout"])
        (work_dir / f"{script_filename}.stderr").write_text(res["stderr"])

        # Record WHAT WAS ACTUALLY WRITTEN, so nothing downstream has to guess.
        # The names derive from the script the runner really ran, so a crypto
        # Sage job produces `solver.sage.stdout` — a name every consumer-side
        # hard-coded list omitted. Measured 2026-08-11 on job 606175dde9d6: the
        # solver printed `FLAG_CANDIDATE: DH{Not_bad!_10.8+_is_ezpz}`, the file
        # was on disk, and the job still finished `no_flag` because
        # `_TRUSTED_FLAG_SOURCES` listed only the `.py` spellings. The UI's
        # artifact links 404'd for the same reason. This is the one place that
        # knows the answer; everything else should read it rather than infer it.
        try:
            from modules._common import read_meta as _rm, write_meta as _wm
            _arts = dict((_rm(job_id) or {}).get("artifacts") or {})
            _arts.update({
                "script": script_filename,
                "stdout": f"{script_filename}.stdout",
                "stderr": f"{script_filename}.stderr",
            })
            _wm(job_id, artifacts=_arts)
        except Exception as e:
            # Never fail a completed run over bookkeeping — consumers keep the
            # legacy name list as a fallback precisely so this can degrade.
            log_fn(f"[runner] artifact name record failed: {e}")

        # ---------- Stage 3: postjudge ----------
        # Shadow recording sits OUTSIDE the enforce gate. It used to be nested
        # under `if enable_judge:`, which is False in shadow — so the live
        # path recorded a prejudge input and then nothing, ever. The suite
        # missed it because every functional check called judge_shadow
        # directly instead of going through this function.
        if judge_mode == "shadow":
            from modules import judge_shadow

            judge_shadow.record_input(
                job_id, "postjudge",
                {
                    "cycle_id": cycle_id,
                    "script_rel": script_filename,
                    "exit_code": res["exit_code"],
                    # The files a delayed postjudge could still Read from cwd
                    # (the prompt invites it), overwritten by the next attempt.
                    **judge_shadow.postjudge_fingerprint(work_dir, script_filename),
                    # What postjudge actually CONSUMES — the byte tails that
                    # reach the prompt and the flag shapes the placeholder
                    # override scans for across the whole output. Recording
                    # "stdout, shortened" reproduced neither: the generic clip
                    # keeps the HEAD, the prompt uses the TAIL, and the
                    # override reads the FULL string.
                    **_judge.postjudge_inputs(res["stdout"], res["stderr"]),
                    # The SAME extra_context enforce would judge on. Without
                    # it shadow scores a different prompt — no timeout note,
                    # no target-reachability note, no prior-hint history — and
                    # a comparison against the real gate measures the wrong
                    # thing.
                    "extra_context": _postjudge_extra(target_note, res, prior_hints),
                },
            )
        if enable_judge:
            extra = _postjudge_extra(target_note, res, prior_hints)
            try:
                post = _judge.postjudge_run(
                    work_dir,
                    script_filename,
                    res["exit_code"],
                    res["stdout"],
                    res["stderr"],
                    log_fn,
                    extra_context=extra,
                )
            except Exception as e:
                log_fn(f"[judge] postjudge failed: {e}")
                post = {
                    "verdict": "unknown",
                    "summary": "",
                    "retry_hint": "",
                    "raw": "",
                    "error": str(e),
                }
            res["judge"] = post
            emit_event(
                job_id, "postjudge", "verdict",
                verdict=post.get("verdict"),
                next_action=post.get("next_action"),
                failure_code=post.get("failure_code"),
            )
        if prejudge is not None:
            res["prejudge"] = prejudge
        return res
    finally:
        # postjudge_run already calls _forget_sid on its happy path —
        # this is the safety net for early-exit / exception paths.
        try:
            _judge._forget_sid(job_id)
        except Exception:
            pass
