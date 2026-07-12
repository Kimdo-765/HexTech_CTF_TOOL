"""Sandboxed exploit/solver execution helper.

After a Claude agent has produced exploit.py / solver.py, the orchestrator
calls run_in_sandbox() to execute the script inside the hextech_ctf_tool-runner
container instead of the worker. This isolates network and resources from
the worker that holds the docker socket and the API key.

The runner image must be built once via:
    docker compose --profile tools build runner

When the `enable_judge` setting is on (default), each call to
attempt_sandbox_run() is wrapped by three short Claude judge calls
defined in modules._judge:

  pre   — review the script BEFORE the container starts. Severity=high
          aborts the run with a `prejudge_blocked` reason.
  during— ONE stall-detection call when the container has emitted no
          new output for 60s while still alive. Judge can decide to
          kill (parse-error / hung) or wait (legitimate slow work).
  post  — categorize the result (success / partial / hung /
          parse_error / network_error / crash / timeout / unknown)
          and produce a retry-ready hint.

Disabling `enable_judge` reverts to plain blocking wait + return.
"""
from __future__ import annotations

import os
import socket
import time
from pathlib import Path
from typing import Optional

import docker

from modules import _judge
from modules._events import emit_event
from modules.settings_io import get_setting

RUNNER_IMAGE = "hextech_ctf_tool-runner"
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
DEFAULT_MEM = "2g"


def _resolve_sandbox_timeout(module, use_sage, override, has_target) -> int:
    """Resolve the sandbox HARD-timeout (seconds) for one run.

    Only the crypto `.sage` path is widened, split on offline vs remote-timed:
      * crypto `.sage`, NO target (offline GB/resultant/LLL) → CRYPTO_SAGE_TIMEOUT_S
        (6000s) — a local algebraic solve can legitimately run many minutes.
      * crypto `.sage`, WITH a remote target → CRYPTO_SAGE_REMOTE_TIMEOUT_S
        (900s) — the server's per-connection window bounds it regardless, so a
        100-min ceiling is pointless (job 4fc37cfcd04a burned the full 6000s
        producing zero output against a 150s server budget).
    An explicit `exploit_timeout_seconds` override is honored up to
    CRYPTO_SAGE_TIMEOUT_S on EITHER crypto-sage branch (so an operator can lift a
    remote solve above 900s when a challenge genuinely needs it). EVERY other
    path — all modules' python3 runs, any non-crypto `.sage` — keeps the
    historical 300s default / 1800s override cap byte-for-byte. `override` is
    meta.exploit_timeout_seconds (None / str / int / junk; ≤0 or unparseable →
    ignored); `has_target` is bool(target) at the call site.
    """
    is_crypto_sage = (module == "crypto") and bool(use_sage)
    if is_crypto_sage:
        base = CRYPTO_SAGE_REMOTE_TIMEOUT_S if has_target else CRYPTO_SAGE_TIMEOUT_S
        cap = CRYPTO_SAGE_TIMEOUT_S
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


def _host_path(job_id: str) -> str:
    host_root = os.environ.get("HOST_DATA_DIR")
    if not host_root:
        raise RuntimeError("HOST_DATA_DIR not set on worker")
    return f"{host_root.rstrip('/')}/jobs/{job_id}"


def _judge_enabled() -> bool:
    """Default ON; off only if the user explicitly disabled it."""
    try:
        v = get_setting("enable_judge")
    except Exception:
        return True
    return bool(v) if v is not None else True


def _wait_with_supervise(
    container,
    *,
    timeout_s: int,
    job_dir_path: Path,
    script_rel: str,
    log_fn,
    enable_judge: bool,
) -> dict:
    """Block until the container exits, the timeout fires, or the
    supervise judge votes kill.

    Returns a dict matching docker-py's `container.wait()` plus optional
    fields:
      StatusCode             — container exit code, or -1 if unknown
      timeout (bool)         — True if timeout_s elapsed before exit
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

    while True:
        # Has the container exited?
        try:
            container.reload()
            status = container.status
        except Exception:
            status = "unknown"

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
        log_fetch_ok = True
        try:
            buf = container.logs(stdout=True, stderr=True)
        except Exception:
            buf = b""
            log_fetch_ok = False
        if not log_fetch_ok:
            last_change = time.time()
        elif len(buf) != last_size:
            last_size = len(buf)
            last_change = time.time()
        elif (
            enable_judge
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
    mem_limit: str = DEFAULT_MEM,
    network: str = "bridge",
    use_sage: bool = False,
    *,
    log_fn=None,
    enable_judge: bool = False,
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

    When `enable_judge` is True the wait loop calls
    `modules._judge.supervise_run_once` after SUPERVISE_STALL_S of
    silence. Pre/post judge calls happen in attempt_sandbox_run, not
    here, so callers that want only "during" supervision can set this
    flag while still calling run_in_sandbox directly.

    Returns: {exit_code, stdout, stderr, stdout_truncated_to,
              timeout?, killed_by_supervise?, supervise?}.
    """
    args = args or []
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
        network_mode=network,
        environment=env,
        stdout=True,
        stderr=True,
        detach=True,
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
            enable_judge=enable_judge,
        )
        exit_code = int(result.get("StatusCode", -1))
        timeout_hit = bool(result.get("timeout", False))
        killed_by_supervise = bool(result.get("killed_by_supervise", False))
        supervise_payload = result.get("supervise")
        out = container.logs(stdout=True, stderr=False)
        err = container.logs(stdout=False, stderr=True)
    finally:
        try:
            container.remove(force=True)
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
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
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

    When `enable_judge` is on (default), wraps the run with three judge
    stages:

      pre  — abort BEFORE the container starts if the judge flags a
             severity=high issue. Returned dict has keys
             {error, prejudge, judge_aborted=True} so the orchestrator
             can record a structured failure.
      during— stall watchdog inside run_in_sandbox.
      post — verdict + retry hint merged into the returned dict under
             the `judge` key.
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

    enable_judge = _judge_enabled()

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

    # The judge stages share one Claude session via session_id resume.
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
                issues=len((prejudge or {}).get("issues") or []),
            )
            if prejudge and not prejudge.get("ok") and prejudge.get("severity") == "high":
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
                log_fn=log_fn, enable_judge=enable_judge,
                timeout_s=per_job_timeout,
            )
        except Exception as e:
            log_fn(f"[runner] failed to spawn sandbox: {e}")
            emit_event(job_id, "run", "spawn_failed", error=str(e))
            return {"error": str(e), "prejudge": prejudge}

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

        # ---------- Stage 3: postjudge ----------
        if enable_judge:
            extra = ""
            if target_note:
                # Surface pre-run target reachability notes to postjudge
                # FIRST so its verdict can distinguish "remote was down"
                # (network_error, operator must refresh instance) from
                # "script's own bug" (parse_error, retry will help).
                extra = target_note + "\n"
            if res.get("timeout"):
                extra += "(runner timeout fired before container exit)\n"
            elif res.get("killed_by_supervise"):
                extra += (
                    "(supervise judge killed the container due to stalled "
                    "output)\n"
                )
            if prior_hints:
                # Attach the retry-hint history so judge can detect
                # "I'm about to repeat myself" — which is the strongest
                # signal for next_action=stop. Each entry is one of the
                # judge's prior postjudge_retry_hints (already capped at
                # ~600 chars upstream).
                extra += (
                    "\nPRIOR RETRY HINTS (this job has already iterated "
                    f"{len(prior_hints)} time(s); your new hint MUST NOT "
                    "rhyme with these — if it does, next_action=stop):\n"
                )
                for i, h in enumerate(prior_hints, 1):
                    if h:
                        extra += f"  #{i}: {h[:300]}\n"
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
