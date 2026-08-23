#!/usr/bin/env python3
"""Offline A'/B/C/E regression and mutation checks for turn 0852."""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import os
import sys
import tempfile
import time
import types
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
TMP = tempfile.TemporaryDirectory(prefix="audit-remediation-")
DATA = Path(TMP.name)
(DATA / "jobs").mkdir()
(DATA / "settings.json").write_text("{}")
os.environ.update(
    DATA_DIR=str(DATA),
    JOBS_DIR=str(DATA / "jobs"),
    SETTINGS_PATH=str(DATA / "settings.json"),
)


def _missing(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is None
    except (ImportError, ValueError):
        return True


if _missing("docker"):
    docker = types.ModuleType("docker")
    docker.from_env = lambda *args, **kwargs: None
    docker.DockerClient = type("DockerClient", (), {})
    docker_errors = types.ModuleType("docker.errors")
    for name in ("APIError", "NotFound", "ImageNotFound", "DockerException", "NullResource"):
        setattr(docker_errors, name, type(name, (Exception,), {}))
    docker.errors = docker_errors
    docker_types = types.ModuleType("docker.types")
    docker_types.Mount = type("Mount", (), {"__init__": lambda self, **kwargs: None})
    docker.types = docker_types
    sys.modules.update({
        "docker": docker,
        "docker.errors": docker_errors,
        "docker.types": docker_types,
    })

if _missing("claude_agent_sdk"):
    sdk = types.ModuleType("claude_agent_sdk")
    for name in (
        "AssistantMessage", "ClaudeAgentOptions", "ResultMessage", "SystemMessage",
        "TextBlock", "ClaudeSDKClient", "UserMessage", "HookMatcher", "AgentDefinition",
    ):
        setattr(sdk, name, type(name, (), {"__init__": lambda self, *args, **kwargs: None}))

    async def _query(*args, **kwargs):
        if False:
            yield None

    sdk.query = _query
    sdk.create_sdk_mcp_server = lambda *args, **kwargs: None
    sdk.tool = lambda *args, **kwargs: (lambda fn: fn)
    sdk.project_key_for_directory = lambda *args, **kwargs: ""
    sys.modules["claude_agent_sdk"] = sdk

if _missing("redis"):
    redis_module = types.ModuleType("redis")
    redis_module.Redis = type(
        "Redis", (), {"from_url": staticmethod(lambda *args, **kwargs: object())}
    )
    sys.modules["redis"] = redis_module

if _missing("rq"):
    rq_module = types.ModuleType("rq")
    rq_module.Queue = type("Queue", (), {"__init__": lambda self, *args, **kwargs: None})
    sys.modules["rq"] = rq_module


PASSED = 0
FAILED = 0

# The production incident resumed the same Codex thread on worker slot 2 exactly
# 0.651435 seconds after the stopped predecessor recorded its terminal timestamp.
# Keep the measured gap here instead of rounding it into a generic sleep probe.
INCIDENT_RESUME_GAP_S = 0.651435
INCIDENT_SESSION_ID = "01a02795-27fa-7423-97ac-df09efcb80c4"


def check(label: str, condition: bool, detail: str = "") -> None:
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  PASS  {label}" + (f" — {detail}" if detail else ""))
    else:
        FAILED += 1
        print(f"  FAIL  {label}" + (f" — {detail}" if detail else ""))


def test_a_turn_ack(mutation: str) -> None:
    from modules.codex_turn_guard import (
        CodexTurnStopRequested,
        acquire_turn_guard,
        release_turn_guard,
        request_turn_stop,
        wait_for_turn_teardown,
    )

    print("\n== A' Codex teardown acknowledgement ==")
    work = DATA / "guard-work"
    work.mkdir()
    ready = work / "ready"
    worker_pid = os.fork()
    if worker_pid == 0:
        guard = acquire_turn_guard(work)
        cli_pid = os.fork()
        if cli_pid == 0:
            if mutation == "a-drop-inherited-guard":
                release_turn_guard(guard)
            ready.write_text("ready")
            time.sleep(1.00)
            os._exit(0)
        # Simulate the RQ workhorse disappearing without orderly teardown.
        os._exit(0)

    deadline = time.monotonic() + 2.0
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    os.waitpid(worker_pid, 0)
    workhorse_reaped_at = time.monotonic()
    time.sleep(max(0.0, workhorse_reaped_at + INCIDENT_RESUME_GAP_S - time.monotonic()))
    race_acknowledged, race_probe_waited = wait_for_turn_teardown(work, timeout_s=0.0)
    race_probe_at = time.monotonic() - workhorse_reaped_at
    incident_source = {
        "worker_slot": "2",
        "agent_session_id": INCIDENT_SESSION_ID,
    }
    incident_successor = {
        "worker_slot": "2",
        "resume_session_id": INCIDENT_SESSION_ID,
    }
    same_lineage = (
        incident_source["worker_slot"] == incident_successor["worker_slot"]
        and incident_source["agent_session_id"] == incident_successor["resume_session_id"]
    )
    check(
        "0.651435s same-slot same-session resume remains fenced",
        same_lineage and not race_acknowledged,
        (
            f"ack={race_acknowledged} gap={race_probe_at:.6f}s "
            f"probe_wait={race_probe_waited:.3f}s"
        ),
    )
    acknowledged, waited = wait_for_turn_teardown(work, timeout_s=2.0)
    teardown_elapsed = time.monotonic() - workhorse_reaped_at
    check(
        "inherited CLI lock survives workhorse exit",
        not race_acknowledged and acknowledged and teardown_elapsed >= 0.90,
        f"ack={acknowledged} total={teardown_elapsed:.3f}s final_wait={waited:.3f}s",
    )

    blocked = DATA / "guard-blocked"
    held = acquire_turn_guard(blocked)
    try:
        blocked_ack, blocked_wait = wait_for_turn_teardown(blocked, timeout_s=0.10)
        if mutation == "a-accept-timeout":
            blocked_ack = True
        check("blocked acknowledgement fails closed", not blocked_ack and blocked_wait >= 0.09,
              f"ack={blocked_ack} waited={blocked_wait:.3f}s")
    finally:
        release_turn_guard(held)

    fenced = DATA / "guard-fenced"
    request_turn_stop(fenced)
    try:
        acquire_turn_guard(fenced)
    except CodexTurnStopRequested:
        fence_blocked = True
    else:
        fence_blocked = False
    check("stop fence blocks a late Codex launch", fence_blocked)

    retry_source = (ROOT / "api/routes/retry.py").read_text()
    builder_start = retry_source.find("def _resubmit(")
    quiescent_pos = retry_source.find("wait_for_turn_teardown(", builder_start)
    allocate_pos = retry_source.find("new_id = new_job_id()", builder_start)
    check("every successor rechecks source quiescence before allocation",
          0 <= quiescent_pos < allocate_pos)
    import api.routes.retry as retry_routes

    predecessor = DATA / "jobs" / ("9" * 12)
    predecessor_work = predecessor / "work"
    held_predecessor = acquire_turn_guard(predecessor_work)
    try:
        try:
            retry_routes._resubmit(
                {"id": "9" * 12, "module": "pwn"},
                "safe retry hint",
                predecessor,
                carry_work=True,
            )
        except Exception as exc:
            successor_rejected = (
                getattr(exc, "status_code", None) == 409
                and getattr(exc, "detail", {}).get("kind") == "stop_ack_timeout"
            )
        else:
            successor_rejected = False
    finally:
        release_turn_guard(held_predecessor)
    check("held source guard rejects successor without allocating a job",
          successor_rejected and len(list((DATA / "jobs").iterdir())) == 1)
    halt_start = retry_source.find("def _halt_source_job")
    fence_pos = retry_source.find("request_turn_stop(", halt_start)
    wait_pos = retry_source.find("wait_for_turn_teardown(", fence_pos)
    reject_pos = retry_source.find('"stop_ack_timeout"', wait_pos)
    resume_start = retry_source.find("async def stop_and_resume")
    halt_call = retry_source.find("to_thread(_halt_source_job", resume_start)
    resubmit_pos = retry_source.find("new_id = _resubmit(", halt_call)
    check("resume waits and rejects before successor creation",
          0 <= fence_pos < wait_pos < reject_pos
          and 0 <= halt_call < resubmit_pos < halt_start)
    check("successor carry excludes the source stop fence",
          '".codex-stop-requested"' in retry_source)


def test_b_failure_and_stale_gate(mutation: str) -> None:
    import modules._common as common
    from modules._common import classify_result_failure, failed_turn_reuses_artifact
    from modules.gpt_responses import GptSessionOptions, ResultMessage
    import hashlib

    print("\n== B structured process error + stale artifact gate ==")
    reason = "mystery" if mutation == "b-swallow-process-error" else "process_error"
    msg = ResultMessage(is_error=True, stop_reason=reason)
    kind, detail = classify_result_failure(
        msg,
        ["earlier prose discusses usage policy but the CLI exited"],
        "agent_error",
    )
    check("structured process_error remains transport_error",
          kind == "transport_error", f"kind={kind} detail={detail!r}")

    work = DATA / "stale-work"
    work.mkdir()
    artifact = work / "exploit.py"
    artifact.write_text("print('carried')\n")
    prior = hashlib.sha256(artifact.read_bytes()).hexdigest()
    before = {} if mutation == "b-bypass-stale-gate" else {"exploit.py": prior}
    picked, stale = failed_turn_reuses_artifact(work, ("exploit.py",), before)
    check("byte-identical carried artifact is stale", picked == "exploit.py" and stale)
    artifact.write_text("print('fresh')\n")
    _, stale_after_edit = failed_turn_reuses_artifact(
        work, ("exploit.py",), {"exploit.py": prior}
    )
    check("artifact changed in failed turn is not called stale", not stale_after_edit)

    source = (ROOT / "modules/_common.py").read_text()
    stale_block = source.find("# A failed turn may inherit")
    gate = source.find("failed_turn_reuses_artifact(", stale_block)
    prejudge = source.find("run_sync(sandbox_runner, picked)", gate)
    check("stale gate executes before sandbox dispatch", 0 <= gate < prejudge)

    async def exercise_main_loop() -> tuple[dict, list[str], Path]:
        import modules.agent_provider as provider
        import modules.gpt_agent as gpt_agent

        run_id = "e" * 12
        run_root = DATA / "jobs" / run_id
        run_work = run_root / "work"
        run_work.mkdir(parents=True)
        (run_root / "meta.json").write_text(json.dumps({
            "id": run_id,
            "module": "pwn",
            "status": "running",
            "description": "safe",
            "agent_provider": "gpt",
        }))
        (run_work / "exploit.py").write_text("print('carried stale build')\n")
        summary: dict = {}
        sandbox_calls: list[str] = []

        class FakeClient:
            def __init__(self, options):
                self.options = options

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def query(self, _prompt):
                return None

            async def receive_response(self):
                yield ResultMessage(
                    duration_ms=1,
                    num_turns=1,
                    is_error=True,
                    stop_reason="process_error",
                )

        original_client = gpt_agent.GptAgentClient
        original_ready = provider.ensure_provider_ready
        original_gate = common.failed_turn_reuses_artifact
        gpt_agent.GptAgentClient = FakeClient
        provider.ensure_provider_ready = lambda _requested=None: "gpt"
        if mutation == "b-bypass-stale-gate":
            common.failed_turn_reuses_artifact = lambda *_args, **_kwargs: ("exploit.py", False)
        try:
            await common.run_main_agent_session(
                run_id,
                options=GptSessionOptions(
                    system_prompt="system",
                    model="gpt-5.6-sol",
                    cwd=str(run_work),
                    env={"JOB_ID": run_id},
                ),
                initial_prompt="solve",
                summary=summary,
                work_dir=run_work,
                artifact_names=("exploit.py",),
                auto_run=False,
                sandbox_runner=lambda picked: sandbox_calls.append(picked),
                log_fn=lambda _line: None,
            )
        finally:
            gpt_agent.GptAgentClient = original_client
            provider.ensure_provider_ready = original_ready
            common.failed_turn_reuses_artifact = original_gate
        return summary, sandbox_calls, run_work

    summary, sandbox_calls, run_work = asyncio.run(exercise_main_loop())
    check("main preserves process_error classification",
          summary.get("agent_error_kind") == "transport_error")
    check("main records and halts the stale failed-turn artifact",
          summary.get("failed_turn_stale_artifact") == "exploit.py"
          and (run_work / "WHY_STOPPED.md").is_file()
          and sandbox_calls == [])


def test_c_stop_audit(mutation: str) -> None:
    from api.stop_audit import append_operator_stop_audit

    print("\n== C durable operator-stop audit ==")
    out = append_operator_stop_audit(
        {"id": "c" * 12, "status": "running"},
        action="stop_and_resume",
        previous_status="running",
        halt={"sent_stop": True, "containers_found": 1, "containers_killed": 1},
        termination_acknowledged=False,
        acknowledgement_wait_ms=101,
    )
    if mutation == "c-empty-audit":
        out["operator_stop_audit"][-1] = {}
    record = (out.get("operator_stop_audit") or [{}])[-1]
    required = {
        "requested_at", "action", "previous_status", "sent_stop",
        "rq_cancelled", "containers_found", "containers_killed",
        "containers_failed_count", "docker_error", "termination_acknowledged",
    }
    check("stop audit record is non-empty and schema-complete",
          required.issubset(record) and record.get("action") == "stop_and_resume")

    jobs_source = (ROOT / "api/routes/jobs.py").read_text()
    retry_source = (ROOT / "api/routes/retry.py").read_text()
    check("pure stop and stop-and-resume both persist the audit",
          "append_operator_stop_audit" in jobs_source
          and "append_operator_stop_audit" in retry_source)
    stop_start = jobs_source.find("def stop_job")
    stop_end = jobs_source.find("\n@router.", stop_start + 1)
    stop_body = jobs_source[stop_start:stop_end]
    check("pure stop remains a clean terminal operation",
          '"status": "stopped"' in stop_body and '"error_kind":' not in stop_body)


def test_e_secret_ingress(mutation: str) -> None:
    import modules.job_secrets as secrets
    from api.storage import write_job_meta
    from modules._common import agent_job_env, log_line
    from modules._events import emit_event
    from modules.gpt_run_events import emit_gpt_event

    print("\n== E job-scoped secret ingress ==")
    job_id = "a" * 12
    child_id = "b" * 12
    (DATA / "jobs" / job_id).mkdir()
    (DATA / "jobs" / child_id).mkdir()
    secret = "ctfd_" + "a1" * 32
    explicit_key = None if mutation == "e-no-ingress" else "CTFD_ACCESS_TOKEN"
    explicit_value = None if mutation == "e-no-ingress" else secret
    safe_description = secrets.prepare_job_secret(
        job_id,
        "credential supplied through the dedicated field",
        secret_key=explicit_key,
        secret_value=explicit_value,
    )
    env = agent_job_env(job_id, "main", DATA / "jobs" / job_id / "work")
    check("dedicated channel injects CTFD_ACCESS_TOKEN",
          env.get("CTFD_ACCESS_TOKEN") == secret)
    secret_path = DATA / "job-secrets" / f"{job_id}.json"
    check("secret is outside the job and mode 0600",
          secret_path.is_file() and (secret_path.stat().st_mode & 0o777) == 0o600)
    check("description contains no secret", secret not in str(safe_description))

    original_redactor = secrets.redact_job_value
    if mutation == "e-no-redaction":
        secrets.redact_job_value = lambda _job_id, value: value
    try:
        log_line(job_id, f"tool echoed {secret}")
        emit_event(job_id, "run", "probe", detail=f"event echoed {secret}")
        emit_gpt_event(job_id, "tool_completed", detail=f"gpt echoed {secret}")
        write_job_meta(job_id, {
            "id": job_id,
            "status": "running",
            "description": f"meta echoed {secret}",
        })
    finally:
        secrets.redact_job_value = original_redactor
    persisted = "\n".join(
        path.read_text(errors="replace")
        for path in (
            DATA / "jobs" / job_id / "run.log",
            DATA / "jobs" / job_id / "events.jsonl",
            DATA / "jobs" / job_id / "gpt-events.jsonl",
            DATA / "jobs" / job_id / "meta.json",
        )
        if path.exists()
    )
    check("meta/events/run.log never persist the secret value", secret not in persisted)

    secrets.copy_job_secrets(job_id, child_id)
    check("hybrid/retry copy preserves secret out-of-band",
          secrets.read_job_secrets(child_id).get("CTFD_ACCESS_TOKEN") == secret)

    reserved_id = "c" * 12
    try:
        secrets.prepare_job_secret(
            reserved_id, "safe", secret_key="AUTH_TOKEN", secret_value="reserved-value"
        )
    except secrets.SecretIngressError:
        reserved_rejected = True
    else:
        reserved_rejected = False
    check("reserved AUTH_TOKEN is rejected", reserved_rejected)

    legacy_id = "d" * 12
    legacy = secrets.prepare_job_secret(legacy_id, f"token={secret}")
    check("legacy CTFd token is migrated, not persisted in prose",
          secret not in str(legacy)
          and secrets.read_job_secrets(legacy_id).get("CTFD_ACCESS_TOKEN") == secret)

    secrets.delete_job_secrets(job_id)
    check("job deletion removes its secret", not secret_path.exists())

    orphan_id = "f" * 12
    secrets.prepare_job_secret(
        orphan_id,
        "safe",
        secret_key="CTFD_ACCESS_TOKEN",
        secret_value=secret,
    )
    orphan_path = DATA / "job-secrets" / f"{orphan_id}.json"
    old = time.time() - 3600
    os.utime(orphan_path, (old, old))
    removed = secrets.cleanup_orphaned_secrets(older_than_epoch=time.time() - 60)
    check("TTL sweep removes aged orphan secret", removed == 1 and not orphan_path.exists())

    route_sources = "\n".join(
        (ROOT / f"api/routes/{name}_module.py").read_text()
        for name in ("pwn", "web", "crypto", "rev", "misc", "forensic", "web3", "hybrid")
    )
    check("all eight ingest routes expose the dedicated fields",
          route_sources.count("challenge_secret_key") >= 16
          and route_sources.count("challenge_secret_value") >= 16)
    runner_source = (ROOT / "modules/_runner.py").read_text()
    check("sandbox receives the job-scoped environment", "read_job_secrets(job_id)" in runner_source)
    retry_source = (ROOT / "api/routes/retry.py").read_text()
    ui_source = (ROOT / "web-ui/app.js").read_text()
    check("retry/resume/continue expose the same dedicated channel",
          retry_source.count("challenge_secret_key") >= 3
          and "appendChallengeSecret" in ui_source
          and "challenge_secret_value" in ui_source)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mutate", default="")
    args = parser.parse_args()
    if args.mutate:
        print(f"== applied mutation: {args.mutate} ==")
    sections = (
        ("A' Codex teardown acknowledgement", test_a_turn_ack),
        ("B structured process error + stale artifact gate", test_b_failure_and_stale_gate),
        ("C durable operator-stop audit", test_c_stop_audit),
        ("E job-scoped secret ingress", test_e_secret_ingress),
    )
    for label, section in sections:
        try:
            section(args.mutate)
        except Exception as exc:
            check(
                f"{label} section completes without an exception",
                False,
                f"{type(exc).__name__}: {exc}",
            )
    print(f"\n== summary: {PASSED} passed, {FAILED} failed ==")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
