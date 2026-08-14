#!/usr/bin/env python3
"""I2 regression: typed dead targets, two-block escalation, and stop headlines.

This drives the real ``run_main_agent_session`` loop with a fake SDK transport
and deterministic sandbox results.  The two negative controls are intentional:
live-target issue prose containing ``DEAD TARGET`` must still redirect, and the
second qualifying self-defeat must still concede before the generic no-run cap.

Run from the repository root::

    python3 scripts/test_prejudge_redirect.py
    python3 scripts/test_prejudge_redirect.py --mutate drop-dead-target
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# The worker image has the SDK; the repository test shell may not.  Match the
# other offline suites and stub only import-time shapes — the loop below installs
# the concrete fake client/message classes it actually executes.
try:
    import claude_agent_sdk  # noqa: F401
except ModuleNotFoundError:
    _sdk_stub = types.ModuleType("claude_agent_sdk")
    for _name in (
        "AssistantMessage", "ClaudeAgentOptions", "ResultMessage",
        "SystemMessage", "TextBlock", "ClaudeSDKClient", "UserMessage",
    ):
        setattr(_sdk_stub, _name, type(_name, (), {}))

    async def _query(*_args, **_kwargs):
        if False:
            yield None

    _sdk_stub.query = _query
    _sdk_stub.HookMatcher = type(
        "HookMatcher", (), {"__init__": lambda self, **kwargs: None}
    )
    _sdk_stub.AgentDefinition = type(
        "AgentDefinition", (), {"__init__": lambda self, **kwargs: None}
    )
    _sdk_stub.create_sdk_mcp_server = lambda *a, **k: None
    _sdk_stub.tool = lambda *a, **k: (lambda fn: fn)
    _sdk_stub.project_key_for_directory = lambda *a, **k: ""
    sys.modules["claude_agent_sdk"] = _sdk_stub

COMMON_SOURCE = (ROOT / "modules" / "_common.py").read_text()
JUDGE_SOURCE = (ROOT / "modules" / "_judge.py").read_text()

MUTATIONS = (
    "drop-dead-target",
    "dead-target-from-prose",
    "skip-concede",
    "third-no-run-block",
    "count-wrapper-as-sandbox",
    "collapse-shadow-no-hint",
    "drop-stop-metrics",
    "drop-target-schema",
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()


def _replace_once(source: str, old: str, new: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"mutation anchor count={count}, expected 1: {old!r}")
    return source.replace(old, new, 1)


def _mutated_sources() -> tuple[str, str]:
    common, judge = COMMON_SOURCE, JUDGE_SOURCE
    if args.mutate == "drop-dead-target":
        common = _replace_once(
            common,
            'if _pj.get("target_liveness") == "dead":',
            'if False and _pj.get("target_liveness") == "dead":',
        )
    elif args.mutate == "dead-target-from-prose":
        common = _replace_once(
            common,
            'if _pj.get("target_liveness") == "dead":',
            'if (_pj.get("target_liveness") == "dead" or '
            'any("dead target" in s.lower() for s in _pj_issues)):',
        )
    elif args.mutate == "skip-concede":
        common = _replace_once(
            common,
            "if _concede_unsolvable:",
            "if False and _concede_unsolvable:",
        )
    elif args.mutate == "third-no-run-block":
        common = _replace_once(
            common,
            "if _n >= 1 and _sandbox_runs == 0:",
            "if _n >= 2 and _sandbox_runs == 0:",
        )
    elif args.mutate == "count-wrapper-as-sandbox":
        common = _replace_once(
            common,
            "if _actual_sandbox_started:",
            "if True:  # mutant: wrapper dispatch is called a real sandbox",
        )
    elif args.mutate == "collapse-shadow-no-hint":
        common = _replace_once(
            common,
            "                _shadow_no_verdict = (\n",
            "                _shadow_no_verdict = False and (\n",
        )
    elif args.mutate == "drop-stop-metrics":
        common = _replace_once(
            common,
            "_turns, _estimated_cost = _prejudge_stop_metrics(job_id, summary)",
            "_turns, _estimated_cost = 0, 0.0",
        )
    elif args.mutate == "drop-target-schema":
        judge = _replace_once(
            judge,
            'target_liveness = str(parsed.get("target_liveness") or "unknown").lower()',
            'target_liveness = "unknown"',
        )
    return common, judge


def _load(source: str, name: str, filename: str):
    module = types.ModuleType(name)
    module.__file__ = filename
    sys.modules[name] = module
    exec(compile(source, filename, "exec"), module.__dict__)
    return module


COMMON_MUT, JUDGE_MUT = _mutated_sources()
C = _load(COMMON_MUT, "_prejudge_redirect_common", str(ROOT / "modules" / "_common.py"))
J = _load(JUDGE_MUT, "_prejudge_redirect_judge", str(ROOT / "modules" / "_judge.py"))

PASSED = 0
FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}\n      got={got!r}\n     want={want!r}")


class _ResultMessage:
    duration_ms = 10
    num_turns = 1
    total_cost_usd = 0.25
    is_error = False
    stop_reason = None


class _AssistantMessage:
    content = []


class _UserMessage:
    content = []


class _Options:
    system_prompt = "system"
    model = "claude-opus-5"
    cwd = "/tmp"
    effort = None
    env = {}
    resume = None
    add_dirs = []


def _install_sdk() -> types.ModuleType:
    if "anyio" not in sys.modules:
        anyio = types.ModuleType("anyio")

        class _ToThread:
            @staticmethod
            async def run_sync(fn, *fn_args):
                return fn(*fn_args)

        anyio.to_thread = _ToThread()
        sys.modules["anyio"] = anyio
    try:
        import claude_agent_sdk as sdk
    except ModuleNotFoundError:
        sdk = types.ModuleType("claude_agent_sdk")
        sys.modules["claude_agent_sdk"] = sdk
    sdk.ResultMessage = _ResultMessage
    sdk.AssistantMessage = _AssistantMessage
    sdk.UserMessage = _UserMessage
    return sdk


def _block(
    target_liveness: str,
    issues: list[str],
    *,
    flag_likelihood: float = 0.4,
) -> dict:
    return {
        "error": "prejudge_blocked",
        "prejudge": {
            "ok": False,
            "severity": "high",
            "target_liveness": target_liveness,
            "flag_likelihood": flag_likelihood,
            "issues": issues,
        },
        "judge_aborted": True,
        "sandbox_started": False,
        "judge_mode": "enforce",
    }


async def _run_case(name: str, sandbox_results: list[dict]) -> dict:
    sdk = _install_sdk()
    temp = tempfile.TemporaryDirectory(prefix=f"i2-{name}-")
    root = Path(temp.name)
    work = root / "work"
    work.mkdir()
    script = work / "exploit.py"
    script.write_text("print('attempt-0')\n")
    (work / "report.md").write_text("# fixture\n")
    meta = {
        "id": name,
        "module": "pwn",
        "target_url": "live.example:31337",
        "description": "ordinary challenge",
        "agent_turns": 1072,
        "cost_usd": 0.0,
        "cost_usd_estimate": 385.23,
    }
    logs: list[str] = []
    queries: list[str] = []
    sandbox_calls: list[str] = []
    index = {"value": 0}
    receives = {"value": 0}

    import modules.agent_provider as providers

    providers.ensure_provider_ready = lambda requested=None: "claude"
    providers.provider_display_name = lambda provider: "Claude"
    providers.provider_meta_fields = lambda provider: {"agent_provider": provider}
    C.read_meta = lambda _job_id: dict(meta)

    def _write_meta(_job_id, **fields):
        meta.update(fields)

    C.write_meta = _write_meta
    C.job_dir = lambda _job_id: root
    C.emit_event = lambda *a, **k: None
    C.auto_retry_max = lambda: 4
    C.budget_exceeded = lambda *a, **k: False
    C.capture_session_id = lambda *a, **k: None
    C.agent_heartbeat = lambda *a, **k: None
    C.record_rate_limit_event = lambda *a, **k: None
    C.log_assistant_blocks = lambda *a, **k: None
    C.log_user_blocks = lambda *a, **k: None

    def _scan(_job_id, *, sandbox_result=None, provenance_out=None, **_kw):
        captured = bool((sandbox_result or {}).get("captured"))
        if provenance_out is not None:
            provenance_out["tier"] = "marker" if captured else ""
        return ["DH{i2_fixture}"] if captured else []

    C.scan_job_for_flags = _scan

    class _Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def query(self, prompt):
            queries.append(str(prompt))

        async def receive_response(self):
            receives["value"] += 1
            # Main applies the injected hint while producing this turn, not at
            # query submission time.  This ordering exercises the production
            # SHA-unchanged guard rather than bypassing it in the fixture.
            if receives["value"] > 1:
                script.write_text(f"print('attempt-{receives['value'] - 1}')\n")
            yield _ResultMessage()

    sdk.ClaudeSDKClient = _Client

    def _sandbox(script_name: str):
        sandbox_calls.append(script_name)
        i = index["value"]
        index["value"] += 1
        if i >= len(sandbox_results):
            raise AssertionError(f"unexpected sandbox call {i + 1} for {name}")
        return dict(sandbox_results[i])

    summary = {"model": "claude-opus-5"}
    escaped = None
    result = None
    try:
        result = await C.run_main_agent_session(
            name,
            options=_Options(),
            initial_prompt="solve",
            summary=summary,
            work_dir=work,
            artifact_names=("exploit.py",),
            auto_run=True,
            sandbox_runner=_sandbox,
            log_fn=logs.append,
        )
    except BaseException as exc:  # report, don't hide a product escape
        escaped = f"{type(exc).__name__}: {exc}"
    why_path = work / "WHY_STOPPED.md"
    why = why_path.read_text() if why_path.is_file() else ""
    out = {
        "escaped": escaped,
        "result": result,
        "summary": dict(summary),
        "meta": dict(meta),
        "logs": list(logs),
        "queries": list(queries),
        "sandbox_calls": list(sandbox_calls),
        "why": why,
    }
    temp.cleanup()
    return out


def _judge_schema_checks() -> None:
    with tempfile.TemporaryDirectory(prefix="i2-judge-") as td:
        root = Path(td)
        (root / "exploit.py").write_text("print('x')\n")
        J.deterministic_prejudge = lambda *a, **k: {
            "ok": True, "severity": "low", "issues": []
        }
        J.resolve_judge_model = lambda *_: None
        payload = {
            "ok": False,
            "severity": "high",
            "flag_likelihood": 0.1,
            "target_liveness": "dead",
            "issues": ["probe evidence"],
        }
        J.judge_turn = lambda *a, **k: J.JudgeTurnResult(
            text=json.dumps(payload), provider="claude"
        )
        out = J.prejudge_script(root, "exploit.py", "dead.example:1", lambda *_: None)
        check("prejudge preserves typed target_liveness=dead", out.get("target_liveness"), "dead")
        payload["target_liveness"] = "DEAD-ISH"
        out2 = J.prejudge_script(root, "exploit.py", "dead.example:1", lambda *_: None)
        check("unknown target_liveness spelling fails closed to unknown",
              out2.get("target_liveness"), "unknown")
        check("the prompt requires the structured liveness field",
              '"target_liveness": "live"|"dead"|"unknown"' in J._PREJUDGE_USER_TMPL,
              True)


def _runner_fact_checks() -> None:
    if "docker" not in sys.modules:
        docker_stub = types.ModuleType("docker")
        docker_stub.from_env = lambda *a, **k: None
        docker_stub.DockerClient = type("DockerClient", (), {})
        docker_errors = types.ModuleType("docker.errors")
        for name in (
            "APIError", "NotFound", "ImageNotFound", "DockerException",
            "NullResource",
        ):
            setattr(docker_errors, name, type(name, (Exception,), {}))
        docker_types = types.ModuleType("docker.types")
        docker_types.Mount = type(
            "Mount", (), {"__init__": lambda self, **kwargs: None}
        )
        docker_stub.errors = docker_errors
        docker_stub.types = docker_types
        sys.modules.update({
            "docker": docker_stub,
            "docker.errors": docker_errors,
            "docker.types": docker_types,
        })
    import modules._runner as R
    from modules import _judge as real_judge

    with tempfile.TemporaryDirectory(prefix="i2-runner-") as td:
        root = Path(td)
        work = root / "work"
        work.mkdir()
        (work / "exploit.py").write_text("print('x')\n")
        calls: list[int] = []
        saved = (
            R.Path,
            R.run_in_sandbox,
            R._judge_mode_for_job,
            R.emit_event,
            real_judge.prejudge_script,
        )

        def _mapped_path(value="", *parts):
            value = str(value)
            if value.startswith("/data/jobs/fact-job"):
                suffix = value[len("/data/jobs/fact-job"):].lstrip("/")
                return root / suffix if suffix else root
            return Path(value, *parts)

        try:
            R.Path = _mapped_path
            R.emit_event = lambda *a, **k: None
            R.run_in_sandbox = lambda *a, **k: (
                calls.append(1),
                {"exit_code": 1, "stdout": "", "stderr": "", "timeout": False},
            )[1]
            R._judge_mode_for_job = lambda _job_id: "off"
            actual = R.attempt_sandbox_run(
                "fact-job", "exploit.py", None, lambda *_: None
            )
            R._judge_mode_for_job = lambda _job_id: "enforce"
            real_judge.prejudge_script = lambda *a, **k: {
                "ok": False,
                "severity": "high",
                "target_liveness": "dead",
                "issues": ["probe"],
            }
            blocked = R.attempt_sandbox_run(
                "fact-job", "exploit.py", None, lambda *_: None
            )
        finally:
            (
                R.Path,
                R.run_in_sandbox,
                R._judge_mode_for_job,
                R.emit_event,
                real_judge.prejudge_script,
            ) = saved

        check("runner marks an actual container execution",
              (actual.get("sandbox_started"), actual.get("judge_mode")),
              (True, "off"))
        check("runner marks a prejudge abort as no sandbox",
              (blocked.get("sandbox_started"), blocked.get("judge_mode")),
              (False, "enforce"))
        check("the blocked attempt did not call the sandbox again", len(calls), 1)


async def main() -> int:
    _judge_schema_checks()
    _runner_fact_checks()

    dead = await _run_case(
        "dead-target",
        [_block("dead", ["current probe returned ECONNREFUSED"])],
    )
    check("A8-a dead target escapes nowhere", dead["escaped"], None)
    check("A8-a dead target does not redirect", len(dead["queries"]), 1)
    check("A8-a gets its own stop kind",
          "`prejudge_dead_target`" in dead["why"], True)

    live = await _run_case(
        "live-target",
        [
            _block("live", [
                "NOT a blocker (verified live this stage): multi-target wiring is fine",
                "VERIFIED DEAD TARGET appears only in an old carried report",
            ]),
            {
                "exit_code": 0,
                "stdout": "FLAG_CANDIDATE: DH{i2_fixture}\n",
                "stderr": "",
                "timeout": False,
                "captured": True,
                "sandbox_started": True,
                "judge_mode": "enforce",
                "judge": {"verdict": "success", "next_action": "stop"},
            },
        ],
    )
    check("A8-b live target still takes the redirect", len(live["queries"]), 2)
    check("A8-b issue prose cannot manufacture dead-target control flow",
          "prejudge_dead_target" in live["why"], False)
    check("A8-b reaches the real second execution", len(live["sandbox_calls"]), 2)

    no_run = await _run_case(
        "two-blocks",
        [
            _block("unknown", ["fix parser boundary"]),
            _block("unknown", ["fix a different parser boundary"]),
            _block("unknown", ["third block must be unreachable"]),
        ],
    )
    check("A2-a stops on the second block", len(no_run["sandbox_calls"]), 2)
    check("A2-a uses prejudge_blocked_no_run",
          "`prejudge_blocked_no_run`" in no_run["why"], True)
    check("A2-a records blocks, zero runs, turns, and estimated cost",
          all(s in no_run["why"] for s in (
              "BLOCKED 2 times", "sandbox runs=0", "main turns=1072",
              "estimated cumulative cost=$",
          )) and "estimated cumulative cost=$0.00" not in no_run["why"], True)
    check("A2-a carries both TTL-expired negative-risk job ids",
          all(s in no_run["why"] for s in ("6b8b78b702b1", "824412f1ada49")),
          True)

    concede_issue = 'self-defeat in report: "no working chain" — agent admits no working chain'
    concede = await _run_case(
        "concede-first",
        [
            _block("unknown", [concede_issue], flag_likelihood=0.02),
            _block("unknown", [concede_issue], flag_likelihood=0.02),
        ],
    )
    check("A2-b concede is evaluated before the second-block cap",
          "`unsolvable_by_analysis`" in concede["why"], True)
    check("A2-b is not relabelled as generic no-run",
          "`prejudge_blocked_no_run`" in concede["why"], False)

    shadow = await _run_case(
        "shadow-no-verdict",
        [{
            "exit_code": 1,
            "stdout": "no flag\n",
            "stderr": "",
            "timeout": False,
            "sandbox_started": True,
            "judge_mode": "shadow",
        }],
    )
    check("A3 shadow unknown gets a distinct headline",
          "`judge_shadow_no_verdict`" in shadow["why"], True)
    check("A3 says shadow unknown is not a stop vote",
          "absence of opinion, not a stop vote" in shadow["why"], True)

    ordinary = await _run_case(
        "ordinary-no-hint",
        [{
            "exit_code": 1,
            "stdout": "no flag\n",
            "stderr": "",
            "timeout": False,
            "sandbox_started": True,
            "judge_mode": "off",
        }],
    )
    check("A3 preserves the existing ordinary no_hint class",
          "`no_hint`" in ordinary["why"], True)

    print(
        f"\n== summary: {PASSED} passed, {FAILED} failed; "
        f"mutation={args.mutate or 'none'} =="
    )
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
