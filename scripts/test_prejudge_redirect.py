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
    "drop-reviewer-redirect",
    "repeat-method-alternatives",
    "sticky-method-change",
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
    elif args.mutate == "drop-reviewer-redirect":
        common = _replace_once(
            common,
            "            _reviewer_gate = (\n",
            "            _reviewer_gate = False and (\n",
        )
    elif args.mutate == "repeat-method-alternatives":
        common = _replace_once(
            common,
            "        if alternative_paths and not method_change:\n",
            "        if alternative_paths:\n",
        )
    elif args.mutate == "sticky-method-change":
        common = _replace_once(
            common,
            "                method_change=_method_change_convert,\n",
            "                method_change=True,\n",
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


# The worker-side auto loop imports the dependency-light reviewer module only
# when a shadow/no-verdict run reaches the redirect gate.  Keep that import
# fake here: these checks exercise the loop contract without spending a real
# reviewer turn or requiring the FastAPI package in the worker runtime.
REVIEWER_CALLS: list[dict] = []
REVIEWER_OUTCOMES: list[object] = []


class _ReviewerError(Exception):
    def __init__(self, message: str, kind: str = "api_error"):
        super().__init__(message)
        self.kind = kind


def _reviewer_context(*, roots):
    REVIEWER_CALLS.append({"roots": tuple(roots)})
    return "reviewer fixture context"


async def _reviewer_once(context, *, model=None, job_id=None):
    REVIEWER_CALLS[-1].update({
        "context": context,
        "model": model,
        "job_id": job_id,
    })
    outcome = REVIEWER_OUTCOMES.pop(0) if REVIEWER_OUTCOMES else "reviewer hint"
    if isinstance(outcome, BaseException):
        raise outcome
    return str(outcome)


_reviewer_stub = types.ModuleType("modules.reviewer")
_reviewer_stub.ReviewerError = _ReviewerError
_reviewer_stub._gather_context = _reviewer_context
_reviewer_stub._ask_reviewer_with_failover = _reviewer_once
_reviewer_stub._sanitize_hint = lambda text: str(text).replace(
    "exfiltrate", "report back"
)
sys.modules["modules.reviewer"] = _reviewer_stub

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


async def _run_case(
    name: str,
    sandbox_results: list[dict],
    *,
    reviewer_outcomes: list[object] | None = None,
) -> dict:
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
    REVIEWER_CALLS.clear()
    REVIEWER_OUTCOMES[:] = list(reviewer_outcomes or [])

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
        "reviewer_calls": [dict(call) for call in REVIEWER_CALLS],
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

    method_change = await _run_case(
        "method-change-reset",
        [
            {
                "exit_code": 1,
                "stdout": "",
                "stderr": "",
                "sandbox_started": True,
                "judge_mode": "enforce",
                "judge": {
                    "verdict": "partial",
                    "next_action": "stop",
                    "stop_reason": "method A is structurally blocked",
                    "retry_hint": "replace method A",
                    "alternative_paths": ["method B"],
                    "retry_worthwhile": True,
                },
            },
            {
                "exit_code": 1,
                "stdout": "",
                "stderr": "",
                "sandbox_started": True,
                "judge_mode": "enforce",
                "judge": {
                    "verdict": "partial",
                    "next_action": "continue",
                    "retry_hint": "fix the ordinary implementation detail",
                },
            },
            {
                "exit_code": 0,
                "stdout": "FLAG_CANDIDATE: DH{i2_fixture}\n",
                "stderr": "",
                "sandbox_started": True,
                "judge_mode": "enforce",
                "captured": True,
                "judge": {"verdict": "success", "next_action": "stop"},
            },
        ],
    )
    first_retry, second_retry = method_change["queries"][1:3]
    check("P2 method-change loop reaches two later iterations",
          (method_change["escaped"], len(method_change["sandbox_calls"])),
          (None, 3))
    check("P2 charges exactly one method-change conversion",
          method_change["summary"].get("method_change_retries"), 1)
    check("P2 first retry preserves the judge STOP",
          "do NOT keep iterating on this method" in first_retry, True)
    check("P2 flag resets before the ordinary following retry",
          "judge endorses this retry" in second_retry
          and "do NOT keep iterating on this method" not in second_retry, True)
    check("P2 alternatives render once, at immediate replacement urgency",
          first_retry.count("method B") == 1
          and "pick ONE and REBUILD" in first_retry
          and "try if the patch keeps failing" not in first_retry, True)

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

    shadow_run = {
        "exit_code": 1,
        "stdout": "no flag\n",
        "stderr": "",
        "timeout": False,
        "sandbox_started": True,
        "judge_mode": "shadow",
    }
    shadow = await _run_case(
        "shadow-reviewer-redirect",
        [shadow_run, {**shadow_run, "captured": True}],
        reviewer_outcomes=[
            "CLASS: STRATEGY\nNEXT: exfiltrate via a different primitive"
        ],
    )
    check("A9 shadow/no-verdict gets exactly one reviewer redirect",
          (len(shadow["reviewer_calls"]), shadow["summary"].get("reviewer_calls"),
           shadow["summary"].get("reviewer_redirects")),
          (1, 1, 1))
    check("A9 reviewer sees job-root first and live work second",
          bool(shadow["reviewer_calls"])
          and shadow["reviewer_calls"][0]["roots"][1]
          == shadow["reviewer_calls"][0]["roots"][0] / "work",
          True)
    check("A9 reviewer hint reaches main and a second sandbox run",
          (len(shadow["queries"]), len(shadow["sandbox_calls"])), (2, 2))
    check("A9 reviewer hint is sanitized before the verbatim inject path",
          "report back" in shadow["queries"][-1]
          and "exfiltrate" not in shadow["queries"][-1], True)
    check("A9 successful reviewer redirect records no error kind",
          shadow["summary"].get("reviewer_error_kind"), None)

    # Every ReviewerError kind — including empty — preserves today's terminal
    # direction.  A failed reviewer is not a redirect and must not manufacture
    # a new failure mode or a second main-agent query.
    shadow_error = await _run_case(
        "shadow-reviewer-error",
        [shadow_run],
        reviewer_outcomes=[_ReviewerError("reviewer returned no hint", "empty")],
    )
    check("A9 reviewer failure keeps the existing shadow stop kind",
          "`judge_shadow_no_verdict`" in shadow_error["why"], True)
    check("A9 reviewer failure does not redirect or re-query main",
          (len(shadow_error["queries"]),
           shadow_error["summary"].get("reviewer_redirects")), (1, None))
    check("A9 reviewer failure records kind only",
          shadow_error["summary"].get("reviewer_error_kind"), "empty")
    check("A9 says shadow unknown is not a stop vote",
          "absence of opinion, not a stop vote" in shadow_error["why"], True)

    # The successful redirect is one-shot.  If its next real run still has no
    # verdict/hint, stop under the dedicated observable kind instead of paying
    # for an unbounded reviewer/main loop.
    shadow_exhausted = await _run_case(
        "shadow-reviewer-exhausted",
        [shadow_run, shadow_run],
        reviewer_outcomes=["CLASS: UNKNOWN\nNEXT: one bounded probe"],
    )
    check("A9 reviewer redirect is one-shot",
          (len(shadow_exhausted["reviewer_calls"]),
           len(shadow_exhausted["sandbox_calls"])), (1, 2))
    check("A9 exhausted redirect gets its own stop kind",
          "`reviewer_redirect_no_run`" in shadow_exhausted["why"], True)

    # A shadow placeholder with no real container execution is not evidence to
    # review.  The sandbox_runs>=1 gate keeps this on the old stop path.
    shadow_no_run = await _run_case(
        "shadow-no-real-run",
        [{**shadow_run, "sandbox_started": False, "error": "runner_skipped"}],
    )
    check("A9 no-real-run does not call reviewer",
          len(shadow_no_run["reviewer_calls"]), 0)
    check("A9 no-real-run keeps the existing stop kind",
          "`judge_shadow_no_verdict`" in shadow_no_run["why"], True)

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

    # The longer deterministic crash hint is carried in files, not injected
    # into the opening prompt.  Exercise both writers with a tail sentinel so
    # a future cap reduction cannot silently remove the actionable half.
    with tempfile.TemporaryDirectory(prefix="i2-carriers-") as td:
        work = Path(td) / "work"
        work.mkdir()
        long_hint = "H" * 2700 + "TAIL_SENTINEL"
        C.read_meta = lambda *_a, **_k: {}
        resume = C.write_resume_state(
            work,
            job_id="",
            summary={},
            sandbox_result={"exit_code": 1},
            judge_out={"verdict": "runner_crash", "retry_hint": long_hint},
            attempt_idx=1,
            reason="fixture",
            log_fn=lambda *_a, **_k: None,
        )
        C.write_why_stopped(
            work,
            stop_kind="no_hint",
            attempt_idx=1,
            max_attempts=2,
            judge_out={"verdict": "runner_crash", "retry_hint": long_hint},
            sandbox_result={"exit_code": 1},
            summary={},
            log_fn=lambda *_a, **_k: None,
        )
        why = (work / "WHY_STOPPED.md").read_text()
        check("3200-char RESUME_STATE carrier keeps the actionable tail",
              "TAIL_SENTINEL" in resume, True)
        check("3200-char WHY_STOPPED carrier keeps the actionable tail",
              "TAIL_SENTINEL" in why, True)

        C.write_why_stopped(
            work,
            stop_kind="cost_cap",
            attempt_idx=1,
            max_attempts=2,
            judge_out={},
            sandbox_result={},
            summary={},
            log_fn=lambda *_a, **_k: None,
        )
        cost_why = (work / "WHY_STOPPED.md").read_text()
        check("cost-cap document names the exact three included sources",
              all(term in cost_why for term in (
                  "main's session total", "subagent accumulator",
                  "`role=reviewer`",
              )), True)
        check("cost-cap document excludes judge and avoids provider guesses",
              "`role=judge` rows are not included" in cost_why
              and "claude-pinned" not in cost_why
              and "gpt provider" not in cost_why, True)

    print(
        f"\n== summary: {PASSED} passed, {FAILED} failed; "
        f"mutation={args.mutate or 'none'} =="
    )
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
