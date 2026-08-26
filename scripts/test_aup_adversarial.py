#!/usr/bin/env python3
"""Adversarial + smoke tests for AUP session recovery.

Run from the repo root:   python3 scripts/test_aup_adversarial.py

test_aup_recovery.py checks the ladder and the checkpoint as pure functions.
This one drives `_aup_restart_session` itself with a stubbed session so the
FAILURE paths actually execute, and then tries to break it.

Two defects were found this way and are pinned below:

  1. The restart prompt appended `summary["initial_prompt_tail"]`, which
     nothing anywhere ever set. The restarted agent would have booted with the
     preamble alone — no mission, no target, no flag format — and
     RESUME_STATE.md is a pointer list, not a task statement.
  2. `agent_error_kind` was cleared BEFORE the call that can still fail. When
     the restart could not start, the caller fell through to the halt with the
     marker already gone, so meta.error_kind would not say policy_refusal —
     which is the exact field api/routes/retry.py keys `prior_aup_blocked` on.
     A failed automatic recovery would have silently disabled the manual one.
"""
from __future__ import annotations

import ast as _ast
import asyncio
import sys
import tempfile
import types
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_results: list[bool] = []


def chk(label: str, cond: bool, got: object = "") -> None:
    _results.append(bool(cond))
    print(("PASS  " if cond else "FAIL  ") + label + ("" if cond else f"  | got={got!r}"))


def section(name: str) -> None:
    print("\n--- " + name + " " + "-" * max(0, 56 - len(name)))


@dataclass
class _Opts:
    system_prompt: str = "SYS"
    model: str = "claude-opus-5"
    cwd: str = "/w"
    effort: str | None = "xhigh"
    env: dict | None = None
    resume: str | None = "dead-session-id"
    add_dirs: list | None = None


def _load(calls: list, blow_up: bool = False, returns=None, use_sentinel=True):
    """Extract _aup_restart_session with run_main_agent_session stubbed."""
    src = (ROOT / "modules" / "_common.py").read_text()
    tree = _ast.parse(src)
    # `_aup_restart_session` grew a call to `job_turn_timeout_s` (the
    # turn-timeout helper) inside the other_provider branch. This slice
    # runs the function in a namespace of its own, so a dependency the
    # slice does not carry raises NameError *inside* the branch, the
    # backend is never invoked, and the suite dies at `calls[0]` having
    # run 10 of its 47 checks. Production imports the whole module and
    # was never affected; what broke was the harness.
    want = {"_aup_restart_session", "_AUP_RESTART_FAILED",
            "job_turn_timeout_s"}
    nodes = [n for n in tree.body
             if (isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef))
                 and n.name in want)
             or (isinstance(n, _ast.Assign)
                 and any(getattr(t, "id", "") in want for t in n.targets))]

    async def _fake_session(job_id, **kw):
        calls.append(kw)
        if blow_up:
            raise RuntimeError("SDK refused to start")
        # `returns` is explicit so a test can make the successor hand back
        # None — an ORDINARY outcome (run_main_agent_session returns
        # last_sandbox for cli_infra_error / auth / rate_limit / unknown) that
        # the original stub could not express, which is exactly why 29 checks
        # missed the sentinel-clobber defect.
        return {"verdict": "success"} if returns is None and use_sentinel else returns

    # `job_turn_timeout_s` (sliced in above) reads job meta to find a
    # per-job budget. Its own try only catches TypeError/ValueError, so a
    # missing name escapes as NameError rather than falling back to the
    # 1800s floor. An empty meta exercises exactly that floor.
    ns: dict = {"Path": Path, "run_main_agent_session": _fake_session,
                "read_meta": lambda _job_id: {},
                "write_meta": lambda *_a, **_k: None}
    # grok_acp lives behind a lazy import; give it a real dataclass
    gm = types.ModuleType("modules.grok_acp")

    @dataclass
    class GrokSessionOptions:
        system_prompt: str = ""
        model: str = ""
        cwd: str = ""
        effort: str | None = None
        env: dict | None = None
        resume: str | None = None
        add_dirs: list | None = None
        # Mirrors the real dataclass. It has carried this field for a while,
        # but nothing passed it until the turn-timeout work started handing a
        # per-job budget to the AUP fallback; the stub then raised TypeError
        # inside the branch's try, which returns _AUP_RESTART_FAILED, so the
        # backend was never invoked and the suite died at `calls[0]`.
        turn_timeout_s: float | None = None

    gm.GrokSessionOptions = GrokSessionOptions
    ap = types.ModuleType("modules.agent_provider")
    ap.default_model_for = lambda p=None: "grok-build"
    pkg = types.ModuleType("modules")
    pkg.__path__ = []  # type: ignore[attr-defined]
    sys.modules["modules"] = pkg
    sys.modules["modules.grok_acp"] = gm
    sys.modules["modules.agent_provider"] = ap

    exec(compile(_ast.Module(body=nodes, type_ignores=[]), "<r>", "exec"), ns)
    return ns, GrokSessionOptions


def _run(ns, **kw):
    logs: list[str] = []
    kw.setdefault("log_fn", logs.append)
    kw.setdefault("work_dir", Path(tempfile.mkdtemp()))
    kw.setdefault("artifact_names", ("exploit.py",))
    kw.setdefault("auto_run", True)
    kw.setdefault("sandbox_runner", None)
    res = asyncio.get_event_loop().run_until_complete(
        ns["_aup_restart_session"]("job1", **kw))
    return res, logs


def main() -> int:
    asyncio.set_event_loop(asyncio.new_event_loop())

    # =============================================== smoke: the happy path
    section("smoke — fresh_session")
    calls: list = []
    ns, _ = _load(calls)
    summary = {"agent_error": "AUP", "agent_error_kind": "policy_refusal",
               "messages": 17}
    res, logs = _run(ns, step="fresh_session", options=_Opts(),
                     original_prompt="MISSION: capture the flag at host:1337",
                     summary=summary)
    chk("the restart runs and returns the session's result",
        res == {"verdict": "success"}, res)
    chk("exactly one session was started", len(calls) == 1, len(calls))
    kw = calls[0]
    chk("the refused transcript is DROPPED", kw["options"].resume is None,
        kw["options"].resume)
    chk("the backend is unchanged for this step",
        kw["options"].model == "claude-opus-5", kw["options"].model)
    chk("system prompt survives", kw["options"].system_prompt == "SYS")
    chk("the original task is carried into the new prompt",
        "MISSION: capture the flag at host:1337" in kw["initial_prompt"],
        kw["initial_prompt"][:120])
    chk("the agent is told it has no history",
        "NO prior conversation" in kw["initial_prompt"])
    chk("...and pointed at the checkpoint",
        "RESUME_STATE.md" in kw["initial_prompt"])
    chk("the dead session's error is cleared for the live run",
        "agent_error_kind" not in summary, summary.get("agent_error_kind"))
    chk("unrelated summary state is preserved", summary.get("messages") == 17)

    # ============================================== smoke: provider switch
    section("smoke — other_provider")
    calls = []
    ns, GSO = _load(calls)
    _sum = {"agent_error_kind": "policy_refusal"}
    res, logs = _run(ns, step="other_provider", options=_Opts(),
                     original_prompt="MISSION: x", summary=_sum)
    kw = calls[0]
    chk("the other backend's option type is used",
        isinstance(kw["options"], GSO), type(kw["options"]).__name__)
    chk("its model comes from that backend's setting",
        kw["options"].model == "grok-build", kw["options"].model)
    chk("no transcript is carried across backends",
        kw["options"].resume is None)
    chk("cwd is preserved", kw["options"].cwd == "/w")
    chk("the switch is recorded on the summary",
        _sum.get("aup_provider_switch") == "grok",
        _sum.get("aup_provider_switch"))
    chk("it is logged plainly",
        any("Grok" in l for l in logs), logs)

    # ================================= adversarial: the restart cannot start
    section("adversarial — the restarted session raises on start")
    calls = []
    ns, _ = _load(calls, blow_up=True)
    summary = {"agent_error": "AUP text", "agent_error_kind": "policy_refusal"}
    res, logs = _run(ns, step="fresh_session", options=_Opts(),
                     original_prompt="M", summary=summary)
    chk("it reports FAILED-to-start, not a fake result",
        res is ns["_AUP_RESTART_FAILED"], res)
    chk("REGRESSION: the policy_refusal marker is RESTORED",
        summary.get("agent_error_kind") == "policy_refusal",
        summary.get("agent_error_kind"))
    chk("...and so is the error text (retry.py reads the kind, humans read this)",
        summary.get("agent_error") == "AUP text", summary.get("agent_error"))
    chk("the failure says why it matters", any("policy_refusal" in l for l in logs), logs)

    # =========================== adversarial: options that cannot be rebuilt
    section("adversarial — hostile options objects")

    class _NoReplace:
        """Not a dataclass, and rejects attribute writes."""
        __slots__ = ()

        def __setattr__(self, k, v):
            raise AttributeError("frozen")

    calls = []
    ns, _ = _load(calls)
    summary = {"agent_error_kind": "policy_refusal"}
    res, _l = _run(ns, step="fresh_session", options=_NoReplace(),
                   original_prompt="M", summary=summary)
    chk("un-rebuildable options -> FAILED, no session started",
        res is ns["_AUP_RESTART_FAILED"] and not calls, (res, len(calls)))
    chk("the marker is untouched on that path",
        summary.get("agent_error_kind") == "policy_refusal")

    section("adversarial — the other backend is unavailable")
    calls = []
    ns, _ = _load(calls)
    sys.modules["modules.grok_acp"] = types.ModuleType("modules.grok_acp")  # no GSO
    summary = {"agent_error_kind": "policy_refusal"}
    res, logs = _run(ns, step="other_provider", options=_Opts(),
                     original_prompt="M", summary=summary)
    chk("missing backend -> FAILED, no session started",
        res is ns["_AUP_RESTART_FAILED"] and not calls, (res, len(calls)))
    chk("the marker survives so the job is still filed correctly",
        summary.get("agent_error_kind") == "policy_refusal")
    chk("it says which step it skipped", any("skipping" in l for l in logs), logs)

    # ================================== adversarial: prompt must not be empty
    section("adversarial — degenerate inputs")
    calls = []
    ns, _ = _load(calls)
    _run(ns, step="fresh_session", options=_Opts(), original_prompt="",
         summary={})
    chk("an empty original prompt still yields a usable preamble",
        "RESUME_STATE.md" in calls[0]["initial_prompt"])
    calls = []
    ns, _ = _load(calls)
    _run(ns, step="fresh_session", options=_Opts(), original_prompt=None,
         summary={})
    chk("a None original prompt does not crash or print 'None'",
        "None" not in calls[0]["initial_prompt"], calls[0]["initial_prompt"][-40:])

    # ============================ adversarial: the two workflow-found defects
    section("adversarial — session-scoped state must not leak into the successor")
    calls = []
    ns, _ = _load(calls)
    # A turn-0 refusal with NO artifact: the classifier writes a probe-only
    # fallback and sets fallback_artifact_used — and that same write is what
    # makes the ladder reachable at all. If the marker leaks, the successor's
    # OWN refusal is never classified (the guard is
    # `is_error and not agent_error and not fallback_artifact_used`), so rung 2
    # is unreachable and the loop queries feedback into a blocked session.
    leaky = {
        "agent_error": "AUP", "agent_error_kind": "policy_refusal",
        "fallback_artifact_used": True,
        "result": {"total_cost_usd": 10.0}, "cost_usd_estimate": 10.0,
        "prejudge_block_redirects": 1, "prejudge_block_sigs": ["abc"],
        "method_change_retries": 1, "judge_hints": ["reuse the carried offsets"],
    }
    _run(ns, step="fresh_session", options=_Opts(), original_prompt="M",
         summary=leaky)
    for k in ("fallback_artifact_used", "result", "cost_usd_estimate",
              "prejudge_block_redirects", "prejudge_block_sigs"):
        chk(f"REGRESSION: {k} does NOT reach the successor", k not in leaky,
            leaky.get(k))
    chk("method_change_retries is KEPT (capped per JOB, not per session)",
        leaky.get("method_change_retries") == 1, leaky.get("method_change_retries"))
    chk("judge_hints are KEPT (they describe the carried artifact)",
        leaky.get("judge_hints") == ["reuse the carried offsets"])

    section("adversarial — a failed restart restores ALL of it, not just the error")
    calls = []
    ns, _ = _load(calls, blow_up=True)
    leaky2 = {"agent_error": "AUP", "agent_error_kind": "policy_refusal",
              "fallback_artifact_used": True, "result": {"total_cost_usd": 3.0},
              "cost_usd_estimate": 3.0, "prejudge_block_redirects": 2}
    before = dict(leaky2)
    res, _l = _run(ns, step="fresh_session", options=_Opts(),
                   original_prompt="M", summary=leaky2)
    chk("failed start -> FAILED sentinel", res is ns["_AUP_RESTART_FAILED"])
    chk("REGRESSION: every session-scoped key is restored, not just the error",
        leaky2 == before, {k: (before.get(k), leaky2.get(k))
                           for k in before if before.get(k) != leaky2.get(k)})

    section("adversarial — a None successor must not clobber a skip sentinel")
    # scan_job_for_flags suppresses the NARRATIVE flag tier only while
    # sandbox_result is truthy AND carries judge_aborted / prejudge_blocked.
    # If the parent hands back the successor's None instead of its own
    # sentinel, agent-authored prose in report.md is promoted to meta.flags
    # and the job reports finished — a false capture.
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location("_c", ROOT / "modules" / "_common.py")
    src_c = (ROOT / "modules" / "_common.py").read_text()
    chk("the parent keeps its own last_sandbox when the successor returns None",
        "return _fresh if _fresh is not None else last_sandbox" in src_c)
    chk("...and the gate it protects still keys on a TRUTHY sandbox_result",
        'sandbox_result.get("error") == "prejudge_blocked"' in src_c
        and "sandbox_result and (" in src_c)

    section("adversarial — Grok gets an ADAPTED system prompt, not the raw one")
    src_a = (ROOT / "modules" / "_common.py").read_text()
    _blk = src_a.split("if step == \"other_provider\":")[1].split("return _AUP_RESTART_FAILED")[0]
    chk("the restart runs the prompt through adapt_system_prompt_for_grok",
        "adapt_system_prompt_for_grok(" in _blk, _blk[:200])
    chk("...and does NOT pass system_prompt straight through",
        "system_prompt=getattr(options" not in _blk)

    section("adversarial — a Grok session id must never reach claude_session_id")
    src_c2 = (ROOT / "modules" / "_common.py").read_text()
    chk("the provider switch stamps meta.agent_provider",
        'write_meta(job_id, agent_provider="grok"' in src_c2)
    chk("capture_session_id gates the Claude-only field on the JOB's provider",
        'get("agent_provider") == "claude"' in src_c2)
    chk("...and still records the provider-neutral id either way",
        src_c2.count("write_meta(job_id, agent_session_id=sid)") == 1, )
    chk("it does NOT gate on Settings (which still says claude after a switch)",
        "active_provider() != \"grok\"" not in
        src_c2.split("def capture_session_id")[1].split("def ")[1 if False else 0])

    section("adversarial — a Grok successor must not be billed at Claude rates")
    calls = []
    ns, _ = _load(calls)
    _m = {"model": "claude-opus-5", "agent_error_kind": "policy_refusal"}
    _run(ns, step="other_provider", options=_Opts(), original_prompt="M",
         summary=_m)
    chk("REGRESSION: summary['model'] follows the provider switch",
        _m.get("model") == "grok-build", _m.get("model"))

    # ===================================== adversarial: recursion is bounded
    section("adversarial — the ladder cannot loop")
    src = (ROOT / "modules" / "_common.py").read_text()
    tree = _ast.parse(src)
    ns2: dict = {}
    nodes = [n for n in tree.body
             if (isinstance(n, _ast.FunctionDef) and n.name == "aup_recovery_step")
             or (isinstance(n, _ast.Assign)
                 and any(getattr(t, "id", "") == "_AUP_RECOVERY_STEPS"
                         for t in n.targets))]
    exec(compile(_ast.Module(body=nodes, type_ignores=[]), "<l>", "exec"), ns2)
    st: dict = {}
    depth = 0
    while ns2["aup_recovery_step"](st, grok_available=True) and depth < 50:
        st.setdefault("aup_recoveries", []).append(
            ns2["aup_recovery_step"](st, grok_available=True))
        depth += 1
    chk("recursion depth is bounded by the ladder length",
        depth == len(ns2["_AUP_RECOVERY_STEPS"]), depth)
    chk("the summary that bounds it is SHARED across restarts (by reference)",
        "summary=summary" in src)

    failed = [r for r in _results if not r]
    print(f"\n{len(_results)} checks, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
