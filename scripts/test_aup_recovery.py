#!/usr/bin/env python3
"""Regression suite for AUP recovery and the resume checkpoint.

Run from the repo root:   python3 scripts/test_aup_recovery.py

A server-side Usage-Policy block ends the SESSION, not necessarily the JOB.
Before this, the orchestrator halted and waited for an operator to press
/retry — which is exactly the recovery it could have performed itself, since
api/routes/retry.py already force-drops the transcript on `prior_aup_blocked`.

The ladder is deliberately short and one-shot per step:

    fresh_session   same backend, no transcript
    other_provider  same work tree, the other configured backend
    (then halt)

Nothing rewrites or re-words the request; only the conversation history is
dropped, and at the second step the backend changes. A refusal that survives a
clean context is about the work itself, so more sessions would just repeat it —
hence "at most once per step", verified below.

These are pure-function tests: the real path needs an actual refusal, which
cannot be produced on demand.
"""
from __future__ import annotations

import ast as _ast
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_results: list[bool] = []


def chk(label: str, cond: bool, got: object = "") -> None:
    _results.append(bool(cond))
    print(("PASS  " if cond else "FAIL  ") + label + ("" if cond else f"  | got={got!r}"))


def section(name: str) -> None:
    print("\n--- " + name + " " + "-" * max(0, 56 - len(name)))


def _load():
    src = (ROOT / "modules" / "_common.py").read_text()
    tree = _ast.parse(src)
    want = {"aup_recovery_step", "write_resume_state", "_AUP_RECOVERY_STEPS"}
    nodes = [n for n in tree.body
             if (isinstance(n, _ast.FunctionDef) and n.name in want)
             or (isinstance(n, _ast.Assign)
                 and any(getattr(t, "id", "") in want for t in n.targets))]
    ns: dict = {"Path": Path}
    exec(compile(_ast.Module(body=nodes, type_ignores=[]), "<a>", "exec"), ns)
    return ns


def main() -> int:
    ns = _load()
    step = ns["aup_recovery_step"]

    # ------------------------------------------------------------- ladder
    section("the ladder walks once, then halts")
    s: dict = {}
    chk("first refusal -> fresh_session",
        step(s, grok_available=True) == "fresh_session", step(s, grok_available=True))

    s = {"aup_recoveries": ["fresh_session"]}
    chk("refusal after a clean context -> other_provider",
        step(s, grok_available=True) == "other_provider", step(s, grok_available=True))

    s = {"aup_recoveries": ["fresh_session", "other_provider"]}
    chk("both tried -> halt (None)", step(s, grok_available=True) is None,
        step(s, grok_available=True))

    section("no second provider configured")
    chk("fresh_session is still offered",
        step({}, grok_available=False) == "fresh_session")
    chk("...and then it halts rather than inventing a step",
        step({"aup_recoveries": ["fresh_session"]}, grok_available=False) is None,
        step({"aup_recoveries": ["fresh_session"]}, grok_available=False))

    section("a step is never repeated")
    seen: list[str] = []
    st: dict = {}
    for _ in range(6):
        nxt = step(st, grok_available=True)
        if nxt is None:
            break
        seen.append(nxt)
        st.setdefault("aup_recoveries", []).append(nxt)
    chk("the ladder terminates", len(seen) == 2, seen)
    chk("no step repeats", len(seen) == len(set(seen)), seen)
    chk("order is fresh-context BEFORE switching backend",
        seen == ["fresh_session", "other_provider"], seen)

    # -------------------------------------------------------- checkpoint
    section("RESUME_STATE.md — what a context-less session needs")
    tmp = Path(tempfile.mkdtemp())
    (tmp / "report.md").write_text("# findings\nOOB write at operator[]\n")
    (tmp / "exploit.py").write_text("print('x')\n")
    (tmp / "empty.md").write_text("")
    logs: list[str] = []
    out = ns["write_resume_state"](
        tmp,
        job_id="",
        summary={"messages": 42, "tool_calls": 88, "exploit_present": True},
        sandbox_result={"verdict": "fail", "exit_code": 1},
        judge_out={"retry_hint": "the leak offset is off by 0x10"},
        attempt_idx=2,
        reason="blocked by the server-side Usage-Policy classifier",
        log_fn=logs.append,
    )
    chk("the file is written", (tmp / "RESUME_STATE.md").is_file())
    chk("it says the conversation is gone",
        "NO prior conversation" in out or "conversation is\ngone" in out
        or "conversation is gone" in out.replace("\n", " "), out[:200])
    chk("it lists artifacts that exist", "report.md" in out and "exploit.py" in out)
    chk("it does NOT list empty ones", "empty.md" not in out)
    chk("it carries the judge's last hint", "off by 0x10" in out)
    chk("it reports where the run got to", "42" in out and "88" in out)
    chk("it says an exploit already exists", "exploit/solver artifact EXISTS" in out)
    chk("it tells the next session not to redo settled work",
        "already answer" in out)
    chk("it logs what it wrote", logs and "RESUME_STATE.md" in logs[0], logs)

    section("checkpoint degrades safely")
    bare = ns["write_resume_state"](
        tmp, job_id="", summary=None, sandbox_result=None, judge_out=None,
        attempt_idx=0, reason="x", log_fn=logs.append)
    chk("no summary / no judge still produces a file", bool(bare.strip()))
    chk("...and does not invent a hint", "hint" not in bare.lower())

    # The sentence "the goal and the target are unchanged" used to be emitted
    # unconditionally. On a restart after an operator changed the target it was
    # a generated FALSEHOOD handed to a context-less agent.
    chk("REGRESSION: it never asserts the target is unchanged",
        "target are unchanged" not in out and "target are unchanged" not in bare,
        out[-200:])
    chk("with no live target it simply says nothing about one",
        "CURRENT target" not in bare, bare[-160:])

    # ------------------------------------------------------------ wiring
    section("wiring")
    src = (ROOT / "modules" / "_common.py").read_text()
    # These used to use src.index(), which finds the DEFINITION, not the call
    # site — so they compared where the functions are declared and could not
    # fail. Anchor on the halt block's own text instead.
    halt = src.split("if summary.get(\"agent_error_kind\") == \"policy_refusal\":")[1]
    halt = halt.split("write_why_stopped(")[0]
    chk("the halt CALLS the ladder before giving up",
        "aup_recovery_step(" in halt, halt[:120])
    chk("the restart drops the refused transcript",
        "_dc_replace(options, resume=None)" in src)
    chk("a failed START falls through to the halt, not to a fake success",
        "_AUP_RESTART_FAILED" in src and "is not _AUP_RESTART_FAILED" in src)
    # Assert the PROPERTY, not the spelling. This used to match the literal
    # `summary.pop("agent_error_kind", None)` and broke the moment the two
    # explicit pops became a set-driven reset — a brittle check that failed on
    # a strictly better implementation. The behavioural version of this lives
    # in test_aup_adversarial.py, which drives the real function.
    chk("session-scoped state is reset before restarting",
        "_SESSION_SCOPED = (" in src)
    for _k in ("agent_error_kind", "fallback_artifact_used", "result",
               "prejudge_block_redirects"):
        chk(f"  ...and {_k} is in that reset",
            src.split("_SESSION_SCOPED = (")[1].split(")")[0].find(_k) >= 0)
    chk("the checkpoint is written BEFORE the restart, in the halt block",
        "write_resume_state(" in halt
        and halt.index("write_resume_state(") < halt.index("_aup_restart_session("),
        halt[:200])
    chk("the restart is only reached when the ladder returned a step",
        halt.index("aup_recovery_step(") < halt.index("_aup_restart_session("))

    # ---------------------------------------------------------------- order
    section("the ladder has to be REACHABLE, not merely present")
    # Everything above proves the halt block is correct. None of it noticed
    # that the block sat BELOW the `if not retry_hint:` give-up, which returns
    # first — so the ladder only ran when a hint already existed. With
    # `enable_judge` off (the shipped setting) the sole hint producer is
    # runner_crash_hint, i.e. missing-module / missing-binary crashes, and the
    # whole recovery path was dead for every other AUP block.
    #
    # Job 3d8cca4e26de: main AUP-blocked on turn 37 holding an exploit that
    # had already connected and leaked a heap address; the run ended
    # `stop_kind=no_hint` with no ladder entry in run.log at all.
    #
    # These assert POSITION, which is the only thing that was ever wrong.
    _aup_at = src.index('if summary.get("agent_error_kind") == "policy_refusal":')
    _giveup_at = src.index(
        'log_fn(\n                    f"[orchestrator] postjudge produced no retry_hint ')
    _crash_at = src.index("_crash_hint = runner_crash_hint(last_sandbox)")
    chk("REGRESSION: the AUP branch is reached BEFORE the no-hint give-up",
        _aup_at < _giveup_at, (_aup_at, _giveup_at))
    chk("...and AFTER the crash-hint synthesis, so an AUP+crash session "
        "carries that hint into RESUME_STATE for its successor",
        _crash_at < _aup_at, (_crash_at, _aup_at))
    chk("the give-up still exists for the non-AUP case",
        "stop_kind=\"no_hint\"" in src)
    chk("both AUP outcomes terminate the loop rather than falling through",
        src[_aup_at:_giveup_at].count("return last_sandbox") >= 1
        and "stop_kind=\"policy_refusal\"" in src[_aup_at:_giveup_at])
    chk("the ordering constraint is written down where it can be read",
        "ORDER IS LOAD-BEARING" in src)

    failed = [r for r in _results if not r]
    print(f"\n{len(_results)} checks, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
