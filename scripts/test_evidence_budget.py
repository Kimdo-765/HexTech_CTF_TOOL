#!/usr/bin/env python3
"""The termination instrument: does it actually stop, and can volatility buy time?

Hermetic by construction — every check runs on synthetic dicts with no job tree
and no /data.  That is deliberate: the corpus exercises only two of the nine
evidence fields, so a suite that leans on it would report a green it did not
earn, and a suite that SKIPS when the corpus is absent would report a green it
did not run at all.

The four designs this instrument replaced all died to the same attack — real
artifacts carry volatility no denylist anticipates, and one unscrubbed token
buys an iteration forever.  So the sharpest checks here feed the instrument the
SHAPES that were fatal, with invented values (this repository is public, and a
verbatim solver tail is job-derived text):

  * a per-instance host:port and instance id that rotate on every provisioning
  * a solver that reports its own attempt count in the exception message, so
    the counter moves every single run
  * traceback line numbers, which shift whenever the agent edits anything above

Run from the repository root::

    python3 scripts/test_evidence_budget.py
    python3 scripts/test_evidence_budget.py --mutate saturation-is-novel
"""
from __future__ import annotations

import argparse
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

EVIDENCE_SOURCE = (ROOT / "modules" / "_evidence.py").read_text()

MUTATIONS = (
    "unbounded-interner",
    "hash-the-stdout",
    "exc-message",
    "saturation-is-novel",
    "changed-since-last",
    "drop-gate-reason",
    "drop-flag-channel",
    "plan-budget-unbounded",
    "plan-gate-not-budget",
    # ...and the integration half: a perfect instrument the loop never reads
    # is this project's standing failure mode, so each consumer gets a
    # mutation that severs it.
    "drop-observe-call",
    "restore-mc-one-shot",
    "ignore-evidence-budget",
    "override-without-alternatives",
    "override-keeps-judge-verdict",
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()


def _replace_once(source: str, old: str, new: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"mutation anchor count={count}, expected 1: {old!r}")
    return source.replace(old, new, 1)


def _mutated_source() -> str:
    src = EVIDENCE_SOURCE
    if args.mutate == "unbounded-interner":
        # The bound is what makes |E| finite.  Without it every distinct value
        # gets its own slot and volatility mints fresh evidence forever.
        src = _replace_once(
            src,
            "        if len(self.slots) < self.k:\n",
            "        if True:\n",
        )
    elif args.mutate == "hash-the-stdout":
        # The obvious wrong instrument: digest the raw output.  Reads as new
        # evidence on every run that prints a port, a nonce or a timestamp.
        src = _replace_once(
            src,
            '        interners["exc"].id(last_exception_class(sandbox.get("stderr"))),\n',
            '        interners["exc"].id(str(sandbox.get("stdout") or "")\n'
            '                            + str(sandbox.get("stderr") or "")),\n',
        )
    elif args.mutate == "exc-message":
        # Keep the whole exception LINE instead of its class.  A counter in the
        # message then buys an iteration every round.
        src = _replace_once(
            src,
            "    matches = _EXC_LINE_RE.findall(str(stderr)[-4000:])\n"
            "    return matches[-1] if matches else \"\"\n",
            "    tail = str(stderr)[-4000:].strip().splitlines()\n"
            "    return tail[-1] if tail else \"\"\n",
        )
    elif args.mutate == "saturation-is-novel":
        # Let a saturated point refund.  The interner then becomes decorative:
        # OTHER paired with any varying field keeps minting new points.
        src = _replace_once(
            src,
            "    novel = (key not in seen) and not saturated\n",
            "    novel = key not in seen\n",
        )
    elif args.mutate == "changed-since-last":
        # The weaker reading of novelty.  An A,B,A,B oscillation between two
        # dead branches then refunds forever.
        src = _replace_once(
            src,
            "    novel = (key not in seen) and not saturated\n",
            "    novel = (not seen or seen[-1] != key) and not saturated\n",
        )
    elif args.mutate == "drop-gate-reason":
        src = _replace_once(
            src,
            "        gate_reason if gate_reason in GATE_REASONS else None,\n",
            "        None,\n",
        )
    elif args.mutate == "drop-flag-channel":
        src = _replace_once(
            src,
            '        interners["flag"].id(flag_candidate_key(flags)),\n',
            '        "",\n',
        )
    elif args.mutate == "plan-budget-unbounded":
        src = _replace_once(
            src,
            '        ledger["plan_budget"] = int(ledger.get("plan_budget", B1)) - 1\n',
            '        ledger["plan_budget"] = B1\n',
        )
    elif args.mutate == "plan-gate-not-budget":
        # Revert P1 to a per-hint GATE.  Measured, its only demonstrated
        # behaviour was a false stop on a reviewer legitimately narrowing a
        # previous plan, so this must cost a named check.
        src = _replace_once(
            src,
            "    if covered:\n"
            '        ledger["plan_budget"] = int(ledger.get("plan_budget", B1)) - 1\n',
            "    if covered:\n"
            '        ledger["plan_budget"] = 0\n',
        )
    return src


def _load(source: str, name: str, filename: str):
    module = types.ModuleType(name)
    module.__file__ = filename
    sys.modules[name] = module
    exec(compile(source, filename, "exec"), module.__dict__)
    return module


E = _load(
    _mutated_source(),
    "_evidence_budget_under_test",
    str(ROOT / "modules" / "_evidence.py"),
)

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


def _set_literals(path: Path) -> dict:
    """Module-level `NAME = {...}` string-set literals, without importing.

    Returns {} rather than raising if the file cannot be parsed — a caller that
    then compares against a missing key fails by NAME, which is the point.
    """
    import ast  # noqa: PLC0415

    out: dict = {}
    try:
        tree = ast.parse(path.read_text())
    except (OSError, SyntaxError):
        return out
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        if not isinstance(node.value, ast.Set):
            continue
        values = set()
        ok = True
        for element in node.value.elts:
            if isinstance(element, ast.Constant) and isinstance(
                element.value, str
            ):
                values.add(element.value)
            else:
                ok = False
                break
        if ok:
            out[target.id] = values
    return out


def _fresh_interners():
    return {
        "exc": E.Interner(E.K_EXC),
        "pj": E.Interner(E.K_PJ),
        "flag": E.Interner(E.K_FLAG),
    }


def _point(ledger, sandbox, *, ran=True, verdict="partial",
           gate_reason="no_capture_evidence", flags=()):
    """Build a point through the ledger's own (persisted) interner state."""
    interners = E._interners(ledger)
    pt = E.evidence_point(
        sandbox, ran=ran, verdict=verdict, gate_reason=gate_reason,
        flags=list(flags), interners=interners,
    )
    E._save_interners(ledger, interners)
    return pt


def _drive(sandboxes, **kw):
    """Feed a sequence of sandbox dicts; return the per-iteration verdicts."""
    ledger = E.new_ledger()
    out = []
    for s in sandboxes:
        out.append(E.observe(ledger, _point(ledger, s, **kw)))
    return ledger, out


def _stop_iteration(results) -> int | None:
    """1-based index of the first iteration at which progress went False."""
    for i, r in enumerate(results, 1):
        if not r["progress"]:
            return i
    return None


# ------------------------------------------------------------- A: the alphabet

def _alphabet_checks() -> None:
    size = E.alphabet_size()
    check("A1 the alphabet is finite and printable",
          isinstance(size, int) and 0 < size < 10 ** 12, True)
    check("A1 the iteration bound is B*(|E|+1)",
          E.max_iterations(), E.B * (size + 1))

    # The domains are COPIES of _judge's.  Copied to keep _evidence free of SDK
    # imports; asserted equal so the copy cannot silently drift.
    #
    # Read with `ast` rather than imported: modules/_judge.py imports
    # claude_agent_sdk at module scope, which is absent from the dev shell, and
    # stubbing it here would mean this check passes against a stub rather than
    # against the real file.  Parsing keeps it hermetic AND authoritative.
    judge_sets = _set_literals(ROOT / "modules" / "_judge.py")
    check("A2 the verdict domain matches _judge exactly",
          set(E.VALID_VERDICTS), judge_sets.get("_VALID_VERDICTS"))
    check("A2 the heap failure-code domain matches _judge exactly",
          set(E.VALID_HEAP_FAILURE_CODES),
          judge_sets.get("_VALID_HEAP_FAILURE_CODES"))

    # ...and the gate-reason mirror matches the four literals the loop assigns.
    common_src = (ROOT / "modules" / "_common.py").read_text()
    for reason in sorted(E.GATE_REASONS):
        check(f"A2 gate_reason {reason!r} is really assigned by the loop",
              f'gate_reason = "{reason}"' in common_src, True)


# ------------------------------------------------------- B: bounded interning

def _interner_checks() -> None:
    it = E.Interner(3)
    check("B1 absent value interns to empty", it.id(""), "")
    check("B1 first distinct values get slots",
          [it.id("a"), it.id("b"), it.id("c")], ["s0", "s1", "s2"])
    check("B1 a repeat returns the same slot", it.id("a"), "s0")
    check("B2 the (K+1)th distinct value saturates", it.id("d"), E.OTHER)
    check("B2 ...and so does every one after it",
          [it.id("e"), it.id("f")], [E.OTHER, E.OTHER])
    check("B2 saturation does not evict an existing slot", it.id("b"), "s1")

    # The interner state must survive the JSON round-trip through `summary`,
    # or every iteration starts fresh and nothing ever saturates.
    revived = E.Interner(3, it.to_state())
    check("B3 interner state round-trips",
          [revived.id("a"), revived.id("zzz")], ["s0", E.OTHER])


# -------------------------------------------------- C: volatility cannot pay

# SHAPES taken from real solver output, VALUES synthetic.  This repository is
# public and these fixtures would otherwise be job-derived text; the checks
# depend on the shape (a counter that moves, a line number that shifts, a
# host:port and instance id that rotate) and not on any real value, so nothing
# is lost by inventing them.
#
# The shape matters because it is exactly what killed the earlier designs: a
# solver that reports its own attempt count, a traceback whose line numbers
# move when the agent edits anything above, and a per-instance endpoint that
# is different on every provisioning.
_ROT_STDERR_A = (
    'Traceback (most recent call last):\n'
    '  File "solver.py", line 217, in <module>\n'
    '    main()\n'
    '  File "solver.py", line 210, in main\n'
    'RuntimeError: no flag after 1368 valid sessions/1380 attempts\n'
)
_ROT_STDERR_B = (
    'Traceback (most recent call last):\n'
    '  File "solver.py", line 231, in <module>\n'
    '    main()\n'
    '  File "solver.py", line 224, in main\n'
    'RuntimeError: no flag after 1402 valid sessions/1415 attempts\n'
)
_ROT_STDOUT_A = (
    "[*] connecting to node7.example.invalid:17690\n"
    "[*] instance aaaa0000bbbb ready\n[!] no flag\n"
)
_ROT_STDOUT_B = (
    "[*] connecting to node2.example.invalid:20411\n"
    "[*] instance cccc1111dddd ready\n[!] no flag\n"
)


def _volatility_checks() -> None:
    check("C1 only the exception CLASS is taken, not its message",
          E.last_exception_class(_ROT_STDERR_A), "RuntimeError")
    check("C1 ...so a run-dependent counter does not change it",
          E.last_exception_class(_ROT_STDERR_A),
          E.last_exception_class(_ROT_STDERR_B))

    led = E.new_ledger()
    a = _point(led, {"exit_code": 1, "stdout": _ROT_STDOUT_A,
                     "stderr": _ROT_STDERR_A})
    b = _point(led, {"exit_code": 1, "stdout": _ROT_STDOUT_B,
                     "stderr": _ROT_STDERR_B})
    check("C2 a rotating host:port and instance id cannot buy an iteration",
          E._canon(a), E._canon(b))
    check("C2 ...and neither can a shifted traceback line number",
          E._canon(a), E._canon(b))

    # The whole point of enumerating signal: stdout is not a field at all.
    led2 = E.new_ledger()
    _point(led2, {"exit_code": 1, "stdout": "x" * 5000})
    _point(led2, {"exit_code": 1, "stdout": "y" * 5000})
    check("C3 stdout contributes no channel to the point",
          len(led2["interners"]["exc"]), 0)


# ------------------------------------------------------ D: termination proper

def _E(tag: str) -> dict:
    """Two sandbox dicts that differ ONLY in a field the point actually reads."""
    return {"exit_code": 1, "stderr": f"{tag}Error: boom\n"}


def _termination_checks() -> None:
    # Paraphrase x5: five rewordings of one mechanism, evidence unmoved.
    same = [_E("Value") for _ in range(6)]
    led, res = _drive(same)
    check("D1 an unmoving evidence point refunds once then drains",
          [r["budget"] for r in res[:4]], [E.B, E.B - 1, E.B - 2, E.B - 3])
    check("D1 paraphrase terminates, and at the budget's own depth",
          _stop_iteration(res), E.B + 1)

    # Oscillation A,B,A,B,A between two dead branches.  Novelty is
    # never-before-seen, so the third A is a repeat, not a change.
    osc = [_E("Value"), _E("Type"), _E("Value"), _E("Type"), _E("Value"),
           _E("Type")]
    led, res = _drive(osc)
    check("D2 an A,B,A,B oscillation terminates",
          _stop_iteration(res) is not None, True)
    check("D2 ...after both real members have run, not before",
          _stop_iteration(res), 5)

    # Two-case requirement.  Both hold exit_code constant and vary only
    # gate_reason, so an implementation that merely diffs the exit code passes
    # one and fails the other.
    led_a = E.new_ledger()
    res_a = [E.observe(led_a, _point(led_a, {"exit_code": 1},
                                     gate_reason="no_capture_evidence"))
             for _ in range(4)]
    led_b = E.new_ledger()
    reasons = ["no_capture_evidence", "no_capture_evidence",
               "weak_flag_evidence", "no_capture_evidence"]
    res_b = [E.observe(led_b, _point(led_b, {"exit_code": 1},
                                     gate_reason=r)) for r in reasons]
    check("D3 four identical states stop at the fourth", _stop_iteration(res_a), 4)
    check("D3 a distinct state in the middle goes further",
          _stop_iteration(res_b), None)
    check("D3 ...and the two cases genuinely differ",
          _stop_iteration(res_a) != _stop_iteration(res_b), True)

    # The expensive false negative: three dead mechanisms failing identically,
    # then a real one on round 4.  Round 4 must RUN.
    led_c = E.new_ledger()
    res_c = []
    for i in range(4):
        flags = ["DH{late_but_real}"] if i == 3 else []
        res_c.append(E.observe(
            led_c, _point(led_c, {"exit_code": 1}, flags=flags)))
    check("D4 a real idea on round 4 is still reached",
          [r["progress"] for r in res_c[:3]], [True, True, True])
    check("D4 ...and its new evidence refunds the budget in full",
          res_c[3]["budget"], E.B)

    # Saturation is the load-bearing rule.  A field that has collapsed can
    # never refund, or the interner is decorative.
    led_d = E.new_ledger()
    pts = []
    for i in range(E.K_EXC + 3):
        pts.append(_point(led_d, {"exit_code": 1,
                                  "stderr": f"Custom{i}Error: x\n"}))
    check("D5 the exception channel saturates once past K",
          E.is_saturated(pts[-1]), True)
    led_e = E.new_ledger()
    res_e = [E.observe(led_e, p) for p in pts]
    check("D5 a saturated point never counts as novel",
          any(r["novel"] and r["saturated"] for r in res_e), False)
    check("D5 ...so an unbounded field cannot keep a run alive",
          _stop_iteration(res_e) is not None, True)

    # Fail-open, and narrowly: this predicate REPLACES a hard one-per-job cap,
    # so an absent ledger must not be stricter than what it replaced.
    check("D6 a missing ledger reads as progress", E.evidence_progress(None), True)
    check("D6 an exhausted ledger does not",
          E.evidence_progress({"budget": 0}), False)


# ------------------------------------------------------------------ F: plans

def _plan_checks() -> None:
    vocab = {"tcache", "unsorted", "bin", "exploit.py", "main_arena"}
    hint_a = ("CLASS: STRATEGY\nNEXT: attack the tcache freelist in "
              "exploit.py by corrupting main_arena")
    # Same class, same grounded anchors, every word different.
    hint_b = ("CLASS: STRATEGY\nNEXT: corrupt main_arena via the tcache "
              "structure that exploit.py already reaches")
    ka = E.plan_key(hint_a, "STRATEGY", vocab)
    kb = E.plan_key(hint_b, "STRATEGY", vocab)
    check("F1 a pure paraphrase yields the same plan key", ka, kb)

    led = E.new_ledger()
    first = E.observe_plan(led, ka)
    check("F1 the first plan is recorded, not charged", first["covered"], False)
    charged = [E.observe_plan(led, kb) for _ in range(E.B1)]
    check("F1 ...and repeats drain the plan budget",
          charged[-1]["progress"], False)
    check("F1 the paraphrase stops on the PLAN budget, evidence untouched",
          E.evidence_progress(led), True)

    # A genuinely different mechanism refunds.
    led2 = E.new_ledger()
    E.observe_plan(led2, ka)
    other = E.plan_key("CLASS: STRATEGY\nNEXT: try the unsorted bin instead",
                       "STRATEGY", vocab)
    check("F2 a different mechanism is not covered",
          E.observe_plan(led2, other)["covered"], False)
    check("F2 ...and restores the plan budget in full",
          led2["plan_budget"], E.B1)

    # A class change alone is enough to be a different plan.
    led3 = E.new_ledger()
    E.observe_plan(led3, ka)
    check("F3 the same anchors under a different CLASS is a new plan",
          E.observe_plan(led3, E.plan_key(hint_a, "IMPLEMENTATION", vocab))
          ["covered"], False)

    # Grounding: tokens the reviewer invented are not shared ground.
    check("F4 anchors are kept to the evidence vocabulary",
          E.extract_anchors("attack the frobnicator in exploit.py", vocab),
          frozenset({"exploit.py"}))
    check("F4 two hints sharing only invented tokens are not the same plan",
          E.plan_key("use the frobnicator", "STRATEGY", vocab)
          != E.plan_key("use the tcache", "STRATEGY", vocab), True)

    # P1 is a BUDGET, not a gate: one narrowing hint must not end a run.
    # Measured, a per-hint gate's only demonstrated behaviour was this false
    # stop.
    led4 = E.new_ledger()
    E.observe_plan(led4, ka)
    narrowed = E.observe_plan(led4, ka)
    check("F5 one repeat does not end the run on its own",
          narrowed["progress"], True)


# ================================================================ integration
#
# The checks above prove the instrument terminates.  They cannot prove the LOOP
# reads it.  A field that is filled and never consumed is this project's
# standing failure mode, so every predicate below is exercised through the real
# run_main_agent_session.

COMMON_SOURCE = (ROOT / "modules" / "_common.py").read_text()


def _mutated_common() -> str:
    src = COMMON_SOURCE
    if args.mutate == "drop-observe-call":
        src = _replace_once(
            src,
            "                _ev = _evidence.observe("
            'summary["evidence_ledger"], _ev_point)\n',
            "                _ev = {'novel': True, 'saturated': False,\n"
            "                       'budget': _evidence.B, 'progress': True}\n",
        )
    elif args.mutate == "restore-mc-one-shot":
        # The bound this work removed: one method-change conversion per job.
        src = _replace_once(
            src,
            "                if (judge_out.get(\"retry_worthwhile\")\n"
            "                        and _ev_ok and (_mc_hint or _mc_alt)\n",
            "                if (judge_out.get(\"retry_worthwhile\")\n"
            "                        and _mc_n < 1 and (_mc_hint or _mc_alt)\n",
        )
    elif args.mutate == "ignore-evidence-budget":
        # Keep the ledger, ignore what it says — the "filled but never read"
        # failure this section exists to catch.
        src = _replace_once(
            src,
            "                _ev_ok = _evidence.evidence_progress(_ev_ledger)\n",
            "                _ev_ok = True\n",
        )
    elif args.mutate == "override-keeps-judge-verdict":
        # The defect this suite scored 59/0 against: the override leaves the
        # judge's own verdict on the dict, so the provenance lookup falls to
        # its default and main is told a reviewer's plan came from postjudge.
        src = _replace_once(
            src,
            '                        judge_out["verdict"] = "reviewer_override"\n',
            "                        pass\n",
        )
    elif args.mutate == "override-without-alternatives":
        # Let the reviewer contest a STOP the judge said was exhaustive.
        # "Empty list if exhaustively tried" is the judge's one preserved
        # authority; removing it makes the override unconditional.
        src = _replace_once(
            src,
            "                elif (_mc_alt and _ev_ok and _plan_ok\n",
            "                elif (_ev_ok and _plan_ok\n",
        )
    return src


INTEGRATION_MUTATIONS = (
    "drop-observe-call",
    "restore-mc-one-shot",
    "ignore-evidence-budget",
    "override-without-alternatives",
    "override-keeps-judge-verdict",
)

REVIEWER_CALLS: list = []
REVIEWER_OUTCOMES: list = []


class _ReviewerError(Exception):
    def __init__(self, message: str, kind: str = "api_error"):
        super().__init__(message)
        self.kind = kind


def _install_reviewer_stub() -> None:
    def _ctx(*, roots):
        REVIEWER_CALLS.append({"roots": tuple(roots)})
        return ("reviewer fixture context mentioning tcache and exploit.py "
                "and main_arena")

    async def _ask(context, *, model=None, job_id=None):
        outcome = REVIEWER_OUTCOMES.pop(0) if REVIEWER_OUTCOMES else (
            "CLASS: STRATEGY\nNEXT: attack the tcache freelist via exploit.py"
        )
        if isinstance(outcome, BaseException):
            raise outcome
        return str(outcome)

    stub = types.ModuleType("modules.reviewer")
    stub.ReviewerError = _ReviewerError
    stub._gather_context = _ctx
    stub._ask_reviewer_with_failover = _ask
    stub._sanitize_hint = lambda t: str(t).replace("exfiltrate", "report back")
    sys.modules["modules.reviewer"] = stub


def _install_sdk_stub() -> None:
    if "claude_agent_sdk" in sys.modules:
        return
    stub = types.ModuleType("claude_agent_sdk")
    for nm in ("AssistantMessage", "ClaudeAgentOptions", "ResultMessage",
               "SystemMessage", "TextBlock", "ClaudeSDKClient", "UserMessage"):
        setattr(stub, nm, type(nm, (), {}))

    async def _q(*_a, **_k):
        if False:
            yield None

    stub.query = _q
    stub.HookMatcher = type("HookMatcher", (), {
        "__init__": lambda self, **kw: None})
    stub.AgentDefinition = type("AgentDefinition", (), {
        "__init__": lambda self, **kw: None})
    stub.create_sdk_mcp_server = lambda *a, **k: None
    stub.tool = lambda *a, **k: (lambda fn: fn)
    stub.project_key_for_directory = lambda *a, **k: ""
    sys.modules["claude_agent_sdk"] = stub


class _ResultMessage:
    duration_ms = 10
    num_turns = 1
    total_cost_usd = 0.25
    is_error = False
    stop_reason = None


class _Options:
    system_prompt = "system"
    model = "claude-opus-5"
    cwd = "/tmp"
    effort = None
    env = {}
    resume = None
    add_dirs = []


def _judged(hint, *, action="continue", verdict="partial", alts=None,
            worthwhile=False, stderr="ValueError: boom\n", exit_code=1):
    out = {
        "exit_code": exit_code,
        "stdout": "",
        "stderr": stderr,
        "sandbox_started": True,
        "judge_mode": "enforce",
        "judge": {
            "verdict": verdict,
            "next_action": action,
            "retry_hint": hint,
            "summary": "no capture",
            "stop_reason": "the chain cannot work" if action == "stop" else "",
        },
    }
    if alts is not None:
        out["judge"]["alternative_paths"] = list(alts)
    if worthwhile:
        out["judge"]["retry_worthwhile"] = True
    return out


def _run_loop(name: str, results: list, *, reviewer=None):
    import asyncio  # noqa: PLC0415
    import tempfile  # noqa: PLC0415

    _install_sdk_stub()
    _install_reviewer_stub()
    REVIEWER_CALLS.clear()
    REVIEWER_OUTCOMES[:] = list(reviewer or [])

    if "anyio" not in sys.modules:
        anyio = types.ModuleType("anyio")

        class _ToThread:
            @staticmethod
            async def run_sync(fn, *a):
                return fn(*a)

        anyio.to_thread = _ToThread()
        sys.modules["anyio"] = anyio

    C = _load(_mutated_common(), f"_evb_common_{name}",
              str(ROOT / "modules" / "_common.py"))
    import claude_agent_sdk as sdk  # noqa: PLC0415
    sdk.ResultMessage = _ResultMessage
    sdk.AssistantMessage = type("AssistantMessage", (), {"content": []})
    sdk.UserMessage = type("UserMessage", (), {"content": []})

    temp = tempfile.TemporaryDirectory(prefix=f"evb-{name}-")
    root = Path(temp.name)
    work = root / "work"
    work.mkdir()
    (work / "exploit.py").write_text("print('a0')\n")
    (work / "report.md").write_text("# fixture\n")
    meta = {"id": name, "module": "pwn", "target_url": "live.example:1337",
            "description": "chal", "agent_turns": 5, "cost_usd": 0.0}
    logs: list = []
    queries: list = []
    idx = {"v": 0}
    recv = {"v": 0}

    import modules.agent_provider as providers  # noqa: PLC0415
    providers.ensure_provider_ready = lambda requested=None: "claude"
    providers.provider_display_name = lambda p: "Claude"
    providers.provider_meta_fields = lambda p: {"agent_provider": p}
    C.read_meta = lambda _j: dict(meta)
    C.write_meta = lambda _j, **f: meta.update(f)
    C.job_dir = lambda _j: root
    C.emit_event = lambda *a, **k: None
    # THE TRAP the design named: leaving this at a positive N proves the
    # COUNTER terminated, not the budget.  -1 is the shipped default
    # (AUTO_RETRY_MAX, modules/_common.py) and it means unlimited.
    C.auto_retry_max = lambda: -1
    C.budget_exceeded = lambda *a, **k: False
    C.capture_session_id = lambda *a, **k: None
    C.agent_heartbeat = lambda *a, **k: None
    C.record_rate_limit_event = lambda *a, **k: None
    C.log_assistant_blocks = lambda *a, **k: None
    C.log_user_blocks = lambda *a, **k: None
    C.scan_job_for_flags = lambda _j, **kw: (
        kw.get("provenance_out", {}).update({"tier": ""}) or []
    )

    class _Client:
        def __init__(self, **_k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return False

        async def query(self, prompt):
            queries.append(str(prompt))

        async def receive_response(self):
            recv["v"] += 1
            (work / "exploit.py").write_text(f"print('a{recv['v']}')\n")
            yield _ResultMessage()

    sdk.ClaudeSDKClient = _Client

    def _sandbox(_script):
        i = idx["v"]
        idx["v"] += 1
        if i >= len(results):
            raise AssertionError(f"unexpected sandbox call {i + 1}")
        return dict(results[i])

    summary = {"model": "claude-opus-5"}
    escaped = None
    try:
        asyncio.run(C.run_main_agent_session(
            name, options=_Options(), initial_prompt="solve", summary=summary,
            work_dir=work, artifact_names=("exploit.py",), auto_run=True,
            sandbox_runner=_sandbox, log_fn=logs.append,
        ))
    except BaseException as exc:
        escaped = f"{type(exc).__name__}: {exc}"
    why = (work / "WHY_STOPPED.md")
    out = {
        "escaped": escaped,
        "summary": dict(summary),
        "meta": dict(meta),
        "logs": list(logs),
        "queries": list(queries),
        "sandbox_calls": idx["v"],
        "reviewer_calls": len(REVIEWER_CALLS),
        "why": why.read_text() if why.is_file() else "",
    }
    temp.cleanup()
    return out


def _integration_checks() -> None:
    # G1 — the loop actually scores each executing iteration.  Identical
    # evidence every round, judge votes continue, no counter in play.
    same = [_judged("fix it") for _ in range(8)]
    g1 = _run_loop("drain", same)
    ledger = g1["summary"].get("evidence_ledger") or {}
    check("G1 the loop escapes cleanly", g1["escaped"], None)
    check("G1 every executing iteration is scored",
          len(ledger.get("log") or []) >= 2, True)
    check("G1 repeated evidence drains the budget",
          (ledger.get("log") or [{}])[-1].get("budget", E.B) < E.B, True)
    check("G1 the budget is logged where the operator can read it",
          any("evidence budget:" in ln for ln in g1["logs"]), True)

    # G2 — the operator's actual request.  Judge STOPs, names untried paths,
    # budget positive: the reviewer answers and the job CONTINUES.
    g2 = _run_loop("override", [
        _judged("", action="stop", alts=["try the unsorted bin instead"]),
        _judged("fix it"),
        _judged("fix it"),
    ])
    check("G2 a judge STOP naming untried paths consults the reviewer",
          g2["reviewer_calls"], 1)
    check("G2 ...and the job continues instead of halting",
          g2["sandbox_calls"] >= 2, True)
    check("G2 ...in the SAME job, via the shared inject tail",
          any("continuing IN THIS JOB" in ln for ln in g2["logs"]), True)
    check("G2 the override is counted",
          g2["summary"].get("judge_stop_overrides"), 1)
    # PROVENANCE.  main grades a hint's authority by who wrote it, and the only
    # signal _format_postjudge_user_turn has is the verdict on the judge dict.
    # Left at the judge's own verdict, the lookup falls to its default and
    # tells main "postjudge — apply this" about a plan the judge voted
    # AGAINST.  That mislabelling class is recorded in production as having
    # corrupted 13 of 23 real injections, and this suite scored 59/0 while the
    # defect was live — the checks above all pass on a mislabelled hint.
    _inj = (g2["summary"].get("injected_turns") or [])
    _ovr_inj = [t for t in _inj if t.get("verdict") == "reviewer_override"]
    check("G2 the injection records the reviewer as the producer",
          len(_ovr_inj), 1)
    check("G2 ...and main is told it came from the reviewer, not postjudge",
          (_ovr_inj[0].get("hint_source") if _ovr_inj else None), "reviewer")
    check("G2 ...and is told WHY there are two opposed opinions",
          "voted stop" in ((_ovr_inj[0].get("hint_origin") or "")
                           if _ovr_inj else ""), True)
    # Both provenance tables must carry the sentinel. They cannot be shared —
    # the formatter's copy is function-local on purpose — so a new producer
    # has been missed in the second one before.
    _csrc = COMMON_SOURCE
    check("G2 the sentinel is registered in the formatter's table",
          '"reviewer_override": (' in _csrc, True)
    check("G2 ...and in the WHY_STOPPED/RESUME_STATE table",
          '"reviewer_override": "a reviewer overriding' in _csrc, True)
    # ...and it must NOT be a real judge verdict, or the lookup stops
    # identifying producers.
    check("G2 the sentinel is not a real judge verdict",
          "reviewer_override" in E.VALID_VERDICTS, False)

    # G3 — the judge's preserved authority.  "Empty list if exhaustively
    # tried" still ends the run, with no reviewer spend.
    g3 = _run_loop("exhaustive", [
        _judged("", action="stop", alts=[]),
    ])
    check("G3 an empty alternative_paths still halts",
          "judge_stop" in g3["why"] or "Judge ruled" in g3["why"], True)
    check("G3 ...without spending a reviewer turn", g3["reviewer_calls"], 0)

    # G4 — the reviewer cannot answer.  Today's behaviour must stand.
    g4 = _run_loop(
        "revfail",
        [_judged("", action="stop", alts=["something untried"])],
        reviewer=[_ReviewerError("provider down", "api_error")],
    )
    check("G4 a reviewer failure leaves the judge's STOP standing",
          "Judge ruled" in g4["why"] or "judge_stop" in g4["why"], True)
    check("G4 ...and records only the failure kind",
          g4["summary"].get("reviewer_error_kind"), "api_error")

    # G5 — the ledger reaches WHY_STOPPED, which is the only way B and the
    # interner capacities can ever be re-derived from live jobs.
    check("G5 the evidence table is rendered into WHY_STOPPED",
          "Evidence budget" in g3["why"], True)
    check("G5 ...and carries no flag candidates or volatile values",
          "DH{" in g3["why"] or "dreamhack" in g3["why"], False)

    # G6 — the method-change conversion is no longer one-per-job.  Two STOPs
    # with retry_worthwhile, distinct evidence between them so the budget
    # stays positive; both must convert.
    g6 = _run_loop("mc2", [
        _judged("swap the method", action="stop", worthwhile=True,
                alts=["method A"], stderr="ValueError: x\n"),
        _judged("swap again", action="stop", worthwhile=True,
                alts=["method B"], stderr="KeyError: y\n"),
        _judged("fix it", stderr="IndexError: z\n"),
    ])
    check("G6 a second method-change conversion is reachable",
          g6["summary"].get("method_change_retries", 0) >= 2, True)

    # G7 — the budget must actually SHUT the door, not merely be recorded.
    # Identical evidence until the budget is gone, then a judge STOP naming
    # untried paths: with no budget the reviewer must not be consulted, and
    # the stop must say the exploration ran out rather than blaming the judge.
    #
    # This is the check that separates "the ledger exists" from "the ledger
    # decides", which is the difference this project keeps getting wrong.
    drain = [_judged("fix it") for _ in range(E.B + 1)]
    drain.append(_judged("", action="stop", alts=["a path never tried"]))
    g7 = _run_loop("gated", drain)
    check("G7 an exhausted budget stops the run",
          g7["escaped"], None)
    check("G7 ...naming the exploration, not the judge",
          "evidence_exhausted" in g7["why"]
          or "stopped reaching states" in g7["why"], True)
    check("G7 ...and does not spend a reviewer turn it cannot afford",
          g7["reviewer_calls"], 0)
    # The two G-cases must differ: G2 continued on a fresh budget, G7 stopped
    # on an exhausted one, with the SAME judge input shape.  One case alone is
    # satisfiable by always-continue or always-stop.
    check("G7 the gated and ungated cases genuinely differ",
          (g2["reviewer_calls"], g7["reviewer_calls"]), (1, 0))


def main() -> int:
    _alphabet_checks()
    _interner_checks()
    _volatility_checks()
    _termination_checks()
    _plan_checks()
    _integration_checks()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
