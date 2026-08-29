#!/usr/bin/env python3
"""The auto-retry loop must say something true every time it stops.

Four independently verified defects, each of which made the loop end while
telling the operator (or the next job) something the code could not know:

  T1  A sandbox_runner that RAISED returned with no WHY_STOPPED at all — the
      one exit in the loop that recorded nothing.  Every extra iteration the
      reviewer work buys makes this handler more reachable.
  T2  ...and it must NOT stamp judge_next_action="stop" while doing so.
      api/routes/retry.py:569 reads that field to SKIP the SDK session fork.
      A docker fault says nothing about the transcript; shedding a good
      conversation over one is a pure loss.
  T3  `summary["judge_hints"]` — the judge's own anti-repeat record, rendered
      into its prompt by modules/_runner.py as "your new hint MUST NOT rhyme
      with these" — only ever held POSTJUDGE hints.  The prejudge redirect,
      runner_crash and reviewer producers all write last_sandbox["judge"]
      AFTER the append site, and last_sandbox is reassigned wholesale by the
      next sandbox call, so their hints were delivered to main and then
      destroyed unseen.
  T4  `retry_hint_ignored` asserted intent ("main ignored retry_hint") that
      identical bytes cannot establish, and write_meta persisted it as
      judge_stop_reason for /retry to carry into the next job as fact.
      _STOP_KIND_HEADERS already learned this for the heading after job
      df7dd1b4a9e8; the stop_reason kept the accusation.  The reviewer's own
      CLASS: label decides which reading is fair.

Run from the repository root::

    python3 scripts/test_stop_truthfulness.py
    python3 scripts/test_stop_truthfulness.py --mutate drop-runner-why-stopped
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Match the other offline suites: stub only import-time SDK shapes.  The loop
# below installs the concrete fake client it actually executes.
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

MUTATIONS = (
    "drop-runner-why-stopped",
    "stamp-stop-on-runner-error",
    "drop-delivered-hint-record",
    "record-hint-at-producer",
    "class-blind",
    "class-anywhere",
    "revert-ignored-libel",
    "unlabelled-is-investigative",
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
    common = COMMON_SOURCE
    if args.mutate == "drop-runner-why-stopped":
        # The historical behaviour: log one line, return, record nothing.
        # Swap the call for a no-op rather than commenting it out, so the
        # mutation stays syntactically valid — an aborted run is not a
        # measurement, it is a broken mutation.
        common = _replace_once(
            common,
            "                    write_why_stopped(\n"
            "                        work_dir,\n"
            '                        stop_kind="sandbox_runner_error",\n',
            "                    (lambda *a, **k: None)(\n"
            "                        work_dir,\n"
            '                        stop_kind="sandbox_runner_error",\n',
        )
    elif args.mutate == "stamp-stop-on-runner-error":
        common = _replace_once(
            common,
            "                    write_meta(\n"
            "                        job_id,\n"
            '                        judge_stop_reason=summary["sandbox_runner_error"],\n',
            "                    write_meta(\n"
            "                        job_id,\n"
            '                        judge_next_action="stop",\n'
            '                        judge_stop_reason=summary["sandbox_runner_error"],\n',
        )
    elif args.mutate == "drop-delivered-hint-record":
        common = _replace_once(
            common,
            "            if _delivered_hint and (\n"
            "                not _hints_so_far or _hints_so_far[-1] != _delivered_hint\n"
            "            ):\n",
            "            if False and _delivered_hint and (\n"
            "                not _hints_so_far or _hints_so_far[-1] != _delivered_hint\n"
            "            ):\n",
        )
    elif args.mutate == "record-hint-at-producer":
        # Records the hint the REAL judge emitted rather than the one actually
        # delivered — i.e. reverts to the pre-fix semantics while still
        # appending something, so a test that only counts entries stays green.
        common = _replace_once(
            common,
            "            _delivered_hint = (\n"
            '                ((last_sandbox or {}).get("judge") or {}).get("retry_hint") or ""\n'
            "            ).strip()\n",
            "            _delivered_hint = (\n"
            '                (summary.get("judge_hints") or [""])[-1]\n'
            "            ).strip()\n",
        )
    elif args.mutate == "class-blind":
        common = _replace_once(
            common,
            "    match = _HINT_CLASS_RE.search(str(hint)[:4000])\n"
            "    return match.group(1) if match else \"\"\n",
            "    return \"\"\n",
        )
    elif args.mutate == "class-anywhere":
        # Drops the line anchor, so prose that merely MENTIONS a class name is
        # read as a declaration.
        common = _replace_once(
            common,
            r'    r"^[ \t]*CLASS:[ \t]*(IMPLEMENTATION|STRATEGY|ENVIRONMENT|UNKNOWN)\b",'
            "\n",
            r'    r"(IMPLEMENTATION|STRATEGY|ENVIRONMENT|UNKNOWN)",' "\n",
        )
    elif args.mutate == "revert-ignored-libel":
        common = _replace_once(
            common,
            '                        f"{picked} unchanged after a {_last_class}-class "',
            '                        f"main ignored retry_hint — {picked} unchanged "\n'
            '                        f"XX-{_last_class}-XX "',
        )
    elif args.mutate == "unlabelled-is-investigative":
        # Fail-OPEN instead of fail-closed: an absent CLASS would excuse an
        # unchanged script after an ordinary postjudge fix hint.
        common = _replace_once(
            common,
            '_INVESTIGATIVE_HINT_CLASSES = frozenset({"STRATEGY", "ENVIRONMENT", "UNKNOWN"})',
            '_INVESTIGATIVE_HINT_CLASSES = frozenset('
            '{"STRATEGY", "ENVIRONMENT", "UNKNOWN", ""})',
        )
    return common


def _load(source: str, name: str, filename: str):
    module = types.ModuleType(name)
    module.__file__ = filename
    sys.modules[name] = module
    exec(compile(source, filename, "exec"), module.__dict__)
    return module


C = _load(
    _mutated_source(),
    "_stop_truthfulness_common",
    str(ROOT / "modules" / "_common.py"),
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


def _block(issues: list) -> dict:
    """A prejudge ship-block: no judge key, so the upstream append sees nothing.

    flag_likelihood stays well above the concede-unsolvable threshold (0.05)
    and target_liveness is live, so the loop takes the ordinary redirect
    branch rather than escalating.
    """
    return {
        "error": "prejudge_blocked",
        "prejudge": {
            "ok": False,
            "severity": "high",
            "target_liveness": "live",
            "flag_likelihood": 0.4,
            "issues": issues,
        },
        "judge_aborted": True,
        "sandbox_started": False,
        "judge_mode": "enforce",
    }


def _fail(hint: str, *, verdict: str = "fail") -> dict:
    """An ordinary failed sandbox run whose postjudge votes continue."""
    return {
        "exit_code": 1,
        "stdout": "",
        "stderr": "no flag\n",
        "sandbox_started": True,
        "judge_mode": "enforce",
        "judge": {
            "verdict": verdict,
            "next_action": "continue",
            "retry_hint": hint,
            "summary": "no capture",
            "specific_diagnosis": "",
        },
    }


async def _run_case(
    name: str,
    sandbox_results: list,
    *,
    main_edits: bool = True,
) -> dict:
    """Drive the real loop.

    `sandbox_results` entries are dicts, or the RAISE sentinel to make the
    sandbox_runner itself throw — the T1/T2 case.  `main_edits=False` makes
    main return without touching the script, which is what arms the
    SHA-unchanged gate for T4.
    """
    sdk = _install_sdk()
    temp = tempfile.TemporaryDirectory(prefix=f"st-{name}-")
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
        "agent_turns": 12,
        "cost_usd": 0.0,
        "cost_usd_estimate": 1.5,
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
        if provenance_out is not None:
            provenance_out["tier"] = ""
        return []

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
            # Main applies the injected hint while producing the turn, not at
            # query submission time — the ordering the production
            # SHA-unchanged guard is written against.
            if main_edits and receives["value"] > 1:
                script.write_text(f"print('attempt-{receives['value'] - 1}')\n")
            yield _ResultMessage()

    sdk.ClaudeSDKClient = _Client

    def _sandbox(script_name: str):
        sandbox_calls.append(script_name)
        i = index["value"]
        index["value"] += 1
        if i >= len(sandbox_results):
            raise AssertionError(f"unexpected sandbox call {i + 1} for {name}")
        entry = sandbox_results[i]
        if entry is RAISE:
            raise RuntimeError("docker: cannot connect to daemon")
        return dict(entry)

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


RAISE = object()


# ---------------------------------------------------------------- unit: CLASS

def _hint_class_checks() -> None:
    hc = C.hint_class
    check("U1 IMPLEMENTATION is read",
          hc("CLASS: IMPLEMENTATION\nNEXT: fix line 11"), "IMPLEMENTATION")
    check("U1 STRATEGY is read",
          hc("CLASS: STRATEGY\nNEXT: two new hypotheses"), "STRATEGY")
    check("U1 ENVIRONMENT is read", hc("CLASS: ENVIRONMENT\n"), "ENVIRONMENT")
    check("U1 UNKNOWN is read", hc("CLASS: UNKNOWN\n"), "UNKNOWN")
    # The method-change conversion prepends a paragraph, so CLASS is not
    # always the first line.  It is still a declaration.
    check("U2 a CLASS line below a prepended paragraph still counts",
          hc("METHOD CHANGE REQUIRED (one-time conversion...)\n\n"
             "CLASS: STRATEGY\nNEXT: rebuild the decisive step"), "STRATEGY")
    # ...but the label must be DECLARED on its own line, not merely mentioned.
    # Postjudge hints discuss these words constantly: the live
    # _format_postjudge_user_turn text says "for an IMPLEMENTATION defect,
    # modify ./x; for a STRATEGY or UNKNOWN failure...".  Matching prose would
    # classify almost every hint.
    check("U3 prose that only MENTIONS a class is not a declaration",
          hc("First classify them as an IMPLEMENTATION defect (verified "
             "chain, broken code) or a STRATEGY/UNKNOWN defect."), "")
    check("U3 an inline mid-line CLASS: is not a declaration",
          hc("see CLASS: STRATEGY for details"), "")
    check("U4 absent label reads as empty, not as a guess", hc("NEXT: x"), "")
    check("U4 None is tolerated", hc(None), "")
    check("U4 empty is tolerated", hc(""), "")
    check("U5 an unrecognised class name is not accepted",
          hc("CLASS: MYSTERY\n"), "")
    # Bounded scan: a declaration past the budget is not found.  This pins the
    # bound itself, so removing it is a named failure rather than a silent
    # performance change.
    check("U6 the scan is bounded to the first 4000 chars",
          hc("x" * 4100 + "\nCLASS: STRATEGY\n"), "")
    check("U6 a declaration just inside the bound IS found",
          hc("x" * 3000 + "\nCLASS: STRATEGY\n"), "STRATEGY")
    # Fail-closed direction: the set that excuses an unchanged script must not
    # contain the empty label, or every unlabelled postjudge hint excuses one.
    check("U7 an absent label is NOT treated as investigative",
          "" in C._INVESTIGATIVE_HINT_CLASSES, False)
    check("U7 IMPLEMENTATION is NOT treated as investigative",
          "IMPLEMENTATION" in C._INVESTIGATIVE_HINT_CLASSES, False)
    check("U7 the three non-edit classes are",
          sorted(C._INVESTIGATIVE_HINT_CLASSES),
          ["ENVIRONMENT", "STRATEGY", "UNKNOWN"])


# ------------------------------------------------------- structural: registry

def _registration_checks() -> None:
    src = COMMON_SOURCE
    # A stop kind is only fully alive when all THREE registrations exist: the
    # headline table, a body branch in the WHY_STOPPED ladder, and a call site.
    # `retry_hint_ignored` is the standing precedent for the omission — it has
    # a header and a call site but no body branch, and falls to the generic
    # else.
    check("S1 sandbox_runner_error has a headline",
          '"sandbox_runner_error": (' in src, True)
    check("S1 sandbox_runner_error has a ladder branch",
          'elif stop_kind == "sandbox_runner_error":' in src, True)
    check("S1 sandbox_runner_error has a call site",
          'stop_kind="sandbox_runner_error",' in src, True)
    # The reviewer redirect log line described its own control flow backwards.
    # It is the ONLY run.log line naming that mechanism, so it is where a
    # reader learns what happens; 12 production jobs show a further turn.
    check("S2 the reviewer redirect no longer claims it precedes a stop",
          "injecting one reviewer redirect before stopping" in src, False)
    check("S2 ...and says it continues the loop instead",
          "injecting a reviewer redirect and CONTINUING the loop" in src, True)


# ------------------------------------------------------------ behaviour: T1/T2

def _runner_crash_checks() -> None:
    out = asyncio.run(_run_case("runner-crash", [RAISE]))
    check("T1 a raising sandbox_runner does not escape the loop",
          out["escaped"], None)
    check("T1 the crash is logged",
          any("sandbox runner crashed" in ln for ln in out["logs"]), True)
    check("T1 it now writes a WHY_STOPPED instead of returning silently",
          bool(out["why"]), True)
    check("T1 ...naming the runner, not the solver",
          "sandbox runner callback raised" in out["why"], True)
    check("T1 the exception text is preserved for the operator",
          "cannot connect to daemon"
          in (out["summary"].get("sandbox_runner_error") or ""), True)
    # T2: the session is INTACT after an infrastructure fault.  Stamping
    # judge_next_action=stop would make api/routes/retry.py:569 skip the SDK
    # session fork and throw away a good, expensive conversation.
    check("T2 an infra fault does not mark the transcript as dead",
          out["meta"].get("judge_next_action"), None)
    check("T2 ...but the reason is still recorded for display",
          bool(out["meta"].get("judge_stop_reason")), True)


# --------------------------------------------------------------- behaviour: T3

def _judge_hints_checks() -> None:
    # Case A — a genuinely SYNTHETIC producer.  A prejudge ship-block leaves
    # last_sandbox with NO "judge" key at the moment the upstream append runs,
    # so `_hint_just_now` is empty and nothing is recorded there.  The loop
    # then synthesizes last_sandbox["judge"] further down and delivers that
    # hint to main.  This is the exact shape the reviewer redirect and
    # runner_crash producers share, and the only one that distinguishes the
    # delivery-side record from the upstream one.
    #
    # An earlier draft of this check used a postjudge result and was VACUOUS:
    # the upstream site already appended it, so `drop-delivered-hint-record`
    # killed nothing and the suite scored 39/0 on the unfixed code.
    blocked = asyncio.run(_run_case(
        "synthetic", [_block(["recvuntil has no timeout="]), _fail("later")],
    ))
    b_hints = blocked["summary"].get("judge_hints") or []
    check("T3a a synthetic producer's hint reaches the anti-repeat record",
          any("prejudge BLOCKED ship" in h for h in b_hints), True)
    check("T3a ...exactly once",
          sum("prejudge BLOCKED ship" in h for h in b_hints), 1)

    # Case B — the ORDINARY postjudge path, which the upstream site already
    # covers.  The delivery-side record must not double-count it.  Together
    # with case A this pins both directions: a hint that was missing is now
    # recorded, and a hint that was already recorded is not duplicated.
    ordinary = "recvuntil needs an explicit timeout= on line 11"
    out = asyncio.run(_run_case(
        "hints", [_fail(ordinary), _fail("second hint")],
    ))
    hints = out["summary"].get("judge_hints") or []
    check("T3b the postjudge hint is still recorded", ordinary in hints, True)
    check("T3b ...exactly once, not twice", hints.count(ordinary), 1)
    check("T3b a second, different hint is recorded too",
          "second hint" in hints, True)


# --------------------------------------------------------------- behaviour: T4

def _ignored_hint_truthfulness_checks() -> None:
    # Case A — an INVESTIGATIVE hint.  Main spends the turn measuring and ships
    # nothing new.  The halt is unchanged (nothing to ship), but the recorded
    # reason must not accuse it of ignoring the hint.
    inv = asyncio.run(_run_case(
        "invest",
        [_fail("CLASS: STRATEGY\nNEXT: two untested hypotheses"), _fail("x")],
        main_edits=False,
    ))
    inv_reason = inv["summary"].get("judge_stop_reason") or ""
    check("T4a an investigative hint still halts (no new artifact to ship)",
          "retry_hint_ignored" in inv["why"]
          or "Script unchanged" in inv["why"], True)
    # Look for the ACCUSATION, not the word.  The corrected text uses "ignored"
    # inside a negation ("identical bytes are NOT evidence the hint was
    # ignored"), so a bare substring test scores the fix as the defect — it did
    # exactly that on the first run of this suite.
    check("T4a ...but does not accuse main of ignoring the hint",
          "main ignored" in inv_reason.lower(), False)
    check("T4a ...and says outright that the bytes prove no such thing",
          "not evidence the hint was ignored" in inv_reason.lower(), True)
    check("T4a ...and names the class that makes that reading unfair",
          "STRATEGY-class" in inv_reason, True)
    check("T4a ...and points the reader at the evidence",
          "report.md" in inv_reason, True)

    # Case B — an ORDINARY postjudge hint with no CLASS label.  It named a
    # correction to this file, so unchanged bytes ARE a non-response and the
    # blunt reading stands.  Fail-closed.
    ordn = asyncio.run(_run_case(
        "ordinary",
        [_fail("recvuntil needs an explicit timeout= on line 11"), _fail("x")],
        main_edits=False,
    ))
    ord_reason = ordn["summary"].get("judge_stop_reason") or ""
    check("T4b an unlabelled hint keeps the blunt reading",
          "without applying the named correction" in ord_reason, True)
    check("T4b ...and does not borrow the investigative excuse",
          "STRATEGY-class" in ord_reason, False)

    # The two cases MUST differ.  One case alone is satisfiable by a constant
    # string — the same two-case requirement main's A2-a rewrite states for the
    # prejudge signature boundary.
    check("T4c the two readings are actually different",
          inv_reason != ord_reason and bool(inv_reason) and bool(ord_reason),
          True)


def main() -> int:
    _hint_class_checks()
    _registration_checks()
    _runner_crash_checks()
    _judge_hints_checks()
    _ignored_hint_truthfulness_checks()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
