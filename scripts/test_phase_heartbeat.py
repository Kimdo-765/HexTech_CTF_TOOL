#!/usr/bin/env python3
"""Regression suite for phase_heartbeat — liveness outside the main SDK loop.

Run inside the worker (needs the module's own dependency tree):

    docker cp modules <worker>:/tmp/ph/modules
    docker cp scripts/test_phase_heartbeat.py <worker>:/tmp/ph/t.py
    docker exec <worker> sh -c 'cd /tmp/ph && DATA_DIR=/tmp/ph/data python3 t.py'

THE DEFECT
`meta.last_agent_event_at` is written by `agent_heartbeat`, which runs only in
main's SDK message loop (`run_main_agent_session`). Four other loops in this
module drive an SDK client and none of them wrote it:

    run_pre_recon           (x2, Claude and Grok clients)   before main
    make_spawn_subagent_mcp                                 during main
    run_report_phase                                        after main

So the timestamp froze for the whole duration of every subagent delegation.
Measured on job 06f3a326d453 while it was working hard: main's last event at
10:35:49, `recon#1` still emitting tool calls at 10:42:19, and the UI's age
readout stuck at 6m40s the entire time — 51 of the last 60 run.log lines were
the subagent's. The number said idle; the job was not.

WHY NOT JUST CALL agent_heartbeat
It carries the token/cost ledger. The subagent loop's own comment says subagent
tool calls belong on the subagent's ledger, not main's, and double-summing one
stream is exactly how agent_tokens once measured EXACTLY 2.0000x (the dedupe
note in _accumulate_tokens). phase_heartbeat therefore writes three fields and
nothing else. These checks pin that down — a future edit that "simplifies" it
into agent_heartbeat fails here.
"""
from __future__ import annotations

import ast as _ast
import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_results: list[bool] = []


def chk(label: str, cond: bool, got: object = "") -> None:
    _results.append(bool(cond))
    print(("PASS  " if cond else "FAIL  ") + label + ("" if cond else f"  | got={got!r}"))


def section(name: str) -> None:
    print("\n--- " + name + " " + "-" * max(0, 56 - len(name)))


class _Msg:
    """Stand-in for an SDK message; only its class name is read."""


class AssistantMessage(_Msg):
    pass


def main() -> int:
    tmp = Path(tempfile.mkdtemp())
    os.environ["DATA_DIR"] = str(tmp)
    sys.path.insert(0, str(ROOT))

    import modules._common as C
    chk("phase_heartbeat is importable", hasattr(C, "phase_heartbeat"))
    if not hasattr(C, "phase_heartbeat"):
        print(f"\n{len(_results)} checks, {len([r for r in _results if not r])} failed")
        return 1

    jid = "testjob00001"
    (tmp / "jobs" / jid).mkdir(parents=True, exist_ok=True)
    (tmp / "jobs" / jid / "meta.json").write_text(json.dumps({"id": jid}))

    def meta() -> dict:
        return json.loads((tmp / "jobs" / jid / "meta.json").read_text())

    # ------------------------------------------------------------- writes
    section("it records liveness")
    C._phase_heartbeat_state.pop(jid, None)
    C.phase_heartbeat(jid, "recon#1", AssistantMessage())
    m = meta()
    chk("last_agent_event_at is written", bool(m.get("last_agent_event_at")), m)
    chk("the message class is recorded",
        m.get("last_event_kind") == "AssistantMessage", m.get("last_event_kind"))
    chk("REGRESSION: the ACTOR is named, so the UI can say who is alive",
        m.get("last_event_actor") == "recon#1", m.get("last_event_actor"))

    # -------------------------------------------------------- no ledger
    section("it must NEVER touch the token/cost ledger")
    for field in ("agent_tokens", "cost_usd", "cost_usd_estimate", "agent_turns",
                  "model_usage", "flag_candidates"):
        chk(f"  {field} untouched", field not in meta(), meta().get(field))

    # ------------------------------------------------------------ throttle
    section("writes stay bounded")
    C._phase_heartbeat_state.pop(jid, None)
    C.phase_heartbeat(jid, "recon#1", AssistantMessage())
    first = meta()["last_agent_event_at"]
    for _ in range(50):
        C.phase_heartbeat(jid, "recon#2", AssistantMessage())
    chk("50 immediate calls collapse to one write (5s throttle)",
        meta()["last_agent_event_at"] == first, meta()["last_agent_event_at"])
    chk("...and the throttle is keyed per JOB, not per actor — concurrent "
        "subagents must not multiply the write rate",
        len(C._phase_heartbeat_state) == 1, C._phase_heartbeat_state)

    C._phase_heartbeat_state[jid] = time.monotonic() - 10.0
    C.phase_heartbeat(jid, "report", AssistantMessage())
    chk("a later call past the interval DOES write",
        meta()["last_agent_event_at"] != first, meta()["last_agent_event_at"])
    chk("...and re-labels the actor", meta()["last_event_actor"] == "report",
        meta()["last_event_actor"])

    # ------------------------------------------------------------- safety
    section("liveness is cosmetic and must never break a phase")
    try:
        C.phase_heartbeat("no/such/job\0bad", "x", AssistantMessage())
        raised = False
    except Exception as e:  # noqa: BLE001
        raised = True
    chk("a broken job id raises nothing", not raised)

    # `_time` is a function-local import everywhere else in this module. If
    # phase_heartbeat forgot its own import the NameError would be swallowed by
    # the broad except and the whole fix would be a silent no-op.
    src_fn = ""
    for node in _ast.parse((ROOT / "modules" / "_common.py").read_text()).body:
        if isinstance(node, _ast.FunctionDef) and node.name == "phase_heartbeat":
            src_fn = _ast.unparse(node)
    chk("REGRESSION: it imports _time itself rather than relying on a global "
        "that does not exist", "import time as _time" in src_fn, src_fn[:200])

    # -------------------------------------------------------------- wiring
    section("every non-main SDK loop reports liveness")
    src = (ROOT / "modules" / "_common.py").read_text()
    tree = _ast.parse(src)
    loops = {"run_pre_recon": 0, "make_spawn_subagent_mcp": 0,
             "run_report_phase": 0, "run_main_agent_session": 0}
    for node in _ast.walk(tree):
        if not isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            continue
        if node.name not in loops:
            continue
        body = _ast.unparse(node)
        loops[node.name] = body.count("phase_heartbeat(")
    for fn in ("run_pre_recon", "make_spawn_subagent_mcp", "run_report_phase"):
        chk(f"  {fn} calls phase_heartbeat", loops[fn] >= 1, loops[fn])
    chk("REGRESSION: main does NOT — it owns agent_heartbeat and the ledger, "
        "and two writers would race the actor label",
        loops["run_main_agent_session"] == 0, loops["run_main_agent_session"])
    chk("both pre-recon clients (Claude and Grok) are covered",
        loops["run_pre_recon"] == 2, loops["run_pre_recon"])
    chk("agent_heartbeat labels its own events 'main', so a subagent tag "
        "cannot linger", 'last_event_actor="main"' in src)

    failed = [r for r in _results if not r]
    print(f"\n{len(_results)} checks, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
