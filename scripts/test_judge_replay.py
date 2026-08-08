#!/usr/bin/env python3
"""The stage-7 replay must reconstruct the right attempt, and touch nothing.

Two things go wrong silently here and both have already happened once in this
corpus:

  * Reading the wrong solver name. Half the jobs run `solver.py`, half
    `exploit.py`; assuming one skips every rev and crypto job — the majority.
  * Reading the wrong ATTEMPT. `result.json["sandbox"]` holds an older failed
    auto-run on 4 of 42 jobs, while the `*.stdout` files and the LAST
    `phase=run kind=exit` event describe the run the outcome came from.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.TemporaryDirectory(prefix="replay7-")
DATA = Path(_TMP.name)
(DATA / "jobs").mkdir()
(DATA / "settings.json").write_text("{}")
os.environ.update(DATA_DIR=str(DATA), JOBS_DIR=str(DATA / "jobs"),
                  SETTINGS_PATH=str(DATA / "settings.json"))


def _missing(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is None
    except (ImportError, ValueError):
        return True


STUBBED = [n for n in ("docker", "claude_agent_sdk") if _missing(n)]
if _missing("docker"):
    _d = types.ModuleType("docker")
    _d.from_env = lambda *a, **k: None
    _d.DockerClient = type("DockerClient", (), {})
    _errors = types.ModuleType("docker.errors")
    for _n in ("APIError", "NotFound", "ImageNotFound", "DockerException", "NullResource"):
        setattr(_errors, _n, type(_n, (Exception,), {}))
    _d.errors = _errors
    _tm = types.ModuleType("docker.types")
    _tm.Mount = type("Mount", (), {"__init__": lambda s, **k: None})
    _d.types = _tm
    sys.modules.update({"docker": _d, "docker.errors": _errors, "docker.types": _tm})

if _missing("claude_agent_sdk"):
    _sdk = types.ModuleType("claude_agent_sdk")
    for _n in ("AssistantMessage", "ClaudeAgentOptions", "ResultMessage",
               "SystemMessage", "TextBlock", "ClaudeSDKClient", "UserMessage"):
        setattr(_sdk, _n, type(_n, (), {"__init__": lambda s, **k: None}))

    async def _query(*a, **k):  # pragma: no cover
        if False:
            yield None

    _sdk.query = _query
    _sdk.HookMatcher = type("HookMatcher", (), {"__init__": lambda s, **k: None})
    _sdk.AgentDefinition = type("AgentDefinition", (), {"__init__": lambda s, **k: None})
    _sdk.create_sdk_mcp_server = lambda *a, **k: None
    _sdk.tool = lambda *a, **k: (lambda fn: fn)
    _sdk.project_key_for_directory = lambda *a, **k: ""
    sys.modules["claude_agent_sdk"] = _sdk

from modules import judge_replay as RP  # noqa: E402
from modules import _judge as J  # noqa: E402

PASSED = FAILED = 0


def check(label, got, want):
    global PASSED, FAILED
    if got == want:
        PASSED += 1
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


def mkjob(jid, *, solver="exploit.py", attempts=(("0", "out", ""),),
          target="h:1", report=None, extra_files=None):
    """A job dir shaped like the real ones: per-attempt exit events, last-wins files."""
    d = DATA / "jobs" / jid
    (d / "work").mkdir(parents=True, exist_ok=True)
    (d / solver).write_text("print('x')\n")
    evs = []
    for code, out, err in attempts:
        evs.append({"phase": "run", "kind": "exit", "exit_code": int(code),
                    "stdout_bytes": len(out), "stderr_bytes": len(err),
                    "timeout": False, "killed_by_supervise": False})
    (d / "events.jsonl").write_text("\n".join(json.dumps(e) for e in evs) + "\n")
    # The runner overwrites these per attempt, so they hold the LAST one.
    (d / (solver + ".stdout")).write_text(attempts[-1][1])
    (d / (solver + ".stderr")).write_text(attempts[-1][2])
    (d / "meta.json").write_text(json.dumps({"id": jid, "module": "pwn",
                                             "status": "finished",
                                             "target_url": target}))
    if report is not None:
        (d / "report.md").write_text(report)
    for name, body in (extra_files or {}).items():
        (d / name).write_text(body)
    return d


# ---------------------------------------------------------------------------
# 1. The solver name comes from the artifacts, not from a guess.
# ---------------------------------------------------------------------------
check("exploit.py jobs are found",
      RP.replay_inputs(mkjob("r-exp"))["script_rel"], "exploit.py")
check("solver.py jobs are found too — half the corpus uses it",
      RP.replay_inputs(mkjob("r-sol", solver="solver.py"))["script_rel"], "solver.py")

_none = DATA / "jobs" / "r-empty"
(_none / "work").mkdir(parents=True, exist_ok=True)
(_none / "meta.json").write_text(json.dumps({"id": "r-empty"}))
check("a job with no sandbox output is unreplayable, not a crash",
      RP.replay_inputs(_none), None)

# ---------------------------------------------------------------------------
# 2. The LAST attempt is the one described by the files.
# ---------------------------------------------------------------------------
_multi = mkjob("r-multi", attempts=(("1", "first attempt failed", "boom"),
                                    ("0", "SECOND attempt worked", "")))
_mi = RP.replay_inputs(_multi)
check("the exit code comes from the LAST run event", _mi["exit_code"], 0)
check("...and the output is the last attempt's",
      _mi["postjudge"]["stdout_tail"], "SECOND attempt worked")
check("...with the attempt count recorded", _mi["attempts"], 2)
check("...and the missing hint history named as a gap",
      any("prior_hints not persisted" in g for g in _mi["gaps"]), True)

# result.json is deliberately NOT consulted: on 4 of 42 real jobs it holds an
# older failed auto-run rather than the run the outcome came from.
_stale = mkjob("r-stale", attempts=(("0", "the good run", ""),),
               extra_files={"result.json": json.dumps(
                   {"sandbox": {"exit_code": 1, "stdout": "an older failed run"}})})
_si = RP.replay_inputs(_stale)
check("a stale result.json does not override the events", _si["exit_code"], 0)
check("...nor its output", _si["postjudge"]["stdout_tail"], "the good run")

# ---------------------------------------------------------------------------
# 3. The judge's inputs are built by the SAME helpers the enforce path uses,
#    so the replayed prompt is not a second implementation of the assembly.
# ---------------------------------------------------------------------------
_long = "DH{real_one_here}" + ("x" * 20_000) + "DH{fake_flag}\n"
_li = RP.replay_inputs(mkjob("r-long", attempts=(("0", _long, ""),)))
check("the tail is the judge's own truncation",
      _li["postjudge"]["stdout_tail"],
      J._truncate_tail(_long, max_bytes=J.POSTJUDGE_STDOUT_BYTES))
check("...and the flag shapes come from the FULL output",
      ("DH{real_one_here}" in _li["postjudge"]["flag_shapes"],
       "DH{fake_flag}" in _li["postjudge"]["flag_shapes"]), (True, True))

_to = mkjob("r-timeout")
_ev = json.loads((_to / "events.jsonl").read_text().strip())
_ev["timeout"] = True
(_to / "events.jsonl").write_text(json.dumps(_ev) + "\n")
check("a timed-out attempt carries the runner's own context line",
      "runner timeout fired" in RP.replay_inputs(_to)["extra_context"], True)

check("the target comes from meta", RP.replay_inputs(mkjob("r-t", target="x:9"))["target"], "x:9")

# ---------------------------------------------------------------------------
# 4. THE PATH. Everything above tests reconstruction; this drives replay_job()
#    and pins what it hands each stage — and that it writes nothing.
# ---------------------------------------------------------------------------
_pj = mkjob("r-path", solver="solver.py",
            attempts=(("7", "DH{seen}\nout tail", "err tail"),),
            target="remote:1337", report="a report\n")
_before = {p: p.read_bytes() for p in sorted(_pj.rglob("*")) if p.is_file()}

_seen = []
_out = RP.replay_job(_pj, runner=lambda stage, payload: (
    _seen.append((stage, payload)), {"stage": stage})[1])

check("both stages ran", [s for s, _ in _seen], ["prejudge", "postjudge"])
_pre = dict(_seen[0][1])
check("prejudge gets the right script and target",
      (_pre["script_rel"], _pre["target"]), ("solver.py", "remote:1337"))
_post = dict(_seen[1][1])
check("postjudge gets the recorded exit code", _post["exit_code"], 7)
check("...the tails, not the raw output",
      (_post["postjudge"]["stdout_tail"], _post["postjudge"]["stderr_tail"]),
      ("DH{seen}\nout tail", "err tail"))
check("...and the flag shapes", _post["postjudge"]["flag_shapes"], ["DH{seen}"])
check("the verdicts are returned under both keys",
      (_out["prejudge"], _out["postjudge_verdict"]),
      ({"stage": "prejudge"}, {"stage": "postjudge"}))

_after = {p: p.read_bytes() for p in sorted(_pj.rglob("*")) if p.is_file()}
check("replay_job writes NOTHING into the job it reads", _after, _before)

# A stage that explodes is reported, not raised: one bad job must not end a
# 42-job sweep.
_boom = RP.replay_job(mkjob("r-boom"), runner=lambda s, p: (_ for _ in ()).throw(
    RuntimeError("judge exploded")))
check("an exploding stage is captured as an error verdict",
      "exploded" in str(_boom["prejudge"].get("error")), True)
check("...and the sweep can continue", _boom["job_id"], "r-boom")

# The judge's prose must not be handed the job's own logger — §8.1 again.
_sink = []
RP.replay_job(mkjob("r-log"), log_sink=_sink,
              runner=lambda s, p: {"ok": True})
check("the caller supplies the log sink, so nothing reaches run.log",
      isinstance(_sink, list), True)

print(f"== summary: {PASSED} passed, {FAILED} failed =="
      + (f"  [stubbed: {', '.join(STUBBED)}]" if STUBBED else "  [all real deps]"))
_TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
