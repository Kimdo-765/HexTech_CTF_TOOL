#!/usr/bin/env python3
"""misc and forensic must actually continue the prior session on a retry.

Run: python3 scripts/test_orchestrator_resume.py [--mutate <name>]

WHAT WAS BROKEN

`/retry` and `/resume` mint a new job id and write the parent's session id into
the child's meta as `resume_session_id` (api/routes/retry.py). Five modules get
that for free: their analyzers call
`modules._common.make_main_session_options`, which passes `resume=resume_sid`
and, for Claude, `fork_session=bool(resume_sid)`.

misc and forensic have no analyzer.py. Their orchestrator.py builds session
options inline and passed NO resume kwarg to any of its three providers. The
field was written on every retry child and read by nobody, so a misc or
forensic retry started a brand-new agent thread with no history - and, because
neither module has a `work/` tree for `_resubmit` to copy, no files either. It
inherited nothing at all.

This was found by adversarial audit, not by a test, and the meta-field evidence
that had been offered as proof of inheritance - child.resume_session_id ==
parent.agent_session_id - proved only that the value was WRITTEN.

THE CHAIN THIS FILE PINS

    child meta.resume_session_id
      -> _resume_sid(job_id)                 (this module)
      -> GptSessionOptions/GrokSessionOptions/ClaudeAgentOptions resume=
      -> client self.session_id              (codex_cli:363, gpt_responses:291,
                                              grok_acp:383)
      -> codex exec resume <sid>             (codex_cli: the `resuming` branch)

Every link is asserted. The last two are asserted against the real source of
the clients, because instantiating a client would launch an agent.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

MUTATIONS = (
    "none",
    "drop-one-site",     # one provider stops receiving resume=
    "constant-resume",   # _resume_sid returns a literal instead of reading meta
    "drop-fork",         # Claude keeps resume= but loses fork_session=
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS, default="none")
args = parser.parse_args()

passed = 0
failed = 0


def check(label: str, got, want=True, *, detail=None) -> None:
    """Compare got to want. Diagnostics go in `detail`, never in `want`.

    Passing a diagnostic as the third positional silently turns it into the
    expected value, so the check compares True to a field list and fails for
    a reason that has nothing to do with the property. That mistake was made
    three times in one day writing these suites; the keyword-only `detail`
    makes it impossible to make positionally.
    """
    global passed, failed
    if got == want:
        passed += 1
        print(f"PASS  {label}")
    else:
        failed += 1
        print(f"FAIL  {label}\n      got  = {got!r}\n      want = {want!r}"
              + (f"\n      detail = {detail!r}" if detail is not None else ""))


def replace_once(source: str, old: str, new: str) -> str:
    n = source.count(old)
    if n != 1:
        raise RuntimeError(f"mutation anchor count is {n}, expected 1: {old[:60]!r}")
    return source.replace(old, new, 1)


MODULES = ("modules/misc/orchestrator.py", "modules/forensic/orchestrator.py")
PROVIDERS = ("GptSessionOptions", "GrokSessionOptions", "ClaudeAgentOptions")


def source_of(rel: str) -> str:
    src = (ROOT / rel).read_text()
    if args.mutate == "drop-one-site" and rel == MODULES[0]:
        src = replace_once(
            src,
            "            enable_subagents=True,\n"
            "            turn_timeout_s=turn_timeout_s,\n"
            "            resume=_resume_sid(job_id),\n",
            "            enable_subagents=True,\n"
            "            turn_timeout_s=turn_timeout_s,\n",
        )
    elif args.mutate == "constant-resume":
        src = replace_once(
            src,
            '    return (read_meta(job_id) or {}).get("resume_session_id") or None',
            '    return "hardcoded-session"  # MUTATION',
        )
    elif args.mutate == "drop-fork" and rel == MODULES[0]:
        src = replace_once(
            src,
            "        resume=_resume_sid(job_id),\n"
            "        fork_session=bool(_resume_sid(job_id)),\n",
            "        resume=_resume_sid(job_id),\n",
        )
    return src


# ------------------------------------------------ 1. every call site is wired
print("--- every provider in both modules receives resume " + "-" * 8)
for rel in MODULES:
    src = source_of(rel)
    tree = ast.parse(src)
    found = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            name = getattr(n.func, "id", None) or getattr(n.func, "attr", None)
            if name in PROVIDERS:
                found[name] = n
    short = rel.split("/")[1]
    check(f"{short}: all three providers are constructed here",
          sorted(found), sorted(PROVIDERS))
    for prov in PROVIDERS:
        n = found.get(prov)
        kw = next((k for k in (n.keywords if n else []) if k.arg == "resume"), None)
        check(f"{short}/{prov} passes resume=", kw is not None)
        if kw is not None:
            txt = ast.unparse(kw.value)
            # Must be read per job, not frozen at import or hardcoded.
            check(f"{short}/{prov} derives it from the job, not a literal",
                  txt, "_resume_sid(job_id)")
    cn = found.get("ClaudeAgentOptions")
    fk = next((k for k in (cn.keywords if cn else []) if k.arg == "fork_session"), None)
    check(f"{short}/Claude also forks the prior session", fk is not None)


# ------------------------------------------------------ 2. the helper is real
print("")
print("--- _resume_sid reads the child's own meta " + "-" * 16)
_TMP = tempfile.TemporaryDirectory(prefix="orch-resume-")
DATA = Path(_TMP.name)
(DATA / "jobs").mkdir()
os.environ.update(DATA_DIR=str(DATA), JOBS_DIR=str(DATA / "jobs"),
                  SETTINGS_PATH=str(DATA / "settings.json"))
(DATA / "settings.json").write_text("{}")


def load_helper(rel: str):
    """Run the module's own _resume_sid with a real read_meta over temp jobs."""
    src = source_of(rel)
    tree = ast.parse(src)
    node = next((n for n in tree.body
                 if isinstance(n, ast.FunctionDef) and n.name == "_resume_sid"), None)
    if node is None:
        return None

    def read_meta(job_id):
        p = Path(os.environ["JOBS_DIR"]) / job_id / "meta.json"
        return json.loads(p.read_text()) if p.is_file() else {}

    ns = {"read_meta": read_meta, "Optional": type(None)}
    ns["Optional"] = __import__("typing").Optional
    exec(compile(ast.Module(body=[node], type_ignores=[]), "<t>", "exec"), ns)
    return ns["_resume_sid"]


def make_job(job_id: str, resume_sid):
    jd = Path(os.environ["JOBS_DIR"]) / job_id
    jd.mkdir(parents=True, exist_ok=True)
    meta = {"id": job_id, "module": "misc"}
    if resume_sid is not None:
        meta["resume_session_id"] = resume_sid
    (jd / "meta.json").write_text(json.dumps(meta))


make_job("child0000with", "01a038f5-c79e-71f3-98fd-ac5eda91c319")
make_job("child000plain", None)
make_job("child0000blank", "")

for rel in MODULES:
    short = rel.split("/")[1]
    fn = load_helper(rel)
    check(f"{short}: _resume_sid exists", fn is not None)
    if fn is None:
        continue
    check(f"{short}: a retry child gets the parent's session",
          fn("child0000with"), "01a038f5-c79e-71f3-98fd-ac5eda91c319")
    check(f"{short}: a first-run job gets None", fn("child000plain"), None)
    check(f"{short}: an empty string is normalised to None",
          fn("child0000blank"), None)
    check(f"{short}: a missing job dir does not raise",
          fn("nosuchjob0000"), None)


# ------------------------------------- 3. the clients consume options.resume
print("")
print("--- the option actually reaches the provider client " + "-" * 7)
CLIENTS = {
    "modules/codex_cli.py": "gpt / codex runtime",
    "modules/gpt_responses.py": "gpt / responses runtime",
    "modules/grok_acp.py": "grok",
}
for rel, label in CLIENTS.items():
    src = (ROOT / rel).read_text()
    check(f"{label}: seeds its session id from options.resume",
          "options.resume" in src)

codex = (ROOT / "modules/codex_cli.py").read_text()
check("codex: a seeded session id switches the CLI to `exec resume`",
      '"resume",' in codex and "self.session_id" in codex)

# The option classes must actually accept the kwarg, or this is a TypeError at
# the first retry rather than a resumed session.
for rel, cls in (("modules/gpt_responses.py", "GptSessionOptions"),
                 ("modules/grok_acp.py", "GrokSessionOptions")):
    t = ast.parse((ROOT / rel).read_text())
    fields = []
    for n in ast.walk(t):
        if isinstance(n, ast.ClassDef) and n.name == cls:
            fields = [b.target.id for b in n.body if isinstance(b, ast.AnnAssign)]
    check(f"{cls} declares a resume field", "resume" in fields,
          detail=fields[:12])

# ClaudeAgentOptions comes from the SDK, which is not importable in every dev
# environment. The shared helper passes both kwargs in production, which is the
# evidence that the SDK accepts them.
common = (ROOT / "modules/_common.py").read_text()
check("the shared helper passes fork_session to ClaudeAgentOptions "
      "(so the SDK accepts it)", "fork_session=bool(resume_sid)" in common)

print("")
print(f"orchestrator-resume: {passed} passed, {failed} failed; "
      f"mutation={args.mutate}")
sys.exit(1 if failed else 0)
