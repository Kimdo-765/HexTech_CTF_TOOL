#!/usr/bin/env python3
"""Main must get its module's web-research scope, not pwn heap examples.

Run: python3 scripts/test_web_research_scope.py [--mutate <name>]

WHAT WAS BROKEN

The base prompt's "Web research — ENABLED" block (modules/_prompts.py:1695)
grants WebSearch/WebFetch and then spends its three concrete bullets on
pwn/heap material: FSOP/IO_FILE magic values, per-version tcache_key, House-of-*
layouts, custom allocator wrappers. For a web or crypto job none of that
applies, so the only thing main takes from the block is the permission.

The sentence that scopes the search — "use the web to find framework & library
CVEs and version-specific bypasses ... for the DETECTED stack" — lives in
`_web_research_addendum`, and it was appended under `if agent_type == "recon"`.
Main never saw it.

Observed on job 890a39993137 (web, gpt/codex). Main read the source, hit a dead
end, and searched for the challenge's OWN writeup with strings lifted straight
out of it:

    "whatUwant" "pokactf2024"
    "Wrong Flag Format" "puppeteer-core" "text/plain"
    POKA CTF 2024 web writeup

That is a correct reading of what it was given. The base block forbids COPYING
a writeup ("Do not blindly copy", "verify every borrowed value") and explicitly
invites the search ("reach for the web when it genuinely helps"). Nothing main
could see narrowed the target of a search to the stack.

This is NOT a re-proposal of the WebSearch block removed on 2026-07-22. Web
research stays enabled; only its scope moves to where main can read it.

WHY THIS IS NOT A TAUTOLOGY

The checks build options through the REAL `make_main_session_options` and
`make_standalone_options` and read the prompt back off the returned object, so
a change that stops reaching either builder fails here. pwn's addendum is ''
by design, which is asserted as a byte-identical prompt rather than assumed.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

MUTATIONS = (
    "none",
    "main-unscoped",     # the append to main's prompt is removed
    "recon-only-again",  # the addendum goes back to recon-only
    "pwn-not-empty",     # pwn stops being a no-op
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS, default="none")
args = parser.parse_args()

passed = 0
failed = 0


def check(label: str, got, want=True, *, detail=None) -> None:
    """Compare got to want. Diagnostics go in `detail`, never in `want`."""
    global passed, failed
    if got == want:
        passed += 1
        print(f"PASS  {label}")
    else:
        failed += 1
        print(f"FAIL  {label}")
        print(f"      got  = {got!r}")
        print(f"      want = {want!r}")
        if detail is not None:
            print(f"      {detail}")


def replace_once(source: str, old: str, new: str) -> str:
    n = source.count(old)
    if n != 1:
        raise RuntimeError(
            f"mutation anchor count is {n}, expected 1: {old[:60]!r}")
    return source.replace(old, new, 1)


# ------------------------------------------------------------------ env
_TMP = tempfile.TemporaryDirectory(prefix="web-research-scope-")
DATA = Path(_TMP.name)
(DATA / "jobs").mkdir()
os.environ.update(DATA_DIR=str(DATA), JOBS_DIR=str(DATA / "jobs"),
                  SETTINGS_PATH=str(DATA / "settings.json"))
(DATA / "settings.json").write_text("{}")
for _k in ("AGENT_PROVIDER", "CLAUDE_MODEL", "GROK_MODEL", "GPT_MODEL"):
    os.environ.pop(_k, None)


def _missing(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is None
    except (ImportError, ValueError):
        return True


STUBBED = []
if _missing("claude_agent_sdk"):
    STUBBED.append("claude_agent_sdk")
    _sdk = types.ModuleType("claude_agent_sdk")

    class _Kw:
        """Captures kwargs so the test can read the prompt back."""

        def __init__(self, **kw):
            for k, v in kw.items():
                setattr(self, k, v)

    for _n in ("AssistantMessage", "ResultMessage", "SystemMessage",
               "TextBlock", "ClaudeSDKClient", "UserMessage"):
        setattr(_sdk, _n, type(_n, (), {}))
    _sdk.ClaudeAgentOptions = type("ClaudeAgentOptions", (_Kw,), {})
    _sdk.HookMatcher = type("HookMatcher", (_Kw,), {})
    _sdk.AgentDefinition = type("AgentDefinition", (_Kw,), {})

    async def _query(*a, **k):  # pragma: no cover
        if False:
            yield None

    _sdk.query = _query
    _sdk.create_sdk_mcp_server = lambda *a, **k: None
    _sdk.tool = lambda *a, **k: (lambda fn: fn)
    _sdk.project_key_for_directory = lambda *a, **k: ""
    sys.modules["claude_agent_sdk"] = _sdk

COMMON = ROOT / "modules" / "_common.py"
SRC = COMMON.read_text()

# ------------------------------------------------------------- mutation
_mut = SRC
if args.mutate == "main-unscoped":
    _mut = replace_once(
        _mut,
        '    _wr_main = _web_research_addendum(_module)\n'
        '    if _wr_main:\n'
        '        system_prompt = system_prompt + "\\n\\n" + _wr_main\n',
        '    pass  # MUTATION - main keeps the pwn-flavored block only\n',
    )
elif args.mutate == "recon-only-again":
    _mut = replace_once(
        _mut,
        '    _wr_main = _web_research_addendum(_module)\n',
        '    _wr_main = ""  # MUTATION - recon-only again\n',
    )
elif args.mutate == "pwn-not-empty":
    _mut = replace_once(
        _mut,
        '_WEB_RESEARCH_BY_MODULE',
        '_WEB_RESEARCH_BY_MODULE_ORIG',
    ) if "_WEB_RESEARCH_BY_MODULE" in _mut else _mut

import modules._common as C  # noqa: E402

if _mut is not SRC:
    exec(compile(_mut, str(COMMON), "exec"), C.__dict__)

if args.mutate == "pwn-not-empty":
    _orig = C._web_research_addendum
    C._web_research_addendum = lambda m: _orig(m) or _orig("web")


MODULES = ("pwn", "web", "rev", "crypto", "web3", "misc", "forensic")
BASE = "BASE-SYSTEM-PROMPT-BODY"


def make_job(job_id: str, module: str) -> str:
    jd = Path(os.environ["JOBS_DIR"]) / job_id
    (jd / "work").mkdir(parents=True, exist_ok=True)
    (jd / "meta.json").write_text(json.dumps({"id": job_id, "module": module}))
    return job_id


def main_prompt_for(module: str) -> str:
    jid = make_job((module + "0" * 12)[:12], module)
    opts = C.make_main_session_options(
        job_id=jid,
        work_dir=str(Path(os.environ["JOBS_DIR"]) / jid / "work"),
        model="test-model",
        system_prompt=BASE,
        base_tools=["Read", "Bash"],
        summary={},
    )
    return getattr(opts, "system_prompt", "") or ""


# --------------------------------------------- 1. the addendum itself
print("--- the per-module reframe exists and is module-specific " + "-" * 6)
for m in MODULES:
    txt = C._web_research_addendum(m)
    if m == "pwn":
        check("pwn has no reframe (base prompt is already pwn-flavored)",
              txt, "")
        continue
    check(f"{m} has a reframe", bool(txt), detail=txt[:80])
    check(f"{m}'s reframe names its own module",
          f"THIS {m} JOB" in txt, detail=txt[:120])
    check(f"{m}'s reframe says it overrides the pwn examples",
          "overrides the pwn-flavored" in txt)

check("an unknown module gets no reframe", C._web_research_addendum("nope"), "")
check("an empty module string gets no reframe", C._web_research_addendum(""), "")


# ------------------------------------------- 2. MAIN receives it (the fix)
print("")
print("--- main's own prompt carries its module's scope " + "-" * 14)
for m in MODULES:
    got = main_prompt_for(m)
    check(f"{m}: main's prompt still contains the base body", BASE in got)
    if m == "pwn":
        # No reframe for pwn, so the prompt must be untouched. Asserted, not
        # assumed: this is what keeps the pwn path byte-identical.
        check("pwn: main's prompt is unchanged", got, BASE)
        continue
    want = C._web_research_addendum(m)
    check(f"{m}: main's prompt carries the {m} reframe", want in got,
          detail=got[-160:])
    # Guarded: an absent reframe must fail the check above BY NAME, not crash
    # `.index()` and abort the run. A mutation that kills the property has to
    # produce a named failure or it has tested nothing.
    check(f"{m}: the reframe comes AFTER the base, so it overrides",
          (want in got and BASE in got
           and got.index(want) > got.index(BASE)))
    # It must be ITS module's reframe, not a neighbour's.
    others = [o for o in MODULES if o not in ("pwn", m)]
    leaked = [o for o in others if C._web_research_addendum(o) in got]
    check(f"{m}: no other module's reframe leaked in", leaked, [])


# --------------------------------------- 3. recon still receives it too
print("")
print("--- the recon subagent did not lose it " + "-" * 23)
jid = make_job("reconjob0000", "web")
try:
    ropts = C.make_standalone_options(
        "recon", "test-model",
        str(Path(os.environ["JOBS_DIR"]) / jid / "work"), jid)
    rprompt = getattr(ropts, "system_prompt", "") or ""
    check("recon's prompt carries the web reframe",
          C._web_research_addendum("web") in rprompt,
          detail=rprompt[-160:])
except Exception as exc:  # noqa: BLE001
    check("make_standalone_options('recon') builds", False,
          detail=f"{type(exc).__name__}: {exc}")


print("")
if STUBBED:
    print("[stubbed: %s]" % ", ".join(STUBBED))
print(f"web-research-scope: {passed} passed, {failed} failed; "
      f"mutation={args.mutate}")
sys.exit(1 if failed else 0)
