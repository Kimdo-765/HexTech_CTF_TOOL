#!/usr/bin/env python3
"""Every factual claim a prompt makes about the environment, EXECUTED.

Run inside the worker (it needs the tools the prompts name):

    docker cp modules <worker>:/tmp/pc/modules
    docker cp scripts/test_prompt_claims.py <worker>:/tmp/pc/t.py
    docker exec <worker> sh -c 'cd /tmp/pc && python3 t.py'

WHY THIS FILE EXISTS
A prompt audit over the 222 KB corpus found that the recurring defect is not
bad advice — it is advice that used to be true. The environment and the code
moved; the catalogue did not. Every one of these was shipped and live:

    pwn libcdb find …            no such subcommand (lookup/hash/file)
    pwn.libcdb.find_libc         no such symbol
    ROPgadget --rop              silently means --ropchain; --jop is an error
    hexdump / vim / pahole       not installed
    libheap                      a priority-queue library, not a heap parser
    PRE_RECON_TIMEOUT_S          invented; nothing times out pre-recon
    mcp__team__spawn_subagent    not in the judge's session

Reading the prompt cannot catch any of these; only running them can. So this
suite RUNS each command the prompts tell an agent to run, and asserts the
prompt text matches what actually happened. A claim that drifts fails here
rather than inside a $20 job.

Checks that assert a tool is ABSENT are deliberate too: the prompt now tells
agents it is absent, and if someone installs it later that sentence becomes
the new lie. The failure message says which way to fix it.
"""
from __future__ import annotations

import importlib
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_results: list[bool] = []


def chk(label: str, cond: bool, got: object = "") -> None:
    _results.append(bool(cond))
    print(("PASS  " if cond else "FAIL  ") + label + ("" if cond else f"  | got={got!r}"))


def section(name: str) -> None:
    print("\n--- " + name + " " + "-" * max(0, 58 - len(name)))


def run(cmd: str, timeout: int = 60) -> tuple[int, str]:
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main() -> int:
    sys.path.insert(0, str(ROOT))
    # This suite EXECUTES the tools the prompts name, so it is only meaningful
    # where those tools live. On the host it would die on the first import and
    # read as a broken suite in a full sweep; say so and skip instead. The
    # tools are the point — never stub them, or the suite stops testing the one
    # thing it exists for.
    # Keyed on the CONTAINER, not on tool presence: a developer host can well
    # have ROPgadget and pwn installed, and then the suite runs happily and
    # measures the HOST — which answers nothing, since every claim here is
    # about what the worker image ships. It would also fail honestly-worded
    # checks like "hexdump is ABSENT", which is true of the image and usually
    # false of a workstation.
    in_worker = Path("/.dockerenv").exists() and Path("/opt/scaffold").is_dir()
    if not in_worker:
        print(f"SKIP  not the worker container — these claims are about the "
              f"worker IMAGE, and measuring this host would answer a different "
              f"question. Run with:\n"
              f"  docker cp modules <worker>:/tmp/pc/modules\n"
              f"  docker cp scripts/test_prompt_claims.py <worker>:/tmp/pc/scripts/\n"
              f"  docker exec <worker> sh -c 'cd /tmp/pc && python3 scripts/test_prompt_claims.py'")
        print("\n0 checks, 0 failed (skipped)")
        return 0
    base = (ROOT / "modules" / "_prompts.py").read_text()
    pwn_p = (ROOT / "modules" / "pwn" / "prompts.py").read_text()
    web_p = (ROOT / "modules" / "web" / "prompts.py").read_text()

    # ------------------------------------------------------------- libcdb
    section("libc identification — the remote-only path")
    rc, out = run("pwn libcdb lookup --help")
    chk("`pwn libcdb lookup` is a real subcommand", rc == 0, out[-120:])
    chk("...and it takes symbol/offset PAIRS, as the prompt now says",
        "symbol_offset_pairs" in out, out[:160])
    rc, out = run("pwn libcdb find x y")
    chk("REGRESSION: `find` is NOT a subcommand", rc != 0 and "invalid choice" in out,
        out[-120:])
    chk("the prompt no longer tells anyone to run it", "libcdb find" not in base)
    chk("the prompt names lookup instead", "libcdb lookup" in base)

    import pwnlib.libcdb as L
    chk("REGRESSION: pwnlib.libcdb.find_libc does not exist", not hasattr(L, "find_libc"))
    chk("search_by_symbol_offsets does", hasattr(L, "search_by_symbol_offsets"))
    chk("the prompt names the one that exists",
        "search_by_symbol_offsets" in base and "find_libc" in base.split(
            "search_by_symbol_offsets")[1][:200],
        "expects the corrective 'there is no find_libc' note next to it")

    # ---------------------------------------------------------- ROPgadget
    section("gadget hunting")
    rc, out = run("ROPgadget --binary /bin/ls --jop")
    chk("REGRESSION: --jop is a usage error", rc != 0, out[-120:])
    rc, out = run("ROPgadget --binary /bin/ls --rop")
    chk("REGRESSION: --rop is NOT rejected — argparse takes it as --ropchain, "
        "so a pipe expecting a gadget list gets chain output instead",
        "ROP chain generation" in out or "Step 1" in out, out[:200])
    rc, out = run("ROPgadget --binary /bin/ls --only 'pop|ret' | head -5")
    chk("the invocation the prompt now gives DOES list gadgets",
        rc == 0 and " : " in out, out[:160])
    chk("no prompt still advertises --rop / --jop as flags",
        "--binary ./bin/<name> --rop /" not in base
        and "--binary <libc> --rop --depth" not in base
        and "--binary <elf> --rop`" not in pwn_p)

    # ------------------------------------------------------------- CLIs
    section("the 'always available' CLI list must be true")
    for tool, present in (("xxd", True), ("strings", True), ("readelf", True),
                          ("objdump", True), ("nano", True),
                          ("hexdump", False), ("vim", False), ("pahole", False)):
        found = shutil.which(tool) is not None
        chk(f"  {tool}: {'installed' if present else 'ABSENT'}", found == present,
            shutil.which(tool))
    chk("vim.tiny — the actual binary — is what the prompt names",
        shutil.which("vim.tiny") is not None and "vim.tiny" in base)
    chk("REGRESSION: hexdump is not listed as available",
        "xxd, hexdump," not in base)
    chk("REGRESSION: pahole is not offered as a struct-layout tool",
        "readelf / pahole" not in base)

    # ---------------------------------------------------------- libheap
    section("libheap is not a heap parser")
    import libheap
    api = [n for n in dir(libheap) if not n.startswith("_")]
    chk("it imports (which is why the wrong claim survived so long)", True)
    chk("REGRESSION: its API is a priority queue, not malloc_chunk",
        "Heap" in api and not any("malloc" in n or "arena" in n or "tcache" in n
                                  for n in api), api)
    chk("no prompt claims it parses malloc_chunk / walks the arena",
        "malloc_chunk" not in base or "libheap" not in base, )
    chk("...and it is off the tool catalogue entirely", "libheap" not in base)

    # ------------------------------------------------------ pre-recon wall
    section("pre-recon has no deadline, so the prompt must not invent one")
    chk("REGRESSION: PRE_RECON_TIMEOUT_S is gone from the prompt",
        "PRE_RECON_TIMEOUT_S" not in base)
    # --include=*.py: a stale __pycache__/*.pyc still carries the old string
    # and is not source. Matching it made this check fail on a clean tree.
    hits = subprocess.run(
        "grep -rl --include=*.py PRE_RECON_TIMEOUT_S " + str(ROOT / "modules"),
        shell=True, capture_output=True, text=True).stdout.strip()
    chk("...and it never existed anywhere else either", not hits, hits)
    chk("the self-imposed budget survives — it is useful, the fake wall was not",
        "TIME BUDGET" in base and "5-6 minutes" in base)
    chk("and the prompt is explicit that nothing will stop it",
        "NO orchestrator timeout" in base)

    # ------------------------------------------------------------- judge
    section("the judge cannot delegate")
    import modules._common as C
    import inspect
    src = inspect.getsource(C.make_standalone_options)
    chk("REGRESSION: subagent options carry no mcp_servers",
        "mcp_servers" not in src)
    # Read the CONSTANT, not a slice of the file. Splitting on the name
    # returned everything after its first mention — i.e. the rest of the
    # module, including blocks where the tool is genuinely available — so the
    # check was measuring the wrong text entirely.
    import modules._prompts as _P
    j = getattr(_P, "JUDGE_AGENT_PROMPT", "") or ""
    chk("the judge prompt constant was found", len(j) > 500, len(j))
    chk("the judge prompt no longer tells it to call the MCP tool",
        "mcp__team__spawn_subagent" not in j, j[:200])
    chk("...and says what to do instead", "CANNOT delegate" in base)
    chk("REGRESSION: main's own delegation instructions are untouched — the "
        "tool IS real there",
        base.count("mcp__team__spawn_subagent") >= 5,
        base.count("mcp__team__spawn_subagent"))

    # --------------------------------------------------------------- web
    section("web: what the sandbox can reach, and what survives the wire")
    chk("the OOB block warns that extraction does not decode",
        "SEND THE FLAG RAW" in web_p)
    chk("...and names base64 explicitly, since that is the reflex",
        "base64" in web_p)
    chk("REGRESSION: local-instance guidance says the sandbox cannot reach it",
        "cannot reach it" in web_p)
    chk("...and tells the shipped script to target the real host",
        "argv" in web_p and "not as the endpoint you ship against" in web_p)
    chk("the 2 GiB per-container cap is stated", "2 GiB each" in web_p)
    # The cap is real: the worker's `docker` is a shim that injects --memory.
    dshim = shutil.which("docker") or ""
    chk("...and the shim that enforces it is on PATH",
        dshim.startswith("/usr/local/bin"), dshim)

    # --------------------------------------------------------- scaffold
    section("the scaffold import the prompt hands out must actually work")
    # These are the three lines from modules/pwn/prompts.py, verbatim. All of
    # them raised ModuleNotFoundError in both images: /opt is on no sys.path
    # and there is no __init__.py, so `scaffold` was never importable — the
    # section that exists to stop agents rewriting heap primitives died on its
    # own first line. Both Dockerfiles now symlink it into site-packages.
    try:
        from scaffold.fsop_wfile import build_full_chain, VTABLE_OFFSET  # noqa: F401
        from scaffold.tcache_poison import safe_link, key_bypass_needed  # noqa: F401
        from scaffold.aslr_retry import aslr_retry, expected_attempts_for  # noqa: F401
        ok, err = True, ""
    except Exception as e:  # noqa: BLE001
        ok, err = False, f"{type(e).__name__}: {e}"
    chk("all three prompt-supplied imports resolve", ok, err)

    import modules.pwn.prompts as _PW
    psp = _PW.SYSTEM_PROMPT
    chk("REGRESSION: the prompt names key_bypass_needed, the symbol that "
        "exists — `needs_key_bypass` never did",
        "key_bypass_needed" in psp and "needs_key_bypass" not in psp)
    chk("...and that is what the scaffold actually defines",
        hasattr(importlib.import_module("scaffold.tcache_poison"),
                "key_bypass_needed"))
    chk("REGRESSION: /opt is NOT on sys.path — putting it there would make "
        "`import gef` resolve to the GEF gdb plugin",
        "/opt" not in sys.path, [p for p in sys.path if p.startswith("/opt")])
    chk("...so gef stays unimportable", importlib.util.find_spec("gef") is None)

    # ------------------------------------------------------------- /tmp
    section("scratch-path policy must not contradict itself")
    # $TMPDIR is <work>/tmp, which resolves to the SAME path inside the
    # auto-run sandbox because it lives in the job tree. /tmp does not: a
    # script that writes /tmp/x while investigating and reads it back at
    # auto-run finds nothing. /tmp is also shared by every job and subagent in
    # this container. The prompt banned it in three places and then handed out
    # copy-pasteable `/tmp/...` recipes in a dozen others — and a concrete
    # example beats an abstract prohibition every time.
    import re as _re
    PROSE = ("NEVER", "never", "shared across", "does not exist", "used to say",
             "clobber", "wrote /tmp/x", "hardcode", "forbids")
    for m in ("crypto", "pwn", "rev", "web", "misc", "forensic"):
        sp = getattr(importlib.import_module(f"modules.{m}.prompts"),
                     "SYSTEM_PROMPT", "") or ""
        bad = [l.strip() for l in sp.splitlines()
               if "/tmp/" in l and "TMPDIR" not in l
               and not any(k in l for k in PROSE)]
        chk(f"  {m}: no command-shaped /tmp example survives", not bad, bad[:2])
    base_sp = getattr(importlib.import_module("modules.pwn.prompts"),
                      "SYSTEM_PROMPT", "") or ""
    chk("REGRESSION: the sweep recipe — the most copy-pasteable of them all — "
        "uses $TMPDIR", "tee $TMPDIR/sweep.out" in base_sp)
    chk("REGRESSION: the debugger's scratch mandate no longer says /tmp, which "
        "the same prompt's own rule forbids",
        "MUST go under /tmp/" not in base)
    chk("...and points at $TMPDIR instead", "MUST go under `$TMPDIR/`" in base)
    chk("the ban itself still reads as a ban (prose keeps saying /tmp)",
        "NEVER write to /tmp/<filename>" in base)

    # -------------------------------------------------------- chain rules
    section("the prejudge rules the prompt lists must be the real ones")
    # The prompt listed 3 of prejudge's 6 critical rules and then said a
    # leak-only chain ships fine if you mark the blocked primitives
    # verified:false. Following that HONESTLY trips the two rules it omitted:
    # a leak-only chain usually has no verified primitive, and the truthful
    # rce_target ("leak only", "not achieved", "PARTIAL …") is exactly what
    # _RCE_TARGET_NEGATIVE / _RCE_TARGET_PARTIAL_PREFIX block on. The prompt
    # was penalising honesty — dress rce_target up and it passes.
    from modules.pwn.chain_schema import validate_chain

    def _crit(d):
        return [m for sev, m in validate_chain(d) if sev == "critical"]

    _base = dict(
        primitives=[{"id": "P1", "name": "leak", "verified": True,
                     "verify_method": "probe"},
                    {"id": "P2", "name": "aaw", "verified": False,
                     "reason_failed": "probe said no"}],
        steps=[{"n": 1, "action": "leak libc", "uses_primitives": ["P1"],
                "prereq": "none", "verify": "x&0xfff==0"}])

    chk("REGRESSION: an honest 'leak only' rce_target IS blocked — the old "
        "prompt promised it would pass",
        bool(_crit(dict(_base, rce_target="__free_hook = system (leak only, "
                                          "not achieved)"))))
    chk("REGRESSION: a bare 'PARTIAL …' prefix is blocked too",
        bool(_crit(dict(_base, rce_target="PARTIAL — leak works, no write"))))
    chk("REGRESSION: an all-unverified primitive set is blocked",
        bool(_crit(dict(
            primitives=[{"id": "P1", "name": "a", "verified": False,
                         "reason_failed": "no"}],
            steps=[{"n": 1, "action": "x", "uses_primitives": [],
                    "prereq": "none", "verify": "v"}],
            rce_target="__free_hook = system"))))
    chk("naming the GOAL — what the prompt now teaches — passes",
        not _crit(dict(_base, rce_target="__free_hook = system")))

    chain_txt = psp
    for rule in ("EVERY primitive has `verified: false`",
                 "self-declares no RCE",
                 "untestable\n     LOCALLY"):
        chk(f"  the prompt now states: {rule.splitlines()[0][:44]}…",
            rule.replace("\n     ", " ") in chain_txt.replace("\n     ", " "))
    chk("REGRESSION: it no longer promises a partial chain ships",
        "prejudge passes; postjudge will" not in chain_txt)
    chk("...and says where partial progress belongs instead",
        "`reason_failed`" in chain_txt and "not a status field" in chain_txt)
    chk("it tells the agent a block is a retry, not a dead end",
        "fix-and-retry turn" in chain_txt)

    # ------------------------------------------------------------ render
    section("all six modules still render")
    for m in ("crypto", "pwn", "rev", "web", "misc", "forensic"):
        try:
            sp = getattr(importlib.import_module(f"modules.{m}.prompts"),
                         "SYSTEM_PROMPT", "") or ""
            chk(f"  {m} renders ({len(sp):,d} chars)", len(sp) > 5000, len(sp))
        except Exception as e:  # noqa: BLE001
            chk(f"  {m} renders", False, str(e)[:80])

    failed = [r for r in _results if not r]
    print(f"\n{len(_results)} checks, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
