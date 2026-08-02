#!/usr/bin/env python3
"""Regression suite for the pre-recon clip / mandatory-section gate.

Run from the repo root:   python3 scripts/test_pre_recon_clip.py

THE BUG THESE PROTECT AGAINST
Job 71edd90398f4, pwn. run.log:

    [04:15:07] reply was 34763 chars — elided 2763 from the middle …
    [04:15:07] respawn attempt 1/4 (missing=['ENV-AWARE PATHS'], len=32166)
    [04:25:45] reply was 35852 chars — elided 3852 from the middle …
    [04:25:45] respawn 1 still degraded (missing=['ENV-AWARE PATHS'], len=32166)
    [04:25:50] respawn attempt 2/4 (missing=['ENV-AWARE PATHS'], len=32166)

`len=32166` identical on every attempt — 32000 plus a 166-char marker. The
model was NOT omitting the section: the head-70%/tail-30% cut removed bytes
22400..26252, and `ENV-AWARE PATHS` sat inside that band. The gate then read
the CLIPPED text, concluded the model had dropped a section, and respawned —
which regenerates a similarly-long report that gets cut in the same place.
Structurally unable to converge: ~$1.20 and ~5 min per attempt, up to 4,
against ~$0.047 for simply passing the whole reply once.

The same failure had already happened at the old 8 KB cap (job 302cd87de603,
4 attempts at len=8013, 44 min and ~$6.4). That fix raised the cap and
switched tail-cut to middle-cut, which moved the boundary without removing
the structural flaw. These tests pin the flaw itself.
"""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

MANDATORY = ("INT-OVERFLOW ANALYSIS", "HEAP STATE MATRIX",
             "ENV-AWARE PATHS", "RCE TARGET TABLE")
CAP = 32000

_results: list[bool] = []


def chk(label: str, cond: bool, got: object = "") -> None:
    _results.append(bool(cond))
    print(("PASS  " if cond else "FAIL  ") + label + ("" if cond else f"  | got={got!r}"))


def section(name: str) -> None:
    print("\n--- " + name + " " + "-" * max(0, 56 - len(name)))


def _load():
    """Import just the two helpers, without _common's dependency tree."""
    import ast as _ast
    src = (ROOT / "modules" / "_common.py").read_text()
    tree = _ast.parse(src)
    want = {"PreReconReply", "_elide_preserving", "PRE_RECON_MAX_CHARS"}
    nodes = [n for n in tree.body
             if (isinstance(n, (_ast.FunctionDef, _ast.ClassDef)) and n.name in want)
             or (isinstance(n, _ast.Assign)
                 and any(getattr(t, "id", "") in want for t in n.targets))]
    ns: dict = {"re": __import__("re")}
    exec(compile(_ast.Module(body=nodes, type_ignores=[]), "<c>", "exec"), ns)
    gate_src = (ROOT / "modules" / "pwn" / "analyzer.py").read_text()
    gtree = _ast.parse(gate_src)
    gnodes = [n for n in gtree.body
              if isinstance(n, _ast.FunctionDef) and n.name == "_missing_pre_recon_sections"]
    exec(compile(_ast.Module(body=gnodes, type_ignores=[]), "<g>", "exec"), ns)
    return ns


def _reply_like_the_real_one(total: int = 35852) -> str:
    """A reply shaped like the one that broke: every mandatory title present,
    ENV-AWARE PATHS positioned inside the band the old cut removed."""
    body = []
    # titles spread across the document; ENV-AWARE PATHS lands ~byte 23000,
    # i.e. inside the 22400..26252 window the head/tail cut drops.
    at = {"INT-OVERFLOW ANALYSIS": 2000, "HEAP STATE MATRIX": 12000,
          "ENV-AWARE PATHS": 23000, "RCE TARGET TABLE": 30000}
    buf = ["x"] * total
    for title, pos in at.items():
        buf[pos:pos + len(title)] = list(title)
    return "".join(buf)


def main() -> int:
    ns = _load()
    elide = ns["_elide_preserving"]
    missing = ns["_missing_pre_recon_sections"]
    Reply = ns["PreReconReply"]
    logs: list[str] = []

    chk("the constant is still the 32 KB the incident was measured at",
        ns["PRE_RECON_MAX_CHARS"] == CAP, ns["PRE_RECON_MAX_CHARS"])

    full = _reply_like_the_real_one()
    chk("the synthetic reply has every mandatory section",
        missing(full, MANDATORY) == [], missing(full, MANDATORY))

    # ---------------------------------------------------------------- the bug
    section("the old blind middle cut (what broke)")
    head = full[: int(CAP * 0.7)]
    tail = full[-(CAP - len(head)):]
    old_clipped = head + "\n\n…(elided)…\n\n" + tail
    chk("old cut LOSES 'ENV-AWARE PATHS'",
        "ENV-AWARE PATHS" in missing(old_clipped, MANDATORY),
        missing(old_clipped, MANDATORY))
    chk("...so the gate on the CLIPPED text respawns",
        missing(old_clipped, MANDATORY) != [])

    # ------------------------------------------------------------- layer 1
    section("layer 1 — the gate reads the PRE-CLIP text")
    reply = Reply(old_clipped, full)
    chk("PreReconReply is still a plain str to every other caller",
        isinstance(reply, str) and str(reply) == old_clipped)
    chk("...and carries the original",
        getattr(reply, "full", None) == full)
    chk("the gate on .full sees NO missing section -> no respawn",
        missing(getattr(reply, "full", reply), MANDATORY) == [],
        missing(getattr(reply, "full", reply), MANDATORY))
    chk("getattr degrades safely on a plain str",
        getattr("bare", "full", "bare") == "bare")

    # ------------------------------------------------------------- layer 2
    section("layer 2 — the clip avoids the mandatory titles")
    logs.clear()
    new_clipped = elide(full, CAP, MANDATORY, logs.append, "t")
    chk("every mandatory title survives the new clip",
        missing(new_clipped, MANDATORY) == [], missing(new_clipped, MANDATORY))
    chk("it actually clipped (result is near the cap)",
        len(new_clipped) <= CAP + 600, len(new_clipped))
    chk("it says what it cut", logs and "elided" in logs[0], logs)

    # a reply UNDER the cap must be untouched
    small = "INT-OVERFLOW ANALYSIS HEAP STATE MATRIX ENV-AWARE PATHS RCE TARGET TABLE"
    chk("under the cap is a no-op", elide(small, CAP, MANDATORY, logs.append, "t") == small)

    # ------------------------------------------------------------- fallback
    section("fallback — mandatory sections alone overflow the budget")
    logs.clear()
    # Titles repeated so densely that their protected spans (title + 200 chars
    # of context, merged) cover the whole document, leaving no droppable gap.
    # A real reply can reach this by quoting the headings in a table of
    # contents and again per-section.
    dense = ("ENV-AWARE PATHS" + "z" * 40) * 900
    out = elide(dense, CAP, MANDATORY, logs.append, "t")
    chk("still produces something bounded", len(out) <= CAP + 600, len(out))
    chk("and says the gate is protected anyway",
        logs and "PRE-CLIP" in logs[0], logs)

    # ------------------------------------------------- the gate still works
    section("a REAL omission must still respawn")
    truly_missing = full.replace("RCE TARGET TABLE", "SOMETHING ELSE ENTIRELY")
    chk("a genuinely absent section is still reported",
        missing(truly_missing, MANDATORY) == ["RCE TARGET TABLE"],
        missing(truly_missing, MANDATORY))
    chk("...even when carried on a PreReconReply",
        missing(getattr(Reply(truly_missing[:100], truly_missing), "full", ""),
                MANDATORY) == ["RCE TARGET TABLE"])

    failed = [r for r in _results if not r]
    print(f"\n{len(_results)} checks, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
