#!/usr/bin/env python3
"""Regression suite for flag detection.

Run from the repo root:   python3 scripts/test_flag_scan.py

THE INCIDENT — job 0c04e636633c (rev, 96 turns, $13.30, 2h49m)
It finished with meta.flags == ["DH{ + 36 chars of [a-z0-9_] + }"], which is a
DESCRIPTION of a flag format, not a flag. Its provenance:

    solver.py:306        print("target: DH{ + 36 chars of [a-z0-9_] + }")
    solver.py.stdout:1   that banner
    solver.py.stdout:25  "no flag found; tried 3383296 candidates in 1500s"
    report.md            "The flag itself was not captured"
    findings.json        exploit_status: "tested-failed"
    solver emitted       ZERO FLAG_CANDIDATE markers

Two defects let that through.

1. The operator's `flag_format` feature compiled a LOOSER matcher than the
   generic FLAG_RE it replaces:
       FLAG_RE           \\{[^\\s}]{1,200}\\}     -- no whitespace, ever
       job_flag_format_re \\{[^}\\r\\n]{1,256}\\}  -- spaces, brackets, plus signs
   The docstring advertises the feature as NARROWING the match. On the
   whitespace axis it was strictly wider, so an English sentence between the
   braces matched. Turning the safety feature ON is what manufactured the
   false positive. Same class appeared at two more sites (the brace-flag
   reducers in _scan_markers and _accumulate_flag_candidates).

2. The TRUSTED tier merges two very different sub-tiers: an explicit
   FLAG_CANDIDATE marker, and a bare regex sweep of the same files. Here the
   marker tier correctly returned empty and the sweep scraped the banner —
   from a stream whose own last line said it had found nothing.
"""
from __future__ import annotations

import ast as _ast
import argparse
import json
import pathlib
import re
import shutil
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

MUTATIONS = (
    "weak-any-tier-terminal",
    "drop-marker-clause",
    "drop-success-clause",
    "accept-runner-regex",
    "drop-provenance-passage",
)

parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()


def _replace_once(source: str, old: str, new: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"mutation anchor count is {count}, expected 1: {old!r}")
    return source.replace(old, new, 1)


COMMON_SOURCE = (ROOT / "modules" / "_common.py").read_text()
_GATE_RETURN = '''    return verdict == "success" or (
        bool(flags_now) and provenance_tier == "marker"
    )'''
if args.mutate == "weak-any-tier-terminal":
    COMMON_SOURCE = _replace_once(
        COMMON_SOURCE, _GATE_RETURN,
        '    return verdict == "success" or bool(flags_now)',
    )
elif args.mutate == "drop-marker-clause":
    COMMON_SOURCE = _replace_once(
        COMMON_SOURCE, _GATE_RETURN, '    return verdict == "success"',
    )
elif args.mutate == "drop-success-clause":
    COMMON_SOURCE = _replace_once(
        COMMON_SOURCE, _GATE_RETURN,
        '    return bool(flags_now) and provenance_tier == "marker"',
    )
elif args.mutate == "accept-runner-regex":
    COMMON_SOURCE = _replace_once(
        COMMON_SOURCE,
        'bool(flags_now) and provenance_tier == "marker"',
        'bool(flags_now) and provenance_tier in ("marker", "runner_regex")',
    )
elif args.mutate == "drop-provenance-passage":
    COMMON_SOURCE = _replace_once(
        COMMON_SOURCE,
        '''                sandbox_result=last_sandbox,
                provenance_out=flag_provenance,
''',
        '''                sandbox_result=last_sandbox,
''',
    )

_results: list[bool] = []


def chk(label: str, cond: bool, got: object = "") -> None:
    _results.append(bool(cond))
    print(("PASS  " if cond else "FAIL  ") + label + ("" if cond else f"  | got={got!r}"))


def section(name: str) -> None:
    print("\n--- " + name + " " + "-" * max(0, 56 - len(name)))


def _load(jobdir: pathlib.Path, flag_format: str = ""):
    """Load the real scanner with job_dir / read_meta redirected."""
    tree = _ast.parse(COMMON_SOURCE)
    nodes = [n for n in tree.body if isinstance(n, _ast.Assign)]
    nodes += [n for n in tree.body if isinstance(n, _ast.FunctionDef)
              and n.name in {"scan_job_for_flags", "_is_placeholder_flag",
                             "job_flag_format_re", "_recorded_artifact_names",
                             "_auto_retry_success"}]
    ns: dict = {
        "re": re, "json": json, "os": __import__("os"),
        "Path": pathlib.Path,
        "job_dir": lambda j: jobdir,
        "read_meta": lambda j: ({"flag_format": flag_format} if flag_format else {}),
        "log_line": lambda j, s: _logs.append(s),
    }
    for n in nodes:
        try:
            exec(compile(_ast.Module(body=[n], type_ignores=[]), "<s>", "exec"), ns)
        except Exception:
            pass
    return ns


_logs: list[str] = []


def _job(**files) -> pathlib.Path:
    d = pathlib.Path(tempfile.mkdtemp())
    for name, text in files.items():
        (d / name.replace("__", ".")).write_text(text)
    return d


# The exact banner from the incident.
BANNER = "target: DH{ + 36 chars of [a-z0-9_] + }"
DENIAL = "no flag found; tried 3383296 candidates in 1500s"
REAL = "DH{bb3cd526550f28ebc618d59e4bebcb6ec82d09dd6d8a98d3d13cb0c695c4796d}"
REAL2 = "DH{Br1ll1ant_bit_dr1bble_<<_>>}"
CANDIDATE_PLACEHOLDER = "DH{candidate_here}"
NARRATIVE_CAPTURE = "DH{2996f516cdf17978ee6dda6d02b35b}"
NARRATIVE_DECOY = "DH{real_looking_but_fake_2026}"


def main() -> int:
    section("the matcher must not be widened by turning the guard ON")
    generic = re.compile(r"DH\{[^\s}]{1,200}\}")
    src = (ROOT / "modules" / "_common.py").read_text()
    fmt_line = [l for l in src.splitlines()
                if "re.escape(prefix)" in l and "re.compile" in l]
    chk("job_flag_format_re exists", len(fmt_line) == 1, fmt_line)
    chk("REGRESSION: it excludes whitespace, like FLAG_RE",
        r"[^\s}]" in fmt_line[0], fmt_line[0].strip())
    chk("...and no longer uses the permissive class",
        r"[^}\r\n]" not in fmt_line[0], fmt_line[0].strip())
    reducers = [l for l in src.splitlines() if "_bf = re.search(" in l]
    chk("both brace-flag reducers tightened too",
        len(reducers) == 2 and all(r"[^\s}]" in l for l in reducers), reducers)

    section("the incident, end to end")
    d = _job(**{"solver.py__stdout": BANNER + "\n" + DENIAL + "\n",
                "solver.py__stderr": "",
                "result.json": json.dumps({"stdout": BANNER + "\n" + DENIAL})})
    ns = _load(d, flag_format="DH{...}")
    chk("the banner is NOT a flag (trusted tier)",
        ns["scan_job_for_flags"]("j", trusted_only=True) == [], )
    chk("...nor at any tier", ns["scan_job_for_flags"]("j") == [])

    section("a real capture must still be found")
    d = _job(**{"solver.py__stdout": REAL + "\n", "solver.py__stderr": ""})
    ns = _load(d, flag_format="DH{...}")
    chk("a bare real flag is found", ns["scan_job_for_flags"]("j", trusted_only=True) == [REAL])

    d = _job(**{"solver.py__stdout": REAL2 + "\n", "solver.py__stderr": ""})
    ns = _load(d, flag_format="DH{...}")
    chk("a real flag with punctuation is found",
        ns["scan_job_for_flags"]("j", trusted_only=True) == [REAL2],
        ns["scan_job_for_flags"]("j", trusted_only=True))

    section("the MARKER tier is never subject to the denial rule")
    d = _job(**{"solver.py__stdout": DENIAL + "\nFLAG_CANDIDATE: " + REAL + "\n",
                "solver.py__stderr": ""})
    ns = _load(d, flag_format="DH{...}")
    chk("an explicit marker wins over a stale denial line",
        ns["scan_job_for_flags"]("j", trusted_only=True) == [REAL],
        ns["scan_job_for_flags"]("j", trusted_only=True))
    marker_pv: dict = {}
    marker_flags = ns["scan_job_for_flags"](
        "j", trusted_only=True, provenance_out=marker_pv
    )
    chk("REGRESSION: marker capture terminates despite a crash verdict",
        ns["_auto_retry_success"](marker_flags, "crash", marker_pv.get("tier", "")),
        (marker_flags, marker_pv))

    section("a sweep hit under a denial is dropped — but LOUDLY")
    _logs.clear()
    d = _job(**{"solver.py__stdout": REAL + "\n" + DENIAL + "\n",
                "solver.py__stderr": ""})
    ns = _load(d, flag_format="DH{...}")
    got = ns["scan_job_for_flags"]("j", trusted_only=True)
    chk("the sweep hit is suppressed", got == [], got)
    chk("REGRESSION: the operator is told, with the candidate",
        any("FLAG SWEEP SUPPRESSED" in l and REAL in l for l in _logs), _logs)
    chk("...and told how to override it",
        any("FLAG_CANDIDATE" in l for l in _logs), _logs)

    section("...but a denial BEFORE the flag is about an earlier attempt")
    # The suppression rule reads the run's own words. Order is what makes those
    # words mean anything: a brute-force loop that prints a per-attempt failure
    # and THEN the flag is the normal shape of success, not of failure. Reading
    # the whole file (as this first did) silently loses that flag — the exact
    # class that cost job a3d4d448 a genuine DH{<64 hex>}.
    _logs.clear()
    d = _job(**{"solver.py__stdout": "k=1: no flag found\nk=2: " + REAL + "\n",
                "solver.py__stderr": ""})
    ns = _load(d, flag_format="DH{...}")
    got = ns["scan_job_for_flags"]("j", trusted_only=True)
    chk("a flag printed AFTER a per-attempt denial survives", got == [REAL], got)
    chk("...and nothing is logged as suppressed", not _logs, _logs)

    section("provenance names WHICH tier promoted the flag")
    d = _job(**{"solver.py__stdout": "FLAG_CANDIDATE: " + REAL + "\n",
                "solver.py__stderr": ""})
    ns = _load(d, flag_format="DH{...}")
    pv: dict = {}
    ns["scan_job_for_flags"]("j", trusted_only=True, provenance_out=pv)
    chk("an explicit marker reports tier=marker", pv.get("tier") == "marker", pv)

    d = _job(**{"solver.py__stdout": REAL + "\n", "solver.py__stderr": ""})
    ns = _load(d, flag_format="DH{...}")
    pv = {}
    ns["scan_job_for_flags"]("j", trusted_only=True, provenance_out=pv)
    chk("REGRESSION: a bare sweep hit is NOT reported as a declaration",
        pv.get("tier") == "runner_regex", pv)
    chk("REGRESSION: bare runner regex does not terminate on a crash verdict",
        not ns["_auto_retry_success"]([REAL], "crash", pv.get("tier", "")), pv)

    d = _job(**{"report.md": "the flag is " + REAL + "\n"})
    ns = _load(d, flag_format="DH{...}")
    pv = {}
    ns["scan_job_for_flags"]("j", provenance_out=pv)
    chk("agent prose reports tier=narrative", pv.get("tier") == "narrative", pv)

    d = _job(**{"solver.py__stdout": "nothing here\n"})
    ns = _load(d, flag_format="DH{...}")
    pv = {}
    ns["scan_job_for_flags"]("j", provenance_out=pv)
    chk("no flag reports no tier", pv.get("tier") == "", pv)

    section("a metavariable is not a capture, even digit-led")
    # The gap the whitespace parity fix does NOT close: `<64hex>` has no
    # whitespace, so it rides the plain FLAG_RE path too. `DH{<36 chars>}` was
    # in this job's findings.json.
    d = _job(**{"solver.py__stdout": "recovered: DH{<64hex>}\n",
                "solver.py__stderr": ""})
    ns = _load(d, flag_format="DH{...}")
    ph = ns["_is_placeholder_flag"]
    for meta_v in ("DH{<64hex>}", "DH{<32hex>}", "DH{<36 chars>}",
                   "DH{<32_hex_chars>}", "DH{<flag>}"):
        chk(f"  {meta_v} is a placeholder at the TRUSTED tier",
            ph(meta_v, trusted=True), meta_v)
    chk("REGRESSION: the bit-shift flag DH{Br1ll1ant_bit_dr1bble_<<_>>} survives",
        not ph("DH{Br1ll1ant_bit_dr1bble_<<_>>}", trusted=True)
        and not ph("DH{Br1ll1ant_bit_dr1bble_<<_>>}"))
    chk("...and a digit-led metavariable never reaches meta.flags",
        ns["scan_job_for_flags"]("j", trusted_only=True) == [],
        ns["scan_job_for_flags"]("j", trusted_only=True))

    section("narrative placeholders must not terminate auto-retry")
    for job_id in ("5c3974d26ab4", "47de39fd0c01", "94d105ace230"):
        d = _job(**{"report.md": "candidate: " + CANDIDATE_PLACEHOLDER + "\n"})
        ns = _load(d, flag_format="DH{...}")
        flags = ns["scan_job_for_flags"](job_id)
        chk(f"REGRESSION {job_id}: DH{{candidate_here}} is filtered",
            flags == [], flags)
        chk(f"REGRESSION {job_id}: filtered prose keeps the retry loop open",
            not ns["_auto_retry_success"](flags, "crash", ""), flags)

    source = COMMON_SOURCE
    chk("REGRESSION: production scan passes provenance to the retry gate",
        source.count("provenance_out=flag_provenance,") == 1
        and source.count(
            'flags_now, verdict, flag_provenance.get("tier", "")'
        ) == 1)
    _event_start = source.find('            emit_event(\n                job_id,\n'
                               '                "run",\n                "flag_gate",')
    _event_end = source.find('            if terminal_capture:', _event_start)
    _event = source[_event_start:_event_end] if _event_start >= 0 else ""
    chk("REGRESSION: the attempt event joins provenance, verdict, and decision",
        _event_start >= 0 and all(
            token in _event for token in (
                "flags_count=", "tier=", "suppressed=", "verdict=",
                "exit_code=", "terminal_capture=", "reason=",
            )
        ), _event)

    section("non-placeholder narrative stays visible without short-circuiting")
    # A narrative value is still returned to each module's final analyzer scan,
    # which writes that same list to meta.flags; only this retry decision changes.
    d = _job(**{"report.md": "example only: " + NARRATIVE_DECOY + "\n"})
    ns = _load(d, flag_format="DH{...}")
    decoy_pv: dict = {}
    decoy_flags = ns["scan_job_for_flags"]("decoy", provenance_out=decoy_pv)
    chk("REGRESSION: a plausible narrative decoy stays visible for curation",
        decoy_flags == [NARRATIVE_DECOY] and decoy_pv.get("tier") == "narrative",
        (decoy_flags, decoy_pv))
    chk("REGRESSION: narrative decoy + crash does not terminate auto-retry",
        not ns["_auto_retry_success"](
            decoy_flags, "crash", decoy_pv.get("tier", "")
        ), (decoy_flags, decoy_pv))

    d = _job(**{"report.md": "captured live: " + NARRATIVE_CAPTURE + "\n"})
    ns = _load(d, flag_format="DH{...}")
    pv = {}
    flags = ns["scan_job_for_flags"]("07d256325546", provenance_out=pv)
    chk("REGRESSION 07d256325546: the narrative capture survives",
        flags == [NARRATIVE_CAPTURE] and pv.get("tier") == "narrative",
        (flags, pv))
    chk("REGRESSION 07d256325546: crash+narrative keeps retry decision open",
        not ns["_auto_retry_success"](
            flags, "crash", pv.get("tier", "")
        ), (flags, pv))
    for success_tier in ("", "marker", "runner_regex", "narrative"):
        chk(f"judge success remains terminal at tier={success_tier or 'empty'}",
            ns["_auto_retry_success"]([], "success", success_tier), success_tier)
    chk("candidate plus real entropy is not classified as a placeholder",
        not ns["_is_placeholder_flag"](
            "DH{candidate_2996f516cdf17978ee6dda6d02b35b}"
        ))

    section("sibling matchers share the character class")
    crypto = (ROOT / "modules" / "crypto" / "pre_analysis.py").read_text()
    cline = [l for l in crypto.splitlines() if "re.escape(prefix).encode()" in l]
    chk("crypto's auto-solver matcher exists", len(cline) == 1, cline)
    chk("REGRESSION: it excludes whitespace too — the format match IS its "
        "only proof of correctness",
        cline and r"[^\s}]" in cline[0] and r"[^}\n]" not in cline[0],
        cline)

    section("a flagless run is not 'finished' — in EVERY module")
    for mod, path in (("forensic", "modules/forensic/orchestrator.py"),
                      ("misc", "modules/misc/orchestrator.py")):
        text = (ROOT / path).read_text()
        chk(f"  {mod} gates its terminal status on flags",
            'final_status = "finished" if flags else "no_flag"' in text
            and 'status="finished", stage="done"' not in text,
            [l.strip() for l in text.splitlines()
             if "final_status" in l or 'status="finished"' in l][:3])

    section("no regression against every real flag on record")
    lib = pathlib.Path("/home/yadohyun/HexTech_CTF_TOOL/data/exploits")
    flags: list[str] = []
    if lib.is_dir():
        for mp in lib.glob("*/meta.json"):
            try:
                flags += (json.loads(mp.read_text()).get("flags") or [])
            except Exception:
                pass
    if not flags:
        chk("(exploit library unreadable here — skipped)", True)
    else:
        lost = []
        for fl in flags:
            m = re.match(r"([A-Za-z][A-Za-z0-9_]{1,15})\{", fl)
            if not m:
                continue
            tight = re.compile(re.escape(m.group(1)) + r"\{[^\s}]{1,256}\}")
            if not tight.search(fl):
                lost.append(fl)
        chk(f"all {len(flags)} stored flags still match the tightened class",
            not lost, lost[:3])
        chk("none of them contains whitespace inside the braces",
            not [f for f in flags if re.search(r"\{[^}]*\s", f)],
            [f for f in flags if re.search(r"\{[^}]*\s", f)][:2])

    failed = [r for r in _results if not r]
    print(
        f"\n{len(_results)} checks, {len(failed)} failed; "
        f"mutation={args.mutate or 'none'}"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
