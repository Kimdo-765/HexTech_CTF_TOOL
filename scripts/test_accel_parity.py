#!/usr/bin/env python3
"""The platform must not prescribe an engine the challenge does not use.

Measured on the msgbox kernel lineage (four jobs, four failures):

  * the challenge's own launcher runs `qemu-system-x86_64` with NO
    `-enable-kvm` and NO `-accel`, i.e. TCG software emulation
  * /dev/kvm IS present on the worker
  * the pwn prompt told the agent to "boot it LOCALLY under KVM", handed it a
    template containing `-enable-kvm`, and called that "true fidelity for THAT
    kernel"

KVM and TCG are different CPUs where kernel exploits live — they diverge on
atomics, on write-protection faults, and on self-modifying code.  So the
prescription was not a speed hint, it swapped the machine under test.  The
same block named only `-cpu` and `-append` as the flags to copy VERBATIM, and
its RESIDUAL caveats named KASLR and `-cpu host` but not the accelerator and
not the emulator's own version.

Separately, `no /dev/kvm` sat in chain_schema's UNTESTABLE-LOCALLY regex,
which downgrades a `critical` ship-block to a `med` "remote probe allowed".
A TCG launcher needs no /dev/kvm, so that phrase excused skipping a test that
was available — and it becomes a standing absolution once challenge execution
moves into the chal's own container, where /dev/kvm is absent by construction.

These are TEXT properties, checked offline.  scripts/test_prompt_claims.py is
the suite that EXECUTES a prompt's environment claims, but it has to run
inside the worker; this one guards the shape of the advice itself.

Run from the repository root::

    python3 scripts/test_accel_parity.py
    python3 scripts/test_accel_parity.py --mutate template-enables-kvm
"""
from __future__ import annotations

import argparse
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PROMPTS = ROOT / "modules" / "pwn" / "prompts.py"
SCHEMA = ROOT / "modules" / "pwn" / "chain_schema.py"
PROMPT_SRC = PROMPTS.read_text()
SCHEMA_SRC = SCHEMA.read_text()

MUTATIONS = (
    "template-enables-kvm",
    "verbatim-omits-accel",
    "residual-omits-version",
    "kvm-excuses-unverified",
    "restore-kvm-absolution",
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()


def _replace_once(source: str, old: str, new: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"mutation anchor count={count}, expected 1: {old!r}")
    return source.replace(old, new, 1)


def _mutated() -> tuple[str, str]:
    prompt, schema = PROMPT_SRC, SCHEMA_SRC
    if args.mutate == "template-enables-kvm":
        prompt = _replace_once(
            prompt,
            "        `qemu-system-x86_64 -m 256 -kernel ./bzImage \\\n",
            "        `qemu-system-x86_64 -enable-kvm -m 256 -kernel ./bzImage \\\n",
        )
    elif args.mutate == "verbatim-omits-accel":
        prompt = _replace_once(
            prompt,
            "      COPY the chal's run script's flags VERBATIM — `-cpu`, "
            "`-append`, AND\n      THE ACCELERATOR (or its absence).",
            "      COPY the chal's run script's flags VERBATIM — especially "
            "`-cpu` and\n      `-append`.",
        )
    elif args.mutate == "residual-omits-version":
        prompt = _replace_once(
            prompt,
            "        · THE EMULATOR ITSELF IS A VERSION.",
            "        · (removed)  ",
        )
    elif args.mutate == "kvm-excuses-unverified":
        prompt = _replace_once(
            prompt,
            "      (qemu-system missing, or a disk-image shape you can't drive), "
            "do NOT\n",
            "      (qemu-system missing, no /dev/kvm on this host, or a "
            "disk-image\n      shape you can't drive), do NOT\n",
        )
    elif args.mutate == "restore-kvm-absolution":
        schema = _replace_once(
            schema,
            r'    r"|wsl2|host kernel|worker kernel"' "\n",
            r'    r"|wsl2|host kernel|worker kernel|no /dev/kvm"' "\n",
        )
    return prompt, schema


PROMPT, SCHEMA_TEXT = _mutated()

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


def _kernel_block() -> str:
    """The YES (kernel-pwn) branch of the KERNEL fidelity note."""
    start = PROMPT.find("• YES (a kernel-pwn chal)")
    end = PROMPT.find("• NO (a userspace chal", start + 1)
    return PROMPT[start:end] if start >= 0 and end > start else ""


def _prescription_checks() -> None:
    block = _kernel_block()
    check("P0 the kernel-pwn branch is findable", bool(block), True)

    # The template is what an agent copies.  It must not hand over an
    # accelerator the challenge's own launcher does not have.
    templates = re.findall(r"`qemu-system-x86_64[^`]*`", block, re.S)
    check("P1 the block offers exactly one qemu template", len(templates), 1)
    check("P1 the template does not add an accelerator",
          any("-enable-kvm" in t or "-accel" in t for t in templates), False)
    check("P1 ...and still teaches the gdb stub",
          all("-s -S" in t for t in templates), True)

    # The VERBATIM list is the rule the template illustrates.  Naming only
    # -cpu and -append is what let the accelerator be added silently.
    #
    # Sliced to the VERBATIM SENTENCE, not the whole block: the block also
    # contains a standalone "THE ACCELERATOR IS PART OF THE MACHINE"
    # paragraph, so a block-wide substring test passes even with the rule
    # itself reverted — measured, it survived the verbatim-omits-accel
    # mutation.
    _v = block.find("VERBATIM")
    verbatim_rule = block[_v:_v + 200] if _v >= 0 else ""
    check("P2 the VERBATIM rule itself names the accelerator",
          "ACCELERATOR" in verbatim_rule.upper(), True)
    check("P2 ...and says its ABSENCE counts too",
          "or its absence" in verbatim_rule, True)
    check("P2 ...and says why: TCG is a different CPU, not a slower one",
          "TCG is a" in block and "DIFFERENT CPU" in block.upper(), True)

    # The RESIDUAL caveats are where an agent learns what a local boot does
    # NOT establish.  They named KASLR and -cpu host; the emulator's own
    # version was the one that cost this lineage four jobs.
    check("P3 the residual caveats name the emulator's version",
          "EMULATOR ITSELF IS A VERSION" in block.upper(), True)
    check("P3 ...and point at the chal's Dockerfile as the source of truth",
          "docker build" in block, True)
    check("P3 ...and still keep the KASLR leak-first rule",
          "KASLR" in block and "LEAK-FIRST" in block.upper(), True)

    # The absolution: "no /dev/kvm" must not be a reason to skip the boot,
    # because a TCG launcher does not need it.
    check("P4 a missing /dev/kvm is no longer a reason to skip the boot",
          re.search(r"can(?:not|'t) run\s*\n?\s*\([^)]*/dev/kvm", block) is not None,
          False)
    check("P4 ...and the block says so explicitly",
          "is NOT one of those reasons" in block, True)

    # The tool catalogue at the top repeats the same advice and was the other
    # half of the misprescription.
    check("P5 the tool list no longer advertises -enable-kvm as the entry",
          "`qemu-system-x86_64 -enable-kvm`    FULL-SYSTEM" in PROMPT, False)
    check("P5 ...and warns against adding it",
          "DO NOT add `-enable-kvm` unless" in PROMPT, True)


def _schema_checks() -> None:
    # Load the (possibly mutated) module to exercise the real regex rather
    # than a retyped copy of it.
    mod = types.ModuleType("_accel_parity_schema")
    mod.__file__ = str(SCHEMA)
    sys.modules["_accel_parity_schema"] = mod
    exec(compile(SCHEMA_TEXT, str(SCHEMA), "exec"), mod.__dict__)
    rx = mod._UNTESTABLE_LOCALLY_RE

    # TWO CASES, and they must differ.  One alone is satisfiable by a regex
    # that matches everything or nothing.
    kvm_phrases = [
        "local boot skipped: no /dev/kvm on this worker",
        "could not verify — /dev/kvm is not available",
    ]
    real_limits = [
        "vsyscall=none on this host, remote is the only test",
        "CET/SHSTK enforced by the WSL2 host kernel",
        "untestable locally without a matching-kernel VM",
        "only verifiable on the remote target",
    ]
    check("S1 a missing /dev/kvm no longer excuses an unverified primitive",
          [bool(rx.search(p)) for p in kvm_phrases], [False, False])
    check("S2 genuine env limits still do",
          [bool(rx.search(p)) for p in real_limits], [True] * len(real_limits))
    check("S3 ...and the two cases genuinely differ",
          any(rx.search(p) for p in real_limits)
          and not any(rx.search(p) for p in kvm_phrases), True)

    # The severity this actually gates, read from the source rather than
    # assumed: a match downgrades a critical ship-block to a med probe.
    check("S4 the regex still gates critical-vs-med, so removal has teeth",
          "_UNTESTABLE_LOCALLY_RE.search(_why)" in SCHEMA_TEXT, True)

    # The OTHER consumer pulls the opposite way — a match SUPPRESSES a
    # concession — so the removal was measured, not reasoned.  Pin that the
    # second consumer still exists, or a future reader will not know to look.
    common = (ROOT / "modules" / "_common.py").read_text()
    check("S5 the concede gate still reads the same regex",
          "_cs._UNTESTABLE_LOCALLY_RE.search(s)" in common, True)


def main() -> int:
    _prescription_checks()
    _schema_checks()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
