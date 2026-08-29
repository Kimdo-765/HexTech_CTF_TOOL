#!/usr/bin/env python3
"""The challenge's engine, not the worker's — enforced below the prompt.

A kernel challenge ships its emulator inside its own Dockerfile and its
launcher invokes it BY NAME, so PATH alone decided which build ran:

    chal/Dockerfile   FROM ubuntu:24.04 ; apt install qemu-system-x86 -> 8.2.2
    chal/run.sh       exec qemu-system-x86_64 ...
    this worker       Debian 13                                       -> 10.0.11

Measured, the divergence is observable: the guest-visible iPXE option-ROM base
is PMM+0EFC6D30 on the worker and PMM+0EFCAE00 in the challenge container, and
the REMOTE prints the container's value.  Five jobs of one lineage developed
against the wrong build.

Fixing the PROMPT was tried first and measured insufficient — job
2a4ecbec367b still ran 12 of 19 boots on the worker's qemu, because the actor
doing the booting was a subagent and modules/codex_cli.py records that child
agents do not inherit main's developer prompt.  So the guarantee has to live
below the prompt, the way worker/docker_memguard.sh already does.

WHAT THIS SUITE PINS
  * the shim's do-nothing rule: every precondition failure exec's the real
    binary, so a worker without a job / image / socket / HOST_DATA_DIR behaves
    exactly as it did before the file existed
  * the trigger is the challenge's own LAUNCHER, not the docker_challenge
    checkbox (37 corpus jobs carry the checkbox; 4 touch qemu-system)
  * the image is reclaimed, because building automatically is what made that
    necessary — there was no `docker rmi` anywhere in the repo before

Run from the repository root::

    python3 scripts/test_chal_engine_parity.py
    python3 scripts/test_chal_engine_parity.py --mutate trigger-on-checkbox
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SHIM = ROOT / "worker" / "chal_engine_shim.sh"
CHALBOX = ROOT / "modules" / "_chalbox.py"
DOCKERFILE = ROOT / "worker" / "Dockerfile"
SHIM_SRC = SHIM.read_text()
CHALBOX_SRC = CHALBOX.read_text()

MUTATIONS = (
    "trigger-on-dockerfile-only",
    "relocate-outside-paths",
    "no-cwd-fallback",
    "build-without-image-check",
    "drop-image-reclaim",
    "relocatable-includes-python",
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
    shim, box = SHIM_SRC, CHALBOX_SRC
    if args.mutate == "trigger-on-dockerfile-only":
        # Build whenever a Dockerfile exists — the 37-vs-4 cost objection.
        box = _replace_once(
            box,
            "    engines = launcher_engines(ctx)\n"
            "    return (ctx, engines) if engines else (None, [])\n",
            "    engines = launcher_engines(ctx)\n"
            "    return ctx, engines\n",
        )
    elif args.mutate == "relocate-outside-paths":
        box = box  # shim-only mutation
        shim = _replace_once(
            shim,
            "            if [ -e \"$_arg\" ]; then\n"
            "                _passthrough \"$@\"\n"
            "            fi\n",
            "            : \n",
        )
    elif args.mutate == "no-cwd-fallback":
        shim = _replace_once(
            shim,
            "        /data/jobs/*)\n"
            "            JOB=\"${PWD#/data/jobs/}\"\n"
            "            JOB=\"${JOB%%/*}\"\n"
            "            ;;\n",
            "        /data/jobs/*) : ;;\n",
        )
    elif args.mutate == "build-without-image-check":
        shim = _replace_once(
            shim,
            'docker image inspect "$IMAGE" >/dev/null 2>&1 || _passthrough "$@"\n',
            ": \n",
        )
    elif args.mutate == "drop-image-reclaim":
        box = _replace_once(
            box,
            '        proc = subprocess.run([_docker_bin(), "rmi", "-f", img],\n',
            '        proc = subprocess.run([_docker_bin(), "version"],\n',
        )
    elif args.mutate == "relocatable-includes-python":
        # A shim for an interpreter would shadow the worker's own — the
        # /usr/local/bin/python3 that carries pwntools.
        box = _replace_once(
            box,
            'RELOCATABLE_ENGINES = ("qemu-system-x86_64", "qemu-system-i386",\n',
            'RELOCATABLE_ENGINES = ("python3", "qemu-system-x86_64", "qemu-system-i386",\n',
        )
    return shim, box


SHIM_TEXT, CHALBOX_TEXT = _mutated()

_box = types.ModuleType("_chal_engine_parity_box")
_box.__file__ = str(CHALBOX)
sys.modules["_chal_engine_parity_box"] = _box
exec(compile(CHALBOX_TEXT, str(CHALBOX), "exec"), _box.__dict__)

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


# --------------------------------------------------------------- the trigger

def _bundle(tmp: Path, *, dockerfile: bool, launcher: str | None) -> tuple:
    """A synthetic job tree: <root>/work/chal is pwn's autoboot unpack target."""
    work = tmp / "work"
    chal = work / "chal"
    chal.mkdir(parents=True)
    if dockerfile:
        (chal / "Dockerfile").write_text(
            "FROM ubuntu:24.04\nRUN apt install qemu-system-x86 socat -y\n"
        )
    if launcher is not None:
        (chal / "run.sh").write_text(launcher)
    return tmp, work


def _trigger_checks() -> None:
    B = _box
    with tempfile.TemporaryDirectory() as td:
        # The real shape: a Dockerfile AND a launcher that execs the engine.
        root, work = _bundle(Path(td) / "a", dockerfile=True,
                             launcher="#!/bin/bash\nexec qemu-system-x86_64 "
                                      "-m 256 -kernel ./bzImage\n")
        ctx, eng = B.should_build(root, work)
        check("T1 a bundle whose launcher execs the engine builds",
              (ctx is not None, eng), (True, ["qemu-system-x86_64"]))

        # A Dockerfile ALONE must not build. This is the cost objection: 37
        # corpus jobs carry docker_challenge=true, 4 touch qemu-system.
        root2, work2 = _bundle(Path(td) / "b", dockerfile=True,
                               launcher="#!/bin/sh\nexec ./chal_binary\n")
        ctx2, eng2 = B.should_build(root2, work2)
        check("T2 a Dockerfile with no engine launcher does NOT build",
              (ctx2, eng2), (None, []))

        # ...and the two cases must differ, or the predicate is a constant.
        check("T2 ...and the two cases genuinely differ",
              (ctx is not None) != (ctx2 is not None), True)

        # No Dockerfile at all: nothing to build from.
        root3, work3 = _bundle(Path(td) / "c", dockerfile=False,
                               launcher="exec qemu-system-x86_64\n")
        check("T3 an engine launcher with no Dockerfile does not build",
              B.should_build(root3, work3)[0], None)

    # The engine list must stay dedicated challenge engines. An interpreter
    # shim would shadow the worker's own — /usr/local/bin/python3 is the one
    # carrying pwntools — and a chal image that merely CONTAINS python3 would
    # capture the agent's tooling.
    check("T4 only dedicated challenge engines are relocatable",
          [e for e in B.RELOCATABLE_ENGINES
           if not e.startswith("qemu-system-")], [])


def _detector_checks() -> None:
    B = _box
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        work = root / "work"
        (work / "chal").mkdir(parents=True)
        # The engine appears in run.sh, NOT in the Dockerfile's package list —
        # which is the real shape: bc257's CMD is a socat that execs run.py
        # that execs run.sh, and no package name reveals the invocation.
        (work / "chal" / "Dockerfile").write_text("FROM ubuntu:24.04\n")
        (work / "chal" / "run.sh").write_text("exec qemu-system-x86_64 -m 256\n")
        ctx, eng = B.should_build(root, work)
        check("D1 the engine is read from the LAUNCHER, not the package list",
              eng, ["qemu-system-x86_64"])
        check("D1 ...and the build context is the dir holding the Dockerfile",
              ctx.name, "chal")

    # A carve/extract hazard: the detector must not walk a job root looking for
    # any Dockerfile anywhere. It checks a fixed candidate list.
    check("D2 the detector does not walk the tree",
          "rglob" in CHALBOX_TEXT or "os.walk" in CHALBOX_TEXT, False)

    # The image name must be derivable identically by the shim, which builds
    # it as chal_$JOB with no sanitising of its own.
    check("D3 the image name is the plain per-job tag",
          B.image_name("2a4ecbec367b"), "chal_2a4ecbec367b")
    check("D3 ...and a hostile job id cannot inject shell or tag syntax",
          B.image_name("a b;rm -rf /"), "chal_abrm-rf")
    # The shim derives the tag itself as chal_$JOB with no sanitising of its
    # own, so the two derivations must agree on the shape that actually
    # occurs. Job ids are hex, which is why the plain concatenation is safe.
    shim_tag = re.search(r'IMAGE="([^"]+)"', SHIM_TEXT)
    check("D4 the shim derives the same tag the builder writes",
          shim_tag.group(1) if shim_tag else None, "chal_${JOB}")
    check("D4 ...and a real job id survives sanitising unchanged",
          B.image_name("2a4ecbec367b"), "chal_" + "2a4ecbec367b")


# ------------------------------------------------------- the shim's contract

def _shim_checks() -> None:
    # The whole design rule: a precondition failure leaves the caller exactly
    # as it was. Count the exits into the real binary.
    n_pass = len(re.findall(r"_passthrough \"\$@\"", SHIM_TEXT))
    check("S1 every precondition exits into the real binary",
          n_pass >= 4, True)

    for label, needle in (
        ("no JOB_ID and no job-shaped cwd", '[ -n "$JOB" ] || _passthrough'),
        ("no HOST_DATA_DIR", '[ -n "${HOST_DATA_DIR:-}" ] || _passthrough'),
        ("no image built", 'docker image inspect "$IMAGE"'),
    ):
        check(f"S1 ...including: {label}", needle in SHIM_TEXT, True)

    # The cwd fallback is load-bearing: the actor that boots is USUALLY a
    # subagent, which may not carry JOB_ID.
    check("S2 the job is derivable from the cwd when JOB_ID is absent",
          'JOB="${PWD#/data/jobs/}"' in SHIM_TEXT, True)

    # A path outside the mount is unreachable after relocation. Found by
    # RUNNING the shim, not reading it: the first end-to-end test passed
    # -hda /tmp/dummy_payload and the guest never booted. That is a break,
    # not a no-op.
    check("S3 an absolute path outside the job mount passes through",
          '/data/jobs/"$JOB"/*) ;;' in SHIM_TEXT, True)
    check("S3 ...and only when the path really exists on the worker",
          'if [ -e "$_arg" ]; then' in SHIM_TEXT, True)

    # The accelerator is part of the machine: neither stripped nor added.
    check("S4 the shim does not strip or inject an accelerator flag",
          bool(re.search(r"(sed|tr|shift).*enable-kvm", SHIM_TEXT)), False)
    check("S4 ...but passes the device through when the caller asked for KVM",
          "--device /dev/kvm" in SHIM_TEXT, True)
    check("S4 ...only when the host actually has it",
          "[ -c /dev/kvm ]" in SHIM_TEXT, True)

    # Same absolute path inside and out is what makes the caller's own
    # arguments work untouched.
    check("S5 the bind maps the job dir at its own absolute path",
          '-v "${HOST_DATA_DIR}/jobs/${JOB}:/data/jobs/${JOB}"' in SHIM_TEXT,
          True)
    check("S5 ...and the working directory is preserved",
          '-w "$PWD"' in SHIM_TEXT, True)

    # Reapable, and stdin-attached for a -nographic guest.
    check("S6 the container is labelled for the reaper",
          '--label "hextech_job=${JOB}"' in SHIM_TEXT, True)
    check("S6 stdin is attached but no tty is allocated",
          "--rm -i \\" in SHIM_TEXT and " -t " not in SHIM_TEXT, True)

    # It must be valid shell.
    proc = subprocess.run(["bash", "-n", str(SHIM)], capture_output=True,
                          text=True)
    check("S7 the shipped shim parses as bash", proc.returncode, 0)


# --------------------------------------------------------------- reclamation

def _reclaim_checks() -> None:
    check("R1 the image is reclaimed by tag",
          '"rmi", "-f", img' in CHALBOX_TEXT, True)
    # Never prune the builder cache: the layers are what make a retry rebuild
    # in milliseconds.
    check("R1 ...without pruning the layer cache",
          "builder prune" in CHALBOX_TEXT or "system prune" in CHALBOX_TEXT,
          False)
    analyzer = (ROOT / "modules" / "pwn" / "analyzer.py").read_text()
    check("R2 the analyzer calls the reclaim at job end",
          "_chalbox.remove_image(" in analyzer, True)
    check("R2 ...and starts the build off the critical path",
          "_chalbox.build_in_background(" in analyzer, True)
    # The state dir is re-derived every attempt, so carrying it forward would
    # hand a successor a PREVIOUS job's image tag.
    retry = (ROOT / "api" / "routes" / "retry.py").read_text()
    check("R3 the chalbox state is not carried into a retry",
          '".chalbox"' in retry, True)


# ------------------------------------------------------------- installation

def _install_checks() -> None:
    df = DOCKERFILE.read_text()
    check("I1 the shim is installed ahead of /usr/bin on PATH",
          "/usr/local/bin/qemu-system-x86_64" in df, True)
    # Linking an engine the image does not ship turns "command not found" into
    # "silently ran the x86 emulator".
    for absent in ("qemu-system-aarch64", "qemu-system-arm"):
        check(f"I2 no symlink for the absent {absent}",
              f"/usr/local/bin/{absent}" in df, False)
    check("I3 the Dockerfile chmods the shim",
          "chmod +x /app/worker/chal_engine_shim.sh" in df, True)

    # ...and that chmod is NOT sufficient, which is why the next check exists.
    #
    # /app/worker is a READ-ONLY BIND MOUNT (docker-compose.yml: ./worker ->
    # /app/worker:ro), so the mode baked into the image layer is replaced at
    # runtime by the HOST file's mode. A 644 script behind an executable-
    # looking symlink is invisible to PATH lookup: the shell skips it and
    # resolves straight to /usr/bin, and the shim silently never runs.
    #
    # This shipped. The rebuild deployed a correct shim that direct invocation
    # relocated perfectly, while `command -v qemu-system-x86_64` still answered
    # /usr/bin/qemu-system-x86_64 — the file was 100644 in git. The working
    # memguard beside it is 100755, which is the whole difference.
    #
    # Checked in GIT's index rather than the working tree: a local chmod does
    # not survive a clone, and the deployment checkout is a clone.
    proc = subprocess.run(
        ["git", "ls-files", "-s", "worker/chal_engine_shim.sh",
         "worker/docker_memguard.sh"],
        cwd=str(ROOT), capture_output=True, text=True,
    )
    modes = dict(
        (line.split("\t")[-1], line.split()[0])
        for line in proc.stdout.splitlines() if line.strip()
    )
    check("I4 the shim carries git's executable bit",
          modes.get("worker/chal_engine_shim.sh"), "100755")
    check("I4 ...matching the shim that already works",
          modes.get("worker/docker_memguard.sh"), "100755")


def main() -> int:
    _trigger_checks()
    _detector_checks()
    _shim_checks()
    _reclaim_checks()
    _install_checks()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
