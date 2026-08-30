#!/usr/bin/env bash
# chal-engine — a `qemu-system-*` shim that relocates the call into the
# CHALLENGE'S OWN container, so the emulator the agent tests on is the one the
# target runs.
#
# WHY THIS EXISTS
# A kernel challenge ships its own engine inside its Dockerfile, and its
# launcher invokes that engine BY NAME:
#
#   chal/Dockerfile   FROM ubuntu:24.04 ; apt install qemu-system-x86 -> 8.2.2
#   chal/run.sh       exec qemu-system-x86_64 ...
#   this worker       Debian 13                                       -> 10.0.11
#
# So PATH decides which binary runs, and an agent that copies the challenge's
# launcher perfectly still tests on a build two major versions away. The
# divergence is observable, not theoretical — the iPXE option-ROM base printed
# at boot differs, and the challenge container's value matches the REMOTE's:
#
#   worker                    PMM+0EFC6D30
#   chal container / remote   PMM+0EFCAE00
#
# The msgbox lineage lost five jobs to this. Job 047de616a1e0 swept
# VICT_BASE 0..31 looking for a working victim slot — the entire search ran on
# qemu 10. Job bc257c849c91 refuted its whole atomic-RMW hypothesis on qemu 10
# and only then noticed the gap, with no way to act on it.
#
# WHY A PROMPT DID NOT FIX IT
# The guidance WAS fixed first (modules/pwn/prompts.py now says the accelerator
# is part of the machine, and that the emulator itself is a version). Job
# 2a4ecbec367b then ran 12 of its 19 boots on the worker's qemu anyway. The
# actor doing the booting was a `debugger` subagent, and modules/codex_cli.py's
# own comment records why it never saw that guidance:
#
#     "Child agents do not automatically receive the main agent's developer
#      prompt."
#
# Only the output-language policy is copied into role overlays. So the advice
# reached main and main delegated the booting. Same lesson as
# worker/docker_memguard.sh, whose header states it plainly: prompt adherence
# is not a guarantee, and the guarantee is the point. This is the enforcement
# point.
#
# FAILURE MODE IS "DO NOTHING", NEVER "BREAK"
# Every precondition below exits into the real binary. A worker without the
# image, without a job, without a docker socket, or without HOST_DATA_DIR
# behaves exactly as it did before this file existed.

set -u

REAL="${CHAL_ENGINE_REAL:-/usr/bin/$(basename "$0")}"
[ -x "$REAL" ] || REAL="/usr/bin/qemu-system-x86_64"

# The name we were invoked as IS the entrypoint we ask the container for, so
# one shim serves every qemu-system-* symlink pointed at it.
ENGINE="$(basename "$0")"

# WHY THIS SHIM LOGS AT ALL
#
# It shipped silent, and job 1da7e690ddcd then booted 20 times: 14 on the
# worker's qemu, 6 relocated, split cleanly by time. Four hypotheses for the
# bypass were eliminated by test — the symlink is installed, the exec bit is
# set, a login shell still resolves to it, and both eras used relative paths.
# The fifth needs the invocation, and the invocation is not recorded: BOTH
# agent models delegate the booting, and delegated tool calls never reach
# gpt-events.jsonl (13 `wait` events, zero subagent Bash rows).
#
# So the shim is the only witness to its own decisions. Without this it can
# fail on half a job's boots and leave nothing to read.
#
# Written to a FILE, not stderr: the agent parses qemu's output, and a line
# injected there is a line it may try to interpret. The one exception is the
# case where no job can be identified — there is no job-scoped place to write,
# and that is precisely the case most worth seeing, so it goes to stderr with
# a prefix the way worker/docker_memguard.sh already does.
_log_shim() {
    _reason="$1"
    shift
    if [ -n "${JOB:-}" ] && [ -d "/data/jobs/${JOB}/work" ]; then
        _dir="/data/jobs/${JOB}/work/.chalbox"
        mkdir -p "$_dir" 2>/dev/null || return 0
        {
            printf '%s engine=%s %s\n' \
                "$(date -u +%H:%M:%S 2>/dev/null || echo '??:??:??')" \
                "$ENGINE" "$_reason"
            printf '    cwd=%s\n    argv=%s\n' "$PWD" "$*"
        } >> "$_dir/shim.log" 2>/dev/null
    else
        printf '[chal-engine] %s (no job identified; cwd=%s)\n' \
            "$_reason" "$PWD" >&2
    fi
}

# Every precondition exits through here, and each names ITSELF — a log that
# only says "passed through" answers the question one step too late.
_passthrough() {
    _why="$1"
    shift
    _log_shim "PASS-THROUGH: $_why" "$@"
    exec "$REAL" "$@"
}

# ---------------------------------------------------------------- preconditions

# 1. Which job? JOB_ID is set in the agent's session env
#    (modules/_common.py), but a subagent or a detached shell may not carry it,
#    and the booting actor here is USUALLY a subagent. So fall back to the cwd,
#    which is /data/jobs/<id>/... for every agent shell.
JOB="${JOB_ID:-}"
if [ -z "$JOB" ]; then
    case "$PWD" in
        /data/jobs/*)
            JOB="${PWD#/data/jobs/}"
            JOB="${JOB%%/*}"
            ;;
    esac
fi
[ -n "$JOB" ] || _passthrough "no JOB_ID and cwd is not under /data/jobs" "$@"

# 2. HOST_DATA_DIR is needed because the bind source is a HOST path — the
#    docker daemon resolves it, not this container.
[ -n "${HOST_DATA_DIR:-}" ] || _passthrough "HOST_DATA_DIR unset — the bind source is a HOST path" "$@"

# 3. The image must already exist. modules/_chalbox.py builds it at job start,
#    off the critical path, precisely so this check passes before the agent's
#    first boot. Building HERE would be worse than not relocating: an agent's
#    boot is routinely wrapped in `timeout 30`, and a cold build is minutes —
#    it would eat the very call it exists to fix.
IMAGE="chal_${JOB}"
docker image inspect "$IMAGE" >/dev/null 2>&1 \
    || _passthrough "no image $IMAGE (chalbox did not build, or docker is unreachable)" "$@"

# 4. Every path the caller named must be REACHABLE after relocation. The
#    container mounts /data/jobs/<id> and nothing else, so an absolute path
#    outside it — /tmp/payload, /opt/something — exists on the worker and not
#    in the container.
#
#    Found by running this shim, not by reading it: the first end-to-end test
#    passed `-hda /tmp/dummy_payload` and the guest simply never booted. That
#    is a BREAK, not a no-op, and the whole design rule here is that a
#    precondition failure must leave the caller exactly as it was. The agent's
#    own TMPDIR is /data/jobs/<id>/work/tmp (modules/_common.py sets it), so
#    scratch files are inside the mount in normal use and this rarely fires.
#
#    Relative paths are fine by construction: -w "$PWD" makes them resolve
#    against the same directory inside the container.
for _arg in "$@"; do
    case "$_arg" in
        /data/jobs/"$JOB"/*) ;;
        /*)
            # A bare flag like -nographic never matches /*; a value that looks
            # like an outside path does. Only treat it as a path when it
            # actually exists on the worker — otherwise a string that merely
            # starts with / (a -append value, say) would disable the shim.
            if [ -e "$_arg" ]; then
                _passthrough "argument $_arg is outside the job mount and exists on this worker" "$@"
            fi
            ;;
    esac
done

# ------------------------------------------------------------------- accelerator

# The accelerator is part of the machine, not a speed knob, so it is NOT
# stripped or added — whatever the caller asked for is what runs. But KVM needs
# the device, and a container does not get it by default. Pass it through only
# when the caller actually asked, and only when the host really has it: a
# --device for a missing node fails the run, which would violate the
# do-nothing-on-doubt rule above.
KVM_ARGS=""
case " $* " in
    *" -enable-kvm "*|*" -accel kvm"*|*"accel=kvm"*)
        if [ -c /dev/kvm ]; then
            KVM_ARGS="--device /dev/kvm"
        fi
        ;;
esac

# --------------------------------------------------------------------- relocate

# -w "$PWD" with a bind at the SAME absolute path is what makes the caller's
# arguments work untouched — relative paths like ./chal/bzImage and absolute
# ones like /data/jobs/<id>/work/chal/flag both resolve. modules/_runner.py
# uses the same trick and its comment records why.
#
# -i keeps stdin attached (a -nographic guest reads it); deliberately no -t,
# which would break piped input.
#
# --label is what reap_chal_containers cleans by, and matters here because a
# `timeout` that kills this client can leave the container behind.
#
# `docker` resolves to worker/docker_memguard.sh, which injects --memory and
# --cpus. That is wanted: a challenge VM started this way is a sibling cgroup
# that nothing else bounds.
# Log the relocation too, so the file is a COMPLETE record rather than a list
# of failures. "Six boots relocated and fourteen did not" is only readable if
# both halves are written; a log of pass-throughs alone cannot distinguish a
# shim that fired twenty times from one that never ran at all.
_log_shim "RELOCATED into ${IMAGE}${KVM_ARGS:+ (+kvm device)}" "$@"

exec docker run --rm -i \
    --label "hextech_job=${JOB}" \
    ${KVM_ARGS} \
    -v "${HOST_DATA_DIR}/jobs/${JOB}:/data/jobs/${JOB}" \
    -w "$PWD" \
    --entrypoint "$ENGINE" \
    "$IMAGE" "$@"
