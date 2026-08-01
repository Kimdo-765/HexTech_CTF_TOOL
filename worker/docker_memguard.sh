#!/usr/bin/env bash
# docker-memguard — a `docker` shim that injects a memory cap into `docker run`
# / `docker create` when the caller did not set one.
#
# WHY THIS EXISTS
# The worker container is capped by a cgroup (WORKER_MEM_LIMIT), but every
# container the AGENT starts is a SIBLING — a separate cgroup the worker's cap
# does not bound. Nothing taught the agent to pass --memory, so challenge
# containers ran unlimited.
#
# 2026-08-01, job 0ddd62708d39: the chal image ran
#   socat TCP-LISTEN:5050,reuseaddr,fork EXEC:"./protoss"
# so every connection forked a fresh `./protoss`, and each one grew ~1-2 GiB
# per minute with no ceiling (measured: 2780 -> 2837 -> 2921 -> 3071 MiB over
# ~80 s on one process). The exploit was an ASLR-retry loop, i.e. it
# reconnected repeatedly. WSL2 died at 22:21:50 with the VM out of memory and
# — the tell — NO container recorded OOMKilled, because an uncapped container
# has no cgroup limit to hit: the kernel ran out globally instead.
#
# A prompt line asking for --memory would not fix this; prompt adherence is not
# a guarantee, and the guarantee is the point. This is the enforcement point.
#
# SCOPE — deliberately narrow:
#   * `run` and `create` only. Every other subcommand is exec'd untouched.
#   * If the caller already passed --memory / -m in any form, nothing changes.
#   * The orchestrator's own sibling containers (decompiler / forensic / misc /
#     runner) go through the docker-py SDK, not this CLI, so they are NOT
#     affected — and modules/_runner.py already sets its own mem_limit (2g).
#     The reachable callers are the agent's Bash and worker/chal_libc_fix.py.
#
# TUNING: CHAL_CONTAINER_MEM (compose env, default 2g). Setting it to an empty
# value or `0` disables injection entirely — an escape hatch that keeps the
# shim transparent rather than making an operator hunt for it.

set -o pipefail
REAL=/usr/bin/docker
LIMIT="${CHAL_CONTAINER_MEM-2g}"

# Disabled, or the real docker is missing → behave exactly like plain docker.
if [ -z "$LIMIT" ] || [ "$LIMIT" = "0" ] || [ ! -x "$REAL" ]; then
    exec "$REAL" "$@"
fi

# First non-flag argument is the subcommand. `docker --context foo run` would
# mis-read `foo` here; that is a pass-through (we only act on an exact `run` /
# `create` match), so the failure mode is "does nothing", never "breaks".
sub=""
for a in "$@"; do
    case "$a" in
        -*) ;;
        *) sub="$a"; break ;;
    esac
done
case "$sub" in
    run|create) ;;
    *) exec "$REAL" "$@" ;;
esac

# Inject unconditionally, immediately after the subcommand — do NOT try to
# detect an existing --memory first. Verified against docker 28: when the flag
# appears twice the LAST occurrence wins, so a caller's own --memory / -m,
# which necessarily comes later on the line, overrides this default for free.
#
# Scanning was the first implementation and it was WRONG: the args include the
# CONTAINER's own command line, so `docker run img cmd --memory ignored` looked
# pre-capped and the container launched unlimited — the exact case the guard
# exists for. A test caught it. No scan, no gap.
#
# Only --memory is injected, never --memory-swap: a caller passing --memory 8g
# would otherwise be paired with our 2g swap and docker rejects memory-swap <
# memory. RAM is what we are bounding; swap defaults still apply.
out=(); done_inject=0
for a in "$@"; do
    out+=("$a")
    if [ "$done_inject" -eq 0 ] && [ "$a" = "$sub" ]; then
        out+=(--memory "$LIMIT")
        done_inject=1
    fi
done

echo "[docker-memguard] default --memory $LIMIT applied" \
     "(pass --memory yourself to override, or set CHAL_CONTAINER_MEM=0)" >&2
exec "$REAL" "${out[@]}"
