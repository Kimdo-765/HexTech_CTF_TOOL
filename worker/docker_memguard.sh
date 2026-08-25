#!/usr/bin/env bash
# docker-memguard — a `docker` shim that injects a memory cap into `docker run`
# / `docker create` when the caller did not set one.
#
# WHY THIS EXISTS
# Each worker slot container is capped by a cgroup (WORKER_SLOT_MEM), but every
# container the AGENT starts is a SIBLING — a separate cgroup no slot's cap
# bounds. Nothing taught the agent to pass --memory, so challenge
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
# CPU LEAKS THE SAME WAY, and it went unbounded for as long as memory did.
# 2026-08-25, job 0a22d7fa7919: an agent fanned its own search into 36
# processes and took 2467% CPU on a 32-core host (load average 45.8) while
# eight other slots crawled. Nothing misbehaved — there was simply no ceiling.
# Worker slots and the runner are now capped at 8 CPUs each; a container the
# AGENT starts is a sibling of both and is bounded here, or nowhere.
#
# --cpus is injected the same way --memory is, and for the same reason: a later
# occurrence of the flag wins, so a caller's own --cpus (which necessarily
# comes after ours) overrides it for free. VERIFIED, not assumed — docker
# 29.6.1, `--cpus 1 --cpus 4` yields cpu.max 400000/100000 and `--cpus 8
# --cpus 2` yields 200000/100000.
#
# TUNING: CHAL_CONTAINER_MEM (default 2g) and CHAL_CONTAINER_CPUS (default 8).
# Each is disabled by setting it to an empty value or `0`. NOTE the change in
# the escape hatch: CHAL_CONTAINER_MEM=0 alone no longer makes the shim fully
# transparent, because the CPU cap is a separate guarantee. Set BOTH to 0 for
# the old pass-through-everything behaviour.

set -o pipefail
# Overridable ONLY so the guard can be tested by pointing it at a recorder that
# prints its argv instead of starting a container. Production never sets it;
# an unset variable keeps the previous hard-coded path exactly.
REAL="${DOCKER_MEMGUARD_REAL:-/usr/bin/docker}"
LIMIT="${CHAL_CONTAINER_MEM-2g}"
CPUS="${CHAL_CONTAINER_CPUS-8}"

_off() { [ -z "$1" ] || [ "$1" = "0" ]; }

# Both caps disabled, or the real docker is missing → behave exactly like
# plain docker.
if { _off "$LIMIT" && _off "$CPUS"; } || [ ! -x "$REAL" ]; then
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
# `docker network create` leaks the same way containers do, and worse in one
# respect: docker's default address pool is finite, so accumulated
# `chal_<id>_net` bridges eventually fail new job setups outright with "could
# not find an available, non-overlapping IPv4 address pool". Three orphaned
# networks with zero attached containers were found 2026-08-02. Labelling them
# lets the end-of-job sweep in modules/_common.reap_job_siblings take them
# back. No --memory here — a network has no cgroup.
if [ "$sub" = "network" ] && [ -n "${JOB_ID:-}" ]; then
    nsub=""; seen_network=0
    for a in "$@"; do
        case "$a" in
            -*) ;;
            network) [ "$seen_network" -eq 0 ] && seen_network=1 || { nsub="$a"; break; } ;;
            *) if [ "$seen_network" -eq 1 ]; then nsub="$a"; break; fi ;;
        esac
    done
    if [ "$nsub" = "create" ]; then
        out=(); done_inject=0
        for a in "$@"; do
            out+=("$a")
            if [ "$done_inject" -eq 0 ] && [ "$a" = "create" ]; then
                out+=(--label "hextech_ctf_tool_job_id=$JOB_ID")
                done_inject=1
            fi
        done
        echo "[docker-memguard] tagged network with hextech_ctf_tool_job_id=$JOB_ID" >&2
        exec "$REAL" "${out[@]}"
    fi
fi

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
#
# The job label rides along for two reasons, and the second one is the bigger
# win. It makes the container ATTRIBUTABLE in the Containers tab — without it
# an agent-started container carries no trace of which job made it, and once
# that job's directory is deleted the link is gone for good (measured
# 2026-08-02: of 12 orphaned challenge containers, only the 3 whose names
# happened to embed a job id could be attributed at all). And it makes the
# container REAPABLE: api/routes/jobs.py `_hard_stop_job` already force-removes
# every sibling labelled `hextech_ctf_tool_job_id=<id>`, so labelling closes
# the leak itself rather than only reporting it.
#
# JOB_ID is exported into the agent's environment by the orchestrator and this
# shim runs as a descendant of the agent's Bash, so it is inherited (verified
# live on job 926773a15d8b). Omitted entirely when unset — an unlabelled
# container is the status quo, whereas a label reading `=` would be a lie that
# `_hard_stop_job` could match against the wrong thing.
out=(); done_inject=0; applied=""
for a in "$@"; do
    out+=("$a")
    if [ "$done_inject" -eq 0 ] && [ "$a" = "$sub" ]; then
        if ! _off "$LIMIT"; then
            out+=(--memory "$LIMIT"); applied="$applied --memory $LIMIT"
        fi
        if ! _off "$CPUS"; then
            out+=(--cpus "$CPUS"); applied="$applied --cpus $CPUS"
        fi
        [ -n "${JOB_ID:-}" ] && out+=(--label "hextech_ctf_tool_job_id=$JOB_ID")
        done_inject=1
    fi
done

echo "[docker-memguard] defaults applied:${applied:- none}" \
     "${JOB_ID:+plus label hextech_ctf_tool_job_id=$JOB_ID }" \
     "(pass the flag yourself to override, or set" \
     "CHAL_CONTAINER_MEM=0 / CHAL_CONTAINER_CPUS=0)" >&2
exec "$REAL" "${out[@]}"
