#!/usr/bin/env bash
#
# start.sh — one-command bring-up for HexTech_CTF_TOOL.
#
# Brings up the core stack (redis, api, worker) AND builds the on-demand
# sandbox tool images (runner, decompiler, forensic, misc) the worker spawns
# per job. Those four sit behind `profiles: ["tools"]` in docker-compose.yml,
# so a plain `docker compose up -d` SKIPS them — and a job then dies at
# sandbox-spawn time with:
#
#     pull access denied for hextech_ctf_tool-runner, repository does not exist
#
# That exact gap silently failed job d6681eeb7288 (no_flag, exploit never ran).
# This script closes it: the tool images are always ensured before the stack
# is declared ready.
#
# Usage:
#   ./start.sh                 build any missing tool images, then bring up core
#   ./start.sh --rebuild       force-rebuild ALL images (core + tools), then up
#   ./start.sh --with-sage     additionally pull the SageMath solver image
#   ./start.sh --no-build      skip image builds; just `up -d` the core stack
#   ./start.sh --down          stop + remove the core stack and exit
#   ./start.sh -h | --help     show this help
#
# Idempotent: safe to re-run. Builds are layer-cached, so re-running when
# everything is already present costs only a few seconds.

set -euo pipefail

# --- run from the repo root no matter where we're invoked from -------------
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- pretty output (no color when not a TTY) -------------------------------
if [ -t 1 ]; then
  B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; C=$'\033[36m'; N=$'\033[0m'
else
  B=''; G=''; Y=''; R=''; C=''; N=''
fi
say()  { printf '%s==>%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '  %s✗%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

# --- the four on-demand images and their compose service names -------------
TOOL_IMAGES=(hextech_ctf_tool-runner hextech_ctf_tool-decompiler \
             hextech_ctf_tool-forensic hextech_ctf_tool-misc)
TOOL_SERVICES=(decompiler forensic misc runner)   # compose builds by service name

# --- flags -----------------------------------------------------------------
REBUILD=0; WITH_SAGE=0; NO_BUILD=0; DOWN=0
for arg in "$@"; do
  case "$arg" in
    --rebuild)   REBUILD=1 ;;
    --with-sage) WITH_SAGE=1 ;;
    --no-build)  NO_BUILD=1 ;;
    --down)      DOWN=1 ;;
    -h|--help)
      sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) die "unknown option: $arg (try --help)" ;;
  esac
done

# --- preflight: docker + compose -------------------------------------------
command -v docker >/dev/null 2>&1 || die "docker not found on PATH"
if docker compose version >/dev/null 2>&1; then
  DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  DC=(docker-compose)
else
  die "neither 'docker compose' nor 'docker-compose' is available"
fi
docker info >/dev/null 2>&1 || die "docker daemon not reachable (is it running? do you have permission?)"

# --- --down short-circuit --------------------------------------------------
if [ "$DOWN" -eq 1 ]; then
  say "Stopping core stack"
  "${DC[@]}" down
  ok "stopped"
  exit 0
fi

# --- .env --------------------------------------------------------------------
if [ ! -f .env ]; then
  if [ -f .env.example ]; then
    cp .env.example .env
    warn ".env was missing — copied from .env.example."
    warn "Edit it (HOST_DATA_DIR to the absolute path of $(pwd)/data) before real use."
  else
    die ".env is missing and no .env.example to seed it from"
  fi
fi

# --- auth hint (non-fatal) -------------------------------------------------
CLAUDE_HOME="${HOST_CLAUDE_HOME:-$HOME/.claude}"
if [ ! -d "$CLAUDE_HOME" ]; then
  warn "Claude config dir not found at $CLAUDE_HOME."
  warn "Run 'claude login' on the host for OAuth, or set ANTHROPIC_API_KEY in .env / Settings."
fi

# --- which tool images are missing -----------------------------------------
missing=()
for img in "${TOOL_IMAGES[@]}"; do
  docker image inspect "$img" >/dev/null 2>&1 || missing+=("$img")
done

# --- build tool images ------------------------------------------------------
if [ "$NO_BUILD" -eq 1 ]; then
  if [ "${#missing[@]}" -gt 0 ]; then
    warn "--no-build set, but these tool images are MISSING: ${missing[*]}"
    warn "Jobs will fail at sandbox-spawn until you build them (drop --no-build)."
  fi
elif [ "$REBUILD" -eq 1 ]; then
  say "Force-rebuilding tool images: ${TOOL_SERVICES[*]}"
  "${DC[@]}" --profile tools build "${TOOL_SERVICES[@]}"
  ok "tool images rebuilt"
elif [ "${#missing[@]}" -gt 0 ]; then
  say "Building missing tool images (${missing[*]})"
  "${DC[@]}" --profile tools build "${TOOL_SERVICES[@]}"
  ok "tool images built"
else
  ok "all 4 tool images already present — skipping build (use --rebuild to force)"
fi

# --- optional SageMath solver image ----------------------------------------
if [ "$WITH_SAGE" -eq 1 ]; then
  say "Pulling SageMath solver image (sage profile)"
  "${DC[@]}" --profile tools-sage pull sage
  ok "sage image pulled"
fi

# --- stop any stale cloudflared OOB tunnel from a prior run -----------------
# The tunnel runs as a docker-run SIBLING (hextech_ctf_tool_tunnel, label
# hextech_ctf_tool_role=tunnel), NOT a compose service; a stale one would keep
# pointing at the old api and hold a dead Callback URL. Reap it before bringing
# the stack up — re-activate via Settings > Activate tunnel afterwards.
say "Removing any stale cloudflared tunnel sibling container"
docker rm -f hextech_ctf_tool_tunnel >/dev/null 2>&1 && ok "removed stale hextech_ctf_tool_tunnel" || true
for c in $(docker ps -aq --filter "label=hextech_ctf_tool_role=tunnel" 2>/dev/null); do
  docker rm -f "$c" >/dev/null 2>&1 || true
done

# --- KVM passthrough for pwn KERNEL challenges (host-conditional) -----------
# The worker's qemu-system-x86_64 can boot a challenge's own kernel under KVM
# only if the host's /dev/kvm is passed into the container. A hard `devices:`
# entry in docker-compose.yml would make `up` FAIL on any host without
# /dev/kvm (no nested virt, CI, macOS), so the committed compose stays
# portable and we generate an OPTIONAL override that Compose auto-merges ONLY
# when the device is present. Gate: /dev/kvm exists AND ENABLE_KVM != 0. The
# file self-identifies (marker) so a hand-authored override is never
# clobbered, and we REMOVE our own stale copy when /dev/kvm vanishes (a host
# that lost nested virt shouldn't keep a broken device mapping).
OVR=docker-compose.override.yml
KVM_MARKER="# AUTO-GENERATED by start.sh: KVM device passthrough"
if [ "${ENABLE_KVM:-1}" != "0" ] && [ -e /dev/kvm ]; then
  if [ ! -f "$OVR" ] || grep -qF "$KVM_MARKER" "$OVR" 2>/dev/null; then
    cat > "$OVR" <<YAML
$KVM_MARKER
# Regenerated on every ./start.sh. Set ENABLE_KVM=0 in .env to disable, or
# replace the marker line above to hand-manage this file. Passing /dev/kvm
# lets the worker's qemu-system-x86_64 use -enable-kvm for kernel pwn.
services:
  worker:
    devices:
      - /dev/kvm:/dev/kvm
YAML
    ok "KVM present (/dev/kvm) — wrote $OVR (worker gets -enable-kvm)"
  else
    warn "$OVR is hand-authored (no marker) — leaving it untouched; add"
    warn "  a '/dev/kvm:/dev/kvm' device to worker yourself if you want KVM."
  fi
elif [ -f "$OVR" ] && grep -qF "$KVM_MARKER" "$OVR" 2>/dev/null; then
  rm -f "$OVR"
  say "No /dev/kvm (or ENABLE_KVM=0) — removed stale generated $OVR"
fi

# --- bring up / (re)build the core stack -----------------------------------
# --build is layer-cached (a no-op recreate when nothing changed) and
# self-heals a core image that was pruned, so we always pass it.
say "Bringing up core stack (redis, api, worker)"
"${DC[@]}" up -d --build

# --- verify -----------------------------------------------------------------
say "Verifying"
fail=0

for img in "${TOOL_IMAGES[@]}"; do
  if docker image inspect "$img" >/dev/null 2>&1; then
    ok "image $img"
  else
    warn "image $img STILL MISSING"; fail=1
  fi
done

for svc in redis api worker; do
  state="$("${DC[@]}" ps --format '{{.Service}} {{.State}}' 2>/dev/null | awk -v s="$svc" '$1==s{print $2}')"
  if [ "$state" = "running" ]; then
    ok "service $svc running"
  else
    warn "service $svc not running (state='${state:-absent}')"; fail=1
  fi
done

# stamp web-ui/version.json so the UI version badge shows the deployed commit
# (start.sh has cd'd to its own dir above, so the relative path is correct)
[ -x ./stamp-version.sh ] && ./stamp-version.sh || true

# --- summary ----------------------------------------------------------------
WEB_PORT="$(grep -E '^WEB_PORT=' .env 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '[:space:]')"
WEB_PORT="${WEB_PORT:-8000}"
echo
if [ "$fail" -eq 0 ]; then
  printf '%sHexTech_CTF_TOOL is up.%s  Open %shttp://localhost:%s%s\n' "$B$G" "$N" "$C" "$WEB_PORT" "$N"
else
  die "startup finished with problems (see warnings above)"
fi

# --- auto-start the cloudflared OOB tunnel (auto-sets Callback URL) ----------
# Honors AUTO_TUNNEL from .env (default 1); skips cleanly if cloudflared isn't
# installed. The api is verified up above, so the tunnel can publish its URL.
# Reached only on success (die exits otherwise). Stop later: ./tunnel.sh stop
AT="$(grep -E '^AUTO_TUNNEL=' .env 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '[:space:]')"
if [ "${AT:-1}" != "0" ]; then
  say "Auto-starting cloudflared OOB tunnel (set AUTO_TUNNEL=0 in .env to skip)"
  AUTO_TUNNEL=1 PROJECT_DIR="$(pwd)" WEB_PORT="$WEB_PORT" API_BASE="http://localhost:$WEB_PORT" \
    bash scripts/tunnel-autostart.sh || true
fi
