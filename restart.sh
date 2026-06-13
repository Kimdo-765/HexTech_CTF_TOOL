#!/usr/bin/env bash
# =============================================================================
# restart.sh — completely restart the hextech_ctf_tool Docker project,
#              clearing the WSL2 "orphan-container trap".
#
# THE TRAP (why a plain `docker compose restart` is not enough):
#   A prior `up --force-recreate` / daemon hiccup can LEAK containerd-shim
#   processes that the `docker` CLI no longer tracks (`docker inspect <id>`
#   -> "no such object") yet that keep running: an orphan uvicorn holds
#   host :8000 serving STALE code with a STALE /data mount (so the collector
#   returns "ok" but logs nothing), and an orphan rq-worker pulls jobs with
#   stale modules/. Killing the orphan PID does NOT help — containerd respawns
#   it from the restart policy. The reliable fix is to restart the docker
#   daemon (snap), which re-syncs dockerd<->containerd and drops every shim.
#
# WHAT THIS DOES (default = HARD, the only reliable "complete" restart):
#   1. `docker compose down --remove-orphans`        (clean tracked state)
#   2. restart the docker daemon (snap, fallback systemd)   <- clears orphans
#   3. `docker compose up -d --force-recreate redis api worker`
#   4. VERIFY via LIVE host routes (not docker-exec): api :8000, the collector
#      actually logs a probe (the orphan-api bug), and rq workers registered.
#
#   --soft : compose down/up WITHOUT a daemon restart (use only when you know
#            there are no orphans; faster, spares unrelated containers).
#   --build: rebuild the api/worker images first (code is bind-mounted, so a
#            rebuild is normally NOT needed — only for dependency changes).
#
# COLLATERAL: a daemon restart stops EVERY container, including ones unrelated
#   to this project (e.g. a `uniqdb-t` challenge box). They are listed before
#   and after so you can restart them yourself. --soft avoids this.
#
# Needs sudo (kills root-owned orphans / restarts the daemon). You will be
# prompted once; the password is never stored in this script.
# =============================================================================
set -uo pipefail

PROJECT_DIR="${PROJECT_DIR:-/home/yadohyun/HexTech_CTF_TOOL}"
PROJECT="hextech_ctf_tool"
CORE_SERVICES="redis api worker"

MODE="hard"; BUILD=0
for a in "$@"; do
  case "$a" in
    --soft)  MODE="soft" ;;
    --hard)  MODE="hard" ;;
    --build) BUILD=1 ;;
    *) echo "unknown arg: $a (use --soft | --hard | --build)"; exit 2 ;;
  esac
done

c_cyan=$'\033[1;36m'; c_yel=$'\033[1;33m'; c_red=$'\033[1;31m'; c_grn=$'\033[1;32m'; c_off=$'\033[0m'
log()  { printf '\n%s[restart]%s %s\n' "$c_cyan" "$c_off" "$*"; }
warn() { printf '%s[restart] WARN:%s %s\n' "$c_yel" "$c_off" "$*"; }
err()  { printf '%s[restart] ERR:%s %s\n'  "$c_red" "$c_off" "$*"; }
ok()   { printf '%s[restart] OK:%s %s\n'   "$c_grn" "$c_off" "$*"; }

cd "$PROJECT_DIR" 2>/dev/null || { err "project dir not found: $PROJECT_DIR"; exit 1; }
[ -f docker-compose.yml ] || { err "no docker-compose.yml in $PROJECT_DIR"; exit 1; }
[ -d data/jobs ] || warn "no data/jobs/ under $PROJECT_DIR — collector verify will be skipped"
log "project=$PROJECT  dir=$PROJECT_DIR  mode=$MODE  build=$BUILD"

# --- run `docker compose` as the REAL user with the correct ~/.claude OAuth
# mount. Running THIS script via sudo makes $HOME=/root, so the compose mount
# `${HOST_CLAUDE_HOME:-${HOME}/.claude}` would point at the empty /root/.claude
# and the worker would have NO claude.ai OAuth token ("OAuth missing"). Also,
# root-created containers later clash with a user `compose up`. So: resolve the
# invoking user's home, pin HOST_CLAUDE_HOME, and create containers AS that user.
REAL_USER="${SUDO_USER:-$(stat -c %U "$PROJECT_DIR" 2>/dev/null || id -un)}"
REAL_HOME="$(getent passwd "$REAL_USER" 2>/dev/null | cut -d: -f6)"; REAL_HOME="${REAL_HOME:-$HOME}"
export HOST_CLAUDE_HOME="${HOST_CLAUDE_HOME:-$REAL_HOME/.claude}"
log "compose user=$REAL_USER  HOST_CLAUDE_HOME=$HOST_CLAUDE_HOME (claude.ai OAuth mount)"
[ -f "$HOST_CLAUDE_HOME/.credentials.json" ] \
  || warn "no $HOST_CLAUDE_HOME/.credentials.json — worker will have NO OAuth token (run \`claude login\` as $REAL_USER)"
dc() {
  if [ "$(id -un)" = "$REAL_USER" ]; then
    docker compose -p "$PROJECT" "$@"
  else
    sudo -u "$REAL_USER" env "HOST_CLAUDE_HOME=$HOST_CLAUDE_HOME" docker compose -p "$PROJECT" "$@"
  fi
}

# --- sudo upfront (cache creds; never hardcode the password) ----------------
if ! sudo -n true 2>/dev/null; then
  log "sudo is required (kill root-owned orphans / restart daemon)"
  sudo -v || { err "sudo unavailable"; exit 1; }
fi

# --- snapshot UNRELATED running containers (collateral of a daemon restart) --
mapfile -t OTHER < <(docker ps --format '{{.Names}}' 2>/dev/null | grep -vE "^${PROJECT}-" || true)
if [ "$MODE" = "hard" ] && [ "${#OTHER[@]}" -gt 0 ]; then
  warn "a daemon restart will STOP these UNRELATED containers too:"
  printf '         - %s\n' "${OTHER[@]}"
fi

# --- 1. clean compose state -------------------------------------------------
log "docker compose down --remove-orphans (keeps named volumes e.g. redis-data)"
dc down --remove-orphans 2>&1 | sed 's/^/    /'

# --- 2. report any docker-UNTRACKED orphan shims still around ----------------
log "scanning for docker-untracked orphan containers (the trap)..."
orphan_found=0
for scope in /sys/fs/cgroup/system.slice/docker-*.scope; do
  [ -e "$scope" ] || continue
  cid="$(basename "$scope" .scope)"; cid="${cid#docker-}"
  if ! docker inspect "$cid" >/dev/null 2>&1; then
    pids="$(sudo cat "$scope/cgroup.procs" 2>/dev/null | tr '\n' ' ')"
    [ -z "${pids// }" ] && continue
    cmd="$(sudo cat /proc/${pids%% *}/cmdline 2>/dev/null | tr '\0' ' ' | cut -c1-60)"
    warn "  orphan ${cid:0:12}  pids=[${pids}]  ($cmd)"
    orphan_found=1
  fi
done
[ "$orphan_found" -eq 0 ] && ok "no docker-untracked orphans detected"

# --- 3. clear orphans ------------------------------------------------------
if [ "$MODE" = "hard" ]; then
  log "restarting docker daemon (re-syncs dockerd<->containerd, drops ALL shims)"
  if command -v snap >/dev/null 2>&1 && snap services docker >/dev/null 2>&1; then
    sudo snap restart docker 2>&1 | sed 's/^/    /'
  else
    sudo systemctl restart docker 2>&1 | sed 's/^/    /'
  fi
  log "waiting for docker daemon to come back..."
  for i in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 2; done
  docker info >/dev/null 2>&1 && ok "daemon up" || { err "daemon did not return"; exit 1; }
elif [ "$orphan_found" -eq 1 ]; then
  warn "--soft mode but orphans are present. A PID kill will be RESPAWNED by"
  warn "containerd's restart policy — surgical kill is unreliable here."
  warn "Re-run WITHOUT --soft to do a daemon restart (the reliable fix)."
fi

# --- 4. (optional) rebuild --------------------------------------------------
if [ "$BUILD" -eq 1 ]; then
  log "building images (api worker)"
  dc build api worker 2>&1 | sed 's/^/    /'
fi

# --- 5. fresh up ------------------------------------------------------------
log "docker compose up -d --force-recreate $CORE_SERVICES"
dc up -d --force-recreate $CORE_SERVICES 2>&1 | sed 's/^/    /'

# --- 6. VERIFY via live routes (not docker-exec, which fresh-imports) -------
log "verifying api on http://localhost:8000 ..."
code=""
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://localhost:8000/ 2>/dev/null)
  [ "$code" = "200" ] && break
  sleep 2
done
[ "$code" = "200" ] && ok "api -> HTTP 200" || err "api not serving (got '${code:-none}')"

# collector sanity — the orphan-api bug was: returns "ok" but logs nothing.
# Hit a REAL job's collector via the live route and confirm callbacks.jsonl grows.
probe_job="$(ls -t data/jobs 2>/dev/null | head -1)"
if [ -n "${probe_job:-}" ]; then
  cb="data/jobs/$probe_job/callbacks.jsonl"
  before=$( [ -f "$cb" ] && wc -l < "$cb" || echo 0 )
  curl -s -o /dev/null --max-time 6 "http://localhost:8000/api/collector/$probe_job/_restartprobe?c=RESTART_OK" 2>/dev/null
  sleep 1
  after=$( [ -f "$cb" ] && wc -l < "$cb" || echo 0 )
  if [ "$after" -gt "$before" ]; then
    ok "collector logs to $cb (orphan-api bug cleared)"
  else
    err "collector still NOT logging for $probe_job — fresh api may not see /data."
    err "  check the api service's volume mount (./data:/data) in docker-compose.yml"
  fi
fi

# worker sanity — registered with redis?
wcount=$(dc exec -T redis redis-cli scard rq:workers 2>/dev/null | tr -d '\r' )
[ -n "${wcount:-}" ] && [ "${wcount:-0}" -gt 0 ] 2>/dev/null \
  && ok "rq workers registered: $wcount" \
  || warn "rq workers registered: ${wcount:-0} (worker may still be starting)"

# --- 6b. auto-start the cloudflared OOB tunnel (auto-sets Callback URL) ------
# Reuses tunnel.sh, run AS the invoking user so the pidfile/detach are
# user-owned (a root-launched tunnel would write a root-owned pidfile). Honors
# AUTO_TUNNEL from .env (default 1); skips if the api isn't serving or
# cloudflared isn't installed. Stop later with `./tunnel.sh stop`.
AT="$(grep -E '^AUTO_TUNNEL=' "$PROJECT_DIR/.env" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '[:space:]')"
if [ "${AT:-1}" != "0" ] && [ "$code" = "200" ]; then
  log "auto-starting cloudflared tunnel (Callback URL auto-set; AUTO_TUNNEL=0 to skip)"
  if [ "$(id -un)" = "$REAL_USER" ]; then
    AUTO_TUNNEL=1 PROJECT_DIR="$PROJECT_DIR" API_BASE="http://localhost:8000" \
      bash "$PROJECT_DIR/scripts/tunnel-autostart.sh" 2>&1 | sed 's/^/    /'
  else
    sudo -u "$REAL_USER" env AUTO_TUNNEL=1 PROJECT_DIR="$PROJECT_DIR" API_BASE="http://localhost:8000" \
      bash "$PROJECT_DIR/scripts/tunnel-autostart.sh" 2>&1 | sed 's/^/    /'
  fi
elif [ "${AT:-1}" != "0" ]; then
  warn "skipping tunnel auto-start (api not serving on :8000)"
fi

# --- 7. summary -------------------------------------------------------------
log "docker compose ps:"
dc ps 2>&1 | sed 's/^/    /'
if [ "$MODE" = "hard" ] && [ "${#OTHER[@]}" -gt 0 ]; then
  warn "unrelated containers stopped by the daemon restart (restart them if needed):"
  printf '         - %s\n' "${OTHER[@]}"
fi
log "done."
