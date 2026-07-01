#!/usr/bin/env bash
# =============================================================================
# deploy.sh — apply freshly-patched code to the RUNNING stack, no rebuild.
#
# WHY THIS IS ENOUGH (no image build, no daemon bounce, no sudo):
#   The source trees are bind-mounted read-only into the containers
#   (docker-compose.yml: ./modules ./api ./web-ui -> api, ./modules ./worker
#   -> worker). So the FILES are always current the instant you edit them; a
#   container RESTART just makes the long-lived Python process re-import them.
#   The UI is served by api StaticFiles straight from ./web-ui with
#   `Cache-Control: no-cache` (api/main.py) — so the UI is ALWAYS fresh on the
#   next browser refresh; it needs NO restart, only Ctrl-Shift-R if your
#   browser is being stubborn.
#
#   => "apply latest" = restart the backend containers whose code changed.
#      api    : api/  modules/  web-ui/   (routes + shared modules + UI host)
#      worker : modules/  worker/         (the agent/runner process)
#      modules/ touches BOTH.
#
# USAGE
#   ./deploy.sh              # restart api + worker (worker SKIPPED if a job is live)
#   ./deploy.sh --api        # api only            (safe anytime — jobs run in worker)
#   ./deploy.sh --worker     # worker only
#   ./deploy.sh --force      # restart worker even if a job is running (KILLS it)
#   ./deploy.sh --changed    # restart only the services whose mounted paths changed
#                            #   since the last deploy (uses git HEAD vs .last_deploy)
#   ./deploy.sh -h|--help
#
# SAFETY
#   * A worker restart KILLS the in-flight job. By default, if any job is
#     running/queued, deploy.sh restarts ONLY api and DEFERS the worker with a
#     warning (re-run with --worker when idle, or --force to override).
#   * If Docker Desktop's WSL integration is shadowing the snap docker CLI
#     (docker can't see the hextech containers although :8000 serves), the
#     light restart can't reach the daemon — deploy.sh detects this and prints
#     the one-time fix instead of silently failing.
#
# EXIT: 0 ok · 2 bad args · 3 cli-shadowed (needs the one-time fix) · 4 stack down
# =============================================================================
set -uo pipefail

PROJECT_DIR="${PROJECT_DIR:-/home/yadohyun/HexTech_CTF_TOOL}"
PROJECT="hextech_ctf_tool"
JOBS_DIR="$PROJECT_DIR/data/jobs"
LAST_DEPLOY_FILE="$PROJECT_DIR/.last_deploy"
API_URL="http://localhost:8000"

if [ -t 1 ]; then
  C=$'\033[1;36m'; Y=$'\033[1;33m'; R=$'\033[1;31m'; G=$'\033[1;32m'; N=$'\033[0m'
else C=''; Y=''; R=''; G=''; N=''; fi
log()  { printf '%s[deploy]%s %s\n' "$C" "$N" "$*"; }
warn() { printf '%s[deploy] WARN:%s %s\n' "$Y" "$N" "$*"; }
err()  { printf '%s[deploy] ERR:%s %s\n'  "$R" "$N" "$*"; }
ok()   { printf '%s[deploy] OK:%s %s\n'   "$G" "$N" "$*"; }

MODE="both"; FORCE=0; CHANGED=0
for a in "$@"; do
  case "$a" in
    --api) MODE="api" ;;
    --worker) MODE="worker" ;;
    --both) MODE="both" ;;
    --force) FORCE=1 ;;
    --changed) CHANGED=1 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) err "unknown arg: $a (use --api|--worker|--both|--force|--changed)"; exit 2 ;;
  esac
done

cd "$PROJECT_DIR" 2>/dev/null || { err "project dir not found: $PROJECT_DIR"; exit 1; }

# --- pick the docker CLI that actually drives THIS project's daemon ----------
# In WSL, /usr/bin/docker can flip to the Docker-Desktop CLI (which sees a
# different, empty daemon) while the stack runs under snap dockerd. We don't
# care WHICH binary, only that `compose ps` sees our containers.
DC() { docker compose -p "$PROJECT" "$@"; }

cli_sees_stack() {
  docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${PROJECT}-"
}
api_up() { [ "$(curl -s -o /dev/null -w '%{http_code}' "$API_URL/" 2>/dev/null)" = "200" ]; }

# --- diagnose the environment BEFORE touching anything -----------------------
if ! cli_sees_stack; then
  if api_up; then
    err "docker CLI is SHADOWED — it cannot see the ${PROJECT} containers, yet"
    err ":8000 is serving (the stack runs under a daemon your CLI can't reach,"
    err "typically snap dockerd hidden by Docker Desktop's WSL integration)."
    echo
    warn "One-time fix (pick ONE), then re-run ./deploy.sh:"
    warn "  A) Docker Desktop -> Settings -> Resources -> WSL Integration ->"
    warn "     toggle this distro OFF  (restores docker -> snap; no sudo after)"
    warn "  B) sudo snap restart docker   (bounces the snap daemon; containers"
    warn "     return via 'restart: unless-stopped' with the new bind-mounted code)"
    exit 3
  fi
  err "stack appears DOWN (no ${PROJECT} containers, :8000 not 200)."
  err "bring it up first:  ./start.sh        (or ./restart.sh if orphaned)"
  exit 4
fi

# --- which services need a restart -------------------------------------------
declare -A WANT=()
if [ "$CHANGED" = 1 ]; then
  base="$(cat "$LAST_DEPLOY_FILE" 2>/dev/null || true)"
  head="$(git rev-parse HEAD 2>/dev/null || true)"
  if [ -z "$base" ] || [ -z "$head" ]; then
    warn "--changed: no git baseline; falling back to restart both"
    WANT[api]=1; WANT[worker]=1
  elif [ "$base" = "$head" ]; then
    ok "nothing new since last deploy ($head) — UI already fresh, no restart needed."
    exit 0
  else
    changed_paths="$(git diff --name-only "$base" "$head" 2>/dev/null)"
    echo "$changed_paths" | grep -qE '^(api/|modules/|web-ui/)' && WANT[api]=1
    echo "$changed_paths" | grep -qE '^(worker/|modules/)'      && WANT[worker]=1
    [ ${#WANT[@]} -eq 0 ] && { ok "changed paths touch no mounted backend code — nothing to restart."; echo "$head" > "$LAST_DEPLOY_FILE" 2>/dev/null || true; exit 0; }
  fi
else
  case "$MODE" in
    api)    WANT[api]=1 ;;
    worker) WANT[worker]=1 ;;
    both)   WANT[api]=1; WANT[worker]=1 ;;
  esac
fi

# --- active-job guard: a worker restart kills the in-flight job ---------------
active_jobs=0
if [ -d "$JOBS_DIR" ]; then
  active_jobs="$(grep -lE '"status"[[:space:]]*:[[:space:]]*"(running|queued)"' "$JOBS_DIR"/*/meta.json 2>/dev/null | wc -l | tr -d ' ')"
fi
if [ -n "${WANT[worker]:-}" ] && [ "$active_jobs" -gt 0 ] && [ "$FORCE" = 0 ]; then
  warn "$active_jobs job(s) running/queued — DEFERRING the worker restart (it would"
  warn "kill the in-flight job). Re-run './deploy.sh --worker' when idle, or"
  warn "'./deploy.sh --force' to restart anyway."
  unset 'WANT[worker]'
fi

[ ${#WANT[@]} -eq 0 ] && { ok "nothing to restart."; exit 0; }

svcs="$(printf '%s ' "${!WANT[@]}")"
log "restarting: $svcs (bind-mounted code — no rebuild)"
# shellcheck disable=SC2086
DC restart $svcs 2>&1 | sed 's/^/  /'

# --- verify ------------------------------------------------------------------
for i in $(seq 1 25); do api_up && break; sleep 1; done
if api_up; then ok "api $API_URL -> 200"; else warn "api not 200 yet — check 'docker compose -p $PROJECT logs api'"; fi

# stamp the deploy so --changed can no-op next time
git rev-parse HEAD > "$LAST_DEPLOY_FILE" 2>/dev/null || true

# stamp web-ui/version.json so the UI version badge shows the deployed commit
[ -x "$PROJECT_DIR/stamp-version.sh" ] && "$PROJECT_DIR/stamp-version.sh" || true

ok "deployed. UI is served no-cache from the ./web-ui mount — just refresh the"
ok "browser (Ctrl-Shift-R) to see UI changes; backend now runs the latest code."
