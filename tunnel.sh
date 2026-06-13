#!/usr/bin/env bash
# =============================================================================
# tunnel.sh — cloudflared quick-tunnel that AUTO-PUBLISHES the public URL into
#             the tool's Settings (Callback URL -> CALLBACK_URL env), so OOB
#             beacons (XSS <img>/fetch/sendBeacon, SSRF, blind RCE) land on the
#             built-in collector with ZERO manual copy and NO interstitial.
#
# WHY cloudflared, not ngrok:
#   ngrok's free tier answers every request with a 200 + HTML browser-warning
#   "interstitial" unless the caller sends `ngrok-skip-browser-warning`. An XSS
#   beacon (<img>, navigator.sendBeacon, a bare fetch) CANNOT set that header,
#   so the bot's exfil hits the warning page instead of the collector and the
#   flag is silently lost. cloudflared quick-tunnels (*.trycloudflare.com) have
#   no interstitial -- every beacon passes through transparently.
#
# WHAT IT DOES:
#   1. Launches `cloudflared tunnel --url http://localhost:<port>` (resident).
#   2. Parses the https://<random>.trycloudflare.com URL it announces.
#   3. PUTs it to /api/settings (callback_url) -- through update_settings()'s
#      lock, so it never races the Settings UI. The next job's apply_to_env()
#      picks it up as CALLBACK_URL with no container restart (settings > env).
#   4. Verifies END-TO-END through the tunnel: the collector answers the literal
#      body "ok" (NOT an HTML interstitial) and the probe is logged.
#   5. Stays resident; re-publishes if cloudflared reconnects with a new URL.
#   6. On Ctrl-C: stops cloudflared and RESTORES the previous Callback URL.
#
# This is the role ngrok used to play (a resident tunnel you run in a terminal),
# minus the manual copy and minus the interstitial failure mode.
#
# Usage:   ./tunnel.sh                 # run from the project dir; Ctrl-C to stop
# Env:     WEB_PORT (8000)  API_BASE  PROJECT_DIR  SETTINGS_PATH
#          TUNNEL_URL_TIMEOUT (30s to first URL)  AUTH_TOKEN
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${PROJECT_DIR:-$SCRIPT_DIR}"
PORT="${WEB_PORT:-8000}"
API_BASE="${API_BASE:-http://localhost:$PORT}"
SETTINGS_PATH="${SETTINGS_PATH:-$PROJECT_DIR/data/settings.json}"
URL_TIMEOUT="${TUNNEL_URL_TIMEOUT:-30}"
# PID file so an auto-starter (start.sh / restart.sh) can find + stop a running
# tunnel and a second `./tunnel.sh` refuses to stack a duplicate.
TUNNEL_PIDFILE="${TUNNEL_PIDFILE:-/tmp/hextech-ctf-tunnel.pid}"

c_cyan=$'\033[1;36m'; c_yel=$'\033[1;33m'; c_red=$'\033[1;31m'; c_grn=$'\033[1;32m'; c_off=$'\033[0m'
log()  { printf '\n%s[tunnel]%s %s\n' "$c_cyan" "$c_off" "$*"; }
warn() { printf '%s[tunnel] WARN:%s %s\n' "$c_yel" "$c_off" "$*"; }
err()  { printf '%s[tunnel] ERR:%s %s\n'  "$c_red" "$c_off" "$*"; }
ok()   { printf '%s[tunnel] OK:%s %s\n'   "$c_grn" "$c_off" "$*"; }

# --- `./tunnel.sh stop` : terminate a running (e.g. auto-started) tunnel ------
# Its TERM trap restores the previous Callback URL and kills cloudflared.
if [ "${1:-}" = "stop" ]; then
  pid=""
  [ -r "$TUNNEL_PIDFILE" ] && pid="$(cat "$TUNNEL_PIDFILE" 2>/dev/null || true)"
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null
    for _ in $(seq 1 15); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null
    ok "stopped tunnel (pid $pid)"
  else
    warn "no live tunnel found (pidfile $TUNNEL_PIDFILE)"
    rm -f "$TUNNEL_PIDFILE" 2>/dev/null
  fi
  exit 0
fi

# --- auth token (only needed if the operator enabled auth in Settings) -------
TOK="${AUTH_TOKEN:-}"
if [ -z "$TOK" ] && [ -r "$SETTINGS_PATH" ]; then
  TOK="$(jq -r '.auth_token // empty' "$SETTINGS_PATH" 2>/dev/null || true)"
fi
_auth=(); [ -n "$TOK" ] && _auth=(-H "Authorization: Bearer $TOK")

api_get_cb() {
  curl -s --max-time 8 "${_auth[@]}" "$API_BASE/api/settings" 2>/dev/null \
    | jq -r '.callback_url // empty' 2>/dev/null
}
api_set_cb() {  # $1 = url ("" clears the override -> reverts to env/default)
  local body; body="$(jq -n --arg u "$1" '{callback_url:$u}')"
  curl -s --max-time 8 -X PUT "${_auth[@]}" \
    -H 'Content-Type: application/json' -d "$body" \
    "$API_BASE/api/settings" >/dev/null 2>&1
}

# --- preflight ---------------------------------------------------------------
command -v cloudflared >/dev/null 2>&1 || {
  err "cloudflared not found. Install it (Debian/WSL2):"
  err "  curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \\"
  err "    -o /usr/local/bin/cloudflared && sudo chmod +x /usr/local/bin/cloudflared"
  err "  docs: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
  exit 1
}
command -v jq   >/dev/null 2>&1 || { err "jq not found (needed to read/patch settings)"; exit 1; }
command -v curl >/dev/null 2>&1 || { err "curl not found"; exit 1; }

log "project=$PROJECT_DIR  api=$API_BASE  settings=$SETTINGS_PATH"
hc="$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "$API_BASE/api/health" 2>/dev/null)"
if [ "$hc" = "200" ]; then
  ok "api is up (/api/health 200)"
else
  warn "api not answering on $API_BASE (got '${hc:-none}') -- start the stack"
  warn "  (./restart.sh) or the tunnel will point at nothing."
fi
[ -n "$TOK" ] && log "auth token detected -- using Bearer header"

# Remember the current Callback URL so Ctrl-C can put it back.
PRIOR_CB="$(api_get_cb)"
[ -z "$PRIOR_CB" ] && [ -r "$SETTINGS_PATH" ] \
  && PRIOR_CB="$(jq -r '.callback_url // empty' "$SETTINGS_PATH" 2>/dev/null || true)"
[ -n "$PRIOR_CB" ] && log "current Callback URL (restored on exit): $PRIOR_CB"

# --- refuse to stack a second tunnel (would fight over the Callback URL) ------
# A stale pidfile (process already gone) is ignored and overwritten below.
if [ -r "$TUNNEL_PIDFILE" ]; then
  oldpid="$(cat "$TUNNEL_PIDFILE" 2>/dev/null || true)"
  if [ -n "$oldpid" ] && [ "$oldpid" != "$$" ] && kill -0 "$oldpid" 2>/dev/null; then
    err "a tunnel is already running (pid $oldpid). Stop it first:  $0 stop"
    exit 1
  fi
fi
echo "$$" > "$TUNNEL_PIDFILE" 2>/dev/null || true

# --- launch cloudflared ------------------------------------------------------
CF_LOG="$(mktemp -t hextech-tunnel.XXXXXX.log)"
CF_PID=""
cleanup() {
  trap - INT TERM EXIT
  [ -n "$CF_PID" ] && kill "$CF_PID" 2>/dev/null
  # Restore the prior Callback URL. NOTE: that URL is itself dead now (it was a
  # previous tunnel), but restoring is least-surprise vs. silently blanking an
  # operator-set VPS URL. Empty prior -> clear the override entirely.
  log "restoring Callback URL to: ${PRIOR_CB:-<unset>}"
  api_set_cb "$PRIOR_CB"
  rm -f "$CF_LOG" "$TUNNEL_PIDFILE" 2>/dev/null
  ok "tunnel down."
  # MUST exit here: a bash trap that returns (instead of exiting) RESUMES the
  # script at the point the signal interrupted -- which would re-print the
  # "tunnel is LIVE" / "cloudflared exited" lines after teardown. Traps were
  # already cleared (`trap -` above), so this is the single, clean exit point.
  exit 0
}
trap cleanup INT TERM EXIT

log "starting cloudflared quick-tunnel -> http://localhost:$PORT"
cloudflared tunnel --url "http://localhost:$PORT" --no-autoupdate >"$CF_LOG" 2>&1 &
CF_PID=$!

extract_url() {
  grep -oE 'https://[a-z0-9][a-z0-9.-]*\.trycloudflare\.com' "$CF_LOG" 2>/dev/null | tail -1
}

# --- wait for the public URL (bounded; Cloudflare may rate-limit) ------------
URL=""
deadline=$(( URL_TIMEOUT * 2 ))   # loop ticks of 0.5s
for (( i=0; i<deadline; i++ )); do
  URL="$(extract_url)"; [ -n "$URL" ] && break
  if ! kill -0 "$CF_PID" 2>/dev/null; then
    err "cloudflared exited before announcing a URL. Last lines:"
    tail -n 15 "$CF_LOG" | sed 's/^/    /'; exit 1
  fi
  sleep 0.5
done
if [ -z "$URL" ]; then
  err "no *.trycloudflare.com URL within ${URL_TIMEOUT}s (Cloudflare rate-limit?). Last lines:"
  tail -n 15 "$CF_LOG" | sed 's/^/    /'; exit 1
fi

publish() {  # $1 = public base url
  local url="$1"
  api_set_cb "$url"
  local got; got="$(api_get_cb)"
  if [ "$got" = "$url" ]; then
    ok "Callback URL published -> $url"
  else
    err "PUT /api/settings did not stick (got '${got:-none}'). api up / auth correct?"
    return 1
  fi
  printf '%s[tunnel]%s   public base : %s\n'                       "$c_cyan" "$c_off" "$url"
  printf '%s[tunnel]%s   collector   : %s/api/collector/<JOB_ID>\n' "$c_cyan" "$c_off" "$url"
  printf '%s[tunnel]%s   exploits get: COLLECTOR_URL=%s/api/collector/<JOB_ID>\n' "$c_cyan" "$c_off" "$url"
}

# --- END-TO-END verify: the discriminator is the BODY, not the status code ---
# ngrok's interstitial is ALSO HTTP 200 -- but its body is HTML. A working
# collector answers the literal "ok". Use a REAL job_id so we also confirm the
# probe is logged (the collector returns "ok" even for an unknown job, so the
# body check alone proves "no interstitial" but not "logged end-to-end").
verify_e2e() {
  local url="$1"
  local pj cbf="" before=0
  pj="$(ls -t "$PROJECT_DIR/data/jobs" 2>/dev/null | head -1)"
  if [ -n "$pj" ]; then
    cbf="$PROJECT_DIR/data/jobs/$pj/callbacks.jsonl"
    before=$( [ -r "$cbf" ] && wc -l < "$cbf" 2>/dev/null || echo 0 )
  else
    pj="_tunnelprobe"
    warn "no jobs under $PROJECT_DIR/data/jobs -- probing without a real job (no logging check)"
  fi
  # A fresh quick-tunnel needs several seconds for Cloudflare's edge to become
  # reachable. During warm-up the edge can answer empty OR a transient Cloudflare
  # error page (HTML, e.g. error 1033 "Argo Tunnel error") -- that is NOT the
  # ngrok interstitial (a cloudflared tunnel structurally can't show one) and NOT
  # a failure, just "not ready yet". So poll strictly for the collector's literal
  # "ok" and treat everything else as keep-waiting; never bail on early HTML.
  log "verifying the collector through the tunnel (edge warm-up may take ~10-40s)..."
  local body="" got_ok=0
  for (( t=0; t<20; t++ )); do
    body="$(curl -s --max-time 8 "$url/api/collector/$pj/_tunnelprobe?c=TUNNEL_OK" 2>/dev/null)"
    [ "$body" = "ok" ] && { got_ok=1; break; }
    sleep 2
  done
  if [ "$got_ok" = 1 ]; then
    ok "collector reachable THROUGH the tunnel, body=\"ok\" (no interstitial)"
  else
    warn "collector not confirmed through the tunnel after ~40s. The edge may still"
    warn "be warming up (transient Cloudflare error pages early on are normal) or the"
    warn "api isn't reachable. It should settle shortly -- re-probe:"
    warn "  curl $url/api/collector/$pj/_p"
  fi
  if [ -n "$cbf" ] && [ "$got_ok" = 1 ]; then
    sleep 1
    local after; after=$( [ -r "$cbf" ] && wc -l < "$cbf" 2>/dev/null || echo 0 )
    if [ "$after" -gt "$before" ]; then
      ok "probe logged to $cbf (end-to-end OOB path proven)"
    else
      warn "collector answered but $cbf did not grow -- check api /data mount / job perms"
    fi
  fi
}

publish "$URL"
verify_e2e "$URL"

log "tunnel is LIVE and Callback URL is set. Leave this running. Ctrl-C to stop + restore."

# --- resident: watch for a reconnect URL change ------------------------------
cur="$URL"
while kill -0 "$CF_PID" 2>/dev/null; do
  sleep 5
  new="$(extract_url)"
  if [ -n "$new" ] && [ "$new" != "$cur" ]; then
    warn "cloudflared reconnected with a NEW URL -> re-publishing"
    cur="$new"; publish "$new"; verify_e2e "$new"
  fi
done
# Reached only when cloudflared's process ends on its own (or `./tunnel.sh stop`
# killed cloudflared first). A SIGINT/SIGTERM to THIS script takes the trap path
# instead and `exit`s before here. Either way the EXIT trap (cleanup) restores
# the prior Callback URL and prints "tunnel down" -- so keep this neutral, not a
# scary "ERR ... restoring via trap" that misreads an intentional stop.
warn "cloudflared process ended -- shutting down tunnel"
