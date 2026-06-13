#!/usr/bin/env bash
# =============================================================================
# tunnel-autostart.sh — bring up the cloudflared OOB tunnel (tunnel.sh) DETACHED
#   and wait until it has auto-published its public URL into Settings
#   (Callback URL). Called by start.sh / restart.sh so the callback URL in
#   /data/settings.json is set automatically whenever the stack comes up.
#
#   Set AUTO_TUNNEL=0 (env or .env) to skip — e.g. if you run your own tunnel.
#   No-ops gracefully (exit 0) when cloudflared isn't installed, so it never
#   blocks a bring-up.
#
# Env in:  PROJECT_DIR  WEB_PORT (8000)  API_BASE  TUNNEL_LOG  TUNNEL_PIDFILE
# =============================================================================
set -uo pipefail

if [ "${AUTO_TUNNEL:-1}" = "0" ]; then
  echo "[tunnel] AUTO_TUNNEL=0 -> skipping tunnel auto-start"
  exit 0
fi

PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
PORT="${WEB_PORT:-8000}"
API_BASE="${API_BASE:-http://localhost:$PORT}"
TUNNEL_LOG="${TUNNEL_LOG:-/tmp/hextech-ctf-tunnel.log}"
TUNNEL_PIDFILE="${TUNNEL_PIDFILE:-/tmp/hextech-ctf-tunnel.pid}"
TS="$PROJECT_DIR/tunnel.sh"

if ! command -v cloudflared >/dev/null 2>&1; then
  echo "[tunnel] cloudflared not installed -> skipping auto-start."
  echo "[tunnel]   install it, then run ./tunnel.sh (or re-run this) to enable OOB callbacks."
  exit 0
fi
[ -r "$TS" ] || { echo "[tunnel] $TS not found -> skipping auto-start"; exit 0; }

# Stop any tunnel we previously started so we don't stack cloudflared instances.
TUNNEL_PIDFILE="$TUNNEL_PIDFILE" bash "$TS" stop >/dev/null 2>&1 || true

echo "[tunnel] starting cloudflared tunnel (detached); log: $TUNNEL_LOG"
# setsid: own session so the tunnel outlives this helper (and the caller).
TUNNEL_PIDFILE="$TUNNEL_PIDFILE" PROJECT_DIR="$PROJECT_DIR" WEB_PORT="$PORT" API_BASE="$API_BASE" \
  setsid bash "$TS" >"$TUNNEL_LOG" 2>&1 </dev/null &
disown 2>/dev/null || true

# Wait for tunnel.sh to publish a *.trycloudflare.com URL into settings
# (cloudflared edge warm-up is a few seconds).
url=""
for _ in $(seq 1 40); do
  url="$(curl -s --max-time 5 "$API_BASE/api/settings" 2>/dev/null | jq -r '.callback_url // empty' 2>/dev/null || true)"
  case "$url" in
    *trycloudflare.com*) break ;;
    *) url="" ;;
  esac
  sleep 1
done

if [ -n "$url" ]; then
  # One reachability check through the EXISTING tunnel: a single GET, NOT a new
  # tunnel, so this does not touch Cloudflare's quick-tunnel rate limit. Poll
  # briefly for edge warm-up so the operator gets an honest reachable/not signal.
  reach=0
  for _ in $(seq 1 15); do
    [ "$(curl -s --max-time 6 "$url/api/collector/_autostartprobe/_p?c=PING" 2>/dev/null || true)" = "ok" ] \
      && { reach=1; break; }
    sleep 2
  done
  if [ "$reach" = 1 ]; then
    echo "[tunnel] Callback URL auto-set -> $url  (reachable -- beacons will land)"
  else
    echo "[tunnel] Callback URL auto-set -> $url  (NOT reachable yet)"
    echo "[tunnel]   the quick-tunnel may still be warming up or be rate-limited;"
    echo "[tunnel]   if beacons don't land, re-roll a fresh URL:  $TS stop && $TS"
  fi
  echo "[tunnel]   stop:  $TS stop      logs:  tail -f $TUNNEL_LOG"
else
  echo "[tunnel] tunnel launched but no *.trycloudflare.com URL within 40s (rate-limit?)."
  echo "[tunnel]   check:  tail -n 30 $TUNNEL_LOG    re-roll:  $TS stop && $TS"
fi
exit 0
