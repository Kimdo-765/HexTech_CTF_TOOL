#!/usr/bin/env bash
# worker-slots.sh — change how many jobs run in parallel, and apply it.
#
# Parallelism is the number of `worker-N` services in docker-compose.yml: one
# container per slot, each running exactly one job (worker/runner.py forces
# concurrency to 1 whenever WORKER_SLOT is set, and says so in its log). The
# Settings field is read-only for that reason — this script is the supported way
# to change it.
#
# WHY A SCRIPT AND NOT `docker compose up -d`:
#
#   * The 70% safety budget lives in the API (api/routes/settings.py) and gates
#     `docker update`. Compose sets `mem_limit` at container CREATE and never
#     touches that code, so adding slots is the one path that can put more cap
#     into the VM than the gate would ever allow. On this host that is not
#     theoretical: 3 slots x 4g is 12 GiB against a 10.9 GiB ceiling, and an
#     over-committed VM is what froze WSL on 2026-07-29 and again on 08-01.
#     The check compose does not do is done here, and refusing is the default.
#   * `start.sh` exports HOST_CODEX_HOME / HOST_CLAUDE_HOME / HOST_GROK_HOME.
#     Bringing the stack up without them mounts an empty codex home and every
#     gpt job dies with "no file-backed ChatGPT login is mounted" — measured,
#     job d639996cd08e.
#   * `start.sh` regenerates docker-compose.override.yml by scanning the compose
#     file for worker services, so a new slot gets /dev/kvm automatically. A
#     hand-rolled `up` leaves the new slot without it and kernel-pwn jobs there
#     silently lose KVM.
#   * Removing a slot leaves an ORPHAN: `up -d` does not delete a service that
#     vanished from the file, so the container keeps running, keeps its cgroup
#     cap, and keeps its RQ registration. Nothing sweeps it either — each slot
#     only sweeps its own `htct-s<N>-w*` prefix on boot, so a slot that no
#     longer exists is swept by nobody. This script removes it explicitly.
#
# Usage:
#   scripts/worker-slots.sh                 show the current state and the budget
#   scripts/worker-slots.sh set N           change to N slots and apply
#   scripts/worker-slots.sh set N --force   proceed despite running jobs / over budget
#   scripts/worker-slots.sh set N --dry-run edit nothing, print what would happen

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

PROJECT=hextech_ctf_tool
COMPOSE=docker-compose.yml
BUDGET_FRACTION=70          # percent of VM RAM that slot caps may claim, in total
MAX_SLOTS=32

if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; N=$'\033[0m'
else B=''; G=''; Y=''; R=''; N=''; fi
log()  { printf '%s\n' "$*"; }
ok()   { printf '%s✔%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '%s✘%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

# --------------------------------------------------------------------------
# facts
# --------------------------------------------------------------------------

current_slots() {
  # Ask compose, not grep: the file uses YAML anchors and only compose resolves
  # them the way the daemon will.
  docker compose -p "$PROJECT" config --services 2>/dev/null \
    | grep -xE 'worker-[0-9]+' | sed 's/worker-//' | sort -n
}

slot_count() { current_slots | grep -c . || true; }

# What a NEW container will be created with. Not what the live ones hold: a
# Settings change applies to live cgroups via the Docker API while .env keeps
# the boot default, so the two legitimately differ and only this one predicts
# the new slot.
new_slot_cap_str() {
  local v
  v="$(grep -E '^WORKER_SLOT_MEM=' .env 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '[:space:]')"
  printf '%s' "${v:-4g}"
}

to_bytes() {
  python3 - "$1" <<'PY'
import sys
v = sys.argv[1].strip().lower()
mult = 1
if v and v[-1] in "kmg":
    mult = {"k": 1024, "m": 1024**2, "g": 1024**3}[v[-1]]
    v = v[:-1]
try:
    print(int(float(v) * mult))
except ValueError:
    print(0)
PY
}

host_mem_bytes() { awk '/^MemTotal:/ {print $2 * 1024; exit}' /proc/meminfo; }

fmt_gib() { python3 -c "print('%.2f GiB' % ($1/1024**3))"; }

live_jobs() {
  python3 - <<'PY'
import json, pathlib
d = pathlib.Path("data/jobs")
out = []
if d.exists():
    for j in sorted(d.iterdir()):
        f = j / "meta.json"
        if not f.is_file():
            continue
        try:
            m = json.loads(f.read_text())
        except Exception:
            continue
        if m.get("status") in ("running", "queued", "starting"):
            out.append("%s(%s,%s)" % (j.name, m.get("module"), m.get("status")))
print(" ".join(out))
PY
}

# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

show_state() {
  local n cap capb host budget total
  n="$(slot_count)"
  cap="$(new_slot_cap_str)"
  capb="$(to_bytes "$cap")"
  host="$(host_mem_bytes)"
  budget=$(( host * BUDGET_FRACTION / 100 ))
  total=$(( n * capb ))

  log "${B}worker slots${N}"
  log "  defined in $COMPOSE : $n  ($(current_slots | sed 's/^/worker-/' | tr '\n' ' '))"
  log "  cap for a NEW slot  : $cap  (WORKER_SLOT_MEM in .env)"
  log "  VM RAM              : $(fmt_gib "$host")"
  log "  ${BUDGET_FRACTION}% safety budget    : $(fmt_gib "$budget")"
  log "  in use by slots     : $(fmt_gib "$total")"
  log ""
  log "  running containers  :"
  local c
  for c in $(docker ps -a --format '{{.Names}}' 2>/dev/null | grep "^${PROJECT}-worker-" || true); do
    local m s slot
    m="$(docker inspect -f '{{.HostConfig.Memory}}' "$c" 2>/dev/null || echo 0)"
    s="$(docker inspect -f '{{.HostConfig.MemorySwap}}' "$c" 2>/dev/null || echo 0)"
    slot="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$c" 2>/dev/null \
            | sed -n 's/^WORKER_SLOT=//p' | head -1)"
    printf '      %-34s WORKER_SLOT=%-3s cap=%s swap=%s\n' \
      "$c" "${slot:-?}" "$(fmt_gib "${m:-0}")" "$(fmt_gib "${s:-0}")"
  done
  log ""
  log "  what fits at $cap per slot:"
  local k tot
  for k in $(seq 1 12); do
    tot=$(( k * capb ))
    if [ "$tot" -le "$budget" ]; then
      printf '      %2d slots = %-10s ok\n' "$k" "$(fmt_gib "$tot")"
    else
      printf '      %2d slots = %-10s over budget\n' "$k" "$(fmt_gib "$tot")"
      break
    fi
  done
}

# --------------------------------------------------------------------------
# the edit
# --------------------------------------------------------------------------

edit_compose() {
  local want="$1"
  python3 - "$COMPOSE" "$want" <<'PY'
import re, sys
path, want = sys.argv[1], int(sys.argv[2])
s = open(path).read()

# Find every worker-N block. Anchoring on the block's own exact text (and
# asserting it is unique) is the same discipline the UI transform used: a
# regex insert that lands in the wrong place still parses, and then silently
# wires the wrong YAML anchor.
BLOCK = re.compile(
    r'\n  worker-(\d+):\n'
    r'    <<: \*worker-service\n'
    r'    container_name: [^\n]+\n'
    r'    environment:\n'
    r'      <<: \*worker-environment\n'
    r'(?:      #[^\n]*\n)*'
    r'      WORKER_SLOT: "\d+"\n')
blocks = list(BLOCK.finditer(s))
have = sorted(int(m.group(1)) for m in blocks)
if not blocks:
    sys.exit("no worker-N block matched the expected shape; refusing to edit")
if have != list(range(1, len(have) + 1)):
    sys.exit("slot numbering is not contiguous (%s); fix by hand first" % have)

if want == len(have):
    print("nochange")
    sys.exit(0)

if want > len(have):
    last = blocks[-1]
    template = last.group(0)
    add = []
    for k in range(len(have) + 1, want + 1):
        b = template
        b = re.sub(r'\n  worker-\d+:', '\n  worker-%d:' % k, b, count=1)
        b = re.sub(r'container_name: (.*)worker-\d+', r'container_name: \1worker-%d' % k, b, count=1)
        b = re.sub(r'WORKER_SLOT: "\d+"', 'WORKER_SLOT: "%d"' % k, b, count=1)
        # The comment on slot 1 explains the sweep prefix; it belongs to that
        # block only, so a copied slot carries the short form.
        b = re.sub(r'\n      #[^\n]*', '', b)
        add.append(b)
    s = s[:last.end()] + "".join(add) + s[last.end():]
else:
    for m in reversed(blocks[want:]):
        s = s[:m.start()] + s[m.end():]

open(path, "w").write(s)
print("edited")
PY
}

# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

cmd="${1:-show}"
case "$cmd" in
  show|"") show_state; exit 0 ;;
  set) : ;;
  *) die "usage: $0 [show] | set N [--force] [--dry-run]" ;;
esac

want="${2:-}"
[ -n "$want" ] || die "usage: $0 set N [--force] [--dry-run]"
case "$want" in ''|*[!0-9]*) die "N must be a number, got: $want" ;; esac
[ "$want" -ge 1 ] || die "N must be at least 1"
[ "$want" -le "$MAX_SLOTS" ] || die "N must be at most $MAX_SLOTS"

FORCE=0; DRY=0
shift 2 || true
for a in "$@"; do
  case "$a" in
    --force) FORCE=1 ;;
    --dry-run) DRY=1 ;;
    *) die "unknown option: $a" ;;
  esac
done

have="$(slot_count)"
cap="$(new_slot_cap_str)"
capb="$(to_bytes "$cap")"
[ "$capb" -gt 0 ] || die "cannot parse WORKER_SLOT_MEM=$cap from .env"
host="$(host_mem_bytes)"
budget=$(( host * BUDGET_FRACTION / 100 ))
total=$(( want * capb ))

log "${B}worker slots: $have -> $want${N}   (cap per slot $cap)"
log ""

if [ "$have" -eq "$want" ]; then
  ok "already $want slots; nothing to do"
  exit 0
fi

# --- gate 1: the budget compose does not check ------------------------------
if [ "$total" -gt "$budget" ]; then
  warn "$want slots x $cap = $(fmt_gib "$total"), over the ${BUDGET_FRACTION}% budget of this VM's $(fmt_gib "$host") ($(fmt_gib "$budget"))."
  warn ""
  warn "Compose sets mem_limit at container CREATE, so it never passes through the"
  warn "API's budget gate. Over-committing the VM is what froze WSL twice."
  warn ""
  warn "Two ways forward:"
  warn "  a) lower the per-slot cap first — Settings -> Jobs, workers & spend ->"
  warn "     'Worker memory limit', AND WORKER_SLOT_MEM in .env so new slots match."
  warn "     $want slots fit at $(python3 -c "print('%.2fg' % ($budget/$want/1024**3))") or less."
  warn "  b) give the VM more RAM: raise memory= in %USERPROFILE%\\.wslconfig on"
  warn "     Windows, then 'wsl --shutdown'. The physical RAM alone changes nothing."
  [ "$FORCE" -eq 1 ] || die "refusing (use --force to override, knowing the above)"
  warn "--force given; continuing anyway"
else
  ok "budget: $want x $cap = $(fmt_gib "$total") of $(fmt_gib "$budget") available"
fi

# --- gate 2: live jobs ------------------------------------------------------
jobs="$(live_jobs)"
if [ -n "$jobs" ]; then
  warn "jobs are live: $jobs"
  warn "Applying recreates worker containers, which kills whatever they are running."
  [ "$FORCE" -eq 1 ] || die "refusing (wait for them, or --force to kill them)"
  warn "--force given; these jobs will be killed"
else
  ok "no running or queued jobs"
fi

# --- the edit ---------------------------------------------------------------
if [ "$DRY" -eq 1 ]; then
  log ""
  log "${B}--dry-run${N}: would edit $COMPOSE to $want slots, then run ./start.sh"
  [ "$want" -lt "$have" ] && log "           and remove containers for slots $((want+1))..$have"
  exit 0
fi

backup="$(mktemp "${COMPOSE}.bak.XXXXXX")"
cp -p "$COMPOSE" "$backup"
restore() { cp -p "$backup" "$COMPOSE"; warn "restored $COMPOSE from $backup"; }

if ! edit_compose "$want" >/dev/null; then
  restore; rm -f "$backup"; die "compose edit failed (no changes kept)"
fi

# The edit is only trustworthy if compose agrees. A YAML file can parse and
# still say something other than what was meant.
got="$(slot_count)"
if [ "$got" != "$want" ]; then
  restore; rm -f "$backup"
  die "after editing, compose reports $got worker services, expected $want (no changes kept)"
fi
ok "$COMPOSE now defines $want worker slots (backup: $backup)"

# --- remove containers for slots that no longer exist -----------------------
# `up -d` does not delete a service that vanished from the file. The container
# keeps running, keeps its cgroup cap, and keeps an RQ registration that no
# slot's boot sweep covers.
if [ "$want" -lt "$have" ]; then
  for k in $(seq $((want + 1)) "$have"); do
    c="${PROJECT}-worker-${k}"
    if docker ps -aq --filter "name=^/${c}$" | grep -q .; then
      docker rm -f "$c" >/dev/null 2>&1 && ok "removed container $c"
    fi
    # The RQ key self-expires in ~6 minutes, but until it does the UI and
    # restart.sh both count a worker that is gone.
    docker exec "${PROJECT}-redis-1" redis-cli SREM rq:workers "rq:worker:htct-s${k}-w0" >/dev/null 2>&1 || true
    docker exec "${PROJECT}-redis-1" redis-cli DEL "rq:worker:htct-s${k}-w0" >/dev/null 2>&1 || true
  done
fi

# --- apply ------------------------------------------------------------------
log ""
log "${B}applying with ./start.sh${N}"
log "  start.sh is the supported path: it exports HOST_CODEX_HOME and the other"
log "  home mounts, and regenerates the KVM override for the new slot list."
log "  It ends in 'up -d --build', so if a tool image's context changed this"
log "  will build for a while. That is not a hang."
log ""
if ! ./start.sh; then
  warn "start.sh failed. $COMPOSE is left at $want slots; the backup is $backup"
  die "not verified"
fi

# --- verify -----------------------------------------------------------------
log ""
log "${B}verifying${N}"
fail=0
for k in $(seq 1 "$want"); do
  c="${PROJECT}-worker-${k}"
  st="$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo missing)"
  [ "$st" = "running" ] && ok "$c running" || { warn "$c is $st"; fail=1; }

  slot="$(docker exec "$c" sh -c 'echo $WORKER_SLOT' 2>/dev/null | tr -d '\r')"
  [ "$slot" = "$k" ] && ok "  WORKER_SLOT=$slot" || { warn "  WORKER_SLOT=$slot, expected $k"; fail=1; }

  m="$(docker inspect -f '{{.HostConfig.Memory}}' "$c" 2>/dev/null || echo 0)"
  s="$(docker inspect -f '{{.HostConfig.MemorySwap}}' "$c" 2>/dev/null || echo 0)"
  if [ "$m" = "$s" ] && [ "$m" != "0" ]; then ok "  cap $(fmt_gib "$m"), memswap equal"
  else warn "  cap=$m memswap=$s — they must match or swap thrash can wedge the VM"; fail=1; fi

  if docker exec "$c" sh -c 'test -s /root/.codex/auth.json' 2>/dev/null; then
    ok "  codex auth mounted"
  else
    warn "  /root/.codex/auth.json is missing or empty — gpt jobs will fail here"; fail=1
  fi
done

sleep 3
reg="$(docker exec "${PROJECT}-redis-1" redis-cli --raw SMEMBERS rq:workers 2>/dev/null | sort | tr '\n' ' ')"
log "  RQ registrations: ${reg:-<none>}"
for k in $(seq 1 "$want"); do
  case "$reg" in *"htct-s${k}-w0"*) ok "  slot $k registered with RQ" ;;
                 *) warn "  slot $k NOT registered with RQ yet (it may still be booting)" ;;
  esac
done

n_containers="$(docker ps -a --format '{{.Names}}' | grep -c "^${PROJECT}-worker-" || true)"
if [ "$n_containers" = "$want" ]; then ok "exactly $want worker containers, no orphans"
else warn "$n_containers worker containers exist but $want slots are defined — an orphan is left"; fail=1; fi

log ""
if [ "$fail" -eq 0 ]; then
  ok "${B}$want slots live${N}  ($want parallel jobs)"
  log "  The Settings field will now read $want. It stays read-only — this script is how it changes."
  rm -f "$backup"
else
  warn "applied, but the checks above found problems. Backup kept: $backup"
  exit 1
fi
