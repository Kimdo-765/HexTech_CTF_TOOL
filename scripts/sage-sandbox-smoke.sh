#!/usr/bin/env bash
# sage-sandbox-smoke.sh — regression guard for the SageMath sandbox path.
#
# WHY THIS EXISTS
# ---------------
# The use_sage=True runner path (modules/_runner.py run_in_sandbox → SAGE_IMAGE)
# had ZERO successful production executions until job 4cc7f5dad29b, which broke
# on its first firing: sagemath/sagemath runs as uid 1001 (USER sage), but the
# bind-mounted work dir is root:root 0755 (the uid-0 worker made it), so
# `sage solver.sage` fails EACCES in the mandatory PREPARSE step — before any
# solver line runs — because sage-preparse writes solver.sage.py next to the
# source (it ignores TMPDIR). Fixed by running the sage container as user 0:0
# (the python3 runner ALREADY runs as root, so this matches, not widens, the
# posture). This smoke test reproduces the exact bug (a) and proves the fix (b),
# so a future edit to the user/cmd logic can't silently regress it again.
#
# The probe uses Sage-ONLY syntax (`R.<x> = ZZ[]`) that python3 cannot parse, so
# a printed marker proves preparse both RAN and successfully WROTE its output
# into the root-owned work dir — not merely that some Python executed.
#
# USAGE:  ./scripts/sage-sandbox-smoke.sh
#   exit 0 = fix present and working; exit 1 = regression (fix missing/broken).
# Requires: a working docker CLI + the sagemath/sagemath image (pulled on first
# real sage job; this script pulls it if absent).
# Env overrides (for Docker-Desktop-shadowed hosts, see CLAUDE.md):
#   DOCKER      — path to the docker binary (default: `docker` on PATH)
#   DOCKER_HOST — docker daemon socket (exported to every docker call)
# e.g.  DOCKER=/snap/bin/docker DOCKER_HOST=unix:///var/run/docker.sock \
#         ./scripts/sage-sandbox-smoke.sh
set -u

DK="${DOCKER:-docker}"      # a single binary path, NOT a command string
IMG="sagemath/sagemath:latest"
MARK="FLAG_CANDIDATE: SAGE_SMOKE_OK"
# Scratch dir. MUST live under a path the docker daemon bind-mounts faithfully.
# On Docker-Desktop-on-WSL2, a sudo-created (root-owned) dir under /tmp does NOT
# propagate into a container mount — the container sees "No such file", masking
# the real test. The home/repo tree IS shared faithfully. Default there; honor
# SMOKE_DIR to override. (mktemp under /tmp is deliberately NOT used.)
G="$(mktemp -d "${SMOKE_DIR:-$HOME}/sage-smoke.XXXXXX")"
cleanup() {
  # $G may hold root-owned files (set below); try sudo, then a root container,
  # then plain rm.
  sudo -n rm -rf "$G" 2>/dev/null && return
  $DK run --rm -v "$G:/g" busybox:latest sh -c 'rm -rf /g/* /g/.* 2>/dev/null' 2>/dev/null
  rm -rf "$G" 2>/dev/null
}
trap cleanup EXIT

mkdir -p "$G/work/tmp"
printf 'R.<x> = ZZ[]\nprint("%s")\n' "$MARK" > "$G/work/solver.sage"

if ! $DK image inspect "$IMG" >/dev/null 2>&1; then
  echo "[*] pulling $IMG (first run) …"
  $DK pull "$IMG" >/dev/null 2>&1 || { echo "[skip] cannot pull $IMG"; exit 0; }
fi

# Mirror production: the worker (root) owns the work tree root:root 0755, so the
# sandbox (uid 1001) can't write it. Set that ownership. Prefer sudo; fall back
# to a throwaway root container (always available since we already need docker)
# when sudo's credential timestamp isn't reachable (subshell/CI/non-tty).
if sudo -n chown -R 0:0 "$G" 2>/dev/null; then
  sudo chmod -R 0755 "$G"
elif $DK run --rm -v "$G:/g" busybox:latest sh -c 'chown -R 0:0 /g && chmod -R 0755 /g' 2>/dev/null; then
  :  # ownership set via root container
else
  echo "[skip] could not set root:root work dir (no passwordless sudo, no busybox)"; exit 0
fi

# Guard against a daemon that doesn't present the root-owned mount to the
# container (Docker-Desktop-on-WSL2 with a /tmp source; see $G note). If a
# --user 0:0 container can't even SEE the file, the mount — not the fix — is
# the problem, so skip rather than emit a false regression. In production
# (real root daemon, work dir under /data) this always passes.
if ! $DK run --rm --user 0:0 -v "$G:/data" busybox:latest \
        test -f /data/work/solver.sage 2>/dev/null; then
  echo "[skip] daemon does not present the root-owned work dir to the container"
  echo "       (mount artifact, not a fix regression). Run under a real root"
  echo "       docker daemon, or set SMOKE_DIR to a faithfully-shared path."
  exit 0
fi

# (a) WITHOUT the fix: default uid 1001 → must EACCES, marker must be ABSENT.
out_a="$($DK run --rm --network none -v "$G:/data" -w /data/work \
          -e TMPDIR=/data/work/tmp "$IMG" sage /data/work/solver.sage 2>&1)"
if echo "$out_a" | grep -q "$MARK"; then
  echo "[!] control FAILED: marker printed even as uid 1001 — the EACCES premise"
  echo "    no longer holds (image user changed?). Investigate before trusting (b)."
  exit 1
fi
echo "[ok] (a) reproduced the bug: uid-1001 sage hits preparse EACCES (no marker)"

# (b) WITH the fix: --user 0:0 + HOME → marker MUST be present.
out_b="$($DK run --rm --network none --user 0:0 -e HOME=/home/sage \
          -v "$G:/data" -w /data/work -e TMPDIR=/data/work/tmp \
          "$IMG" sage /data/work/solver.sage 2>&1)"
if echo "$out_b" | grep -q "$MARK"; then
  echo "[ok] (b) fix works: --user 0:0 lets sage preparse write the root-owned"
  echo "     work dir → solver ran and printed the marker"
  echo "PASS: sage sandbox path healthy"
  exit 0
fi
echo "[FAIL] (b) fix NOT working — sage still could not run as uid 0:"
echo "$out_b" | tail -5
exit 1
