#!/usr/bin/env bash
# Stamp web-ui/version.json with the current git commit so the UI version badge
# (header #version-badge, fed by GET /api/version) shows which build is
# deployed. web-ui/ is bind-mounted read-only into the api container, so the api
# reads this file live — no image rebuild needed. The file is git-ignored (it is
# a per-deploy artifact, not source). `patched_at` is computed live by the api
# from source mtimes, so even if this stamp is skipped the "last patch" date
# stays accurate; the stamp only adds the recognizable commit hash + deploy time.
set -uo pipefail
cd "$(dirname "$0")"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
CDATE="$(git log -1 --format=%cI 2>/dev/null || echo '')"
NOW="$(date -Iseconds 2>/dev/null || date)"
printf '{"commit":"%s","commit_date":"%s","deployed_at":"%s"}\n' \
  "$COMMIT" "$CDATE" "$NOW" > web-ui/version.json \
  && echo "stamped web-ui/version.json -> $COMMIT ($CDATE)" \
  || echo "[warn] could not write web-ui/version.json"
