#!/usr/bin/env bash
# Initialise HexTech's private Codex runtime home from the operator's login.
#
# The containers run Codex as uid 0.  Mounting the operator's ~/.codex rw lets
# those processes replace config.toml and session files with root-owned 0600
# files, which breaks an already-running host TUI.  HexTech therefore gets a
# separate writable home and imports only the OAuth credential on first use.
set -euo pipefail

SOURCE_HOME="${1:?source Codex home is required}"
RUNTIME_HOME="${2:?HexTech Codex runtime home is required}"

source_real="$(realpath -m -- "$SOURCE_HOME")"
runtime_real="$(realpath -m -- "$RUNTIME_HOME")"
if [ "$source_real" = "$runtime_real" ]; then
  printf 'refusing to bootstrap Codex into the operator home: %s\n' "$source_real" >&2
  exit 2
fi

umask 077
mkdir -p -- "$RUNTIME_HOME"
chmod 700 -- "$RUNTIME_HOME" 2>/dev/null || true

# Never copy config.toml, sessions, locks, skills, or package state.  The
# HexTech adapter supplies its runtime configuration via CLI flags and needs
# only file-backed ChatGPT OAuth.  Copying the rest would recreate the TUI
# ownership collision this helper exists to prevent.
if [ ! -s "$RUNTIME_HOME/auth.json" ] && [ -s "$SOURCE_HOME/auth.json" ]; then
  auth_tmp="$RUNTIME_HOME/.auth.json.bootstrap.$$"
  cp -- "$SOURCE_HOME/auth.json" "$auth_tmp"
  chmod 600 -- "$auth_tmp"
  mv -f -- "$auth_tmp" "$RUNTIME_HOME/auth.json"
  printf 'initialized isolated HexTech Codex OAuth at %s\n' "$RUNTIME_HOME"
fi
