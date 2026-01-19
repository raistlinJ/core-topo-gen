#!/usr/bin/env bash
set -euo pipefail

# Start the Web UI on the host at 127.0.0.1:9090 using a preferred Python interpreter.
# Priority: $WEBUI_PY -> core-python -> python3 -> python

choose_python() {
  local candidates=()
  if [[ -n "${WEBUI_PY:-}" ]]; then
    candidates+=("$WEBUI_PY")
  fi
  candidates+=("core-python" "python3" "python")

  local cmd
  for cmd in "${candidates[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      continue
    fi
    # Prefer an interpreter that can actually start the Web UI and render Markdown.
    if "$cmd" -c 'import flask, markdown, bleach' >/dev/null 2>&1; then
      echo "$cmd"; return 0
    fi
  done

  # Fall back to python3/python even if Flask isn't installed, so the error is explicit.
  if command -v python3 >/dev/null 2>&1; then
    echo "python3"; return 0
  fi
  echo "python"
}

PY_CMD=$(choose_python)

# Move to repo root if script run from elsewhere
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT/webapp"

export PYTHONUNBUFFERED=1

# Host-web runs behind a reverse proxy; default to a stable, restart-friendly configuration.
# Override as needed: CORETG_DEBUG=1 CORETG_USE_RELOADER=1 make host-web
: "${CORETG_HOST:=127.0.0.1}"
: "${CORETG_DEBUG:=0}"
: "${CORETG_USE_RELOADER:=0}"
export CORETG_HOST CORETG_DEBUG CORETG_USE_RELOADER

echo "[host-web] Using interpreter: $PY_CMD"
echo "[host-web] Starting Web UI on http://${CORETG_HOST}:9090 (debug=${CORETG_DEBUG}, reloader=${CORETG_USE_RELOADER})"

# Write backend logs to a stable location so `make host-web` stays readable.
LOG_DIR="$REPO_ROOT/outputs/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/host-webui.log"

# Start the server in background and write its PID to repo root server.pid
cd "$REPO_ROOT/webapp"
"$PY_CMD" app_backend.py >>"$LOG_FILE" 2>&1 &
SERVER_PID=$!
echo "$SERVER_PID" > "$REPO_ROOT/server.pid"
echo "[host-web] Server PID: $SERVER_PID (written to $REPO_ROOT/server.pid)"
echo "[host-web] Logs: $LOG_FILE"
wait "$SERVER_PID"
