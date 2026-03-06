#!/usr/bin/env bash
set -euo pipefail

# Run the Web UI in auto/local/remote CORE mode.
# - auto: legacy/backward-compatible behavior (no forced local-mode lock)
# - local: CORE gRPC defaults to 127.0.0.1:50051 and enables local-mode lock
# - remote: CORE gRPC must be supplied (or uses env/defaults)
#
# Examples:
#   bash scripts/run_webui_mode.sh
#   bash scripts/run_webui_mode.sh --mode local
#   bash scripts/run_webui_mode.sh --mode remote --core-host 10.0.0.50 --core-port 50051
#   bash scripts/run_webui_mode.sh --mode remote --core-host corevm.local --detach --web-port 9090

usage() {
  cat <<'USAGE'
Usage: run_webui_mode.sh [options]

Options:
  --mode <auto|local|remote> Run mode (default: auto)
  --core-host <host>         CORE gRPC host (remote mode recommended)
  --core-port <port>         CORE gRPC port (default: 50051)
  --web-host <host>          Web bind host (default: 127.0.0.1)
  --web-port <port>          Web bind port (default: 9090)
  --python <path-or-cmd>     Python interpreter/command override
  --log-level <level>        WEBAPP_LOG_LEVEL (default: INFO)
  --detach                   Run in background and write logs to outputs/logs/
  --kill-existing            Kill process listening on --web-port before start
  -h, --help                 Show help
USAGE
}

choose_python() {
  local requested="${1:-}"
  local -a candidates=()
  if [[ -n "$requested" ]]; then
    candidates+=("$requested")
  fi
  if [[ -n "${WEBUI_PY:-}" ]]; then
    candidates+=("$WEBUI_PY")
  fi
  if [[ -x ".venv312/bin/python" ]]; then
    candidates+=(".venv312/bin/python")
  fi
  if [[ -x ".venv/bin/python" ]]; then
    candidates+=(".venv/bin/python")
  fi
  candidates+=("core-python" "python3" "python")

  local cmd
  for cmd in "${candidates[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
      echo "$cmd"
      return 0
    fi
  done
  return 1
}

MODE="auto"
CORE_HOST_ARG=""
CORE_PORT_ARG="50051"
WEB_HOST_ARG="127.0.0.1"
WEB_PORT_ARG="9090"
PYTHON_ARG=""
LOG_LEVEL_ARG="INFO"
DETACH="0"
KILL_EXISTING="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="${2:-}"
      shift 2
      ;;
    --core-host)
      CORE_HOST_ARG="${2:-}"
      shift 2
      ;;
    --core-port)
      CORE_PORT_ARG="${2:-}"
      shift 2
      ;;
    --web-host)
      WEB_HOST_ARG="${2:-}"
      shift 2
      ;;
    --web-port)
      WEB_PORT_ARG="${2:-}"
      shift 2
      ;;
    --python)
      PYTHON_ARG="${2:-}"
      shift 2
      ;;
    --log-level)
      LOG_LEVEL_ARG="${2:-}"
      shift 2
      ;;
    --detach)
      DETACH="1"
      shift
      ;;
    --kill-existing)
      KILL_EXISTING="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ "$MODE" != "auto" && "$MODE" != "local" && "$MODE" != "remote" ]]; then
  echo "Invalid --mode: $MODE (expected auto, local or remote)" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

PY_CMD="$(choose_python "$PYTHON_ARG")"

CORE_HOST_EFFECTIVE="$CORE_HOST_ARG"
if [[ -z "$CORE_HOST_EFFECTIVE" ]]; then
  if [[ "$MODE" == "local" ]]; then
    CORE_HOST_EFFECTIVE="127.0.0.1"
  elif [[ "$MODE" == "auto" ]]; then
    CORE_HOST_EFFECTIVE="${CORE_HOST:-localhost}"
  else
    CORE_HOST_EFFECTIVE="${CORE_HOST:-localhost}"
  fi
fi

if [[ "$KILL_EXISTING" == "1" ]]; then
  existing_pid="$(lsof -t -iTCP:"$WEB_PORT_ARG" -sTCP:LISTEN 2>/dev/null | head -n 1 || true)"
  if [[ -n "$existing_pid" ]]; then
    echo "[webui:$MODE] Stopping existing listener PID $existing_pid on port $WEB_PORT_ARG"
    kill "$existing_pid" || true
    sleep 0.4
  fi
fi

export PYTHONUNBUFFERED=1
export WEBAPP_LOG_LEVEL="$LOG_LEVEL_ARG"
export CORETG_DEBUG="${CORETG_DEBUG:-0}"
export CORETG_USE_RELOADER="${CORETG_USE_RELOADER:-0}"
export CORETG_HOST="$WEB_HOST_ARG"
export CORETG_PORT="$WEB_PORT_ARG"
export CORE_HOST="$CORE_HOST_EFFECTIVE"
export CORE_PORT="$CORE_PORT_ARG"
export CORETG_RUN_MODE="$MODE"

if [[ "$MODE" == "local" ]]; then
  export CORETG_LOCAL_MODE="1"
  export CORETG_LOCAL_CORE_HOST="$CORE_HOST_EFFECTIVE"
  export CORETG_LOCAL_CORE_PORT="$CORE_PORT_ARG"
  export CORETG_LOCAL_SSH_PORT="${CORETG_LOCAL_SSH_PORT:-22}"
else
  export CORETG_LOCAL_MODE="0"
fi

echo "[webui:$MODE] python=$PY_CMD"
echo "[webui:$MODE] bind=${CORETG_HOST}:${CORETG_PORT}"
echo "[webui:$MODE] core=${CORE_HOST}:${CORE_PORT}"
echo "[webui:$MODE] log_level=${WEBAPP_LOG_LEVEL}"

if [[ "$DETACH" == "1" ]]; then
  mkdir -p outputs/logs
  log_file="outputs/logs/webui-${MODE}-${WEB_PORT_ARG}.log"
  nohup "$PY_CMD" -u -m main >"$log_file" 2>&1 &
  pid="$!"
  echo "[webui:$MODE] started pid=$pid"
  echo "$pid" > server.pid
  echo "[webui:$MODE] log=$log_file"
  exit 0
fi

exec "$PY_CMD" -u -m main
