#!/usr/bin/env bash
set -euo pipefail

# Run the web app with Envoy proxy settings pre-configured via environment variables.
# Defaults assume Envoy is listening with TLS on 127.0.0.1:7443 and certs are under webapp_proxy/certs.

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
CERT_DIR="$REPO_ROOT/webapp_proxy/certs"

# Defaults (can be overridden via flags or pre-set env)
CORE_HOST_DEFAULT=${CORE_HOST:-127.0.0.1}
CORE_PORT_DEFAULT=${CORE_PORT:-7443}
CORE_TLS_DEFAULT=${CORE_TLS:-1}
CA_CERT_DEFAULT=${CORE_CA_CERT:-"$CERT_DIR/ca.crt"}
CLIENT_CERT_DEFAULT=${CORE_CLIENT_CERT:-"$CERT_DIR/client.crt"}
CLIENT_KEY_DEFAULT=${CORE_CLIENT_KEY:-"$CERT_DIR/client.key"}

USE_MTLS_DEFAULT=0
PYTHON_BIN=""

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --host <host>           CORE_HOST to reach Envoy (default: $CORE_HOST_DEFAULT)
  --port <port>           CORE_PORT to reach Envoy (default: $CORE_PORT_DEFAULT)
  --h2c                   Disable TLS to Envoy (sets CORE_TLS=0)
  --tls                   Enable TLS to Envoy (sets CORE_TLS=1) [default]
  --ca <path>             Path to CA cert to trust (default: $CA_CERT_DEFAULT)
  --mtls                  Enable mTLS; also export client cert/key if present
  --client-cert <path>    Path to client certificate (PEM)
  --client-key <path>     Path to client private key (PEM)
  --python <path>         Python interpreter to use (default: auto-detect)
  -h, --help              Show this help
EOF
}

# Parse flags
CORE_HOST_VAL="$CORE_HOST_DEFAULT"
CORE_PORT_VAL="$CORE_PORT_DEFAULT"
CORE_TLS_VAL="$CORE_TLS_DEFAULT"
CA_CERT_VAL="$CA_CERT_DEFAULT"
CLIENT_CERT_VAL="$CLIENT_CERT_DEFAULT"
CLIENT_KEY_VAL="$CLIENT_KEY_DEFAULT"
USE_MTLS_VAL=$USE_MTLS_DEFAULT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)
      CORE_HOST_VAL="$2"; shift 2;;
    --port)
      CORE_PORT_VAL="$2"; shift 2;;
    --h2c)
      CORE_TLS_VAL=0; shift;;
    --tls)
      CORE_TLS_VAL=1; shift;;
    --ca)
      CA_CERT_VAL="$2"; shift 2;;
    --mtls)
      USE_MTLS_VAL=1; shift;;
    --client-cert)
      CLIENT_CERT_VAL="$2"; shift 2;;
    --client-key)
      CLIENT_KEY_VAL="$2"; shift 2;;
    --python)
      PYTHON_BIN="$2"; shift 2;;
    -h|--help)
      usage; exit 0;;
    *)
      echo "Unknown option: $1" >&2; usage; exit 2;;
  esac
done

# Auto-detect Python if not provided
if [[ -z "${PYTHON_BIN}" ]]; then
  if [[ -x "/opt/core/venv/bin/python" ]]; then
    PYTHON_BIN="/opt/core/venv/bin/python"
  elif [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
    PYTHON_BIN="$REPO_ROOT/.venv/bin/python"
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python)"
  else
    echo "Error: Could not find a Python interpreter" >&2
    exit 3
  fi
fi

# Export env vars for the app process
export CORE_HOST="$CORE_HOST_VAL"
export CORE_PORT="$CORE_PORT_VAL"
export CORE_TLS="$CORE_TLS_VAL"

if [[ "$CORE_TLS_VAL" == "1" ]]; then
  if [[ -f "$CA_CERT_VAL" ]]; then
    export CORE_CA_CERT="$CA_CERT_VAL"
  else
    echo "Warning: CORE_TLS=1 but CA cert not found at $CA_CERT_VAL; TLS may fail if system trust doesn't include your CA" >&2
  fi

  # Enable mTLS if requested or if both files exist
  if [[ "$USE_MTLS_VAL" == "1" || ( -f "$CLIENT_CERT_VAL" && -f "$CLIENT_KEY_VAL" ) ]]; then
    if [[ -f "$CLIENT_CERT_VAL" && -f "$CLIENT_KEY_VAL" ]]; then
      export CORE_CLIENT_CERT="$CLIENT_CERT_VAL"
      export CORE_CLIENT_KEY="$CLIENT_KEY_VAL"
    else
      echo "Warning: --mtls specified but client cert/key missing; continuing without mTLS" >&2
    fi
  fi
fi

echo "Starting web app with:"
echo "  CORE_HOST=$CORE_HOST CORE_PORT=$CORE_PORT CORE_TLS=$CORE_TLS"
if [[ "${CORE_TLS}" == "1" ]]; then
  echo "  CORE_CA_CERT=${CORE_CA_CERT:-<unset>}"
  echo "  CORE_CLIENT_CERT=${CORE_CLIENT_CERT:-<unset>}"
  echo "  CORE_CLIENT_KEY=${CORE_CLIENT_KEY:-<unset>}"
fi
echo "  Python: $PYTHON_BIN"

exec "$PYTHON_BIN" "$REPO_ROOT/webapp/app_backend.py"
