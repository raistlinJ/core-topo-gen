#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CATALOG_ROOT="$REPO_ROOT/outputs/installed_vuln_catalogs"
STATE_PATH="$CATALOG_ROOT/_catalogs_state.json"

DRY_RUN=0
YES=0
REMOVE_ALL=0

usage() {
  cat <<'USAGE'
Usage: prune_vuln_catalog_packs.sh [options]

Delete installed vulnerability catalog packs from outputs/installed_vuln_catalogs.

Default behavior:
  - keep the active catalog pack from _catalogs_state.json
  - remove all other catalog pack directories

Options:
  --all       Remove all catalog pack directories and reset state
  --dry-run   Show what would be removed without deleting anything
  --yes       Do not prompt for confirmation
  -h, --help  Show help

Notes:
  - This only removes app-level catalog pack files.
  - If these files live inside Docker overlay2 layers, run docker cleanup after
    deleting packs so the Docker engine can reclaim the space.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)
      REMOVE_ALL=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --yes)
      YES=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -d "$CATALOG_ROOT" ]]; then
  echo "No installed vulnerability catalog directory found at $CATALOG_ROOT"
  exit 0
fi

export CATALOG_ROOT STATE_PATH REMOVE_ALL

mapfile -t PLAN_LINES < <(python3 <<'PY'
import json
import os
from pathlib import Path

catalog_root = Path(os.environ['CATALOG_ROOT'])
state_path = Path(os.environ['STATE_PATH'])
remove_all = os.environ.get('REMOVE_ALL') == '1'

state = {'catalogs': [], 'active_id': ''}
if state_path.exists():
    try:
        state = json.loads(state_path.read_text(encoding='utf-8'))
        if not isinstance(state, dict):
            state = {'catalogs': [], 'active_id': ''}
    except Exception:
        state = {'catalogs': [], 'active_id': ''}

active_id = str(state.get('active_id') or '').strip()
catalogs = state.get('catalogs') if isinstance(state.get('catalogs'), list) else []
known_ids = []
for item in catalogs:
    if not isinstance(item, dict):
        continue
    cid = str(item.get('id') or '').strip()
    if cid:
        known_ids.append(cid)

dirs = sorted([p.name for p in catalog_root.iterdir() if p.is_dir()])

if remove_all:
    remove_ids = dirs
    keep_ids = []
    new_active = ''
    kept_catalogs = []
else:
    keep_ids = [active_id] if active_id else []
    remove_ids = [cid for cid in dirs if cid not in keep_ids]
    kept_catalogs = [item for item in catalogs if isinstance(item, dict) and str(item.get('id') or '').strip() in keep_ids]
    new_active = active_id if active_id in keep_ids else ''

for cid in remove_ids:
    print(f'REMOVE\t{catalog_root / cid}')

print(f'STATE\t{state_path}')
payload = {'catalogs': kept_catalogs, 'active_id': new_active}
print('STATE_JSON\t' + json.dumps(payload, sort_keys=True))
print('ACTIVE\t' + (active_id or ''))
PY
)

REMOVE_PATHS=()
STATE_JSON=''
ACTIVE_ID=''

for line in "${PLAN_LINES[@]}"; do
  kind="${line%%$'\t'*}"
  rest="${line#*$'\t'}"
  case "$kind" in
    REMOVE)
      REMOVE_PATHS+=("$rest")
      ;;
    STATE_JSON)
      STATE_JSON="$rest"
      ;;
    ACTIVE)
      ACTIVE_ID="$rest"
      ;;
  esac
done

if [[ ${#REMOVE_PATHS[@]} -eq 0 ]]; then
  if [[ "$REMOVE_ALL" == "1" ]]; then
    echo "No catalog pack directories found to remove."
  else
    if [[ -n "$ACTIVE_ID" ]]; then
      echo "Nothing to prune. Active catalog pack $ACTIVE_ID is the only installed pack."
    else
      echo "Nothing to prune. No inactive catalog pack directories found."
    fi
  fi
  exit 0
fi

echo "Vulnerability catalog pack cleanup target list:"
for path in "${REMOVE_PATHS[@]}"; do
  echo "  $path"
done

if [[ "$DRY_RUN" == "1" ]]; then
  echo "Dry run only; no files removed."
  exit 0
fi

if [[ "$YES" != "1" ]]; then
  printf "Remove these catalog pack directories? [y/N] "
  read -r answer
  case "$answer" in
    y|Y|yes|YES)
      ;;
    *)
      echo "Aborted."
      exit 1
      ;;
  esac
fi

for path in "${REMOVE_PATHS[@]}"; do
  rm -rf "$path"
done

if [[ -n "$STATE_JSON" ]]; then
  mkdir -p "$CATALOG_ROOT"
  printf '%s\n' "$STATE_JSON" > "$STATE_PATH"
fi

echo "Vulnerability catalog pack cleanup complete."
echo "Docker may still hold deleted bytes in overlay2 until old containers/images are removed."