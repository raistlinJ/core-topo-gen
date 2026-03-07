#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUTS_DIR="$REPO_ROOT/outputs"
REPORTS_DIR="$REPO_ROOT/reports"

DRY_RUN=0
YES=0

usage() {
  cat <<'USAGE'
Usage: clear_runtime_data.sh [options]

Clears prior scenario/runtime data while preserving generator/vulnerability assets.

Options:
  --dry-run   Show what would be removed without deleting anything
  --yes       Do not prompt for confirmation
  -h, --help  Show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
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

declare -a PRESERVE_OUTPUT_BASENAMES=(
  "secrets"
  "users"
  "installed_generators"
  "installed_vuln_catalogs"
  "flags"
  "flag_packages"
  "flag_generators_runs"
  "flag_node_generators_runs"
  "flag_generators_test_core_hint.json"
  "sample_flag_package_src"
  "sample_flag_compose_package_src"
  "sample_flag_compose_multi_package_src"
  "vulns"
  "vuln-tests"
)

declare -a REMOVE_PATHS=()

contains_preserved_output() {
  local name="$1"
  local kept
  for kept in "${PRESERVE_OUTPUT_BASENAMES[@]}"; do
    if [[ "$name" == "$kept" ]]; then
      return 0
    fi
  done
  return 1
}

queue_remove() {
  local path="$1"
  [[ -e "$path" || -L "$path" ]] || return 0
  REMOVE_PATHS+=("$path")
}

if [[ -d "$OUTPUTS_DIR" ]]; then
  while IFS= read -r -d '' child; do
    base="$(basename "$child")"
    if contains_preserved_output "$base"; then
      continue
    fi
    queue_remove "$child"
  done < <(find "$OUTPUTS_DIR" -mindepth 1 -maxdepth 1 -print0)
fi

if [[ -d "$REPORTS_DIR" ]]; then
  while IFS= read -r -d '' report; do
    queue_remove "$report"
  done < <(find "$REPORTS_DIR" -maxdepth 1 -type f \( -name 'scenario_report_*.md' -o -name 'pre_session_capture_*' \) -print0)
fi

queue_remove "$REPO_ROOT/server.pid"

if [[ ${#REMOVE_PATHS[@]} -eq 0 ]]; then
  echo "No runtime data matched cleanup rules."
  exit 0
fi

echo "Runtime data cleanup target list:"
for path in "${REMOVE_PATHS[@]}"; do
  echo "  $path"
done

if [[ "$DRY_RUN" == "1" ]]; then
  echo "Dry run only; no files removed."
  exit 0
fi

if [[ "$YES" != "1" ]]; then
  printf "Remove these paths? [y/N] "
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

echo "Runtime data cleanup complete."