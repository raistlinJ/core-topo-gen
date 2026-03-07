# Stability Baseline (2026-03-07)

## Baseline Identity
- Branch: `main`
- Commit: `23b84f1`
- Validation date: `2026-03-07`

## Test Baseline
- Command:
  - `./.venv312/bin/python -m pytest -q -ra`
- Result:
  - `462 passed, 3 skipped`

## Skipped Tests
- `tests/test_flag_test_core_e2e_smoke.py:25`
  - Reason: `Set CORETG_RUN_LIVE_FLAG_CORE_SMOKE=1 to run live CORE smoke`
- `tests/test_orchestrator_parity.py:18`
  - Reason: `core.api.grpc not fully available; skipping CLI orchestrator parity test`
- `tests/test_web_cli_preview_parity.py:18`
  - Reason: `core.api.grpc not installed; skipping parity test`

## Runtime Smoke
- Web UI start:
  - `bash scripts/run_webui_mode.sh --mode auto --web-port 9090 --kill-existing --detach`
- Health check:
  - `curl -fsS http://127.0.0.1:9090/healthz`
  - Expected output: `ok`
- Login route check:
  - `curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:9090/login`
  - Expected status: `200`

## Stability Release Checklist
- Ensure dependency bootstrap succeeds:
  - `make ensure-webui-deps`
- Run full test suite with skip reasons:
  - `./.venv312/bin/python -m pytest -q -ra`
- Confirm no new unexpected skips/failures.
- Confirm Web UI smoke checks (`/healthz`, `/login`).
- Confirm working tree is clean before tagging.

## Known-Good Tag Commands
Use these once you are ready to mark the baseline.

1. Verify branch, commit, and cleanliness:
```bash
git rev-parse --abbrev-ref HEAD
git rev-parse --short HEAD
git status --short
```

2. If needed, commit remaining tracked changes first (example):
```bash
git add API.md docs/openapi.yaml
git commit -m "docs: finalize API and OpenAPI updates"
```

3. Create and push annotated stability tag:
```bash
git tag -a stable-2026-03-07 -m "Stable baseline: tests green (462 passed, 3 skipped)"
git push origin stable-2026-03-07
```

4. Quick tag verification:
```bash
git show stable-2026-03-07 --no-patch
git ls-remote --tags origin | rg stable-2026-03-07
```

## Notes
- Current local tree at validation time had modified files:
  - `API.md`
  - `docs/openapi.yaml`
- Tag only after deciding whether these changes should be included.
