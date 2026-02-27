# Quick Start

## Prerequisites
- Python 3.10+ (3.11 recommended)
- [uv](https://docs.astral.sh/uv/)
- [CORE](https://www.nrl.navy.mil/Our-Work/Areas-of-Research/CORE/) 9.2 or newer with `core-daemon` running
- Docker (optional) for nginx reverse proxy or vulnerability compose targets

## Install dependencies
Using **uv**:
```bash
uv sync --extra dev
```

## HTTPS via Docker Compose
Run the web app behind nginx with TLS termination:
```bash
docker compose up -d --build
```
- Open `https://localhost`.
- Verify HTTPS health: `curl -k https://localhost/healthz`
- Stop the stack: `docker compose down`
- Host-network deploy mode keeps nginx on `80/443` while the web backend binds to `127.0.0.1:9090`.
- Safety: in Execute → Advanced, `Delete all docker containers` is disabled when the Web UI is running in Docker.

## Launch the Web UI
Run the backend directly for local development:
```bash
uv run python webapp/app_backend.py
```
- Visit `http://localhost:9090`.
- For HTTPS + reverse proxy mode, use [HTTPS via Docker Compose](#https-via-docker-compose).
- HITL editor note: the “Attach to” dropdown offers `Existing Router`, `Existing Switch`, or `New Router`. Once Proxmox credentials and VM selections are validated, use **Apply Internal Bridge** to create/update a Proxmox bridge and retarget both the CORE VM and external VM interfaces in one step.

## Run the CLI
With **uv**:
```bash
uv run python -m core_topo_gen.cli --xml path/to/scenario.xml --seed 42 --verbose
```
Popular options:
- `--scenario NAME` pick a specific scenario entry
- `--host / --port` override the CORE gRPC endpoint (defaults `127.0.0.1:50051`)
- `--layout-density {compact|normal|spacious}` adjust map spacing
- `--seg-include-hosts`, `--seg-allow-docker-ports`, `--nat-mode`, `--dnat-prob` fine-tune segmentation
- `--traffic-pattern`, `--traffic-rate`, `--traffic-content` override traffic defaults

## VS Code smoke tasks
For Execute retry-prompt validation, use these tasks from **Terminal → Run Task**:

- `Smoke UI Execute Retry Prompt`  
	Runs `scripts/ui_execute_retry_smoke.py` against the currently running Web UI.
- `Restart + Smoke UI Execute Retry Prompt`  
	Restarts Web UI on port 9090, waits for `/healthz`, then runs the same smoke.

Expected success output includes:

- `prompt_seen=True`
- `retry_click=ok`
- `retry_run_id_before=<id>`
- `retry_run_id_after=<different-id>`

Live CORE credential parity smoke for flag tests:

- Script: `python scripts/flag_test_core_e2e_check.py`
	- Logs into Web UI, reads a CORE secret from `outputs/secrets/core`, runs both `/flag_generators_test/run` and `/flag_node_generators_test/run` with `core` credentials payload, polls outputs, and performs cleanup.
	- Useful env vars: `CORETG_WEB_BASE`, `CORETG_WEB_USER`, `CORETG_WEB_PASS`, `CORETG_CORE_SECRET_ID`, `CORETG_SMOKE_POLL_SECONDS`.
- Pytest gate for CI/live infra:
	- `CORETG_RUN_LIVE_FLAG_CORE_SMOKE=1 pytest -q tests/test_flag_test_core_e2e_smoke.py`
	- Skipped by default unless `CORETG_RUN_LIVE_FLAG_CORE_SMOKE=1` is set.
