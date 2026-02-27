# Troubleshooting

- **`core-python` not found`** – set `WEBUI_PY` before `make host-web` or rely on `python3`; the backend falls back to `sys.executable` if needed.
- **Empty TLS cert folder (`nginx/certs`)** – run `scripts/dev_gen_certs.sh` or `make dev-certs` before composing nginx.
- **`core-daemon` unreachable`** – verify daemon status and host/port; GUI run modal will surface connection issues immediately.
- **Docker vulnerabilities skipped** – ensure images are downloaded/pulled via the Vulnerabilities catalog and Docker is available to the host.
- **Log dock won’t auto-scroll** – click the “Follow Off/On” toggle to re-enable auto-follow.
- **Proxmox validate returns 502 (nginx)** – run `python scripts/proxmox_validate_smoke.py --base-url https://localhost` and confirm you get a clean `401 Authentication failed` (bad creds) or `success: true` (good creds) rather than a 502.
