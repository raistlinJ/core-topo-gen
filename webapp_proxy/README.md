# Envoy gRPC Proxy for CORE

This folder contains a hardened Envoy configuration to proxy the CORE gRPC daemon.

- Downstream: TLS (mTLS optional) on :7443
- Upstream: h2c to core-daemon at 127.0.0.1:50051
- Admin: 127.0.0.1:9901 (local only)

## Files
- `envoy.yaml` — main Envoy config
- `systemd/envoy-core-proxy.service` — sample systemd unit
- `certs/` — place `server.crt`, `server.key`, `ca.crt` (and `client.crt`, `client.key` for mTLS)
- `scripts/generate-dev-certs.sh` — helper to generate self-signed dev certs (not for prod)

## Quick start (non-Docker)
1) Keep core-daemon private:
   - Run on the CORE host: `sudo core-daemon --grpc-address 127.0.0.1` (or default)
   - Ensure port 50051 is NOT exposed externally.

2) Generate test certs (optional, dev only):
   - `bash webapp_proxy/scripts/generate-dev-certs.sh`

3) Configure Envoy:
   - Edit `webapp_proxy/envoy.yaml` cert paths if needed.
   - To enforce mTLS, set `require_client_certificate: true` in the DownstreamTlsContext and ensure `ca.crt` is present.

4) Run Envoy directly for a smoke test:
   - `sudo mkdir -p /var/log/envoy && sudo chown $USER /var/log/envoy`
   - `envoy -c webapp_proxy/envoy.yaml --log-level info`
      - If your web app does not use TLS yet, you can run a plaintext listener for testing:
         - `envoy -c webapp_proxy/envoy-h2c.yaml --log-level info`

5) Install as a service (optional):
   - Create user: `sudo useradd --system --no-create-home --shell /usr/sbin/nologin envoy || true`
   - `sudo cp webapp_proxy/systemd/envoy-core-proxy.service /etc/systemd/system/`
   - `sudo systemctl daemon-reload`
   - `sudo systemctl enable --now envoy-core-proxy`

6) Firewall (defense in depth):
   - Allow only your web app’s source IP(s) to port 7443.
   - Keep 50051 blocked from all sources.

## Web app client settings
- Point the web app’s CORE_HOST/CORE_PORT to the proxy (host:7443).
- If mTLS is enabled, configure the gRPC client to use `client.crt` and `client.key` and trust `ca.crt`.
- The proxy only supports HTTP/2 (gRPC) on the downstream.

### App TLS env vars (when using TLS listener)
Set these before starting the web app so it connects to Envoy over TLS:

- `CORE_HOST=127.0.0.1` (or proxy host)
- `CORE_PORT=7443`
- `CORE_TLS=1`
- `CORE_CA_CERT=/absolute/path/to/ca.crt`
- Optional mTLS:
   - `CORE_CLIENT_CERT=/absolute/path/to/client.crt`
   - `CORE_CLIENT_KEY=/absolute/path/to/client.key`

### TLS vs plaintext (h2c)
- `envoy.yaml` uses TLS on 7443. Your client must use a TLS gRPC channel and trust the CA (see certs/).
- `envoy-h2c.yaml` uses plaintext (h2c) on 7443 for quick testing. Your client can use an insecure channel.
   - Switch back to TLS for real use once you’ve validated the path end-to-end.

## Admin interface
- Envoy admin listens on 127.0.0.1:9901. Do not expose publicly. Useful endpoints: `/stats`, `/clusters`, `/listeners`, `/ready`.

## Troubleshooting
- Validate config without starting: `envoy --mode validate -c webapp_proxy/envoy.yaml`
- Ensure logs directory exists: `sudo mkdir -p /var/log/envoy && sudo chown $USER /var/log/envoy`
- Tail access log (appears only after first request): `tail -f /var/log/envoy/core-grpc-access.log`
- Check listeners: `curl -s http://127.0.0.1:9901/listeners`
- Check clusters and upstream health: `curl -s http://127.0.0.1:9901/clusters | grep -A3 core_daemon`

## Production notes
- Use a proper CA and rotate certs regularly.
- Consider WireGuard/IPsec between the web app host and the CORE host; bind Envoy only to the tunnel IP.
- Add rate limits, per-method RBAC, and JWT/OIDC validation if needed (Envoy supports all of these via filters).
- Keep systemd hardening; review file permissions of `certs/` and `/var/log/envoy`.
