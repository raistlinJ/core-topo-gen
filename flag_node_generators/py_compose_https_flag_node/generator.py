import hashlib
import json
from pathlib import Path
from typing import Any, Dict


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text("utf-8"))
    except Exception:
        return {}


def _compute_flag(seed: str, node_name: str, flag_prefix: str) -> str:
    base = f"{seed}|{node_name}".encode("utf-8", "replace")
    digest = hashlib.sha256(base).hexdigest()[:16]
    prefix = (flag_prefix or "FLAG").strip() or "FLAG"
    return f"{prefix}{{{digest}}}"


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main() -> None:
    inputs_dir = Path("/inputs")
    outputs_dir = Path("/outputs")

    cfg = _read_json(inputs_dir / "config.json")

    seed = str(cfg.get("seed") or "") or "seed"
    node_name = str(cfg.get("node_name") or "docker-node")
    flag_prefix = str(cfg.get("flag_prefix") or "FLAG")

    https_port = int(cfg.get("https_port") or 8443)

    flag_value = _compute_flag(seed=seed, node_name=node_name, flag_prefix=flag_prefix)

    # We generate support files alongside docker-compose.yml: nginx config and html.
    html_dir = outputs_dir / "html"
    conf_dir = outputs_dir / "nginx"
    certs_dir = outputs_dir / "certs"
    html_dir.mkdir(parents=True, exist_ok=True)
    conf_dir.mkdir(parents=True, exist_ok=True)
    certs_dir.mkdir(parents=True, exist_ok=True)

    _write_text(html_dir / "index.html", f"<html><body><h1>{flag_value}</h1></body></html>\n")
    _write_text(html_dir / "flag.txt", flag_value + "\n")

    nginx_conf = (
        "server {\n"
        "  listen 443 ssl;\n"
        "  server_name _;\n"
        "  ssl_certificate /etc/nginx/certs/server.crt;\n"
        "  ssl_certificate_key /etc/nginx/certs/server.key;\n"
        "  location / {\n"
        "    root /usr/share/nginx/html;\n"
        "    index index.html;\n"
        "  }\n"
        "}\n"
    )
    _write_text(conf_dir / "default.conf", nginx_conf)

    # Nginx alpine doesn't include openssl by default; we install it at runtime to mint a self-signed cert.
    compose_text = (
        "services:\n"
        "  node:\n"
        "    image: nginx:alpine\n"
        "    ports:\n"
        f"      - \"{https_port}:443\"\n"
        "    volumes:\n"
        "      - ./html:/usr/share/nginx/html:ro\n"
        "      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro\n"
        "      - ./certs:/etc/nginx/certs\n"
        "    command: [\"/bin/sh\", \"-lc\", \"set -euo pipefail; "
        "apk add --no-cache openssl; "
        "if [ ! -f /etc/nginx/certs/server.key ]; then "
        "openssl req -x509 -newkey rsa:2048 -days 365 -nodes "
        "-subj /CN=localhost "
        "-keyout /etc/nginx/certs/server.key -out /etc/nginx/certs/server.crt; "
        "fi; exec nginx -g 'daemon off;'\" ]\n"
    )

    compose_path = outputs_dir / "docker-compose.yml"
    _write_text(compose_path, compose_text)

    manifest = {
        "generator_id": str(cfg.get("generator_id") or "nodegen.py.https_flag_node"),
        "outputs": {
            "compose_path": str(compose_path.name),
            "flag": flag_value,
            "https_port": https_port,
            "flag_url_hint": f"https://<node-ip>:{https_port}/flag.txt",
        },
    }
    _write_text(outputs_dir / "outputs.json", json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
