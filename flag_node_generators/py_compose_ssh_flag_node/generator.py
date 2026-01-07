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


def _compute_cred(seed: str, node_name: str, label: str, length: int) -> str:
    base = f"{seed}|{node_name}|{label}".encode("utf-8", "replace")
    digest = hashlib.sha256(base).hexdigest()
    return digest[: max(4, int(length))]


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

    ssh_port = int(cfg.get("ssh_port") or 22)
    ssh_username = str(cfg.get("ssh_username") or "")
    ssh_password = str(cfg.get("ssh_password") or "")

    if not ssh_username:
        ssh_username = "user_" + _compute_cred(seed, node_name, "ssh_user", 8)
    # password: hex-ish string, deterministic
    if not ssh_password:
        ssh_password = _compute_cred(seed, node_name, "ssh_pass", 16)

    flag_value = _compute_flag(seed=seed, node_name=node_name, flag_prefix=flag_prefix)

    # Ubuntu + openssh-server installed at container start.
    # Exposes port 22 inside the container; compose maps host port if desired.
    compose_text = (
        "services:\n"
        "  node:\n"
        "    image: ubuntu:22.04\n"
        "    ports:\n"
        f"      - \"{ssh_port}:22\"\n"
        "    environment:\n"
        f"      FLAG: {json.dumps(flag_value)}\n"
        f"      SSH_USERNAME: {json.dumps(ssh_username)}\n"
        f"      SSH_PASSWORD: {json.dumps(ssh_password)}\n"
        "    command: [\"bash\", \"-lc\", \"set -euo pipefail; "
        "export DEBIAN_FRONTEND=noninteractive; "
        "apt-get update; apt-get install -y --no-install-recommends openssh-server ca-certificates; "
        "mkdir -p /var/run/sshd; "
        "useradd -m -s /bin/bash \"$SSH_USERNAME\"; "
        "echo \"$SSH_USERNAME:$SSH_PASSWORD\" | chpasswd; "
        "mkdir -p /home/\"$SSH_USERNAME\"; "
        "echo \"$FLAG\" > /home/\"$SSH_USERNAME\"/flag.txt; "
        "chown \"$SSH_USERNAME\":\"$SSH_USERNAME\" /home/\"$SSH_USERNAME\"/flag.txt; "
        "chmod 400 /home/\"$SSH_USERNAME\"/flag.txt; "
        "sed -ri 's/^#?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config; "
        "sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config; "
        "exec /usr/sbin/sshd -D -e\" ]\n"
    )

    compose_path = outputs_dir / "docker-compose.yml"
    _write_text(compose_path, compose_text)

    manifest = {
        "generator_id": str(cfg.get("generator_id") or "nodegen.py.ssh_flag_node"),
        "outputs": {
            "compose_path": str(compose_path.name),
            "flag": flag_value,
            "node_name": node_name,
            "ssh_username": ssh_username,
            "ssh_password": ssh_password,
            "ssh_port": ssh_port,
        },
    }
    _write_text(outputs_dir / "outputs.json", json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
