import hashlib
import json
from pathlib import Path
from typing import Any, Dict


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text("utf-8"))
    except Exception:
        return {}


def _derive_user_pass(seed: str, node_name: str) -> tuple[str, str]:
    h = hashlib.sha256(f"{seed}|{node_name}".encode("utf-8", "replace")).hexdigest()
    user = f"user_{h[:6]}"
    pw = f"pw_{h[6:14]}"
    return user, pw


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

    seed = str(cfg.get("seed") or "seed")
    node_name = str(cfg.get("node_name") or "docker-node")
    nfs_port = int(cfg.get("nfs_port") or 2049)
    flag_prefix = str(cfg.get("flag_prefix") or "FLAG")

    user, pw = _derive_user_pass(seed=seed, node_name=node_name)
    credential_pair = f"{user}:{pw}"

    flag_value = _compute_flag(seed=seed, node_name=node_name, flag_prefix=flag_prefix)

    exports_dir = outputs_dir / "exports"
    exports_dir.mkdir(parents=True, exist_ok=True)
    _write_text(exports_dir / "creds.txt", credential_pair + "\n")
    _write_text(exports_dir / "flag.txt", flag_value + "\n")

    # Use a user-space NFS server so the container does not require kernel `nfsd`
    # support (which typically needs `--privileged` and mounting /proc/fs/nfsd).
    # Prefer NFSv4-only to avoid rpcbind/mountd extra ports.
    ganesha_conf_text = (
        "NFS_Core_Param {\n"
        "  Protocols = 4;\n"
        "  # Avoid auxiliary RPC services in minimal containers.\n"
        "  Enable_NLM = false;\n"
        "  Enable_RQUOTA = false;\n"
        "}\n"
        "\n"
        "DBus {\n"
        "  Enabled = false;\n"
        "}\n"
        "\n"
        "EXPORT {\n"
        "  Export_Id = 1;\n"
        "  Path = /exports;\n"
        "  Pseudo = /exports;\n"
        "  Access_Type = RW;\n"
        "  Squash = no_root_squash;\n"
        "  SecType = sys;\n"
        "  Protocols = 4;\n"
        "  Transports = TCP;\n"
        "  FSAL {\n"
        "    Name = VFS;\n"
        "  }\n"
        "}\n"
    )
    _write_text(outputs_dir / "ganesha.conf", ganesha_conf_text)

    # CORE VMs often block/require auth for Quay.io pulls. To avoid registry auth
    # issues, build a tiny image locally (from a public base) that installs Ganesha.
    # This does require outbound apt access during build.
    dockerfile_text = (
        "FROM ubuntu:22.04\n"
        "ENV DEBIAN_FRONTEND=noninteractive\n"
        "RUN apt-get update \\\n"
        "  && apt-get install -y --no-install-recommends nfs-ganesha nfs-ganesha-vfs rpcbind netbase iproute2 \\\n"
        "  && rm -rf /var/lib/apt/lists/*\n"
        "\n"
        "# ganesha.nfsd is installed by the packages above\n"
    )
    _write_text(outputs_dir / "Dockerfile", dockerfile_text)

    compose_text = (
        "services:\n"
        "  node:\n"
        "    build:\n"
        "      context: .\n"
        "      dockerfile: Dockerfile\n"
        "    command: ['sh','-lc','rpcbind -w -f & RPCBIND_PID=$!; trap ""kill $RPCBIND_PID 2>/dev/null || true"" EXIT; ganesha.nfsd -F -L STDOUT -f /etc/ganesha/ganesha.conf || { echo \\\"[coretg] ganesha failed; keeping container alive\\\" >&2; sleep infinity; }']\n"
        "    privileged: true\n"
        "    ports:\n"
        f"      - \"{nfs_port}:2049\"\n"
        "    volumes:\n"
        "      - ./exports:/exports\n"
        "      - ./ganesha.conf:/etc/ganesha/ganesha.conf:ro\n"
        "    hostname: nfs\n"
    )

    compose_path = outputs_dir / "docker-compose.yml"
    _write_text(compose_path, compose_text)

    manifest = {
        "generator_id": str(cfg.get("generator_id") or "sample.nfs_sensitive_file"),
        "outputs": {
            "Flag(flag_id)": flag_value,
            "Credential(user, password)": credential_pair,
            "File(path)": str(compose_path.name),
            "PortForward(host, port)": nfs_port,
            "Directory(host, path)": "exports",
        },
    }
    _write_text(outputs_dir / "outputs.json", json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
