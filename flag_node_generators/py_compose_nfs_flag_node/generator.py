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

    nfs_port = int(cfg.get("nfs_port") or 2049)

    flag_value = _compute_flag(seed=seed, node_name=node_name, flag_prefix=flag_prefix)

    # Support files: exports directory with flag.
    exports_dir = outputs_dir / "exports"
    exports_dir.mkdir(parents=True, exist_ok=True)
    _write_text(exports_dir / "flag.txt", flag_value + "\n")

    # NFS server container.
    # NOTE: Many NFS server images require elevated privileges/caps.
    # We keep it explicit so it works in typical docker setups.
    compose_text = (
        "services:\n"
        "  node:\n"
        "    image: itsthenetwork/nfs-server-alpine:latest\n"
        "    privileged: true\n"
        "    environment:\n"
        "      SHARED_DIRECTORY: /exports\n"
        "    ports:\n"
        f"      - \"{nfs_port}:2049\"\n"
        "    volumes:\n"
        "      - ./exports:/exports\n"
    )

    compose_path = outputs_dir / "docker-compose.yml"
    _write_text(compose_path, compose_text)

    manifest = {
        "generator_id": str(cfg.get("generator_id") or "nodegen.py.nfs_flag_node"),
        "outputs": {
            "compose_path": str(compose_path.name),
            "flag": flag_value,
            "node_name": node_name,
            "nfs_port": nfs_port,
            "nfs_export": "/exports",
            "mount_hint": f"mount -t nfs <node-ip>:/exports /mnt && cat /mnt/flag.txt",
        },
    }
    _write_text(outputs_dir / "outputs.json", json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
