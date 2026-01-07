import hashlib
import json
import os
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

    seed = str(cfg.get("seed") or "")
    node_name = str(cfg.get("node_name") or "docker-node")
    flag_prefix = str(cfg.get("flag_prefix") or "FLAG")

    if not seed:
        seed = "seed"

    flag_value = _compute_flag(seed=seed, node_name=node_name, flag_prefix=flag_prefix)

    compose_text = (
        "services:\n"
        "  node:\n"
        "    image: ubuntu:22.04\n"
        "    environment:\n"
        f"      FLAG: {json.dumps(flag_value)}\n"
        "    command: [\"bash\", \"-lc\", \"set -euo pipefail; echo $FLAG > /flag.txt; chmod 400 /flag.txt; sleep infinity\"]\n"
    )

    compose_path = outputs_dir / "docker-compose.yml"
    _write_text(compose_path, compose_text)

    manifest = {
        "generator_id": str(cfg.get("generator_id") or "nodegen.py.compose_flag_node"),
        "outputs": {
            "compose_path": str(compose_path.name),
            "flag": flag_value,
            "node_name": node_name,
        },
    }
    _write_text(outputs_dir / "outputs.json", json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
