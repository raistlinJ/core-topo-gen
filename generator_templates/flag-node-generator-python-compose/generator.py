import hashlib
import json
from pathlib import Path


def _read_config() -> dict:
    try:
        return json.loads(Path("/inputs/config.json").read_text("utf-8"))
    except Exception:
        return {}


def _flag(seed: str, node_name: str, flag_prefix: str = "FLAG") -> str:
    digest = hashlib.sha256(f"{seed}|{node_name}|flag".encode("utf-8", "replace")).hexdigest()[:16]
    prefix = (flag_prefix or "FLAG").strip() or "FLAG"
    return f"{prefix}{{{digest}}}"


def main() -> None:
    cfg = _read_config()
    seed = str(cfg.get("seed") or "").strip()
    node_name = str(cfg.get("node_name") or "").strip()
    flag_prefix = str(cfg.get("flag_prefix") or "FLAG").strip() or "FLAG"

    if not seed:
        raise SystemExit("Missing seed in /inputs/config.json")
    if not node_name:
        raise SystemExit("Missing node_name in /inputs/config.json")

    flag_value = _flag(seed, node_name, flag_prefix)

    # TODO: generate a per-node docker-compose.yml.
    compose_text = (
        "services:\n"
        "  node:\n"
        "    image: alpine:3.19\n"
        "    command: [\"sh\", \"-lc\", \"echo \\\"$FLAG\\\" > /flag.txt && tail -f /dev/null\"]\n"
        "    environment:\n"
        f"      FLAG: {json.dumps(flag_value)}\n"
    )

    out_dir = Path("/outputs")
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "docker-compose.yml").write_text(compose_text, encoding="utf-8")

    outputs = {
        "generator_id": "CHANGE_ME_PLUGIN_ID",
        "outputs": {
            "File(path)": "docker-compose.yml",
            "Flag(flag_id)": flag_value
        }
    }
    (out_dir / "outputs.json").write_text(json.dumps(outputs, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
