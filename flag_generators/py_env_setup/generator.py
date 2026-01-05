import argparse
import json
import os
from pathlib import Path


def _load_config(path: str) -> dict:
    if not path:
        return {}
    try:
        p = Path(path)
        if not p.exists():
            return {}
        data = json.loads(p.read_text("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Set up an environment directory with starter files.")
    parser.add_argument("--config", default=os.environ.get("CONFIG_PATH", ""))
    parser.add_argument("--env-name", default=os.environ.get("ENV_NAME", ""))
    parser.add_argument("--base-dir", default=os.environ.get("OUT_DIR", "out"))
    args = parser.parse_args()

    cfg = _load_config(args.config)
    if not args.env_name:
        args.env_name = str(cfg.get("env_name") or cfg.get("env-name") or "")

    if not args.env_name:
        raise SystemExit("Missing --env-name (or ENV_NAME env var)")

    base_dir = Path(args.base_dir)
    base_dir.mkdir(parents=True, exist_ok=True)

    env_dir = base_dir / args.env_name
    env_dir.mkdir(parents=True, exist_ok=True)

    (env_dir / "README.txt").write_text(
        "Environment initialized by Flag-Generator.\n"
        "This directory can be used by later tasks/flow steps.\n",
        encoding="utf-8",
    )
    (env_dir / ".env").write_text("# Placeholder env file\n", encoding="utf-8")

    outputs = {
        "generator_id": "gen.py.env_setup",
        "outputs": {
            "env_dir": str(env_dir.resolve()),
        },
    }

    outputs_path = base_dir / "outputs.json"
    outputs_path.write_text(json.dumps(outputs, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(outputs, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
