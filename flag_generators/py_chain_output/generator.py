import argparse
import hashlib
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


def _handoff(challenge: str) -> str:
    return hashlib.sha256(challenge.encode("utf-8")).hexdigest()[:32]


def main() -> int:
    parser = argparse.ArgumentParser(description="Produce a handoff token for subsequent flow steps.")
    parser.add_argument("--config", default=os.environ.get("CONFIG_PATH", ""))
    parser.add_argument("--challenge", default=os.environ.get("CHALLENGE", ""))
    parser.add_argument("--out-dir", default=os.environ.get("OUT_DIR", "out"))
    args = parser.parse_args()

    cfg = _load_config(args.config)
    if not args.challenge:
        args.challenge = str(cfg.get("challenge") or "")

    if not args.challenge:
        raise SystemExit("Missing --challenge (or CHALLENGE env var)")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    token = _handoff(args.challenge)

    outputs = {
        "generator_id": "gen.py.chain_output",
        "outputs": {
            "handoff_token": token,
        },
    }

    outputs_path = out_dir / "outputs.json"
    outputs_path.write_text(json.dumps(outputs, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(outputs, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
