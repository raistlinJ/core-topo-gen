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


def _derive_private_ip(seed: str) -> str:
    # Deterministic, safe private-range IP from seed.
    digest = hashlib.sha256(seed.encode("utf-8", "replace")).digest()
    b1, b2, b3 = digest[0], digest[1], digest[2]
    return f"10.{b1}.{b2}.{b3}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Sample generator: emit a deterministic network.ip")
    ap.add_argument("--config", default=os.environ.get("CONFIG_PATH", ""))
    ap.add_argument("--seed", default=os.environ.get("SEED", ""))
    ap.add_argument("--out-dir", default=os.environ.get("OUT_DIR", "out"))
    args = ap.parse_args()

    cfg = _load_config(args.config)
    seed = str(args.seed or cfg.get("seed") or "seed")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    ip = _derive_private_ip(seed)

    # Optional “binary” artifact for debugging/realism (not required by Flow).
    bin_path = out_dir / "sample.bin"
    bin_path.write_bytes(b"SAMPLE" + ip.encode("utf-8") + b"\n")

    outputs = {
        "generator_id": str(cfg.get("generator_id") or "sample.binary_embed_text"),
        "outputs": {
            "network.ip": ip,
        },
    }

    (out_dir / "outputs.json").write_text(json.dumps(outputs, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(outputs, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
