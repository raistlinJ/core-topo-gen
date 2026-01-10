import argparse
import base64
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


def _derive_key(seed: str, secret: str, length: int) -> bytes:
    # Expand deterministically using repeated SHA256 blocks.
    out = b""
    counter = 0
    while len(out) < length:
        h = hashlib.sha256(f"{seed}|{secret}|xor|{counter}".encode("utf-8")).digest()
        out += h
        counter += 1
    return out[:length]


def _derive_flag(seed: str, secret: str, generator_id: str, flag_prefix: str) -> str:
    base = f"{seed}|{secret}|{generator_id}".encode("utf-8", "replace")
    digest = hashlib.sha256(base).hexdigest()[:24]
    prefix = (flag_prefix or "FLAG").strip() or "FLAG"
    return f"{prefix}{{{digest}}}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an XOR key (deterministic).")
    parser.add_argument("--config", default=os.environ.get("CONFIG_PATH", ""))
    parser.add_argument("--seed", default=os.environ.get("SEED", ""))
    parser.add_argument("--secret", default=os.environ.get("SECRET", ""))
    parser.add_argument("--key-len", type=int, default=int(os.environ.get("KEY_LEN", "16")))
    parser.add_argument("--flag-prefix", default=os.environ.get("FLAG_PREFIX", "FLAG"))
    parser.add_argument("--out-dir", default=os.environ.get("OUT_DIR", "out"))
    args = parser.parse_args()

    cfg = _load_config(args.config)
    if not args.seed:
        args.seed = str(cfg.get("seed") or "")
    if not args.secret:
        args.secret = str(cfg.get("secret") or "")
    if args.key_len == 16:
        try:
            args.key_len = int(cfg.get("key_len") or cfg.get("key-len") or args.key_len)
        except Exception:
            pass
    if args.flag_prefix == "FLAG":
        args.flag_prefix = str(cfg.get("flag_prefix") or cfg.get("flag-prefix") or args.flag_prefix)

    if not args.seed:
        raise SystemExit("Missing --seed (or SEED env var)")
    if not args.secret:
        raise SystemExit("Missing --secret (or SECRET env var)")

    key_len = int(args.key_len or 16)
    if key_len < 1:
        key_len = 16
    if key_len > 64:
        key_len = 64

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    key = _derive_key(args.seed, args.secret, key_len)
    key_hex = key.hex()
    key_b64 = base64.b64encode(key).decode("ascii")

    flag_value = _derive_flag(args.seed, args.secret, "gen.py.xor", args.flag_prefix)

    artifact_path = out_dir / "xor_key.txt"
    artifact_path.write_text(key_hex + "\n", encoding="utf-8")

    outputs = {
        "generator_id": "gen.py.xor",
        "outputs": {
            "flag": flag_value,
            "xor_key_hex": key_hex,
            "xor_key_b64": key_b64,
            "xor_key_len": key_len,
            "artifact_path": str(artifact_path.resolve()),
        },
    }

    try:
        (out_dir / "flag.txt").write_text(flag_value + "\n", encoding="utf-8")
    except Exception:
        pass

    (out_dir / "outputs.json").write_text(json.dumps(outputs, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(outputs, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
