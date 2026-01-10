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


def _derive_user_pass(seed: str) -> tuple[str, str]:
    h = hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()
    user = f"user_{h[:6]}"
    pw = f"pw_{h[6:14]}"
    return user, pw


def _derive_flag(seed: str, generator_id: str, flag_prefix: str) -> str:
    base = f"{seed}|{generator_id}".encode("utf-8", "replace")
    digest = hashlib.sha256(base).hexdigest()[:24]
    prefix = (flag_prefix or "FLAG").strip() or "FLAG"
    return f"{prefix}{{{digest}}}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Sample generator: emit a filesystem.file containing creds")
    ap.add_argument("--config", default=os.environ.get("CONFIG_PATH", ""))
    ap.add_argument("--seed", default=os.environ.get("SEED", ""))
    ap.add_argument("--flag-prefix", default=os.environ.get("FLAG_PREFIX", "FLAG"))
    ap.add_argument("--out-dir", default=os.environ.get("OUT_DIR", "out"))
    args = ap.parse_args()

    cfg = _load_config(args.config)
    seed = str(args.seed or cfg.get("seed") or "seed")
    flag_prefix = str(args.flag_prefix or cfg.get("flag_prefix") or cfg.get("flag-prefix") or "FLAG")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    user, pw = _derive_user_pass(seed)
    generator_id = str(cfg.get("generator_id") or "sample.textfile_username_password")
    flag_value = _derive_flag(seed, generator_id, flag_prefix)
    secrets_path = out_dir / "secrets.txt"
    secrets_path.write_text(f"username={user}\npassword={pw}\n", encoding="utf-8")

    outputs = {
        "generator_id": generator_id,
        "outputs": {
            "flag": flag_value,
            "filesystem.file": str(secrets_path.name),
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
