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


def _h(seed: str, secret: str, label: str) -> str:
    base = f"{seed}|{secret}|{label}".encode("utf-8")
    return hashlib.sha256(base).hexdigest()


def _derive_flag(seed: str, secret: str, generator_id: str, flag_prefix: str) -> str:
    base = f"{seed}|{secret}|{generator_id}".encode("utf-8", "replace")
    digest = hashlib.sha256(base).hexdigest()[:24]
    prefix = (flag_prefix or "FLAG").strip() or "FLAG"
    return f"{prefix}{{{digest}}}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate web username/password credentials.")
    parser.add_argument("--config", default=os.environ.get("CONFIG_PATH", ""))
    parser.add_argument("--seed", default=os.environ.get("SEED", ""))
    parser.add_argument("--secret", default=os.environ.get("SECRET", ""))
    parser.add_argument("--username-prefix", default=os.environ.get("USERNAME_PREFIX", "webuser"))
    parser.add_argument("--flag-prefix", default=os.environ.get("FLAG_PREFIX", "FLAG"))
    parser.add_argument("--out-dir", default=os.environ.get("OUT_DIR", "out"))
    args = parser.parse_args()

    cfg = _load_config(args.config)
    if not args.seed:
        args.seed = str(cfg.get("seed") or "")
    if not args.secret:
        args.secret = str(cfg.get("secret") or "")
    if args.username_prefix == "webuser":
        args.username_prefix = str(cfg.get("username_prefix") or cfg.get("username-prefix") or args.username_prefix)
    if args.flag_prefix == "FLAG":
        args.flag_prefix = str(cfg.get("flag_prefix") or cfg.get("flag-prefix") or args.flag_prefix)

    if not args.seed:
        raise SystemExit("Missing --seed (or SEED env var)")
    if not args.secret:
        raise SystemExit("Missing --secret (or SECRET env var)")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    digest = _h(args.seed, args.secret, "web-creds")
    username = f"{args.username_prefix}{digest[:6]}"
    password = f"W@{digest[6:18]}!{digest[18:22]}"

    flag_value = _derive_flag(args.seed, args.secret, "gen.py.web_creds", args.flag_prefix)

    creds = {
        "username": username,
        "password": password,
    }

    artifact_path = out_dir / "web_creds.json"
    artifact_path.write_text(json.dumps(creds, indent=2) + "\n", encoding="utf-8")

    outputs = {
        "generator_id": "gen.py.web_creds",
        "outputs": {
            "flag": flag_value,
            "web_username": username,
            "web_password": password,
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
