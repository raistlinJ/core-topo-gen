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


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate SSH username/password credentials.")
    parser.add_argument("--config", default=os.environ.get("CONFIG_PATH", ""))
    parser.add_argument("--seed", default=os.environ.get("SEED", ""))
    parser.add_argument("--secret", default=os.environ.get("SECRET", ""))
    parser.add_argument("--username-prefix", default=os.environ.get("USERNAME_PREFIX", "sshuser"))
    parser.add_argument("--out-dir", default=os.environ.get("OUT_DIR", "out"))
    args = parser.parse_args()

    cfg = _load_config(args.config)
    if not args.seed:
        args.seed = str(cfg.get("seed") or "")
    if not args.secret:
        args.secret = str(cfg.get("secret") or "")
    if args.username_prefix == "sshuser":
        args.username_prefix = str(cfg.get("username_prefix") or cfg.get("username-prefix") or args.username_prefix)

    if not args.seed:
        raise SystemExit("Missing --seed (or SEED env var)")
    if not args.secret:
        raise SystemExit("Missing --secret (or SECRET env var)")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    digest = _h(args.seed, args.secret, "ssh-creds")
    username = f"{args.username_prefix}{digest[:6]}"
    # Make a reasonably complex deterministic password.
    password = f"P@{digest[6:18]}!{digest[18:22]}"

    creds = {
        "username": username,
        "password": password,
    }

    artifact_path = out_dir / "ssh_creds.json"
    artifact_path.write_text(json.dumps(creds, indent=2) + "\n", encoding="utf-8")

    outputs = {
        "generator_id": "gen.py.ssh_creds",
        "outputs": {
            "ssh_username": username,
            "ssh_password": password,
            "artifact_path": str(artifact_path.resolve()),
        },
    }

    (out_dir / "outputs.json").write_text(json.dumps(outputs, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(outputs, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
