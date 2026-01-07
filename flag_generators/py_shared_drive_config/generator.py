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


def _h(*parts: str) -> str:
    base = "|".join(parts).encode("utf-8")
    return hashlib.sha256(base).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate shared network drive configuration info.")
    parser.add_argument("--config", default=os.environ.get("CONFIG_PATH", ""))
    parser.add_argument("--seed", default=os.environ.get("SEED", ""))
    parser.add_argument("--secret", default=os.environ.get("SECRET", ""))
    parser.add_argument("--env-name", default=os.environ.get("ENV_NAME", ""))
    parser.add_argument("--out-dir", default=os.environ.get("OUT_DIR", "out"))
    args = parser.parse_args()

    cfg = _load_config(args.config)
    if not args.seed:
        args.seed = str(cfg.get("seed") or "")
    if not args.secret:
        args.secret = str(cfg.get("secret") or "")
    if not args.env_name:
        args.env_name = str(cfg.get("env_name") or cfg.get("env-name") or "")

    if not args.seed:
        raise SystemExit("Missing --seed (or SEED env var)")
    if not args.secret:
        raise SystemExit("Missing --secret (or SECRET env var)")
    if not args.env_name:
        raise SystemExit("Missing --env-name (or ENV_NAME env var)")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    digest = _h(args.seed, args.secret, args.env_name, "shared-drive")

    # Keep this generic: it's "config info" only.
    share_host = "fileserver"
    share_name = f"share_{digest[:8]}"
    share_path = f"/srv/{share_name}"
    mount_point = f"/mnt/{share_name}"

    drive_username = f"drive{digest[8:14]}"
    drive_password = f"D@{digest[14:26]}!{digest[26:30]}"

    cfg_out = {
        "share_host": share_host,
        "share_name": share_name,
        "share_path": share_path,
        "mount_point": mount_point,
        "username": drive_username,
        "password": drive_password,
        "protocol": "smb",
    }

    artifact_path = out_dir / "shared_drive_config.json"
    artifact_path.write_text(json.dumps(cfg_out, indent=2) + "\n", encoding="utf-8")

    outputs = {
        "generator_id": "gen.py.shared_drive_config",
        "outputs": {
            "drive_share_host": share_host,
            "drive_share_name": share_name,
            "drive_share_path": share_path,
            "drive_mount_point": mount_point,
            "drive_username": drive_username,
            "drive_password": drive_password,
            "artifact_path": str(artifact_path.resolve()),
        },
    }

    (out_dir / "outputs.json").write_text(json.dumps(outputs, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(outputs, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
