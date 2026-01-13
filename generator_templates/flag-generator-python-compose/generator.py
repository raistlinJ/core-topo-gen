import hashlib
import json
from pathlib import Path


def _read_config() -> dict:
    try:
        return json.loads(Path("/inputs/config.json").read_text("utf-8"))
    except Exception:
        return {}


def _flag(seed: str, secret: str, flag_prefix: str = "FLAG") -> str:
    digest = hashlib.sha256(f"{seed}|{secret}|flag".encode("utf-8", "replace")).hexdigest()[:24]
    prefix = (flag_prefix or "FLAG").strip() or "FLAG"
    return f"{prefix}{{{digest}}}"


def main() -> None:
    cfg = _read_config()
    seed = str(cfg.get("seed") or "").strip()
    secret = str(cfg.get("secret") or "").strip()
    flag_prefix = str(cfg.get("flag_prefix") or "FLAG").strip() or "FLAG"

    if not seed:
        raise SystemExit("Missing seed in /inputs/config.json")
    if not secret:
        raise SystemExit("Missing secret in /inputs/config.json")

    # TODO: implement your challenge logic and additional outputs.
    flag_value = _flag(seed, secret, flag_prefix)
    outputs = {
        "generator_id": "CHANGE_ME_PLUGIN_ID",
        "outputs": {
            "flag": flag_value,
            "example": "replace-me",
        },
    }

    out_dir = Path("/outputs")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "outputs.json").write_text(json.dumps(outputs, indent=2) + "\n", encoding="utf-8")
    (out_dir / "hint.txt").write_text("TODO: write a next-step hint here\n", encoding="utf-8")


if __name__ == "__main__":
    main()
