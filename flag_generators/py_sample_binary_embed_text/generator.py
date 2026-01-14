import argparse
import hashlib
import json
import os
import subprocess
import tempfile
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


def _derive_flag(seed: str, generator_id: str, flag_prefix: str) -> str:
    base = f"{seed}|{generator_id}".encode("utf-8", "replace")
    digest = hashlib.sha256(base).hexdigest()[:24]
    prefix = (flag_prefix or "FLAG").strip() or "FLAG"
    return f"{prefix}{{{digest}}}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Sample generator: emit a deterministic network.ip")
    ap.add_argument("--config", default=os.environ.get("CONFIG_PATH", ""))
    ap.add_argument("--seed", default=os.environ.get("SEED", ""))
    ap.add_argument("--flag-prefix", default=os.environ.get("FLAG_PREFIX", "FLAG"))
    ap.add_argument("--out-dir", default=os.environ.get("OUT_DIR", "out"))
    ap.add_argument("--bin-name", default=os.environ.get("BIN_NAME", "challenge"))
    args = ap.parse_args()

    cfg = _load_config(args.config)
    seed = str(args.seed or cfg.get("seed") or "seed")
    flag_prefix = str(args.flag_prefix or cfg.get("flag_prefix") or cfg.get("flag-prefix") or "FLAG")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    artifacts_dir = out_dir / 'artifacts'
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    ip = _derive_private_ip(seed)
    generator_id = str(cfg.get("generator_id") or "sample.binary_embed_text")
    flag_value = _derive_flag(seed, generator_id, flag_prefix)

    # Prefer config-provided name so Flow can set per-node filenames.
    # (Flow passes a `challenge` value by default.)
    cfg_bin = str(cfg.get("challenge") or cfg.get("bin_name") or cfg.get("bin-name") or "").strip()

    # Build an x86_64 ELF binary that contains the flag in .rodata.
    # NOTE: The compose service is pinned to linux/amd64 to ensure the compiler
    # produces an x64 binary even on ARM hosts.
    bin_name = (cfg_bin or str(args.bin_name or "challenge").strip() or "challenge").replace("/", "_")
    bin_path = artifacts_dir / bin_name
    c_source = (
        "#include <stdio.h>\n"
        "#include <stdint.h>\n"
        "\n"
        "__attribute__((used)) static const char EMBEDDED_FLAG[] = \"" + flag_value.replace("\\", "\\\\").replace("\"", "\\\"") + "\";\n"
        "__attribute__((used)) static const char EMBEDDED_IP[] = \"" + ip.replace("\\", "\\\\").replace("\"", "\\\"") + "\";\n"
        "\n"
        "static uint64_t fnv1a64(const char* s) {\n"
        "  const uint64_t FNV_OFFSET = 1469598103934665603ULL;\n"
        "  const uint64_t FNV_PRIME  = 1099511628211ULL;\n"
        "  uint64_t h = FNV_OFFSET;\n"
        "  if(!s) return h;\n"
        "  for(const unsigned char* p = (const unsigned char*)s; *p; p++){\n"
        "    h ^= (uint64_t)(*p);\n"
        "    h *= FNV_PRIME;\n"
        "  }\n"
        "  return h;\n"
        "}\n"
        "\n"
        "int main(int argc, char** argv) {\n"
        "  (void)argc; (void)argv;\n"
        "  // Decoy output: does NOT print the flag.\n"
        "  uint64_t h = fnv1a64(EMBEDDED_IP);\n"
        "  printf(\"ok:%016llx\\n\", (unsigned long long)h);\n"
        "  return 0;\n"
        "}\n"
    )

    try:
        with tempfile.TemporaryDirectory(prefix="coretg_bin_") as td:
            src_path = Path(td) / "challenge.c"
            src_path.write_text(c_source, encoding="utf-8")
            cmd = [
                "gcc",
                "-O2",
                "-s",
                "-fno-asynchronous-unwind-tables",
                "-fno-unwind-tables",
                "-o",
                str(bin_path),
                str(src_path),
            ]
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            os.chmod(bin_path, 0o755)
        except Exception:
            pass
    except subprocess.CalledProcessError as e:
        # Make it easy to debug in generator logs.
        raise SystemExit(f"Failed to compile embedded flag binary: {e.stderr or e.stdout or e}")
    except Exception as e:
        raise SystemExit(f"Failed to compile embedded flag binary: {e}")

    outputs = {
        "generator_id": generator_id,
        "outputs": {
            "flag": flag_value,
            "filesystem.file": f"artifacts/{bin_name}",
            "network.ip": ip,
        },
    }

    (out_dir / "outputs.json").write_text(json.dumps(outputs, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(outputs, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
