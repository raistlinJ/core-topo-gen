import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path


def _sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def _sha256_file(path: Path, *, max_bytes: int = 5_000_000) -> str:
    h = hashlib.sha256()
    remaining = max(0, int(max_bytes))
    with path.open('rb') as f:
        while True:
            if remaining <= 0:
                break
            chunk = f.read(min(1024 * 64, remaining))
            if not chunk:
                break
            h.update(chunk)
            remaining -= len(chunk)
    return h.hexdigest()


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


def _derive_flag(seed: str, generator_id: str, flag_prefix: str | None = None) -> str:
    base = f"{seed}|{generator_id}".encode("utf-8", "replace")
    digest = hashlib.sha256(base).hexdigest()[:24]
    prefix = (flag_prefix or "FLAG").strip() or "FLAG"
    return f"{prefix}{{{digest}}}"


def _derive_filename(seed: str) -> str:
    # Deterministic but "random-looking" name for scenarios.
    digest = hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()[:10]
    return f"challenge_{digest}"


def _build_c_source(*, flag_value: str) -> str:
    # Keep the binary stable and simple: embed strings into .rodata without printing them.
    return (
        "#include <stdio.h>\n"
        "#include <stdint.h>\n"
        "\n"
        "__attribute__((used)) static const char EMBEDDED_FLAG[] = \"" + flag_value.replace("\\", "\\\\").replace("\"", "\\\"") + "\";\n"
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
        "  uint64_t h = fnv1a64(EMBEDDED_FLAG);\n"
        "  printf(\"ok:%016llx\\n\", (unsigned long long)h);\n"
        "  return 0;\n"
        "}\n"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Sample generator: produce an x64 binary with an embedded flag")
    ap.add_argument("--config", default=os.environ.get("CONFIG_PATH", ""))
    ap.add_argument("--seed", default=os.environ.get("SEED", ""))
    ap.add_argument("--out-dir", default=os.environ.get("OUT_DIR", "out"))
    ap.add_argument("--bin-name", default=os.environ.get("BIN_NAME", ""), help="Optional output binary filename")
    ap.add_argument(
        "--skip-compile",
        action="store_true",
        default=str(os.environ.get("CORETG_SKIP_COMPILE", "")).strip().lower() in ("1", "true", "yes"),
        help="For tests/dev only: write a stub binary instead of invoking gcc.",
    )
    args = ap.parse_args()

    cfg = _load_config(args.config)
    seed = str(args.seed or cfg.get("seed") or "seed")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    artifacts_dir = out_dir / 'artifacts'
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    generator_id = str(cfg.get("generator_id") or "sample.binary_embed_text")
    cfg_flag = str(cfg.get("flag") or "").strip()
    flag_value = cfg_flag or _derive_flag(seed, generator_id, os.environ.get("FLAG_PREFIX", "FLAG"))

    # Inputs:
    # - filename (preferred)
    # - bin_name/bin-name (legacy)
    cfg_filename = str(
        cfg.get("filename")
        or cfg.get("bin_name")
        or cfg.get("bin-name")
        or ""
    ).strip()

    # Build an x86_64 ELF binary that contains the flag in .rodata.
    # NOTE: The compose service is pinned to linux/amd64 to ensure the compiler
    # produces an x64 binary even on ARM hosts.
    default_name = _derive_filename(seed)
    bin_name = (cfg_filename or str(args.bin_name or "").strip() or default_name).replace("/", "_")
    bin_path = artifacts_dir / bin_name

    c_source = _build_c_source(flag_value=flag_value)

    if args.skip_compile:
        # For tests/dev environments without gcc.
        # Keep it easy to validate via strings(): include the literal flag.
        bin_path.write_bytes(b"CORETG_STUB_BINARY\n" + c_source.encode('utf-8', 'replace'))
        try:
            os.chmod(bin_path, 0o755)
        except Exception:
            pass
    else:
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
        },
    }

    (out_dir / "outputs.json").write_text(json.dumps(outputs, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(outputs, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
