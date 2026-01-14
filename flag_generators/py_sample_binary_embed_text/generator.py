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


def _build_c_source(*, flag_value: str, ip: str, input_sha256: str | None = None, input_name: str | None = None) -> str:
    # Keep the binary stable and simple: embed strings into .rodata without printing them.
    extra = ""
    if input_sha256:
        extra += "__attribute__((used)) static const char EMBEDDED_INPUT_SHA256[] = \"" + input_sha256.replace("\\", "\\\\").replace("\"", "\\\"") + "\";\n"
    if input_name:
        extra += "__attribute__((used)) static const char EMBEDDED_INPUT_NAME[] = \"" + input_name.replace("\\", "\\\\").replace("\"", "\\\"") + "\";\n"

    return (
        "#include <stdio.h>\n"
        "#include <stdint.h>\n"
        "\n"
        "__attribute__((used)) static const char EMBEDDED_FLAG[] = \"" + flag_value.replace("\\", "\\\\").replace("\"", "\\\"") + "\";\n"
        "__attribute__((used)) static const char EMBEDDED_IP[] = \"" + ip.replace("\\", "\\\\").replace("\"", "\\\"") + "\";\n"
        + extra +
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


def main() -> int:
    ap = argparse.ArgumentParser(description="Sample generator: emit a deterministic network.ip")
    ap.add_argument("--config", default=os.environ.get("CONFIG_PATH", ""))
    ap.add_argument("--seed", default=os.environ.get("SEED", ""))
    ap.add_argument("--flag-prefix", default=os.environ.get("FLAG_PREFIX", "FLAG"))
    ap.add_argument("--out-dir", default=os.environ.get("OUT_DIR", "out"))
    ap.add_argument("--bin-name", default=os.environ.get("BIN_NAME", "challenge"))
    ap.add_argument(
        "--skip-compile",
        action="store_true",
        default=str(os.environ.get("CORETG_SKIP_COMPILE", "")).strip().lower() in ("1", "true", "yes"),
        help="For tests/dev only: write a stub binary instead of invoking gcc.",
    )
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

    # Prefer config-provided name so callers can set per-node output filenames.
    # NOTE: `challenge` is a legacy alias kept for backward compatibility.
    cfg_bin = str(cfg.get("bin_name") or cfg.get("bin-name") or cfg.get("challenge") or "").strip()

    # Build an x86_64 ELF binary that contains the flag in .rodata.
    # NOTE: The compose service is pinned to linux/amd64 to ensure the compiler
    # produces an x64 binary even on ARM hosts.
    bin_name = (cfg_bin or str(args.bin_name or "challenge").strip() or "challenge").replace("/", "_")
    bin_path = artifacts_dir / bin_name

    # Optional input file: allow users/Flow to provide an arbitrary file under the inputs mount.
    # If present, we embed its sha256 so the produced binary varies even with a fixed seed.
    input_file_raw = str(
        cfg.get('input_file')
        or cfg.get('input-file')
        or cfg.get('input.path')
        or cfg.get('input_path')
        or ''
    ).strip()

    input_sha256: str | None = None
    input_name: str | None = None
    if input_file_raw:
        config_dir = Path(args.config).resolve().parent if args.config else None
        candidates: list[Path] = []
        if os.path.isabs(input_file_raw):
            candidates.append(Path(input_file_raw))
        else:
            rel = input_file_raw.lstrip('/').replace('\\', '/')
            if rel.startswith('inputs/'):
                rel = rel[len('inputs/'):]
            if config_dir is not None:
                candidates.append(config_dir / rel)
            candidates.append(out_dir / 'inputs' / rel)
            candidates.append(out_dir / rel)

        for cand in candidates:
            try:
                if cand.exists() and cand.is_file():
                    input_sha256 = _sha256_file(cand)
                    input_name = cand.name
                    break
            except Exception:
                continue

        if input_sha256 is None:
            # Fallback: treat the input value itself as content.
            input_sha256 = _sha256_bytes(input_file_raw.encode('utf-8', 'replace'))
            input_name = 'input_file'

    c_source = _build_c_source(flag_value=flag_value, ip=ip, input_sha256=input_sha256, input_name=input_name)

    if args.skip_compile:
        # For tests/dev environments without gcc.
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
            "network.ip": ip,
        },
    }

    if input_sha256:
        outputs.setdefault('inputs', {})
        outputs['inputs']['input_sha256'] = input_sha256
        if input_name:
            outputs['inputs']['input_name'] = input_name

    (out_dir / "outputs.json").write_text(json.dumps(outputs, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(outputs, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
