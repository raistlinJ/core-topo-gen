import json
import os
import sys
from pathlib import Path


def _load_generator_module():
    # Import the generator.py as a module without needing it to be a package.
    gen_path = Path(__file__).resolve().parents[1] / "flag_generators" / "py_sample_binary_embed_text" / "generator.py"
    assert gen_path.exists()

    import importlib.util

    spec = importlib.util.spec_from_file_location("sample_binary_embed_text_generator", gen_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_sample_binary_embed_text_outputs_and_optional_input_file(tmp_path: Path, monkeypatch):
    gen = _load_generator_module()

    out_dir = tmp_path / "out"
    inputs_dir = out_dir / "inputs"
    inputs_dir.mkdir(parents=True)

    # Create an optional input file under inputs/.
    (inputs_dir / "seed_material.txt").write_text("hello world\n", encoding="utf-8")

    cfg = {
        "seed": "seed-1",
        "flag_prefix": "FLAG",
        "bin_name": "challengeA",
        "input_file": "seed_material.txt",
        "generator_id": "sample.binary_embed_text",
    }
    config_path = inputs_dir / "config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")

    # Run in test mode: skip gcc compilation.
    monkeypatch.setenv("CORETG_SKIP_COMPILE", "1")

    argv0 = sys.argv[:]
    try:
        sys.argv = [
            "generator.py",
            "--config",
            str(config_path),
            "--out-dir",
            str(out_dir),
            "--bin-name",
            "challengeA",
        ]
        rc = gen.main()
        assert rc == 0
    finally:
        sys.argv = argv0

    manifest = out_dir / "outputs.json"
    assert manifest.exists()

    doc = json.loads(manifest.read_text("utf-8"))
    assert isinstance(doc, dict)
    outputs = doc.get("outputs")
    assert isinstance(outputs, dict)

    # Per catalog spec: must emit these outputs.
    assert isinstance(outputs.get("flag"), str) and outputs["flag"].startswith("FLAG{")
    assert outputs.get("network.ip", "").startswith("10.")
    assert outputs.get("filesystem.file") == "artifacts/challengeA"

    # And the injected artifact must exist at the referenced path.
    bin_path = out_dir / "artifacts" / "challengeA"
    assert bin_path.exists()


def test_sample_binary_embed_text_binary_changes_with_seed(tmp_path: Path, monkeypatch):
    gen = _load_generator_module()

    def run(seed: str) -> bytes:
        out_dir = tmp_path / f"out_{seed}"
        inputs_dir = out_dir / "inputs"
        inputs_dir.mkdir(parents=True)
        cfg = {
            "seed": seed,
            "flag_prefix": "FLAG",
            "bin_name": "challenge",
            "generator_id": "sample.binary_embed_text",
        }
        config_path = inputs_dir / "config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")

        monkeypatch.setenv("CORETG_SKIP_COMPILE", "1")
        argv0 = sys.argv[:]
        try:
            sys.argv = [
                "generator.py",
                "--config",
                str(config_path),
                "--out-dir",
                str(out_dir),
                "--bin-name",
                "challenge",
            ]
            rc = gen.main()
            assert rc == 0
        finally:
            sys.argv = argv0

        return (out_dir / "artifacts" / "challenge").read_bytes()

    b1 = run("seed-1")
    b2 = run("seed-2")
    assert b1 != b2
