import json
from pathlib import Path

from scripts import run_flag_generator as rfg


def test_inject_files_can_reference_output_artifact_key(tmp_path: Path):
    out_dir = tmp_path
    (out_dir / "artifacts").mkdir(parents=True, exist_ok=True)

    # Simulate a generator output file.
    (out_dir / "artifacts" / "challenge").write_text("bin", encoding="utf-8")

    (out_dir / "outputs.json").write_text(
        json.dumps({"outputs": {"filesystem.file": "artifacts/challenge"}}),
        encoding="utf-8",
    )

    expanded = rfg.expand_inject_files_from_outputs(out_dir, ["filesystem.file"])
    assert expanded == ["artifacts/challenge"]

    injected_dir = rfg._stage_injected_dir(out_dir, expanded)
    assert injected_dir is not None
    assert (injected_dir / "challenge").exists()
