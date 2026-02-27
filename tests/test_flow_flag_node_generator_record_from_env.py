import json
import os
from pathlib import Path


def test_flow_flag_record_from_env_flag_node_generator(tmp_path: Path, monkeypatch):
    from core_topo_gen.builders.topology import _flow_flag_record_from_host_metadata

    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    compose_path = run_dir / "docker-compose.yml"
    compose_path.write_text("services:\n  node:\n    image: ubuntu:22.04\n", encoding="utf-8")

    # No metadata.flow_flag, only env-provided assignment.
    monkeypatch.setenv(
        "CORETG_FLOW_ASSIGNMENTS_JSON",
        json.dumps(
            [
                {
                    "node_id": "5",
                    "type": "flag-node-generator",
                    "generator_id": "nfs_sensitive_file",
                    "generator_name": "Sample: NFS Sensitive File",
                    "run_dir": str(run_dir),
                }
            ]
        ),
    )

    rec = _flow_flag_record_from_host_metadata({"node_id": "5", "metadata": {}})
    assert isinstance(rec, dict)
    assert rec.get("Type") == "docker-compose"
    assert rec.get("Path") == str(compose_path)
