from pathlib import Path


def test_flow_flag_record_from_host_metadata_flag_node_generator(tmp_path: Path):
    from core_topo_gen.builders.topology import _flow_flag_record_from_host_metadata

    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    compose_path = run_dir / "docker-compose.yml"
    compose_path.write_text("services:\n  node:\n    image: alpine:3.19\n", encoding="utf-8")

    hdata = {
        "metadata": {
            "flow_flag": {
                "type": "flag-node-generator",
                "generator_id": "nfs_sensitive_file",
                "generator_name": "Sample: NFS Sensitive File",
                "run_dir": str(run_dir),
            }
        }
    }
    rec = _flow_flag_record_from_host_metadata(hdata)
    assert isinstance(rec, dict)
    assert rec.get("Type") == "docker-compose"
    assert rec.get("Path") == str(compose_path)
