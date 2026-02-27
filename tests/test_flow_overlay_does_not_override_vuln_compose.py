from core_topo_gen.builders.topology import _flow_flag_artifacts_overlay_from_host_metadata


def test_flow_flag_generator_overlay_does_not_override_vuln_record_fields():
    # Simulate a host with Flow flag-generator metadata.
    hdata = {
        "metadata": {
            "flow_flag": {
                "type": "flag-generator",
                "artifacts_dir": "/tmp/vulns/flag_generators_runs/flow-x/01_gen/artifacts",
                "mount_path": "/flow_artifacts",
                "inject_files": ["File(path)"],
                "outputs_manifest": "outputs.json",
                "run_dir": "/tmp/vulns/flag_generators_runs/flow-x/01_gen",
            }
        }
    }

    overlay = _flow_flag_artifacts_overlay_from_host_metadata(hdata)
    assert overlay is not None
    assert overlay["ArtifactsMountPath"] == "/flow_artifacts"

    # Base vuln compose record (what docker_slot_plan should supply).
    vuln_rec = {
        "Type": "docker-compose",
        "Name": "airflow/CVE-2020-11981",
        "Path": "/tmp/vulns/catalog/vulhub/airflow/CVE-2020-11981/docker-compose.yml",
        "Vector": "vuln",
    }

    merged = {**vuln_rec, **overlay}

    # Ensure we kept vuln identity and only overlaid artifacts/inject fields.
    assert merged["Name"] == "airflow/CVE-2020-11981"
    assert merged["Path"].endswith("/airflow/CVE-2020-11981/docker-compose.yml")
    assert merged["Vector"] == "vuln"
    assert merged["ArtifactsDir"]
