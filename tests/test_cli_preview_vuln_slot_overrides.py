from core_topo_gen.cli import _merge_vuln_slot_assignments_with_preview, _preview_vuln_slot_overrides


def test_preview_vuln_slot_overrides_maps_airflow_to_slot_1():
    preview_full = {
        "hosts": [
            {"node_id": 6, "name": "docker-1"},
            {"node_id": 7, "name": "docker-2"},
            {"node_id": 8, "name": "docker-3"},
        ],
        "vulnerabilities_by_node": {
            "6": ["airflow/CVE-2020-11981"],
        },
    }

    vuln_items = [
        {
            "selected": "Specific",
            "v_name": "airflow/CVE-2020-11981",
            "v_path": "outputs/installed_vuln_catalogs/20260115-183504-10474c/content/vulhub/airflow/CVE-2020-11981/docker-compose.yml",
            "v_vector": "",
            "v_metric": "Count",
            "v_count": "1",
        }
    ]

    slot_names = ["slot-1", "slot-2", "slot-3"]
    overrides = _preview_vuln_slot_overrides(
        preview_full,
        vuln_items=vuln_items,
        catalog=[],
        slot_names=slot_names,
    )

    assert "slot-1" in overrides
    rec = overrides["slot-1"]
    assert rec["Type"] == "docker-compose"
    assert rec["Name"] == "airflow/CVE-2020-11981"
    assert rec["Path"].endswith("/airflow/CVE-2020-11981/docker-compose.yml")


def test_merge_preview_overrides_replaces_non_preview_slots_when_map_exists():
    preview_full = {
        "hosts": [
            {"node_id": 6, "name": "workstation-1"},
            {"node_id": 7, "name": "docker-1"},
        ],
        "vulnerabilities_by_node": {
            "7": ["airflow/CVE-2020-11981"],
        },
    }

    assignments_slots = {
        "slot-1": {"Type": "docker-compose", "Name": "unexpected/CVE", "Path": "/tmp/unexpected.yml", "Vector": ""},
        "slot-2": {"Type": "docker-compose", "Name": "other/CVE", "Path": "/tmp/other.yml", "Vector": ""},
    }
    overrides = {
        "slot-2": {
            "Type": "docker-compose",
            "Name": "airflow/CVE-2020-11981",
            "Path": "/tmp/airflow.yml",
            "Vector": "",
        }
    }

    merged = _merge_vuln_slot_assignments_with_preview(
        assignments_slots,
        overrides=overrides,
        preview_full=preview_full,
    )

    assert list(merged.keys()) == ["slot-2"]
    assert merged["slot-2"]["Name"] == "airflow/CVE-2020-11981"
