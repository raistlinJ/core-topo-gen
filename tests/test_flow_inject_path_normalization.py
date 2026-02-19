import json
import xml.etree.ElementTree as ET

from webapp import app_backend as backend


def _sample_assignment() -> dict:
    artifacts_dir = "/tmp/vulns/flag_generators_runs/flow-newscenario1/01_binary_embed_text_docker-3/artifacts"
    resolved_file_path = f"{artifacts_dir}/challenge_cf7c967dd5"
    return {
        "node_id": "docker-3",
        "id": "binary_embed_text",
        "artifacts_dir": artifacts_dir,
        "inject_source_dir": artifacts_dir,
        "run_dir": "/tmp/vulns/flag_generators_runs/flow-newscenario1/01_binary_embed_text_docker-3",
        "resolved_outputs": {
            "File(path)": resolved_file_path,
        },
        "resolved_paths": {
            "artifacts_dir": {
                "path": artifacts_dir,
                "is_remote": False,
            },
            "inject_source_dir": {
                "path": artifacts_dir,
                "is_remote": False,
            },
            "inject_sources": [
                {
                    "path": "/tmp/vulns/flag_generators_runs/flow-newscenario1/01_binary_embed_text_docker-3/File(path)",
                    "is_remote": False,
                }
            ],
        },
    }


def test_enrich_flow_state_normalizes_symbolic_inject_source_path() -> None:
    flow_state = {
        "flag_assignments": [_sample_assignment()],
    }

    enriched = backend._enrich_flow_state_with_artifacts(flow_state)
    assignments = enriched.get("flag_assignments") if isinstance(enriched, dict) else None
    assert isinstance(assignments, list) and assignments

    first = assignments[0]
    resolved = first.get("resolved_paths") if isinstance(first, dict) else None
    inject_sources = resolved.get("inject_sources") if isinstance(resolved, dict) else None
    assert isinstance(inject_sources, list) and inject_sources

    inject_path = str((inject_sources[0] or {}).get("path") or "")
    assert inject_path.endswith("/challenge_cf7c967dd5")
    assert "File(path)" not in inject_path


def test_update_flow_state_xml_persists_normalized_inject_source_path(tmp_path) -> None:
    scenario_name = "NewScenario1"
    xml_path = tmp_path / "scenario.xml"
    xml_path.write_text(
        f"<Scenarios><Scenario name=\"{scenario_name}\"><ScenarioEditor/></Scenario></Scenarios>",
        encoding="utf-8",
    )

    flow_state = {
        "scenario": scenario_name,
        "flag_assignments": [_sample_assignment()],
    }
    enriched = backend._enrich_flow_state_with_artifacts(flow_state)

    ok, err = backend._update_flow_state_in_xml(str(xml_path), scenario_name, enriched)
    assert ok, err

    tree = ET.parse(str(xml_path))
    root = tree.getroot()
    flow_state_el = root.find("./Scenario/ScenarioEditor/FlagSequencing/FlowState")
    assert flow_state_el is not None and (flow_state_el.text or "").strip()

    persisted = json.loads(flow_state_el.text)
    assignments = persisted.get("flag_assignments") if isinstance(persisted, dict) else None
    assert isinstance(assignments, list) and assignments

    resolved = assignments[0].get("resolved_paths") if isinstance(assignments[0], dict) else None
    inject_sources = resolved.get("inject_sources") if isinstance(resolved, dict) else None
    assert isinstance(inject_sources, list) and inject_sources

    inject_path = str((inject_sources[0] or {}).get("path") or "")
    assert inject_path.endswith("/challenge_cf7c967dd5")
    assert "File(path)" not in inject_path


def test_update_flow_state_xml_backfills_inject_files_from_manifest(tmp_path) -> None:
    scenario_name = "NewScenario1"
    xml_path = tmp_path / "scenario.xml"
    xml_path.write_text(
        f"<Scenarios><Scenario name=\"{scenario_name}\"><ScenarioEditor/></Scenario></Scenarios>",
        encoding="utf-8",
    )

    # Simulate a FlowState payload where inject_files was persisted as an empty list.
    flow_state = {
        "scenario": scenario_name,
        "flag_assignments": [
            {
                "node_id": "6",
                "id": "textfile_username_password",
                "inject_files": [],
            }
        ],
    }

    ok, err = backend._update_flow_state_in_xml(str(xml_path), scenario_name, flow_state)
    assert ok, err

    tree = ET.parse(str(xml_path))
    root = tree.getroot()
    flow_state_el = root.find("./Scenario/ScenarioEditor/FlagSequencing/FlowState")
    assert flow_state_el is not None and (flow_state_el.text or "").strip()

    persisted = json.loads(flow_state_el.text)
    assigns = persisted.get("flag_assignments") if isinstance(persisted, dict) else None
    assert isinstance(assigns, list) and assigns
    inj = assigns[0].get("inject_files") if isinstance(assigns[0], dict) else None
    assert inj == ["File(path)"], inj
