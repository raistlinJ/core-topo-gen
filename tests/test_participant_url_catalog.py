import json
from pathlib import Path

import pytest


@pytest.fixture()
def tmp_repo_root(tmp_path, monkeypatch):
    # Import lazily so monkeypatching module globals works.
    import webapp.app_backend as backend

    repo = tmp_path / "repo"
    repo.mkdir(parents=True, exist_ok=True)

    # Force outputs dir under our temp repo.
    monkeypatch.setattr(backend, "_REPO_ROOT", str(repo))
    return repo


def test_merge_participant_urls_allows_clear(tmp_repo_root):
    import webapp.app_backend as backend

    outputs_dir = Path(backend._outputs_dir())
    outputs_dir.mkdir(parents=True, exist_ok=True)

    catalog_path = Path(backend._scenario_catalog_file())
    catalog = {
        "names": ["Scenario 1b"],
        "sources": [""],
        "updated_at": "2020-01-01T00:00:00Z",
        "participant_urls": {
            "scenario 1b": "https://old.example:8006",
        },
    }
    catalog_path.write_text(json.dumps(catalog, indent=2), encoding="utf-8")

    # Clear the URL hint
    backend._merge_participant_urls_into_scenario_catalog({"Scenario 1b": ""})

    _names, _paths, hints = backend._load_scenario_catalog_from_disk()
    assert "scenario 1b" in hints
    assert hints["scenario 1b"] == ""


def test_merge_participant_urls_updates_value(tmp_repo_root):
    import webapp.app_backend as backend

    outputs_dir = Path(backend._outputs_dir())
    outputs_dir.mkdir(parents=True, exist_ok=True)

    catalog_path = Path(backend._scenario_catalog_file())
    catalog = {
        "names": ["Scenario 1b"],
        "sources": [""],
        "updated_at": "2020-01-01T00:00:00Z",
    }
    catalog_path.write_text(json.dumps(catalog, indent=2), encoding="utf-8")

    backend._merge_participant_urls_into_scenario_catalog({"Scenario 1b": "https://pve.example:8006"})

    _names, _paths, hints = backend._load_scenario_catalog_from_disk()
    assert hints.get("scenario 1b")


def test_collect_participant_urls_prefers_cleared_hint_over_xml(tmp_repo_root):
        import webapp.app_backend as backend

        # Create a scenario XML that contains a participant URL.
        scen_dir = Path(backend._outputs_dir()) / "scenarios"
        scen_dir.mkdir(parents=True, exist_ok=True)
        scen_path = scen_dir / "Scenario_1b.xml"
        scen_path.write_text(
                """<?xml version='1.0' encoding='utf-8'?>
<Scenarios>
    <Scenario name='Scenario 1b'>
        <ScenarioEditor>
            <HardwareInLoop enabled='true' participant_proxmox_url='https://xml.example:8006'/>
        </ScenarioEditor>
    </Scenario>
</Scenarios>
""",
                encoding="utf-8",
        )

        scenario_paths = {"scenario 1b": {str(scen_path)}}
        # Catalog hint explicitly cleared.
        catalog_hints = {"scenario 1b": ""}

        mapping = backend._collect_scenario_participant_urls(scenario_paths, catalog_hints)
        assert "scenario 1b" in mapping
        assert mapping["scenario 1b"] == ""
