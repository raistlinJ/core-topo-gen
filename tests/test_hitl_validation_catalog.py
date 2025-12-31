import json
import os
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
    # Reset any cached state that might depend on paths.
    return repo


def test_merge_and_load_hitl_validation_hints(tmp_repo_root):
    import webapp.app_backend as backend

    outputs_dir = Path(backend._outputs_dir())
    outputs_dir.mkdir(parents=True, exist_ok=True)

    # Seed minimal scenario_catalog.json
    catalog_path = Path(backend._scenario_catalog_file())
    catalog = {
        "names": ["Scenario 1"],
        "sources": [""],
        "updated_at": "2020-01-01T00:00:00Z",
    }
    catalog_path.write_text(json.dumps(catalog, indent=2), encoding="utf-8")

    backend._merge_hitl_validation_into_scenario_catalog(
        "Scenario 1",
        proxmox={
            "url": "https://pve.example:8006",
            "port": 8006,
            "username": "root@pam",
            "verify_ssl": True,
            "secret_id": "01-scenario-abc123",
            "validated": True,
            "password": "SHOULD_NOT_PERSIST",
        },
        core={
            "core_secret_id": "01-core-abc123",
            "validated": True,
            "ssh_username": "core",
            "ssh_password": "SHOULD_NOT_PERSIST",
        },
    )

    hints = backend._load_scenario_hitl_validation_from_disk()
    assert "scenario 1" in hints
    scen = hints["scenario 1"]
    assert scen["proxmox"]["secret_id"] == "01-scenario-abc123"
    assert "password" not in scen["proxmox"]
    assert scen["core"]["core_secret_id"] == "01-core-abc123"
    assert "ssh_password" not in scen["core"]


def test_builder_seed_merges_hitl_validation_hints(tmp_repo_root, monkeypatch):
    import webapp.app_backend as backend

    outputs_dir = Path(backend._outputs_dir())
    outputs_dir.mkdir(parents=True, exist_ok=True)

    # Seed catalog with a hitl_validation entry.
    catalog_path = Path(backend._scenario_catalog_file())
    catalog = {
        "names": ["Scenario 1"],
        "sources": [""],
        "updated_at": "2020-01-01T00:00:00Z",
        "hitl_validation": {
            "scenario 1": {
                "proxmox": {"secret_id": "p1", "validated": True, "url": "https://pve.local"},
                "core": {"core_secret_id": "c1", "validated": True, "vm_key": "node::vm"},
            }
        },
    }
    catalog_path.write_text(json.dumps(catalog, indent=2), encoding="utf-8")

    # Avoid catalog path parsing; force builder catalog seed inputs.
    def fake_catalog_for_user(_history=None, *, user=None):
        return ["Scenario 1"], {}, {}

    monkeypatch.setattr(backend, "_scenario_catalog_for_user", fake_catalog_for_user)

    seeded = backend._builder_catalog_seed_scenarios({"scenario 1"}, user={"username": "b", "role": "builder"})
    assert len(seeded) == 1
    hitl = seeded[0].get("hitl")
    assert isinstance(hitl, dict)
    assert hitl.get("proxmox", {}).get("secret_id") == "p1"
    assert hitl.get("core", {}).get("core_secret_id") == "c1"
