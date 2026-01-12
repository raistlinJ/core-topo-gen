import uuid

import pytest

from webapp import app_backend


def test_flow_vuln_nodes_only_use_flag_generators(monkeypatch: pytest.MonkeyPatch):
    scenario = f"zz-flow-vuln-only-flaggen-{uuid.uuid4().hex[:8]}"

    # Preview with two hosts: one vuln-bearing docker, one non-vuln docker.
    preview = {
        "seed": 0,
        "hosts": [
            {"node_id": "h1", "name": "dockervuln-1", "role": "Docker", "vulnerabilities": [{"name": "docker-compose:web"}]},
            {"node_id": "h2", "name": "host-2", "role": "Docker", "vulnerabilities": []},
        ],
    }

    flag_gen = {
        "id": "fg1",
        "name": "FlagGen",
        "inputs": [],
        "outputs": [{"name": "flag", "required": False}],
        "hint_template": "Next: {{NEXT_NODE_ID}}",
        "language": "python",
        "_source_name": "test",
    }
    node_gen = {
        "id": "ng1",
        "name": "NodeGen",
        "inputs": [],
        "outputs": [],
        "hint_template": "Next: {{NEXT_NODE_ID}}",
        "language": "python",
        "_source_name": "test",
    }

    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", lambda: ([flag_gen], []))
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([node_gen], []))

    chain_nodes = [
        {"id": "h1", "name": "dockervuln-1", "type": "docker", "is_vuln": True},
        {"id": "h2", "name": "host-2", "type": "docker", "is_vuln": False},
    ]

    assignments = app_backend._flow_compute_flag_assignments(preview, chain_nodes, scenario)
    assert len(assignments) == 2

    a1 = assignments[0]
    assert a1["node_id"] == "h1"
    assert a1["type"] == "flag-generator"
    assert a1.get("generator_catalog") == "flag_generators"

    a2 = assignments[1]
    assert a2["node_id"] == "h2"
    assert a2["type"] in {"flag-generator", "flag-node-generator"}
