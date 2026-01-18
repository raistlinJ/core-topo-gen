import pytest

from webapp import app_backend


def test_flow_optional_inputs_excluded_from_effective_inputs(monkeypatch: pytest.MonkeyPatch):
    """Optional inputs should never be treated as missing prerequisites.

    Specifically: if a plugin-level requires token matches an input field declared
    with required=False, it must not appear in the assignment's effective `inputs`.
    """

    fake_gen = {
        "id": "opt_consumer",
        "name": "Optional Consumer",
        "language": "python",
        "_source_name": "test",
        "inputs": [
            {"name": "Credential(user, password)", "required": False},
        ],
        "outputs": [],
    }

    def fake_flag_generators_from_enabled_sources():
        return [fake_gen], []

    def fake_flag_node_generators_from_enabled_sources():
        return [], []

    def fake_enabled_plugin_contracts_by_id():
        return {
            "opt_consumer": {
                "plugin_id": "opt_consumer",
                "plugin_type": "flag-generator",
                "version": "1.0",
                "requires": ["Credential(user, password)"],
                "produces": [],
                "inputs": {},
            }
        }

    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", fake_flag_generators_from_enabled_sources)
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", fake_flag_node_generators_from_enabled_sources)
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", fake_enabled_plugin_contracts_by_id)

    preview = {
        "seed": 1,
        "hosts": [{"node_id": "h1", "name": "host-1", "role": "Docker", "vulnerabilities": []}],
        "routers": [],
        "switches": [],
        "switches_detail": [],
        "host_router_map": {},
        "r2r_links_preview": [],
    }
    chain_nodes = [{"id": "h1", "name": "host-1", "type": "docker", "is_vuln": False}]

    fas = app_backend._flow_compute_flag_assignments(preview, chain_nodes, "zz-test")
    assert len(fas) == 1
    a0 = fas[0]

    # Optional field is recorded as optional, but is not treated as an effective required input.
    assert "Credential(user, password)" in (a0.get("input_fields_optional") or [])
    assert "Credential(user, password)" not in (a0.get("inputs") or [])

    # Strict ordering validation must not fail due to that optional token.
    ok, errors = app_backend._flow_validate_chain_order_by_requires_produces(chain_nodes, fas, scenario_label="zz-test")
    assert ok, errors
