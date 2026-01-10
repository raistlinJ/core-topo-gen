from webapp import app_backend


def test_flow_reorder_chain_by_generator_dag_reorders_nodes_and_updates_next_fields():
    chain_nodes = [
        {"id": "n2", "name": "Node 2", "type": "docker"},
        {"id": "n1", "name": "Node 1", "type": "docker"},
    ]

    # n2 depends on artifact produced by n1.
    flag_assignments = [
        {
            "node_id": "n2",
            "id": "g_consumer",
            "name": "Consumer",
            "type": "flag-generator",
            "inputs": ["token"],
            "outputs": [],
            "hint_template": "Next: {{NEXT_NODE_ID}}",
        },
        {
            "node_id": "n1",
            "id": "g_producer",
            "name": "Producer",
            "type": "flag-generator",
            "inputs": [],
            "outputs": ["token"],
            "hint_template": "Next: {{NEXT_NODE_ID}}",
        },
    ]

    plugins_by_id = {
        "g_producer": {
            "plugin_id": "g_producer",
            "plugin_type": "flag-generator",
            "version": "test",
            "requires": [],
            "produces": [{"artifact": "token"}],
            "inputs": {},
        },
        "g_consumer": {
            "plugin_id": "g_consumer",
            "plugin_type": "flag-generator",
            "version": "test",
            "requires": ["token"],
            "produces": [],
            "inputs": {},
        },
    }

    new_chain, new_assignments, dag_debug = app_backend._flow_reorder_chain_by_generator_dag(
        chain_nodes,
        flag_assignments,
        scenario_label="scenario",
        plugins_by_id_override=plugins_by_id,
        return_debug=True,
    )

    assert [n["id"] for n in new_chain] == ["n1", "n2"]
    assert [a["node_id"] for a in new_assignments] == ["n1", "n2"]

    assert new_assignments[0]["next_node_id"] == "n2"
    assert new_assignments[1]["next_node_id"] == ""
    assert "Next: n2" in (new_assignments[0].get("hint") or "")

    assert isinstance(dag_debug, dict)
    assert dag_debug.get("ok") is True
    assert dag_debug.get("order") == ["n1", "n2"]
    edges = dag_debug.get("edges")
    assert isinstance(edges, list)
    assert any(e.get("src") == "n1" and e.get("dst") == "n2" and e.get("artifact") == "token" for e in edges)
