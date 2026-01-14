from webapp.app_backend import _attack_flow_builder_afb_for_chain


def _find_named_objects(afb: dict, obj_id: str) -> list[str]:
    names: list[str] = []
    for o in afb.get("objects") or []:
        if not isinstance(o, dict):
            continue
        if o.get("id") != obj_id:
            continue
        props = o.get("properties")
        if not isinstance(props, list):
            continue
        for pair in props:
            if isinstance(pair, list) and len(pair) == 2 and pair[0] == "name":
                names.append(str(pair[1] or ""))
    return names


def test_afb_export_emits_inject_files_as_artifact_nodes():
    chain_nodes = [{"id": "n1", "name": "Node 1", "ipv4": "10.0.0.1"}]
    flag_assignments = [
        {
            "node_id": "n1",
            "id": "gen1",
            "name": "Test Generator",
            "type": "flag-generator",
            "inject_files": ["injected/flag.txt", "hint.txt"],
            "produces": ["flag"],
            "output_fields": ["flag"],
        }
    ]

    afb = _attack_flow_builder_afb_for_chain(
        chain_nodes=chain_nodes,
        scenario_label="Scenario",
        flag_assignments=flag_assignments,
    )

    artifact_names = _find_named_objects(afb, "artifact")
    assert "injected/flag.txt" in artifact_names
    assert "hint.txt" in artifact_names
