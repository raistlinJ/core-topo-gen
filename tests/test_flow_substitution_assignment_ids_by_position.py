from core_topo_gen.utils.flow_substitution import flow_assignment_ids_by_position


def test_flow_assignment_ids_by_position_preserves_duplicates():
    # Duplicate node IDs are legal when allow_node_duplicates is enabled.
    # The important part is that generator IDs remain aligned by *position*,
    # not by node_id.
    flag_assignments = [
        {"node_id": "A", "id": "g0"},
        {"node_id": "B", "id": "g1"},
        {"node_id": "A", "id": "g2"},
    ]

    ids = flow_assignment_ids_by_position(flag_assignments)
    assert ids == ["g0", "g1", "g2"]


def test_flow_assignment_ids_by_position_accepts_generator_id_fallback():
    flag_assignments = [
        {"node_id": "A", "generator_id": "g0"},
        {"node_id": "B", "id": "g1"},
        {"node_id": "C"},
    ]
    ids = flow_assignment_ids_by_position(flag_assignments)
    assert ids == ["g0", "g1", ""]
