from core_topo_gen.utils.flow_seed import flow_generator_seed


def test_flow_generator_seed_includes_occurrence_index_and_changes_per_occurrence():
    s0 = flow_generator_seed(
        base_seed=123,
        scenario_norm="zz-scen",
        node_id="n1",
        gen_id="g1",
        occurrence_idx=0,
    )
    s1 = flow_generator_seed(
        base_seed=123,
        scenario_norm="zz-scen",
        node_id="n1",
        gen_id="g1",
        occurrence_idx=1,
    )

    assert s0 == "123:zz-scen:n1:g1:0"
    assert s1 == "123:zz-scen:n1:g1:1"
    assert s0 != s1


def test_flow_generator_seed_default_occurrence_is_zero():
    s_default = flow_generator_seed(
        base_seed="7",
        scenario_norm="zz",
        node_id="h1",
        gen_id="gen",
    )
    s0 = flow_generator_seed(
        base_seed="7",
        scenario_norm="zz",
        node_id="h1",
        gen_id="gen",
        occurrence_idx=0,
    )
    assert s_default == s0
