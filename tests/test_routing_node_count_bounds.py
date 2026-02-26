from core_topo_gen.parsers.routing import parse_routing_info
from core_topo_gen.planning.orchestrator import compute_full_plan


def test_routing_parser_uses_section_node_count_min_when_items_absent(tmp_path):
    xml_path = tmp_path / "routing_bounds.xml"
    xml_path.write_text(
        """
<Scenarios>
  <Scenario name="S1">
    <ScenarioEditor>
      <section name="Node Information" density_count="10" base_nodes="10" total_nodes="10">
        <item selected="Workstation" factor="1.0" />
      </section>
      <section name="Routing" density="0.0" node_count_min_enabled="true" node_count_min="3" />
    </ScenarioEditor>
  </Scenario>
</Scenarios>
""".strip(),
        encoding="utf-8",
    )

    density, items = parse_routing_info(str(xml_path), "S1")

    assert density == 0.0
    assert len(items) == 1
    assert items[0].abs_count == 3

    plan = compute_full_plan(str(xml_path), scenario="S1", seed=123, include_breakdowns=True)
    assert int(plan.get("routers_planned") or 0) == 3
