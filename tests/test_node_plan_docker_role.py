import os
import tempfile

from core_topo_gen.planning.node_plan import compute_node_plan
from core_topo_gen.parsers.node_info import parse_node_info


def _write_xml(xml: str) -> str:
    td = tempfile.mkdtemp()
    path = os.path.join(td, "s.xml")
    with open(path, "w") as f:
        f.write(xml)
    return path


def test_node_info_docker_count_row_preserved():
    xml = """<Scenarios>
  <Scenario name='s'>
    <ScenarioEditor>
      <section name='Node Information'>
        <item selected='Docker' v_metric='Count' v_count='5'/>
      </section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>"""
    path = _write_xml(xml)

    density_base, weight_items, count_items, _services = parse_node_info(path, "s")
    assert density_base == 10  # default when absent
    assert weight_items == []
    assert ("Docker", 5) in count_items

    role_counts, breakdown = compute_node_plan(density_base, weight_items, count_items)
    assert role_counts.get("Docker") == 5
    assert "Docker" in breakdown.get("allowed_roles", [])


def test_node_info_docker_weight_row_allocates_base_hosts():
    xml = """<Scenarios>
  <Scenario name='s'>
    <ScenarioEditor>
      <section name='Node Information'>
        <item selected='Docker' factor='1'/>
      </section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>"""
    path = _write_xml(xml)

    density_base, weight_items, count_items, _services = parse_node_info(path, "s")
    assert density_base == 10  # default when absent
    assert count_items == []
    assert ("Docker", 1.0) in weight_items

    role_counts, _breakdown = compute_node_plan(density_base, weight_items, count_items)
    assert role_counts.get("Docker") == 10
