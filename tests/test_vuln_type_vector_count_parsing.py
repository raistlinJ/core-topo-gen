import os
import xml.etree.ElementTree as ET


def test_parse_vulnerabilities_type_vector_count_includes_v_count(tmp_path):
    from core_topo_gen.parsers.vulnerabilities import parse_vulnerabilities_info

    root = ET.Element('Scenarios')
    scen = ET.SubElement(root, 'Scenario', name='S1')
    se = ET.SubElement(scen, 'ScenarioEditor')

    # Minimal Node Information so density_base > 0 is possible in downstream planning.
    sec_nodes = ET.SubElement(se, 'section', name='Node Information')
    ET.SubElement(sec_nodes, 'item', selected='Docker', factor='1.0')

    sec_v = ET.SubElement(se, 'section', name='Vulnerabilities', density='0.0')
    ET.SubElement(
        sec_v,
        'item',
        selected='Type/Vector',
        v_metric='Count',
        v_count='2',
        v_type='docker-compose',
        v_vector='web',
        factor='1.0',
    )

    xml_path = tmp_path / 's.xml'
    ET.ElementTree(root).write(xml_path, encoding='utf-8', xml_declaration=True)

    density, items = parse_vulnerabilities_info(str(xml_path), 'S1')
    assert density == 0.0
    assert len(items) == 1
    assert items[0].get('selected') == 'Type/Vector'
    assert items[0].get('v_metric') == 'Count'
    assert items[0].get('v_count') == 2
    assert items[0].get('v_type') == 'docker-compose'
    assert items[0].get('v_vector') == 'web'


def test_compute_full_plan_includes_type_vector_count_items(tmp_path, monkeypatch):
    """Ensures Count-based vulnerability rows are not dropped during planning.

    This is what drives both Preview tabs and Flag Sequencing eligibility/annotations.
    """
    from core_topo_gen.planning.orchestrator import compute_full_plan

    # Create an XML with a density_base > 0 so the planner can run without relying on defaults.
    root = ET.Element('Scenarios')
    scen = ET.SubElement(root, 'Scenario', name='S1')
    se = ET.SubElement(scen, 'ScenarioEditor')

    sec_nodes = ET.SubElement(se, 'section', name='Node Information')
    ET.SubElement(sec_nodes, 'item', selected='Docker', factor='1.0')
    # Keep other sections present but minimal.
    ET.SubElement(se, 'section', name='Routing', density='0.0')
    ET.SubElement(se, 'section', name='Services', density='0.0')
    ET.SubElement(se, 'section', name='Traffic', density='0.0')
    ET.SubElement(se, 'section', name='Segmentation', density='0.0')

    sec_v = ET.SubElement(se, 'section', name='Vulnerabilities', density='0.0')
    ET.SubElement(
        sec_v,
        'item',
        selected='Type/Vector',
        v_metric='Count',
        v_count='3',
        v_type='docker-compose',
        v_vector='web',
        factor='1.0',
    )

    xml_path = tmp_path / 's.xml'
    ET.ElementTree(root).write(xml_path, encoding='utf-8', xml_declaration=True)

    plan = compute_full_plan(str(xml_path), scenario='S1', seed=123, include_breakdowns=False)
    vplan = plan.get('vulnerability_plan') or {}
    # Name should include v_type/v_vector (per orchestrator normalization)
    assert vplan.get('docker-compose:web') == 3
