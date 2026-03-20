from core_topo_gen.planning.ai_topology_intent import apply_compiled_sections_to_scenario
from core_topo_gen.planning.ai_topology_intent import compile_ai_topology_intent


def _scenario_payload(name='IntentScenario'):
    return {
        'name': name,
        'sections': {
            'Node Information': {'density': 0, 'total_nodes': 0, 'items': []},
            'Routing': {'density': 0.0, 'items': []},
            'Services': {'density': 0.0, 'items': []},
            'Traffic': {'density': 0.0, 'items': []},
            'Vulnerabilities': {'density': 0.0, 'items': [], 'flag_type': 'text'},
            'Segmentation': {'density': 0.0, 'items': []},
        },
        'notes': '',
    }


def test_compile_ai_topology_intent_seeds_router_and_host_counts():
    compiled = compile_ai_topology_intent(
        'Create a topology with 30 nodes, 8 routers with low router-to-router link ratio, and 4 servers.'
    )

    assert compiled.locked_sections == ('Routing', 'Node Information')
    assert compiled.applied_actions == ['Routing routers=8', 'Node Server=4', 'Node PC=18']

    routing = compiled.section_payloads['Routing']
    assert routing['items'][0]['selected'] == 'OSPFv2'
    assert routing['items'][0]['v_count'] == 8
    assert routing['items'][0]['r2r_mode'] == 'Min'

    node_info = compiled.section_payloads['Node Information']
    assert node_info['total_nodes'] == 22
    assert node_info['items'][0]['selected'] == 'Server'
    assert node_info['items'][0]['v_count'] == 4
    assert node_info['items'][1]['selected'] == 'PC'
    assert node_info['items'][1]['v_count'] == 18


def test_apply_compiled_sections_to_scenario_overrides_llm_node_and_routing_rows():
    compiled = compile_ai_topology_intent('Create a network with 12 nodes and 3 routers.')
    scenario = _scenario_payload()
    scenario['sections']['Node Information']['items'] = [
        {'selected': 'Server', 'v_metric': 'Count', 'v_count': 99, 'factor': 1.0},
    ]
    scenario['sections']['Routing']['items'] = [
        {'selected': 'BGP', 'v_metric': 'Count', 'v_count': 99, 'factor': 1.0},
    ]

    merged = apply_compiled_sections_to_scenario(scenario, compiled)

    node_items = merged['sections']['Node Information']['items']
    routing_items = merged['sections']['Routing']['items']
    assert node_items == [
        {'selected': 'PC', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 9},
    ]
    assert routing_items == [
        {'selected': 'OSPFv2', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 3},
    ]


def test_compile_ai_topology_intent_also_compiles_services_and_traffic_rows():
    compiled = compile_ai_topology_intent(
        'create a network with 10 nodes, 2 routers, two ssh and one web service, plus two tcp and one udp flows, and two periodic and one burst flows'
    )

    assert compiled.locked_sections == ('Routing', 'Node Information', 'Services', 'Traffic')
    assert compiled.section_payloads['Services']['items'] == [
        {'selected': 'SSH', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 2},
        {'selected': 'HTTP', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 1},
    ]
    assert compiled.section_payloads['Traffic']['items'] == [
        {'selected': 'TCP', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 2, 'pattern': 'periodic', 'content_type': 'text'},
        {'selected': 'UDP', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 1, 'pattern': 'burst', 'content_type': 'text'},
    ]


def test_compile_ai_topology_intent_compiles_vulnerabilities_from_catalog_and_allocates_docker_slots():
    compiled = compile_ai_topology_intent(
        'Create a network with 12 nodes, 3 routers, and 2 web vulnerabilities.',
        vuln_catalog=[
            {'Name': 'appweb/CVE-2018-8715', 'Path': '/catalog/appweb/CVE-2018-8715/docker-compose.yml', 'Description': 'Web server vulnerability'},
            {'Name': 'jboss/CVE-2017-12149', 'Path': '/catalog/jboss/CVE-2017-12149/docker-compose.yml', 'Description': 'JBoss Java deserialization'},
        ],
    )

    node_items = compiled.section_payloads['Node Information']['items']
    vuln_items = compiled.section_payloads['Vulnerabilities']['items']

    assert compiled.locked_sections == ('Routing', 'Node Information', 'Vulnerabilities')
    assert node_items == [
        {'selected': 'PC', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 7},
        {'selected': 'Docker', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 2},
    ]
    assert vuln_items == [
        {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'appweb/CVE-2018-8715', 'v_path': '/catalog/appweb/CVE-2018-8715/docker-compose.yml'},
        {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'jboss/CVE-2017-12149', 'v_path': '/catalog/jboss/CVE-2017-12149/docker-compose.yml'},
    ]


def test_compile_ai_topology_intent_supports_word_counts_for_servers_and_vulnerable_docker_targets():
    compiled = compile_ai_topology_intent(
        'Generate two servers and three vulnerable docker targets.',
        vuln_catalog=[
            {'Name': 'Demo Vuln', 'Path': 'demo/path', 'Description': 'Demo desc'},
        ],
    )

    assert compiled.section_payloads['Node Information']['items'] == [
        {'selected': 'Server', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 2},
        {'selected': 'Docker', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 3},
    ]
    assert compiled.section_payloads['Vulnerabilities']['items'] == [
        {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'Demo Vuln', 'v_path': 'demo/path'},
        {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'Demo Vuln', 'v_path': 'demo/path'},
        {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'Demo Vuln', 'v_path': 'demo/path'},
    ]


def test_compile_ai_topology_intent_compiles_segmentation_counts():
    compiled = compile_ai_topology_intent(
        'Create a network with 2 firewall segments and 1 nat segment.'
    )

    assert compiled.locked_sections == ('Segmentation',)
    assert compiled.section_payloads['Segmentation']['items'] == [
        {'selected': 'Firewall', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 2},
        {'selected': 'NAT', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 1},
    ]