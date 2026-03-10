import json

from MCP.server import ScenarioAuthoringMCPServer


def _tool_call(server, name, arguments):
    response = server.handle_message({
        'jsonrpc': '2.0',
        'id': 3,
        'method': 'tools/call',
        'params': {
            'name': name,
            'arguments': arguments,
        },
    })
    assert response is not None
    assert 'error' not in response
    result = response.get('result') or {}
    assert result.get('isError') is False
    return result.get('structuredContent') or {}


def test_mcp_initialize_and_list_tools():
    server = ScenarioAuthoringMCPServer()

    init_response = server.handle_message({
        'jsonrpc': '2.0',
        'id': 1,
        'method': 'initialize',
        'params': {},
    })
    assert init_response is not None
    init_result = init_response.get('result') or {}
    assert init_result.get('protocolVersion')
    assert init_result.get('serverInfo', {}).get('name') == 'core-topo-gen-mcp'

    list_response = server.handle_message({
        'jsonrpc': '2.0',
        'id': 2,
        'method': 'tools/list',
        'params': {},
    })
    assert list_response is not None
    tools = (list_response.get('result') or {}).get('tools') or []
    tool_names = {tool.get('name') for tool in tools}
    assert 'scenario.create_draft' in tool_names
    assert 'scenario.get_authoring_schema' in tool_names
    assert 'scenario.add_node_role_item' in tool_names
    assert 'scenario.add_routing_item' in tool_names
    assert 'scenario.add_service_item' in tool_names
    assert 'scenario.add_traffic_item' in tool_names
    assert 'scenario.add_segmentation_item' in tool_names
    assert 'scenario.search_vulnerability_catalog' in tool_names
    assert 'scenario.add_vulnerability_item' in tool_names
    assert 'scenario.preview_draft' in tool_names
    assert 'scenario.save_xml' in tool_names

    vuln_tool = next(tool for tool in tools if tool.get('name') == 'scenario.add_vulnerability_item')
    vuln_properties = (((vuln_tool.get('inputSchema') or {}).get('properties')) or {})
    assert 'factor' not in vuln_properties
    assert 'query' not in vuln_properties
    assert set(vuln_properties) >= {'draft_id', 'v_name', 'v_path', 'v_type', 'v_vector', 'v_count'}


def test_mcp_draft_preview_and_save_flow(tmp_path, monkeypatch):
    from webapp import app_backend

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(app_backend, '_outputs_dir', lambda: str(outdir))

    server = ScenarioAuthoringMCPServer()

    created = _tool_call(server, 'scenario.create_draft', {'name': 'McpScenario'})
    draft = created.get('draft') or {}
    draft_id = draft.get('draft_id')
    assert draft_id
    assert draft.get('scenario', {}).get('name') == 'McpScenario'

    updated = _tool_call(server, 'scenario.replace_section', {
        'draft_id': draft_id,
        'section_name': 'Node Information',
        'section_payload': {
            'density': 0,
            'total_nodes': 0,
            'items': [
                {'selected': 'PC', 'v_metric': 'Count', 'v_count': 3, 'factor': 1.0},
            ],
        },
    })
    assert updated.get('draft', {}).get('scenario', {}).get('sections', {}).get('Node Information', {}).get('items')

    previewed = _tool_call(server, 'scenario.preview_draft', {'draft_id': draft_id})
    preview = previewed.get('preview') or {}
    assert len(preview.get('hosts') or []) == 3

    saved = _tool_call(server, 'scenario.save_xml', {'draft_id': draft_id})
    xml_path = saved.get('xml_path')
    assert xml_path

    parsed = app_backend._parse_scenarios_xml(xml_path)
    scenarios = parsed.get('scenarios') or []
    assert len(scenarios) == 1
    assert scenarios[0].get('name') == 'McpScenario'


def test_mcp_preview_draft_concretizes_random_routing_placeholders():
    server = ScenarioAuthoringMCPServer()

    created = _tool_call(server, 'scenario.create_draft', {'name': 'RandomRoutingDraft'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    _tool_call(server, 'scenario.replace_section', {
        'draft_id': draft_id,
        'section_name': 'Routing',
        'section_payload': {
            'density': 0,
            'items': [
                {'selected': 'Random', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0},
            ],
        },
    })
    _tool_call(server, 'scenario.replace_section', {
        'draft_id': draft_id,
        'section_name': 'Node Information',
        'section_payload': {
            'density': 0,
            'total_nodes': 0,
            'items': [
                {'selected': 'PC', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0},
            ],
        },
    })

    previewed = _tool_call(server, 'scenario.preview_draft', {'draft_id': draft_id})
    draft = previewed.get('draft') or {}
    routing_items = (((draft.get('scenario') or {}).get('sections') or {}).get('Routing') or {}).get('items') or []

    assert routing_items
    assert routing_items[0].get('selected') in {'RIP', 'RIPNG', 'BGP', 'OSPFv2', 'OSPFv3'}
    assert len((previewed.get('preview') or {}).get('routers') or []) == 1


def test_mcp_preview_draft_honors_explicit_router_counts_without_hosts():
    server = ScenarioAuthoringMCPServer()

    created = _tool_call(server, 'scenario.create_draft', {'name': 'RouterOnlyDraft'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    _tool_call(server, 'scenario.add_routing_item', {
        'draft_id': draft_id,
        'protocol': 'ospf',
        'count': 5,
    })

    previewed = _tool_call(server, 'scenario.preview_draft', {'draft_id': draft_id})

    assert len((previewed.get('preview') or {}).get('routers') or []) == 5


def test_mcp_replace_section_repairs_router_rows_misplaced_in_node_information():
    server = ScenarioAuthoringMCPServer()

    created = _tool_call(server, 'scenario.create_draft', {'name': 'RouterRepairScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    response = server.handle_message({
        'jsonrpc': '2.0',
        'id': 8,
        'method': 'tools/call',
        'params': {
            'name': 'scenario.replace_section',
            'arguments': {
                'draft_id': draft_id,
                'section_name': 'Node Information',
                'section_payload': {
                    'density': 0,
                    'total_nodes': 0,
                    'items': [
                        {'selected': 'Router', 'v_metric': 'Count', 'v_count': 5, 'factor': 1.0},
                    ],
                },
            },
        },
    })

    assert response is not None
    error = response.get('error') or {}
    assert error.get('code') == -32602
    assert 'Node Information selected must be one of:' in str(error.get('message') or '')


def test_mcp_replace_section_accepts_json_string_payload():
    server = ScenarioAuthoringMCPServer()

    created = _tool_call(server, 'scenario.create_draft', {'name': 'StringPayloadScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    updated = _tool_call(server, 'scenario.replace_section', {
        'draft_id': draft_id,
        'section_name': 'Node Information',
        'section_payload': json.dumps({
            'density': 0,
            'total_nodes': 0,
            'items': [
                {'selected': 'PC', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0},
            ],
        }),
    })

    items = (((updated.get('draft') or {}).get('scenario') or {}).get('sections') or {}).get('Node Information', {}).get('items') or []
    assert len(items) == 1
    assert items[0].get('v_count') == 2


def test_mcp_replace_section_accepts_alias_section_name_and_wrapped_object():
    server = ScenarioAuthoringMCPServer()

    created = _tool_call(server, 'scenario.create_draft', {'name': 'AliasSectionScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    updated = _tool_call(server, 'scenario.replace_section', {
        'draft_id': draft_id,
        'section_name': 'scenarioInfo',
        'section_payload': {
            'section_payload': {
                'density': 0,
                'total_nodes': 0,
                'items': [
                    {'selected': 'PC', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0},
                ],
            },
        },
    })

    items = (((updated.get('draft') or {}).get('scenario') or {}).get('sections') or {}).get('Node Information', {}).get('items') or []
    assert len(items) == 1
    assert items[0].get('selected') == 'PC'


def test_mcp_replace_section_accepts_wrapped_json_string_payload():
    server = ScenarioAuthoringMCPServer()

    created = _tool_call(server, 'scenario.create_draft', {'name': 'WrappedStringPayloadScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    updated = _tool_call(server, 'scenario.replace_section', {
        'draft_id': draft_id,
        'section_name': 'Vulns',
        'section_payload': json.dumps({
            'payload': {
                'density': 0,
                'flag_type': 'text',
                'items': [
                    {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'mysql/CVE-2012-2122', 'factor': 1.0},
                ],
            },
        }),
    })

    items = (((updated.get('draft') or {}).get('scenario') or {}).get('sections') or {}).get('Vulnerabilities', {}).get('items') or []
    assert len(items) == 1
    assert items[0].get('v_name') == 'mysql/CVE-2012-2122'


def test_mcp_replace_section_rejects_unknown_service_selected_value():
    server = ScenarioAuthoringMCPServer()

    created = _tool_call(server, 'scenario.create_draft', {'name': 'ReplaceServiceRejectScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    response = server.handle_message({
        'jsonrpc': '2.0',
        'id': 6,
        'method': 'tools/call',
        'params': {
            'name': 'scenario.replace_section',
            'arguments': {
                'draft_id': draft_id,
                'section_name': 'Services',
                'section_payload': {
                    'density': 0.5,
                    'items': [
                        {'selected': 'DNS', 'factor': 1.0},
                    ],
                },
            },
        },
    })

    assert response is not None
    error = response.get('error') or {}
    assert error.get('code') == -32602
    assert 'SSH, HTTP, DHCPClient, or Random' in str(error.get('message') or '')


def test_mcp_replace_section_rejects_removed_events_section():
    server = ScenarioAuthoringMCPServer()

    created = _tool_call(server, 'scenario.create_draft', {'name': 'EventsNormalizeScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    response = server.handle_message({
        'jsonrpc': '2.0',
        'id': 7,
        'method': 'tools/call',
        'params': {
            'name': 'scenario.replace_section',
            'arguments': {
                'draft_id': draft_id,
                'section_name': 'Events',
                'section_payload': {
                    'density': 0.5,
                    'items': [
                        {'selected': 'script', 'script_path': 'scripts/demo.sh', 'factor': 1.0},
                    ],
                },
            },
        },
    })

    assert response is not None
    error = response.get('error') or {}
    assert error.get('code') == -32602
    assert 'Unknown section_name: Events' in str(error.get('message') or '')


def test_mcp_replace_section_preserves_legacy_vulnerability_and_segmentation_modes():
    server = ScenarioAuthoringMCPServer()

    created = _tool_call(server, 'scenario.create_draft', {'name': 'LegacyModesScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    updated_vulns = _tool_call(server, 'scenario.replace_section', {
        'draft_id': draft_id,
        'section_name': 'Vulnerabilities',
        'section_payload': {
            'density': 0,
            'flag_type': 'text',
            'items': [
                {'selected': 'Category', 'v_type': 'docker-compose', 'v_vector': 'remote', 'v_metric': 'Count', 'v_count': 1},
            ],
        },
    })

    vuln_items = (((updated_vulns.get('draft') or {}).get('scenario') or {}).get('sections') or {}).get('Vulnerabilities', {}).get('items') or []
    assert len(vuln_items) == 1
    assert vuln_items[0].get('selected') == 'Type/Vector'

    updated_seg = _tool_call(server, 'scenario.replace_section', {
        'draft_id': draft_id,
        'section_name': 'Segmentation',
        'section_payload': {
            'density': 0.5,
            'items': [
                {'selected': 'custom', 'factor': 1.0},
            ],
        },
    })

    seg_items = (((updated_seg.get('draft') or {}).get('scenario') or {}).get('sections') or {}).get('Segmentation', {}).get('items') or []
    assert len(seg_items) == 1
    assert seg_items[0].get('selected') == 'CUSTOM'


def test_mcp_set_notes_accepts_text_alias():
    server = ScenarioAuthoringMCPServer()

    created = _tool_call(server, 'scenario.create_draft', {'name': 'NotesAliasScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    updated = _tool_call(server, 'scenario.set_notes', {
        'draft_id': draft_id,
        'text': 'Scenario generated from a compact SQL-focused prompt.',
    })

    draft = updated.get('draft') or {}
    scenario = draft.get('scenario') or {}
    assert scenario.get('notes') == 'Scenario generated from a compact SQL-focused prompt.'


def test_mcp_replace_section_accepts_bare_item_list_payload():
    server = ScenarioAuthoringMCPServer()

    created = _tool_call(server, 'scenario.create_draft', {'name': 'ListPayloadScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    updated = _tool_call(server, 'scenario.replace_section', {
        'draft_id': draft_id,
        'section_name': 'Node Information',
        'section_payload': [
            {'selected': 'PC', 'v_metric': 'Count', 'v_count': 5, 'factor': 1.0},
        ],
    })

    node_info = (((updated.get('draft') or {}).get('scenario') or {}).get('sections') or {}).get('Node Information') or {}
    items = node_info.get('items') or []
    assert len(items) == 1
    assert items[0].get('v_count') == 5


def test_mcp_add_node_role_item_appends_docker_count_row():
    server = ScenarioAuthoringMCPServer()

    created = _tool_call(server, 'scenario.create_draft', {'name': 'DockerRoleScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    updated = _tool_call(server, 'scenario.add_node_role_item', {
        'draft_id': draft_id,
        'role': 'docker',
        'count': 3,
    })

    node_info = (((updated.get('draft') or {}).get('scenario') or {}).get('sections') or {}).get('Node Information') or {}
    items = node_info.get('items') or []
    assert items
    assert items[-1].get('selected') == 'Docker'
    assert items[-1].get('v_metric') == 'Count'
    assert items[-1].get('v_count') == 3


def test_mcp_add_node_role_item_rejects_router_values():
    server = ScenarioAuthoringMCPServer()

    created = _tool_call(server, 'scenario.create_draft', {'name': 'RouterWrongSectionScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    response = server.handle_message({
        'jsonrpc': '2.0',
        'id': 4,
        'method': 'tools/call',
        'params': {
            'name': 'scenario.add_node_role_item',
            'arguments': {
                'draft_id': draft_id,
                'role': 'router',
                'count': 2,
            },
        },
    })

    assert response is not None
    error = response.get('error') or {}
    assert error.get('code') == -32602
    assert 'scenario.add_routing_item' in str(error.get('message') or '')


def test_mcp_add_service_item_appends_http_count_row():
    server = ScenarioAuthoringMCPServer()

    created = _tool_call(server, 'scenario.create_draft', {'name': 'ServiceScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    updated = _tool_call(server, 'scenario.add_service_item', {
        'draft_id': draft_id,
        'service': 'http',
        'count': 2,
    })

    section = (((updated.get('draft') or {}).get('scenario') or {}).get('sections') or {}).get('Services') or {}
    items = section.get('items') or []
    assert items
    assert items[-1].get('selected') == 'HTTP'
    assert items[-1].get('v_metric') == 'Count'
    assert items[-1].get('v_count') == 2


def test_mcp_add_routing_item_appends_protocol_count_row_with_edge_hints():
    server = ScenarioAuthoringMCPServer()

    created = _tool_call(server, 'scenario.create_draft', {'name': 'RoutingScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    updated = _tool_call(server, 'scenario.add_routing_item', {
        'draft_id': draft_id,
        'protocol': 'ospf',
        'count': 2,
        'r2r_mode': 'mesh',
        'r2r_edges': 1,
        'r2s_mode': 'count',
        'r2s_edges': 3,
        'r2s_hosts_min': 2,
        'r2s_hosts_max': 4,
    })

    section = (((updated.get('draft') or {}).get('scenario') or {}).get('sections') or {}).get('Routing') or {}
    items = section.get('items') or []
    assert items
    assert items[-1].get('selected') == 'OSPFv2'
    assert items[-1].get('v_metric') == 'Count'
    assert items[-1].get('v_count') == 2
    assert items[-1].get('r2r_mode') == 'full_mesh'
    assert items[-1].get('r2r_edges') == 1
    assert items[-1].get('r2s_mode') == 'count'
    assert items[-1].get('r2s_edges') == 3
    assert items[-1].get('r2s_hosts_min') == 2
    assert items[-1].get('r2s_hosts_max') == 4
    assert float(section.get('density') or 0.0) == 0.5


def test_mcp_add_segmentation_item_appends_firewall_row_with_density_default():
    server = ScenarioAuthoringMCPServer()

    created = _tool_call(server, 'scenario.create_draft', {'name': 'SegScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    updated = _tool_call(server, 'scenario.add_segmentation_item', {
        'draft_id': draft_id,
        'kind': 'firewall',
    })

    section = (((updated.get('draft') or {}).get('scenario') or {}).get('sections') or {}).get('Segmentation') or {}
    items = section.get('items') or []
    assert items
    assert items[-1].get('selected') == 'Firewall'
    assert items[-1].get('factor') == 1.0
    assert float(section.get('density') or 0.0) == 0.5


def test_mcp_get_authoring_schema_exposes_backend_option_sets():
    server = ScenarioAuthoringMCPServer()

    schema = _tool_call(server, 'scenario.get_authoring_schema', {})
    assert schema.get('schema_version') == '2025-03-26'
    top_level = schema.get('top_level') or {}
    assert top_level.get('section_order')
    assert set(top_level.get('scenario_fields') or {}) >= {'name', 'notes', 'density_count'}

    sections = schema.get('sections') or {}

    node_info = sections.get('Node Information') or {}
    assert set(node_info.get('ui_selected_values') or []) >= {'Server', 'Workstation', 'PC', 'Docker', 'Random'}
    assert set(node_info.get('selected_values') or []) >= {'Server', 'Workstation', 'PC', 'Docker'}
    assert set(node_info.get('section_fields') or {}) >= {'density', 'density_count', 'base_nodes', 'total_nodes'}
    assert set(node_info.get('item_fields') or {}) >= {'selected', 'factor', 'v_metric', 'v_count'}

    traffic = sections.get('Traffic') or {}
    assert set(traffic.get('selected_values') or []) >= {'TCP', 'UDP'}
    assert set(traffic.get('content_type_values') or []) >= {'text', 'photo', 'audio', 'video', 'gibberish'}
    assert set(traffic.get('pattern_values') or []) >= {'continuous', 'periodic', 'burst', 'poisson', 'ramp'}
    traffic_item_fields = traffic.get('item_fields') or {}
    assert set(traffic_item_fields) >= {'selected', 'factor', 'v_metric', 'v_count', 'pattern', 'rate_kbps', 'period_s', 'jitter_pct', 'content_type'}
    assert traffic_item_fields.get('rate_kbps', {}).get('aliases') == ['rate']
    assert traffic_item_fields.get('period_s', {}).get('aliases') == ['period']
    assert traffic_item_fields.get('jitter_pct', {}).get('aliases') == ['jitter']
    assert traffic_item_fields.get('content_type', {}).get('aliases') == ['content']

    services = sections.get('Services') or {}
    assert set(services.get('ui_selected_values') or []) >= {'SSH', 'HTTP', 'DHCPClient', 'Random'}
    assert set(services.get('selected_values') or []) >= {'SSH', 'HTTP', 'DHCPClient'}
    assert services.get('supports_custom_selected_value') is False
    assert services.get('section_defaults', {}).get('density') == 0.5
    assert 'selected' in (services.get('item_fields') or {})

    segmentation = sections.get('Segmentation') or {}
    assert set(segmentation.get('selected_values') or []) >= {'Firewall', 'NAT', 'CUSTOM'}
    assert segmentation.get('section_defaults', {}).get('density') == 0.5
    assert (segmentation.get('item_fields') or {}).get('selected', {}).get('aliases') == ['kind', 'type', 'name']

    routing = sections.get('Routing') or {}
    assert set(routing.get('item_fields') or {}) >= {
        'selected', 'factor', 'v_metric', 'v_count', 'r2r_mode', 'r2r_edges', 'r2s_mode', 'r2s_edges', 'r2s_hosts_min', 'r2s_hosts_max'
    }

    vulnerabilities = sections.get('Vulnerabilities') or {}
    assert set(vulnerabilities.get('ui_selected_values') or []) >= {'Random', 'Specific'}
    assert set(vulnerabilities.get('legacy_selected_values') or []) >= {'Type/Vector'}
    assert 'factor' not in (vulnerabilities.get('item_fields') or {})
    selection_modes = vulnerabilities.get('selection_modes') or {}
    assert set(selection_modes) >= {'Specific', 'Type/Vector'}
    assert selection_modes.get('Type/Vector', {}).get('selected_aliases') == ['Category']

    assert 'Events' not in sections

    notes = sections.get('Notes') or {}
    assert 'notes' in (notes.get('section_fields') or {})


def test_mcp_add_service_item_rejects_unknown_service_values():
    server = ScenarioAuthoringMCPServer()

    created = _tool_call(server, 'scenario.create_draft', {'name': 'ServiceRejectScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    response = server.handle_message({
        'jsonrpc': '2.0',
        'id': 5,
        'method': 'tools/call',
        'params': {
            'name': 'scenario.add_service_item',
            'arguments': {
                'draft_id': draft_id,
                'service': 'dns',
                'count': 1,
            },
        },
    })

    assert response is not None
    error = response.get('error') or {}
    assert error.get('code') == -32602
    assert 'SSH, HTTP, DHCPClient, or Random' in str(error.get('message') or '')


def test_mcp_get_authoring_schema_can_filter_single_section():
    server = ScenarioAuthoringMCPServer()

    schema = _tool_call(server, 'scenario.get_authoring_schema', {'section_name': 'traffic'})

    assert schema.get('section_name') == 'Traffic'
    section = schema.get('section') or {}
    assert set(section.get('selected_values') or []) >= {'TCP', 'UDP'}
    assert set(section.get('item_fields') or {}) >= {'pattern', 'rate_kbps', 'period_s', 'jitter_pct', 'content_type'}


def test_mcp_get_authoring_schema_exposes_vulnerability_mode_requirements():
    server = ScenarioAuthoringMCPServer()

    schema = _tool_call(server, 'scenario.get_authoring_schema', {'section_name': 'Vulnerabilities'})

    assert schema.get('section_name') == 'Vulnerabilities'
    section = schema.get('section') or {}
    selection_modes = section.get('selection_modes') or {}
    assert 'factor' not in (section.get('item_fields') or {})
    assert selection_modes.get('Specific', {}).get('required_item_fields') == ['selected', 'v_name']
    assert selection_modes.get('Type/Vector', {}).get('required_item_fields') == ['selected', 'v_type', 'v_vector']


def test_mcp_add_traffic_item_appends_concrete_tcp_flow_row():
    server = ScenarioAuthoringMCPServer()

    created = _tool_call(server, 'scenario.create_draft', {'name': 'TrafficScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    updated = _tool_call(server, 'scenario.add_traffic_item', {
        'draft_id': draft_id,
        'protocol': 'tcp',
        'count': 2,
    })

    traffic = (((updated.get('draft') or {}).get('scenario') or {}).get('sections') or {}).get('Traffic') or {}
    items = traffic.get('items') or []
    assert items
    assert items[-1].get('selected') == 'TCP'
    assert items[-1].get('v_metric') == 'Count'
    assert items[-1].get('v_count') == 2
    assert items[-1].get('content_type') == 'text'
    assert items[-1].get('pattern') == 'continuous'


def test_mcp_search_vulnerability_catalog_returns_mysql_match(monkeypatch):
    import MCP.server as mcp_server

    monkeypatch.setattr(mcp_server, 'load_vuln_catalog', lambda repo_root: [
        {
            'Name': 'mysql/CVE-2012-2122',
            'Path': 'https://github.com/vulhub/vulhub/tree/master/mysql/CVE-2012-2122',
            'Type': 'docker-compose',
            'Vector': 'remote',
            'CVE': 'CVE-2012-2122',
            'Description': 'MySQL Authentication Bypass',
        },
        {
            'Name': 'redis/CVE-2022-0543',
            'Path': 'https://github.com/vulhub/vulhub/tree/master/redis/CVE-2022-0543',
            'Type': 'docker-compose',
            'Vector': 'remote',
            'CVE': 'CVE-2022-0543',
            'Description': 'Redis sandbox escape',
        },
    ])

    server = ScenarioAuthoringMCPServer()
    result = _tool_call(server, 'scenario.search_vulnerability_catalog', {'query': 'mysql vulnerability'})

    assert result.get('count') == 1
    first = (result.get('results') or [])[0]
    assert first.get('name') == 'mysql/CVE-2012-2122'
    assert first.get('cve') == 'CVE-2012-2122'


def test_mcp_add_vulnerability_item_from_catalog_query(monkeypatch):
    import MCP.server as mcp_server

    monkeypatch.setattr(mcp_server, 'load_vuln_catalog', lambda repo_root: [
        {
            'Name': 'mysql/CVE-2012-2122',
            'Path': 'https://github.com/vulhub/vulhub/tree/master/mysql/CVE-2012-2122',
            'Type': 'docker-compose',
            'Vector': 'remote',
            'CVE': 'CVE-2012-2122',
            'Description': 'MySQL Authentication Bypass',
        },
    ])

    server = ScenarioAuthoringMCPServer()
    created = _tool_call(server, 'scenario.create_draft', {'name': 'VulnScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    updated = _tool_call(server, 'scenario.add_vulnerability_item', {
        'draft_id': draft_id,
        'query': 'mysql vulnerability',
        'v_count': 1,
    })

    added_item = updated.get('added_item') or {}
    assert added_item.get('selected') == 'Specific'
    assert added_item.get('v_name') == 'mysql/CVE-2012-2122'
    assert added_item.get('v_path') == 'https://github.com/vulhub/vulhub/tree/master/mysql/CVE-2012-2122'
    draft = updated.get('draft') or {}
    vuln_items = (((draft.get('scenario') or {}).get('sections') or {}).get('Vulnerabilities') or {}).get('items') or []
    assert len(vuln_items) == 1
    assert vuln_items[0].get('v_name') == 'mysql/CVE-2012-2122'


def test_mcp_add_vulnerability_item_canonicalizes_name_from_matching_path(monkeypatch):
    import MCP.server as mcp_server

    monkeypatch.setattr(mcp_server, 'load_vuln_catalog', lambda repo_root: [
        {
            'Name': 'jboss/CVE-2017-12149',
            'Path': 'https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149',
            'Type': 'docker-compose',
            'Vector': 'remote',
            'CVE': 'CVE-2017-12149',
            'Description': 'JBoss Java deserialization',
        },
    ])

    server = ScenarioAuthoringMCPServer()
    created = _tool_call(server, 'scenario.create_draft', {'name': 'CanonicalizeVulnScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    updated = _tool_call(server, 'scenario.add_vulnerability_item', {
        'draft_id': draft_id,
        'v_name': 'jboss',
        'v_path': 'https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149',
        'v_count': 1,
    })

    added_item = updated.get('added_item') or {}
    assert added_item.get('v_name') == 'jboss/CVE-2017-12149'
    assert added_item.get('v_path') == 'https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149'


def test_mcp_add_vulnerability_item_rejects_specific_vuln_outside_enabled_catalog(monkeypatch):
    import MCP.server as mcp_server

    monkeypatch.setattr(mcp_server, 'load_vuln_catalog', lambda repo_root: [
        {
            'Name': 'mysql/CVE-2012-2122',
            'Path': 'https://github.com/vulhub/vulhub/tree/master/mysql/CVE-2012-2122',
            'Type': 'docker-compose',
            'Vector': 'remote',
            'CVE': 'CVE-2012-2122',
            'Description': 'MySQL Authentication Bypass',
        },
    ])

    server = ScenarioAuthoringMCPServer()
    created = _tool_call(server, 'scenario.create_draft', {'name': 'RejectUnknownVulnScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    response = server.handle_message({
        'jsonrpc': '2.0',
        'id': 9,
        'method': 'tools/call',
        'params': {
            'name': 'scenario.add_vulnerability_item',
            'arguments': {
                'draft_id': draft_id,
                'v_name': 'jboss',
                'v_path': 'https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149',
                'v_count': 1,
            },
        },
    })

    assert response is not None
    error = response.get('error') or {}
    assert error.get('code') == -32602
    assert 'enabled catalog entry' in str(error.get('message') or '')


def test_mcp_add_vulnerability_item_accepts_type_vector_aliases_without_selected(monkeypatch):
    server = ScenarioAuthoringMCPServer()
    created = _tool_call(server, 'scenario.create_draft', {'name': 'TypeVectorScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    updated = _tool_call(server, 'scenario.add_vulnerability_item', {
        'draft_id': draft_id,
        'type': 'sql',
        'vector': 'remote',
        'v_count': 1,
    })

    added_item = updated.get('added_item') or {}
    assert added_item.get('selected') == 'Type/Vector'
    assert added_item.get('v_type') == 'sql'
    assert added_item.get('v_vector') == 'remote'


def test_mcp_add_vulnerability_item_accepts_description_alias_for_catalog_search(monkeypatch):
    import MCP.server as mcp_server

    monkeypatch.setattr(mcp_server, 'load_vuln_catalog', lambda repo_root: [
        {
            'Name': 'mysql/CVE-2012-2122',
            'Path': 'https://github.com/vulhub/vulhub/tree/master/mysql/CVE-2012-2122',
            'Type': 'docker-compose',
            'Vector': 'remote',
            'CVE': 'CVE-2012-2122',
            'Description': 'MySQL Authentication Bypass',
        },
    ])

    server = ScenarioAuthoringMCPServer()
    created = _tool_call(server, 'scenario.create_draft', {'name': 'DescriptionAliasScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    updated = _tool_call(server, 'scenario.add_vulnerability_item', {
        'draft_id': draft_id,
        'description': 'mysql vulnerability',
    })

    added_item = updated.get('added_item') or {}
    assert added_item.get('selected') == 'Specific'
    assert added_item.get('v_name') == 'mysql/CVE-2012-2122'


def test_mcp_add_vulnerability_item_can_reuse_last_search_results(monkeypatch):
    import MCP.server as mcp_server

    monkeypatch.setattr(mcp_server, 'load_vuln_catalog', lambda repo_root: [
        {
            'Name': 'mysql/CVE-2012-2122',
            'Path': 'https://github.com/vulhub/vulhub/tree/master/mysql/CVE-2012-2122',
            'Type': 'docker-compose',
            'Vector': 'remote',
            'CVE': 'CVE-2012-2122',
            'Description': 'MySQL Authentication Bypass',
        },
    ])

    server = ScenarioAuthoringMCPServer()
    created = _tool_call(server, 'scenario.create_draft', {'name': 'ReuseSearchScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    searched = _tool_call(server, 'scenario.search_vulnerability_catalog', {'query': 'mysql vulnerability'})
    assert searched.get('count') == 1

    updated = _tool_call(server, 'scenario.add_vulnerability_item', {
        'draft_id': draft_id,
        'v_count': 1,
    })

    added_item = updated.get('added_item') or {}
    assert added_item.get('selected') == 'Specific'
    assert added_item.get('v_name') == 'mysql/CVE-2012-2122'


def test_mcp_add_vulnerability_item_preserves_prior_search_when_followup_query_misses(monkeypatch):
    import MCP.server as mcp_server

    monkeypatch.setattr(mcp_server, 'load_vuln_catalog', lambda repo_root: [
        {
            'Name': 'mysql/CVE-2012-2122',
            'Path': 'https://github.com/vulhub/vulhub/tree/master/mysql/CVE-2012-2122',
            'Type': 'docker-compose',
            'Vector': 'remote',
            'CVE': 'CVE-2012-2122',
            'Description': 'MySQL Authentication Bypass',
        },
    ])

    server = ScenarioAuthoringMCPServer()
    created = _tool_call(server, 'scenario.create_draft', {'name': 'PreserveSearchScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    searched = _tool_call(server, 'scenario.search_vulnerability_catalog', {'query': 'mysql vulnerability'})
    assert searched.get('count') == 1

    updated = _tool_call(server, 'scenario.add_vulnerability_item', {
        'draft_id': draft_id,
        'name': 'sql',
        'v_count': 1,
    })

    added_item = updated.get('added_item') or {}
    assert added_item.get('selected') == 'Specific'
    assert added_item.get('v_name') == 'mysql/CVE-2012-2122'


def test_mcp_replace_section_canonicalizes_specific_vulnerability_from_matching_path(monkeypatch):
    import MCP.server as mcp_server

    monkeypatch.setattr(mcp_server, 'load_vuln_catalog', lambda repo_root: [
        {
            'Name': 'jboss/CVE-2017-12149',
            'Path': 'https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149',
            'Type': 'docker-compose',
            'Vector': 'remote',
            'CVE': 'CVE-2017-12149',
            'Description': 'JBoss Java deserialization',
        },
    ])

    server = ScenarioAuthoringMCPServer()
    created = _tool_call(server, 'scenario.create_draft', {'name': 'ReplaceCanonicalizeScenario'})
    draft_id = (created.get('draft') or {}).get('draft_id')

    updated = _tool_call(server, 'scenario.replace_section', {
        'draft_id': draft_id,
        'section_name': 'Vulnerabilities',
        'section_payload': {
            'density': 0,
            'flag_type': 'text',
            'items': [
                {
                    'selected': 'Specific',
                    'v_metric': 'Count',
                    'v_count': 1,
                    'v_name': 'jboss',
                    'v_path': 'https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149',
                },
            ],
        },
    })

    vuln_items = (((updated.get('draft') or {}).get('scenario') or {}).get('sections') or {}).get('Vulnerabilities', {}).get('items') or []
    assert len(vuln_items) == 1
    assert vuln_items[0].get('v_name') == 'jboss/CVE-2017-12149'
    assert vuln_items[0].get('v_path') == 'https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149'


def test_mcp_returns_error_for_missing_draft():
    server = ScenarioAuthoringMCPServer()
    response = server.handle_message({
        'jsonrpc': '2.0',
        'id': 4,
        'method': 'tools/call',
        'params': {
            'name': 'scenario.get_draft',
            'arguments': {'draft_id': 'missing'},
        },
    })
    assert response is not None
    error = response.get('error') or {}
    assert error.get('code') == -32001
    assert 'Unknown draft_id' in (error.get('message') or '')