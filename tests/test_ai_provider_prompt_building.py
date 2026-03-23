import json

from webapp.routes import ai_provider


def _scenario_payload(name='PromptBuildScenario'):
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


def test_ollama_prompt_uses_generic_compiler_guidance_for_segmentation_only_request():
    prompt = ai_provider._build_ollama_prompt(
        _scenario_payload(),
        'Create a network with 2 firewall segments and 1 nat segment.',
    )
    rules = json.loads(prompt)
    instructions = rules.get('instructions') or []
    joined = '\n'.join(str(item) for item in instructions)

    assert 'Treat compiler-seeded sections in the template as authoritative for explicit structured requests: Segmentation.' in joined
    assert 'Preserve those seeded rows unless the user request clearly requires different values.' in joined
    assert 'Node Information and Routing rows' not in joined
    assert 'There is no r2h field.' not in joined


def test_ollama_repair_prompt_only_adds_vulnerability_guidance_when_vulnerabilities_are_seeded(monkeypatch):
    monkeypatch.setattr(
        ai_provider.app_backend,
        '_load_backend_vuln_catalog_items',
        lambda: [
            {
                'Name': 'appweb/CVE-2018-8715',
                'Path': '/catalog/appweb/CVE-2018-8715/docker-compose.yml',
                'Description': 'Web server vulnerability',
            }
        ],
    )

    vuln_prompt = ai_provider._build_ollama_repair_prompt(
        _scenario_payload(),
        'Create a network with 1 web vulnerability.',
        '{}',
    )
    vuln_rules = json.loads(vuln_prompt)
    vuln_joined = '\n'.join(str(item) for item in (vuln_rules.get('instructions') or []))

    traffic_prompt = ai_provider._build_ollama_repair_prompt(
        _scenario_payload(),
        'Create a network with two tcp flows.',
        '{}',
    )
    traffic_rules = json.loads(traffic_prompt)
    traffic_joined = '\n'.join(str(item) for item in (traffic_rules.get('instructions') or []))

    assert 'concrete Specific rows with explicit v_name and v_path from catalog matches' in vuln_joined
    assert 'concrete Specific rows with explicit v_name and v_path from catalog matches' not in traffic_joined
    assert 'backend-supported pattern labels only' in traffic_joined


def test_direct_ai_provider_import_registers_ai_routes_on_backend_app():
    app = ai_provider.app_backend.app
    rules = {rule.rule for rule in app.url_map.iter_rules()}

    assert '/api/ai/generate_scenario_preview' in rules
    assert '/api/ai/generate_scenario_preview_stream' in rules
    assert '/api/ai/generate_scenario_preview_stream/cancel' in rules