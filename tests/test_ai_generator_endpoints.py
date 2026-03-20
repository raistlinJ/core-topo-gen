import json
import asyncio
import threading
import time
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError, URLError

from webapp.app_backend import app


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def _scenario_payload(name='AiScenario'):
    return {
        'name': name,
        'base': {'filepath': ''},
        'sections': {
            'Node Information': {'density': 0, 'items': [{'selected': 'PC', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0}]},
            'Routing': {'density': 0.0, 'items': []},
            'Services': {'density': 0.0, 'items': []},
            'Traffic': {'density': 0.0, 'items': []},
            'Vulnerabilities': {'density': 0.0, 'items': [], 'flag_type': 'text'},
            'Segmentation': {'density': 0.0, 'items': []},
        },
        'notes': '',
    }


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload
        self._lines = None

    def read(self):
        return json.dumps(self._payload).encode('utf-8')

    def __iter__(self):
        return iter(self._lines or [])

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _FakeStreamingResponse(_FakeResponse):
    def __init__(self, lines):
        super().__init__({})
        self._lines = lines


def _fake_ollama_urlopen_factory(*, generated_payload, models=None):
    discovered_models = list(models or ['gpt-oss:20b'])

    def fake_urlopen(request_obj, timeout=0):
        url = request_obj.full_url
        if url.endswith('/api/tags'):
            return _FakeResponse({'models': [{'name': name} for name in discovered_models]})
        assert url.endswith('/api/generate')
        body = json.loads(request_obj.data.decode('utf-8'))
        assert body.get('model') in discovered_models
        if body.get('stream') is True:
            raw = json.dumps(generated_payload)
            return _FakeStreamingResponse([
                json.dumps({'response': raw, 'done': False}).encode('utf-8') + b'\n',
                json.dumps({'response': '', 'done': True}).encode('utf-8') + b'\n',
            ])
        assert body.get('stream') is False
        assert isinstance(body.get('format'), dict)
        return _FakeResponse({'response': json.dumps(generated_payload)})

    return fake_urlopen


def _fake_litellm_urlopen_factory(*, generated_payload, models=None, expected_api_key='test-litellm-key'):
    discovered_models = list(models or ['gpt-4o-mini'])

    def fake_urlopen(request_obj, timeout=0):
        url = request_obj.full_url
        auth_header = request_obj.headers.get('Authorization')
        if expected_api_key:
            assert auth_header == f'Bearer {expected_api_key}'
        if url.endswith('/v1/models') or url.endswith('/models'):
            return _FakeResponse({'data': [{'id': name} for name in discovered_models]})
        assert url.endswith('/v1/chat/completions') or url.endswith('/chat/completions')
        body = json.loads(request_obj.data.decode('utf-8'))
        assert body.get('model') in discovered_models
        assert body.get('response_format') == {'type': 'json_object'}
        content = json.dumps(generated_payload)
        return _FakeResponse({'choices': [{'message': {'role': 'assistant', 'content': content}}]})

    return fake_urlopen


class _FakeTool:
    def __init__(self, name, description, input_schema=None):
        self.name = name
        self.description = description
        self.inputSchema = input_schema or {'type': 'object'}


class _FakeToolText:
    def __init__(self, text):
        self.text = text


class _FakeToolResult:
    def __init__(self, payload):
        self.content = [_FakeToolText(json.dumps(payload))]
        self.isError = False


class _FakeErrorToolResult:
    def __init__(self, payload):
        self.content = [_FakeToolText(json.dumps(payload))]
        self.isError = True


def _fake_bridge_generation_result(name='BridgeFallbackScenario'):
    return {
        'provider': 'ollama',
        'bridge_mode': 'mcp-python-sdk',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'llama3.1',
        'prompt_used': 'fallback prompt',
        'provider_response': 'Updated draft via MCP bridge fallback.',
        'generated_scenario': {
            'name': name,
            'notes': 'Recovered through MCP bridge fallback.',
            'sections': {
                'Node Information': {
                    'density': 0,
                    'items': [
                        {'selected': 'PC', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0},
                    ],
                },
                'Routing': {'density': 0.0, 'items': []},
                'Services': {'density': 0.0, 'items': []},
                'Traffic': {'density': 0.0, 'items': []},
                'Vulnerabilities': {'density': 0.0, 'items': [], 'flag_type': 'text'},
                'Segmentation': {'density': 0.0, 'items': []},
            },
        },
        'preview': {'hosts': [{}, {}], 'routers': [], 'switches': []},
        'plan': {},
        'flow_meta': {},
        'breakdowns': None,
        'bridge_tools': [],
        'enabled_tools': ['server.scenario.create_draft', 'server.scenario.preview_draft'],
        'draft_id': 'draft-fallback-1',
        'count_intent_mismatch': None,
        'count_intent_retry_used': False,
        'prompt_coverage_mismatch': None,
        'prompt_coverage_retry_used': False,
    }


class _ClosableResponse:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class _AbortableClient:
    def __init__(self):
        self.abort_current_query = False


class _FakeSession:
    def __init__(self, client):
        self._client = client

    async def call_tool(self, tool_name, tool_args):
        if tool_name == 'scenario.create_draft':
            scenario = json.loads(json.dumps(tool_args.get('scenario') or _scenario_payload('BridgeScenario')))
            self._client._draft = {
                'draft_id': 'draft-bridge-1',
                'scenario': scenario,
            }
            return _FakeToolResult({'draft': self._client._draft})
        if tool_name == 'scenario.get_draft':
            return _FakeToolResult({'draft': self._client._draft})
        if tool_name == 'scenario.preview_draft':
            scenario = self._client._draft['scenario']
            host_count = 0
            try:
                host_count = int((scenario.get('sections', {}).get('Node Information', {}).get('items') or [{}])[0].get('v_count') or 0)
            except Exception:
                host_count = 0
            return _FakeToolResult({
                'draft': self._client._draft,
                'preview': {'hosts': [{'id': idx + 1} for idx in range(host_count)], 'routers': [], 'switches': []},
                'plan': {'seed': 1234},
                'flow_meta': {},
            })
        raise AssertionError(f'unexpected tool call: {tool_name}')


class _RaisingToolSession:
    async def call_tool(self, tool_name, tool_args):
        raise RuntimeError('Node Information selected must be one of: Server, Workstation, PC, Docker, or Random')


class _ErrorResultSession:
    async def call_tool(self, tool_name, tool_args):
        return _FakeErrorToolResult({'error': 'Node Information selected must be one of: Server, Workstation, PC, Docker, or Random'})


class _FakeToolManager:
    def __init__(self):
        self._tools = [
            _FakeTool('server.scenario.create_draft', '[server] create draft'),
            _FakeTool('server.scenario.get_draft', '[server] get draft'),
            _FakeTool('server.scenario.preview_draft', '[server] preview draft'),
            _FakeTool('server.scenario.replace_section', '[server] replace section'),
        ]
        self._enabled = {tool.name: True for tool in self._tools}

    def set_available_tools(self, tools):
        self._tools = tools

    def set_enabled_tools(self, enabled_tools):
        self._enabled = dict(enabled_tools)

    def get_available_tools(self):
        return self._tools

    def get_enabled_tools(self):
        return dict(self._enabled)

    def set_tool_status(self, tool_name, enabled):
        if tool_name in self._enabled:
            self._enabled[tool_name] = enabled


class _FakeHilManager:
    def __init__(self):
        self.enabled = True
        self.session_auto_execute = False

    def set_enabled(self, enabled):
        self.enabled = enabled

    def set_session_auto_execute(self, enabled):
        self.session_auto_execute = enabled


class _FakeMcpBridgeClient:
    def __init__(self, model='qwen2.5:7b', host='http://localhost:11434'):
        self.model = model
        self.host = host
        self.sessions = {}
        self.tool_manager = _FakeToolManager()
        self.hil_manager = _FakeHilManager()
        self._draft = None

    async def connect_to_servers(self, server_paths=None, server_urls=None, config_path=None, auto_discovery=False):
        self.sessions = {'server': {'session': _FakeSession(self)}}

    async def process_query(self, query):
        assert 'draft-bridge-1' in query
        assert 'Enabled tools:' in query
        scenario = self._draft['scenario']
        scenario['name'] = 'BridgeGeneratedScenario'
        scenario['notes'] = 'Generated through MCP bridge.'
        scenario['sections']['Node Information'] = {
            'density': 0,
            'total_nodes': 0,
            'items': [{'selected': 'PC', 'v_metric': 'Count', 'v_count': 3, 'factor': 1.0}],
        }
        return 'Updated draft via MCP tools.'

    async def cleanup(self):
        return None


class _FailingMcpBridgeClient(_FakeMcpBridgeClient):
    async def process_query(self, query):
        raise RuntimeError('No vulnerability catalog match found; provide v_name/v_path or refine the query')


class _UnknownDraftOnceSession(_FakeSession):
    async def call_tool(self, tool_name, tool_args):
        if tool_name == 'scenario.get_draft' and getattr(self._client, '_fail_unknown_draft_once', False):
            self._client._fail_unknown_draft_once = False
            raise RuntimeError(f"Unknown draft_id: {tool_args.get('draft_id')}")
        return await super().call_tool(tool_name, tool_args)


class _UnknownDraftOnceMcpBridgeClient(_FakeMcpBridgeClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._fail_unknown_draft_once = True

    async def connect_to_servers(self, server_paths=None, server_urls=None, config_path=None, auto_discovery=False):
        self.sessions = {'server': {'session': _UnknownDraftOnceSession(self)}}


def test_save_xml_api_roundtrip_preserves_ai_generator_state(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    scenario = _scenario_payload('AiPersistedScenario')
    scenario['ai_generator'] = {
        'provider': 'ollama',
        'bridge_mode': 'mcp-python-sdk',
        'hil_enabled': True,
        'base_url': 'http://127.0.0.1:11434',
        'api_key': 'persist-me',
        'enforce_ssl': True,
        'model': 'llama3.1',
        'mcp_server_path': 'MCP/server.py',
        'mcp_server_url': 'http://127.0.0.1:9090/mcp',
        'servers_json_path': 'MCP/mcp-bridge-servers.json',
        'auto_discovery': True,
        'available_tools': [
            {'name': 'server.scenario.create_draft', 'server_name': 'server', 'tool_name': 'scenario.create_draft', 'description': 'create'},
            {'name': 'server.scenario.preview_draft', 'server_name': 'server', 'tool_name': 'scenario.preview_draft', 'description': 'preview'},
        ],
        'enabled_tools': ['server.scenario.create_draft', 'server.scenario.preview_draft'],
        'draft_id': 'draft-ai-1',
        'draft_prompt': 'Build an offline lab with two hosts.',
        'prompt_packet': '{"prompt":"Build an offline lab with two hosts."}',
        'last_packet_at': '2026-03-07T22:05:00Z',
        'last_generation_summary': {'routers': 1, 'hosts': 2, 'switches': 1, 'seed': 1234},
        'last_generation_error': '',
        'prompt_coverage_mismatch': {
            'reasons': ['Traffic missing requested selected_values: UDP'],
            'missing_values': [
                {
                    'target': 'Traffic',
                    'field': 'selected_values',
                    'expected_values': ['TCP', 'UDP'],
                    'missing_values': ['UDP'],
                    'actual_values': ['TCP'],
                    'reason': 'user explicitly requested these traffic protocols',
                },
            ],
        },
        'prompt_coverage_retry_used': True,
        'validation': {
            'ok': True,
            'in_progress': False,
            'ollama_ok': True,
            'bridge_ok': True,
            'checked_at': '2026-03-07T22:06:00Z',
            'message': 'Connection validated.',
            'models': ['llama3.1', 'qwen2.5:32b'],
            'model_found': True,
            'provider': 'ollama',
        },
    }

    resp = client.post('/save_xml_api', data=json.dumps({'scenarios': [scenario]}), content_type='application/json')
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('ok') is True

    xml_path = payload.get('result_path')
    parsed = backend._parse_scenarios_xml(xml_path)
    scenarios = parsed.get('scenarios') or []
    assert len(scenarios) == 1
    restored = scenarios[0].get('ai_generator') or {}
    assert restored.get('provider') == 'ollama'
    assert restored.get('bridge_mode') == 'mcp-python-sdk'
    assert restored.get('hil_enabled') is True
    assert restored.get('base_url') == 'http://127.0.0.1:11434'
    assert restored.get('api_key') == 'persist-me'
    assert restored.get('enforce_ssl') is True
    assert restored.get('model') == 'llama3.1'
    assert restored.get('mcp_server_path') == 'MCP/server.py'
    assert restored.get('mcp_server_url') == 'http://127.0.0.1:9090/mcp'
    assert restored.get('servers_json_path') == 'MCP/mcp-bridge-servers.json'
    assert restored.get('auto_discovery') is True
    assert restored.get('draft_id') == 'draft-ai-1'
    assert restored.get('draft_prompt') == 'Build an offline lab with two hosts.'
    assert restored.get('prompt_packet') == '{"prompt":"Build an offline lab with two hosts."}'
    assert restored.get('last_packet_at') == '2026-03-07T22:05:00Z'
    assert restored.get('enabled_tools') == ['server.scenario.create_draft', 'server.scenario.preview_draft']
    assert len(restored.get('available_tools') or []) == 2
    assert (restored.get('last_generation_summary') or {}).get('hosts') == 2
    assert restored.get('prompt_coverage_retry_used') is True
    assert (restored.get('prompt_coverage_mismatch') or {}).get('reasons') == ['Traffic missing requested selected_values: UDP']
    validation = restored.get('validation') or {}
    assert validation.get('ok') is True
    assert validation.get('ollama_ok') is True
    assert validation.get('bridge_ok') is True
    assert validation.get('message') == 'Connection validated.'
    assert validation.get('models') == ['llama3.1', 'qwen2.5:32b']


def test_ai_generate_scenario_preview_uses_ollama_and_returns_preview(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    generated = {
        'scenario': {
            'name': 'GeneratedOfflineScenario',
            'density_count': 0,
            'notes': 'Generated by mocked ollama.',
            'sections': {
                'Node Information': {
                    'density': 0,
                    'items': [
                        {'selected': 'PC', 'v_metric': 'Count', 'v_count': 3, 'factor': 1.0},
                    ],
                },
                'Routing': {'density': 0.0, 'items': []},
                'Services': {'density': 0.0, 'items': []},
                'Traffic': {'density': 0.0, 'items': []},
                'Vulnerabilities': {'density': 0.0, 'items': [], 'flag_type': 'text'},
                'Segmentation': {'density': 0.0, 'items': []},
            },
        }
    }

    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_ollama_urlopen_factory(generated_payload=generated, models=['llama3.1']),
    )

    scenario = _scenario_payload('PromptSeedScenario')
    scenario['ai_generator'] = {
        'provider': 'ollama',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'llama3.1',
    }

    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'prompt': 'Generate a small offline scenario with three PCs.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('success') is True
    assert payload.get('generated_scenario', {}).get('name') == 'PromptSeedScenario'
    assert payload.get('generated_scenario', {}).get('notes') == 'Generated by mocked ollama.'
    preview = payload.get('preview') or {}
    hosts = preview.get('hosts') or []
    assert len(hosts) == 3


def test_ai_generate_scenario_preview_intent_compiler_overrides_llm_topology_rows(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    generated = {
        'scenario': {
            'name': 'CompilerOverrideScenario',
            'density_count': 0,
            'notes': 'Generated by mocked ollama.',
            'sections': {
                'Node Information': {
                    'density': 0,
                    'items': [
                        {'selected': 'Server', 'v_metric': 'Count', 'v_count': 99, 'factor': 1.0},
                    ],
                },
                'Routing': {
                    'density': 0.0,
                    'items': [
                        {'selected': 'BGP', 'v_metric': 'Count', 'v_count': 99, 'factor': 1.0},
                    ],
                },
                'Services': {'density': 0.0, 'items': []},
                'Traffic': {'density': 0.0, 'items': []},
                'Vulnerabilities': {'density': 0.0, 'items': [], 'flag_type': 'text'},
                'Segmentation': {'density': 0.0, 'items': []},
            },
        }
    }

    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_ollama_urlopen_factory(generated_payload=generated, models=['llama3.1']),
    )

    scenario = _scenario_payload('CompilerOverrideScenario')
    scenario['ai_generator'] = {
        'provider': 'ollama',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'llama3.1',
    }

    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'prompt': 'Create a topology with 12 nodes and 3 routers.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    generated_scenario = payload.get('generated_scenario') or {}
    node_items = (((generated_scenario.get('sections') or {}).get('Node Information')) or {}).get('items') or []
    routing_items = (((generated_scenario.get('sections') or {}).get('Routing')) or {}).get('items') or []
    assert node_items == [{'selected': 'PC', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 9}]
    assert len(routing_items) == 1
    assert routing_items[0].get('selected') == 'OSPFv2'
    assert routing_items[0].get('v_metric') == 'Count'
    assert routing_items[0].get('v_count') == 3


def test_ai_generate_scenario_preview_compiler_overrides_services_and_traffic_rows(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    generated = {
        'scenario': {
            'name': 'CompilerServicesTrafficScenario',
            'density_count': 0,
            'notes': 'Generated by mocked ollama.',
            'sections': {
                'Node Information': {'density': 0, 'items': [{'selected': 'Server', 'v_metric': 'Count', 'v_count': 99, 'factor': 1.0}]},
                'Routing': {'density': 0.0, 'items': [{'selected': 'BGP', 'v_metric': 'Count', 'v_count': 99, 'factor': 1.0}]},
                'Services': {'density': 0.0, 'items': [{'selected': 'DHCPClient', 'v_metric': 'Count', 'v_count': 99, 'factor': 1.0}]},
                'Traffic': {'density': 0.0, 'items': [{'selected': 'UDP', 'pattern': 'continuous', 'v_metric': 'Count', 'v_count': 99, 'factor': 1.0, 'content_type': 'text'}]},
                'Vulnerabilities': {'density': 0.0, 'items': [], 'flag_type': 'text'},
                'Segmentation': {'density': 0.0, 'items': []},
            },
        }
    }

    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_ollama_urlopen_factory(generated_payload=generated, models=['llama3.1']),
    )

    scenario = _scenario_payload('CompilerServicesTrafficScenario')
    scenario['ai_generator'] = {
        'provider': 'ollama',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'llama3.1',
    }

    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'prompt': 'create a network with 10 nodes, 2 routers, two ssh and one web service, plus two tcp and one udp flows, and two periodic and one burst flows',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    generated_scenario = payload.get('generated_scenario') or {}
    services_items = (((generated_scenario.get('sections') or {}).get('Services')) or {}).get('items') or []
    traffic_items = (((generated_scenario.get('sections') or {}).get('Traffic')) or {}).get('items') or []
    assert services_items == [
        {'selected': 'SSH', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 2},
        {'selected': 'HTTP', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 1},
    ]
    assert len(traffic_items) == 2
    assert traffic_items[0].get('selected') == 'TCP'
    assert traffic_items[0].get('v_metric') == 'Count'
    assert traffic_items[0].get('v_count') == 2
    assert traffic_items[0].get('pattern') == 'periodic'
    assert traffic_items[0].get('content_type') == 'text'
    assert traffic_items[1].get('selected') == 'UDP'
    assert traffic_items[1].get('v_metric') == 'Count'
    assert traffic_items[1].get('v_count') == 1
    assert traffic_items[1].get('pattern') == 'burst'
    assert traffic_items[1].get('content_type') == 'text'


def test_ai_generate_scenario_preview_compiler_overrides_vulnerability_rows_and_allocates_docker_targets(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(
        backend,
        '_load_backend_vuln_catalog_items',
        lambda: [
            {'Name': 'appweb/CVE-2018-8715', 'Path': '/catalog/appweb/CVE-2018-8715/docker-compose.yml', 'Description': 'Web server vulnerability'},
            {'Name': 'jboss/CVE-2017-12149', 'Path': '/catalog/jboss/CVE-2017-12149/docker-compose.yml', 'Description': 'JBoss Java deserialization'},
        ],
    )

    generated = {
        'scenario': {
            'name': 'CompilerVulnScenario',
            'density_count': 0,
            'notes': 'Generated by mocked ollama.',
            'sections': {
                'Node Information': {'density': 0, 'items': [{'selected': 'Server', 'v_metric': 'Count', 'v_count': 99, 'factor': 1.0}]},
                'Routing': {'density': 0.0, 'items': [{'selected': 'BGP', 'v_metric': 'Count', 'v_count': 99, 'factor': 1.0}]},
                'Services': {'density': 0.0, 'items': []},
                'Traffic': {'density': 0.0, 'items': []},
                'Vulnerabilities': {
                    'density': 0.0,
                    'items': [
                        {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'bogus', 'v_path': '/bad/path'},
                    ],
                    'flag_type': 'text',
                },
                'Segmentation': {'density': 0.0, 'items': []},
            },
        }
    }

    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_ollama_urlopen_factory(generated_payload=generated, models=['llama3.1']),
    )

    scenario = _scenario_payload('CompilerVulnScenario')
    scenario['ai_generator'] = {
        'provider': 'ollama',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'llama3.1',
    }

    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'prompt': 'Create a network with 12 nodes, 3 routers, and 2 web vulnerabilities.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    generated_scenario = payload.get('generated_scenario') or {}
    node_items = (((generated_scenario.get('sections') or {}).get('Node Information')) or {}).get('items') or []
    vuln_items = (((generated_scenario.get('sections') or {}).get('Vulnerabilities')) or {}).get('items') or []

    assert node_items == [
        {'selected': 'PC', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 7},
        {'selected': 'Docker', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 2},
    ]
    assert vuln_items == [
        {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'appweb/CVE-2018-8715', 'v_path': '/catalog/appweb/CVE-2018-8715/docker-compose.yml'},
        {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'jboss/CVE-2017-12149', 'v_path': '/catalog/jboss/CVE-2017-12149/docker-compose.yml'},
    ]


def test_ai_generate_scenario_preview_compiler_overrides_segmentation_rows(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    generated = {
        'scenario': {
            'name': 'CompilerSegmentationScenario',
            'density_count': 0,
            'notes': 'Generated by mocked ollama.',
            'sections': {
                'Node Information': {'density': 0, 'items': [{'selected': 'PC', 'v_metric': 'Count', 'v_count': 4, 'factor': 1.0}]},
                'Routing': {'density': 0.0, 'items': []},
                'Services': {'density': 0.0, 'items': []},
                'Traffic': {'density': 0.0, 'items': []},
                'Vulnerabilities': {'density': 0.0, 'items': [], 'flag_type': 'text'},
                'Segmentation': {'density': 0.0, 'items': [{'selected': 'Random', 'factor': 1.0}]},
            },
        }
    }

    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_ollama_urlopen_factory(generated_payload=generated, models=['llama3.1']),
    )

    scenario = _scenario_payload('CompilerSegmentationScenario')
    scenario['ai_generator'] = {
        'provider': 'ollama',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'llama3.1',
    }

    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'prompt': 'Create a network with 2 firewall segments and 1 nat segment.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    generated_scenario = payload.get('generated_scenario') or {}
    segmentation_items = (((generated_scenario.get('sections') or {}).get('Segmentation')) or {}).get('items') or []

    assert segmentation_items == [
        {'selected': 'Firewall', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 2},
        {'selected': 'NAT', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 1},
    ]


def test_ai_provider_validate_litellm_uses_optional_api_key_and_ssl(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp.routes import ai_provider

    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_litellm_urlopen_factory(generated_payload={'scenario': _scenario_payload('unused')}, models=['gpt-4o-mini']),
    )
    monkeypatch.setattr(ai_provider, 'McpBridgeClient', _FakeMcpBridgeClient)

    resp = client.post(
        '/api/ai/provider/validate',
        json={
            'provider': 'litellm',
            'base_url': 'https://litellm.example.com/v1',
            'api_key': 'test-litellm-key',
            'enforce_ssl': True,
            'model': 'gpt-4o-mini',
            'bridge_mode': 'mcp-python-sdk',
            'mcp_server_path': 'MCP/server.py',
            'enabled_tools': ['server.scenario.replace_section'],
        },
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('success') is True
    assert payload.get('provider') == 'litellm'
    assert payload.get('model_found') is True
    assert payload.get('enforce_ssl') is True
    assert payload.get('bridge', {}).get('bridge_mode') == 'mcp-python-sdk'
    tool_names = [tool.get('name') for tool in (payload.get('tools') or [])]
    assert 'server.scenario.replace_section' in tool_names
    assert payload.get('enabled_tools') == ['server.scenario.replace_section']
    assert 'gpt-4o-mini' in (payload.get('models') or [])


def test_ai_provider_catalog_includes_litellm_and_bridge_capabilities() -> None:
    client = app.test_client()
    _login(client)

    resp = client.get('/api/ai/providers')
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('success') is True
    providers = payload.get('providers') or []
    provider_map = {
        str(entry.get('provider') or '').strip().lower(): entry
        for entry in providers
        if isinstance(entry, dict)
    }
    assert 'litellm' in provider_map
    assert provider_map['litellm'].get('enabled') is True
    assert provider_map['litellm'].get('supports_mcp_bridge') is True
    assert provider_map['litellm'].get('default_base_url') == 'https://localhost:4000/v1'
    assert provider_map['ollama'].get('supports_mcp_bridge') is True


def test_ai_provider_validate_skip_bridge_refreshes_litellm_models_without_mcp(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp.routes import ai_provider

    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_litellm_urlopen_factory(generated_payload={'scenario': _scenario_payload('unused')}, models=['gpt-4o-mini', 'gpt-4.1-mini']),
    )

    def _unexpected_client(*args, **kwargs):
        raise AssertionError('MCP Python SDK bridge should not be initialized when skip_bridge is true')

    monkeypatch.setattr(ai_provider, 'McpBridgeClient', _unexpected_client)

    resp = client.post(
        '/api/ai/provider/validate',
        json={
            'provider': 'litellm',
            'bridge_mode': 'mcp-python-sdk',
            'skip_bridge': True,
            'base_url': 'https://litellm.example.com/v1',
            'api_key': 'test-litellm-key',
            'enforce_ssl': True,
            'model': 'gpt-4o-mini',
            'mcp_server_path': 'MCP/server.py',
        },
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('success') is True
    assert payload.get('bridge') is None
    assert payload.get('tools') is None
    assert 'gpt-4o-mini' in (payload.get('models') or [])
    assert 'gpt-4.1-mini' in (payload.get('models') or [])


def test_ai_provider_validate_litellm_rejects_http_when_ssl_enforced(tmp_path):
    client = app.test_client()
    _login(client)

    resp = client.post(
        '/api/ai/provider/validate',
        json={
            'provider': 'litellm',
            'base_url': 'http://litellm.example.com/v1',
            'enforce_ssl': True,
            'model': 'gpt-4o-mini',
        },
    )
    assert resp.status_code == 400
    payload = resp.get_json() or {}
    assert 'https' in str(payload.get('error') or '').lower()


def test_ai_generate_scenario_preview_uses_litellm_direct_provider(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    generated = {
        'scenario': {
            'name': 'GeneratedLiteLlmScenario',
            'density_count': 0,
            'notes': 'Generated by mocked litellm.',
            'sections': {
                'Node Information': {
                    'density': 0,
                    'items': [
                        {'selected': 'PC', 'v_metric': 'Count', 'v_count': 3, 'factor': 1.0},
                    ],
                },
                'Routing': {'density': 0.0, 'items': []},
                'Services': {'density': 0.0, 'items': []},
                'Traffic': {'density': 0.0, 'items': []},
                'Vulnerabilities': {'density': 0.0, 'items': [], 'flag_type': 'text'},
                'Segmentation': {'density': 0.0, 'items': []},
            },
        }
    }

    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_litellm_urlopen_factory(generated_payload=generated, models=['gpt-4o-mini']),
    )

    scenario = _scenario_payload('LiteLlmPromptScenario')
    scenario['ai_generator'] = {
        'provider': 'litellm',
        'base_url': 'https://litellm.example.com/v1',
        'api_key': 'test-litellm-key',
        'enforce_ssl': True,
        'model': 'gpt-4o-mini',
    }

    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'litellm',
            'base_url': 'https://litellm.example.com/v1',
            'api_key': 'test-litellm-key',
            'enforce_ssl': True,
            'model': 'gpt-4o-mini',
            'bridge_mode': 'mcp-python-sdk',
            'skip_bridge': True,
            'prompt': 'Generate a small offline scenario with three PCs.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('success') is True
    assert payload.get('provider') == 'litellm'
    assert payload.get('generated_scenario', {}).get('name') == 'LiteLlmPromptScenario'
    assert payload.get('generated_scenario', {}).get('notes') == 'Generated by mocked litellm.'
    assert len((payload.get('preview') or {}).get('hosts') or []) == 3
    attempts = payload.get('provider_attempts') or []
    assert attempts
    assert attempts[0].get('format_mode') == 'json_object'


def test_ai_generate_scenario_preview_uses_mcp_python_sdk_bridge_for_litellm(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_litellm_urlopen_factory(generated_payload={'scenario': _scenario_payload('unused')}, models=['gpt-4o-mini']),
    )
    monkeypatch.setattr(ai_provider, 'McpBridgeClient', _FakeMcpBridgeClient)

    scenario = _scenario_payload('LiteLlmBridgeScenario')
    scenario['ai_generator'] = {
        'provider': 'litellm',
        'bridge_mode': 'mcp-python-sdk',
        'base_url': 'https://litellm.example.com/v1',
        'api_key': 'test-litellm-key',
        'enforce_ssl': True,
        'model': 'gpt-4o-mini',
        'mcp_server_path': 'MCP/server.py',
        'enabled_tools': ['server.scenario.replace_section'],
    }

    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'litellm',
            'bridge_mode': 'mcp-python-sdk',
            'base_url': 'https://litellm.example.com/v1',
            'api_key': 'test-litellm-key',
            'enforce_ssl': True,
            'model': 'gpt-4o-mini',
            'mcp_server_path': 'MCP/server.py',
            'enabled_tools': ['server.scenario.replace_section'],
            'prompt': 'Build a small offline three-host scenario with MCP tools.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('success') is True
    assert payload.get('provider') == 'litellm'
    assert payload.get('bridge_mode') == 'mcp-python-sdk'
    assert payload.get('generated_scenario', {}).get('name') == 'LiteLlmBridgeScenario'
    assert payload.get('generated_scenario', {}).get('notes') == 'Generated through MCP bridge.'
    assert len((payload.get('preview') or {}).get('hosts') or []) == 3
    assert payload.get('enabled_tools') == ['server.scenario.replace_section']


def test_ai_generator_refresh_connection_failure_preserves_existing_mcp_tools_snippets() -> None:
    workflow_text = (Path(__file__).resolve().parent.parent / 'webapp' / 'static' / 'ai_generator_workflow.js').read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        "const nextAvailableTools = data && Array.isArray(data.tools)",
        ": (Array.isArray(aiState.available_tools) ? aiState.available_tools : []);",
        "available_tools: Array.isArray(aiState.available_tools) ? aiState.available_tools : [],",
        "enabled_tools: Array.isArray(aiState.enabled_tools) ? aiState.enabled_tools : [],",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in workflow_text]
    assert not missing, 'Missing MCP tool preservation snippets during AI Generator refresh: ' + '; '.join(missing)


def test_ai_generate_scenario_preview_adds_docker_capacity_for_vuln_targets(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(
        backend,
        '_load_backend_vuln_catalog_items',
        lambda: [{'Name': 'Demo Vuln', 'Path': 'demo/path', 'Description': 'Demo desc'}],
    )

    generated = {
        'scenario': {
            'name': 'GeneratedVulnDockerScenario',
            'density_count': 0,
            'notes': 'Generated with vuln pressure.',
            'sections': {
                'Node Information': {
                    'density': 0,
                    'items': [
                        {'selected': 'Docker', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0},
                        {'selected': 'Server', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0},
                    ],
                },
                'Routing': {'density': 0.0, 'items': []},
                'Services': {'density': 0.0, 'items': []},
                'Traffic': {'density': 0.0, 'items': []},
                'Vulnerabilities': {
                    'density': 0.0,
                    'items': [
                        {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 3, 'v_name': 'Demo Vuln', 'v_path': 'demo/path'},
                    ],
                    'flag_type': 'text',
                },
                'Segmentation': {'density': 0.0, 'items': []},
            },
        }
    }

    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_ollama_urlopen_factory(generated_payload=generated, models=['llama3.1']),
    )

    scenario = _scenario_payload('PromptSeedScenario')
    scenario['ai_generator'] = {
        'provider': 'ollama',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'llama3.1',
    }

    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'prompt': 'Generate two servers and three vulnerable docker targets.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('success') is True
    generated_scenario = payload.get('generated_scenario') or {}
    node_items = ((generated_scenario.get('sections') or {}).get('Node Information') or {}).get('items') or []
    docker_total = sum(
        int(item.get('v_count') or 0)
        for item in node_items
        if isinstance(item, dict) and str(item.get('selected') or '').strip() == 'Docker' and str(item.get('v_metric') or '').strip() == 'Count'
    )
    assert docker_total == 3


def test_ai_generate_scenario_preview_canonicalizes_specific_vuln_name_from_matching_path(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(
        backend,
        '_load_backend_vuln_catalog_items',
        lambda: [{
            'Name': 'jboss/CVE-2017-12149',
            'Path': 'https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149',
            'Description': 'JBoss Java deserialization',
        }],
    )

    generated = {
        'scenario': {
            'name': 'GeneratedJbossScenario',
            'density_count': 0,
            'notes': 'Generated with a JBoss vulnerability.',
            'sections': {
                'Node Information': {'density': 0, 'items': [{'selected': 'Docker', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0}]},
                'Routing': {'density': 0.0, 'items': []},
                'Services': {'density': 0.0, 'items': []},
                'Traffic': {'density': 0.0, 'items': []},
                'Vulnerabilities': {
                    'density': 0.0,
                    'items': [
                        {
                            'selected': 'Specific',
                            'v_metric': 'Count',
                            'v_count': 1,
                            'v_name': 'jboss',
                            'v_path': 'https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149',
                        },
                    ],
                    'flag_type': 'text',
                },
                'Segmentation': {'density': 0.0, 'items': []},
            },
        }
    }

    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_ollama_urlopen_factory(generated_payload=generated, models=['llama3.1']),
    )

    scenario = _scenario_payload('PromptSeedScenario')
    scenario['ai_generator'] = {
        'provider': 'ollama',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'llama3.1',
    }

    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'prompt': 'Add a jboss vulnerability.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    vuln_items = (((payload.get('generated_scenario') or {}).get('sections') or {}).get('Vulnerabilities') or {}).get('items') or []
    assert len(vuln_items) == 1
    assert vuln_items[0].get('v_name') == 'jboss/CVE-2017-12149'
    assert vuln_items[0].get('v_path') == 'https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149'


def test_ai_generate_scenario_preview_rejects_specific_vuln_outside_enabled_catalog(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(
        backend,
        '_load_backend_vuln_catalog_items',
        lambda: [{
            'Name': 'mysql/CVE-2012-2122',
            'Path': 'https://github.com/vulhub/vulhub/tree/master/mysql/CVE-2012-2122',
            'Description': 'MySQL Authentication Bypass',
        }],
    )

    generated = {
        'scenario': {
            'name': 'InvalidJbossScenario',
            'density_count': 0,
            'notes': 'Generated with an invalid vulnerability.',
            'sections': {
                'Node Information': {'density': 0, 'items': [{'selected': 'Docker', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0}]},
                'Routing': {'density': 0.0, 'items': []},
                'Services': {'density': 0.0, 'items': []},
                'Traffic': {'density': 0.0, 'items': []},
                'Vulnerabilities': {
                    'density': 0.0,
                    'items': [
                        {
                            'selected': 'Specific',
                            'v_metric': 'Count',
                            'v_count': 1,
                            'v_name': 'jboss',
                            'v_path': 'https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149',
                        },
                    ],
                    'flag_type': 'text',
                },
                'Segmentation': {'density': 0.0, 'items': []},
            },
        }
    }

    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_ollama_urlopen_factory(generated_payload=generated, models=['llama3.1']),
    )

    scenario = _scenario_payload('PromptSeedScenario')
    scenario['ai_generator'] = {
        'provider': 'ollama',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'llama3.1',
    }

    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'prompt': 'Add a jboss vulnerability.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )
    assert resp.status_code == 400
    payload = resp.get_json() or {}
    assert payload.get('success') is False
    assert 'enabled catalog entry' in str(payload.get('error') or '')


def test_ai_generate_scenario_preview_rejects_unrelated_specific_vuln_substitution(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(
        backend,
        '_load_backend_vuln_catalog_items',
        lambda: [{
            'Name': 'mysql/CVE-2012-2122',
            'Path': 'https://github.com/vulhub/vulhub/tree/master/mysql/CVE-2012-2122',
            'Description': 'MySQL Authentication Bypass',
        }],
    )

    generated = {
        'scenario': {
            'name': 'MysqlSubstitutionScenario',
            'density_count': 0,
            'notes': 'Generated with an unrelated vulnerability substitution.',
            'sections': {
                'Node Information': {'density': 0, 'items': [{'selected': 'Docker', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0}]},
                'Routing': {'density': 0.0, 'items': []},
                'Services': {'density': 0.0, 'items': []},
                'Traffic': {'density': 0.0, 'items': []},
                'Vulnerabilities': {
                    'density': 0.0,
                    'items': [
                        {
                            'selected': 'Specific',
                            'v_metric': 'Count',
                            'v_count': 1,
                            'v_name': 'mysql/CVE-2012-2122',
                            'v_path': 'https://github.com/vulhub/vulhub/tree/master/mysql/CVE-2012-2122',
                        },
                    ],
                    'flag_type': 'text',
                },
                'Segmentation': {'density': 0.0, 'items': []},
            },
        }
    }

    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_ollama_urlopen_factory(generated_payload=generated, models=['llama3.1']),
    )

    scenario = _scenario_payload('PromptSeedScenario')
    scenario['ai_generator'] = {
        'provider': 'ollama',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'llama3.1',
    }

    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'prompt': 'Add a jboss vulnerability.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )

    assert resp.status_code == 400
    payload = resp.get_json() or {}
    assert payload.get('success') is False
    assert 'enabled catalog entry' in str(payload.get('error') or '')


def test_ai_generate_scenario_preview_rebuilds_from_clean_seed_and_drops_old_sections(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    generated = {
        'scenario': {
            'name': 'RebuiltScenario',
            'density_count': 0,
            'notes': 'Freshly rebuilt from the prompt.',
            'sections': {
                'Node Information': {
                    'density': 0,
                    'items': [
                        {'selected': 'PC', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0},
                    ],
                },
                'Routing': {
                    'density': 0.0,
                    'items': [
                        {'selected': 'RIP', 'v_metric': 'Count', 'v_count': 3, 'factor': 1.0, 'r2s_mode': 'Uniform'},
                    ],
                },
                'Services': {'density': 0.0, 'items': []},
                'Traffic': {'density': 0.0, 'items': []},
                'Vulnerabilities': {'density': 0.0, 'items': [], 'flag_type': 'text'},
                'Segmentation': {'density': 0.0, 'items': []},
            },
        }
    }

    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_ollama_urlopen_factory(generated_payload=generated, models=['llama3.1']),
    )

    scenario = _scenario_payload('ExistingScenario')
    scenario['notes'] = 'Old notes that should be replaced.'
    scenario['hitl'] = {
        'enabled': True,
        'proxmox': {'url': 'https://prox.example.local', 'username': 'root@pam'},
        'core': {'grpc_host': 'core.example.local', 'grpc_port': 50051},
        'interfaces': [{'name': 'eth1', 'attachment': 'existing_router'}],
    }
    scenario['sections']['Services'] = {
        'density': 1.0,
        'items': [{'selected': 'HTTP', 'factor': 1.0}],
    }
    scenario['sections']['Traffic'] = {
        'density': 1.0,
        'items': [{'selected': 'iperf', 'factor': 1.0, 'pattern': 'full-mesh'}],
    }

    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'prompt': 'Rebuild this scenario from scratch with 3 routers and 2 hosts.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('success') is True
    generated_scenario = payload.get('generated_scenario') or {}
    assert generated_scenario.get('name') == 'ExistingScenario'
    assert generated_scenario.get('notes') == 'Freshly rebuilt from the prompt.'
    assert (generated_scenario.get('hitl') or {}).get('enabled') is True
    assert ((generated_scenario.get('hitl') or {}).get('core') or {}).get('grpc_host') == 'core.example.local'
    assert (generated_scenario.get('sections') or {}).get('Services', {}).get('items') == []
    assert (generated_scenario.get('sections') or {}).get('Traffic', {}).get('items') == []
    assert 'Events' not in (generated_scenario.get('sections') or {})
    routing_items = (generated_scenario.get('sections') or {}).get('Routing', {}).get('items') or []
    assert routing_items and routing_items[0].get('v_metric') == 'Count'
    assert routing_items[0].get('v_count') == 3
    preview = payload.get('preview') or {}
    assert len(preview.get('hosts') or []) == 2
    assert len(preview.get('routers') or []) > 0


def test_ai_generate_scenario_preview_stream_emits_llm_output_and_result(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    generated = {
        'scenario': {
            'name': 'StreamedScenario',
            'density_count': 0,
            'notes': 'Generated through streamed ollama output.',
            'sections': {
                'Node Information': {
                    'density': 0,
                    'items': [
                        {'selected': 'PC', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0},
                    ],
                },
                'Routing': {'density': 0.0, 'items': []},
                'Services': {'density': 0.0, 'items': []},
                'Traffic': {'density': 0.0, 'items': []},
                'Vulnerabilities': {'density': 0.0, 'items': [], 'flag_type': 'text'},
                'Segmentation': {'density': 0.0, 'items': []},
            },
        }
    }

    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_ollama_urlopen_factory(generated_payload=generated, models=['llama3.1']),
    )

    scenario = _scenario_payload('StreamingPromptScenario')
    scenario['ai_generator'] = {
        'provider': 'ollama',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'llama3.1',
    }
    
    resp = client.post(
        '/api/ai/generate_scenario_preview_stream',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'prompt': 'Generate a streamed scenario with two PCs.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
        buffered=False,
    )
    assert resp.status_code == 200

    events = []
    for chunk in resp.response:
        text = chunk.decode('utf-8') if isinstance(chunk, bytes) else str(chunk)
        for line in text.splitlines():
            if line.strip():
                events.append(json.loads(line))

    assert any(event.get('type') == 'status' for event in events)
    assert any(event.get('type') == 'llm_delta' and 'StreamedScenario' in str(event.get('text') or '') for event in events)
    result_event = next(event for event in events if event.get('type') == 'result')
    result_data = result_event.get('data') or {}
    assert result_data.get('success') is True
    assert result_data.get('generated_scenario', {}).get('name') == 'StreamingPromptScenario'
    assert result_data.get('generated_scenario', {}).get('notes') == 'Generated through streamed ollama output.'


def test_ai_generate_scenario_preview_stream_uses_strict_json_rewrite_after_two_invalid_attempts(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    generated = {
        'scenario': {
            'name': 'StreamedStrictRewriteScenario',
            'density_count': 0,
            'notes': 'Recovered after strict JSON rewrite.',
            'sections': {
                'Node Information': {
                    'density': 0,
                    'items': [
                        {'selected': 'PC', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0},
                    ],
                },
                'Routing': {'density': 0.0, 'items': []},
                'Services': {'density': 0.0, 'items': []},
                'Traffic': {'density': 0.0, 'items': []},
                'Vulnerabilities': {'density': 0.0, 'items': [], 'flag_type': 'text'},
                'Segmentation': {'density': 0.0, 'items': []},
            },
        }
    }

    call_state = {'generate_calls': 0}

    def fake_urlopen(request_obj, timeout=0):
        url = request_obj.full_url
        if url.endswith('/api/tags'):
            return _FakeResponse({'models': [{'name': 'llama3.1'}]})
        assert url.endswith('/api/generate')
        body = json.loads(request_obj.data.decode('utf-8'))
        assert body.get('model') == 'llama3.1'
        if body.get('stream') is True:
            call_state['generate_calls'] += 1
            if call_state['generate_calls'] < 3:
                raw = 'We need to output JSON only, top-level object must be {": {"scenario":{}}}'
            else:
                raw = json.dumps(generated)
            return _FakeStreamingResponse([
                json.dumps({'response': raw, 'done': False}).encode('utf-8') + b'\n',
                json.dumps({'response': '', 'done': True}).encode('utf-8') + b'\n',
            ])
        raise AssertionError('expected streaming generate request')

    monkeypatch.setattr(ai_provider, 'urlopen', fake_urlopen)

    scenario = _scenario_payload('StreamingStrictRewritePromptScenario')
    resp = client.post(
        '/api/ai/generate_scenario_preview_stream',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'prompt': 'Generate a streamed scenario with two PCs.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
        buffered=False,
    )
    assert resp.status_code == 200

    events = []
    for chunk in resp.response:
        text = chunk.decode('utf-8') if isinstance(chunk, bytes) else str(chunk)
        for line in text.splitlines():
            if line.strip():
                events.append(json.loads(line))

    status_messages = [str(event.get('message') or '') for event in events if event.get('type') == 'status']
    assert any('Initial draft was not valid JSON' in message for message in status_messages)
    assert any('strict JSON rewrite' in message for message in status_messages)
    result_event = next(event for event in events if event.get('type') == 'result')
    result_data = result_event.get('data') or {}
    assert result_data.get('success') is True


def test_ai_generate_scenario_preview_stream_times_out_on_hung_ollama_open(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    def fake_urlopen(request_obj, timeout=0):
        url = request_obj.full_url
        if url.endswith('/api/tags'):
            return _FakeResponse({'models': [{'name': 'llama3.1'}]})
        time.sleep(6.0)
        return _FakeStreamingResponse([])

    monkeypatch.setattr(ai_provider, 'urlopen', fake_urlopen)

    scenario = _scenario_payload('StreamingTimeoutPromptScenario')
    resp = client.post(
        '/api/ai/generate_scenario_preview_stream',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'prompt': 'Generate a streamed scenario with two PCs.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
            'timeout_seconds': 5,
        },
        buffered=False,
    )
    assert resp.status_code == 200

    events = []
    for chunk in resp.response:
        text = chunk.decode('utf-8') if isinstance(chunk, bytes) else str(chunk)
        for line in text.splitlines():
            if line.strip():
                events.append(json.loads(line))

    error_event = next(event for event in events if event.get('type') == 'error')
    assert 'could not reach ollama' in str(error_event.get('error') or '').lower()
    assert 'timed out' in str(error_event.get('error') or '').lower()


def test_ai_generate_scenario_preview_falls_back_to_mcp_bridge_after_ollama_json_failure(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    def fake_generate(self, payload, *, current_scenario, user_prompt, log=None):
        raise ai_provider.ProviderAdapterError('Ollama did not return valid JSON for scenario generation.', status_code=502)

    async def fake_bridge_generate(payload, *, current_scenario, user_prompt, model, host):
        return _fake_bridge_generation_result('FallbackPreviewScenario')

    monkeypatch.setattr(ai_provider.OllamaProviderAdapter, 'generate', fake_generate)
    monkeypatch.setattr(ai_provider, '_mcp_bridge_generate', fake_bridge_generate)

    scenario = _scenario_payload('FallbackPreviewScenario')
    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'prompt': 'Generate a scenario with two PCs.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('success') is True
    assert payload.get('bridge_mode') == 'mcp-python-sdk'
    assert payload.get('direct_generation_error') == 'Ollama did not return valid JSON for scenario generation.'
    assert payload.get('generated_scenario', {}).get('name') == 'FallbackPreviewScenario'


def test_ai_generate_scenario_preview_reports_direct_timeout_details(monkeypatch):
    client = app.test_client()
    _login(client)

    from urllib.error import URLError

    from webapp.routes import ai_provider

    def fake_generate_once(self, *, base_url, model, prompt, timeout_seconds):
        raise URLError(TimeoutError('timed out'))

    monkeypatch.setattr(ai_provider.OllamaProviderAdapter, '_generate_once', fake_generate_once)

    scenario = _scenario_payload('TimeoutDetailsScenario')
    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'qwen3.5:35b',
            'prompt': 'Generate a medium scenario with web traffic.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
            'timeout_seconds': 37,
        },
    )

    assert resp.status_code == 502
    payload = resp.get_json() or {}
    assert payload.get('success') is False
    assert 'Could not reach Ollama' in str(payload.get('error') or '')
    assert payload.get('provider_generation_stage') == 'direct_generate'
    assert payload.get('provider_error_category') == 'timeout'
    assert payload.get('provider_current_attempt') == 'initial'
    assert payload.get('timeout_seconds') == 37.0
    assert payload.get('model') == 'qwen3.5:35b'
    attempts = payload.get('provider_attempts') or []
    assert len(attempts) == 1
    assert attempts[0].get('attempt') == 'initial'
    assert attempts[0].get('status') == 'failed'
    assert 'timed out' in str(attempts[0].get('error') or '').lower()


def test_ai_provider_wall_clock_timeout_interrupts_hung_direct_call():
    from webapp.routes import ai_provider

    entered = threading.Event()
    release = threading.Event()

    def hung_call():
        entered.set()
        release.wait(0.5)
        return {'ok': True}

    started_at = time.monotonic()
    try:
        ai_provider._run_with_wall_clock_timeout(hung_call, timeout_seconds=0.01)
        assert False, 'expected wall-clock timeout'
    except URLError as exc:
        elapsed = time.monotonic() - started_at
        assert entered.wait(0.1) is True
        assert elapsed < 0.2
        assert 'timed out' in str(getattr(exc, 'reason', exc)).lower()
    finally:
        release.set()


def test_ai_provider_validate_defaults_ollama_to_mcp_bridge_without_explicit_bridge_mode(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp.routes import ai_provider

    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_ollama_urlopen_factory(generated_payload={'scenario': _scenario_payload('unused')}, models=['llama3.1']),
    )
    monkeypatch.setattr(ai_provider, 'McpBridgeClient', _FakeMcpBridgeClient)

    resp = client.post(
        '/api/ai/provider/validate',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'mcp_server_path': 'MCP/server.py',
        },
    )

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('success') is True
    assert payload.get('bridge', {}).get('bridge_mode') == 'mcp-python-sdk'
    assert any(tool.get('name') == 'server.scenario.replace_section' for tool in (payload.get('tools') or []))


def test_ai_provider_validate_accepts_legacy_ollmcp_bridge_mode_alias(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp.routes import ai_provider

    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_ollama_urlopen_factory(generated_payload={'scenario': _scenario_payload('unused')}, models=['llama3.1']),
    )
    monkeypatch.setattr(ai_provider, 'McpBridgeClient', _FakeMcpBridgeClient)

    resp = client.post(
        '/api/ai/provider/validate',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'bridge_mode': 'ollmcp',
            'mcp_server_path': 'MCP/server.py',
        },
    )

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('success') is True
    assert payload.get('bridge', {}).get('bridge_mode') == 'mcp-python-sdk'


def test_ai_generate_scenario_preview_defaults_ollama_to_mcp_bridge_without_explicit_bridge_mode(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_ollama_urlopen_factory(generated_payload={'scenario': _scenario_payload('unused')}, models=['llama3.1']),
    )
    monkeypatch.setattr(ai_provider, 'McpBridgeClient', _FakeMcpBridgeClient)

    scenario = _scenario_payload('DefaultBridgeScenario')
    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'mcp_server_path': 'MCP/server.py',
            'enabled_tools': ['server.scenario.replace_section'],
            'prompt': 'Generate a simple scenario through MCP tools.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('success') is True
    assert payload.get('bridge_mode') == 'mcp-python-sdk'
    assert payload.get('generated_scenario', {}).get('name') == 'DefaultBridgeScenario'


def test_ai_generate_scenario_preview_stream_defaults_ollama_to_mcp_bridge_without_explicit_bridge_mode(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_ollama_urlopen_factory(generated_payload={'scenario': _scenario_payload('unused')}, models=['llama3.1']),
    )
    monkeypatch.setattr(ai_provider, 'McpBridgeClient', _FakeMcpBridgeClient)

    scenario = _scenario_payload('DefaultBridgeStreamScenario')
    resp = client.post(
        '/api/ai/generate_scenario_preview_stream',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'mcp_server_path': 'MCP/server.py',
            'enabled_tools': ['server.scenario.replace_section'],
            'prompt': 'Generate a simple streamed scenario through MCP tools.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
        buffered=False,
    )

    assert resp.status_code == 200
    events = []
    for chunk in resp.response:
        text = chunk.decode('utf-8') if isinstance(chunk, bytes) else str(chunk)
        for line in text.splitlines():
            if line.strip():
                events.append(json.loads(line))

    status_messages = [str(event.get('message') or '') for event in events if event.get('type') == 'status']
    assert any('Connecting MCP bridge' in message for message in status_messages)
    result_event = next(event for event in events if event.get('type') == 'result')
    result_data = result_event.get('data') or {}
    assert result_data.get('success') is True
    assert result_data.get('bridge_mode') == 'mcp-python-sdk'


def test_ai_generate_scenario_preview_stream_falls_back_to_mcp_bridge_after_ollama_json_failure(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    def fake_streaming_result(*args, **kwargs):
        raise ai_provider.ProviderAdapterError('Ollama did not return valid JSON for scenario generation.', status_code=502)

    async def fake_bridge_generate_with_events(payload, *, current_scenario, user_prompt, model, host, emit, cancel_check=None, on_client_ready=None, on_response_open=None):
        emit('status', message='Connecting MCP bridge...')
        emit('tool_call', tool_name='server.scenario.create_draft')
        return _fake_bridge_generation_result('FallbackStreamScenario')

    monkeypatch.setattr(ai_provider, '_generate_ollama_streaming_result', fake_streaming_result)
    monkeypatch.setattr(ai_provider, '_mcp_bridge_generate_with_events', fake_bridge_generate_with_events)

    scenario = _scenario_payload('FallbackStreamScenario')
    resp = client.post(
        '/api/ai/generate_scenario_preview_stream',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'prompt': 'Generate a scenario with two PCs.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
        buffered=False,
    )
    assert resp.status_code == 200

    events = []
    for chunk in resp.response:
        text = chunk.decode('utf-8') if isinstance(chunk, bytes) else str(chunk)
        for line in text.splitlines():
            if line.strip():
                events.append(json.loads(line))

    status_messages = [str(event.get('message') or '') for event in events if event.get('type') == 'status']
    assert any('Falling back to MCP bridge' in message for message in status_messages)
    result_event = next(event for event in events if event.get('type') == 'result')
    result_data = result_event.get('data') or {}
    assert result_data.get('success') is True
    assert result_data.get('bridge_mode') == 'mcp-python-sdk'
    assert result_data.get('generated_scenario', {}).get('name') == 'FallbackStreamScenario'


def test_ai_generate_scenario_preview_repairs_router_rows_misplaced_in_node_information(monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp.routes import ai_provider

    generated = {
        'scenario': {
            'name': 'MisplacedRouterScenario',
            'density_count': 0,
            'notes': 'Routers were emitted into the wrong section.',
            'sections': {
                'Node Information': {
                    'density': 0,
                    'items': [
                        {'selected': 'Router', 'v_metric': 'Count', 'v_count': 5, 'factor': 1.0},
                    ],
                },
                'Routing': {'density': 0.0, 'items': []},
                'Services': {'density': 0.0, 'items': []},
                'Traffic': {'density': 0.0, 'items': []},
                'Vulnerabilities': {'density': 0.0, 'items': [], 'flag_type': 'text'},
                'Segmentation': {'density': 0.0, 'items': []},
            },
        }
    }

    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_ollama_urlopen_factory(generated_payload=generated, models=['llama3.1']),
    )

    scenario = _scenario_payload('MisplacedRouterSeedScenario')
    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'prompt': 'Create a router-only topology with 5 routers.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('success') is True

    generated_scenario = payload.get('generated_scenario') or {}
    node_items = (generated_scenario.get('sections') or {}).get('Node Information', {}).get('items') or []
    routing_items = (generated_scenario.get('sections') or {}).get('Routing', {}).get('items') or []

    assert all(str(item.get('selected') or '').strip() != 'Router' for item in node_items if isinstance(item, dict))
    assert routing_items
    assert routing_items[0].get('selected') == 'OSPFv2'
    assert routing_items[0].get('v_metric') == 'Count'
    assert routing_items[0].get('v_count') == 5

    preview = payload.get('preview') or {}
    assert len(preview.get('routers') or []) == 5
    assert len(preview.get('hosts') or []) == 0


def test_repo_mcp_bridge_client_emits_full_tool_result(monkeypatch):
    from webapp.routes import ai_provider

    client = ai_provider._RepoMcpBridgeClient(model='llama3.1', host='http://127.0.0.1:11434')
    long_text = 'X' * 1600
    emitted = []
    responses = [
        {
            'role': 'assistant',
            'content': '',
            'tool_calls': [{
                'function': {
                    'name': 'server.scenario.replace_section',
                    'arguments': {'section_name': 'Routing'},
                },
            }],
        },
        {
            'role': 'assistant',
            'content': 'done',
            'tool_calls': [],
        },
    ]

    def fake_emit(event_type, **payload):
        emitted.append((event_type, payload))

    def fake_stream_chat(*, messages, emit, cancel_check=None, on_response_open=None):
        return responses.pop(0)

    async def fake_call_tool(client_obj, qualified_tool_name, arguments):
        return {'payload': long_text}

    monkeypatch.setattr(client, '_stream_chat', fake_stream_chat)
    monkeypatch.setattr(ai_provider, '_mcp_bridge_call_tool', fake_call_tool)

    result = asyncio.run(client._run_query('test prompt', emit=fake_emit))

    assert result == 'done'
    tool_result_events = [payload for event_type, payload in emitted if event_type == 'tool' and payload.get('stage') == 'result']
    assert tool_result_events
    assert json.loads(tool_result_events[0]['message'])['payload'] == long_text


def test_repo_mcp_bridge_client_recovers_from_router_replace_section_error(monkeypatch):
    from webapp.routes import ai_provider

    client = ai_provider._RepoMcpBridgeClient(model='llama3.1', host='http://127.0.0.1:11434')
    emitted = []
    responses = [
        {
            'role': 'assistant',
            'content': '',
            'tool_calls': [{
                'function': {
                    'name': 'server.scenario.replace_section',
                    'arguments': {
                        'section_name': 'Node Information',
                        'section_payload': {
                            'items': [
                                {'selected': 'Router', 'v_metric': 'Count', 'v_count': 5, 'factor': 1.0},
                            ],
                        },
                    },
                },
            }],
        },
        {
            'role': 'assistant',
            'content': '',
            'tool_calls': [{
                'function': {
                    'name': 'server.scenario.add_routing_item',
                    'arguments': {
                        'protocol': 'ospf',
                        'count': 5,
                    },
                },
            }],
        },
        {
            'role': 'assistant',
            'content': 'done',
            'tool_calls': [],
        },
    ]
    observed_messages = []

    def fake_emit(event_type, **payload):
        emitted.append((event_type, payload))

    def fake_stream_chat(*, messages, emit, cancel_check=None, on_response_open=None):
        observed_messages.append(json.loads(json.dumps(messages)))
        return responses.pop(0)

    async def fake_call_tool(client_obj, qualified_tool_name, arguments):
        if qualified_tool_name == 'server.scenario.replace_section':
            raise ai_provider.ProviderAdapterError(
                'Node Information selected must be one of: Server, Workstation, PC, Docker, or Random',
                status_code=400,
            )
        if qualified_tool_name == 'server.scenario.add_routing_item':
            return {'ok': True}
        raise AssertionError(f'unexpected tool call: {qualified_tool_name}')

    monkeypatch.setattr(client, '_stream_chat', fake_stream_chat)
    monkeypatch.setattr(ai_provider, '_mcp_bridge_call_tool', fake_call_tool)

    result = asyncio.run(client._run_query('create a scenario with 5 routers', emit=fake_emit))

    assert result == 'done'
    assert len(observed_messages) >= 2
    retry_context = observed_messages[1][-1]
    assert retry_context.get('role') == 'tool'
    retry_payload = json.loads(retry_context.get('content') or '{}')
    assert retry_payload.get('recoverable') is True
    assert retry_payload.get('retry_hint', {}).get('tool') == 'scenario.add_routing_item'
    assert retry_payload.get('retry_hint', {}).get('count') == 5
    status_messages = [str(payload.get('message') or '') for event_type, payload in emitted if event_type == 'status']
    assert any('routing tool error' in message.lower() for message in status_messages)
    tool_result_events = [payload for event_type, payload in emitted if event_type == 'tool' and payload.get('stage') == 'result']
    assert tool_result_events
    assert 'Router counts belong in Routing' in str(tool_result_events[0].get('message') or '')


def test_repo_mcp_bridge_client_uses_openai_parser_for_litellm_nonstream(monkeypatch):
    from webapp.routes import ai_provider

    client = ai_provider._RepoMcpBridgeClient(
        model='gpt-4o-mini',
        host='https://litellm.example.com/v1',
        provider='litellm',
        api_key='test-litellm-key',
    )
    client._draft = {
        'draft_id': 'draft-bridge-1',
        'scenario': _scenario_payload('BridgeScenario'),
    }
    client.sessions = {'server': {'session': _FakeSession(client)}}

    responses = [
        {
            'choices': [{
                'message': {
                    'role': 'assistant',
                    'content': '',
                    'tool_calls': [{
                        'id': 'call_1',
                        'type': 'function',
                        'function': {
                            'name': 'server.scenario.get_draft',
                            'arguments': json.dumps({'draft_id': 'draft-bridge-1'}),
                        },
                    }],
                },
            }],
        },
        {
            'choices': [{
                'message': {
                    'role': 'assistant',
                    'content': 'done',
                },
            }],
        },
    ]

    def fake_post_chat(*, messages):
        return responses.pop(0)

    monkeypatch.setattr(client, '_post_chat', fake_post_chat)

    result = asyncio.run(client._run_query('use MCP tools', initial_draft_id='draft-bridge-1'))

    assert result == 'done'
    assert responses == []


def test_repo_mcp_bridge_client_requires_tools_for_litellm_requests(monkeypatch):
    from webapp.routes import ai_provider

    client = ai_provider._RepoMcpBridgeClient(
        model='gpt-4o-mini',
        host='https://litellm.example.com/v1',
        provider='litellm',
        api_key='test-litellm-key',
    )

    captured = {}

    def fake_post_json(url, payload, *, timeout, headers=None):
        captured['url'] = url
        captured['payload'] = payload
        captured['headers'] = headers
        return {'choices': [{'message': {'role': 'assistant', 'content': 'ok'}}]}

    monkeypatch.setattr(ai_provider, '_post_json', fake_post_json)
    monkeypatch.setattr(
        client.tool_manager,
        'get_enabled_tool_objects',
        lambda: [_FakeTool('server.scenario.get_draft', 'Get draft', {'type': 'object', 'properties': {'draft_id': {'type': 'string'}}})],
    )

    client._post_chat(messages=[{'role': 'user', 'content': 'test prompt'}])

    assert captured['url'].endswith('/chat/completions')
    assert captured['payload'].get('tool_choice') == 'required'
    assert isinstance(captured['payload'].get('tools'), list)
    assert captured['payload']['tools']
    assert captured['headers'] == {'Authorization': 'Bearer test-litellm-key'}


def test_repo_mcp_bridge_client_rejects_plain_text_litellm_bridge_reply(monkeypatch):
    from webapp.routes import ai_provider

    client = ai_provider._RepoMcpBridgeClient(
        model='gpt-4o-mini',
        host='https://litellm.example.com/v1',
        provider='litellm',
        api_key='test-litellm-key',
    )
    monkeypatch.setattr(
        client.tool_manager,
        'get_enabled_tool_objects',
        lambda: [_FakeTool('server.scenario.get_draft', 'Get draft', {'type': 'object', 'properties': {'draft_id': {'type': 'string'}}})],
    )

    def fake_post_chat(*, messages):
        return {
            'choices': [{
                'message': {
                    'role': 'assistant',
                    'content': 'We need to output JSON only, top-level object must be {": {"scenario":{}}}',
                },
            }],
        }

    monkeypatch.setattr(client, '_post_chat', fake_post_chat)

    try:
        asyncio.run(client._run_query('use MCP tools'))
    except ai_provider.ProviderAdapterError as exc:
        assert exc.status_code == 502
        assert 'plain text instead of MCP tool calls' in exc.message
        assert 'top-level object' in str(exc.details.get('provider_response') or '').lower()
    else:  # pragma: no cover
        raise AssertionError('expected ProviderAdapterError')


def test_ai_generate_scenario_preview_rejects_bridge_generation_without_enabled_tools(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_litellm_urlopen_factory(generated_payload={'scenario': _scenario_payload('unused')}, models=['gpt-4o-mini']),
    )
    monkeypatch.setattr(ai_provider, 'McpBridgeClient', _FakeMcpBridgeClient)

    scenario = _scenario_payload('LiteLlmBridgeScenario')
    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'litellm',
            'bridge_mode': 'mcp-python-sdk',
            'base_url': 'https://litellm.example.com/v1',
            'api_key': 'test-litellm-key',
            'enforce_ssl': True,
            'model': 'gpt-4o-mini',
            'mcp_server_path': 'MCP/server.py',
            'enabled_tools': [],
            'prompt': 'Build a small offline three-host scenario with MCP tools.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )

    assert resp.status_code == 400
    payload = resp.get_json() or {}
    assert 'No enabled MCP tools are available' in str(payload.get('error') or '')


def test_mcp_bridge_call_tool_wraps_raw_mcp_exception():
    from webapp.routes import ai_provider

    client = type('Client', (), {
        'sessions': {'server': {'session': _RaisingToolSession()}},
    })()

    try:
        asyncio.run(ai_provider._mcp_bridge_call_tool(client, 'server.scenario.replace_section', {}))
    except ai_provider.ProviderAdapterError as exc:
        assert exc.status_code == 502
        assert exc.message == 'Node Information selected must be one of: Server, Workstation, PC, Docker, or Random'
    else:  # pragma: no cover
        raise AssertionError('expected ProviderAdapterError')


def test_mcp_bridge_call_tool_wraps_error_result_payload():
    from webapp.routes import ai_provider

    client = type('Client', (), {
        'sessions': {'server': {'session': _ErrorResultSession()}},
    })()

    try:
        asyncio.run(ai_provider._mcp_bridge_call_tool(client, 'server.scenario.replace_section', {}))
    except ai_provider.ProviderAdapterError as exc:
        assert exc.status_code == 502
        assert exc.message == 'Node Information selected must be one of: Server, Workstation, PC, Docker, or Random'
    else:  # pragma: no cover
        raise AssertionError('expected ProviderAdapterError')


def test_normalize_mcp_bridge_tool_name_repairs_server_prefix_separator():
    from webapp.routes import ai_provider

    normalized = ai_provider._normalize_mcp_bridge_tool_name(
        'server_scenario.replace_section',
        known_server_names=['server'],
    )

    assert normalized == 'server.scenario.replace_section'


def test_build_llm_chat_tool_schema_hides_draft_id_and_duplicate_aliases():
    from webapp.routes import ai_provider

    schema = ai_provider._build_llm_chat_tool_schema(
        'server.scenario.add_routing_item',
        {
            'type': 'object',
            'properties': {
                'draft_id': {'type': 'string'},
                'selected': {'type': 'string'},
                'protocol': {'type': 'string'},
                'kind': {'type': 'string'},
                'type': {'type': 'string'},
                'count': {'type': 'integer'},
                'v_count': {'type': 'integer'},
                'r2r_edges': {'type': 'integer'},
            },
            'required': ['draft_id'],
        },
    )

    properties = schema.get('properties') or {}
    assert 'draft_id' not in properties
    assert 'kind' not in properties
    assert 'type' not in properties
    assert 'v_count' not in properties
    assert set(properties) >= {'selected', 'protocol', 'count', 'r2r_edges'}
    assert schema.get('required') == []


def test_sanitize_mcp_bridge_tool_arguments_injects_draft_id_and_strips_unsupported_fields():
    from webapp.routes import ai_provider

    sanitized = ai_provider._sanitize_mcp_bridge_tool_arguments(
        'server.scenario.add_vulnerability_item',
        {
            'v_name': 'jboss',
            'v_path': 'https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149',
            'factor': '?',
            'selected': 'Specific',
        },
        input_schema={
            'type': 'object',
            'properties': {
                'draft_id': {'type': 'string'},
                'v_name': {'type': 'string'},
                'v_path': {'type': 'string'},
                'v_type': {'type': 'string'},
                'v_vector': {'type': 'string'},
                'v_count': {'type': 'integer'},
            },
        },
        current_draft_id='draft-123',
    )

    assert sanitized == {
        'draft_id': 'draft-123',
        'v_name': 'jboss',
        'v_path': 'https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149',
    }


def test_sanitize_mcp_bridge_tool_arguments_replaces_blank_draft_id_with_active_draft():
    from webapp.routes import ai_provider

    sanitized = ai_provider._sanitize_mcp_bridge_tool_arguments(
        'server.scenario.add_routing_item',
        {
            'draft_id': '   ',
            'selected': 'OSPFv2',
            'count': 3,
        },
        input_schema={
            'type': 'object',
            'properties': {
                'draft_id': {'type': 'string'},
                'selected': {'type': 'string'},
                'count': {'type': 'integer'},
            },
        },
        current_draft_id='draft-456',
    )

    assert sanitized == {
        'draft_id': 'draft-456',
        'selected': 'OSPFv2',
        'count': 3,
    }


def test_mcp_bridge_process_query_server_side_passes_initial_draft_id_when_supported():
    from webapp.routes import ai_provider

    class _DraftAwareClient:
        def __init__(self):
            self.calls = []

        async def process_query(self, prompt, *, initial_draft_id=''):
            self.calls.append({'prompt': prompt, 'initial_draft_id': initial_draft_id})
            return 'ok'

    client = _DraftAwareClient()
    result = asyncio.run(ai_provider._mcp_bridge_process_query_server_side(
        client,
        prompt='hello',
        model='test-model',
        initial_draft_id='draft-seeded',
    ))

    assert result == 'ok'
    assert client.calls == [{'prompt': 'hello', 'initial_draft_id': 'draft-seeded'}]


def test_mcp_bridge_goal_prompt_mentions_draft_id_is_injected():
    from webapp.routes import ai_provider

    prompt = ai_provider._build_mcp_bridge_goal_prompt(
        draft_id='draft-1',
        enabled_tools=['server.scenario.add_routing_item'],
        scenario_name='InjectedDraftScenario',
        user_prompt='create a topology with 3 routers',
    )

    assert 'injects the current draft_id automatically' in prompt


def test_build_prompt_repair_decision_recognizes_ollama_tool_parse_error():
    from webapp.routes import ai_provider

    decision = ai_provider._build_prompt_repair_decision(
        prompt='base prompt',
        exc=ai_provider.ProviderAdapterError(
            'Ollama returned HTTP 500. {"error":"error parsing tool call: raw=..."}',
            status_code=502,
        ),
    )

    assert decision.category == 'ollama-tool-parse-error'
    assert decision.retryable is True
    assert 'do not pass factor' in str(decision.retry_prompt or '').lower()


def test_build_prompt_repair_decision_adds_vulnerability_grounding_for_tool_parse_error(monkeypatch):
    from webapp.routes import ai_provider

    monkeypatch.setattr(
        ai_provider,
        '_search_vulnerability_catalog_for_prompt',
        lambda query, limit=3: [
            {
                'name': 'Next JS Demo Vuln',
                'path': '/tmp/catalog/next-js/CVE-2025-1234/docker-compose.yml',
            },
        ],
    )

    decision = ai_provider._build_prompt_repair_decision(
        prompt='base prompt',
        user_prompt='add 1 vulnerability for next js',
        exc=ai_provider.ProviderAdapterError(
            'Ollama returned HTTP 500. {"error":"error parsing tool call: raw=..."}',
            status_code=502,
        ),
    )

    retry_prompt = str(decision.retry_prompt or '')
    assert 'scenario.search_vulnerability_catalog' in retry_prompt
    assert 'pass only strict json keys draft_id, v_name, v_path, and v_count' in retry_prompt.lower()
    assert 'quoted json string' in retry_prompt.lower()
    assert 'Next JS Demo Vuln' in retry_prompt
    assert '/tmp/catalog/next-js/CVE-2025-1234/docker-compose.yml' in retry_prompt


def test_build_prompt_repair_decision_adds_traffic_grounding_for_tool_parse_error():
    from webapp.routes import ai_provider

    decision = ai_provider._build_prompt_repair_decision(
        prompt='base prompt',
        user_prompt='create 3 tcp flows with periodic pattern',
        exc=ai_provider.ProviderAdapterError(
            'Ollama returned HTTP 500. {"error":"error parsing tool call: raw=..."}',
            status_code=502,
        ),
    )

    retry_prompt = str(decision.retry_prompt or '')
    assert 'for scenario.add_traffic_item, pass only strict json keys' in retry_prompt.lower()
    assert 'when count is present, omit factor entirely' in retry_prompt.lower()
    assert 'example valid traffic tool call json' in retry_prompt.lower()
    assert '"protocol":"TCP","count":3,"pattern":"periodic","content_type":"text"' in retry_prompt


def test_build_generation_repair_decision_recognizes_unknown_draft_id():
    from webapp.routes import ai_provider

    decision = ai_provider._build_generation_repair_decision(
        ai_provider.ProviderAdapterError('Unknown draft_id: draft-123', status_code=502)
    )

    assert decision.category == 'unknown-draft-id'
    assert decision.retryable is True
    assert decision.recreate_draft is True


def test_build_tool_repair_decision_returns_recoverable_tool_response():
    from webapp.routes import ai_provider

    decision = ai_provider._build_tool_repair_decision(
        'server.scenario.replace_section',
        {
            'section_name': 'Node Information',
            'section_payload': {
                'items': [
                    {'selected': 'Router', 'v_metric': 'Count', 'v_count': 5, 'factor': 1.0},
                ],
            },
        },
        ai_provider.ProviderAdapterError(
            'Node Information selected must be one of: Server, Workstation, PC, Docker, or Random',
            status_code=400,
        ),
        enabled_tool_names=['server.scenario.add_routing_item'],
    )

    assert decision.category == 'routing-tool-error'
    assert decision.retryable is True
    assert 'scenario.add_routing_item' in str(decision.tool_response or '')
    assert 'routing tool error' in str(decision.status_message or '').lower()


def test_classify_tool_repair_detects_traffic_and_vulnerability_categories():
    from webapp.routes import ai_provider

    traffic_category, traffic_message = ai_provider._classify_tool_repair(
        json.dumps({
            'recoverable': True,
            'retry_hint': {'tool': 'scenario.add_traffic_item', 'pattern': 'burst'},
        }),
        qualified_tool_name='server.scenario.add_traffic_item',
    )
    vuln_category, vuln_message = ai_provider._classify_tool_repair(
        json.dumps({
            'recoverable': True,
            'retry_hint': {'tool': 'scenario.add_vulnerability_item', 'selected': 'Type/Vector'},
        }),
        qualified_tool_name='server.scenario.add_vulnerability_item',
    )

    assert traffic_category == 'traffic-tool-error'
    assert 'traffic tool error' in traffic_message.lower()
    assert vuln_category == 'vulnerability-tool-error'
    assert 'vulnerability tool error' in vuln_message.lower()


def test_classify_tool_repair_detects_service_category():
    from webapp.routes import ai_provider

    service_category, service_message = ai_provider._classify_tool_repair(
        json.dumps({
            'recoverable': True,
            'retry_hint': {'tool': 'scenario.add_service_item', 'selected': 'HTTP'},
        }),
        qualified_tool_name='server.scenario.add_service_item',
    )

    assert service_category == 'service-tool-error'
    assert 'service tool error' in service_message.lower()


def test_build_tool_repair_decision_repairs_add_service_item_selection_error():
    from webapp.routes import ai_provider

    decision = ai_provider._build_tool_repair_decision(
        'server.scenario.add_service_item',
        {
            'service': 'https',
            'count': 3,
        },
        ai_provider.ProviderAdapterError(
            'selected or service must be one of: SSH, HTTP, DHCPClient, or Random',
            status_code=400,
        ),
        enabled_tool_names=['server.scenario.add_service_item'],
    )

    assert decision.category == 'service-tool-error'
    assert decision.retryable is True
    assert 'scenario.add_service_item' in str(decision.tool_response or '')
    assert '"selected": "HTTP"' in str(decision.tool_response or '')
    assert '"count": 3' in str(decision.tool_response or '')
    assert 'service tool error' in str(decision.status_message or '').lower()


def test_build_tool_repair_decision_repairs_services_replace_section_selection_error():
    from webapp.routes import ai_provider

    decision = ai_provider._build_tool_repair_decision(
        'server.scenario.replace_section',
        {
            'section_name': 'Services',
            'section_payload': {
                'items': [
                    {'service': 'dhcp', 'v_count': 2},
                ],
            },
        },
        ai_provider.ProviderAdapterError(
            'selected or service must be one of: SSH, HTTP, DHCPClient, or Random',
            status_code=400,
        ),
        enabled_tool_names=['server.scenario.replace_section'],
    )

    assert decision.category == 'service-tool-error'
    assert decision.retryable is True
    assert 'scenario.replace_section' in str(decision.tool_response or '')
    assert '"section_name": "Services"' in str(decision.tool_response or '')
    assert '"selected": "DHCPClient"' in str(decision.tool_response or '')
    assert '"v_count": 2' in str(decision.tool_response or '')


def test_mcp_bridge_call_tool_accepts_repaired_server_prefix_separator():
    from webapp.routes import ai_provider

    class _SuccessSession:
        async def call_tool(self, tool_name, tool_args):
            assert tool_name == 'scenario.replace_section'
            return _FakeToolResult({'ok': True, 'tool_name': tool_name, 'tool_args': tool_args})

    client = type('Client', (), {
        'sessions': {'server': {'session': _SuccessSession()}},
    })()

    result = asyncio.run(ai_provider._mcp_bridge_call_tool(client, 'server_scenario.replace_section', {
        'section_name': 'Routing',
        'section_payload': {'items': []},
    }))

    assert isinstance(result, dict)
    assert result.get('ok') is True


def test_build_recoverable_router_error_falls_back_to_routing_replace_section():
    from webapp.routes import ai_provider

    payload = json.loads(ai_provider._build_recoverable_mcp_bridge_tool_error(
        'server.scenario.replace_section',
        {
            'section_name': 'Node Information',
            'section_payload': {
                'items': [
                    {'selected': 'Router', 'v_metric': 'Count', 'v_count': 5, 'factor': 1.0},
                ],
            },
        },
        ai_provider.ProviderAdapterError(
            'Node Information selected must be one of: Server, Workstation, PC, Docker, or Random',
            status_code=400,
        ),
        enabled_tool_names=['server.scenario.replace_section'],
    ) or '{}')

    assert payload.get('recoverable') is True
    assert payload.get('retry_hint', {}).get('tool') == 'scenario.replace_section'
    assert payload.get('retry_hint', {}).get('section_name') == 'Routing'
    routing_items = payload.get('retry_hint', {}).get('section_payload', {}).get('items') or []
    assert routing_items
    assert routing_items[0].get('selected') == 'OSPFv2'
    assert routing_items[0].get('v_count') == 5


def test_build_recoverable_router_error_preserves_routing_edge_hints():
    from webapp.routes import ai_provider

    payload = json.loads(ai_provider._build_recoverable_mcp_bridge_tool_error(
        'server.scenario.replace_section',
        {
            'section_name': 'Node Information',
            'section_payload': {
                'items': [
                    {
                        'selected': 'ospf',
                        'v_metric': 'Count',
                        'v_count': 5,
                        'factor': 1.0,
                        'r2r_mode': 'count',
                        'r2r_edges': 2,
                        'r2s_mode': 'count',
                        'r2s_edges': 2,
                        'r2s_hosts_min': 2,
                        'r2s_hosts_max': 2,
                    },
                ],
            },
        },
        ai_provider.ProviderAdapterError(
            'Node Information selected must be one of: Server, Workstation, PC, Docker, or Random',
            status_code=400,
        ),
        enabled_tool_names=['server.scenario.add_routing_item'],
    ) or '{}')

    assert payload.get('recoverable') is True
    retry_hint = payload.get('retry_hint', {})
    assert retry_hint.get('tool') == 'scenario.add_routing_item'
    assert retry_hint.get('protocol') == 'OSPFv2'
    assert retry_hint.get('count') == 5
    assert retry_hint.get('r2r_mode') == 'count'
    assert retry_hint.get('r2r_edges') == 2
    assert retry_hint.get('r2s_mode') == 'count'
    assert retry_hint.get('r2s_edges') == 2
    assert retry_hint.get('r2s_hosts_min') == 2
    assert retry_hint.get('r2s_hosts_max') == 2
    assert 'r2r_* and r2s_* fields' in str(payload.get('guidance') or '')


def test_build_recoverable_router_error_detects_protocol_alias_in_node_information():
    from webapp.routes import ai_provider

    payload = json.loads(ai_provider._build_recoverable_mcp_bridge_tool_error(
        'server.scenario.replace_section',
        {
            'section_name': 'Node Information',
            'section_payload': {
                'items': [
                    {
                        'protocol': 'ospf',
                        'count': 5,
                        'r2r_mode': 'count',
                        'r2r_edges': 2,
                    },
                ],
            },
        },
        ai_provider.ProviderAdapterError(
            'Node Information selected must be one of: Server, Workstation, PC, Docker, or Random',
            status_code=400,
        ),
        enabled_tool_names=['server.scenario.add_routing_item'],
    ) or '{}')

    assert payload.get('recoverable') is True
    retry_hint = payload.get('retry_hint', {})
    assert retry_hint.get('tool') == 'scenario.add_routing_item'
    assert retry_hint.get('protocol') == 'OSPFv2'
    assert retry_hint.get('count') == 5
    assert retry_hint.get('r2r_mode') == 'count'
    assert retry_hint.get('r2r_edges') == 2


def test_build_recoverable_router_error_detects_invalid_routing_placeholder():
    from webapp.routes import ai_provider

    payload = json.loads(ai_provider._build_recoverable_mcp_bridge_tool_error(
        'server.scenario.replace_section',
        {
            'section_name': 'Routing',
            'section_payload': {
                'items': [
                    {
                        'selected': 'Routing',
                        'count': 5,
                        'r2r_mode': 'count',
                        'r2r_edges': 2,
                        'r2s_mode': 'count',
                        'r2s_edges': 2,
                    },
                ],
            },
        },
        ai_provider.ProviderAdapterError(
            'Routing selected must be one of: RIP, RIPNG, BGP, OSPFv2, OSPFv3, or Random',
            status_code=400,
        ),
        enabled_tool_names=['server.scenario.add_routing_item'],
    ) or '{}')

    assert payload.get('recoverable') is True
    retry_hint = payload.get('retry_hint', {})
    assert retry_hint.get('tool') == 'scenario.add_routing_item'
    assert retry_hint.get('protocol') == 'OSPFv2'
    assert retry_hint.get('count') == 5
    assert retry_hint.get('r2r_mode') == 'count'
    assert retry_hint.get('r2r_edges') == 2
    assert retry_hint.get('r2s_mode') == 'count'
    assert retry_hint.get('r2s_edges') == 2
    assert 'Do not use selected="Routing"' in str(payload.get('guidance') or '')


def test_mcp_bridge_goal_prompt_mentions_routing_ratio_fields():
    from webapp.routes import ai_provider

    prompt = ai_provider._build_mcp_bridge_goal_prompt(
        draft_id='draft-1',
        enabled_tools=['server.scenario.add_routing_item'],
        scenario_name='RatioScenario',
        user_prompt='use a 2-2 router to router ratio',
    )

    assert 'r2r_* and r2s_* fields' in prompt
    assert 'There is no r2h field' in prompt
    assert 'v_count is router quantity' in prompt
    assert 'r2r_edges is router-to-router links per router' in prompt
    assert 'scenario.search_vulnerability_catalog first' in prompt
    assert 'explicit v_name and v_path' in prompt
    assert 'Do not pass factor' in prompt
    assert 'make separate add_vulnerability_item calls with v_count=1' in prompt


def test_build_recoverable_traffic_pattern_error_uses_add_traffic_item_retry():
    from webapp.routes import ai_provider

    payload = json.loads(ai_provider._build_recoverable_mcp_bridge_tool_error(
        'server.scenario.add_traffic_item',
        {
            'protocol': 'udp',
            'count': 2,
            'pattern': 'bursts',
            'content_type': 'text',
        },
        ai_provider.ProviderAdapterError(
            'pattern must be one of: continuous, periodic, burst, poisson, or ramp',
            status_code=400,
        ),
        enabled_tool_names=['server.scenario.add_traffic_item'],
    ) or '{}')

    assert payload.get('recoverable') is True
    assert payload.get('retry_hint', {}).get('tool') == 'scenario.add_traffic_item'
    assert payload.get('retry_hint', {}).get('protocol') == 'UDP'
    assert payload.get('retry_hint', {}).get('count') == 2
    assert payload.get('retry_hint', {}).get('pattern') == 'burst'
    assert 'exact pattern values' in str(payload.get('guidance') or '')


def test_build_recoverable_vulnerability_catalog_error_uses_catalog_search_for_broad_requests():
    from webapp.routes import ai_provider

    payload = json.loads(ai_provider._build_recoverable_mcp_bridge_tool_error(
        'server.scenario.add_vulnerability_item',
        {
            'v_name': 'web',
            'v_count': 3,
        },
        ai_provider.ProviderAdapterError(
            'Specific vulnerability must match an enabled catalog entry by v_path or v_name',
            status_code=400,
        ),
        enabled_tool_names=['server.scenario.add_vulnerability_item', 'server.scenario.search_vulnerability_catalog'],
    ) or '{}')

    assert payload.get('recoverable') is True
    retry_hint = payload.get('retry_hint', {})
    assert retry_hint.get('tool') == 'scenario.search_vulnerability_catalog'
    assert retry_hint.get('query') == 'web'
    assert retry_hint.get('limit') == 9
    guidance = str(payload.get('guidance') or '').lower()
    assert 'do not invent a specific vulnerability name/path' in guidance
    assert 'search the vulnerability catalog using the user\'s wording' in guidance
    assert 'type/vector' not in guidance


def test_mcp_bridge_goal_prompt_mentions_exact_traffic_patterns_for_varied_profiles():
    from webapp.routes import ai_provider

    prompt = ai_provider._build_mcp_bridge_goal_prompt(
        draft_id='draft-traffic-1',
        enabled_tools=['server.scenario.add_traffic_item'],
        scenario_name='TrafficScenario',
        user_prompt='create various tcp and udp traffic with various traffic profiles',
    )

    assert 'one exact pattern from: continuous, periodic, burst, poisson, or ramp' in prompt
    assert 'create multiple Traffic rows' in prompt


def test_mcp_bridge_goal_prompt_mentions_catalog_search_for_broad_vulnerability_requests():
    from webapp.routes import ai_provider

    prompt = ai_provider._build_mcp_bridge_goal_prompt(
        draft_id='draft-web-1',
        enabled_tools=['server.scenario.add_vulnerability_item', 'server.scenario.search_vulnerability_catalog'],
        scenario_name='WebVulnScenario',
        user_prompt='I want 3 vulnerabilities related to web',
    )

    prompt_lower = prompt.lower()
    assert 'do not invent a synthetic category row' in prompt_lower
    assert 'search the vulnerability catalog using the user\'s wording' in prompt_lower
    assert 'do not pass v_type or v_vector filters' in prompt_lower
    assert 'type/vector' not in prompt.lower()


def test_vulnerability_grounding_guidance_uses_web_query_hint_and_candidates(monkeypatch):
    from webapp.routes import ai_provider

    monkeypatch.setattr(
        ai_provider,
        '_load_vulnerability_catalog_for_prompt',
        lambda: [
            {
                'Name': 'appweb/CVE-2018-8715',
                'Path': '/catalog/appweb/CVE-2018-8715/docker-compose.yml',
                'Description': 'Web server vulnerability',
                'Type': 'docker-compose',
                'Vector': '',
                'CVE': 'CVE-2018-8715',
            },
            {
                'Name': 'jboss/CVE-2017-12149',
                'Path': '/catalog/jboss/CVE-2017-12149/docker-compose.yml',
                'Description': 'JBoss web console deserialization',
                'Type': 'docker-compose',
                'Vector': '',
                'CVE': 'CVE-2017-12149',
            },
        ],
    )

    guidance = ai_provider._build_vulnerability_grounding_guidance('I want 2 vulnerabilities related to web')
    joined = '\n'.join(guidance).lower()

    assert 'query="web"' in joined
    assert 'do one focused vulnerability search' in joined
    assert 'appweb/cve-2018-8715' in joined
    assert 'jboss/cve-2017-12149' in joined


def test_mcp_bridge_goal_prompt_includes_grounded_vulnerability_candidates(monkeypatch):
    from webapp.routes import ai_provider

    monkeypatch.setattr(
        ai_provider,
        '_load_vulnerability_catalog_for_prompt',
        lambda: [
            {
                'Name': 'appweb/CVE-2018-8715',
                'Path': '/catalog/appweb/CVE-2018-8715/docker-compose.yml',
                'Description': 'Web server vulnerability',
                'Type': 'docker-compose',
                'Vector': '',
                'CVE': 'CVE-2018-8715',
            },
        ],
    )

    prompt = ai_provider._build_mcp_bridge_goal_prompt(
        draft_id='draft-web-2',
        enabled_tools=['server.scenario.add_vulnerability_item', 'server.scenario.search_vulnerability_catalog'],
        scenario_name='GroundedWebScenario',
        user_prompt='I want 1 web vulnerability',
    )

    prompt_lower = prompt.lower()
    assert 'query="web"' in prompt_lower
    assert 'do one focused vulnerability search' in prompt_lower
    assert 'appweb/cve-2018-8715' in prompt_lower


def test_count_intent_guidance_derives_host_remainder_from_total_nodes_and_routers():
    from webapp.routes import ai_provider

    prompt = ai_provider._build_mcp_bridge_goal_prompt(
        draft_id='draft-2',
        enabled_tools=['server.scenario.add_node_role_item', 'server.scenario.add_routing_item'],
        scenario_name='CountScenario',
        user_prompt='create a topology with 30 nodes and 10 routers',
    )

    assert 'total topology nodes=30' in prompt
    assert 'router nodes=10' in prompt
    assert 'Node Information host counts should sum to 20' in prompt
    assert 'Routing router count should be 10' in prompt


def test_count_intent_guidance_accounts_for_vulnerability_docker_capacity():
    from webapp.routes import ai_provider

    prompt = ai_provider._build_mcp_bridge_goal_prompt(
        draft_id='draft-3',
        enabled_tools=['server.scenario.add_node_role_item', 'server.scenario.add_routing_item', 'server.scenario.add_vulnerability_item'],
        scenario_name='CountWithVulnsScenario',
        user_prompt='I want a network with 30 nodes, 8 routers, and 3 vulnerabilities related to web',
    )

    assert 'total topology nodes=30' in prompt
    assert 'router nodes=8' in prompt
    assert 'final preview host count should be 22' in prompt
    assert '3 vulnerability target(s)' in prompt
    assert 'keep the other Node Information host rows to 19' in prompt


def test_count_intent_guidance_uses_existing_hosts_for_vulnerabilities_when_host_budget_is_full():
    from webapp.routes import ai_provider

    prompt = ai_provider._build_mcp_bridge_goal_prompt(
        draft_id='draft-3b',
        enabled_tools=['server.scenario.add_node_role_item', 'server.scenario.add_routing_item', 'server.scenario.add_vulnerability_item'],
        scenario_name='CountWithExactHostCompositionScenario',
        user_prompt='Create a network with 12 nodes, 3 routers, 4 servers, 5 workstations, and 1 web vulnerability',
    )

    prompt_lower = prompt.lower()
    assert 'final preview host count should be 9' in prompt_lower
    assert 'satisfy the requested vulnerabilities on those existing hosts instead of adding extra docker host rows' in prompt_lower


def test_goal_prompt_orders_routing_before_vulnerability_search_for_combined_request():
    from webapp.routes import ai_provider

    prompt = ai_provider._build_mcp_bridge_goal_prompt(
        draft_id='draft-4',
        enabled_tools=[
            'server.scenario.add_node_role_item',
            'server.scenario.add_routing_item',
            'server.scenario.search_vulnerability_catalog',
            'server.scenario.add_vulnerability_item',
        ],
        scenario_name='OrderedScenario',
        user_prompt='I want a network with 30 nodes, 8 routers with low router-to-router link ratio. I also want 3 vulnerabilities related to web',
    )

    prompt_lower = prompt.lower()
    assert 'author routing first, then node information host rows, then vulnerabilities' in prompt_lower
    assert 'do not postpone the routing section until after vulnerability search' in prompt_lower
    assert 'do not pass v_type or v_vector filters' in prompt_lower
    assert 'r2r_mode="min"' in prompt_lower


def test_deterministic_mcp_bridge_seed_does_not_duplicate_vulnerability_seed_ops(monkeypatch):
    from webapp.routes import ai_provider
    from core_topo_gen.planning.ai_topology_intent import AiTopologyIntent
    from core_topo_gen.planning.ai_topology_intent import CompiledAiTopologyIntent

    calls = []

    async def fake_call_tool(client, qualified_tool_name, arguments):
        calls.append((qualified_tool_name, dict(arguments)))
        return {'ok': True}

    compiled = CompiledAiTopologyIntent(
        intent=AiTopologyIntent(
            total_nodes=None,
            router_count=None,
            derived_host_count=None,
            node_role_counts={},
            service_counts={},
            traffic_rows=[],
            segmentation_counts={},
            vulnerability_target_count=1,
            r2r_density='',
        ),
        section_payloads={},
        tool_seed_ops=[
            {'kind': 'vulnerability', 'v_name': 'jboss/CVE-2017-12149', 'v_path': 'demo/path', 'v_count': 1},
        ],
        applied_actions=['Vulnerability jboss/CVE-2017-12149'],
        locked_sections=(),
    )

    monkeypatch.setattr(ai_provider, '_compile_ai_intent', lambda _prompt: compiled)
    monkeypatch.setattr(ai_provider, '_extract_vulnerability_target_count', lambda _prompt: 1)
    monkeypatch.setattr(ai_provider, '_extract_vulnerability_query_hint', lambda _prompt: 'jboss')
    monkeypatch.setattr(ai_provider, '_search_vulnerability_catalog_for_prompt', lambda _query, limit=1: [{'name': 'jboss/CVE-2017-12149', 'path': 'demo/path'}])
    monkeypatch.setattr(ai_provider, '_mcp_bridge_call_tool', fake_call_tool)

    applied = asyncio.run(ai_provider._apply_deterministic_mcp_bridge_seed(
        client=object(),
        available_tools=['server.scenario.add_vulnerability_item'],
        draft_id='draft-1',
        user_prompt='Add a jboss vulnerability.',
    ))

    vuln_calls = [call for call in calls if call[0] == 'server.scenario.add_vulnerability_item']
    assert vuln_calls == []
    assert applied == ['Vulnerability jboss/CVE-2017-12149']


def test_canonicalize_generated_routing_modes_title_cases_edge_modes():
    from webapp.routes import ai_provider

    scenario = _scenario_payload('RoutingModeCanonicalizeScenario')
    scenario['sections']['Routing'] = {
        'density': 0.0,
        'items': [
            {
                'selected': 'OSPFv2',
                'factor': 1.0,
                'v_metric': 'Count',
                'v_count': 8,
                'r2r_mode': 'min',
                'r2s_mode': 'nonuniform',
            },
        ],
    }

    canonical = ai_provider._canonicalize_generated_routing_modes(scenario)
    routing_item = canonical['sections']['Routing']['items'][0]

    assert routing_item['r2r_mode'] == 'Min'
    assert routing_item['r2s_mode'] == 'NonUniform'


def test_prompt_coverage_mismatch_detects_missing_requested_sections():
    from webapp.routes import ai_provider

    scenario = _scenario_payload('CoverageScenario')
    mismatch = ai_provider._get_prompt_coverage_mismatch(
        'add 3 vulnerabilities, tcp traffic, services, segmentation, and 2 docker hosts',
        scenario,
    )

    assert mismatch is not None
    missing = {item['target']: item for item in mismatch.get('missing') or []}
    assert missing['Vulnerabilities']['expected_min_items'] == 3
    assert missing['Vulnerabilities']['actual_items'] == 0
    assert missing['Traffic']['expected_min_items'] == 1
    assert missing['Services']['expected_min_items'] == 1
    assert missing['Segmentation']['expected_min_items'] == 1
    assert missing['Docker']['expected_min_items'] == 2


def test_prompt_coverage_mismatch_detects_missing_requested_values():
    from webapp.routes import ai_provider

    scenario = _scenario_payload('ValueCoverageScenario')
    scenario['sections']['Traffic'] = {
        'density': 0.0,
        'items': [
            {'selected': 'TCP', 'pattern': 'continuous', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0, 'content_type': 'text'},
        ],
    }
    scenario['sections']['Routing'] = {
        'density': 0.0,
        'items': [
            {'selected': 'OSPFv2', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0},
        ],
    }

    mismatch = ai_provider._get_prompt_coverage_mismatch(
        'create tcp and udp traffic with periodic pattern and bgp routing',
        scenario,
    )

    assert mismatch is not None
    missing_values = {(item['target'], item['field']): item for item in mismatch.get('missing_values') or []}
    assert missing_values[('Traffic', 'selected_values')]['missing_values'] == ['UDP']
    assert missing_values[('Traffic', 'pattern_values')]['missing_values'] == ['periodic']
    assert missing_values[('Routing', 'selected_values')]['missing_values'] == ['BGP']


def test_prompt_coverage_mismatch_detects_exact_node_role_counts():
    from webapp.routes import ai_provider

    scenario = _scenario_payload('NodeRoleCoverageScenario')
    scenario['sections']['Node Information'] = {
        'density': 0.0,
        'items': [
            {'selected': 'Server', 'v_metric': 'Count', 'v_count': 4, 'factor': 1.0},
            {'selected': 'Workstation', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0},
        ],
    }

    mismatch = ai_provider._get_prompt_coverage_mismatch(
        'create 5 servers and 2 workstations',
        scenario,
    )

    assert mismatch is not None
    missing = {item['target']: item for item in mismatch.get('missing') or []}
    assert missing['Node Information:Server']['expected_items'] == 5
    assert missing['Node Information:Server']['actual_items'] == 4
    assert 'exactly 5 Server hosts' in missing['Node Information:Server']['reason']
    assert 'Node Information:Workstation' not in missing


def test_prompt_coverage_mismatch_detects_routing_density_values():
    from webapp.routes import ai_provider

    scenario = _scenario_payload('RoutingDensityScenario')
    scenario['sections']['Routing'] = {
        'density': 0.0,
        'items': [
            {'selected': 'OSPFv2', 'r2r_mode': 'max', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0},
        ],
    }

    mismatch = ai_provider._get_prompt_coverage_mismatch(
        'create 8 routers with low router-to-router link ratio',
        scenario,
    )

    assert mismatch is not None
    missing_values = {(item['target'], item['field']): item for item in mismatch.get('missing_values') or []}
    assert missing_values[('Routing', 'r2r_density_values')]['missing_values'] == ['low']
    assert missing_values[('Routing', 'r2r_density_values')]['actual_values'] == ['high']

    retry_prompt = ai_provider._build_prompt_coverage_retry_prompt('base prompt', mismatch).lower()
    assert 'missing value coverage: routing is missing requested r2r_density_values: low.' in retry_prompt
    assert 'router-to-router density semantics match the request' in retry_prompt


def test_prompt_coverage_mismatch_detects_exact_service_traffic_and_segmentation_counts():
    from webapp.routes import ai_provider

    scenario = _scenario_payload('SectionCountCoverageScenario')
    scenario['sections']['Services'] = {
        'density': 0.0,
        'items': [
            {'selected': 'SSH', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0},
            {'selected': 'HTTP', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0},
        ],
    }
    scenario['sections']['Traffic'] = {
        'density': 0.0,
        'items': [
            {'selected': 'TCP', 'pattern': 'periodic', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0, 'content_type': 'text'},
        ],
    }
    scenario['sections']['Segmentation'] = {
        'density': 0.0,
        'items': [
            {'selected': 'Firewall', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0},
        ],
    }

    mismatch = ai_provider._get_prompt_coverage_mismatch(
        'create 2 ssh services, 2 tcp flows, 2 periodic flows, and 2 firewall segments',
        scenario,
    )

    assert mismatch is not None
    missing = {item['target']: item for item in mismatch.get('missing') or []}
    assert missing['Services:SSH']['expected_items'] == 2
    assert missing['Services:SSH']['actual_items'] == 1
    assert missing['Traffic:TCP']['expected_items'] == 2
    assert missing['Traffic:TCP']['actual_items'] == 1
    assert missing['Traffic Pattern:periodic']['expected_items'] == 2
    assert missing['Traffic Pattern:periodic']['actual_items'] == 1
    assert missing['Segmentation:Firewall']['expected_items'] == 2
    assert missing['Segmentation:Firewall']['actual_items'] == 1

    retry_prompt = ai_provider._build_prompt_coverage_retry_prompt('base prompt', mismatch).lower()
    assert 'missing requirement: services:ssh expected exactly 2 item(s) but draft has 1.' in retry_prompt
    assert 'missing requirement: traffic:tcp expected exactly 2 item(s) but draft has 1.' in retry_prompt
    assert 'missing requirement: traffic pattern:periodic expected exactly 2 item(s) but draft has 1.' in retry_prompt
    assert 'missing requirement: segmentation:firewall expected exactly 2 item(s) but draft has 1.' in retry_prompt
    assert 'do not duplicate one label to satisfy another requested label' in retry_prompt
    assert 'do not reuse one protocol label to satisfy another requested protocol' in retry_prompt
    assert 'include each missing pattern explicitly rather than duplicating another pattern' in retry_prompt
    assert 'use scenario.add_service_item to add or repair a row with selected="ssh" and count=2.' in retry_prompt
    assert 'use scenario.add_traffic_item to add or repair row(s) with selected="tcp", content_type="text", and count=2.' in retry_prompt
    assert 'use scenario.add_traffic_item to add or repair row(s) with pattern="periodic", content_type="text", and count=2.' in retry_prompt


def test_prompt_coverage_mismatch_detects_word_number_and_pair_phrasings():
    from webapp.routes import ai_provider

    scenario = _scenario_payload('WordNumberCoverageScenario')
    scenario['sections']['Services'] = {
        'density': 0.0,
        'items': [
            {'selected': 'HTTP', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0},
        ],
    }
    scenario['sections']['Traffic'] = {
        'density': 0.0,
        'items': [
            {'selected': 'TCP', 'pattern': 'periodic', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0, 'content_type': 'text'},
        ],
    }
    scenario['sections']['Segmentation'] = {
        'density': 0.0,
        'items': [],
    }

    mismatch = ai_provider._get_prompt_coverage_mismatch(
        'create two web services, a pair of periodic tcp streams, and a firewall segment',
        scenario,
    )

    assert mismatch is not None
    missing = {item['target']: item for item in mismatch.get('missing') or []}
    assert missing['Services:HTTP']['expected_items'] == 2
    assert missing['Services:HTTP']['actual_items'] == 1
    assert missing['Traffic:TCP']['expected_items'] == 2
    assert missing['Traffic:TCP']['actual_items'] == 1
    assert missing['Traffic Pattern:periodic']['expected_items'] == 2
    assert missing['Traffic Pattern:periodic']['actual_items'] == 1
    assert missing['Segmentation:Firewall']['expected_items'] == 1
    assert missing['Segmentation:Firewall']['actual_items'] == 0


def test_prompt_coverage_mismatch_detects_compound_service_and_protocol_phrasing():
    from webapp.routes import ai_provider

    scenario = _scenario_payload('CompoundPhraseCoverageScenario')
    scenario['sections']['Services'] = {
        'density': 0.0,
        'items': [
            {'selected': 'SSH', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0},
            {'selected': 'HTTP', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0},
        ],
    }
    scenario['sections']['Traffic'] = {
        'density': 0.0,
        'items': [
            {'selected': 'TCP', 'pattern': 'continuous', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0, 'content_type': 'text'},
            {'selected': 'UDP', 'pattern': 'continuous', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0, 'content_type': 'text'},
        ],
    }

    mismatch = ai_provider._get_prompt_coverage_mismatch(
        'create two ssh and one web service, plus two tcp and one udp flows',
        scenario,
    )

    assert mismatch is not None
    missing = {item['target']: item for item in mismatch.get('missing') or []}
    assert missing['Services:SSH']['expected_items'] == 2
    assert missing['Services:SSH']['actual_items'] == 1
    assert 'Services:HTTP' not in missing
    assert missing['Traffic:TCP']['expected_items'] == 2
    assert missing['Traffic:TCP']['actual_items'] == 1
    assert 'Traffic:UDP' not in missing


def test_prompt_coverage_mismatch_detects_compound_traffic_pattern_phrasing():
    from webapp.routes import ai_provider

    scenario = _scenario_payload('CompoundPatternCoverageScenario')
    scenario['sections']['Traffic'] = {
        'density': 0.0,
        'items': [
            {'selected': 'TCP', 'pattern': 'periodic', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0, 'content_type': 'text'},
            {'selected': 'TCP', 'pattern': 'burst', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0, 'content_type': 'text'},
        ],
    }

    mismatch = ai_provider._get_prompt_coverage_mismatch(
        'create two periodic and one burst flows',
        scenario,
    )

    assert mismatch is not None
    missing = {item['target']: item for item in mismatch.get('missing') or []}
    assert missing['Traffic Pattern:periodic']['expected_items'] == 2
    assert missing['Traffic Pattern:periodic']['actual_items'] == 1
    assert 'Traffic Pattern:burst' not in missing


def test_execute_mcp_bridge_prompt_with_preview_retry_retries_once_for_prompt_value_coverage_mismatch(monkeypatch):
    from webapp.routes import ai_provider

    observed_prompts = []
    preview_attempt = {'index': 0}

    first_scenario = _scenario_payload('CoverageValueRetryScenario')
    first_scenario['sections']['Traffic'] = {
        'density': 0.0,
        'items': [{'selected': 'TCP', 'pattern': 'continuous', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0, 'content_type': 'text'}],
    }
    first_scenario['sections']['Routing'] = {
        'density': 0.0,
        'items': [{'selected': 'OSPFv2', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0}],
    }
    second_scenario = _scenario_payload('CoverageValueRetryScenario')
    second_scenario['sections']['Traffic'] = {
        'density': 0.0,
        'items': [
            {'selected': 'TCP', 'pattern': 'continuous', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0, 'content_type': 'text'},
            {'selected': 'UDP', 'pattern': 'periodic', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0, 'content_type': 'text'},
        ],
    }
    second_scenario['sections']['Routing'] = {
        'density': 0.0,
        'items': [{'selected': 'BGP', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0}],
    }

    async def fake_process_query_server_side(client, *, prompt, model, user_prompt=None, initial_draft_id='', emit=None, cancel_check=None, on_response_open=None):
        observed_prompts.append(prompt)
        preview_attempt['index'] = len(observed_prompts) - 1
        return f'response-{len(observed_prompts)}'

    async def fake_call_tool(client, qualified_tool_name, arguments):
        if qualified_tool_name == 'server.scenario.get_draft':
            scenario = first_scenario if preview_attempt['index'] == 0 else second_scenario
            return {'draft': {'draft_id': 'draft-value-coverage-1', 'scenario': scenario}}
        if qualified_tool_name == 'server.scenario.preview_draft':
            return {
                'preview': {'routers': [{'id': 1}], 'hosts': [{'id': 1}, {'id': 2}], 'switches': []},
                'plan': {},
                'flow_meta': {},
            }
        raise AssertionError(f'unexpected tool call: {qualified_tool_name}')

    monkeypatch.setattr(ai_provider, '_mcp_bridge_process_query_server_side', fake_process_query_server_side)
    monkeypatch.setattr(ai_provider, '_mcp_bridge_call_tool', fake_call_tool)

    result = asyncio.run(ai_provider._execute_mcp_bridge_prompt_with_preview_retry(
        object(),
        draft_id='draft-value-coverage-1',
        prompt='base prompt',
        user_prompt='create tcp and udp traffic with periodic pattern and bgp routing',
        model='gpt-oss:20b',
        get_tool='server.scenario.get_draft',
        preview_tool='server.scenario.preview_draft',
    ))

    assert len(observed_prompts) == 2
    prompt_text = observed_prompts[1].lower()
    assert 'missing value coverage: traffic is missing requested selected_values: udp.' in prompt_text
    assert 'missing value coverage: routing is missing requested selected_values: bgp.' in prompt_text
    assert result.get('prompt_coverage_retry_used') is True
    assert result.get('prompt_coverage_mismatch') is None


def test_execute_mcp_bridge_prompt_with_preview_retry_retries_once_for_prompt_coverage_mismatch(monkeypatch):
    from webapp.routes import ai_provider

    observed_prompts = []
    preview_attempt = {'index': 0}

    first_scenario = _scenario_payload('CoverageRetryScenario')
    second_scenario = _scenario_payload('CoverageRetryScenario')
    second_scenario['sections']['Vulnerabilities'] = {
        'density': 0.0,
        'items': [
            {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'demo/web-login-1', 'v_path': 'demo/web-login-1'},
            {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'demo/web-login-2', 'v_path': 'demo/web-login-2'},
            {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'demo/web-login-3', 'v_path': 'demo/web-login-3'},
        ],
        'flag_type': 'text',
    }
    second_scenario['sections']['Traffic'] = {
        'density': 0.0,
        'items': [{'selected': 'TCP', 'pattern': 'continuous', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0, 'content_type': 'text'}],
    }

    async def fake_process_query_server_side(client, *, prompt, model, user_prompt=None, initial_draft_id='', emit=None, cancel_check=None, on_response_open=None):
        observed_prompts.append(prompt)
        preview_attempt['index'] = len(observed_prompts) - 1
        return f'response-{len(observed_prompts)}'

    async def fake_call_tool(client, qualified_tool_name, arguments):
        if qualified_tool_name == 'server.scenario.get_draft':
            scenario = first_scenario if preview_attempt['index'] == 0 else second_scenario
            return {
                'draft': {
                    'draft_id': 'draft-coverage-1',
                    'scenario': scenario,
                },
            }
        if qualified_tool_name == 'server.scenario.preview_draft':
            return {
                'preview': {
                    'routers': [],
                    'hosts': [{'id': idx + 1} for idx in range(2)],
                    'switches': [],
                },
                'plan': {},
                'flow_meta': {},
            }
        raise AssertionError(f'unexpected tool call: {qualified_tool_name}')

    monkeypatch.setattr(ai_provider, '_mcp_bridge_process_query_server_side', fake_process_query_server_side)
    monkeypatch.setattr(ai_provider, '_mcp_bridge_call_tool', fake_call_tool)

    result = asyncio.run(ai_provider._execute_mcp_bridge_prompt_with_preview_retry(
        object(),
        draft_id='draft-coverage-1',
        prompt='base prompt',
        user_prompt='add 3 web vulnerabilities and tcp traffic',
        model='gpt-oss:20b',
        get_tool='server.scenario.get_draft',
        preview_tool='server.scenario.preview_draft',
    ))

    assert len(observed_prompts) == 2
    assert 'previous draft item counts: services=0, traffic=0, vulnerabilities=0, segmentation=0, docker=0.' in observed_prompts[1].lower()
    assert 'missing requirement: vulnerabilities expected at least 3 item(s) but draft has 0.' in observed_prompts[1].lower()
    assert 'add the missing traffic rows before finishing.' in observed_prompts[1].lower()
    assert result.get('prompt_coverage_retry_used') is True
    assert result.get('prompt_coverage_mismatch') is None


def test_execute_mcp_bridge_prompt_with_preview_retry_can_apply_count_then_coverage_retries(monkeypatch):
    from webapp.routes import ai_provider

    observed_prompts = []
    preview_attempt = {'index': 0}

    first_scenario = _scenario_payload('CountThenCoverageScenario')
    second_scenario = _scenario_payload('CountThenCoverageScenario')
    second_scenario['sections']['Node Information'] = {
        'density': 0.0,
        'items': [
            {'selected': 'Server', 'v_metric': 'Count', 'v_count': 8, 'factor': 1.0},
        ],
    }
    third_scenario = _scenario_payload('CountThenCoverageScenario')
    third_scenario['sections']['Node Information'] = {
        'density': 0.0,
        'items': [
            {'selected': 'Server', 'v_metric': 'Count', 'v_count': 8, 'factor': 1.0},
        ],
    }
    third_scenario['sections']['Routing'] = {
        'density': 0.0,
        'items': [
            {'selected': 'OSPFv2', 'r2r_mode': 'min', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0},
        ],
    }
    third_scenario['sections']['Services'] = {
        'density': 0.0,
        'items': [
            {'selected': 'SSH', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0},
            {'selected': 'HTTP', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0},
        ],
    }
    third_scenario['sections']['Traffic'] = {
        'density': 0.0,
        'items': [
            {'selected': 'TCP', 'pattern': 'periodic', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0, 'content_type': 'text'},
            {'selected': 'UDP', 'pattern': 'burst', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0, 'content_type': 'text'},
        ],
    }

    async def fake_process_query_server_side(client, *, prompt, model, user_prompt=None, initial_draft_id='', emit=None, cancel_check=None, on_response_open=None):
        observed_prompts.append(prompt)
        preview_attempt['index'] = len(observed_prompts) - 1
        return f'response-{len(observed_prompts)}'

    async def fake_call_tool(client, qualified_tool_name, arguments):
        if qualified_tool_name == 'server.scenario.get_draft':
            if preview_attempt['index'] == 0:
                scenario = first_scenario
            elif preview_attempt['index'] == 1:
                scenario = second_scenario
            else:
                scenario = third_scenario
            return {
                'draft': {
                    'draft_id': 'draft-count-coverage-1',
                    'scenario': scenario,
                },
            }
        if qualified_tool_name == 'server.scenario.preview_draft':
            if preview_attempt['index'] == 0:
                return {
                    'preview': {'routers': [], 'hosts': [{'id': idx + 1} for idx in range(2)], 'switches': []},
                    'plan': {},
                    'flow_meta': {},
                }
            return {
                'preview': {'routers': [{'id': 1}, {'id': 2}], 'hosts': [{'id': idx + 1} for idx in range(8)], 'switches': []},
                'plan': {},
                'flow_meta': {},
            }
        raise AssertionError(f'unexpected tool call: {qualified_tool_name}')

    monkeypatch.setattr(ai_provider, '_mcp_bridge_process_query_server_side', fake_process_query_server_side)
    monkeypatch.setattr(ai_provider, '_mcp_bridge_call_tool', fake_call_tool)

    result = asyncio.run(ai_provider._execute_mcp_bridge_prompt_with_preview_retry(
        object(),
        draft_id='draft-count-coverage-1',
        prompt='base prompt',
        user_prompt='create a network with 10 nodes, 2 routers with low router-to-router link ratio, two ssh and one web service, plus two tcp and one udp flows, and two periodic and one burst flows',
        model='gpt-oss:20b',
        get_tool='server.scenario.get_draft',
        preview_tool='server.scenario.preview_draft',
    ))

    assert len(observed_prompts) == 3
    assert result.get('count_intent_retry_used') is True
    assert result.get('prompt_coverage_retry_used') is True
    assert result.get('count_intent_mismatch') is None
    assert result.get('prompt_coverage_mismatch') is None
    assert 'previous preview counts:' in observed_prompts[1].lower()
    assert 'missing value coverage: traffic is missing requested selected_values: tcp, udp.' in observed_prompts[2].lower()
    assert 'missing requirement: services expected at least 1 item(s) but draft has 0.' in observed_prompts[2].lower()


def test_build_seeded_traffic_rows_uses_single_explicit_pattern_without_pattern_count():
    from webapp.routes import ai_provider

    prompt = 'Create a network with 2 TCP flows with periodic pattern.'

    assert ai_provider._extract_traffic_protocol_count_intent(prompt) == {'TCP': 2}
    assert ai_provider._extract_traffic_pattern_count_intent(prompt) == {}
    assert ai_provider._build_seeded_traffic_rows(prompt) == [
        {'protocol': 'TCP', 'count': 2, 'pattern': 'periodic', 'content_type': 'text'},
    ]


def test_build_seeded_traffic_rows_skips_ambiguous_multi_pattern_prompt():
    from webapp.routes import ai_provider

    prompt = 'Create tcp and udp traffic with periodic and burst patterns.'

    assert ai_provider._build_seeded_traffic_rows(prompt) == []


def test_execute_mcp_bridge_prompt_with_preview_retry_can_retry_prompt_coverage_twice(monkeypatch):
    from webapp.routes import ai_provider

    observed_prompts = []
    preview_attempt = {'index': 0}

    first_scenario = _scenario_payload('CoverageRetryTwiceScenario')
    second_scenario = _scenario_payload('CoverageRetryTwiceScenario')
    second_scenario['sections']['Node Information'] = {
        'density': 0.0,
        'items': [
            {'selected': 'Server', 'v_metric': 'Count', 'v_count': 8, 'factor': 1.0},
        ],
    }
    second_scenario['sections']['Routing'] = {
        'density': 0.0,
        'items': [
            {'selected': 'OSPFv2', 'r2r_mode': 'min', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0},
        ],
    }
    second_scenario['sections']['Services'] = {
        'density': 0.0,
        'items': [
            {'selected': 'SSH', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0},
            {'selected': 'HTTP', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0},
        ],
    }
    second_scenario['sections']['Traffic'] = {
        'density': 0.0,
        'items': [
            {'selected': 'TCP', 'pattern': 'periodic', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0, 'content_type': 'text'},
        ],
    }
    third_scenario = deepcopy(second_scenario)
    third_scenario['sections']['Traffic'] = {
        'density': 0.0,
        'items': [
            {'selected': 'TCP', 'pattern': 'periodic', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0, 'content_type': 'text'},
            {'selected': 'UDP', 'pattern': 'burst', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0, 'content_type': 'text'},
        ],
    }

    async def fake_process_query_server_side(client, *, prompt, model, user_prompt=None, initial_draft_id='', emit=None, cancel_check=None, on_response_open=None):
        observed_prompts.append(prompt)
        preview_attempt['index'] = len(observed_prompts) - 1
        return f'response-{len(observed_prompts)}'

    async def fake_call_tool(client, qualified_tool_name, arguments):
        if qualified_tool_name == 'server.scenario.get_draft':
            if preview_attempt['index'] == 0:
                scenario = first_scenario
            elif preview_attempt['index'] == 1:
                scenario = second_scenario
            else:
                scenario = third_scenario
            return {
                'draft': {
                    'draft_id': 'draft-coverage-twice-1',
                    'scenario': scenario,
                },
            }
        if qualified_tool_name == 'server.scenario.preview_draft':
            return {
                'preview': {'routers': [{'id': 1}, {'id': 2}], 'hosts': [{'id': idx + 1} for idx in range(8)], 'switches': []},
                'plan': {},
                'flow_meta': {},
            }
        raise AssertionError(f'unexpected tool call: {qualified_tool_name}')

    monkeypatch.setattr(ai_provider, '_mcp_bridge_process_query_server_side', fake_process_query_server_side)
    monkeypatch.setattr(ai_provider, '_mcp_bridge_call_tool', fake_call_tool)

    result = asyncio.run(ai_provider._execute_mcp_bridge_prompt_with_preview_retry(
        object(),
        draft_id='draft-coverage-twice-1',
        prompt='base prompt',
        user_prompt='create a network with 10 nodes, 2 routers with low router-to-router link ratio, two ssh and one web service, plus two tcp and one udp flows, and two periodic and one burst flows',
        model='gpt-oss:20b',
        get_tool='server.scenario.get_draft',
        preview_tool='server.scenario.preview_draft',
    ))

    assert len(observed_prompts) == 3
    assert result.get('count_intent_retry_used') is False
    assert result.get('prompt_coverage_retry_used') is True
    assert result.get('count_intent_mismatch') is None
    assert result.get('prompt_coverage_mismatch') is None
    assert 'missing value coverage: traffic is missing requested selected_values: tcp, udp.' in observed_prompts[1].lower()
    assert 'missing value coverage: traffic is missing requested selected_values: udp.' in observed_prompts[2].lower()
    assert 'missing value coverage: traffic is missing requested pattern_values: burst.' in observed_prompts[2].lower()


def test_execute_mcp_bridge_prompt_with_preview_retry_retries_once_for_count_mismatch(monkeypatch):
    from webapp.routes import ai_provider

    observed_prompts = []
    preview_attempt = {'index': 0}

    async def fake_process_query_server_side(client, *, prompt, model, user_prompt=None, initial_draft_id='', emit=None, cancel_check=None, on_response_open=None):
        observed_prompts.append(prompt)
        preview_attempt['index'] = len(observed_prompts) - 1
        return f'response-{len(observed_prompts)}'

    async def fake_call_tool(client, qualified_tool_name, arguments):
        if qualified_tool_name == 'server.scenario.get_draft':
            return {
                'draft': {
                    'draft_id': 'draft-1',
                    'scenario': _scenario_payload('RetryScenario'),
                },
            }
        if qualified_tool_name == 'server.scenario.preview_draft':
            if preview_attempt['index'] == 0:
                return {
                    'preview': {
                        'routers': [],
                        'hosts': [{'id': idx + 1} for idx in range(10)],
                        'switches': [{'id': 1}],
                    },
                    'plan': {},
                    'flow_meta': {},
                }
            return {
                'preview': {
                    'routers': [{'id': idx + 1} for idx in range(10)],
                    'hosts': [{'id': idx + 1} for idx in range(20)],
                    'switches': [{'id': 1}],
                },
                'plan': {},
                'flow_meta': {},
            }
        raise AssertionError(f'unexpected tool call: {qualified_tool_name}')

    monkeypatch.setattr(ai_provider, '_mcp_bridge_process_query_server_side', fake_process_query_server_side)
    monkeypatch.setattr(ai_provider, '_mcp_bridge_call_tool', fake_call_tool)

    result = asyncio.run(ai_provider._execute_mcp_bridge_prompt_with_preview_retry(
        object(),
        draft_id='draft-1',
        prompt='base prompt',
        user_prompt='create a topology with 30 nodes and 10 routers',
        model='gpt-oss:20b',
        get_tool='server.scenario.get_draft',
        preview_tool='server.scenario.preview_draft',
    ))

    assert len(observed_prompts) == 2
    assert 'Previous preview counts: routers=0, hosts=10, switches=1.' in observed_prompts[1]
    assert 'Node Information host total=20' in observed_prompts[1]
    assert result.get('count_intent_retry_used') is True
    assert result.get('count_intent_mismatch') is None


def test_execute_mcp_bridge_prompt_with_preview_retry_mentions_vulnerability_host_budget(monkeypatch):
    from webapp.routes import ai_provider

    observed_prompts = []
    preview_attempt = {'index': 0}
    repaired_scenario = _scenario_payload('CountWithVulnRetryScenario')
    repaired_scenario['sections']['Node Information'] = {
        'density': 0.0,
        'items': [
            {'selected': 'Server', 'v_metric': 'Count', 'v_count': 19, 'factor': 1.0},
            {'selected': 'Docker', 'v_metric': 'Count', 'v_count': 3, 'factor': 1.0},
        ],
    }
    repaired_scenario['sections']['Routing'] = {
        'density': 0.0,
        'items': [
            {'selected': 'OSPFv2', 'r2r_mode': 'min', 'v_metric': 'Count', 'v_count': 8, 'factor': 1.0},
        ],
    }
    repaired_scenario['sections']['Vulnerabilities'] = {
        'density': 0.0,
        'items': [
            {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'demo/web-1', 'v_path': 'demo/web-1'},
            {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'demo/web-2', 'v_path': 'demo/web-2'},
            {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'demo/web-3', 'v_path': 'demo/web-3'},
        ],
        'flag_type': 'text',
    }

    async def fake_process_query_server_side(_client, prompt, model, **_kwargs):
        observed_prompts.append(prompt)
        return 'ok'

    async def fake_call_tool(_session, qualified_tool_name, tool_args):
        if qualified_tool_name == 'server.scenario.get_draft':
            return {
                'draft': {
                    'draft_id': 'draft-vuln',
                    'scenario': repaired_scenario if preview_attempt['index'] >= 1 else _scenario_payload('CountWithVulnRetryScenario'),
                },
            }
        if qualified_tool_name == 'server.scenario.preview_draft':
            preview_attempt['index'] += 1
            if preview_attempt['index'] == 1:
                return {
                    'preview': {
                        'routers': [{'id': idx + 1} for idx in range(8)],
                        'hosts': [{'id': idx + 1} for idx in range(26)],
                        'switches': [{'id': idx + 1} for idx in range(8)],
                    },
                    'plan': {},
                    'flow_meta': {},
                }
            return {
                'preview': {
                    'routers': [{'id': idx + 1} for idx in range(8)],
                    'hosts': [{'id': idx + 1} for idx in range(22)],
                    'switches': [{'id': idx + 1} for idx in range(8)],
                },
                'plan': {},
                'flow_meta': {},
            }
        raise AssertionError(f'unexpected tool call: {qualified_tool_name}')

    monkeypatch.setattr(ai_provider, '_mcp_bridge_process_query_server_side', fake_process_query_server_side)
    monkeypatch.setattr(ai_provider, '_mcp_bridge_call_tool', fake_call_tool)

    result = asyncio.run(ai_provider._execute_mcp_bridge_prompt_with_preview_retry(
        object(),
        draft_id='draft-vuln',
        prompt='base prompt',
        user_prompt='I want a network with 30 nodes, 8 routers with low router-to-router link ratio. I also want 3 vulnerabilities related to web',
        model='gpt-oss:20b',
        get_tool='server.scenario.get_draft',
        preview_tool='server.scenario.preview_draft',
    ))

    assert len(observed_prompts) == 2
    assert 'Previous preview counts: routers=8, hosts=26, switches=8.' in observed_prompts[1]
    assert 'Node Information host total=22' in observed_prompts[1]
    assert '3 vulnerability target(s)' in observed_prompts[1]
    assert 'keep the other Node Information host rows to 19' in observed_prompts[1]
    assert 'author Routing first, then Node Information host rows, then Vulnerabilities' in observed_prompts[1]
    assert 'do not pass v_type or v_vector filters' in observed_prompts[1].lower()
    assert result.get('count_intent_retry_used') is True
    assert result.get('count_intent_mismatch') is None


def test_mcp_bridge_process_query_retries_once_on_ollama_tool_parse_error():
    from webapp.routes import ai_provider

    observed_prompts = []

    class _FakeClient:
        async def process_query(self, prompt):
            observed_prompts.append(prompt)
            if len(observed_prompts) == 1:
                raise ai_provider.ProviderAdapterError(
                    'Ollama returned HTTP 500. {"error":"error parsing tool call: raw=..."}',
                    status_code=502,
                )
            return 'ok'

    result = asyncio.run(ai_provider._mcp_bridge_process_query_server_side(
        _FakeClient(),
        prompt='create a scenario with 3 different types of sql vulnerabilities',
        model='gpt-oss:20b',
        user_prompt='create a scenario with 3 different types of sql vulnerabilities',
    ))

    assert result == 'ok'
    assert len(observed_prompts) == 2
    assert 'do not pass factor' in observed_prompts[1].lower()
    assert 'multiple separate add_vulnerability_item calls' in observed_prompts[1].lower()
    assert 'pass only strict json keys draft_id, v_name, v_path, and v_count' in observed_prompts[1].lower()


def test_mcp_bridge_process_query_retry_prompt_mentions_traffic_factor_omission():
    from webapp.routes import ai_provider

    observed_prompts = []

    class _FakeClient:
        async def process_query(self, prompt):
            observed_prompts.append(prompt)
            if len(observed_prompts) == 1:
                raise ai_provider.ProviderAdapterError(
                    'Ollama returned HTTP 500. {"error":"error parsing tool call: raw=..."}',
                    status_code=502,
                )
            return 'ok'

    result = asyncio.run(ai_provider._mcp_bridge_process_query_server_side(
        _FakeClient(),
        prompt='base prompt',
        model='gpt-oss:20b',
        user_prompt='create 3 tcp flows with periodic pattern',
    ))

    assert result == 'ok'
    assert len(observed_prompts) == 2
    assert 'when count is present, omit factor entirely' in observed_prompts[1].lower()
    assert 'example valid traffic tool call json' in observed_prompts[1].lower()


def test_ai_generate_scenario_preview_concretizes_random_routing_before_preview(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    generated = {
        'scenario': {
            'name': 'RandomRoutingScenario',
            'density_count': 0,
            'notes': 'Generated with placeholder routing.',
            'sections': {
                'Node Information': {
                    'density': 0,
                    'items': [
                        {'selected': 'PC', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0},
                    ],
                },
                'Routing': {
                    'density': 0.0,
                    'items': [
                        {'selected': 'Random', 'v_metric': 'Count', 'v_count': 1, 'factor': 1.0},
                    ],
                },
                'Services': {'density': 0.0, 'items': []},
                'Traffic': {'density': 0.0, 'items': []},
                'Vulnerabilities': {'density': 0.0, 'items': [], 'flag_type': 'text'},
                'Segmentation': {'density': 0.0, 'items': []},
            },
        }
    }

    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_ollama_urlopen_factory(generated_payload=generated, models=['llama3.1']),
    )

    scenario = _scenario_payload('RandomRoutingSeedScenario')
    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'llama3.1',
            'prompt': 'Generate a small scenario with one router.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('success') is True
    routing_items = (payload.get('generated_scenario') or {}).get('sections', {}).get('Routing', {}).get('items') or []
    assert routing_items
    assert routing_items[0].get('selected') in {'RIP', 'RIPNG', 'BGP', 'OSPFv2', 'OSPFv3'}
    preview = payload.get('preview') or {}
    assert len(preview.get('routers') or []) == 1


def test_backend_concretize_preview_placeholders_handles_non_routing_randoms(monkeypatch):
    from webapp import app_backend as backend

    monkeypatch.setattr(
        backend,
        '_load_backend_vuln_catalog_items',
        lambda: [{'Name': 'Demo Vuln', 'Path': 'demo/path', 'Description': 'Demo desc'}],
    )

    scenario = {
        'name': 'RandomEverywhere',
        'density_count': 0,
        'sections': {
            'Node Information': {'density': 0, 'items': []},
            'Routing': {'density': 0, 'items': []},
            'Services': {'density': 0, 'items': [{'selected': 'Random'}]},
            'Traffic': {
                'density': 0,
                'items': [{
                    'selected': 'Random',
                    'content_type': 'Random',
                    'pattern': 'Random',
                    'rate_kbps': 'Random',
                    'period_s': 'Random',
                    'jitter_pct': 'Random',
                }],
            },
            'Vulnerabilities': {'density': 0, 'flag_type': 'text', 'items': [{'selected': 'Random'}]},
            'Segmentation': {'density': 0, 'items': [{'selected': 'Random'}]},
        },
    }

    concretized = backend._concretize_preview_placeholders(scenario, seed=7)
    sections = concretized.get('sections') or {}

    node_items = (sections.get('Node Information') or {}).get('items') or []
    assert node_items
    assert node_items[-1].get('selected') == 'PC'
    assert node_items[-1].get('v_count') == 10

    service_items = (sections.get('Services') or {}).get('items') or []
    assert service_items[0].get('selected') in {'SSH', 'HTTP', 'DHCPClient'}

    traffic_items = (sections.get('Traffic') or {}).get('items') or []
    assert traffic_items[0].get('selected') in {'TCP', 'UDP'}
    assert traffic_items[0].get('content_type') in {'text', 'photo', 'audio', 'video', 'gibberish'}
    assert traffic_items[0].get('pattern') in {'continuous', 'periodic', 'burst', 'poisson', 'ramp'}
    assert traffic_items[0].get('rate_kbps') in {32.0, 128.0, 256.0, 512.0}
    assert traffic_items[0].get('period_s') in {0.5, 2.0, 5.0, 8.0}
    assert traffic_items[0].get('jitter_pct') in {5.0, 15.0, 25.0, 35.0}
    assert (traffic_items[0].get('rate_kbps'), traffic_items[0].get('period_s'), traffic_items[0].get('jitter_pct')) != (64.0, 1.0, 10.0)

    vuln_items = (sections.get('Vulnerabilities') or {}).get('items') or []
    assert vuln_items[0].get('selected') == 'Specific'
    assert vuln_items[0].get('v_name') == 'Demo Vuln'
    assert vuln_items[0].get('v_path') == 'demo/path'

    segmentation_items = (sections.get('Segmentation') or {}).get('items') or []
    assert segmentation_items[0].get('selected') in {'Firewall', 'NAT'}


def test_backend_concretize_preview_placeholders_normalizes_routing_count_rows():
    from webapp import app_backend as backend

    scenario = {
        'name': 'RoutingCountOnly',
        'density_count': 0,
        'sections': {
            'Node Information': {'density': 0, 'items': []},
            'Routing': {
                'density': 0,
                'items': [
                    {'protocol': 'ospf', 'v_count': 5, 'factor': 1.0},
                ],
            },
            'Services': {'density': 0, 'items': []},
            'Traffic': {'density': 0, 'items': []},
            'Vulnerabilities': {'density': 0, 'flag_type': 'text', 'items': []},
            'Segmentation': {'density': 0, 'items': []},
        },
    }

    concretized = backend._concretize_preview_placeholders(scenario, seed=7)
    routing_items = (concretized.get('sections') or {}).get('Routing', {}).get('items') or []

    assert routing_items
    assert routing_items[0].get('selected') == 'OSPFv2'
    assert routing_items[0].get('v_metric') == 'Count'
    assert routing_items[0].get('v_count') == 5


def test_backend_concretize_preview_placeholders_resolves_routing_random_edge_modes():
    from webapp import app_backend as backend

    scenario = {
        'name': 'RoutingRandomAi',
        'density_count': 0,
        'sections': {
            'Node Information': {'density': 0, 'items': []},
            'Routing': {
                'density': 0,
                'items': [
                    {
                        'selected': 'Random',
                        'factor': 1.0,
                        'v_metric': 'Count',
                        'v_count': 3,
                        'r2r_mode': 'Random',
                        'r2s_mode': 'Random',
                    },
                ],
            },
            'Services': {'density': 0, 'items': []},
            'Traffic': {'density': 0, 'items': []},
            'Vulnerabilities': {'density': 0, 'flag_type': 'text', 'items': []},
            'Segmentation': {'density': 0, 'items': []},
        },
    }

    concretized = backend._concretize_preview_placeholders(scenario, seed=7)
    routing_items = (concretized.get('sections') or {}).get('Routing', {}).get('items') or []

    assert routing_items
    routing_item = routing_items[0]
    assert routing_item.get('selected') in {'RIP', 'RIPNG', 'BGP', 'OSPFv2', 'OSPFv3'}
    assert routing_item.get('r2r_mode') in {'Min', 'Uniform', 'Exact', 'NonUniform'}
    assert routing_item.get('r2s_mode') in {'Min', 'Uniform', 'Exact', 'NonUniform'}

    if routing_item.get('r2r_mode') == 'Exact':
        assert int(routing_item.get('r2r_edges') or 0) > 0
    else:
        assert routing_item.get('r2r_edges') in (None, '', 0)

    if routing_item.get('r2s_mode') == 'Exact':
        assert int(routing_item.get('r2s_edges') or 0) > 0
    if routing_item.get('r2s_mode') == 'NonUniform':
        assert int(routing_item.get('r2s_hosts_min') or 0) > 0
        assert int(routing_item.get('r2s_hosts_max') or 0) >= int(routing_item.get('r2s_hosts_min') or 0)


def test_backend_concretize_preview_placeholders_normalizes_other_section_aliases():
    from webapp import app_backend as backend

    scenario = {
        'name': 'AliasRows',
        'density_count': 0,
        'sections': {
            'Node Information': {
                'density': 0,
                'items': [
                    {'role': 'servers', 'count': 2},
                ],
            },
            'Routing': {'density': 0, 'items': []},
            'Services': {
                'density': 0,
                'items': [
                    {'service': 'https', 'v_count': 3},
                ],
            },
            'Traffic': {
                'density': 0,
                'items': [
                    {
                        'protocol': 'udp',
                        'content': 'image',
                        'pattern': 'bursty',
                        'rate': 128,
                        'period': 2,
                        'jitter': 5,
                        'v_count': 4,
                    },
                ],
            },
            'Vulnerabilities': {'density': 0, 'flag_type': 'text', 'items': []},
            'Segmentation': {
                'density': 0,
                'items': [
                    {'kind': 'fw', 'v_count': 2},
                ],
            },
        },
    }

    concretized = backend._concretize_preview_placeholders(scenario, seed=7)
    sections = concretized.get('sections') or {}

    node_items = (sections.get('Node Information') or {}).get('items') or []
    assert node_items[0].get('selected') == 'Server'
    assert node_items[0].get('v_metric') == 'Count'
    assert node_items[0].get('v_count') == 2

    service_items = (sections.get('Services') or {}).get('items') or []
    assert service_items[0].get('selected') == 'HTTP'
    assert service_items[0].get('v_metric') == 'Count'
    assert service_items[0].get('v_count') == 3

    traffic_items = (sections.get('Traffic') or {}).get('items') or []
    assert traffic_items[0].get('selected') == 'UDP'
    assert traffic_items[0].get('content_type') == 'photo'
    assert traffic_items[0].get('pattern') == 'burst'
    assert traffic_items[0].get('rate_kbps') == 128.0
    assert traffic_items[0].get('period_s') == 2.0
    assert traffic_items[0].get('jitter_pct') == 5.0
    assert traffic_items[0].get('v_metric') == 'Count'
    assert traffic_items[0].get('v_count') == 4

    segmentation_items = (sections.get('Segmentation') or {}).get('items') or []
    assert segmentation_items[0].get('selected') == 'Firewall'
    assert segmentation_items[0].get('v_metric') == 'Count'
    assert segmentation_items[0].get('v_count') == 2


def test_ai_generate_scenario_preview_stream_cancel_endpoint_marks_active_request():
    client = app.test_client()
    _login(client)

    from webapp.routes import ai_provider

    request_id = 'cancel-me-1'
    entry = ai_provider._register_ai_stream(request_id)
    fake_response = _ClosableResponse()
    fake_client = _AbortableClient()
    entry['response'] = fake_response
    entry['client'] = fake_client

    try:
        resp = client.post(
            '/api/ai/generate_scenario_preview_stream/cancel',
            json={'request_id': request_id},
        )
        assert resp.status_code == 200
        payload = resp.get_json() or {}
        assert payload.get('success') is True
        assert payload.get('request_id') == request_id
        assert entry['cancelled'].is_set() is True
        assert fake_response.closed is True
        assert fake_client.abort_current_query is True
    finally:
        ai_provider._unregister_ai_stream(request_id)


def test_ai_generate_scenario_preview_stream_surfaces_bridge_tool_error(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(ai_provider, 'urlopen', _fake_ollama_urlopen_factory(generated_payload={'scenario': _scenario_payload('unused')}, models=['qwen2.5:32b']))
    monkeypatch.setattr(ai_provider, 'McpBridgeClient', _FailingMcpBridgeClient)

    scenario = _scenario_payload('BridgeFailureScenario')
    resp = client.post(
        '/api/ai/generate_scenario_preview_stream',
        json={
            'provider': 'ollama',
            'bridge_mode': 'mcp-python-sdk',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'qwen2.5:32b',
            'prompt': 'Create a small scenario with an SQL vulnerability.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
            'mcp_server_path': 'MCP/server.py',
        },
        buffered=False,
    )
    assert resp.status_code == 200

    events = []
    for chunk in resp.response:
        text = chunk.decode('utf-8') if isinstance(chunk, bytes) else str(chunk)
        for line in text.splitlines():
            if line.strip():
                events.append(json.loads(line))

    error_event = next(event for event in events if event.get('type') == 'error')
    assert 'No vulnerability catalog match found' in str(error_event.get('error') or '')
    assert 'Unexpected generation failure while contacting Ollama.' not in str(error_event.get('error') or '')


def test_ai_download_transcript_returns_attachment_response():
    client = app.test_client()
    _login(client)

    resp = client.post(
        '/api/ai/download_transcript',
        data={
            'transcript': 'Status: Done\n\nLLM Output:\nhello world',
            'filename': 'My Transcript',
        },
    )

    assert resp.status_code == 200
    assert resp.mimetype == 'text/plain'
    disposition = str(resp.headers.get('Content-Disposition') or '')
    assert 'attachment;' in disposition
    assert 'my-transcript.txt' in disposition
    assert 'hello world' in resp.get_data(as_text=True)


def test_ai_generate_scenario_preview_recovers_from_unknown_draft_id_once(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(ai_provider, 'urlopen', _fake_ollama_urlopen_factory(generated_payload={'scenario': _scenario_payload('unused')}, models=['gpt-oss:20b']))
    monkeypatch.setattr(ai_provider, 'McpBridgeClient', _UnknownDraftOnceMcpBridgeClient)

    scenario = _scenario_payload('RecoverUnknownDraftScenario')
    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'bridge_mode': 'mcp-python-sdk',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'gpt-oss:20b',
            'mcp_server_path': 'MCP/server.py',
            'enabled_tools': [
                'server.scenario.create_draft',
                'server.scenario.get_draft',
                'server.scenario.preview_draft',
            ],
            'prompt': 'Generate a scenario with 30 nodes, 8 routers, and web vulnerabilities.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('success') is True
    assert payload.get('draft_id')
    generated_scenario = payload.get('generated_scenario') or {}
    assert generated_scenario.get('name') == 'RecoverUnknownDraftScenario'


def test_ai_generate_scenario_preview_stream_recovers_from_unknown_draft_id_once(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(ai_provider, 'urlopen', _fake_ollama_urlopen_factory(generated_payload={'scenario': _scenario_payload('unused')}, models=['gpt-oss:20b']))
    monkeypatch.setattr(ai_provider, 'McpBridgeClient', _UnknownDraftOnceMcpBridgeClient)

    scenario = _scenario_payload('RecoverUnknownDraftStreamScenario')
    resp = client.post(
        '/api/ai/generate_scenario_preview_stream',
        json={
            'provider': 'ollama',
            'bridge_mode': 'mcp-python-sdk',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'gpt-oss:20b',
            'mcp_server_path': 'MCP/server.py',
            'enabled_tools': [
                'server.scenario.create_draft',
                'server.scenario.get_draft',
                'server.scenario.preview_draft',
            ],
            'prompt': 'Generate a scenario with 30 nodes, 8 routers, and web vulnerabilities.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
        buffered=False,
    )

    assert resp.status_code == 200
    events = []
    for chunk in resp.response:
        text = chunk.decode('utf-8') if isinstance(chunk, bytes) else str(chunk)
        for line in text.splitlines():
            if line.strip():
                events.append(json.loads(line))

    status_messages = [str(event.get('message') or '') for event in events if event.get('type') == 'status']
    assert any('Recreating the draft and retrying once' in message for message in status_messages)
    result_event = next(event for event in events if event.get('type') == 'result')
    payload = result_event.get('data') or {}
    assert payload.get('success') is True
    assert payload.get('draft_id')


def test_ai_browser_flow_validate_generate_save_load_roundtrip(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    generated = {
        'scenario': {
            'name': 'BrowserRoundtripScenario',
            'density_count': 0,
            'notes': 'Round-tripped from AI browser flow.',
            'sections': {
                'Node Information': {
                    'density': 0,
                    'items': [
                        {'selected': 'PC', 'v_metric': 'Count', 'v_count': 3, 'factor': 1.0},
                    ],
                },
                'Routing': {'density': 0.0, 'items': []},
                'Services': {'density': 0.0, 'items': []},
                'Traffic': {'density': 0.0, 'items': []},
                'Vulnerabilities': {'density': 0.0, 'items': [], 'flag_type': 'text'},
                'Segmentation': {'density': 0.0, 'items': []},
            },
        }
    }
    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_ollama_urlopen_factory(generated_payload=generated, models=['gpt-oss:20b']),
    )

    page = client.get('/?tab=ai-generator')
    assert page.status_code == 200
    assert b'AI Generator' in page.data

    validate_resp = client.post(
        '/api/ai/provider/validate',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'gpt-oss:20b',
        },
    )
    assert validate_resp.status_code == 200
    validate_payload = validate_resp.get_json() or {}
    assert validate_payload.get('success') is True
    assert validate_payload.get('model_found') is True
    assert 'gpt-oss:20b' in (validate_payload.get('models') or [])

    scenario = _scenario_payload('BrowserSeedScenario')
    scenario['ai_generator'] = {
        'provider': 'ollama',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'gpt-oss:20b',
        'draft_prompt': 'Generate a small offline scenario with three PCs.',
    }
    generate_resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'gpt-oss:20b',
            'prompt': scenario['ai_generator']['draft_prompt'],
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )
    assert generate_resp.status_code == 200
    generate_payload = generate_resp.get_json() or {}
    assert generate_payload.get('success') is True
    assert generate_payload.get('generated_scenario', {}).get('name') == 'BrowserSeedScenario'
    assert len((generate_payload.get('preview') or {}).get('hosts') or []) == 3
    assert generate_payload.get('provider_attempts')

    save_resp = client.post(
        '/save_xml_api',
        data=json.dumps({'scenarios': [generate_payload['generated_scenario']]}),
        content_type='application/json',
    )
    assert save_resp.status_code == 200
    save_payload = save_resp.get_json() or {}
    assert save_payload.get('ok') is True

    parsed = backend._parse_scenarios_xml(save_payload.get('result_path'))
    loaded = (parsed.get('scenarios') or [])[0]
    assert loaded.get('name') == 'BrowserSeedScenario'
    assert loaded.get('notes') == 'Round-tripped from AI browser flow.'
    restored_ai = loaded.get('ai_generator') or {}
    assert restored_ai.get('provider') == 'ollama'
    assert restored_ai.get('model') == 'gpt-oss:20b'


def test_ai_generate_scenario_preview_falls_back_to_plain_json_format(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    generated = {
        'scenario': {
            'name': 'FallbackFormatScenario',
            'notes': 'Recovered with plain json format.',
            'sections': {
                'Node Information': {
                    'density': 0,
                    'items': [{'selected': 'PC', 'v_metric': 'Count', 'v_count': 3, 'factor': 1.0}],
                },
                'Routing': {'density': 0.0, 'items': []},
                'Services': {'density': 0.0, 'items': []},
                'Traffic': {'density': 0.0, 'items': []},
                'Vulnerabilities': {'density': 0.0, 'items': [], 'flag_type': 'text'},
                'Segmentation': {'density': 0.0, 'items': []},
            },
        }
    }

    state = {'generate_calls': 0}

    def fake_urlopen(request_obj, timeout=0):
        url = request_obj.full_url
        if url.endswith('/api/tags'):
            return _FakeResponse({'models': [{'name': 'gpt-oss:20b'}]})
        body = json.loads(request_obj.data.decode('utf-8'))
        state['generate_calls'] += 1
        if state['generate_calls'] == 1:
            assert isinstance(body.get('format'), dict)
            raise HTTPError(
                url,
                500,
                'Internal Server Error',
                hdrs=None,
                fp=BytesIO(b'{"error":"failed to load model vocabulary required for format"}'),
            )
        assert body.get('format') == 'json'
        return _FakeResponse({'response': json.dumps(generated)})

    monkeypatch.setattr(ai_provider, 'urlopen', fake_urlopen)

    scenario = _scenario_payload('FallbackSeedScenario')
    scenario['ai_generator'] = {
        'provider': 'ollama',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'gpt-oss:20b',
    }

    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'gpt-oss:20b',
            'prompt': 'Generate a small offline scenario with three PCs.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('success') is True
    assert payload.get('generated_scenario', {}).get('name') == 'FallbackSeedScenario'
    attempts = payload.get('provider_attempts') or []
    assert attempts
    assert attempts[0].get('format_mode') == 'json'


def test_ai_provider_validate_discovers_tools_for_mcp_python_sdk(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp.routes import ai_provider

    monkeypatch.setattr(ai_provider, 'urlopen', _fake_ollama_urlopen_factory(generated_payload={'scenario': _scenario_payload('unused')}, models=['gpt-oss:20b']))
    monkeypatch.setattr(ai_provider, 'McpBridgeClient', _FakeMcpBridgeClient)

    resp = client.post(
        '/api/ai/provider/validate',
        json={
            'provider': 'ollama',
            'bridge_mode': 'mcp-python-sdk',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'gpt-oss:20b',
            'mcp_server_path': 'MCP/server.py',
            'enabled_tools': ['server.scenario.replace_section'],
        },
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('success') is True
    assert payload.get('bridge', {}).get('bridge_mode') == 'mcp-python-sdk'
    assert payload.get('bridge', {}).get('hil_enabled') is False
    tool_names = [tool.get('name') for tool in (payload.get('tools') or [])]
    assert 'server.scenario.replace_section' in tool_names
    assert 'server.scenario.create_draft' not in tool_names
    assert 'server.scenario.preview_draft' not in tool_names
    assert 'server.scenario.delete_draft' not in tool_names
    assert payload.get('enabled_tools') == ['server.scenario.replace_section']


def test_ai_provider_validate_skip_bridge_refreshes_models_without_mcp(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp.routes import ai_provider

    monkeypatch.setattr(
        ai_provider,
        'urlopen',
        _fake_ollama_urlopen_factory(generated_payload={'scenario': _scenario_payload('unused')}, models=['gpt-oss:20b', 'llama3.2:latest']),
    )

    def _unexpected_client(*args, **kwargs):
        raise AssertionError('MCP Python SDK bridge should not be initialized when skip_bridge is true')

    monkeypatch.setattr(ai_provider, 'McpBridgeClient', _unexpected_client)

    resp = client.post(
        '/api/ai/provider/validate',
        json={
            'provider': 'ollama',
            'bridge_mode': 'mcp-python-sdk',
            'skip_bridge': True,
            'base_url': 'http://127.0.0.1:11434',
            'model': 'gpt-oss:20b',
            'mcp_server_path': 'MCP/server.py',
        },
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('success') is True
    assert payload.get('bridge') is None
    assert payload.get('tools') is None
    assert 'gpt-oss:20b' in (payload.get('models') or [])
    assert 'llama3.2:latest' in (payload.get('models') or [])


def test_ai_provider_validate_times_out_on_hung_ollama_tags_request(monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp.routes import ai_provider

    def fake_urlopen(request_obj, timeout=0):
        time.sleep(2.0)
        return _FakeResponse({'models': [{'name': 'qwen3.5:35b'}]})

    monkeypatch.setattr(ai_provider, 'urlopen', fake_urlopen)

    resp = client.post(
        '/api/ai/provider/validate',
        json={
            'provider': 'ollama',
            'skip_bridge': True,
            'base_url': 'http://127.0.0.1:11434',
            'model': 'qwen3.5:35b',
            'timeout_seconds': 1,
        },
    )

    assert resp.status_code == 502
    payload = resp.get_json() or {}
    assert payload.get('success') is False
    assert 'could not reach ollama' in str(payload.get('error') or '').lower()
    assert 'timed out' in str(payload.get('error') or '').lower()


def test_ai_generate_scenario_preview_uses_mcp_python_sdk_bridge(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(ai_provider, 'urlopen', _fake_ollama_urlopen_factory(generated_payload={'scenario': _scenario_payload('unused')}, models=['gpt-oss:20b']))
    monkeypatch.setattr(ai_provider, 'McpBridgeClient', _FakeMcpBridgeClient)

    scenario = _scenario_payload('BridgeSeedScenario')
    scenario['ai_generator'] = {
        'provider': 'ollama',
        'bridge_mode': 'mcp-python-sdk',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'gpt-oss:20b',
        'mcp_server_path': 'MCP/server.py',
        'enabled_tools': [
            'server.scenario.replace_section',
        ],
    }

    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'bridge_mode': 'mcp-python-sdk',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'gpt-oss:20b',
            'mcp_server_path': 'MCP/server.py',
            'enabled_tools': scenario['ai_generator']['enabled_tools'],
            'prompt': 'Build a small offline three-host scenario.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('success') is True
    assert payload.get('bridge_mode') == 'mcp-python-sdk'
    assert payload.get('generated_scenario', {}).get('name') == 'BridgeSeedScenario'
    assert payload.get('generated_scenario', {}).get('notes') == 'Generated through MCP bridge.'
    assert len((payload.get('preview') or {}).get('hosts') or []) == 3
    assert payload.get('draft_id') == 'draft-bridge-1'
    assert payload.get('enabled_tools') == ['server.scenario.replace_section']


def test_ai_generate_scenario_preview_disables_mcp_python_sdk_hil(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(ai_provider, 'urlopen', _fake_ollama_urlopen_factory(generated_payload={'scenario': _scenario_payload('unused')}, models=['gpt-oss:20b']))

    created_clients = []

    class _TrackingFakeMcpBridgeClient(_FakeMcpBridgeClient):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            created_clients.append(self)

    monkeypatch.setattr(ai_provider, 'McpBridgeClient', _TrackingFakeMcpBridgeClient)

    scenario = _scenario_payload('BridgeSeedScenario')
    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'bridge_mode': 'mcp-python-sdk',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'gpt-oss:20b',
            'mcp_server_path': 'MCP/server.py',
            'enabled_tools': [
                'server.scenario.create_draft',
            ],
            'prompt': 'Generate a three-host scenario.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )

    assert resp.status_code == 200
    assert created_clients
    assert created_clients[0].hil_manager.enabled is False
    assert created_clients[0].hil_manager.session_auto_execute is True


def test_ai_generate_scenario_preview_can_reenable_mcp_python_sdk_hil(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(ai_provider, 'urlopen', _fake_ollama_urlopen_factory(generated_payload={'scenario': _scenario_payload('unused')}, models=['gpt-oss:20b']))

    created_clients = []

    class _TrackingFakeMcpBridgeClient(_FakeMcpBridgeClient):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            created_clients.append(self)

    monkeypatch.setattr(ai_provider, 'McpBridgeClient', _TrackingFakeMcpBridgeClient)

    scenario = _scenario_payload('BridgeSeedScenario')
    resp = client.post(
        '/api/ai/generate_scenario_preview',
        json={
            'provider': 'ollama',
            'bridge_mode': 'mcp-python-sdk',
            'base_url': 'http://127.0.0.1:11434',
            'model': 'gpt-oss:20b',
            'mcp_server_path': 'MCP/server.py',
            'hil_enabled': True,
            'enabled_tools': [
                'server.scenario.create_draft',
                'server.scenario.get_draft',
                'server.scenario.preview_draft',
            ],
            'prompt': 'Generate a three-host scenario.',
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        },
    )

    assert resp.status_code == 200
    assert created_clients
    assert created_clients[0].hil_manager.enabled is True
    assert created_clients[0].hil_manager.session_auto_execute is False


def test_resolve_bridge_server_configs_dedupes_direct_path_against_servers_json(tmp_path):
    from webapp.routes import ai_provider

    config_path = tmp_path / 'servers.json'
    config_path.write_text(
        json.dumps({
            'mcpServers': {
                'core-topo-gen': {
                    'command': 'python',
                    'args': ['MCP/server.py'],
                    'cwd': str(ai_provider._REPO_ROOT),
                    'disabled': False,
                },
            },
        }),
        encoding='utf-8',
    )

    configs = ai_provider._resolve_bridge_server_configs(
        server_paths=[ai_provider._DEFAULT_MCP_SERVER_PATH],
        server_urls=None,
        config_path=str(config_path),
        auto_discovery=False,
    )

    assert len(configs) == 1
    assert configs[0]['server_name'] == 'server'
    assert configs[0]['transport'] == 'stdio'
    assert configs[0]['args'] == [ai_provider._DEFAULT_MCP_SERVER_PATH]


def test_normalize_mcp_bridge_payload_preserves_servers_json_path():
    from webapp.routes import ai_provider

    payload = ai_provider._normalize_mcp_bridge_payload({
        'bridge_mode': 'mcp-python-sdk',
        'mcp_server_path': 'MCP/server.py',
        'servers_json_path': 'MCP/mcp-bridge-servers.json',
    })

    assert payload.get('servers_json_path') == ai_provider._DEFAULT_MCP_SERVERS_JSON_PATH


def test_normalize_mcp_bridge_payload_does_not_default_server_path_when_servers_json_path_is_explicit():
    from webapp.routes import ai_provider

    payload = ai_provider._normalize_mcp_bridge_payload({
        'bridge_mode': 'mcp-python-sdk',
        'servers_json_path': 'MCP/mcp-bridge-servers.json',
    })

    assert payload.get('servers_json_path') == ai_provider._DEFAULT_MCP_SERVERS_JSON_PATH
    assert payload.get('mcp_server_path') == ''