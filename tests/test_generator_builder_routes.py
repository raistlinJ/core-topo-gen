import io
import json
import os
import zipfile

from webapp import app_backend as backend
from webapp.routes import ai_provider as ai_provider_routes
from webapp.routes import generator_builder_routes


app = backend.app
app.config.setdefault('TESTING', True)
app.config['TESTING'] = True


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (200, 302)


def test_generator_builder_page_renders(monkeypatch):
    client = app.test_client()
    _login(client)

    called = {'count': 0}

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: called.__setitem__('count', called['count'] + 1))

    resp = client.get('/generator_builder')

    assert resp.status_code == 200
    assert called['count'] == 1
    body = resp.get_data(as_text=True)
    assert 'Prompt-Driven Authoring' in body
    assert 'Provider Config' in body
    assert 'LLM Model' in body
    assert 'Fetch Models' in body
    assert 'Connect / validate' in body
    assert 'Submit New' in body
    assert 'Test' in body
    assert 'Submit as Refinement' in body
    assert 'Download README' in body
    assert 'Add to catalog' in body
    assert 'Generated Summary' in body
    assert 'Generator Builder Output' in body
    assert 'CORE VM Credentials' in body
    assert 'Save and Run Test' in body
    assert 'Progress / Log' in body
    assert 'Generated Files' in body
    assert 'Download Transcript' in body
    assert 'API key' in body
    assert 'Verify TLS certificates' in body
    assert 'Iteration History' in body
    assert 'Latest Test Result' in body
    assert 'gbLatestTestSnapshot' in body
    assert 'gbPromptIntentPreview' in body
    assert 'gbIntentApplySuggestedBtn' in body
    assert 'gbIntentRuntimeInputs' in body
    assert 'gbIntentHintTemplates' in body
    assert 'gbIntentOverridesPanel' in body
    assert 'data-gb-intent-fill="runtime_inputs"' in body
    assert 'gbIntentOverridesSummary' in body
    assert 'Install & downloads' in body
    assert 'Locked until validation' in body
    assert 'coretg_builder_model_config' in body
    assert 'After Scaffold' not in body
    assert 'Compatibility Checklist' not in body
    assert 'Test &amp; Iterate' not in body
    assert 'Advanced <span class="gb-optional-badge">Optional</span>' not in body
    assert 'Test Configuration' not in body


def test_generator_artifacts_index_merges_sources_reserved_and_custom(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(
        backend,
        '_flag_generators_from_enabled_sources',
        lambda: ([{'id': 'flag-a', 'name': 'Flag A', 'outputs': [{'name': 'alpha', 'type': 'file', 'description': 'Alpha file', 'sensitive': False}]}], []),
    )
    monkeypatch.setattr(
        backend,
        '_flag_node_generators_from_enabled_sources',
        lambda: ([{'id': 'node-b', 'name': 'Node B', 'outputs': [{'name': 'beta', 'type': 'path', 'description': '', 'sensitive': True}]}], []),
    )
    monkeypatch.setattr(backend, '_load_custom_artifacts', lambda: {'custom.gamma': {'type': 'json'}, 'alpha': {'type': 'ignored'}})
    monkeypatch.setitem(
        backend._RESERVED_ARTIFACTS,
        'reserved.delta',
        {'type': 'text', 'description': 'Reserved item', 'sensitive': False},
    )

    resp = client.get('/api/generators/artifacts_index')

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('ok') is True
    artifacts = {item['artifact']: item for item in (payload.get('artifacts') or [])}
    assert artifacts['alpha']['type'] == 'file'
    assert artifacts['alpha']['producers'][0]['plugin_id'] == 'flag-a'
    assert artifacts['beta']['sensitive'] is True
    assert artifacts['reserved.delta']['producers'][0]['plugin_type'] == 'reserved'
    assert artifacts['custom.gamma']['type'] == 'json'


def test_generator_artifacts_index_custom_add_persists_item(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(
        backend,
        '_upsert_custom_artifact',
        lambda artifact, *, type_value=None: {'artifact': artifact, 'type': type_value},
    )

    resp = client.post('/api/generators/artifacts_index/custom', json={'artifact': 'artifact.one', 'type': 'json'})

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload == {'ok': True, 'artifact': {'artifact': 'artifact.one', 'type': 'json'}}


def test_generator_scaffold_meta_returns_sorted_paths(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(
        backend,
        '_build_generator_scaffold',
        lambda payload: ({'z/file.txt': 'z', 'a/manifest.yaml': 'm'}, 'manifest-body', 'folder'),
    )

    resp = client.post('/api/generators/scaffold_meta', json={'plugin_id': 'demo'})

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload == {
        'ok': True,
        'manifest_yaml': 'manifest-body',
        'scaffold_paths': ['a/manifest.yaml', 'z/file.txt'],
    }


def test_generator_prompt_intent_preview_returns_structured_sections(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    resp = client.post('/api/generators/prompt_intent_preview', json={
        'plugin_type': 'flag-generator',
        'prompt': (
            'Build a flag-generator that derives deterministic SSH credentials and a hint from seed and secret.\n'
            'Runtime inputs: seed (required), token (required, sensitive).\n'
            'Artifact outputs: Flag(flag_id), Credential(user,password), File(path).\n'
            'Include inject_files with File(path).\n'
            'Inject destination: /opt/bootstrap.\n'
            'Hint templates: Next: SSH using {{OUTPUT.Credential(user,password)}}.\n'
            'README should mention determinism and parity testing.'
        ),
    })

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('ok') is True
    titles = [section.get('title') for section in (payload.get('sections') or [])]
    assert 'User-Specified' in titles
    assert 'Notes' in titles
    merged = payload.get('merged') or {}
    assert merged.get('inject_files') == ['File(path) -> /opt/bootstrap']
    assert merged.get('hint_templates') == ['Next: SSH using {{OUTPUT.Credential(user,password)}}.']


def test_generator_prompt_intent_preview_applies_manual_overrides(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    resp = client.post('/api/generators/prompt_intent_preview', json={
        'plugin_type': 'flag-generator',
        'prompt': 'Build a flag-generator that derives deterministic SSH credentials and a hint from seed and secret.',
        'intent_overrides': {
            'runtime_inputs': 'seed (required)\nnode_name (required)',
            'produces': 'Flag(flag_id)\nCredential(user)',
            'inject_files': 'Credential(user)',
            'readme_mentions': 'custom docs, test parity',
        },
    })

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('ok') is True
    titles = [section.get('title') for section in (payload.get('sections') or [])]
    assert 'Manual Overrides' in titles
    assert payload.get('merged', {}).get('produces') == ['Flag(flag_id)', 'Credential(user)']
    assert payload.get('editable', {}).get('runtime_inputs') == 'seed (required)\nnode_name (required)'
    assert payload.get('notes', {}).get('readme_mentions') == ['custom docs', 'test parity']


def test_generator_scaffold_zip_streams_archive(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(
        backend,
        '_build_generator_scaffold',
        lambda payload: ({'demo/manifest.yaml': 'manifest-body', 'demo/run.py': 'print(1)\n'}, 'manifest-body', 'demo'),
    )
    monkeypatch.setattr(backend, '_sanitize_id', lambda value: 'demo-plugin')

    resp = client.post('/api/generators/scaffold_zip', json={'plugin_id': 'Demo Plugin'})

    assert resp.status_code == 200
    assert resp.mimetype == 'application/zip'
    assert 'attachment; filename=generator_scaffold_demo-plugin.zip' in resp.headers.get('Content-Disposition', '')

    with zipfile.ZipFile(io.BytesIO(resp.data), 'r') as archive:
        assert sorted(archive.namelist()) == ['demo/manifest.yaml', 'demo/run.py']
        assert archive.read('demo/manifest.yaml').decode('utf-8') == 'manifest-body'


def test_build_generator_scaffold_accepts_runtime_inputs_and_generator_override():
    scaffold_files, manifest_yaml, folder_path = backend._build_generator_scaffold({
        'plugin_type': 'flag-node-generator',
        'plugin_id': 'token_gate',
        'folder_name': 'py_token_gate',
        'name': 'Token Gate',
        'description': 'Generated from AI.',
        'requires': [{'artifact': 'Knowledge(ip)', 'optional': False}],
        'produces': ['Flag(flag_id)'],
        'runtime_inputs': [
            {'name': 'seed', 'type': 'string', 'required': True},
            {'name': 'node_name', 'type': 'string', 'required': True},
            {'name': 'flag_prefix', 'type': 'string', 'required': False},
        ],
        'generator_py_text': 'print("hello from override")\n',
    })

    assert folder_path == 'flag_node_generators/py_token_gate'
    assert 'name: seed' in manifest_yaml
    assert 'name: node_name' in manifest_yaml
    assert 'required: false' in manifest_yaml
    assert '    - File(path)' in manifest_yaml
    assert scaffold_files['flag_node_generators/py_token_gate/generator.py'] == 'print("hello from override")\n'


def test_generator_ai_scaffold_normalizes_model_output(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    class _DummyAdapter:
        capability = type('Capability', (), {'default_base_url': 'http://127.0.0.1:11434'})()

    assistant_json = {
        'plugin_id': 'ssh_creds_drop',
        'name': 'SSH Credentials Drop',
        'description': 'Deterministic SSH credential generator.',
        'requires': [{'artifact': 'Knowledge(ip)', 'optional': False}],
        'optional_requires': ['Knowledge(hostname)'],
        'produces': ['Flag(flag_id)', 'Credential(user,password)', 'File(path)'],
        'runtime_inputs': [
            {'name': 'seed', 'type': 'string', 'required': True},
            {'name': 'secret', 'type': 'string', 'required': True, 'sensitive': True},
        ],
        'hint_templates': ['Next: use {{OUTPUT.Credential(user,password)}}'],
        'inject_files': ['File(path)'],
        'generator_py_text': 'print("ai")\n',
        'readme_text': '# Demo\n',
    }

    captured: dict[str, object] = {}

    def _fake_post_json(url, payload, *, timeout, headers=None, verify_ssl=True):
        captured['url'] = url
        captured['payload'] = payload
        captured['timeout'] = timeout
        captured['verify_ssl'] = verify_ssl
        return {'response': '', 'thinking': json.dumps(assistant_json)}

    monkeypatch.setattr(ai_provider_routes, '_get_provider_adapter', lambda provider: _DummyAdapter())
    monkeypatch.setattr(ai_provider_routes, '_normalize_base_url', lambda value: str(value))
    monkeypatch.setattr(ai_provider_routes, '_post_json', _fake_post_json)

    resp = client.post('/api/generators/ai_scaffold', json={
        'plugin_type': 'flag-generator',
        'provider': 'ollama',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'qwen2.5:7b',
        'prompt': 'Build a deterministic SSH credential generator.',
    })

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('ok') is True
    assert payload['scaffold_request']['plugin_id'] == 'ssh_creds_drop'
    assert payload['scaffold_request']['requires'] == [
        {'artifact': 'Knowledge(ip)', 'optional': False},
        {'artifact': 'Knowledge(hostname)', 'optional': True},
    ]
    assert payload['scaffold_request']['runtime_inputs'][1]['sensitive'] is True
    assert captured['url'] == 'http://127.0.0.1:11434/api/generate'
    assert captured['timeout'] == 240.0
    assert captured['verify_ssl'] is True
    assert captured['payload']['model'] == 'qwen2.5:7b'
    assert captured['payload']['stream'] is False
    assert captured['payload']['format'] == 'json'
    assert 'flag_generators/py_ssh_creds_drop/generator.py' in payload['files']
    assert payload['files']['flag_generators/py_ssh_creds_drop/generator.py'] == 'print("ai")\n'
    assert 'Credential(user,password)' in payload['manifest_yaml']


def test_generator_ai_scaffold_stream_emits_prompt_delta_and_result(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    class _DummyAdapter:
        capability = type('Capability', (), {'default_base_url': 'http://127.0.0.1:11434'})()

    assistant_json = {
        'plugin_id': 'stream_demo',
        'name': 'Stream Demo',
        'description': 'Deterministic stream demo.',
        'requires': [{'artifact': 'Knowledge(ip)', 'optional': False}],
        'produces': ['Flag(flag_id)'],
        'runtime_inputs': [{'name': 'seed', 'type': 'string', 'required': True}],
        'generator_py_text': 'print("stream")\n',
    }
    full = json.dumps(assistant_json)

    monkeypatch.setattr(ai_provider_routes, '_get_provider_adapter', lambda provider: _DummyAdapter())
    monkeypatch.setattr(ai_provider_routes, '_normalize_base_url', lambda value: str(value))

    def _fake_stream_json_lines(url, payload, *, timeout, headers=None, verify_ssl=True, cancellation_check=None, on_open=None):
        if callable(on_open):
            on_open(object())
        yield {'response': full[: len(full) // 2]}
        yield {'response': full[len(full) // 2 :]}

    monkeypatch.setattr(ai_provider_routes, '_stream_json_lines', _fake_stream_json_lines)

    resp = client.post('/api/generators/ai_scaffold_stream', json={
        'request_id': 'builder-stream-test',
        'plugin_type': 'flag-generator',
        'provider': 'ollama',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'qwen2.5:7b',
        'prompt': 'Build a deterministic stream demo generator.',
    })

    assert resp.status_code == 200
    assert resp.mimetype == 'application/x-ndjson'
    events = [json.loads(line) for line in resp.get_data(as_text=True).splitlines() if line.strip()]
    event_types = [event.get('type') for event in events]
    assert 'llm_prompt' in event_types
    assert 'llm_delta' in event_types
    assert 'result' in event_types
    result_event = next(event for event in events if event.get('type') == 'result')
    assert result_event['data']['scaffold_request']['plugin_id'] == 'stream_demo'
    assert 'flag_generators/py_stream_demo/generator.py' in result_event['data']['files']


def test_generator_ai_scaffold_openai_compatible_uses_api_key_and_ssl(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    class _DummyAdapter:
        capability = type('Capability', (), {'default_base_url': 'https://litellm.example.com/v1'})()

    captured: dict[str, object] = {}

    class _DummyClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def _post_chat(self, *, messages):
            assert messages[0]['role'] == 'system'
            return {'choices': [{'message': {'content': json.dumps({'plugin_id': 'api_key_tls_demo'})}}]}

        def _uses_openai_chat_completions(self):
            return True

    monkeypatch.setattr(ai_provider_routes, '_get_provider_adapter', lambda provider: _DummyAdapter())
    monkeypatch.setattr(
        ai_provider_routes,
        '_normalize_openai_compatible_base_url',
        lambda value, *, enforce_ssl: 'http://litellm.local/v1' if not enforce_ssl else 'https://litellm.example.com/v1',
    )
    monkeypatch.setattr(ai_provider_routes, '_RepoMcpBridgeClient', lambda **kwargs: _DummyClient(**kwargs))
    monkeypatch.setattr(ai_provider_routes, '_extract_openai_chat_message', lambda payload: (payload.get('choices') or [{}])[0].get('message') or {})

    resp = client.post('/api/generators/ai_scaffold', json={
        'plugin_type': 'flag-generator',
        'provider': 'litellm',
        'base_url': 'http://litellm.local/v1',
        'api_key': 'builder-secret-key',
        'enforce_ssl': False,
        'model': 'gpt-4o-mini',
        'prompt': 'Build a demo generator.',
    })

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('ok') is True
    assert captured['provider'] == 'litellm'
    assert captured['host'] == 'http://litellm.local/v1'
    assert captured['api_key'] == 'builder-secret-key'
    assert captured['verify_ssl'] is False


def test_generator_ai_scaffold_openai_compatible_rejects_http_when_ssl_required(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    class _DummyAdapter:
        capability = type('Capability', (), {'default_base_url': 'https://litellm.example.com/v1'})()

    monkeypatch.setattr(ai_provider_routes, '_get_provider_adapter', lambda provider: _DummyAdapter())

    def _raise_on_http(value, *, enforce_ssl):
        raise ValueError('Base URL must use https when Enforce SSL is enabled.')

    monkeypatch.setattr(ai_provider_routes, '_normalize_openai_compatible_base_url', _raise_on_http)

    resp = client.post('/api/generators/ai_scaffold', json={
        'plugin_type': 'flag-generator',
        'provider': 'litellm',
        'base_url': 'http://litellm.local/v1',
        'api_key': 'builder-secret-key',
        'enforce_ssl': True,
        'model': 'gpt-4o-mini',
        'prompt': 'Build a demo generator.',
    })

    assert resp.status_code == 400
    payload = resp.get_json() or {}
    assert payload.get('ok') is False
    assert payload.get('error') == 'Base URL must use https when Enforce SSL is enabled.'


def test_generator_builder_ai_messages_include_flag_generator_grounding():
    messages = generator_builder_routes._build_generator_builder_ai_messages({
        'plugin_type': 'flag-generator',
        'prompt': 'Build a deterministic credential generator.',
    })

    user_content = messages[1]['content']
    assert 'Repo authoring guidance:' in user_content
    assert 'Reference docs excerpt: AI scaffolding quickstart (docs/GENERATOR_AUTHORING.md :: ## 0) AI scaffolding quickstart):' in user_content
    assert 'If you are using AI to create generators, use this minimal handoff packet:' in user_content
    assert 'Ask AI to self-check output keys against manifest `artifacts.produces`.' in user_content
    assert 'Run installed-pack Execute parity check.' in user_content
    assert 'Reference template: generator.py (generator_templates/flag-generator-python-compose/generator.py):' in user_content
    assert 'Reference template: docker-compose.yml (generator_templates/flag-generator-python-compose/docker-compose.yml):' in user_content
    assert 'Reference sample: manifest.yaml (flag_generators/py_sample_textfile_username_password/manifest.yaml):' in user_content
    assert 'Reference sample: generator.py (flag_generators/py_sample_textfile_username_password/generator.py):' in user_content
    assert 'Treat inject_files as runtime file paths that must be created, not as abstract artifact declarations.' in user_content
    assert 'If inject_files references File(path), then produces must include File(path)' in user_content


def test_generator_builder_ai_messages_include_node_generator_grounding():
    messages = generator_builder_routes._build_generator_builder_ai_messages({
        'plugin_type': 'flag-node-generator',
        'prompt': 'Build a deterministic node generator.',
    })

    user_content = messages[1]['content']
    assert 'Reference template: generator.py (generator_templates/flag-node-generator-python-compose/generator.py):' in user_content
    assert 'Reference template: docker-compose.yml (generator_templates/flag-node-generator-python-compose/docker-compose.yml):' in user_content
    assert 'Reference sample: manifest.yaml (flag_node_generators/py_sample_nfs_sensitive_file/manifest.yaml):' in user_content
    assert 'Reference sample: generator.py (flag_node_generators/py_sample_nfs_sensitive_file/generator.py):' in user_content


def test_generator_builder_ai_messages_add_targeted_inject_failure_guidance():
    messages = generator_builder_routes._build_generator_builder_ai_messages({
        'plugin_type': 'flag-generator',
        'prompt': 'Please refine the generator.',
        'current_scaffold_request': {
            'plugin_type': 'flag-generator',
            'plugin_id': 'demo',
            'folder_name': 'py_demo',
            'name': 'Demo',
            'description': 'demo',
            'requires': [],
            'produces': ['Flag(flag_id)', 'File(path)'],
            'inject_files': ['File(path)'],
            'runtime_inputs': [{'name': 'seed', 'type': 'string', 'required': True}],
        },
        'last_test_result': {
            'ok': False,
            'returncode': 1,
            'stderr': 'FileNotFoundError: inject_files validation failed: missing 1 paths: [\'File(path)\']',
            'failure_summary': 'inject_files validation failed: missing 1 paths: [\'File(path)\']',
            'files': [],
        },
    })

    user_content = messages[1]['content']
    assert 'Observed failure to fix first: inject_files referenced file paths that were never created.' in user_content
    assert 'If you keep inject_files: ["File(path)"]' in user_content
    assert 'If no injected file is needed, remove inject_files and remove File(path) from produces.' in user_content


def test_generator_builder_ai_messages_add_prompt_derived_ssh_credential_defaults():
    messages = generator_builder_routes._build_generator_builder_ai_messages({
        'plugin_type': 'flag-generator',
        'prompt': 'Build a flag-generator that derives deterministic SSH credentials and a hint from seed and secret.',
    })

    user_content = messages[1]['content']
    assert 'Prompt-derived defaults to apply only when the prompt did not already specify a conflicting requirement:' in user_content
    assert 'Suggested runtime inputs: seed (required), secret (required, sensitive), flag_prefix (optional).' in user_content
    assert 'Suggested artifact requirements: Knowledge(ip), Knowledge(hostname) (optional).' in user_content
    assert 'Suggested artifact outputs: Flag(flag_id), Credential(user), Credential(user,password), File(path).' in user_content
    assert 'Suggested inject_files entries: File(path).' in user_content
    assert 'Suggested hint template shape: Next: SSH to {{NEXT_NODE_NAME}} using {{OUTPUT.Credential(user)}} / {{OUTPUT.Credential(user,password)}}.' in user_content
    assert 'README should mention determinism, local runner testing.' in user_content


def test_generator_builder_ai_messages_explicit_prompt_specs_override_heuristics_in_guidance():
    messages = generator_builder_routes._build_generator_builder_ai_messages({
        'plugin_type': 'flag-generator',
        'prompt': (
            'Build a deterministic SSH credential generator.\n'
            'Runtime inputs: seed (required), token (required, sensitive).\n'
            'Artifact outputs: Flag(flag_id), Credential(user).\n'
            'Include inject_files with Credential(user).\n'
            'README should mention parity testing.'
        ),
    })

    user_content = messages[1]['content']
    assert 'User-specified scaffold requirements detected in the prompt. These override heuristic defaults when there is any conflict:' in user_content
    assert 'Respect these user-specified runtime inputs: seed (required), token (required, sensitive).' in user_content
    assert 'Respect these user-specified artifact outputs: Flag(flag_id), Credential(user).' in user_content
    assert 'Respect these user-specified inject_files entries: Credential(user).' in user_content
    assert 'Suggested runtime inputs: seed (required), secret (required, sensitive), flag_prefix (optional).' in user_content
    assert 'README should mention parity testing.' in user_content


def test_generator_builder_ai_messages_builder_overrides_take_precedence_in_guidance():
    messages = generator_builder_routes._build_generator_builder_ai_messages({
        'plugin_type': 'flag-generator',
        'prompt': 'Build a flag-generator that derives deterministic SSH credentials and a hint from seed and secret.',
        'intent_overrides': {
            'runtime_inputs': 'seed (required)\nnode_name (required)',
            'produces': 'Flag(flag_id)\nCredential(user)',
            'hint_templates': 'Next: use {{OUTPUT.Credential(user)}}',
        },
    })

    user_content = messages[1]['content']
    assert 'Builder preview overrides are set. These take precedence over both prompt-derived explicit requirements and heuristics:' in user_content
    assert 'Respect these Builder override runtime inputs: seed (required), node_name (required).' in user_content
    assert 'Respect these Builder override artifact outputs: Flag(flag_id), Credential(user).' in user_content
    assert 'Respect these Builder override hint templates: Next: use {{OUTPUT.Credential(user)}}.' in user_content


def test_normalize_ai_scaffold_payload_uses_prompt_intent_defaults_when_ai_omits_fields():
    payload = generator_builder_routes._normalize_ai_scaffold_payload(
        {
            'plugin_id': 'ssh_creds_demo',
            'name': 'SSH Demo',
            'description': 'demo',
            'generator_py_text': 'print("demo")\n',
        },
        {
            'plugin_type': 'flag-generator',
            'prompt': 'Build a flag-generator that derives deterministic SSH credentials and a hint from seed and secret.',
        },
    )

    assert payload['runtime_inputs'] == [
        {'name': 'seed', 'type': 'string', 'required': True},
        {'name': 'secret', 'type': 'string', 'required': True, 'sensitive': True},
        {'name': 'flag_prefix', 'type': 'string', 'required': False},
    ]
    assert payload['requires'] == [
        {'artifact': 'Knowledge(ip)', 'optional': False},
        {'artifact': 'Knowledge(hostname)', 'optional': True},
    ]
    assert payload['produces'] == ['Flag(flag_id)', 'Credential(user)', 'Credential(user,password)', 'File(path)']
    assert payload['inject_files'] == ['File(path)']
    assert payload['hint_templates'] == ['Next: SSH to {{NEXT_NODE_NAME}} using {{OUTPUT.Credential(user)}} / {{OUTPUT.Credential(user,password)}}']


def test_normalize_ai_scaffold_payload_prioritizes_explicit_prompt_specs_over_inferred_defaults():
    payload = generator_builder_routes._normalize_ai_scaffold_payload(
        {
            'plugin_id': 'explicit_demo',
            'name': 'Explicit Demo',
            'description': 'demo',
            'generator_py_text': 'print("demo")\n',
        },
        {
            'plugin_type': 'flag-generator',
            'prompt': (
                'Build a deterministic SSH credential generator.\n'
                'Runtime inputs: seed (required), token (required, sensitive).\n'
                'Artifact requirements: require Knowledge(ip).\n'
                'Artifact outputs: Flag(flag_id), Credential(user).\n'
                'Include inject_files with Credential(user).'
            ),
        },
    )

    assert payload['runtime_inputs'] == [
        {'name': 'seed', 'type': 'string', 'required': True},
        {'name': 'token', 'type': 'string', 'required': True, 'sensitive': True},
    ]
    assert payload['requires'] == [
        {'artifact': 'Knowledge(ip)', 'optional': False},
    ]
    assert payload['produces'] == ['Flag(flag_id)', 'Credential(user)']
    assert payload['inject_files'] == ['Credential(user)']


def test_normalize_ai_scaffold_payload_applies_hint_templates_and_inject_destination_from_prompt():
    payload = generator_builder_routes._normalize_ai_scaffold_payload(
        {
            'plugin_id': 'hint_demo',
            'name': 'Hint Demo',
            'description': 'demo',
            'generator_py_text': 'print("demo")\n',
        },
        {
            'plugin_type': 'flag-generator',
            'prompt': (
                'Build a deterministic SSH credential generator.\n'
                'Artifact outputs: Flag(flag_id), Credential(user,password), File(path).\n'
                'Include inject_files with File(path).\n'
                'Inject destination: /opt/bootstrap.\n'
                'Hint templates: Next: SSH using {{OUTPUT.Credential(user,password)}}.'
            ),
        },
    )

    assert payload['inject_files'] == ['File(path) -> /opt/bootstrap']
    assert payload['hint_templates'] == ['Next: SSH using {{OUTPUT.Credential(user,password)}}.']


def test_normalize_ai_scaffold_payload_prioritizes_manual_overrides_over_prompt_intent():
    payload = generator_builder_routes._normalize_ai_scaffold_payload(
        {
            'plugin_id': 'manual_demo',
            'name': 'Manual Demo',
            'description': 'demo',
            'generator_py_text': 'print("demo")\n',
        },
        {
            'plugin_type': 'flag-generator',
            'prompt': (
                'Build a deterministic SSH credential generator.\n'
                'Runtime inputs: seed (required), token (required, sensitive).\n'
                'Artifact outputs: Flag(flag_id), Credential(user,password), File(path).\n'
                'Include inject_files with File(path).\n'
                'Hint templates: Next: SSH using {{OUTPUT.Credential(user,password)}}.'
            ),
            'intent_overrides': {
                'runtime_inputs': 'seed (required)\nnode_name (required)',
                'produces': 'Flag(flag_id)\nCredential(user)',
                'inject_files': 'Credential(user)',
                'hint_templates': 'Next: use {{OUTPUT.Credential(user)}}',
                'readme_mentions': 'custom docs',
            },
        },
    )

    assert payload['runtime_inputs'] == [
        {'name': 'seed', 'type': 'string', 'required': True},
        {'name': 'node_name', 'type': 'string', 'required': True},
    ]
    assert payload['produces'] == ['Flag(flag_id)', 'Credential(user)']
    assert payload['inject_files'] == ['Credential(user)']
    assert payload['hint_templates'] == ['Next: use {{OUTPUT.Credential(user)}}']


def test_generator_builder_test_runs_remote_core_vm(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    def _fake_remote_test(*, scaffold_files, plugin_kind, plugin_id, config):
        assert plugin_kind == 'flag-node-generator'
        assert plugin_id == 'demo_nodegen'
        assert config == {'seed': 'demo-seed', 'node_name': 'node1'}
        assert 'flag_node_generators/py_demo_nodegen/generator.py' in scaffold_files
        return {
            'ok': True,
            'returncode': 0,
            'stdout': 'remote ok\n',
            'stderr': '',
            'files': [
                {'path': 'outputs.json', 'text': '{"outputs":{"Flag(flag_id)":"FLAG{demo}"}}'},
                {'path': 'docker-compose.yml', 'text': 'services:\n  node:\n    image: alpine:3.19\n'},
            ],
        }

    monkeypatch.setattr(backend, '_run_remote_builder_scaffold_test', _fake_remote_test)

    resp = client.post('/api/generators/builder_test', json={
        'scaffold_request': {
            'plugin_type': 'flag-node-generator',
            'plugin_id': 'demo_nodegen',
            'folder_name': 'py_demo_nodegen',
            'name': 'Demo NodeGen',
            'description': 'demo',
            'requires': [],
            'produces': ['Flag(flag_id)'],
            'runtime_inputs': [
                {'name': 'seed', 'type': 'string', 'required': True},
                {'name': 'node_name', 'type': 'string', 'required': True},
            ],
            'generator_py_text': 'print("demo")\n',
        },
    })

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload['ok'] is True
    assert payload['returncode'] == 0
    assert payload['test_mode'] == 'remote_core_vm'
    file_map = {entry['path']: entry for entry in payload['files']}
    assert 'outputs.json' in file_map
    assert 'FLAG{demo}' in (file_map['outputs.json']['text'] or '')
    assert 'docker-compose.yml' in file_map


def test_generator_builder_test_run_uses_async_catalog_style_flow(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_parse_flag_test_core_cfg_from_form', lambda form: {'ssh_host': 'core', 'ssh_port': 22, 'ssh_username': 'user', 'ssh_password': 'pw'})
    monkeypatch.setattr(backend, '_ensure_core_vm_idle_for_test', lambda core_cfg: None)
    monkeypatch.setattr(backend, '_cleanup_remote_test_runtime', lambda meta: None)
    monkeypatch.setattr(backend, '_sync_remote_flag_test_outputs', lambda meta: None)
    monkeypatch.setattr(backend, '_purge_remote_flag_test_dir', lambda meta: None)

    class _DoneChannel:
        def exit_status_ready(self):
            return True

        def recv_exit_status(self):
            return 0

        def close(self):
            return None

    class _DoneThread:
        def join(self, timeout=None):
            return None

    def _fake_start(*, run_id, run_dir, log_handle, scaffold_files, plugin_kind, plugin_id, cfg, core_cfg):
        assert plugin_kind == 'flag-generator'
        assert plugin_id == 'demo'
        assert cfg['seed'] == 'custom-seed'
        os.makedirs(run_dir, exist_ok=True)
        with open(os.path.join(run_dir, 'outputs.json'), 'w', encoding='utf-8') as handle:
            handle.write('{"outputs":{"Flag(flag_id)":"FLAG{demo}"}}\n')
        log_handle.write('[builder-test] started\n')
        log_handle.flush()
        return {
            'ssh_client': None,
            'ssh_channel': _DoneChannel(),
            'ssh_log_thread': _DoneThread(),
            'remote_run_dir': '/tmp/tests/demo',
            'remote_repo_dir': '/tmp/tests/repo',
            'remote_env_path': '/tmp/tests/env.sh',
        }

    monkeypatch.setattr(backend, '_start_remote_builder_scaffold_test_process', _fake_start)

    resp = client.post('/api/generators/builder_test/run', data={
        'scaffold_request': json.dumps({
            'plugin_type': 'flag-generator',
            'plugin_id': 'demo',
            'folder_name': 'py_demo',
            'name': 'Demo Builder Generator',
            'description': 'demo',
            'requires': [],
            'produces': ['Flag(flag_id)'],
            'runtime_inputs': [
                {'name': 'seed', 'type': 'string', 'required': True},
            ],
            'generator_py_text': 'print("demo")\n',
        }),
        'seed': 'custom-seed',
        'core': json.dumps({'ssh_host': 'core'}),
    })

    assert resp.status_code == 200, resp.get_data(as_text=True)
    payload = resp.get_json() or {}
    assert payload['ok'] is True
    run_id = payload['run_id']

    outputs_resp = client.get(f'/api/generators/builder_test/outputs/{run_id}')
    assert outputs_resp.status_code == 200
    outputs_payload = outputs_resp.get_json() or {}
    output_paths = {entry['path'] for entry in (outputs_payload.get('outputs') or [])}
    scaffold_paths = {entry['path'] for entry in (outputs_payload.get('scaffold') or [])}
    assert 'outputs.json' in output_paths
    assert 'scaffold/flag_generators/py_demo/generator.py' in scaffold_paths
    assert 'scaffold/_scaffold_request.json' in scaffold_paths
    assert '[builder-test] started' in str(outputs_payload.get('log_tail') or '')

    cleanup_resp = client.post(f'/api/generators/builder_test/cleanup/{run_id}')
    assert cleanup_resp.status_code == 200
    cleanup_payload = cleanup_resp.get_json() or {}
    assert cleanup_payload['ok'] is True


def test_generator_builder_test_outputs_include_failure_summary(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_parse_flag_test_core_cfg_from_form', lambda form: {'ssh_host': 'core', 'ssh_port': 22, 'ssh_username': 'user', 'ssh_password': 'pw'})
    monkeypatch.setattr(backend, '_ensure_core_vm_idle_for_test', lambda core_cfg: None)
    monkeypatch.setattr(backend, '_cleanup_remote_test_runtime', lambda meta: None)
    monkeypatch.setattr(backend, '_sync_remote_flag_test_outputs', lambda meta: None)
    monkeypatch.setattr(backend, '_purge_remote_flag_test_dir', lambda meta: None)

    class _FailChannel:
        def exit_status_ready(self):
            return True

        def recv_exit_status(self):
            return 1

        def close(self):
            return None

    class _DoneThread:
        def join(self, timeout=None):
            return None

    def _fake_start(*, run_id, run_dir, log_handle, scaffold_files, plugin_kind, plugin_id, cfg, core_cfg):
        os.makedirs(run_dir, exist_ok=True)
        log_handle.write('Failed to generate base image\n')
        log_handle.write('Traceback (most recent call last):\n')
        log_handle.write('subprocess.CalledProcessError: docker compose run failed\n')
        log_handle.flush()
        return {
            'ssh_client': None,
            'ssh_channel': _FailChannel(),
            'ssh_log_thread': _DoneThread(),
            'remote_run_dir': '/tmp/tests/demo',
            'remote_repo_dir': '/tmp/tests/repo',
            'remote_env_path': '/tmp/tests/env.sh',
        }

    monkeypatch.setattr(backend, '_start_remote_builder_scaffold_test_process', _fake_start)

    resp = client.post('/api/generators/builder_test/run', data={
        'scaffold_request': json.dumps({
            'plugin_type': 'flag-generator',
            'plugin_id': 'demo_fail',
            'folder_name': 'py_demo_fail',
            'name': 'Demo Fail',
            'description': 'demo',
            'requires': [],
            'produces': ['Flag(flag_id)'],
            'runtime_inputs': [
                {'name': 'seed', 'type': 'string', 'required': True},
            ],
            'generator_py_text': 'print("demo")\n',
        }),
        'seed': 'custom-seed',
        'core': json.dumps({'ssh_host': 'core'}),
    })

    assert resp.status_code == 200, resp.get_data(as_text=True)
    run_id = (resp.get_json() or {}).get('run_id')
    assert run_id

    outputs_resp = client.get(f'/api/generators/builder_test/outputs/{run_id}')
    assert outputs_resp.status_code == 200
    outputs_payload = outputs_resp.get_json() or {}
    assert outputs_payload.get('returncode') == 1
    assert 'Failed to generate base image' in str(outputs_payload.get('failure_summary') or '')
    assert 'CalledProcessError' in str(outputs_payload.get('failure_summary') or '')


def test_generator_install_generated_wraps_scaffold_as_pack(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    installed = {}

    def _fake_install(*, zip_path, pack_label, pack_origin):
        assert pack_label == 'Demo Pack'
        assert pack_origin == 'generator_builder'
        with zipfile.ZipFile(zip_path, 'r') as archive:
            installed['names'] = sorted(archive.namelist())
            installed['manifest'] = archive.read('flag_generators/py_demo/manifest.yaml').decode('utf-8')
        return True, 'Installed 1 generator(s) from Demo Pack'

    monkeypatch.setattr(backend, '_install_generator_pack_or_bundle', _fake_install)

    resp = client.post('/api/generators/install_generated', json={
        'pack_label': 'Demo Pack',
        'scaffold_request': {
            'plugin_type': 'flag-generator',
            'plugin_id': 'demo',
            'folder_name': 'py_demo',
            'name': 'Demo Pack',
            'description': 'demo',
            'requires': [],
            'produces': ['Flag(flag_id)'],
            'runtime_inputs': [{'name': 'seed', 'type': 'string', 'required': True}],
            'generator_py_text': 'print("demo")\n',
            'readme_text': '# Demo\n',
        },
    })

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload == {
        'ok': True,
        'message': 'Installed 1 generator(s) from Demo Pack',
        'pack_label': 'Demo Pack',
    }
    assert installed['names'] == [
        'flag_generators/py_demo/README.md',
        'flag_generators/py_demo/docker-compose.yml',
        'flag_generators/py_demo/generator.py',
        'flag_generators/py_demo/manifest.yaml',
    ]
    assert 'id: demo' in installed['manifest']