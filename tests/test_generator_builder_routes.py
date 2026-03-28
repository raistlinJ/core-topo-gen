import io
import json
import os
import time
import zipfile
from pathlib import Path

from webapp import app_backend as backend
from webapp.routes import ai_provider as ai_provider_routes
from webapp.routes import generator_builder_routes


app = backend.app
app.config.setdefault('TESTING', True)
app.config['TESTING'] = True


GENERATOR_BUILDER_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / 'webapp' / 'templates' / 'generator_builder.html'


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
    assert 'Install to Catalog' in body
    assert 'Submit as Refinement' in body
    assert 'Generated Summary' in body
    assert 'Generating Scaffolding' in body
    assert 'Generator Builder Output' in body
    assert 'Clear Builder State' in body
    assert 'CORE VM Credentials' in body
    assert 'Save and Run Test' in body
    assert 'Progress / Log' in body
    assert 'Generated Files' in body
    assert 'Download Transcript' in body
    assert 'API key' in body
    assert 'Verify TLS certificates' in body
    assert 'Iteration History' in body
    assert 'Latest Test Result' in body
    assert 'gbInstallBtnHint' in body
    assert 'gbGenerateOverlayOutput' in body
    assert 'gbGenerateOverlayEvents' in body
    assert 'Auto-follow' in body
    assert 'gbStreamAutoFollowInput' in body
    assert 'gbGenerateOverlayAutoFollowInput' in body
    assert 'gbSaveApiKeyBtn' in body
    assert 'gbClearApiKeyBtn' in body
    assert '/api/ai/provider/credential/status' in body
    assert 'Stored securely on the server for your account.' in body
    assert 'Locked until validation' in body
    assert 'coretg_builder_model_config' in body
    assert 'coretg_builder_workspace_state' in body
    assert 'gbInstallSuccessAlert' in body
    assert 'gbOutputInstallBtn' in body
    assert '<div class="gb-inline-snapshot d-none" id="gbLatestTestSnapshot"></div>' not in body
    assert 'After Scaffold' not in body
    assert 'Compatibility Checklist' not in body
    assert 'Test &amp; Iterate' not in body
    assert 'Advanced <span class="gb-optional-badge">Optional</span>' not in body


def test_generator_builder_template_redacts_sensitive_test_output() -> None:
    text = GENERATOR_BUILDER_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert 'function redactBuilderSensitiveText(line, extraTokens = [])' in text
    assert "elements.testStdout.textContent = redactBuilderSensitiveText(String(payload.stdout || ''));" in text
    assert "elements.testStderr.textContent = redactBuilderSensitiveText(String(payload.stderr || ''));" in text
    assert 'Test Configuration' not in text
    assert 'Install & downloads' not in text
    assert 'Normalized manifest.yaml' not in text
    assert 'Raw model response' not in text
    assert 'Prompt Intent Preview' not in text
    assert 'gbPromptIntentPreview' not in text


def test_generator_builder_template_aggregates_thinking_and_scrolls_latest_activity() -> None:
    text = GENERATOR_BUILDER_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        "transcriptThinkingText: ''",
        "function upsertTranscriptEvent(key, text) {",
        "upsertTranscriptEvent('thinking', `Thinking:\\n${state.transcriptThinkingText}`);",
        "target.scrollTop = target.scrollHeight;",
        "const shouldRevealResults = isNavTabActive(elements.buildTabTestBtn) && isNavTabActive(elements.testProgressTabBtn);",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, 'Missing Builder thinking aggregation / auto-follow snippets: ' + '; '.join(missing)
    assert "scrollIntoView({ block: 'end' });" not in text


def test_generator_builder_template_ignores_stale_api_key_overrides_when_stored_key_exists() -> None:
    text = GENERATOR_BUILDER_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        'apiKeyDirty: false,',
        'function resolveBuilderApiKeyForPayload() {',
        "return state.apiKeyDirty ? raw : '';",
        'api_key: resolveBuilderApiKeyForPayload(),',
        'state.apiKeyDirty = true;',
        'state.apiKeyDirty = false;',
        'if (state.hasStoredApiKey && !state.apiKeyDirty && elements.apiKey) {',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, 'Missing Builder stored-key protection snippets: ' + '; '.join(missing)


def test_generator_builder_template_invalidates_validation_on_model_change_event() -> None:
    text = GENERATOR_BUILDER_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        "elements.model.addEventListener('change', () => {",
        "invalidateModelStep('Model selection changed. Validate again to unlock prompting.');",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, 'Missing Builder model change invalidation snippets: ' + '; '.join(missing)


def test_generator_builder_template_shows_install_result_popup_for_success_and_failure() -> None:
    text = GENERATOR_BUILDER_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        'function showInstallResultAlert(message, detail = \'\', tone = \'success\') {',
        'async function showInstallResultPopup({ title, message, detail = \'\', tone = \'success\', installedAs = null } = {}) {',
        "const resultTone = renameNote ? 'warning' : 'success';",
        "const resultTitle = renameNote ? 'Installed With New ID' : 'Install Succeeded';",
        "showInstallResultAlert('Install failed.', message, 'danger');",
        "title: 'Install Failed',",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, 'Missing Builder install popup snippets: ' + '; '.join(missing)


def test_generator_builder_template_prompts_for_cancel_during_long_waits() -> None:
    text = GENERATOR_BUILDER_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        'const GENERATE_CANCEL_PROMPT_CHECKPOINTS_MS = [90000, 180000, 240000, 360000];',
        'function requestGenerateCancellation(reason = \'Cancellation requested by user.\'',
        'function scheduleNextGenerateLongWaitPrompt() {',
        'async function promptForLongRunningGenerationCancel(checkpointMs) {',
        "cancelLabel: 'Keep Waiting'",
        'appendTranscriptEvent(`User chose to keep waiting after ${seconds}s.`);',
        'startGenerateLongWaitPrompts();',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, 'Missing Builder long-wait cancel prompt snippets: ' + '; '.join(missing)


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


def test_generator_scaffold_meta_surfaces_validation_errors(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(
        backend,
        '_build_generator_scaffold',
        lambda payload: (
            {
                'flag_generators/py_demo/manifest.yaml': 'manifest_version: 1\ninputs:\n  - name: seed\n',
                'flag_generators/py_demo/generator.py': (
                    'def main():\n'
                    '    raise SystemExit("Missing secret in /inputs/config.json")\n'
                ),
            },
            'manifest_version: 1\ninputs:\n  - name: seed\n',
            'flag_generators/py_demo',
        ),
    )

    resp = client.post('/api/generators/scaffold_meta', json={'plugin_id': 'demo'})

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload['ok'] is True
    assert payload['validation_ok'] is False
    assert payload.get('validation_errors')
    assert 'secret' in str(payload['validation_errors'][0])


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


def test_build_generator_builder_ai_messages_compact_grounding_uses_excerpts():
    full_messages = generator_builder_routes._build_generator_builder_ai_messages({
        'plugin_type': 'flag-generator',
        'prompt': 'Build a deterministic demo generator.',
    })
    compact_messages = generator_builder_routes._build_generator_builder_ai_messages({
        'plugin_type': 'flag-generator',
        'prompt': 'Build a deterministic demo generator.',
        'compact_grounding': True,
    })
    ultra_compact_messages = generator_builder_routes._build_generator_builder_ai_messages({
        'plugin_type': 'flag-generator',
        'prompt': 'Build a deterministic demo generator.',
        'compact_grounding': True,
        'ultra_compact_prompt': True,
    })

    full_text = full_messages[1]['content']
    compact_text = compact_messages[1]['content']
    ultra_compact_text = ultra_compact_messages[1]['content']

    assert 'Grounding mode: full' in full_text
    assert 'Grounding mode: compact' in compact_text
    assert 'Grounding mode: ultra-compact' in ultra_compact_text
    assert 'Compact grounding mode is active for this request' in compact_text
    assert 'Ultra-compact grounding mode is active for this request' in ultra_compact_text
    assert 'Reference sample excerpt: manifest.yaml' in compact_text
    assert 'Reference template: generator.py' in full_text
    assert len(compact_text) < len(full_text)
    assert len(ultra_compact_text) < len(compact_text)


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


def test_generator_scaffold_zip_rejects_invalid_scaffold(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(
        backend,
        '_build_generator_scaffold',
        lambda payload: (
            {
                'flag_generators/py_demo_invalid_zip/manifest.yaml': 'manifest_version: 1\ninputs:\n  - name: seed\n',
                'flag_generators/py_demo_invalid_zip/generator.py': 'def main():\n    raise SystemExit("Missing secret in /inputs/config.json")\n',
            },
            'manifest_version: 1\ninputs:\n  - name: seed\n',
            'flag_generators/py_demo_invalid_zip',
        ),
    )

    resp = client.post('/api/generators/scaffold_zip', json={'plugin_id': 'demo_invalid_zip'})

    assert resp.status_code == 400
    payload = resp.get_json() or {}
    assert payload['ok'] is False
    assert 'secret' in str(payload.get('error') or '')
    assert payload.get('validation_errors')


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
    assert captured['timeout'] == 480.0
    assert captured['verify_ssl'] is True
    assert captured['payload']['model'] == 'qwen2.5:7b'
    assert captured['payload']['stream'] is False
    assert captured['payload']['format'] == 'json'
    assert 'flag_generators/py_ssh_creds_drop/generator.py' in payload['files']
    assert payload['files']['flag_generators/py_ssh_creds_drop/generator.py'] == 'print("ai")\n'
    assert 'Credential(user,password)' in payload['manifest_yaml']


def test_generator_ai_scaffold_auto_heals_runtime_input_mismatch(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    class _DummyAdapter:
        capability = type('Capability', (), {'default_base_url': 'http://127.0.0.1:11434'})()

    invalid_json = {
        'plugin_id': 'heal_demo',
        'name': 'Heal Demo',
        'description': 'Initial invalid scaffold.',
        'produces': ['Flag(flag_id)'],
        'runtime_inputs': [
            {'name': 'seed', 'type': 'string', 'required': True},
        ],
        'generator_py_text': (
            'def main():\n'
            '    raise SystemExit("Missing secret in /inputs/config.json")\n'
        ),
    }
    healed_json = {
        'plugin_id': 'heal_demo',
        'name': 'Heal Demo',
        'description': 'Healed scaffold.',
        'produces': ['Flag(flag_id)'],
        'runtime_inputs': [
            {'name': 'seed', 'type': 'string', 'required': True},
            {'name': 'secret', 'type': 'string', 'required': True, 'sensitive': True},
        ],
        'generator_py_text': (
            'def main():\n'
            '    raise SystemExit("Missing secret in /inputs/config.json")\n'
        ),
    }

    responses = [invalid_json, healed_json]
    captured_prompts: list[str] = []

    def _fake_post_json(url, payload, *, timeout, headers=None, verify_ssl=True):
        captured_prompts.append(str(payload.get('prompt') or ''))
        current = responses.pop(0)
        return {'response': '', 'thinking': json.dumps(current)}

    monkeypatch.setattr(ai_provider_routes, '_get_provider_adapter', lambda provider: _DummyAdapter())
    monkeypatch.setattr(ai_provider_routes, '_normalize_base_url', lambda value: str(value))
    monkeypatch.setattr(ai_provider_routes, '_post_json', _fake_post_json)

    resp = client.post('/api/generators/ai_scaffold', json={
        'plugin_type': 'flag-generator',
        'provider': 'ollama',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'qwen2.5:7b',
        'prompt': 'Build a deterministic credential generator.',
    })

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('ok') is True
    assert payload['auto_heal']['attempted'] is True
    assert payload['auto_heal']['healed'] is True
    assert payload['auto_heal']['initial_validation_errors']
    assert payload['validation_errors'] == []
    assert payload['scaffold_request']['runtime_inputs'] == [
        {'name': 'seed', 'type': 'string', 'required': True},
        {'name': 'secret', 'type': 'string', 'required': True, 'sensitive': True},
    ]
    assert len(captured_prompts) == 2
    assert 'Fix these scaffold validation errors first:' in captured_prompts[1]
    assert 'secret' in captured_prompts[1]


def test_generator_ai_scaffold_auto_heals_scaffold_construction_error(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    class _DummyAdapter:
        capability = type('Capability', (), {'default_base_url': 'http://127.0.0.1:11434'})()

    valid_json = {
        'plugin_id': 'json_heal_demo',
        'name': 'JSON Heal Demo',
        'description': 'Recovered scaffold.',
        'produces': ['Flag(flag_id)'],
        'runtime_inputs': [{'name': 'seed', 'type': 'string', 'required': True}],
        'generator_py_text': 'print("ok")\n',
    }

    responses = ['not valid json', json.dumps(valid_json)]
    captured_prompts: list[str] = []

    def _fake_post_json(url, payload, *, timeout, headers=None, verify_ssl=True):
        captured_prompts.append(str(payload.get('prompt') or ''))
        current = responses.pop(0)
        return {'response': current, 'thinking': ''}

    monkeypatch.setattr(ai_provider_routes, '_get_provider_adapter', lambda provider: _DummyAdapter())
    monkeypatch.setattr(ai_provider_routes, '_normalize_base_url', lambda value: str(value))
    monkeypatch.setattr(ai_provider_routes, '_post_json', _fake_post_json)

    resp = client.post('/api/generators/ai_scaffold', json={
        'plugin_type': 'flag-generator',
        'provider': 'ollama',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'qwen2.5:7b',
        'prompt': 'Build a deterministic demo generator.',
    })

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('ok') is True
    assert payload['auto_heal']['attempted'] is True
    assert payload['auto_heal']['healed'] is True
    assert payload['auto_heal']['initial_scaffold_errors']
    assert 'valid JSON object' in payload['auto_heal']['initial_scaffold_errors'][0]
    assert payload['scaffold_request']['plugin_id'] == 'json_heal_demo'
    assert len(captured_prompts) == 2
    assert 'Fix these scaffold construction errors first:' in captured_prompts[1]


def test_generator_ai_scaffold_auto_heals_noop_refinement(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    class _DummyAdapter:
        capability = type('Capability', (), {'default_base_url': 'http://127.0.0.1:11434'})()

    current_scaffold = {
        'plugin_type': 'flag-generator',
        'plugin_id': 'refine_demo',
        'folder_name': 'py_refine_demo',
        'name': 'Refine Demo',
        'description': 'Current scaffold.',
        'requires': [],
        'produces': ['Flag(flag_id)'],
        'runtime_inputs': [{'name': 'seed', 'type': 'string', 'required': True}],
        'generator_py_text': 'print("before")\n',
    }
    current_files, _manifest_yaml, _folder_path = backend._build_generator_scaffold(current_scaffold)
    unchanged_json = {
        'plugin_id': 'refine_demo',
        'folder_name': 'py_refine_demo',
        'name': 'Refine Demo',
        'description': 'Current scaffold.',
        'produces': ['Flag(flag_id)'],
        'runtime_inputs': [{'name': 'seed', 'type': 'string', 'required': True}],
        'generator_py_text': 'print("before")\n',
    }
    healed_json = {
        'plugin_id': 'refine_demo',
        'folder_name': 'py_refine_demo',
        'name': 'Refine Demo',
        'description': 'Refined scaffold.',
        'produces': ['Flag(flag_id)'],
        'runtime_inputs': [{'name': 'seed', 'type': 'string', 'required': True}],
        'generator_py_text': 'print("after")\n',
    }

    responses = [unchanged_json, healed_json]
    captured_prompts: list[str] = []

    def _fake_post_json(url, payload, *, timeout, headers=None, verify_ssl=True):
        captured_prompts.append(str(payload.get('prompt') or ''))
        current = responses.pop(0)
        return {'response': '', 'thinking': json.dumps(current)}

    monkeypatch.setattr(ai_provider_routes, '_get_provider_adapter', lambda provider: _DummyAdapter())
    monkeypatch.setattr(ai_provider_routes, '_normalize_base_url', lambda value: str(value))
    monkeypatch.setattr(ai_provider_routes, '_post_json', _fake_post_json)

    resp = client.post('/api/generators/ai_scaffold', json={
        'plugin_type': 'flag-generator',
        'provider': 'ollama',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'qwen2.5:7b',
        'prompt': 'Refine the generator to fix the last failure and change the generated output.',
        'current_scaffold_request': current_scaffold,
        'current_files': current_files,
        'last_test_result': {
            'ok': False,
            'returncode': 1,
            'failure_summary': 'Generator still behaves the same after refinement.',
            'stderr': 'Generator still behaves the same after refinement.',
            'stdout': '',
            'files': [],
        },
    })

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('ok') is True
    assert payload['auto_heal']['attempted'] is True
    assert payload['auto_heal']['healed'] is True
    assert any('same scaffold files' in str(item).lower() for item in payload['auto_heal']['initial_validation_errors'])
    assert any('generator still behaves the same after refinement.' in str(item).lower() for item in payload['auto_heal']['initial_validation_errors'])
    assert len(captured_prompts) == 2
    assert 'same scaffold files' in captured_prompts[1].lower()


def test_build_generator_builder_ai_messages_require_actual_refine_edits():
    messages = generator_builder_routes._build_generator_builder_ai_messages({
        'plugin_type': 'flag-generator',
        'prompt': 'Refine the current generator.',
        'current_scaffold_request': {
            'plugin_id': 'refine_demo',
            'folder_name': 'py_refine_demo',
        },
        'current_files': {
            'flag_generators/py_refine_demo/generator.py': 'print("before")\n',
        },
    })

    text = messages[1]['content']
    assert 'Do not return the current scaffold unchanged' in text


def test_build_generator_builder_ai_messages_include_missing_module_guidance():
    messages = generator_builder_routes._build_generator_builder_ai_messages({
        'plugin_type': 'flag-generator',
        'prompt': 'Refine the current generator.',
        'current_scaffold_request': {
            'plugin_id': 'refine_demo',
            'folder_name': 'py_refine_demo',
        },
        'current_files': {
            'flag_generators/py_refine_demo/generator.py': 'from PIL import Image\n',
        },
        'last_test_result': {
            'ok': False,
            'returncode': 1,
            'failure_summary': "ModuleNotFoundError: No module named 'PIL'",
            'stderr': '',
            'stdout': '',
            'files': [],
        },
    })

    text = messages[1]['content']
    assert 'missing the Python dependency PIL' in text
    assert 'compose_text or the Docker image build' in text


def test_build_generator_builder_ai_messages_include_iteration_history_and_validation() -> None:
    messages = generator_builder_routes._build_generator_builder_ai_messages({
        'plugin_type': 'flag-generator',
        'prompt': 'Now update the compose file so dependencies are installed and keep the Batman theme.',
        'current_scaffold_request': {
            'plugin_id': 'batman_demo',
            'folder_name': 'py_batman_demo',
        },
        'current_files': {
            'flag_generators/py_batman_demo/generator.py': 'from PIL import Image\nprint("demo")\n',
        },
        'iteration_history': [
            {
                'mode': 'create',
                'prompt': 'Create a Batman-themed stego flag generator.',
                'plugin_id': 'batman_demo',
                'status': 'scaffold updated',
            },
            {
                'mode': 'test',
                'prompt': 'irrelevant test row',
                'plugin_id': 'batman_demo',
                'status': 'failed rc=1',
            },
            {
                'mode': 'refine',
                'prompt': 'Keep the same generator but make the image output deterministic.',
                'plugin_id': 'batman_demo',
                'status': 'scaffold updated',
            },
        ],
        'scaffold_validation': {
            'ok': False,
            'pending': False,
            'errors': ['manifest and generator inputs are out of sync'],
            'message': '',
            'source': 'generation',
        },
    })

    text = messages[1]['content']
    assert 'Original create request:' in text
    assert 'Create a Batman-themed stego flag generator.' in text
    assert 'Recent create/refine history (oldest to newest):' in text
    assert 'Keep the same generator but make the image output deterministic.' in text
    assert 'irrelevant test row' not in text
    assert 'Current scaffold validation warnings:' in text
    assert 'manifest and generator inputs are out of sync' in text


def test_generator_ai_scaffold_stream_openai_compatible_concatenates_fragment_lists(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    class _DummyAdapter:
        capability = type('Capability', (), {'default_base_url': 'https://litellm.example.com/v1'})()

    monkeypatch.setattr(ai_provider_routes, '_get_provider_adapter', lambda provider: _DummyAdapter())
    monkeypatch.setattr(ai_provider_routes, '_resolve_payload_with_stored_api_key', lambda payload: {**payload, 'api_key': 'stored-builder-key'})
    monkeypatch.setattr(ai_provider_routes, '_normalize_openai_compatible_base_url', lambda value, *, enforce_ssl: 'https://litellm.example.com/v1')

    def _fake_post_json(url, payload, *, timeout, headers=None, verify_ssl=True, on_open=None):
        if callable(on_open):
            on_open(object())
        return {
            'choices': [
                {
                    'message': {
                        'content': [
                            {'type': 'text', 'text': '{'},
                            {'type': 'text', 'text': '"plugin_id": '},
                            {'type': 'text', 'text': '"nemotron_demo"'},
                            {'type': 'text', 'text': '}'},
                        ],
                    },
                }
            ]
        }

    monkeypatch.setattr(ai_provider_routes, '_post_json', _fake_post_json)

    resp = client.post('/api/generators/ai_scaffold_stream', json={
        'request_id': 'builder-openai-fragment-list-test',
        'plugin_type': 'flag-generator',
        'provider': 'litellm',
        'base_url': 'https://litellm.example.com/v1',
        'model': 'nemotron',
        'prompt': 'Build a deterministic fragment-list demo generator.',
    })

    assert resp.status_code == 200
    events = [json.loads(line) for line in resp.get_data(as_text=True).splitlines() if line.strip()]
    llm_deltas = [str(event.get('text') or '') for event in events if event.get('type') == 'llm_delta']
    assert llm_deltas
    assert '\n' not in llm_deltas[-1]
    assert llm_deltas[-1] == '{"plugin_id": "nemotron_demo"}'


def test_generator_ai_scaffold_stream_auto_heals_scaffold_build_error(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    class _DummyAdapter:
        capability = type('Capability', (), {'default_base_url': 'http://127.0.0.1:11434'})()

    assistant_json = {
        'plugin_id': 'stream_build_heal_demo',
        'name': 'Stream Build Heal Demo',
        'description': 'Recovered after scaffold build failure.',
        'produces': ['Flag(flag_id)'],
        'runtime_inputs': [{'name': 'seed', 'type': 'string', 'required': True}],
        'generator_py_text': 'print("stream-build")\n',
    }
    stream_payloads = [json.dumps(assistant_json), json.dumps(assistant_json)]
    original_build = generator_builder_routes._BUILD_GENERATOR_SCAFFOLD
    build_calls = {'count': 0}

    monkeypatch.setattr(ai_provider_routes, '_get_provider_adapter', lambda provider: _DummyAdapter())
    monkeypatch.setattr(ai_provider_routes, '_normalize_base_url', lambda value: str(value))

    def _fake_stream_json_lines(url, payload, *, timeout, headers=None, verify_ssl=True, cancellation_check=None, on_open=None):
        if callable(on_open):
            on_open(object())
        yield {'response': stream_payloads.pop(0)}

    def _build_once_then_succeed(scaffold_payload):
        build_calls['count'] += 1
        if build_calls['count'] == 1:
            raise RuntimeError('synthetic scaffold build failed')
        return original_build(scaffold_payload)

    monkeypatch.setattr(ai_provider_routes, '_stream_json_lines', _fake_stream_json_lines)
    monkeypatch.setattr(generator_builder_routes, '_BUILD_GENERATOR_SCAFFOLD', _build_once_then_succeed)

    resp = client.post('/api/generators/ai_scaffold_stream', json={
        'request_id': 'builder-stream-scaffold-heal-test',
        'plugin_type': 'flag-generator',
        'provider': 'ollama',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'qwen2.5:7b',
        'prompt': 'Build a deterministic stream demo generator.',
    })

    assert resp.status_code == 200
    events = [json.loads(line) for line in resp.get_data(as_text=True).splitlines() if line.strip()]
    event_types = [event.get('type') for event in events]
    assert 'llm_output_reset' in event_types
    status_messages = [str(event.get('message') or '') for event in events if event.get('type') == 'status']
    assert 'Generated scaffold could not be normalized or built; attempting AI auto-heal...' in status_messages
    result_event = next(event for event in events if event.get('type') == 'result')
    assert result_event['data']['auto_heal']['attempted'] is True
    assert result_event['data']['auto_heal']['healed'] is True
    assert result_event['data']['auto_heal']['initial_scaffold_errors'] == ['synthetic scaffold build failed']
    assert result_event['data']['scaffold_request']['plugin_id'] == 'stream_build_heal_demo'


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


def test_generator_ai_scaffold_stream_auto_heals_runtime_input_mismatch(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    class _DummyAdapter:
        capability = type('Capability', (), {'default_base_url': 'http://127.0.0.1:11434'})()

    invalid_json = {
        'plugin_id': 'stream_heal_demo',
        'name': 'Stream Heal Demo',
        'description': 'Initial invalid scaffold.',
        'produces': ['Flag(flag_id)'],
        'runtime_inputs': [{'name': 'seed', 'type': 'string', 'required': True}],
        'generator_py_text': 'def main():\n    raise SystemExit("Missing secret in /inputs/config.json")\n',
    }
    healed_json = {
        'plugin_id': 'stream_heal_demo',
        'name': 'Stream Heal Demo',
        'description': 'Healed scaffold.',
        'produces': ['Flag(flag_id)'],
        'runtime_inputs': [
            {'name': 'seed', 'type': 'string', 'required': True},
            {'name': 'secret', 'type': 'string', 'required': True, 'sensitive': True},
        ],
        'generator_py_text': 'def main():\n    raise SystemExit("Missing secret in /inputs/config.json")\n',
    }
    stream_payloads = [json.dumps(invalid_json), json.dumps(healed_json)]

    monkeypatch.setattr(ai_provider_routes, '_get_provider_adapter', lambda provider: _DummyAdapter())
    monkeypatch.setattr(ai_provider_routes, '_normalize_base_url', lambda value: str(value))

    def _fake_stream_json_lines(url, payload, *, timeout, headers=None, verify_ssl=True, cancellation_check=None, on_open=None):
        if callable(on_open):
            on_open(object())
        yield {'response': stream_payloads.pop(0)}

    monkeypatch.setattr(ai_provider_routes, '_stream_json_lines', _fake_stream_json_lines)

    resp = client.post('/api/generators/ai_scaffold_stream', json={
        'request_id': 'builder-stream-heal-test',
        'plugin_type': 'flag-generator',
        'provider': 'ollama',
        'base_url': 'http://127.0.0.1:11434',
        'model': 'qwen2.5:7b',
        'prompt': 'Build a deterministic stream demo generator.',
    })

    assert resp.status_code == 200
    events = [json.loads(line) for line in resp.get_data(as_text=True).splitlines() if line.strip()]
    event_types = [event.get('type') for event in events]
    assert 'llm_output_reset' in event_types
    status_messages = [str(event.get('message') or '') for event in events if event.get('type') == 'status']
    assert 'Generated scaffold failed validation; attempting AI auto-heal...' in status_messages
    result_event = next(event for event in events if event.get('type') == 'result')
    assert result_event['data']['auto_heal']['attempted'] is True
    assert result_event['data']['auto_heal']['healed'] is True
    assert result_event['data']['scaffold_request']['runtime_inputs'] == [
        {'name': 'seed', 'type': 'string', 'required': True},
        {'name': 'secret', 'type': 'string', 'required': True, 'sensitive': True},
    ]


def test_generator_ai_scaffold_stream_emits_openai_compatible_progress_statuses(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    class _DummyAdapter:
        capability = type('Capability', (), {'default_base_url': 'https://litellm.example.com/v1'})()

    monkeypatch.setattr(ai_provider_routes, '_get_provider_adapter', lambda provider: _DummyAdapter())
    monkeypatch.setattr(ai_provider_routes, '_resolve_payload_with_stored_api_key', lambda payload: {**payload, 'api_key': 'stored-builder-key'})
    monkeypatch.setattr(ai_provider_routes, '_normalize_openai_compatible_base_url', lambda value, *, enforce_ssl: 'https://litellm.example.com/v1')
    def _fake_post_json(url, payload, *, timeout, headers=None, verify_ssl=True, on_open=None):
        assert url == 'https://litellm.example.com/v1/chat/completions'
        assert payload['messages'][0]['role'] == 'user'
        assert payload['response_format'] == {'type': 'json_object'}
        assert headers == {'Authorization': 'Bearer stored-builder-key'}
        if callable(on_open):
            on_open(object())
        time.sleep(0.03)
        return {'choices': [{'message': {'content': json.dumps({'plugin_id': 'builder_progress_demo'})}}]}

    monkeypatch.setattr(ai_provider_routes, '_post_json', _fake_post_json)
    monkeypatch.setattr(generator_builder_routes, '_BUILDER_PROVIDER_HEARTBEAT_SECONDS', 0.01)

    resp = client.post('/api/generators/ai_scaffold_stream', json={
        'request_id': 'builder-openai-progress-test',
        'plugin_type': 'flag-generator',
        'provider': 'litellm',
        'base_url': 'https://litellm.example.com/v1',
        'model': 'gpt-4o-mini',
        'prompt': 'Build a demo generator.',
    })

    assert resp.status_code == 200
    assert resp.mimetype == 'application/x-ndjson'
    events = [json.loads(line) for line in resp.get_data(as_text=True).splitlines() if line.strip()]
    statuses = [event.get('message') for event in events if event.get('type') == 'status']
    assert 'Preparing Builder prompt...' in statuses
    assert 'Using ultra-compact Builder prompt for OpenAI-compatible create request.' in statuses
    assert 'Using compact Builder grounding for OpenAI-compatible request.' in statuses
    assert 'Contacting litellm...' in statuses
    assert any(str(message).startswith('Builder diagnostics: prompt_chars=') for message in statuses)
    assert 'Contacting OpenAI-compatible endpoint (initial)...' in statuses
    assert any(str(message).startswith('Still waiting on OpenAI-compatible endpoint (initial)... elapsed=') for message in statuses)
    assert any(str(message).startswith('OpenAI-compatible endpoint accepted the request after ') for message in statuses)
    assert any(str(message).startswith('OpenAI-compatible endpoint responded (initial) in ') for message in statuses)
    event_types = [event.get('type') for event in events]
    assert 'llm_prompt' in event_types
    assert 'llm_delta' in event_types
    assert 'result' in event_types


def test_generator_ai_scaffold_stream_openai_compatible_extracts_reasoning_content(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    class _DummyAdapter:
        capability = type('Capability', (), {'default_base_url': 'https://litellm.example.com/v1'})()

    monkeypatch.setattr(ai_provider_routes, '_get_provider_adapter', lambda provider: _DummyAdapter())
    monkeypatch.setattr(ai_provider_routes, '_resolve_payload_with_stored_api_key', lambda payload: {**payload, 'api_key': 'stored-builder-key'})
    monkeypatch.setattr(ai_provider_routes, '_normalize_openai_compatible_base_url', lambda value, *, enforce_ssl: 'https://litellm.example.com/v1')

    def _fake_post_json(url, payload, *, timeout, headers=None, verify_ssl=True, on_open=None):
        if callable(on_open):
            on_open(object())
        return {
            'choices': [
                {
                    'message': {
                        'content': '',
                        'reasoning_content': json.dumps({'plugin_id': 'builder_reasoning_demo'}),
                    },
                },
            ],
        }

    monkeypatch.setattr(ai_provider_routes, '_post_json', _fake_post_json)

    resp = client.post('/api/generators/ai_scaffold_stream', json={
        'request_id': 'builder-openai-reasoning-content-test',
        'plugin_type': 'flag-generator',
        'provider': 'litellm',
        'base_url': 'https://litellm.example.com/v1',
        'model': 'gpt-4o-mini',
        'prompt': 'Build a demo generator.',
    })

    assert resp.status_code == 200
    events = [json.loads(line) for line in resp.get_data(as_text=True).splitlines() if line.strip()]
    assert any(event.get('type') == 'llm_delta' and 'builder_reasoning_demo' in str(event.get('text') or '') for event in events)
    result_event = next(event for event in events if event.get('type') == 'result')
    assert result_event['data']['scaffold_request']['plugin_id'] == 'builder_reasoning_demo'


def test_generator_ai_scaffold_openai_compatible_uses_api_key_and_ssl(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    class _DummyAdapter:
        capability = type('Capability', (), {'default_base_url': 'https://litellm.example.com/v1'})()

    captured: dict[str, object] = {}

    monkeypatch.setattr(ai_provider_routes, '_get_provider_adapter', lambda provider: _DummyAdapter())
    monkeypatch.setattr(
        ai_provider_routes,
        '_normalize_openai_compatible_base_url',
        lambda value, *, enforce_ssl: 'http://litellm.local/v1' if not enforce_ssl else 'https://litellm.example.com/v1',
    )
    def _fake_post_json(url, payload, *, timeout, headers=None, verify_ssl=True, on_open=None):
        captured['url'] = url
        captured['headers'] = headers
        captured['verify_ssl'] = verify_ssl
        captured['payload'] = payload
        return {'choices': [{'message': {'content': json.dumps({'plugin_id': 'api_key_tls_demo'})}}]}

    monkeypatch.setattr(ai_provider_routes, '_post_json', _fake_post_json)

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
    assert captured['url'] == 'http://litellm.local/v1/chat/completions'
    assert captured['headers'] == {'Authorization': 'Bearer builder-secret-key'}
    assert captured['verify_ssl'] is False
    assert captured['payload']['response_format'] == {'type': 'json_object'}


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


def test_generator_builder_async_test_success_refreshes_install_gating_snippets() -> None:
    text = GENERATOR_BUILDER_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        'function updateLatestBuilderTestResult(data, runId) {',
        'builderTestState.latestOutputsData = data || null;',
        'state.lastTestResult = data || null;',
        'updateActionButtons();',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, 'Missing builder test success install-gating refresh snippets: ' + '; '.join(missing)


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


def test_generator_builder_ai_messages_add_runtime_input_drift_guidance():
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
            'produces': ['Flag(flag_id)'],
            'runtime_inputs': [{'name': 'seed', 'type': 'string', 'required': True}],
        },
        'last_test_result': {
            'ok': False,
            'returncode': 1,
            'stderr': 'Generated scaffold is inconsistent: generator.py requires runtime input(s) secret via /inputs/config.json, but manifest.yaml does not declare them under inputs.',
            'failure_summary': 'Generated scaffold is inconsistent: generator.py requires runtime input(s) secret via /inputs/config.json, but manifest.yaml does not declare them under inputs.',
            'files': [],
        },
    })

    user_content = messages[1]['content']
    assert 'Observed failure to fix first: generator.py requires runtime config keys that manifest inputs do not declare.' in user_content
    assert 'Every key that generator.py treats as required from /inputs/config.json must appear in runtime_inputs' in user_content


def test_generator_builder_ai_messages_add_image_generation_guidance_for_stego_prompts():
    messages = generator_builder_routes._build_generator_builder_ai_messages({
        'plugin_type': 'flag-generator',
        'prompt': 'Build a deterministic stego generator that creates a PNG image with a hidden flag.',
    })

    user_content = messages[1]['content']
    assert 'For image or steganography outputs, generate a valid, viewable carrier image file rather than random bytes renamed to .png or .jpg.' in user_content
    assert 'Prefer Pillow/PIL with an explicit install step in compose_text when you need to create or modify images' in user_content
    assert 'Do not append arbitrary payload bytes after image end markers or mutate container bytes outside real pixel data.' in user_content


def test_generator_builder_ai_messages_prioritize_refine_context_and_render_file_blocks():
    messages = generator_builder_routes._build_generator_builder_ai_messages({
        'plugin_type': 'flag-generator',
        'prompt': 'Please refine the generator to fix the failing image output.',
        'current_scaffold_request': {
            'plugin_id': 'demo',
            'folder_name': 'py_demo',
            'name': 'Demo',
            'description': 'demo',
            'requires': [],
            'produces': ['Flag(flag_id)', 'File(path)'],
            'runtime_inputs': [{'name': 'seed', 'type': 'string', 'required': True}],
        },
        'current_files': {
            'flag_generators/py_demo/generator.py': 'print("demo")\n',
            'flag_generators/py_demo/manifest.yaml': 'manifest_version: 1\n',
        },
        'last_test_result': {
            'ok': False,
            'returncode': 1,
            'failure_summary': 'generated image is corrupt',
            'stderr': 'generated image is corrupt',
            'stdout': '',
            'files': [],
        },
    })

    user_content = messages[1]['content']
    assert 'Refinement priority:' in user_content
    assert 'Treat the current scaffold below as the source material to edit, not as a loose example.' in user_content
    assert 'File: flag_generators/py_demo/generator.py' in user_content
    assert '```python' in user_content
    assert 'print("demo")' in user_content
    assert user_content.index('Latest local test result:') < user_content.index('Reference template: generator.py')
    assert user_content.index('Current scaffold files:') < user_content.index('Reference template: generator.py')


def test_generator_builder_template_handles_stream_auto_heal_reset() -> None:
    text = GENERATOR_BUILDER_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        "if (type === 'llm_output_reset') {",
        'assistantAttemptLabel',
        'state.assistantText = \'\';',
        'Starting another model attempt after an automatic retry.',
        'Automatic scaffold repair succeeded after an early validation failure.',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, 'Missing Builder auto-heal stream handling snippets: ' + '; '.join(missing)


def test_generator_builder_template_surfaces_scaffold_validation_warnings() -> None:
    text = GENERATOR_BUILDER_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        'id="gbScaffoldValidationBanner"',
        'scaffoldValidation: null,',
        'function applyScaffoldValidationState(result, options = {}) {',
        'function renderScaffoldValidation() {',
        "Validating current scaffold contract...",
        "Scaffold contract check passed: manifest inputs, generated files, and runtime expectations are aligned.",
        "Scaffold validation warning",
        "Scaffold validation', !validation ? 'pending'",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, 'Missing Builder scaffold validation warning snippets: ' + '; '.join(missing)


def test_generator_builder_template_refreshes_validation_for_restored_scaffolds() -> None:
    text = GENERATOR_BUILDER_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        "function refreshScaffoldValidation(options = {}) {",
        "fetchJson('/api/generators/scaffold_meta'",
        "applyScaffoldValidationState(result, { source: 'refresh' });",
        "setTimeout(() => { refreshScaffoldValidation({ quiet: true }); }, 0);",
        "Resolve scaffold validation warnings before installing this generator.",
        "Wait for scaffold validation to finish before installing.",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, 'Missing Builder scaffold validation refresh/gating snippets: ' + '; '.join(missing)


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


def test_generator_builder_test_rejects_runtime_input_mismatch(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    def _unexpected_remote_test(**_kwargs):
        raise AssertionError('remote builder test should not run for an inconsistent scaffold')

    monkeypatch.setattr(backend, '_run_remote_builder_scaffold_test', _unexpected_remote_test)

    resp = client.post('/api/generators/builder_test', json={
        'scaffold_request': {
            'plugin_type': 'flag-generator',
            'plugin_id': 'demo_mismatch',
            'folder_name': 'py_demo_mismatch',
            'name': 'Demo Mismatch',
            'description': 'demo',
            'requires': [],
            'produces': ['Flag(flag_id)'],
            'runtime_inputs': [
                {'name': 'seed', 'type': 'string', 'required': True},
            ],
            'generator_py_text': (
                'import json\n'
                'from pathlib import Path\n\n'
                'def _read_config():\n'
                '    return json.loads(Path("/inputs/config.json").read_text("utf-8"))\n\n'
                'def main():\n'
                '    cfg = _read_config()\n'
                '    seed = str(cfg.get("seed") or "").strip()\n'
                '    secret = str(cfg.get("secret") or "").strip()\n'
                '    if not seed:\n'
                '        raise SystemExit("Missing seed in /inputs/config.json")\n'
                '    if not secret:\n'
                '        raise SystemExit("Missing secret in /inputs/config.json")\n\n'
                'if __name__ == "__main__":\n'
                '    main()\n'
            ),
        },
    })

    assert resp.status_code == 400
    payload = resp.get_json() or {}
    assert payload['ok'] is False
    assert 'Generated scaffold is inconsistent' in str(payload.get('error') or '')
    assert 'secret' in str(payload.get('error') or '')
    assert payload.get('validation_errors')


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


def test_generator_builder_test_run_rejects_runtime_input_mismatch(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_parse_flag_test_core_cfg_from_form', lambda form: {'ssh_host': 'core', 'ssh_port': 22, 'ssh_username': 'user', 'ssh_password': 'pw'})
    monkeypatch.setattr(backend, '_ensure_core_vm_idle_for_test', lambda core_cfg: None)

    def _unexpected_start(**_kwargs):
        raise AssertionError('async remote builder test should not start for an inconsistent scaffold')

    monkeypatch.setattr(backend, '_start_remote_builder_scaffold_test_process', _unexpected_start)

    resp = client.post('/api/generators/builder_test/run', data={
        'scaffold_request': json.dumps({
            'plugin_type': 'flag-generator',
            'plugin_id': 'demo_async_mismatch',
            'folder_name': 'py_demo_async_mismatch',
            'name': 'Demo Async Mismatch',
            'description': 'demo',
            'requires': [],
            'produces': ['Flag(flag_id)'],
            'runtime_inputs': [
                {'name': 'seed', 'type': 'string', 'required': True},
            ],
            'generator_py_text': (
                'import json\n'
                'from pathlib import Path\n\n'
                'def _read_config():\n'
                '    return json.loads(Path("/inputs/config.json").read_text("utf-8"))\n\n'
                'def main():\n'
                '    cfg = _read_config()\n'
                '    seed = str(cfg.get("seed") or "").strip()\n'
                '    secret = str(cfg.get("secret") or "").strip()\n'
                '    if not seed:\n'
                '        raise SystemExit("Missing seed in /inputs/config.json")\n'
                '    if not secret:\n'
                '        raise SystemExit("Missing secret in /inputs/config.json")\n\n'
                'if __name__ == "__main__":\n'
                '    main()\n'
            ),
        }),
        'seed': 'custom-seed',
        'core': json.dumps({'ssh_host': 'core'}),
    })

    assert resp.status_code == 400
    payload = resp.get_json() or {}
    assert payload['ok'] is False
    assert 'Generated scaffold is inconsistent' in str(payload.get('error') or '')
    assert 'secret' in str(payload.get('error') or '')
    assert payload.get('validation_errors')


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
    assert payload.get('ok') is True
    assert payload.get('message') == 'Installed 1 generator(s) from Demo Pack'
    assert payload.get('pack_label') == 'Demo Pack'
    assert payload.get('renamed') is False
    assert payload.get('rename_note') == ''
    assert payload.get('installed_as') == {
        'plugin_type': 'flag-generator',
        'plugin_id': 'demo',
        'name': 'Demo Pack',
        'folder_name': 'py_demo',
    }
    assert installed['names'] == [
        'flag_generators/py_demo/README.md',
        'flag_generators/py_demo/docker-compose.yml',
        'flag_generators/py_demo/generator.py',
        'flag_generators/py_demo/manifest.yaml',
    ]
    assert 'id: demo' in installed['manifest']


def test_generator_install_generated_rejects_invalid_scaffold(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    def _unexpected_install(**_kwargs):
        raise AssertionError('install should not run for an invalid scaffold')

    monkeypatch.setattr(backend, '_install_generator_pack_or_bundle', _unexpected_install)

    resp = client.post('/api/generators/install_generated', json={
        'pack_label': 'Demo Pack',
        'scaffold_request': {
            'plugin_type': 'flag-generator',
            'plugin_id': 'demo_invalid_install',
            'folder_name': 'py_demo_invalid_install',
            'name': 'Demo Invalid Install',
            'description': 'demo',
            'requires': [],
            'produces': ['Flag(flag_id)'],
            'runtime_inputs': [
                {'name': 'seed', 'type': 'string', 'required': True},
            ],
            'generator_py_text': (
                'def main():\n'
                '    raise SystemExit("Missing secret in /inputs/config.json")\n'
            ),
        },
    })

    assert resp.status_code == 400
    payload = resp.get_json() or {}
    assert payload['ok'] is False
    assert 'secret' in str(payload.get('error') or '')
    assert payload.get('validation_errors')


def test_generator_install_generated_renames_duplicate_id(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_flag_generators_from_enabled_sources', lambda: ([{'id': 'demo', 'name': 'Demo Pack'}], []))

    installed = {}

    def _fake_install(*, zip_path, pack_label, pack_origin):
        assert pack_label == 'Demo Pack 2'
        assert pack_origin == 'generator_builder'
        with zipfile.ZipFile(zip_path, 'r') as archive:
            installed['names'] = sorted(archive.namelist())
            installed['manifest'] = archive.read('flag_generators/py_demo_2/manifest.yaml').decode('utf-8')
        return True, 'Installed 1 generator(s) from Demo Pack 2'

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
    assert payload.get('ok') is True
    assert payload.get('renamed') is True
    assert payload.get('pack_label') == 'Demo Pack 2'
    assert payload.get('rename_note') == 'Duplicate generator id "demo" detected. Installed as "demo_2".'
    assert payload.get('installed_as') == {
        'plugin_type': 'flag-generator',
        'plugin_id': 'demo_2',
        'name': 'Demo Pack 2',
        'folder_name': 'py_demo_2',
    }
    assert installed['names'] == [
        'flag_generators/py_demo_2/README.md',
        'flag_generators/py_demo_2/docker-compose.yml',
        'flag_generators/py_demo_2/generator.py',
        'flag_generators/py_demo_2/manifest.yaml',
    ]
    assert 'id: demo_2' in installed['manifest']


def test_generator_install_generated_detects_duplicates_in_configured_install_root(tmp_path, monkeypatch):
    install_root = tmp_path / 'installed_generators'
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(install_root))

    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    payload = {
        'pack_label': 'Live Smoke Demo',
        'scaffold_request': {
            'plugin_type': 'flag-generator',
            'plugin_id': 'live_smoke_demo',
            'folder_name': 'py_live_smoke_demo',
            'name': 'Live Smoke Demo',
            'description': 'demo',
            'requires': [],
            'produces': ['Flag(flag_id)'],
            'runtime_inputs': [{'name': 'seed', 'type': 'string', 'required': True}],
            'generator_py_text': 'print("demo")\n',
            'readme_text': '# Demo\n',
        },
    }

    first = client.post('/api/generators/install_generated', json=payload)
    assert first.status_code == 200
    first_payload = first.get_json() or {}
    assert first_payload.get('renamed') is False
    assert (first_payload.get('installed_as') or {}).get('plugin_id') == 'live_smoke_demo'

    second = client.post('/api/generators/install_generated', json=payload)
    assert second.status_code == 200
    second_payload = second.get_json() or {}
    assert second_payload.get('renamed') is True
    assert second_payload.get('rename_note') == 'Duplicate generator id "live_smoke_demo" detected. Installed as "live_smoke_demo_2".'
    assert (second_payload.get('installed_as') or {}).get('plugin_id') == 'live_smoke_demo_2'