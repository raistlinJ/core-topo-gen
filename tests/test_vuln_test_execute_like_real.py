import os

from webapp import app_backend


def test_vuln_test_build_ephemeral_execute_job_builds_xml_and_job_spec(tmp_path, monkeypatch):
    run_dir = tmp_path / 'run'
    run_dir.mkdir(parents=True, exist_ok=True)
    compose_path = run_dir / 'docker-compose.yml'
    compose_path.write_text("version: '3.8'\nservices:\n  app:\n    image: alpine:latest\n", encoding='utf-8')

    monkeypatch.setattr(
        app_backend,
        '_planner_persist_flow_plan',
        lambda **kwargs: {
            'xml_path': kwargs.get('xml_path'),
            'preview_plan_path': kwargs.get('xml_path'),
            'scenario': kwargs.get('scenario'),
            'full_preview': {},
        },
    )

    job_spec, err = app_backend._vuln_test_build_ephemeral_execute_job(
        run_dir=str(run_dir),
        run_id='abc123',
        core_cfg={'ssh_host': '127.0.0.1', 'ssh_username': 'u', 'ssh_password': 'p', 'host': '127.0.0.1', 'port': 50051},
        item_id=7,
        item_name='Demo Vuln',
        compose_path=str(compose_path),
    )

    assert err is None
    assert isinstance(job_spec, dict)
    xml_path = str(job_spec.get('xml_path') or '')
    assert xml_path and os.path.exists(xml_path)
    assert job_spec.get('preview_plan_path') == xml_path
    assert job_spec.get('flow_enabled') is False

    xml_text = open(xml_path, 'r', encoding='utf-8').read()
    assert "<section name='Node Information'>" in xml_text
    assert "selected='Docker'" in xml_text
    assert "<section name='Vulnerabilities'" in xml_text
    assert "selected='Specific'" in xml_text
    assert f"v_path='{str(compose_path)}'" in xml_text


def test_vuln_catalog_test_start_defaults_execute_like_real(monkeypatch, tmp_path):
    compose_path = tmp_path / 'catalog-compose.yml'
    compose_path.write_text("version: '3.8'\nservices:\n  app:\n    image: alpine:latest\n", encoding='utf-8')

    monkeypatch.setattr(app_backend, '_load_vuln_catalogs_state', lambda: {'catalogs': []})
    monkeypatch.setattr(app_backend, '_get_active_vuln_catalog_entry', lambda _state: {'id': 'cat1'})
    monkeypatch.setattr(app_backend, '_normalize_vuln_catalog_items', lambda _entry: [{'id': 1, 'name': 'Demo Vuln'}])
    monkeypatch.setattr(app_backend, '_vuln_catalog_item_abs_compose_path', lambda **_kwargs: str(compose_path))
    monkeypatch.setattr(
        app_backend,
        '_merge_core_configs',
        lambda *_args, **_kwargs: {
            'ssh_host': '127.0.0.1',
            'ssh_port': 22,
            'ssh_username': 'u',
            'ssh_password': 'p',
            'host': '127.0.0.1',
            'port': 50051,
        },
    )
    monkeypatch.setattr(app_backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    monkeypatch.setattr(app_backend, '_list_active_core_sessions', lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        app_backend,
        '_vuln_test_build_ephemeral_execute_job',
        lambda **_kwargs: ({
            'seed': None,
            'xml_path': str(tmp_path / 'ephemeral.xml'),
            'preview_plan_path': str(tmp_path / 'ephemeral.xml'),
            'core_override': {'ssh_host': '127.0.0.1'},
            'scenario_name_hint': 'vuln-test',
            'scenario_for_plan': 'vuln-test',
        }, None),
    )
    monkeypatch.setattr(app_backend, '_run_cli_background_task', lambda *_args, **_kwargs: None)

    class _DummyThread:
        def __init__(self, target=None, args=(), kwargs=None, name=None, daemon=None):
            self.target = target
            self.args = args

        def start(self):
            return None

    monkeypatch.setattr(app_backend.threading, 'Thread', _DummyThread)

    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()
    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (200, 302)

    resp = client.post('/vuln_catalog_items/test/start', json={'item_id': 1, 'core': {}})
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('ok') is True
    assert payload.get('execute_like_real') is True

    run_id = str(payload.get('run_id') or '')
    assert run_id
    meta = app_backend.RUNS.get(run_id) or {}
    assert meta.get('kind') == 'vuln_test'
    assert meta.get('execute_like_real') is True
    assert meta.get('cleanup_generated_artifacts') is True

    app_backend.RUNS.pop(run_id, None)
