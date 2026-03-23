from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

from webapp.app_backend import app


def _login(client) -> None:
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_run_cli_sync_renders_success_without_preview_plan_form(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text(
        '<Scenarios><Scenario name="Scenario A"><ScenarioEditor/></Scenario></Scenarios>',
        encoding='utf-8',
    )

    monkeypatch.setattr(backend, '_current_user', lambda: {'username': 'coreadmin', 'role': 'admin'})
    monkeypatch.setattr(
        backend,
        '_parse_scenarios_xml',
        lambda path: {'scenarios': [{'name': 'Scenario A'}], 'core': {}},
    )
    monkeypatch.setattr(backend, '_coerce_bool', lambda value: False)
    monkeypatch.setattr(backend, '_webui_running_in_docker', lambda: False)
    monkeypatch.setattr(backend, '_scrub_scenario_core_config', lambda cfg: cfg)
    monkeypatch.setattr(
        backend,
        '_merge_core_configs',
        lambda *parts, include_password=True: {'host': '127.0.0.1', 'port': 50051, 'ssh_enabled': False},
    )
    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    monkeypatch.setattr(backend, '_sanitize_venv_bin_path', lambda value: '')
    monkeypatch.setattr(backend, '_venv_is_explicit', lambda cfg, preferred: False)
    monkeypatch.setattr(backend, '_resolve_cli_venv_bin', lambda preferred, allow_fallback=True: '')
    monkeypatch.setattr(backend, '_grpc_save_current_session_xml_with_config', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path))
    monkeypatch.setattr(backend, '_select_python_interpreter', lambda cli_venv_bin=None: 'python')
    monkeypatch.setattr(backend, '_prepare_cli_env', lambda preferred_venv_bin=None: {})
    monkeypatch.setattr(backend, '_scenario_names_from_xml', lambda path: ['Scenario A'])
    monkeypatch.setattr(backend, '_safe_name', lambda value: 'scenario-a')

    @contextmanager
    def _fake_core_connection(core_cfg):
        yield ('127.0.0.1', 50051)

    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend, '_read_flow_state_from_xml_path', lambda path, scenario=None: {})
    monkeypatch.setattr(backend, '_update_flow_state_in_xml', lambda path, scenario, flow_state: None)
    monkeypatch.setattr(
        backend.subprocess,
        'run',
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout='cli ok', stderr=''),
    )
    monkeypatch.setattr(backend, '_load_preview_payload_from_path', lambda path, scenario=None: {'full_preview': {'role_counts': {'Docker': 0}}})
    monkeypatch.setattr(backend, '_sync_local_vulns_to_remote', lambda *args, **kwargs: False)
    monkeypatch.setattr(backend, '_run_remote_python_json', lambda *args, **kwargs: {'items': []})
    monkeypatch.setattr(backend, '_remote_copy_flow_artifacts_into_containers_script', lambda password=None: 'noop')
    monkeypatch.setattr(backend, '_extract_report_path_from_text', lambda text: None)
    monkeypatch.setattr(backend, '_find_latest_report_path', lambda: None)
    monkeypatch.setattr(backend, '_extract_summary_path_from_text', lambda text: None)
    monkeypatch.setattr(backend, '_derive_summary_from_report', lambda report_path: None)
    monkeypatch.setattr(backend, '_find_latest_summary_path', lambda: None)
    monkeypatch.setattr(backend, '_extract_validation_summary_from_text', lambda text: None)
    monkeypatch.setattr(backend, '_persist_execute_validation_artifacts', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_extract_session_id_from_text', lambda text: None)
    monkeypatch.setattr(backend, '_record_session_mapping', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_write_remote_session_scenario_meta', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_append_session_scenario_discrepancies', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_default_core_dict', lambda: {})
    monkeypatch.setattr(backend, '_normalize_core_config', lambda cfg, include_password=False: dict(cfg or {}))
    monkeypatch.setattr(backend, '_attach_base_upload', lambda payload: None)
    monkeypatch.setattr(backend, '_prepare_payload_for_index', lambda payload, user=None: payload)
    monkeypatch.setattr(backend, '_write_single_scenario_xml', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_build_full_scenario_archive', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_local_timestamp_display', lambda: '2026-03-19 00:00:00')
    monkeypatch.setattr(backend, '_append_run_history', lambda entry: None)
    monkeypatch.setattr(
        backend,
        'render_template',
        lambda template, **kwargs: backend.jsonify(
            {
                'template': template,
                'run_success': kwargs.get('run_success'),
                'result_path': (kwargs.get('payload') or {}).get('result_path'),
            }
        ),
    )

    resp = client.post('/run_cli', data={'xml_path': str(xml_path), 'scenario': 'Scenario A'})

    assert resp.status_code == 200
    assert resp.get_json() == {
        'template': 'index.html',
        'run_success': True,
        'result_path': str(xml_path),
    }


def test_run_cli_sync_uses_saved_page_core_cfg_when_xml_lacks_password(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text(
        '<Scenarios><Scenario name="Scenario A"><ScenarioEditor/></Scenario></Scenarios>',
        encoding='utf-8',
    )

    monkeypatch.setattr(backend, '_current_user', lambda: {'username': 'coreadmin', 'role': 'admin'})
    monkeypatch.setattr(
        backend,
        '_parse_scenarios_xml',
        lambda path: {
            'scenarios': [
                {
                    'name': 'Scenario A',
                    'hitl': {
                        'core': {
                            'host': 'localhost',
                            'port': 50051,
                            'ssh_enabled': True,
                            'ssh_host': '',
                            'ssh_username': 'core',
                            'ssh_password': '',
                        }
                    },
                }
            ],
            'core': {},
        },
    )
    monkeypatch.setattr(backend, '_coerce_bool', lambda value: False)
    monkeypatch.setattr(backend, '_webui_running_in_docker', lambda: False)
    monkeypatch.setattr(backend, '_scrub_scenario_core_config', lambda cfg: cfg)
    monkeypatch.setattr(
        backend,
        '_merge_core_configs',
        lambda *parts, include_password=True: {
            key: value
            for part in parts
            if isinstance(part, dict)
            for key, value in part.items()
        },
    )
    monkeypatch.setattr(backend, '_load_run_history', lambda: [])
    monkeypatch.setattr(backend, '_normalize_scenario_label', lambda value: str(value or '').strip().lower())
    monkeypatch.setattr(
        backend,
        '_select_core_config_for_page',
        lambda scenario_norm, history, include_password=True: {
            'host': '10.0.0.8',
            'port': 50051,
            'ssh_enabled': True,
            'validated': True,
            'ssh_host': '10.0.0.8',
            'ssh_username': 'core',
            'ssh_password': 'saved-secret',
            'core_secret_id': 'core-secret-1',
        },
    )
    observed = {}

    def _capture_core_cfg(cfg):
        observed['host'] = cfg.get('host')
        observed['port'] = cfg.get('port')
        observed['ssh_host'] = cfg.get('ssh_host')
        observed['ssh_password'] = cfg.get('ssh_password')
        return cfg

    monkeypatch.setattr(backend, '_require_core_ssh_credentials', _capture_core_cfg)
    monkeypatch.setattr(backend, '_sanitize_venv_bin_path', lambda value: '')
    monkeypatch.setattr(backend, '_venv_is_explicit', lambda cfg, preferred: False)
    monkeypatch.setattr(backend, '_resolve_cli_venv_bin', lambda preferred, allow_fallback=True: '')
    monkeypatch.setattr(backend, '_grpc_save_current_session_xml_with_config', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path))
    monkeypatch.setattr(backend, '_select_python_interpreter', lambda cli_venv_bin=None: 'python')
    monkeypatch.setattr(backend, '_prepare_cli_env', lambda preferred_venv_bin=None: {})
    monkeypatch.setattr(backend, '_scenario_names_from_xml', lambda path: ['Scenario A'])
    monkeypatch.setattr(backend, '_safe_name', lambda value: 'scenario-a')

    @contextmanager
    def _fake_core_connection(core_cfg):
        yield ('127.0.0.1', 50051)

    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend, '_read_flow_state_from_xml_path', lambda path, scenario=None: {})
    monkeypatch.setattr(backend, '_update_flow_state_in_xml', lambda path, scenario, flow_state: None)
    monkeypatch.setattr(
        backend.subprocess,
        'run',
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout='cli ok', stderr=''),
    )
    monkeypatch.setattr(backend, '_load_preview_payload_from_path', lambda path, scenario=None: {'full_preview': {'role_counts': {'Docker': 0}}})
    monkeypatch.setattr(backend, '_sync_local_vulns_to_remote', lambda *args, **kwargs: False)
    monkeypatch.setattr(backend, '_run_remote_python_json', lambda *args, **kwargs: {'items': []})
    monkeypatch.setattr(backend, '_remote_copy_flow_artifacts_into_containers_script', lambda password=None: 'noop')
    monkeypatch.setattr(backend, '_extract_report_path_from_text', lambda text: None)
    monkeypatch.setattr(backend, '_find_latest_report_path', lambda: None)
    monkeypatch.setattr(backend, '_extract_summary_path_from_text', lambda text: None)
    monkeypatch.setattr(backend, '_derive_summary_from_report', lambda report_path: None)
    monkeypatch.setattr(backend, '_find_latest_summary_path', lambda: None)
    monkeypatch.setattr(backend, '_extract_validation_summary_from_text', lambda text: None)
    monkeypatch.setattr(backend, '_persist_execute_validation_artifacts', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_extract_session_id_from_text', lambda text: None)
    monkeypatch.setattr(backend, '_record_session_mapping', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_write_remote_session_scenario_meta', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_append_session_scenario_discrepancies', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_default_core_dict', lambda: {})
    monkeypatch.setattr(backend, '_normalize_core_config', lambda cfg, include_password=False: dict(cfg or {}))
    monkeypatch.setattr(backend, '_attach_base_upload', lambda payload: None)
    monkeypatch.setattr(backend, '_prepare_payload_for_index', lambda payload, user=None: payload)
    monkeypatch.setattr(backend, '_write_single_scenario_xml', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_build_full_scenario_archive', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_local_timestamp_display', lambda: '2026-03-19 00:00:00')
    monkeypatch.setattr(backend, '_append_run_history', lambda entry: None)
    monkeypatch.setattr(
        backend,
        'render_template',
        lambda template, **kwargs: backend.jsonify(
            {
                'template': template,
                'run_success': kwargs.get('run_success'),
                'result_path': (kwargs.get('payload') or {}).get('result_path'),
            }
        ),
    )

    resp = client.post('/run_cli', data={'xml_path': str(xml_path), 'scenario': 'Scenario A'})

    assert resp.status_code == 200
    assert resp.get_json() == {
        'template': 'index.html',
        'run_success': True,
        'result_path': str(xml_path),
    }
    assert observed == {
        'host': 'localhost',
        'port': 50051,
        'ssh_host': '10.0.0.8',
        'ssh_password': 'saved-secret',
    }