import json

from webapp import app_backend as backend
from webapp.routes import core_page as core_page_routes


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_core_page_no_scenario_context_renders_empty_state(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(core_page_routes, 'render_template', lambda template, **ctx: json.dumps({'template': template, 'ctx': ctx}))
    monkeypatch.setattr(backend, '_load_run_history', lambda: [])
    monkeypatch.setattr(backend, '_scenario_catalog_for_user', lambda history, user=None: ([], {}, {}))
    monkeypatch.setattr(backend, '_current_core_ui_logs', lambda: [])

    resp = client.get('/core')

    payload = json.loads(resp.get_data(as_text=True))
    assert resp.status_code == 200
    assert payload['template'] == 'core.html'
    assert payload['ctx']['no_scenario_context'] is True
    assert payload['ctx']['sessions'] == []


def test_core_page_filters_sessions_for_selected_scenario(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(core_page_routes, 'render_template', lambda template, **ctx: json.dumps({'template': template, 'ctx': ctx}))
    monkeypatch.setattr(backend, '_load_run_history', lambda: [{'scenario_name': 'Alpha'}])
    monkeypatch.setattr(backend, '_current_user', lambda: {'username': 'coreadmin'})
    monkeypatch.setattr(backend, '_scenario_catalog_for_user', lambda history, user=None: (['Alpha'], {'alpha': set()}, {}))
    monkeypatch.setattr(backend, '_collect_scenario_participant_urls', lambda scenario_paths, scenario_url_hints: {})
    monkeypatch.setattr(backend, '_normalize_scenario_label', lambda value: str(value or '').strip().lower())
    monkeypatch.setattr(backend, '_resolve_scenario_display', lambda scenario_norm, scenario_names, scenario_query: 'Alpha')
    monkeypatch.setattr(backend, '_select_core_config_for_page', lambda *args, **kwargs: {'host': '127.0.0.1', 'port': 50051})
    monkeypatch.setattr(backend, '_ensure_core_vm_metadata', lambda core_cfg: core_cfg)
    monkeypatch.setattr(backend, '_build_core_vm_summary', lambda core_cfg: (False, {}))
    monkeypatch.setattr(backend, '_list_active_core_sessions', lambda *args, **kwargs: [{'id': 1, 'scenario_name': 'Alpha', 'file': '/tmp/alpha.xml'}, {'id': 2, 'scenario_name': 'Beta', 'file': '/tmp/beta.xml'}])
    monkeypatch.setattr(backend, '_scan_core_xmls', lambda: [{'path': '/tmp/alpha.xml'}, {'path': '/tmp/beta.xml'}])
    monkeypatch.setattr(backend, '_load_core_sessions_store', lambda: {})
    monkeypatch.setattr(backend, '_migrate_core_sessions_store_with_core_targets', lambda mapping, history: mapping)
    monkeypatch.setattr(backend, '_filter_core_sessions_store_for_core', lambda mapping, host, port: mapping)
    monkeypatch.setattr(backend, '_build_session_scenario_labels', lambda mapping, scenario_names, scenario_paths: {})
    monkeypatch.setattr(backend, '_session_ids_for_scenario', lambda mapping, scenario_norm, scenario_paths: set())
    monkeypatch.setattr(backend, '_annotate_sessions_with_scenarios', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_filter_sessions_by_scenario', lambda sessions, scenario_norm, scenario_paths, scenario_session_ids: ([sessions[0]], True))
    monkeypatch.setattr(backend, '_filter_xmls_by_scenario', lambda xmls, scenario_norm, scenario_paths, mapping: ([xmls[0]], True))
    monkeypatch.setattr(backend, '_read_remote_session_scenario_meta_bulk', lambda *args, **kwargs: {})
    monkeypatch.setattr(backend, '_session_store_updated_at_for_session_id', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_scenario_timestamped_filename', lambda scenario_name, ts_epoch: f'{scenario_name}.xml')
    monkeypatch.setattr(backend, '_attach_hitl_metadata_to_sessions', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_attach_participant_urls_to_sessions', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_current_core_ui_logs', lambda: [])

    resp = client.get('/core?scenario=Alpha')

    payload = json.loads(resp.get_data(as_text=True))
    assert resp.status_code == 200
    assert payload['ctx']['active_scenario'] == 'Alpha'
    assert [session['id'] for session in payload['ctx']['sessions']] == [1]
    assert [xml['path'] for xml in payload['ctx']['xmls']] == ['/tmp/alpha.xml']