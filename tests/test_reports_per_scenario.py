import json
import os

from webapp.app_backend import app


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_reports_data_is_single_scenario(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    def fake_outputs_dir():
        return str(outdir)

    monkeypatch.setattr(backend, '_outputs_dir', fake_outputs_dir)

    # Legacy-ish entry: scenario_names contains multiple names but scenario_name is the active one.
    # NOTE: backend.RUN_HISTORY_PATH is computed at import time, so patch it too.
    run_history_path = outdir / 'run_history.json'
    monkeypatch.setattr(backend, 'RUN_HISTORY_PATH', str(run_history_path))
    run_history_path.write_text(
        json.dumps([
            {
                'timestamp': '2025-12-26T00:00:00Z',
                'mode': 'async',
                'scenario_name': 'Alpha',
                'scenario_names': ['Alpha', 'Beta'],
                'xml_path': str(tmp_path / 'outputs' / 'scenarios.xml'),
                'returncode': 0,
            }
        ]),
        encoding='utf-8',
    )

    resp = client.get('/reports_data')
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'history' in data
    assert len(data['history']) == 1
    entry = data['history'][0]
    assert entry.get('scenario_names') == ['Alpha']
