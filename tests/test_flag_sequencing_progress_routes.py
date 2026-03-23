from pathlib import Path

from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (200, 302)


def test_api_flow_progress_filters_relevant_lines(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    logs_dir = tmp_path / 'logs'
    logs_dir.mkdir(parents=True)
    log_path = logs_dir / 'webui-9090.log'
    log_path.write_text(
        '\n'.join(
            [
                'ordinary line',
                '[flow.progress] started',
                'Repo upload completed',
                '[remote-sync] copied artifact',
                '[flow.phase] running',
            ]
        ),
        encoding='utf-8',
    )

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(tmp_path))

    resp = client.get('/api/flag-sequencing/flow_progress')

    assert resp.status_code == 200
    assert resp.get_json() == {
        'ok': True,
        'lines': [
            '[flow.progress] started',
            'Repo upload completed',
            '[remote-sync] copied artifact',
            '[flow.phase] running',
        ],
    }