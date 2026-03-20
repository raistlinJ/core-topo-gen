from pathlib import Path

from flask import Flask

from webapp.routes import plan_preview_pages


def _backend_for_pages(tmp_path: Path):
    plans_dir = tmp_path / 'plans'
    plans_dir.mkdir(parents=True, exist_ok=True)
    return type(
        'BackendModule',
        (),
        {
            '_outputs_dir': staticmethod(lambda: str(tmp_path)),
        },
    )()


def test_full_preview_from_plan_redirects_when_missing_input(tmp_path):
    app = Flask(__name__)
    app.secret_key = 'test'
    app.add_url_rule('/', endpoint='index', view_func=lambda: 'ok')
    plan_preview_pages.register(app, backend_module=_backend_for_pages(tmp_path))

    client = app.test_client()
    resp = client.post('/plan/full_preview_from_plan', data={}, follow_redirects=False)

    assert resp.status_code in (302, 303)
    assert resp.headers['Location'].endswith('/')


def test_full_preview_from_plan_redirects_with_notice_for_valid_plan(tmp_path):
    app = Flask(__name__)
    app.secret_key = 'test'
    app.add_url_rule('/', endpoint='index', view_func=lambda: 'ok')
    backend = _backend_for_pages(tmp_path)
    plan_preview_pages.register(app, backend_module=backend)

    plan_path = tmp_path / 'plans' / 'preview.json'
    plan_path.write_text('{}', encoding='utf-8')

    client = app.test_client()
    resp = client.post('/plan/full_preview_from_plan', data={'preview_plan': str(plan_path)}, follow_redirects=False)

    assert resp.status_code in (302, 303)
    assert resp.headers['Location'].endswith('/')