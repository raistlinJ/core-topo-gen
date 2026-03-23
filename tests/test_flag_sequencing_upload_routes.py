from io import BytesIO
from types import SimpleNamespace
import os
import re
import uuid

from flask import Flask
from werkzeug.utils import secure_filename

from webapp.routes import flag_sequencing_uploads


def _normalize_scenario_label(value: str) -> str:
    normalized = re.sub(r'[^a-z0-9]+', '-', str(value or '').strip().lower()).strip('-')
    return normalized


def _build_backend(tmp_path):
    outputs_dir = tmp_path / 'outputs'

    def flow_uploads_dir() -> str:
        path = outputs_dir / 'flow_uploads'
        path.mkdir(parents=True, exist_ok=True)
        return str(path)

    def flow_inject_uploads_dir() -> str:
        path = outputs_dir / 'flow_inject_uploads'
        path.mkdir(parents=True, exist_ok=True)
        return str(path)

    return SimpleNamespace(
        _normalize_scenario_label=_normalize_scenario_label,
        _local_timestamp_safe=lambda: '20260319T120000',
        _flow_uploads_dir=flow_uploads_dir,
        _flow_inject_uploads_dir=flow_inject_uploads_dir,
        secure_filename=secure_filename,
        os=os,
        uuid=uuid,
    )


def _make_client(tmp_path):
    app = Flask(__name__)
    app.config['TESTING'] = True
    flag_sequencing_uploads.register(app, backend_module=_build_backend(tmp_path))
    return app.test_client()


def test_upload_flow_input_file_saves_under_scenario_directory(tmp_path):
    client = _make_client(tmp_path)

    resp = client.post(
        '/api/flag-sequencing/upload_flow_input_file',
        data={
            'scenario': 'Demo Scenario',
            'step_index': '3',
            'input_name': '../credential file',
            'generator_id': 'gen-1',
            'file': (BytesIO(b'secret payload'), '../payload.bin'),
        },
        content_type='multipart/form-data',
    )

    assert resp.status_code == 200
    body = resp.get_json()
    assert body['ok'] is True
    assert body['scenario_norm'] == 'demo-scenario'
    assert body['step_index'] == '3'
    assert body['generator_id'] == 'gen-1'
    assert body['input_name'] == '../credential file'
    assert body['stored_filename'] == 'credential_file__payload.bin'
    assert os.path.exists(body['stored_path'])
    with open(body['stored_path'], 'rb') as handle:
        assert handle.read() == b'secret payload'


def test_upload_flow_inject_file_returns_inject_value(tmp_path):
    client = _make_client(tmp_path)

    resp = client.post(
        '/api/flag-sequencing/upload_flow_inject_file',
        data={
            'scenario': 'Demo Scenario',
            'step_index': '7',
            'generator_id': 'gen-2',
            'file': (BytesIO(b'inject payload'), '../artifact.tar.gz'),
        },
        content_type='multipart/form-data',
    )

    assert resp.status_code == 200
    body = resp.get_json()
    assert body['ok'] is True
    assert body['scenario_norm'] == 'demo-scenario'
    assert body['step_index'] == '7'
    assert body['generator_id'] == 'gen-2'
    assert body['stored_filename'] == 'artifact.tar.gz'
    assert body['inject_value'] == f"upload:{body['stored_path']}"
    assert os.path.exists(body['stored_path'])


def test_upload_flow_input_file_requires_scenario(tmp_path):
    client = _make_client(tmp_path)

    resp = client.post(
        '/api/flag-sequencing/upload_flow_input_file',
        data={
            'scenario': '   ',
            'file': (BytesIO(b'data'), 'payload.bin'),
        },
        content_type='multipart/form-data',
    )

    assert resp.status_code == 400
    assert resp.get_json() == {'ok': False, 'error': 'No scenario specified.'}