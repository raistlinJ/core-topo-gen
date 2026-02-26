from __future__ import annotations

import json
import os
from typing import Any, Callable, Optional

from flask import jsonify, request


def register(
    app,
    *,
    current_user_getter: Callable[[], dict[str, Any] | None],
    outputs_dir: Callable[[], str],
    save_core_credentials: Callable[[dict[str, Any]], dict[str, Any]],
    load_core_credentials: Callable[[str], Optional[dict[str, Any]]],
    core_port: int,
    default_core_venv_bin: str,
    logger=None,
) -> None:
    """Register flag-generator test CORE SSH credential persistence routes.

    These routes back the "Save Credentials" toggle in the flag generator test modal.
    They intentionally store only a pointer file under outputs/ and keep the password
    encrypted via the existing CORE secret store.
    """

    def _hint_path() -> str:
        return os.path.join(outputs_dir(), 'flag_generators_test_core_hint.json')

    def _load_hint() -> dict[str, Any]:
        path = _hint_path()
        try:
            if not os.path.exists(path):
                return {}
            with open(path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_hint(hint: dict[str, Any]) -> None:
        path = _hint_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(hint or {}, fh, indent=2)
        os.replace(tmp, path)

    def _require_auth():
        current = current_user_getter()
        if not current or not current.get('username'):
            return None, (jsonify({'ok': False, 'error': 'Authentication required'}), 401)
        return current, None

    def _save_view():
        _user, auth_resp = _require_auth()
        if auth_resp is not None:
            return auth_resp

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or not payload:
            try:
                payload = request.form.to_dict(flat=True) if request.form else {}
            except Exception:
                payload = {}

        ssh_host = str(payload.get('ssh_host') or payload.get('host') or '').strip()
        ssh_username = str(payload.get('ssh_username') or payload.get('username') or '').strip()
        ssh_password_raw = payload.get('ssh_password') or payload.get('password') or ''
        ssh_password = str(ssh_password_raw) if not isinstance(ssh_password_raw, str) else ssh_password_raw
        try:
            ssh_port = int(payload.get('ssh_port') or 22)
        except Exception:
            ssh_port = 22

        if not ssh_host:
            return jsonify({'ok': False, 'error': 'ssh_host is required'}), 400
        if not ssh_username:
            return jsonify({'ok': False, 'error': 'ssh_username is required'}), 400
        if not ssh_password:
            return jsonify({'ok': False, 'error': 'ssh_password is required'}), 400

        grpc_host = str(payload.get('grpc_host') or payload.get('host') or ssh_host).strip()
        try:
            grpc_port = int(payload.get('grpc_port') or payload.get('port') or core_port)
        except Exception:
            grpc_port = core_port

        secret_payload = {
            'scenario_name': 'flag-generators-test',
            'scenario_index': None,
            'grpc_host': grpc_host,
            'grpc_port': grpc_port,
            'ssh_host': ssh_host,
            'ssh_port': ssh_port,
            'ssh_username': ssh_username,
            'ssh_password': ssh_password,
            'ssh_enabled': True,
            'venv_bin': default_core_venv_bin,
        }
        try:
            stored_meta = save_core_credentials(secret_payload)
        except Exception as exc:
            try:
                if logger is not None:
                    logger.exception('[flaggen_test] failed to persist CORE creds: %s', exc)
            except Exception:
                pass
            return jsonify({'ok': False, 'error': 'Failed to store credentials'}), 500

        try:
            _save_hint({
                'core_secret_id': stored_meta.get('identifier'),
                'stored_at': stored_meta.get('stored_at'),
                'ssh_host': stored_meta.get('ssh_host'),
                'ssh_port': stored_meta.get('ssh_port'),
                'ssh_username': stored_meta.get('ssh_username'),
            })
        except Exception:
            pass

        return jsonify({'ok': True, 'core_secret_id': stored_meta.get('identifier'), 'summary': stored_meta})

    def _get_view():
        _user, auth_resp = _require_auth()
        if auth_resp is not None:
            return auth_resp

        hint = _load_hint()
        secret_id = str(hint.get('core_secret_id') or '').strip()
        if not secret_id:
            return jsonify({'ok': True, 'credentials': None})

        record = load_core_credentials(secret_id)
        if not record:
            return jsonify({'ok': True, 'credentials': None})

        creds = {
            'ssh_host': record.get('ssh_host') or '',
            'ssh_port': int(record.get('ssh_port') or 22),
            'ssh_username': record.get('ssh_username') or '',
            'ssh_password': record.get('ssh_password_plain') or record.get('password_plain') or '',
            'grpc_host': record.get('grpc_host') or record.get('host') or '',
            'grpc_port': int(record.get('grpc_port') or record.get('port') or core_port),
            'core_secret_id': record.get('identifier') or secret_id,
            'stored_at': record.get('stored_at'),
        }
        return jsonify({'ok': True, 'credentials': creds})

    app.add_url_rule(
        '/api/flag_generators_test/core_credentials/save',
        endpoint='api_flag_generators_test_core_credentials_save',
        view_func=_save_view,
        methods=['POST'],
    )
    app.add_url_rule(
        '/api/flag_generators_test/core_credentials/get',
        endpoint='api_flag_generators_test_core_credentials_get',
        view_func=_get_view,
        methods=['POST'],
    )
