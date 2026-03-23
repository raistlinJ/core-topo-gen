from __future__ import annotations

import json
import os
import shlex
import textwrap
from typing import Any, Callable, Optional, Sequence

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    sanitize_venv_bin_path: Callable[[Any], Optional[str]],
    ensure_paramiko_available: Callable[[], None],
    paramiko_getter: Callable[[], Any],
    python_executable_names: Sequence[str],
) -> None:
    if not begin_route_registration(app, 'core_venv_probe_routes'):
        return

    def _test_core_venv_view():
        payload = request.get_json(silent=True) or {}
        raw_path = payload.get('venv_bin') or payload.get('path') or ''
        sanitized = sanitize_venv_bin_path(raw_path)
        if not sanitized:
            return jsonify({'ok': False, 'error': 'Provide the CORE virtualenv bin path to test.'}), 400
        if not os.path.isabs(sanitized):
            return jsonify({'ok': False, 'error': f'CORE venv bin must be an absolute path: {sanitized}'}), 400
        ssh_host = str(payload.get('ssh_host') or payload.get('host') or '').strip()
        if not ssh_host:
            return jsonify({'ok': False, 'error': 'Provide the SSH host for the CORE VM to test the virtualenv.'}), 400
        try:
            ssh_port = int(payload.get('ssh_port') or 22)
        except Exception:
            return jsonify({'ok': False, 'error': 'SSH port must be an integer.'}), 400
        ssh_username = str(payload.get('ssh_username') or '').strip()
        if not ssh_username:
            return jsonify({'ok': False, 'error': 'Enter the SSH username before testing the CORE virtualenv.'}), 400
        ssh_password_raw = payload.get('ssh_password')
        ssh_password = '' if ssh_password_raw in (None, '') else str(ssh_password_raw)
        if not ssh_password:
            return jsonify({'ok': False, 'error': 'Enter the SSH password before testing the CORE virtualenv.'}), 400
        try:
            ensure_paramiko_available()
        except RuntimeError as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 500
        paramiko_module = paramiko_getter()
        client = paramiko_module.SSHClient()  # type: ignore[assignment]
        client.set_missing_host_key_policy(paramiko_module.AutoAddPolicy())  # type: ignore[attr-defined]
        try:
            client.connect(
                hostname=ssh_host,
                port=ssh_port,
                username=ssh_username,
                password=ssh_password,
                look_for_keys=False,
                allow_agent=False,
                timeout=15.0,
                banner_timeout=15.0,
                auth_timeout=15.0,
            )
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Failed to open SSH session to {ssh_host}:{ssh_port}: {exc}'}), 502
        python_candidates = [os.path.join(sanitized, exe_name) for exe_name in python_executable_names]
        candidate_literal = ' '.join(shlex.quote(path) for path in python_candidates)
        python_probe = textwrap.dedent(
            """
            import json
            import sys

            result = {
                "python": sys.executable,
                "version": sys.version.split()[0],
            }
            try:
                import core  # type: ignore  # noqa: F401
                import core.api.grpc.client  # type: ignore  # noqa: F401
            except Exception as exc:  # pragma: no cover - remote execution
                result["status"] = "error"
                result["error"] = repr(exc)
            else:
                result["status"] = "ok"
            print("::VENVCHECK::" + json.dumps(result))
            if result.get("status") != "ok":
                sys.exit(3)
            """
        ).strip()
        missing_payload = json.dumps({
            'status': 'error',
            'error': f'No python executable found in {sanitized}',
        })
        remote_cmd = textwrap.dedent(
            f"""
            CANDIDATES=({candidate_literal})
            FOUND=0
            for candidate in "${{CANDIDATES[@]}}"; do
                if [ -x "$candidate" ]; then
                    FOUND=1
                    "$candidate" - <<'PY'
{python_probe}
PY
                    exit $?
                fi
            done
            if [ $FOUND -eq 0 ]; then
                echo "::VENVCHECK::{missing_payload}"
                exit 10
            fi
            """
        ).strip()
        try:
            stdin, stdout, stderr = client.exec_command(remote_cmd, timeout=30.0)
            try:
                stdout_data = stdout.read()
                stderr_data = stderr.read()
            finally:
                try:
                    stdin.close()
                except Exception:
                    pass
            exit_code = stdout.channel.recv_exit_status() if hasattr(stdout, 'channel') else 0
        except Exception as exc:
            try:
                client.close()
            except Exception:
                pass
            return jsonify({'ok': False, 'error': f'Failed to probe CORE virtualenv via SSH: {exc}'}), 500
        finally:
            try:
                client.close()
            except Exception:
                pass

        def _decode(data: Any) -> str:
            if isinstance(data, bytes):
                return data.decode('utf-8', 'ignore')
            return str(data or '')

        stdout_text = _decode(stdout_data)
        stderr_text = _decode(stderr_data)
        summary: dict[str, Any] | None = None
        for blob in (stdout_text, stderr_text):
            if not blob:
                continue
            for line in blob.splitlines():
                line = line.strip()
                if not line or not line.startswith('::VENVCHECK::'):
                    continue
                payload_text = line.split('::VENVCHECK::', 1)[-1]
                try:
                    summary = json.loads(payload_text)
                    break
                except Exception:
                    continue
            if summary:
                break
        python_version = summary.get('version') if isinstance(summary, dict) else None
        python_path = summary.get('python') if isinstance(summary, dict) else None
        status = summary.get('status') if isinstance(summary, dict) else None
        error_detail = summary.get('error') if isinstance(summary, dict) else None
        if exit_code == 0 and status == 'ok':
            message = summary.get('message') or f"Python {python_version or ''} imported core.api.grpc successfully.".strip()
            return jsonify({
                'ok': True,
                'message': message,
                'venv_bin': sanitized,
                'python_executable': python_path,
                'python_version': python_version,
                'ssh_host': ssh_host,
                'ssh_port': ssh_port,
                'stdout': stdout_text.strip(),
                'stderr': stderr_text.strip(),
            })
        error_message = error_detail or stderr_text.strip() or stdout_text.strip() or 'core.api.grpc import failed in this environment.'
        return jsonify({
            'ok': False,
            'error': error_message,
            'venv_bin': sanitized,
            'python_executable': python_path,
            'python_version': python_version,
            'ssh_host': ssh_host,
            'ssh_port': ssh_port,
            'stdout': stdout_text.strip(),
            'stderr': stderr_text.strip(),
            'returncode': exit_code,
        }), 400

    app.add_url_rule('/test_core_venv', endpoint='test_core_venv', view_func=_test_core_venv_view, methods=['POST'])
    mark_routes_registered(app, 'core_venv_probe_routes')