from __future__ import annotations

import time
from typing import Any, Callable, Optional

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    core_config_for_request: Callable[..., dict[str, Any]],
    list_active_core_sessions: Callable[..., list[dict]],
    execute_remote_core_session_action: Callable[..., None],
    ensure_paramiko_available: Callable[[], None],
    paramiko_getter: Callable[[], Any],
    collect_remote_core_daemon_pids: Callable[[Any], list[int]],
    stop_remote_core_daemon_conflict: Callable[..., None],
    core_host_default: str,
    core_port_default: int,
) -> None:
    if not begin_route_registration(app, 'core_execute_support_routes'):
        return

    def _core_kill_active_sessions_api_view():
        payload = request.get_json(silent=True) or {}
        kill_all = bool(payload.get('kill_all'))
        session_ids_raw = payload.get('session_ids')

        core_cfg = core_config_for_request(include_password=True)
        core_host = core_cfg.get('host', core_host_default)
        try:
            core_port = int(core_cfg.get('port', core_port_default))
        except Exception:
            core_port = core_port_default

        session_ids: list[int] = []
        if not kill_all and isinstance(session_ids_raw, list):
            for item in session_ids_raw:
                try:
                    session_ids.append(int(str(item).strip()))
                except Exception:
                    continue

        if kill_all or not session_ids:
            try:
                sessions = list_active_core_sessions(core_host, int(core_port), core_cfg, errors=[], meta={})
            except Exception:
                sessions = []
            for entry in sessions:
                sid = entry.get('id')
                if sid in (None, ''):
                    continue
                try:
                    session_ids.append(int(str(sid).strip()))
                except Exception:
                    continue

        seen: set[int] = set()
        ordered_ids: list[int] = []
        for sid in session_ids:
            if sid in seen:
                continue
            seen.add(sid)
            ordered_ids.append(sid)

        deleted: list[int] = []
        errors: list[str] = []
        for sid in ordered_ids:
            try:
                execute_remote_core_session_action(core_cfg, 'delete', sid, logger=app.logger)
                deleted.append(sid)
            except Exception as exc:
                errors.append(f'Failed deleting session {sid}: {exc}')

        return jsonify({
            'ok': not errors,
            'deleted': deleted,
            'errors': errors,
            'core_host': core_host,
            'core_port': core_port,
        }), 200

    def _core_stop_duplicate_daemons_api_view():
        payload = request.get_json(silent=True) or {}
        pids_raw = payload.get('pids')
        requested_pids: list[int] = []
        if isinstance(pids_raw, list):
            for item in pids_raw:
                try:
                    requested_pids.append(int(str(item).strip()))
                except Exception:
                    continue

        core_cfg = core_config_for_request(include_password=True)
        ssh_password = core_cfg.get('ssh_password')
        if not ssh_password:
            return jsonify({
                'ok': False,
                'error': 'Stopping core-daemon requires sudo; provide an SSH password.',
                'can_stop_daemons': False,
            }), 400
        paramiko_module = paramiko_getter()
        if paramiko_module is None:
            return jsonify({'ok': False, 'error': 'Paramiko unavailable; cannot SSH to CORE VM.'}), 500
        ensure_paramiko_available()

        ssh_client = paramiko_module.SSHClient()  # type: ignore[assignment]
        ssh_client.set_missing_host_key_policy(paramiko_module.AutoAddPolicy())  # type: ignore[attr-defined]
        try:
            ssh_client.connect(
                hostname=str(core_cfg.get('ssh_host') or core_cfg.get('host') or 'localhost'),
                port=int(core_cfg.get('ssh_port') or 22),
                username=str(core_cfg.get('ssh_username') or ''),
                password=ssh_password,
                look_for_keys=False,
                allow_agent=False,
                timeout=10.0,
                banner_timeout=10.0,
                auth_timeout=10.0,
            )
            before = collect_remote_core_daemon_pids(ssh_client)
            target = requested_pids or before
            stop_remote_core_daemon_conflict(
                ssh_client,
                sudo_password=ssh_password,
                pids=target,
                logger=app.logger,
            )
            try:
                time.sleep(1.0)
            except Exception:
                pass
            after = collect_remote_core_daemon_pids(ssh_client)
            return jsonify({'ok': True, 'daemon_pids_before': before, 'daemon_pids_after': after}), 200
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 500
        finally:
            try:
                ssh_client.close()
            except Exception:
                pass

    app.add_url_rule('/core/kill_active_sessions_api', endpoint='core_kill_active_sessions_api', view_func=_core_kill_active_sessions_api_view, methods=['POST'])
    app.add_url_rule('/core/stop_duplicate_daemons_api', endpoint='core_stop_duplicate_daemons_api', view_func=_core_stop_duplicate_daemons_api_view, methods=['POST'])
    mark_routes_registered(app, 'core_execute_support_routes')