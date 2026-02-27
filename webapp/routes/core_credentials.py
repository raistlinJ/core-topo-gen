from __future__ import annotations

from typing import Any, Callable, Optional

from flask import jsonify, request


def register(
    app,
    *,
    current_user_getter: Callable[[], dict[str, Any] | None],
    normalize_role_value: Callable[[Any], str],
    delete_core_credentials: Callable[[str], bool],
    load_core_credentials: Callable[[str], Optional[dict[str, Any]]],
    clear_hitl_validation_in_scenario_catalog: Callable[..., Any],
    default_core_venv_bin: str,
    logger=None,
) -> None:
    """Register CORE credential utility endpoints.

    Extracted from `webapp.app_backend` to reduce file size.
    """

    def _require_admin():
        current = current_user_getter()
        if not current or normalize_role_value(current.get('role')) != 'admin':
            return None, (jsonify({'success': False, 'error': 'Admin privileges required'}), 403)
        return current, None

    def _clear_view():
        _user, auth_resp = _require_admin()
        if auth_resp is not None:
            return auth_resp

        payload = request.get_json(silent=True) or {}
        secret_id_raw = payload.get('core_secret_id') or payload.get('secret_id')
        secret_id = secret_id_raw.strip() if isinstance(secret_id_raw, str) else ''
        scenario_index = payload.get('scenario_index')
        scenario_name = str(payload.get('scenario_name') or '').strip()
        removed = False
        try:
            if secret_id:
                removed = delete_core_credentials(secret_id)
        except Exception:
            try:
                if logger is not None:
                    logger.exception(
                        '[core] failed to clear credentials for %s (scenario %s)',
                        secret_id or 'unknown',
                        scenario_name or scenario_index,
                    )
            except Exception:
                pass
            return jsonify({'success': False, 'error': 'Failed to clear stored CORE credentials'}), 500

        try:
            if logger is not None:
                logger.info(
                    '[core] cleared credentials request for %s (scenario_index=%s, removed=%s)',
                    scenario_name or 'unnamed',
                    scenario_index,
                    removed,
                )
        except Exception:
            pass

        try:
            if scenario_name:
                clear_hitl_validation_in_scenario_catalog(scenario_name, core=True)
        except Exception:
            pass

        return jsonify({
            'success': True,
            'secret_removed': removed,
            'scenario_index': scenario_index,
            'scenario_name': scenario_name,
        })

    def _get_view():
        _user, auth_resp = _require_admin()
        if auth_resp is not None:
            return auth_resp

        payload = request.get_json(silent=True) or {}
        secret_id_raw = payload.get('core_secret_id') or payload.get('secret_id')
        secret_id = secret_id_raw.strip() if isinstance(secret_id_raw, str) else ''
        if not secret_id:
            return jsonify({'success': False, 'error': 'core_secret_id is required'}), 400
        try:
            record = load_core_credentials(secret_id)
        except RuntimeError as exc:
            return jsonify({'success': False, 'error': str(exc)}), 500
        if not record:
            return jsonify({'success': False, 'error': 'Stored credentials not found'}), 404

        credentials = {
            'identifier': record.get('identifier') or secret_id,
            'scenario_name': record.get('scenario_name') or '',
            'scenario_index': record.get('scenario_index'),
            'host': record.get('host') or record.get('grpc_host') or '',
            'port': int(record.get('port') or record.get('grpc_port') or 50051),
            'grpc_host': record.get('grpc_host') or record.get('host') or '',
            'grpc_port': int(record.get('grpc_port') or record.get('port') or 50051),
            'ssh_host': record.get('ssh_host') or '',
            'ssh_port': int(record.get('ssh_port') or 22),
            'ssh_username': record.get('ssh_username') or '',
            'ssh_password': record.get('ssh_password_plain') or '',
            'ssh_enabled': bool(record.get('ssh_enabled', True)),
            'venv_bin': record.get('venv_bin') or default_core_venv_bin,
            'vm_key': record.get('vm_key') or '',
            'vm_name': record.get('vm_name') or '',
            'vm_node': record.get('vm_node') or '',
            'vmid': record.get('vmid'),
            'proxmox_secret_id': record.get('proxmox_secret_id'),
            'proxmox_target': record.get('proxmox_target'),
            'stored_at': record.get('stored_at'),
        }
        return jsonify({'success': True, 'credentials': credentials})

    app.add_url_rule(
        '/api/core/credentials/clear',
        endpoint='api_core_credentials_clear',
        view_func=_clear_view,
        methods=['POST'],
    )
    app.add_url_rule(
        '/api/core/credentials/get',
        endpoint='api_core_credentials_get',
        view_func=_get_view,
        methods=['POST'],
    )
