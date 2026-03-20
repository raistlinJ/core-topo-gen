from __future__ import annotations

from typing import Any, Callable

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    merge_core_configs: Callable[..., dict[str, Any]],
    require_core_ssh_credentials: Callable[[dict[str, Any]], dict[str, Any]],
    open_ssh_client: Callable[[dict[str, Any]], Any],
    remote_static_repo_dir: Callable[[Any], str],
    remote_path_join: Callable[..., str],
    remote_repo_missing_error_type: type[Exception],
) -> None:
    if not begin_route_registration(app, 'core_remote_repo_routes'):
        return

    def _check_remote_repo_view():
        payload = request.get_json(silent=True) or {}
        core_cfg = payload.get('core')
        if not isinstance(core_cfg, dict):
            try:
                core_json = payload.get('core_json')
                if core_json:
                    import json
                    core_cfg = json.loads(core_json)
            except Exception:
                core_cfg = None
        if not isinstance(core_cfg, dict):
            return jsonify({'error': 'core config missing'}), 400
        try:
            core_cfg = merge_core_configs(core_cfg, include_password=True)
            core_cfg = require_core_ssh_credentials(core_cfg)
        except Exception as exc:
            return jsonify({'error': str(exc)}), 400

        client = None
        sftp = None
        try:
            client = open_ssh_client(core_cfg)
            sftp = client.open_sftp()
            repo_dir = remote_static_repo_dir(sftp)
            try:
                sftp.stat(repo_dir)
            except Exception as exc:
                raise remote_repo_missing_error_type(repo_dir) from exc
            package_dir = remote_path_join(repo_dir, 'core_topo_gen')
            package_init = remote_path_join(package_dir, '__init__.py')
            try:
                sftp.stat(package_dir)
                sftp.stat(package_init)
            except Exception as exc:
                raise remote_repo_missing_error_type(repo_dir) from exc
            return jsonify({'ok': True, 'repo_path': repo_dir})
        except remote_repo_missing_error_type as exc:
            return jsonify({'error': str(exc), 'missing_repo': exc.repo_path, 'can_push_repo': True}), 404
        except Exception as exc:
            return jsonify({'error': str(exc)}), 500
        finally:
            try:
                if sftp:
                    sftp.close()
            except Exception:
                pass
            try:
                if client:
                    client.close()
            except Exception:
                pass

    app.add_url_rule('/core/check_remote_repo', endpoint='check_remote_repo', view_func=_check_remote_repo_view, methods=['POST'])
    mark_routes_registered(app, 'core_remote_repo_routes')