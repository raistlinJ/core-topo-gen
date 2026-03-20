from __future__ import annotations

from typing import Any

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'core_test_prepare_routes'):
        return

    backend = backend_module

    @app.route('/api/test/core_sessions/prepare', methods=['POST'])
    def api_test_core_sessions_prepare():
        backend._require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        cleanup = bool(payload.get('cleanup'))

        try:
            core_payload = payload.get('core') if isinstance(payload, dict) else None
            if not isinstance(core_payload, dict):
                return jsonify({'ok': False, 'error': 'CORE VM SSH config required: missing core payload'}), 400
            core_cfg = backend._merge_core_configs(core_payload, include_password=True)
            if not core_cfg.get('host'):
                core_cfg['host'] = core_cfg.get('ssh_host') or '127.0.0.1'
            if not core_cfg.get('port'):
                core_cfg['port'] = backend.CORE_PORT
            core_cfg = backend._require_core_ssh_credentials(core_cfg)
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'CORE VM SSH config required: {exc}'}), 400

        host = str(core_cfg.get('host') or '127.0.0.1')
        try:
            port = int(core_cfg.get('port') or backend.CORE_PORT)
        except Exception:
            port = backend.CORE_PORT

        errors: list[str] = []
        try:
            sessions = backend._list_active_core_sessions(host, port, core_cfg, errors=errors, meta={})
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Unable to verify CORE sessions: {exc}'}), 409
        if errors:
            return jsonify({'ok': False, 'error': f'Unable to verify CORE sessions: {errors[0]}'}), 409

        session_ids: list[int] = []
        for entry in sessions or []:
            sid = entry.get('id') if isinstance(entry, dict) else None
            if sid in (None, ''):
                continue
            try:
                session_ids.append(int(str(sid).strip()))
            except Exception:
                continue
        session_ids = list(dict.fromkeys(session_ids))

        if not session_ids:
            return jsonify({'ok': True, 'active': False, 'session_count': 0, 'session_ids': [], 'cleaned': False}), 200

        if not cleanup:
            return jsonify(
                {
                    'ok': True,
                    'active': True,
                    'session_count': len(session_ids),
                    'session_ids': session_ids,
                    'cleaned': False,
                }
            ), 200

        stopped: list[int] = []
        deleted: list[int] = []
        action_errors: list[str] = []
        for sid in session_ids:
            try:
                backend._execute_remote_core_session_action(core_cfg, 'stop', sid, logger=app.logger)
                stopped.append(sid)
            except Exception:
                pass
            try:
                backend._execute_remote_core_session_action(core_cfg, 'delete', sid, logger=app.logger)
                deleted.append(sid)
            except Exception as exc:
                action_errors.append(f'Failed cleaning session {sid}: {exc}')

        cleanup_notes: list[str] = []
        cleanup_containers = 0
        cleanup_images = 0
        try:
            status_payload = backend._run_remote_python_json(
                core_cfg,
                backend._remote_docker_status_script(core_cfg.get('ssh_password')),
                logger=app.logger,
                label='docker.status(test prepare cleanup)',
                timeout=60.0,
            )
            names: list[str] = []
            if isinstance(status_payload, dict) and isinstance(status_payload.get('items'), list):
                for item in status_payload.get('items') or []:
                    if isinstance(item, dict) and item.get('name'):
                        names.append(str(item.get('name')))
            if names:
                docker_cleanup_payload = backend._run_remote_python_json(
                    core_cfg,
                    backend._remote_docker_cleanup_script(names, core_cfg.get('ssh_password')),
                    logger=app.logger,
                    label='docker.cleanup(test prepare cleanup)',
                    timeout=120.0,
                )
                if isinstance(docker_cleanup_payload, dict) and isinstance(docker_cleanup_payload.get('results'), list):
                    cleanup_containers = len(docker_cleanup_payload.get('results') or [])
            else:
                cleanup_notes.append('no docker-compose node containers to cleanup')
        except Exception as exc:
            cleanup_notes.append(f'container cleanup skipped/failed: {exc}')

        try:
            image_cleanup_payload = backend._run_remote_python_json(
                core_cfg,
                backend._remote_docker_remove_wrapper_images_script(core_cfg.get('ssh_password')),
                logger=app.logger,
                label='docker.wrapper_images.cleanup(test prepare cleanup)',
                timeout=180.0,
            )
            if isinstance(image_cleanup_payload, dict) and isinstance(image_cleanup_payload.get('removed'), list):
                cleanup_images = len(image_cleanup_payload.get('removed') or [])
        except Exception as exc:
            cleanup_notes.append(f'wrapper image cleanup skipped/failed: {exc}')

        if action_errors:
            return jsonify(
                {
                    'ok': False,
                    'error': action_errors[0],
                    'active': True,
                    'session_count': len(session_ids),
                    'session_ids': session_ids,
                    'stopped': stopped,
                    'deleted': deleted,
                    'cleanup_notes': cleanup_notes,
                    'cleanup_containers': cleanup_containers,
                    'cleanup_images': cleanup_images,
                }
            ), 409

        return jsonify(
            {
                'ok': True,
                'active': True,
                'cleaned': True,
                'session_count': len(session_ids),
                'session_ids': session_ids,
                'stopped': stopped,
                'deleted': deleted,
                'cleanup_notes': cleanup_notes,
                'cleanup_containers': cleanup_containers,
                'cleanup_images': cleanup_images,
            }
        ), 200

    mark_routes_registered(app, 'core_test_prepare_routes')