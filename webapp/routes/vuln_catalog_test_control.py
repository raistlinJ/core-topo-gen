from __future__ import annotations

from typing import Any, Callable

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    require_builder_or_admin: Callable[[], None],
    runs_store: dict[str, dict[str, Any]],
    stop_vuln_test_meta: Callable[[dict[str, Any], bool | None], Any],
) -> None:
    if not begin_route_registration(app, 'vuln_catalog_test_control_routes'):
        return

    @app.route('/vuln_catalog_items/test/stop', methods=['POST'])
    def vuln_catalog_items_test_stop():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        run_id = str(payload.get('run_id') or '').strip()
        ok_value = payload.get('ok')
        user_ok = True if ok_value is True else (False if ok_value is False else None)
        if not run_id:
            return jsonify({'ok': False, 'error': 'run_id required'}), 400
        meta = runs_store.get(run_id)
        if not meta or meta.get('kind') != 'vuln_test':
            return jsonify({'ok': False, 'error': 'not found'}), 404

        return stop_vuln_test_meta(meta, user_ok)

    @app.route('/vuln_catalog_items/test/stop_active', methods=['POST'])
    def vuln_catalog_items_test_stop_active():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        ok_value = payload.get('ok')
        user_ok = True if ok_value is True else (False if ok_value is False else None)
        active_meta = None
        try:
            for meta in runs_store.values():
                if isinstance(meta, dict) and meta.get('kind') == 'vuln_test' and not meta.get('done'):
                    active_meta = meta
                    break
        except Exception:
            active_meta = None
        if not active_meta:
            return jsonify({'ok': False, 'error': 'no active test'}), 404
        return stop_vuln_test_meta(active_meta, user_ok)

    @app.route('/vuln_catalog_items/test/status', methods=['POST'])
    def vuln_catalog_items_test_status():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        run_id = str(payload.get('run_id') or '').strip()
        if not run_id:
            return jsonify({'ok': False, 'error': 'run_id required'}), 400
        meta = runs_store.get(run_id)
        if not isinstance(meta, dict) or meta.get('kind') != 'vuln_test':
            return jsonify({'ok': False, 'error': 'not found'}), 404
        return jsonify({
            'ok': True,
            'done': bool(meta.get('done')),
            'cleanup_started': bool(meta.get('cleanup_started')),
            'cleanup_done': bool(meta.get('cleanup_done')),
        })

    mark_routes_registered(app, 'vuln_catalog_test_control_routes')