from __future__ import annotations

from typing import Callable

from flask import flash, jsonify, redirect, request, url_for

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    require_builder_or_admin: Callable[[], None],
    set_pack_disabled_state: Callable[..., tuple[bool, str]],
    set_generator_disabled_state: Callable[..., tuple[bool, str]],
    set_generator_validation_state: Callable[..., tuple[bool, str]],
    delete_installed_generator: Callable[..., tuple[bool, str]],
) -> None:
    if not begin_route_registration(app, 'generator_catalog_mutations_routes'):
        return

    def _batch_mutate(kind: str):
        payload = request.get_json(silent=True) or {}
        generator_ids = payload.get('generator_ids') if isinstance(payload.get('generator_ids'), list) else []
        action = str(payload.get('action') or '').strip().lower()
        ids = []
        for value in generator_ids:
            gid = str(value or '').strip()
            if gid:
                ids.append(gid)
        ids = list(dict.fromkeys(ids))
        if not ids:
            return jsonify({'ok': False, 'error': 'No generator ids provided'}), 400
        if action not in {'disable', 'delete', 'override_success', 'override_fail'}:
            return jsonify({'ok': False, 'error': f'Unsupported action: {action}'}), 400

        updated: list[str] = []
        errors: list[dict[str, str]] = []
        for gid in ids:
            try:
                if action == 'disable':
                    ok, note = set_generator_disabled_state(kind=kind, generator_id=gid, disabled=True)
                elif action == 'delete':
                    ok, note = delete_installed_generator(kind=kind, generator_id=gid)
                elif action == 'override_success':
                    ok, note = set_generator_validation_state(kind=kind, generator_id=gid, validated_ok=True, validated_incomplete=False)
                else:
                    ok, note = set_generator_validation_state(kind=kind, generator_id=gid, validated_ok=False, validated_incomplete=False)
            except Exception as exc:
                ok, note = False, str(exc)
            if ok:
                updated.append(gid)
            else:
                errors.append({'generator_id': gid, 'error': note})

        if not updated and errors:
            return jsonify({'ok': False, 'error': errors[0]['error'], 'errors': errors, 'updated': []}), 400

        return jsonify({
            'ok': len(errors) == 0,
            'updated': updated,
            'errors': errors,
            'message': f'Applied {action} to {len(updated)} item(s).',
        })

    @app.route('/generator_packs/set_disabled/<pack_id>', methods=['POST'])
    def generator_packs_set_disabled(pack_id: str):
        require_builder_or_admin()
        disabled = str(request.form.get('disabled') or '').strip().lower() in {'1', 'true', 'yes', 'on'}
        ok, msg = set_pack_disabled_state(pack_id=pack_id, disabled=disabled)
        flash(msg if ok else f'Failed: {msg}')
        return redirect(url_for('flag_catalog_page'))

    @app.route('/api/flag_generators/delete', methods=['POST'])
    def api_flag_generators_delete():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        generator_id = str(payload.get('generator_id') or payload.get('id') or '').strip()
        ok, note = delete_installed_generator(kind='flag-generator', generator_id=generator_id)
        return jsonify({'ok': ok, 'message': note} if ok else {'ok': False, 'error': note}), (200 if ok else 400)

    @app.route('/api/flag_node_generators/delete', methods=['POST'])
    def api_flag_node_generators_delete():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        generator_id = str(payload.get('generator_id') or payload.get('id') or '').strip()
        ok, note = delete_installed_generator(kind='flag-node-generator', generator_id=generator_id)
        return jsonify({'ok': ok, 'message': note} if ok else {'ok': False, 'error': note}), (200 if ok else 400)

    @app.route('/api/generator_packs/set_disabled', methods=['POST'])
    def api_generator_packs_set_disabled():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        pack_id = str(payload.get('pack_id') or '').strip()
        disabled = bool(payload.get('disabled') is True)
        ok, note = set_pack_disabled_state(pack_id=pack_id, disabled=disabled)
        return jsonify({'ok': ok, 'message': note} if ok else {'ok': False, 'error': note}), (200 if ok else 400)

    @app.route('/api/flag_generators/set_disabled', methods=['POST'])
    def api_flag_generators_set_disabled():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        generator_id = str(payload.get('generator_id') or payload.get('id') or '').strip()
        disabled = bool(payload.get('disabled') is True)
        ok, note = set_generator_disabled_state(kind='flag-generator', generator_id=generator_id, disabled=disabled)
        return jsonify({'ok': ok, 'message': note} if ok else {'ok': False, 'error': note}), (200 if ok else 400)

    @app.route('/api/flag_node_generators/set_disabled', methods=['POST'])
    def api_flag_node_generators_set_disabled():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        generator_id = str(payload.get('generator_id') or payload.get('id') or '').strip()
        disabled = bool(payload.get('disabled') is True)
        ok, note = set_generator_disabled_state(kind='flag-node-generator', generator_id=generator_id, disabled=disabled)
        return jsonify({'ok': ok, 'message': note} if ok else {'ok': False, 'error': note}), (200 if ok else 400)

    @app.route('/api/flag_generators/batch_mutate', methods=['POST'])
    def api_flag_generators_batch_mutate():
        require_builder_or_admin()
        return _batch_mutate('flag-generator')

    @app.route('/api/flag_node_generators/batch_mutate', methods=['POST'])
    def api_flag_node_generators_batch_mutate():
        require_builder_or_admin()
        return _batch_mutate('flag-node-generator')

    mark_routes_registered(app, 'generator_catalog_mutations_routes')