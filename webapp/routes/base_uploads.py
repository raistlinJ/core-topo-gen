from __future__ import annotations

import copy
import json
import os
import uuid
from typing import Any, Callable, Optional

from flask import flash, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    current_user_getter: Callable[[], dict | None],
    local_timestamp_safe: Callable[[], str],
    validate_core_xml: Callable[[str], tuple[bool, Any]],
    default_scenarios_payload: Callable[[], dict[str, Any]],
    attach_base_upload: Callable[[dict[str, Any]], None],
    save_base_upload_state: Callable[[dict[str, Any]], None],
    prepare_payload_for_index: Callable[..., dict[str, Any]],
    clear_base_upload_state: Callable[[], None],
    load_editor_state_snapshot: Callable[[Optional[dict]], Optional[dict[str, Any]]],
    persist_editor_state_snapshot: Callable[..., None],
    analyze_core_xml: Callable[[str], dict[str, Any]],
    ui_build_id: str,
) -> None:
    if not begin_route_registration(app, 'base_uploads_routes'):
        return

    def _upload_base_view():
        user = current_user_getter()
        uploaded = request.files.get('base_xml')
        if not uploaded or uploaded.filename == '':
            flash('No base scenario file selected.')
            return redirect(url_for('index'))
        filename = secure_filename(uploaded.filename)
        base_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'base')
        os.makedirs(base_dir, exist_ok=True)
        unique = local_timestamp_safe() + '-' + uuid.uuid4().hex[:8]
        saved_path = os.path.join(base_dir, f'{unique}-{filename}')
        uploaded.save(saved_path)
        ok, errs = validate_core_xml(saved_path)
        payload = default_scenarios_payload()
        payload['base_upload'] = {
            'path': saved_path,
            'valid': bool(ok),
            'display_name': filename,
            'exists': True,
        }
        if not ok:
            flash('Base scenario XML is INVALID. See details link for errors.')
        else:
            flash('Base scenario uploaded and validated.')
            try:
                payload['scenarios'][0]['base']['filepath'] = saved_path
                payload['scenarios'][0]['base']['display_name'] = filename
            except Exception:
                pass
        attach_base_upload(payload)
        if payload.get('base_upload'):
            save_base_upload_state(payload['base_upload'])
        payload = prepare_payload_for_index(payload, user=user)
        return render_template('index.html', payload=payload, logs=(errs if not ok else ''), xml_preview='', ui_build_id=ui_build_id)

    def _remove_base_view():
        user = current_user_getter()
        try:
            payload = default_scenarios_payload()
            existing_snapshot = load_editor_state_snapshot(user) or {}
            data_str = request.form.get('scenarios_json')
            if data_str:
                try:
                    data = json.loads(data_str)
                    if isinstance(data, dict) and 'scenarios' in data:
                        payload['scenarios'] = data['scenarios']
                except Exception:
                    pass
            try:
                if payload['scenarios'] and isinstance(payload['scenarios'][0], dict):
                    payload['scenarios'][0].setdefault('base', {}).update({'filepath': '', 'display_name': ''})
            except Exception:
                pass
            flash('Base scenario removed.')
            clear_base_upload_state()
            payload.pop('base_upload', None)
            try:
                snapshot_source = dict(existing_snapshot) if isinstance(existing_snapshot, dict) else {}
                snapshot_source['scenarios'] = copy.deepcopy(payload.get('scenarios') or [])
                snapshot_source.pop('base_upload', None)
                persist_editor_state_snapshot(snapshot_source, user=user)
            except Exception:
                pass
            payload = prepare_payload_for_index(payload, user=user)
            snapshot = load_editor_state_snapshot(user)
            if snapshot:
                payload['editor_snapshot'] = snapshot
            return render_template('index.html', payload=payload, logs='', xml_preview='', ui_build_id=ui_build_id)
        except Exception as exc:
            flash(f'Failed to remove base: {exc}')
            return redirect(url_for('index'))

    def _base_details_view():
        xml_path = request.args.get('path')
        if not xml_path or not os.path.exists(xml_path):
            return 'File not found', 404
        ok, errs = validate_core_xml(xml_path)
        summary = analyze_core_xml(xml_path) if ok else {'error': errs}
        return render_template('base_details.html', xml_path=xml_path, valid=ok, errors=errs, summary=summary)

    app.add_url_rule('/upload_base', endpoint='upload_base', view_func=_upload_base_view, methods=['POST'])
    app.add_url_rule('/remove_base', endpoint='remove_base', view_func=_remove_base_view, methods=['POST'])
    app.add_url_rule('/base_details', endpoint='base_details', view_func=_base_details_view, methods=['GET'])
    mark_routes_registered(app, 'base_uploads_routes')