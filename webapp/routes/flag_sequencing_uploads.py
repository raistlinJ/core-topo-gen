from __future__ import annotations

from typing import Any

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def _unique_dest_filename(backend: Any, dir_path: str, filename: str) -> str:
    base = backend.secure_filename(filename) or 'upload'
    candidate = base
    root, ext = backend.os.path.splitext(base)
    index = 1
    while backend.os.path.exists(backend.os.path.join(dir_path, candidate)):
        candidate = f"{root}_{index}{ext}"
        index += 1
        if index > 5000:
            break
    return candidate


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'flag_sequencing_uploads_routes'):
        return

    backend = backend_module

    @app.route('/api/flag-sequencing/upload_flow_input_file', methods=['POST'])
    def api_flow_upload_flow_input_file():
        """Upload a file to be used as a Flow generator input override."""
        scenario_label = str(request.form.get('scenario') or '').strip()
        scenario_norm = backend._normalize_scenario_label(scenario_label)
        if not scenario_norm:
            return jsonify({'ok': False, 'error': 'No scenario specified.'}), 400

        step_index_raw = str(request.form.get('step_index') or '').strip()
        input_name = str(request.form.get('input_name') or '').strip()
        generator_id = str(request.form.get('generator_id') or '').strip()

        upload_file = request.files.get('file')
        if not upload_file or not getattr(upload_file, 'filename', ''):
            return jsonify({'ok': False, 'error': 'No file provided.'}), 400

        max_bytes = 10 * 1024 * 1024
        try:
            content_length = request.content_length
            if isinstance(content_length, int) and content_length > max_bytes:
                return jsonify({'ok': False, 'error': 'File too large (max 10MB).'}), 413
        except Exception:
            pass

        original_filename = str(getattr(upload_file, 'filename', '') or '')
        safe_filename = backend.secure_filename(original_filename) or 'upload'
        unique = backend._local_timestamp_safe() + '-' + backend.uuid.uuid4().hex[:8]
        base_dir = backend.os.path.join(backend._flow_uploads_dir(), scenario_norm, unique)
        backend.os.makedirs(base_dir, exist_ok=True)

        prefix = backend.secure_filename(input_name) or 'input'
        stored_name = _unique_dest_filename(backend, base_dir, f"{prefix}__{safe_filename}")
        stored_path = backend.os.path.join(base_dir, stored_name)
        try:
            upload_file.save(stored_path)
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Failed saving upload: {exc}'}), 400

        return jsonify(
            {
                'ok': True,
                'scenario': scenario_label or scenario_norm,
                'scenario_norm': scenario_norm,
                'step_index': step_index_raw,
                'generator_id': generator_id,
                'input_name': input_name,
                'original_filename': original_filename,
                'stored_filename': stored_name,
                'stored_path': backend.os.path.abspath(stored_path),
            }
        )

    @app.route('/api/flag-sequencing/upload_flow_inject_file', methods=['POST'])
    def api_flow_upload_flow_inject_file():
        """Upload a file to be used as a Flow inject override."""
        scenario_label = str(request.form.get('scenario') or '').strip()
        scenario_norm = backend._normalize_scenario_label(scenario_label)
        if not scenario_norm:
            return jsonify({'ok': False, 'error': 'No scenario specified.'}), 400

        step_index_raw = str(request.form.get('step_index') or '').strip()
        generator_id = str(request.form.get('generator_id') or '').strip()

        upload_file = request.files.get('file')
        if not upload_file or not getattr(upload_file, 'filename', ''):
            return jsonify({'ok': False, 'error': 'No file provided.'}), 400

        max_bytes = 10 * 1024 * 1024
        try:
            content_length = request.content_length
            if isinstance(content_length, int) and content_length > max_bytes:
                return jsonify({'ok': False, 'error': 'File too large (max 10MB).'}), 413
        except Exception:
            pass

        original_filename = str(getattr(upload_file, 'filename', '') or '')
        safe_filename = backend.secure_filename(original_filename) or 'upload'
        unique = backend._local_timestamp_safe() + '-' + backend.uuid.uuid4().hex[:8]
        base_dir = backend.os.path.join(backend._flow_inject_uploads_dir(), scenario_norm, unique)
        backend.os.makedirs(base_dir, exist_ok=True)

        stored_name = _unique_dest_filename(backend, base_dir, safe_filename)
        stored_path = backend.os.path.join(base_dir, stored_name)
        try:
            upload_file.save(stored_path)
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Failed saving upload: {exc}'}), 400

        absolute_stored_path = backend.os.path.abspath(stored_path)
        return jsonify(
            {
                'ok': True,
                'scenario': scenario_label or scenario_norm,
                'scenario_norm': scenario_norm,
                'step_index': step_index_raw,
                'generator_id': generator_id,
                'original_filename': original_filename,
                'stored_filename': stored_name,
                'stored_path': absolute_stored_path,
                'inject_value': f'upload:{absolute_stored_path}',
            }
        )

    mark_routes_registered(app, 'flag_sequencing_uploads_routes')