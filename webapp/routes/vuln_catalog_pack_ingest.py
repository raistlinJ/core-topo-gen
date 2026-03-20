from __future__ import annotations

from typing import Any, Callable

from flask import flash, jsonify, redirect, request, url_for

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    require_builder_or_admin: Callable[[], None],
    install_vuln_catalog_zip_file: Callable[..., dict[str, Any]],
    install_vuln_catalog_zip_bytes: Callable[..., dict[str, Any]],
    is_safe_remote_zip_url: Callable[[str], tuple[bool, str]],
    download_zip_from_url: Callable[[str], bytes],
    request_entity_too_large_type: type[Exception],
    secure_filename_func: Callable[[str], str],
    tempfile_module: Any,
    os_module: Any,
    urlparse_func: Callable[[str], Any],
) -> None:
    if not begin_route_registration(app, 'vuln_catalog_pack_ingest_routes'):
        return

    @app.route('/vuln_catalog_packs/upload', methods=['POST'])
    def vuln_catalog_packs_upload():
        require_builder_or_admin()
        is_ajax = str(request.headers.get('X-Requested-With') or '').lower() == 'xmlhttprequest' or 'application/json' in str(request.headers.get('Accept') or '')
        try:
            upload_file = request.files.get('zip_file')
        except request_entity_too_large_type:
            msg = 'File too large for this server upload limit.'
            if is_ajax:
                return jsonify({'ok': False, 'error': msg}), 413
            flash(msg)
            return redirect(url_for('vuln_catalog_page'))

        if not upload_file:
            if is_ajax:
                return jsonify({'ok': False, 'error': 'Missing zip_file'}), 400
            flash('Missing zip_file')
            return redirect(url_for('vuln_catalog_page'))

        max_upload_bytes = 1024 * 1024 * 1024
        try:
            max_upload_bytes = int(os_module.getenv('CORETG_VULN_PACK_MAX_BYTES') or max_upload_bytes)
        except Exception:
            max_upload_bytes = 1024 * 1024 * 1024
        try:
            req_len = request.content_length
            if isinstance(req_len, int) and req_len > max_upload_bytes:
                msg = f'File too large (max {max_upload_bytes // (1024 * 1024)}MB).'
                if is_ajax:
                    return jsonify({'ok': False, 'error': msg}), 413
                flash(msg)
                return redirect(url_for('vuln_catalog_page'))
        except Exception:
            pass

        tmp_path = ''
        try:
            try:
                with tempfile_module.NamedTemporaryFile(prefix='vuln-upload-', suffix='.zip', delete=False) as tmp:
                    tmp_path = tmp.name
                upload_file.save(tmp_path)
            except request_entity_too_large_type:
                msg = 'File too large for this server upload limit.'
                if is_ajax:
                    return jsonify({'ok': False, 'error': msg}), 413
                flash(msg)
                return redirect(url_for('vuln_catalog_page'))

            label = secure_filename_func(getattr(upload_file, 'filename', '') or '') or 'vuln-catalog'
            entry = install_vuln_catalog_zip_file(zip_file_path=tmp_path, label=label, origin='upload')
            try:
                os_module.remove(tmp_path)
            except Exception:
                pass
            if is_ajax:
                return jsonify({'ok': True, 'message': 'Vulnerability catalog pack installed.', 'catalog_id': str(entry.get('id') or '')})
            flash('Vulnerability catalog pack installed.')
        except Exception as exc:
            try:
                if tmp_path:
                    os_module.remove(tmp_path)
            except Exception:
                pass
            if is_ajax:
                return jsonify({'ok': False, 'error': f'Failed to install vulnerability catalog pack: {exc}'}), 400
            flash(f'Failed to install vulnerability catalog pack: {exc}')
        return redirect(url_for('vuln_catalog_page'))

    @app.route('/vuln_catalog_packs/import_url', methods=['POST'])
    def vuln_catalog_packs_import_url():
        require_builder_or_admin()
        url = str(request.form.get('zip_url') or '').strip()
        ok, msg = is_safe_remote_zip_url(url)
        if not ok:
            flash(f'Blocked URL: {msg}')
            return redirect(url_for('vuln_catalog_page'))
        try:
            data = download_zip_from_url(url)
            label = os_module.path.basename(urlparse_func(url).path) or 'vuln-catalog'
            install_vuln_catalog_zip_bytes(zip_bytes=data, label=label, origin=url)
            flash('Vulnerability catalog pack installed from URL.')
        except Exception as exc:
            flash(f'Failed to import vulnerability catalog pack: {exc}')
        return redirect(url_for('vuln_catalog_page'))

    mark_routes_registered(app, 'vuln_catalog_pack_ingest_routes')