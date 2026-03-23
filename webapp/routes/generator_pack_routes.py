from __future__ import annotations

from typing import Any, Callable

from flask import flash, jsonify, redirect, request, send_file, url_for
from werkzeug.utils import secure_filename

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    install_generator_pack_or_bundle: Callable[..., tuple[bool, str]],
    load_installed_generator_packs_state: Callable[[], dict],
    save_installed_generator_packs_state: Callable[[dict], None],
    installed_generators_root: Callable[[], str],
    get_repo_root: Callable[[], str],
    local_timestamp_display: Callable[[], str],
    local_timestamp_safe: Callable[[], str],
    compute_next_numeric_generator_id: Callable[..., int],
    install_generator_pack_payload: Callable[..., tuple[bool, str, list[dict[str, Any]], int, list[dict[str, Any]]]],
    download_zip_from_url: Callable[[str], bytes],
    pack_to_zip_bytes: Callable[[dict], bytes],
    os_module: Any,
    tempfile_module: Any,
    uuid_module: Any,
    shutil_module: Any,
    io_module: Any,
    zipfile_module: Any,
) -> None:
    if not begin_route_registration(app, 'generator_pack_routes'):
        return

    @app.route('/generator_packs/upload', methods=['POST'])
    def generator_packs_upload():
        is_xhr = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        file_obj = request.files.get('zip_file')
        if not file_obj or file_obj.filename == '':
            if is_xhr:
                return jsonify({'ok': False, 'error': 'No zip selected.'}), 400
            flash('No zip selected.')
            return redirect(url_for('flag_catalog_page'))
        filename = secure_filename(file_obj.filename)
        if not filename.lower().endswith('.zip'):
            if is_xhr:
                return jsonify({'ok': False, 'error': 'Only .zip allowed.'}), 400
            flash('Only .zip allowed.')
            return redirect(url_for('flag_catalog_page'))

        fd, tmp_path = tempfile_module.mkstemp(prefix='coretg_pack_', suffix='-' + filename)
        os_module.close(fd)
        try:
            file_obj.save(tmp_path)
            label = filename[:-4] if filename.lower().endswith('.zip') else filename
            ok, note = install_generator_pack_or_bundle(zip_path=tmp_path, pack_label=label, pack_origin='upload')
            if is_xhr:
                if ok:
                    warnings: list[dict[str, Any]] = []
                    try:
                        state = load_installed_generator_packs_state()
                        packs = state.get('packs') if isinstance(state, dict) else None
                        if isinstance(packs, list) and packs:
                            last = packs[-1] if isinstance(packs[-1], dict) else {}
                            ww = last.get('warnings') if isinstance(last, dict) else None
                            if isinstance(ww, list):
                                warnings = ww
                    except Exception:
                        warnings = []
                    return jsonify({'ok': True, 'message': note, 'warnings': warnings}), 200
                return jsonify({'ok': False, 'error': f'Pack install failed: {note}'}), 400
            flash(note if ok else f'Pack install failed: {note}')
        finally:
            try:
                os_module.remove(tmp_path)
            except Exception:
                pass
        return redirect(url_for('flag_catalog_page'))

    @app.route('/generator_packs/import_url', methods=['POST'])
    def generator_packs_import_url():
        url = str(request.form.get('zip_url') or '').strip()
        if not url:
            flash('Missing URL.')
            return redirect(url_for('flag_catalog_page'))
        try:
            data = download_zip_from_url(url)
            fd, tmp_path = tempfile_module.mkstemp(prefix='coretg_pack_url_', suffix='.zip')
            os_module.close(fd)
            try:
                with open(tmp_path, 'wb') as fh:
                    fh.write(data)
                ok, note = install_generator_pack_or_bundle(zip_path=tmp_path, pack_label=url, pack_origin='url')
                flash(note if ok else f'Pack install failed: {note}')
            finally:
                try:
                    os_module.remove(tmp_path)
                except Exception:
                    pass
        except Exception as exc:
            flash(f'URL import failed: {exc}')
        return redirect(url_for('flag_catalog_page'))

    @app.route('/generator_packs/delete/<pack_id>', methods=['POST'])
    def generator_packs_delete(pack_id: str):
        pid = str(pack_id or '').strip()
        if not pid:
            flash('Missing pack id')
            return redirect(url_for('flag_catalog_page'))

        installed_root = os_module.path.abspath(installed_generators_root())
        state = load_installed_generator_packs_state()
        packs = state.get('packs') or []
        if not isinstance(packs, list):
            packs = []

        target = None
        kept = []
        for pack in packs:
            if isinstance(pack, dict) and str(pack.get('id') or '') == pid:
                target = pack
                continue
            kept.append(pack)

        if not target:
            flash('Pack not found')
            return redirect(url_for('flag_catalog_page'))

        removed = 0
        failures: list[str] = []
        for item in (target.get('installed') or []):
            if not isinstance(item, dict):
                continue
            path = str(item.get('path') or '').strip()
            if not path:
                continue
            abs_path = os_module.path.abspath(path)
            try:
                if os_module.path.commonpath([installed_root, abs_path]) != installed_root:
                    failures.append(f'refused to delete outside installed root: {abs_path}')
                    continue
            except Exception:
                failures.append(f'refused to delete path: {abs_path}')
                continue

            try:
                if os_module.path.isdir(abs_path):
                    shutil_module.rmtree(abs_path, ignore_errors=False)
                    removed += 1
                elif os_module.path.exists(abs_path):
                    os_module.remove(abs_path)
                    removed += 1
            except Exception as exc:
                failures.append(f'failed deleting {abs_path}: {exc}')

        state['packs'] = kept
        save_installed_generator_packs_state(state)

        if failures:
            flash(f'Uninstalled pack {pid} with warnings: removed={removed}; {failures[0]}')
        else:
            flash(f'Uninstalled pack {pid} (removed {removed} item(s))')
        return redirect(url_for('flag_catalog_page'))

    @app.route('/generator_packs/download/<pack_id>')
    def generator_packs_download(pack_id: str):
        pid = str(pack_id or '').strip()
        state = load_installed_generator_packs_state()
        packs = state.get('packs') or []
        if not isinstance(packs, list):
            packs = []
        target = None
        for pack in packs:
            if isinstance(pack, dict) and str(pack.get('id') or '') == pid:
                target = pack
                break
        if not target:
            flash('Pack not found')
            return redirect(url_for('flag_catalog_page'))

        data = pack_to_zip_bytes(target)
        label = secure_filename(str(target.get('label') or '')).strip() or 'pack'
        download_name = f'generator-pack-{pid}-{label}.zip'
        return send_file(io_module.BytesIO(data), as_attachment=True, download_name=download_name)

    @app.route('/generator_packs/export_all')
    def generator_packs_export_all():
        state = load_installed_generator_packs_state()
        packs = state.get('packs') or []
        if not isinstance(packs, list):
            packs = []

        mem = io_module.BytesIO()
        with zipfile_module.ZipFile(mem, 'w', zipfile_module.ZIP_DEFLATED) as zf:
            for pack in packs:
                if not isinstance(pack, dict):
                    continue
                pid = str(pack.get('id') or '').strip()
                if not pid:
                    continue
                label = secure_filename(str(pack.get('label') or '')).strip() or 'pack'
                arcname = f'packs/{pid}-{label}.zip'
                try:
                    zf.writestr(arcname, pack_to_zip_bytes(pack))
                except Exception:
                    continue
        mem.seek(0)
        return send_file(mem, as_attachment=True, download_name='generator_packs.zip')

    mark_routes_registered(app, 'generator_pack_routes')