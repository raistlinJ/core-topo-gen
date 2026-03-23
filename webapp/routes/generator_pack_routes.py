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

    def _latest_pack_success_payload(note: str) -> dict[str, Any]:
        warnings: list[dict[str, Any]] = []
        installed_generators: list[dict[str, Any]] = []
        grouped: list[dict[str, Any]] = []
        pack_id = ''
        pack_label = ''
        pack_origin = ''
        try:
            state = load_installed_generator_packs_state()
            packs = state.get('packs') if isinstance(state, dict) else None
            if isinstance(packs, list) and packs:
                last = packs[-1] if isinstance(packs[-1], dict) else {}
                pack_id = str(last.get('id') or '').strip()
                pack_label = str(last.get('label') or '').strip()
                pack_origin = str(last.get('origin') or '').strip()
                ww = last.get('warnings') if isinstance(last, dict) else None
                if isinstance(ww, list):
                    warnings = [item for item in ww if isinstance(item, dict)]
                raw_installed = last.get('installed') if isinstance(last, dict) else None
                if isinstance(raw_installed, list):
                    for item in raw_installed:
                        if not isinstance(item, dict):
                            continue
                        record = dict(item)
                        try:
                            marker_path = os_module.path.join(str(record.get('path') or '').strip(), '.coretg_pack.json')
                            if marker_path and os_module.path.exists(marker_path) and os_module.path.isfile(marker_path):
                                import json

                                with open(marker_path, 'r', encoding='utf-8') as handle:
                                    marker = json.load(handle)
                                if isinstance(marker, dict):
                                    source_id = str(marker.get('source_generator_id') or '').strip()
                                    if source_id:
                                        record['source_id'] = source_id
                        except Exception:
                            pass
                        installed_generators.append(record)
        except Exception:
            warnings = []
            installed_generators = []

        grouped_map: dict[str, list[str]] = {}
        for item in installed_generators:
            kind = str(item.get('kind') or '').strip() or 'generator'
            gid = str(item.get('source_id') or item.get('id') or '').strip()
            if not gid:
                continue
            grouped_map.setdefault(kind, []).append(gid)
        grouped = [
            {'kind': kind, 'count': len(ids), 'ids': ids}
            for kind, ids in grouped_map.items()
        ]
        installed_ids = [
            str(item.get('source_id') or item.get('id') or '').strip()
            for item in installed_generators
            if str(item.get('source_id') or item.get('id') or '').strip()
        ]
        if len(installed_ids) == 1:
            confirmation_text = f'Added to catalog as {installed_ids[0]}.'
        elif installed_ids:
            confirmation_text = f'Added to catalog as {", ".join(installed_ids)}.'
        elif pack_label:
            confirmation_text = f'Added generator pack {pack_label} to the catalog.'
        else:
            confirmation_text = 'Generator pack added to catalog.'
        return {
            'ok': True,
            'message': note,
            'warnings': warnings,
            'confirmation_text': confirmation_text,
            'confirmation_detail': note,
            'installed_as': {
                'pack_id': pack_id,
                'pack_label': pack_label,
                'origin': pack_origin,
                'generators': installed_generators,
                'grouped': grouped,
            },
        }

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
                    return jsonify(_latest_pack_success_payload(note)), 200
                return jsonify({'ok': False, 'error': f'Pack install failed: {note}'}), 400
            if ok:
                payload = _latest_pack_success_payload(note)
                flash(f"{payload.get('confirmation_text') or note} {payload.get('confirmation_detail') or ''}".strip())
            else:
                flash(f'Pack install failed: {note}')
        finally:
            try:
                os_module.remove(tmp_path)
            except Exception:
                pass
        return redirect(url_for('flag_catalog_page'))

    @app.route('/generator_packs/import_url', methods=['POST'])
    def generator_packs_import_url():
        is_xhr = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        url = str(request.form.get('zip_url') or '').strip()
        if not url:
            if is_xhr:
                return jsonify({'ok': False, 'error': 'Missing URL.'}), 400
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
                if is_xhr:
                    if ok:
                        return jsonify(_latest_pack_success_payload(note)), 200
                    return jsonify({'ok': False, 'error': f'Pack install failed: {note}'}), 400
                if ok:
                    payload = _latest_pack_success_payload(note)
                    flash(f"{payload.get('confirmation_text') or note} {payload.get('confirmation_detail') or ''}".strip())
                else:
                    flash(f'Pack install failed: {note}')
            finally:
                try:
                    os_module.remove(tmp_path)
                except Exception:
                    pass
        except Exception as exc:
            if is_xhr:
                return jsonify({'ok': False, 'error': f'URL import failed: {exc}'}), 400
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