from __future__ import annotations

from typing import Any, Callable

from flask import flash, jsonify, redirect, request, url_for

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    require_builder_or_admin: Callable[[], None],
    load_vuln_catalogs_state: Callable[[], dict],
    write_vuln_catalogs_state: Callable[[dict], None],
    get_active_vuln_catalog_entry: Callable[[dict], dict | None],
    normalize_vuln_catalog_items: Callable[[dict], list[dict[str, Any]]],
    write_vuln_catalog_csv_from_items: Callable[..., list[str]],
    vuln_catalog_pack_dir: Callable[[str], str],
    shutil_module: Any,
) -> None:
    if not begin_route_registration(app, 'vuln_catalog_mutations_routes'):
        return

    @app.route('/vuln_catalog_packs/set_active/<catalog_id>', methods=['POST'])
    def vuln_catalog_packs_set_active(catalog_id: str):
        require_builder_or_admin()
        cid = str(catalog_id or '').strip()
        state = load_vuln_catalogs_state()
        catalogs = [catalog for catalog in (state.get('catalogs') or []) if isinstance(catalog, dict)]
        if not any(str(catalog.get('id') or '').strip() == cid for catalog in catalogs):
            flash('Unknown catalog id')
            return redirect(url_for('vuln_catalog_page'))
        state['active_id'] = cid
        write_vuln_catalogs_state(state)
        flash('Active vulnerability catalog updated.')
        return redirect(url_for('vuln_catalog_page'))

    @app.route('/vuln_catalog_packs/delete/<catalog_id>', methods=['POST'])
    def vuln_catalog_packs_delete(catalog_id: str):
        require_builder_or_admin()
        cid = str(catalog_id or '').strip()
        state = load_vuln_catalogs_state()
        catalogs = [catalog for catalog in (state.get('catalogs') or []) if isinstance(catalog, dict)]
        kept = [catalog for catalog in catalogs if str(catalog.get('id') or '').strip() != cid]
        state['catalogs'] = kept
        if str(state.get('active_id') or '').strip() == cid:
            state['active_id'] = str((kept[0].get('id') if kept else '') or '').strip()
        write_vuln_catalogs_state(state)
        shutil_module.rmtree(vuln_catalog_pack_dir(cid), ignore_errors=True)
        flash('Vulnerability catalog pack deleted.')
        return redirect(url_for('vuln_catalog_page'))

    @app.route('/vuln_catalog_items/set_disabled', methods=['POST'])
    def vuln_catalog_items_set_disabled():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        item_id_raw = payload.get('item_id')
        disabled = bool(payload.get('disabled', False))
        try:
            item_id = int(item_id_raw)
        except Exception:
            return jsonify({'ok': False, 'error': 'Invalid item_id'}), 400

        state = load_vuln_catalogs_state()
        entry = get_active_vuln_catalog_entry(state)
        if not entry:
            return jsonify({'ok': False, 'error': 'No active catalog pack'}), 404
        cid = str(entry.get('id') or '').strip()
        catalogs = [catalog for catalog in (state.get('catalogs') or []) if isinstance(catalog, dict)]

        updated = False
        for catalog in catalogs:
            if str(catalog.get('id') or '').strip() != cid:
                continue
            items = normalize_vuln_catalog_items(catalog)
            for item in items:
                if int(item.get('id') or 0) == item_id:
                    item['disabled'] = disabled
                    updated = True
                    break
            catalog['compose_items'] = items
            catalog['csv_paths'] = write_vuln_catalog_csv_from_items(catalog_id=cid, items=items)
            break
        if not updated:
            return jsonify({'ok': False, 'error': 'Unknown item id'}), 404

        state['catalogs'] = catalogs
        write_vuln_catalogs_state(state)
        return jsonify({'ok': True})

    @app.route('/vuln_catalog_items/delete', methods=['POST'])
    def vuln_catalog_items_delete():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        item_id_raw = payload.get('item_id')
        try:
            item_id = int(item_id_raw)
        except Exception:
            return jsonify({'ok': False, 'error': 'Invalid item_id'}), 400

        state = load_vuln_catalogs_state()
        entry = get_active_vuln_catalog_entry(state)
        if not entry:
            return jsonify({'ok': False, 'error': 'No active catalog pack'}), 404
        cid = str(entry.get('id') or '').strip()
        catalogs = [catalog for catalog in (state.get('catalogs') or []) if isinstance(catalog, dict)]

        removed = False
        for catalog in catalogs:
            if str(catalog.get('id') or '').strip() != cid:
                continue
            items = normalize_vuln_catalog_items(catalog)
            kept = [item for item in items if int(item.get('id') or 0) != item_id]
            removed = len(kept) != len(items)
            catalog['compose_items'] = kept
            catalog['compose_count'] = len(kept)
            catalog['csv_paths'] = write_vuln_catalog_csv_from_items(catalog_id=cid, items=kept)
            break
        if not removed:
            return jsonify({'ok': False, 'error': 'Unknown item id'}), 404

        state['catalogs'] = catalogs
        write_vuln_catalogs_state(state)
        return jsonify({'ok': True})

    mark_routes_registered(app, 'vuln_catalog_mutations_routes')