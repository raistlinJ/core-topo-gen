from __future__ import annotations

from typing import Any, Callable

from flask import jsonify, render_template, request, send_file, url_for

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    require_builder_or_admin: Callable[[], None],
    load_vuln_catalogs_state: Callable[[], dict],
    get_active_vuln_catalog_entry: Callable[[dict], dict | None],
    normalize_vuln_catalog_items: Callable[[dict], list[dict[str, Any]]],
    vuln_catalog_pack_content_dir: Callable[[str], str],
    safe_path_under: Callable[[str, str], str],
    get_repo_root: Callable[[], str],
    load_vuln_catalog: Callable[[str], list[Any]],
    os_module: Any,
) -> None:
    if not begin_route_registration(app, 'vuln_catalog_overview_routes'):
        return

    @app.route('/vuln_catalog_page')
    def vuln_catalog_page():
        require_builder_or_admin()
        state = load_vuln_catalogs_state()
        catalogs = [catalog for catalog in (state.get('catalogs') or []) if isinstance(catalog, dict)]
        active_id = str(state.get('active_id') or '').strip()
        active_label = None
        for catalog in catalogs:
            if str(catalog.get('id') or '').strip() == active_id:
                active_label = str(catalog.get('label') or '').strip() or active_id
                break
        items_count = None
        try:
            items_count = len(load_vuln_catalog(get_repo_root()))
        except Exception:
            items_count = None
        return render_template(
            'vuln_catalog.html',
            catalogs=catalogs,
            active_id=active_id,
            active_label=active_label,
            items_count=items_count,
            active_page='vuln_catalog',
        )

    @app.route('/vuln_catalog_items_data')
    def vuln_catalog_items_data():
        require_builder_or_admin()
        state = load_vuln_catalogs_state()
        entry = get_active_vuln_catalog_entry(state)
        if not entry:
            return jsonify({'ok': True, 'active': None, 'items': []})
        cid = str(entry.get('id') or '').strip()
        items = normalize_vuln_catalog_items(entry)
        from_source = str(entry.get('from_source') or entry.get('label') or '').strip()

        def _display_name(item: dict[str, Any]) -> str:
            base = str(item.get('name') or '').strip() or 'root'
            rel_dir = str(item.get('rel_dir') or item.get('dir_rel') or '').strip()
            if not rel_dir or rel_dir in ('', '.', 'root'):
                return base
            parts = [part for part in rel_dir.replace('\\', '/').split('/') if part]
            if len(parts) >= 2:
                return f'{parts[-2]}/{parts[-1]}'
            return parts[-1] if parts else base

        base_dir = vuln_catalog_pack_content_dir(cid)
        out_items: list[dict[str, Any]] = []
        for item in items:
            readme_url = ''
            try:
                rel_dir = str(item.get('dir_rel') or item.get('rel_dir') or '').strip().replace('\\', '/')
                abs_dir = safe_path_under(base_dir, rel_dir)
                if os_module.path.isdir(abs_dir):
                    best_name = None
                    best_rank = 10**9
                    for name in os_module.listdir(abs_dir):
                        if not isinstance(name, str):
                            continue
                        low = name.lower().strip()
                        if not low.startswith('readme'):
                            continue
                        ext = os_module.path.splitext(low)[1].lstrip('.')
                        if ext not in ('md', 'markdown', 'txt'):
                            continue
                        if low in ('readme.md', 'readme.markdown', 'readme.txt'):
                            rank = 0
                        elif low.startswith('readme.en'):
                            rank = 1
                        else:
                            rank = 2
                        if rank < best_rank:
                            best_rank = rank
                            best_name = name
                    if best_name:
                        rel = os_module.path.relpath(os_module.path.join(abs_dir, best_name), base_dir).replace('\\', '/')
                        readme_url = url_for('vuln_catalog_packs_readme', catalog_id=cid, subpath=rel)
            except Exception:
                readme_url = ''
            log_path = str(item.get('last_test_log_path') or '').strip()
            log_download_url = ''
            if log_path:
                try:
                    outputs_root = os_module.path.abspath(os_module.path.join(get_repo_root(), 'outputs'))
                    abs_log_path = os_module.path.abspath(log_path)
                    if os_module.path.isfile(abs_log_path) and os_module.path.commonpath([outputs_root, abs_log_path]) == outputs_root:
                        log_download_url = url_for('vuln_catalog_item_test_log_download', item_id=int(item.get('id') or 0))
                except Exception:
                    log_download_url = ''
            out_items.append({
                'id': int(item.get('id') or 0),
                'name': _display_name(item),
                'type': 'docker-compose',
                'from_source': from_source,
                'disabled': bool(item.get('disabled', False)),
                'readme_url': readme_url,
                'validated_ok': bool(item.get('validated_ok')) if item.get('validated_ok') is not None else None,
                'validated_incomplete': bool(item.get('validated_incomplete') is True),
                'validated_at': str(item.get('validated_at') or '').strip() or None,
                'log_download_url': log_download_url or None,
                'eligible_for_selection': bool(item.get('validated_ok') is True and item.get('validated_incomplete') is not True and not bool(item.get('disabled', False))),
            })
        return jsonify({
            'ok': True,
            'active': {
                'id': cid,
                'label': str(entry.get('label') or '').strip() or cid,
                'from_source': from_source,
            },
            'items': out_items,
        })

    @app.route('/vuln_catalog_items/test/log')
    def vuln_catalog_item_test_log_download():
        require_builder_or_admin()
        try:
            item_id = int(request.args.get('item_id') or 0)
        except Exception:
            item_id = 0
        if item_id <= 0:
            return jsonify({'ok': False, 'error': 'Invalid item id'}), 400

        state = load_vuln_catalogs_state()
        entry = get_active_vuln_catalog_entry(state)
        if not entry:
            return jsonify({'ok': False, 'error': 'No active catalog pack'}), 404

        outputs_root = os_module.path.abspath(os_module.path.join(get_repo_root(), 'outputs'))
        items = normalize_vuln_catalog_items(entry)
        for item in items:
            if int(item.get('id') or 0) != item_id:
                continue
            log_path = str(item.get('last_test_log_path') or '').strip()
            if not log_path:
                return jsonify({'ok': False, 'error': 'Log not available'}), 404
            abs_log_path = os_module.path.abspath(log_path)
            try:
                if os_module.path.commonpath([outputs_root, abs_log_path]) != outputs_root:
                    return jsonify({'ok': False, 'error': 'Refusing path'}), 400
            except Exception:
                return jsonify({'ok': False, 'error': 'Refusing path'}), 400
            if not os_module.path.isfile(abs_log_path):
                return jsonify({'ok': False, 'error': 'Log not available'}), 404
            download_name = str(item.get('last_test_log_filename') or os_module.path.basename(abs_log_path) or f'vuln-item-{item_id}.log').strip()
            return send_file(abs_log_path, as_attachment=True, download_name=download_name, mimetype='text/plain; charset=utf-8')

        return jsonify({'ok': False, 'error': 'Unknown item id'}), 404

    mark_routes_registered(app, 'vuln_catalog_overview_routes')