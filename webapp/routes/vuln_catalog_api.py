from __future__ import annotations

from typing import Any, Callable

from flask import jsonify, url_for

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    load_vuln_catalogs_state: Callable[[], dict],
    get_active_vuln_catalog_entry: Callable[[dict], dict | None],
    normalize_vuln_catalog_items: Callable[[dict], list[dict[str, Any]]],
    vuln_catalog_item_abs_compose_path: Callable[..., str],
    os_module: Any,
) -> None:
    if not begin_route_registration(app, 'vuln_catalog_api_routes'):
        return

    @app.route('/vuln_catalog')
    def vuln_catalog():
        try:
            try:
                state = load_vuln_catalogs_state()
                entry = get_active_vuln_catalog_entry(state)
            except Exception:
                entry = None

            if entry and isinstance(entry, dict):
                catalog_id = str(entry.get('id') or '').strip()
                norm_items = normalize_vuln_catalog_items(entry)
                from_source = str(entry.get('from_source') or entry.get('label') or '').strip()

                def _display_name(item: dict[str, Any]) -> str:
                    base = str(item.get('name') or '').strip() or 'root'
                    rel_dir = str(item.get('rel_dir') or item.get('dir_rel') or '').strip()
                    if not rel_dir or rel_dir in ('', '.', 'root'):
                        return base
                    parts = [part for part in rel_dir.replace('\\', '/').split('/') if part]
                    if len(parts) >= 2:
                        return f"{parts[-2]}/{parts[-1]}"
                    return parts[-1] if parts else base

                items: list[dict[str, Any]] = []
                for item in norm_items:
                    if bool(item.get('disabled', False)):
                        continue
                    try:
                        abs_compose = vuln_catalog_item_abs_compose_path(catalog_id=catalog_id, item=item)
                    except Exception:
                        continue
                    files_api_url = ''
                    try:
                        files_api_url = url_for('vuln_catalog_pack_item_files', catalog_id=catalog_id, item_id=int(item.get('id') or 0))
                    except Exception:
                        files_api_url = ''
                    items.append(
                        {
                            'Name': _display_name(item),
                            'Path': os_module.path.abspath(abs_compose),
                            'Type': 'docker-compose',
                            'Vector': '',
                            'Startup': '',
                            'CVE': '',
                            'Description': '',
                            'References': '',
                            'id': str(item.get('id') or '').strip(),
                            'from_source': from_source,
                            'files_api_url': files_api_url,
                            'validated_ok': bool(item.get('validated_ok')) if item.get('validated_ok') is not None else None,
                            'validated_at': str(item.get('validated_at') or '').strip() or None,
                            'eligible_for_selection': bool(item.get('validated_ok') is True and item.get('validated_incomplete') is not True),
                        }
                    )
            else:
                items = []

            types = sorted({str(item.get('Type') or '').strip() for item in items if str(item.get('Type') or '').strip()})
            vectors = sorted({str(item.get('Vector') or '').strip() for item in items if str(item.get('Vector') or '').strip()})
            return jsonify({'types': types, 'vectors': vectors, 'items': items})
        except Exception as exc:
            return jsonify({'error': str(exc), 'types': [], 'vectors': [], 'items': []}), 500

    mark_routes_registered(app, 'vuln_catalog_api_routes')