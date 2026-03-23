from __future__ import annotations

from typing import Any, Callable

from flask import render_template

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    load_installed_generator_packs_state: Callable[[], dict],
) -> None:
    if not begin_route_registration(app, 'flag_catalog_pages_routes'):
        return

    @app.route('/flag_catalog')
    def flag_catalog_page():
        packs_state = load_installed_generator_packs_state()
        try:
            packs = packs_state.get('packs', []) if isinstance(packs_state, dict) else []
            for pack in packs:
                if not isinstance(pack, dict):
                    continue
                installed = pack.get('installed')
                if not isinstance(installed, list):
                    continue
                grouped: dict[str, list[str]] = {}
                for item in installed:
                    if not isinstance(item, dict):
                        continue
                    kind = str(item.get('kind') or '').strip()
                    gid = str(item.get('id') or '').strip()
                    if not kind or not gid:
                        continue
                    grouped.setdefault(kind, []).append(gid)
                installed_grouped = []
                for kind, ids in grouped.items():
                    uniq_ids = []
                    seen = set()
                    for value in ids:
                        if value in seen:
                            continue
                        seen.add(value)
                        uniq_ids.append(value)
                    installed_grouped.append({'kind': kind, 'ids': uniq_ids, 'count': len(uniq_ids)})
                if installed_grouped:
                    pack['installed_grouped'] = installed_grouped
        except Exception:
            pass
        return render_template(
            'flag_catalog.html',
            packs=packs_state.get('packs', []),
            active_page='flag_catalog',
        )

    @app.route('/data_sources')
    def data_sources_page():
        return render_template('data_sources.html', active_page='')

    mark_routes_registered(app, 'flag_catalog_pages_routes')