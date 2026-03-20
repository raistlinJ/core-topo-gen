from __future__ import annotations

import os
from typing import Callable

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, derive_seed_for_scenario: Callable[[str, str], int], logger=None) -> None:
    if not begin_route_registration(app, 'seed_hints_routes'):
        return

    def _seed_hints_view():
        try:
            payload = request.get_json(silent=True) or {}
            xml_path = (payload.get('xml_path') or '').strip()
            scenarios = payload.get('scenarios') or []
            if not xml_path:
                return jsonify({'ok': False, 'error': 'xml_path missing'}), 400
            xml_path_abs = os.path.abspath(xml_path)
            if not os.path.exists(xml_path_abs):
                return jsonify({'ok': False, 'error': f'XML not found: {xml_path_abs}'}), 404

            try:
                from core_topo_gen.planning.plan_cache import hash_xml_file

                xml_hash = hash_xml_file(xml_path_abs)
            except Exception as exc:
                return jsonify({'ok': False, 'error': f'Failed to hash XML: {exc}'}), 500

            seeds: dict[str, int] = {}
            if isinstance(scenarios, list):
                for raw in scenarios:
                    try:
                        name = (str(raw) if raw is not None else '').strip()
                        if not name:
                            continue
                        key = name.lower()
                        if key in seeds:
                            continue
                        seeds[key] = derive_seed_for_scenario(xml_hash, name)
                    except Exception:
                        continue
            return jsonify({'ok': True, 'xml_path': xml_path_abs, 'xml_hash': xml_hash, 'seeds': seeds})
        except Exception as exc:
            try:
                if logger is not None:
                    logger.exception('[seed_hints] error: %s', exc)
            except Exception:
                pass
            return jsonify({'ok': False, 'error': str(exc)}), 500

    app.add_url_rule('/api/seed_hints', endpoint='api_seed_hints', view_func=_seed_hints_view, methods=['POST'])
    mark_routes_registered(app, 'seed_hints_routes')