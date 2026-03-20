from __future__ import annotations

from typing import Callable

from flask import jsonify

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    flag_generators_from_enabled_sources: Callable[[], tuple[list[dict], list[dict]]],
    flag_node_generators_from_enabled_sources: Callable[[], tuple[list[dict], list[dict]]],
    is_installed_generator_view: Callable[[dict], bool],
    annotate_disabled_state: Callable[..., list[dict]],
) -> None:
    if not begin_route_registration(app, 'generator_catalog_data_routes'):
        return

    @app.route('/flag_generators_data')
    def flag_generators_data():
        try:
            generators, errors = flag_generators_from_enabled_sources()
            generators = [g for g in (generators or []) if isinstance(g, dict) and is_installed_generator_view(g)]
            generators = annotate_disabled_state(generators, kind='flag-generator')
            return jsonify({'generators': generators, 'errors': errors})
        except Exception as exc:
            return jsonify({'generators': [], 'errors': [{'error': str(exc)}]}), 500

    @app.route('/flag_node_generators_data')
    def flag_node_generators_data():
        try:
            generators, errors = flag_node_generators_from_enabled_sources()
            generators = [g for g in (generators or []) if isinstance(g, dict) and is_installed_generator_view(g)]
            generators = annotate_disabled_state(generators, kind='flag-node-generator')
            return jsonify({'generators': generators, 'errors': errors})
        except Exception as exc:
            return jsonify({'generators': [], 'errors': [{'error': str(exc)}]}), 500

    mark_routes_registered(app, 'generator_catalog_data_routes')