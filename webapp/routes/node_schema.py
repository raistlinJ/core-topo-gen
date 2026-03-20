from __future__ import annotations

import os
from typing import Callable

from flask import jsonify, send_file

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, node_schema_authoring_path: Callable[[], str | None]) -> None:
    if not begin_route_registration(app, 'node_schema_routes'):
        return

    def _node_schema_authoring_yaml_view():
        path = node_schema_authoring_path()
        if not path or not os.path.isfile(path):
            return jsonify({'ok': False, 'error': 'schema not found'}), 404
        return send_file(
            path,
            mimetype='text/yaml; charset=utf-8',
            as_attachment=False,
            download_name='node_schema_authoring.yaml',
        )

    app.add_url_rule(
        '/schemas/node_authoring.yaml',
        endpoint='node_schema_authoring_yaml',
        view_func=_node_schema_authoring_yaml_view,
        methods=['GET'],
    )
    mark_routes_registered(app, 'node_schema_routes')