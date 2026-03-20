from __future__ import annotations

from typing import Any

from webapp import flow_prepare_preview_execute
from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'flag_sequencing_prepare_preview_routes'):
        return

    backend = backend_module

    @app.route('/api/flag-sequencing/prepare_preview_for_execute', methods=['POST'])
    def api_flow_prepare_preview_for_execute():
        return flow_prepare_preview_execute.execute(backend=backend)

    mark_routes_registered(app, 'flag_sequencing_prepare_preview_routes')