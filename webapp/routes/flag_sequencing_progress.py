from __future__ import annotations

from typing import Any, Callable

from flask import jsonify

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    outputs_dir: Callable[[], str],
    os_module: Any,
) -> None:
    if not begin_route_registration(app, 'flag_sequencing_progress_routes'):
        return

    @app.route('/api/flag-sequencing/flow_progress', methods=['GET'])
    def api_flow_progress():
        try:
            port = int(os_module.environ.get('CORETG_PORT') or 9090)
        except Exception:
            port = 9090
        log_path = os_module.path.join(outputs_dir(), 'logs', f'webui-{port}.log')
        lines: list[str] = []
        try:
            if os_module.path.exists(log_path):
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as file_handle:
                    raw = file_handle.read().splitlines()[-400:]
                for line in raw:
                    if ('[flow.progress]' in line) or ('[flow.' in line) or ('[remote-sync]' in line) or ('Repo upload' in line):
                        lines.append(line.strip())
        except Exception:
            lines = []
        return jsonify({'ok': True, 'lines': lines})

    mark_routes_registered(app, 'flag_sequencing_progress_routes')