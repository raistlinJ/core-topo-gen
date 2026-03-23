from __future__ import annotations

import json
from typing import Callable

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, require_builder_or_admin: Callable[[], None], logger=None) -> None:
    if not begin_route_registration(app, 'client_exec_diag_routes'):
        return

    def _client_exec_diag_view():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({'ok': False, 'error': 'invalid payload'}), 400
        try:
            stage = str(payload.get('stage') or '').strip() or 'unknown'
            reason = str(payload.get('reason') or '').strip() or 'unknown'
            message = str(payload.get('message') or '').strip()
            code = payload.get('code')
            status = payload.get('status')
            ready_state = payload.get('readyState')
            run_id = str(payload.get('run_id') or '').strip()
            url = str(payload.get('url') or payload.get('responseURL') or '').strip()
            attempts = payload.get('attempts')
            if logger is not None:
                logger.error(
                    '[client-exec-diag] stage=%s reason=%s message=%s code=%s status=%s readyState=%s run_id=%s url=%s attempts=%s payload=%s',
                    stage,
                    reason,
                    message,
                    code,
                    status,
                    ready_state,
                    run_id,
                    url,
                    attempts,
                    json.dumps(payload, ensure_ascii=False),
                )
        except Exception:
            pass
        return jsonify({'ok': True})

    app.add_url_rule('/api/client_exec_diag', endpoint='api_client_exec_diag', view_func=_client_exec_diag_view, methods=['POST'])
    mark_routes_registered(app, 'client_exec_diag_routes')