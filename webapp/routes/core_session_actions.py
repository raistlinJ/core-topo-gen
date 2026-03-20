from __future__ import annotations

import os
from typing import Any, Callable

from flask import flash, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    redirect_core_page_with_scenario: Callable[..., Any],
    core_config_for_request: Callable[..., dict[str, Any]],
    execute_remote_core_session_action: Callable[..., None],
    uploads_dir: Callable[[], str],
    outputs_dir: Callable[[], str],
    update_xml_session_mapping: Callable[[str, int | None], None],
) -> None:
    if not begin_route_registration(app, 'core_session_actions_routes'):
        return

    def _core_start_session_view():
        sid = request.form.get('session_id')
        if not sid:
            flash('Missing session id')
            return redirect_core_page_with_scenario()
        try:
            sid_int = int(sid)
        except Exception:
            flash('Invalid session id')
            return redirect_core_page_with_scenario()
        core_cfg = core_config_for_request(include_password=True)
        try:
            execute_remote_core_session_action(core_cfg, 'start', sid_int, logger=app.logger)
            flash(f'Started session {sid_int}.')
        except Exception as exc:
            flash(f'Failed to start session: {exc}')
        return redirect_core_page_with_scenario()

    def _core_delete_view():
        sid = request.form.get('session_id')
        xml_path = request.form.get('path')
        if sid:
            try:
                sid_int = int(sid)
                core_cfg = core_config_for_request(include_password=True)
                execute_remote_core_session_action(core_cfg, 'delete', sid_int, logger=app.logger)
                flash(f'Deleted session {sid_int}.')
            except Exception as exc:
                flash(f'Failed to delete session: {exc}')
        if xml_path:
            ap = os.path.abspath(xml_path)
            try:
                allowed = [os.path.abspath(uploads_dir()), os.path.abspath(outputs_dir())]
                if any(ap.startswith(root + os.sep) or ap == root for root in allowed):
                    try:
                        os.remove(ap)
                        flash('Deleted XML file.')
                    except FileNotFoundError:
                        pass
                    except Exception as exc:
                        flash(f'Failed deleting XML: {exc}')
                    update_xml_session_mapping(ap, None)
                else:
                    flash('Refusing to delete file outside outputs/ or uploads/.')
            except Exception:
                pass
        return redirect_core_page_with_scenario()

    app.add_url_rule('/core/start_session', endpoint='core_start_session', view_func=_core_start_session_view, methods=['POST'])
    app.add_url_rule('/core/delete', endpoint='core_delete', view_func=_core_delete_view, methods=['POST'])
    mark_routes_registered(app, 'core_session_actions_routes')