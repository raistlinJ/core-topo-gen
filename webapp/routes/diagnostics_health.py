from __future__ import annotations

import os
from typing import Any, Callable

from flask import Response, abort, jsonify, redirect, request, session, url_for


def register(
    app,
    *,
    current_user_getter: Callable[[], dict[str, Any] | None],
    is_admin_view_role: Callable[[Any], bool],
    normalize_role_value: Callable[[Any], str],
    ui_view_allowed: set[str],
    ui_view_default: str,
    admin_view_roles: set[str],
    ui_view_session_key: str,
    urlparse_func: Callable[[str], Any],
    parse_qs_func: Callable[[str], dict[str, list[str]]],
    resolve_ui_view_redirect_target: Callable[[str | None], str],
) -> None:
    """Register diagnostics and health routes extracted from app_backend."""

    @app.route('/diag/modules')
    def diag_modules():
        out: dict[str, Any] = {}
        try:
            import core_topo_gen as ctg  # type: ignore
            out['core_topo_gen.__file__'] = getattr(ctg, '__file__', None)
        except Exception as e:
            out['core_topo_gen_error'] = str(e)
        try:
            import core_topo_gen.planning as plan_pkg  # type: ignore
            planning_file = getattr(plan_pkg, '__file__', None)
            out['planning_dir'] = os.path.dirname(planning_file) if planning_file else None
            if not planning_file:
                out['planning_file_is_none'] = True
        except Exception as e:
            out['planning_import_error'] = str(e)
        return jsonify(out)

    @app.route('/ui-view', methods=['POST'])
    def set_ui_view_mode():
        user = current_user_getter()
        if not user or not is_admin_view_role(user.get('role')):
            abort(403)

        requested = (request.form.get('mode') or '').strip().lower()
        if requested not in ui_view_allowed:
            requested = ui_view_default

        role = normalize_role_value(user.get('role'))
        if role == 'builder' and requested == 'admin':
            requested = 'builder'
        if role not in admin_view_roles:
            requested = ui_view_default

        session[ui_view_session_key] = requested
        target = request.form.get('next') or request.referrer

        scenario_hint = ''
        if target:
            try:
                parsed_target = urlparse_func(target)
                query_params = parse_qs_func(parsed_target.query or '')
                scenario_hint = (query_params.get('scenario', [''])[0] or '').strip()
            except Exception:
                scenario_hint = ''
        if not scenario_hint:
            try:
                scenario_hint = (request.form.get('scenario') or request.args.get('scenario') or '').strip()
            except Exception:
                scenario_hint = ''

        if requested == 'participant':
            redirect_target = url_for('participant_ui_page', scenario=scenario_hint) if scenario_hint else url_for('participant_ui_page')
        else:
            redirect_target = resolve_ui_view_redirect_target(target)
        return redirect(redirect_target)

    @app.route('/healthz')
    def healthz():
        return Response('ok', mimetype='text/plain')

    @app.route('/favicon.ico')
    def favicon():
        return ('', 204)
