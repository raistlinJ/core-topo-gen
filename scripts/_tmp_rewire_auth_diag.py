from pathlib import Path

p = Path('/Users/jcacosta/Documents/core-topo-gen/webapp/app_backend.py')
t = p.read_text()
orig = t

diag_marker = "# Diagnostic endpoint for environment/module troubleshooting\n"
diag_block = (
    "try:\n"
    "    from webapp.routes import diagnostics_health as _diagnostics_health_routes\n\n"
    "    _diagnostics_health_routes.register(\n"
    "        app,\n"
    "        current_user_getter=_current_user,\n"
    "        is_admin_view_role=_is_admin_view_role,\n"
    "        normalize_role_value=_normalize_role_value,\n"
    "        ui_view_allowed=_UI_VIEW_ALLOWED,\n"
    "        ui_view_default=_UI_VIEW_DEFAULT,\n"
    "        admin_view_roles=_ADMIN_VIEW_ROLES,\n"
    "        ui_view_session_key=_UI_VIEW_SESSION_KEY,\n"
    "        urlparse_func=urlparse,\n"
    "        parse_qs_func=parse_qs,\n"
    "        resolve_ui_view_redirect_target=_resolve_ui_view_redirect_target,\n"
    "    )\n"
    "except Exception:\n"
    "    pass\n\n\n"
)

if "from webapp.routes import diagnostics_health as _diagnostics_health_routes" not in t:
    if diag_marker not in t:
        raise SystemExit('diagnostics marker not found')
    t = t.replace(diag_marker, diag_marker + diag_block, 1)

auth_marker = "@app.route('/login', methods=['GET', 'POST'])\n"
auth_block = (
    "try:\n"
    "    from webapp.routes import auth_users as _auth_users_routes\n\n"
    "    _auth_users_routes.register(\n"
    "        app,\n"
    "        load_users=_load_users,\n"
    "        save_users=_save_users,\n"
    "        require_admin=_require_admin,\n"
    "        current_user_getter=_current_user,\n"
    "        set_current_user=_set_current_user,\n"
    "        normalize_role_value=_normalize_role_value,\n"
    "        allowed_user_roles=lambda: set(_ALLOWED_USER_ROLES),\n"
    "        normalize_scenario_label=_normalize_scenario_label,\n"
    "        normalize_scenario_assignments=_normalize_scenario_assignments,\n"
    "        scenario_catalog_for_user=_scenario_catalog_for_user,\n"
    "        default_ui_view_mode_for_role=_default_ui_view_mode_for_role,\n"
    "        is_participant_role=_is_participant_role,\n"
    "        ui_view_session_key=_UI_VIEW_SESSION_KEY,\n"
    "    )\n"
    "except Exception:\n"
    "    pass\n\n\n"
)

if "from webapp.routes import auth_users as _auth_users_routes" not in t:
    if auth_marker not in t:
        raise SystemExit('auth marker not found')
    t = t.replace(auth_marker, auth_block + auth_marker, 1)

for dec in [
    "@app.route('/diag/modules')\n",
    "@app.route('/ui-view', methods=['POST'])\n",
    "@app.route('/login', methods=['GET', 'POST'])\n",
    "@app.route('/logout', methods=['POST', 'GET'])\n",
    "@app.route('/users', methods=['GET'])\n",
    "@app.route('/users', methods=['POST'])\n",
    "@app.route('/users/delete/<username>', methods=['POST'])\n",
    "@app.route('/users/password/<username>', methods=['POST'])\n",
    "@app.route('/users/role/<username>', methods=['POST'])\n",
    "@app.route('/users/scenarios/<username>', methods=['POST'])\n",
    "@app.route('/me/password', methods=['GET', 'POST'])\n",
    "@app.route('/healthz')\n",
    "@app.route('/favicon.ico')\n",
]:
    t = t.replace(dec, '')

if t != orig:
    p.write_text(t)
    print('updated')
else:
    print('nochange')
