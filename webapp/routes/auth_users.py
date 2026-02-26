from __future__ import annotations

from typing import Any, Callable

from flask import flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


def register(
    app,
    *,
    load_users: Callable[[], dict[str, Any]],
    save_users: Callable[[dict[str, Any]], Any],
    require_admin: Callable[[], bool],
    current_user_getter: Callable[[], dict[str, Any] | None],
    set_current_user: Callable[[dict[str, Any] | None], Any],
    normalize_role_value: Callable[[Any], str],
    allowed_user_roles: Callable[[], set[str]],
    normalize_scenario_label: Callable[[Any], str],
    normalize_scenario_assignments: Callable[[Any], list[str]],
    scenario_catalog_for_user: Callable[..., Any],
    default_ui_view_mode_for_role: Callable[[str], str],
    is_participant_role: Callable[[str], bool],
    ui_view_session_key: str,
) -> None:
    """Register authentication + user management routes.

    Extracted from `webapp.app_backend`.

    Important: most dependencies are injected so tests that monkeypatch
    `webapp.app_backend` symbols continue to work.
    """

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if not username or not password:
            flash("Username and password required")
            return render_template("login.html", error=True), 400

        db = load_users()
        users = db.get("users", [])
        user = next((u for u in users if u.get("username") == username), None)
        if user and check_password_hash(user.get("password_hash", ""), password):
            role_value = normalize_role_value(user.get("role"))
            set_current_user({"username": user.get("username"), "role": role_value})
            session.permanent = True
            try:
                session[ui_view_session_key] = default_ui_view_mode_for_role(role_value)
            except Exception:
                pass
            if is_participant_role(role_value):
                return redirect(url_for("participant_ui_page"))
            return redirect(url_for("index"))

        flash("Invalid username or password")
        return render_template("login.html", error=True), 401

    @app.route("/logout", methods=["POST", "GET"])
    def logout():
        set_current_user(None)
        return redirect(url_for("login"))

    @app.route("/users", methods=["GET"])
    def users_page():
        if not require_admin():
            return redirect(url_for("index"))

        db = load_users()
        raw_users = db.get("users", [])
        admin_count = sum(
            1
            for entry in raw_users
            if isinstance(entry, dict) and normalize_role_value(entry.get("role")) == "admin"
        )

        scenario_names, _scenario_paths, _scenario_url_hints = scenario_catalog_for_user(user=current_user_getter())
        scenario_options: list[dict[str, str]] = []
        display_by_norm: dict[str, str] = {}
        for display_name in scenario_names:
            norm = normalize_scenario_label(display_name)
            if not norm:
                continue
            display_by_norm[norm] = display_name
            scenario_options.append({"value": norm, "label": display_name})
        scenario_options.sort(key=lambda o: o["label"].lower())

        users_out: list[dict[str, Any]] = []
        for entry in raw_users:
            if not isinstance(entry, dict):
                continue
            normalized = dict(entry)
            normalized["role"] = normalize_role_value(entry.get("role"))
            assigned = normalize_scenario_assignments(entry.get("scenarios"))
            normalized["assigned_scenarios"] = assigned
            normalized["assigned_scenarios_display"] = [display_by_norm.get(norm, norm) for norm in assigned]
            is_only_admin = normalized["role"] == "admin" and admin_count <= 1
            normalized["role_locked"] = is_only_admin
            if is_only_admin:
                normalized["role_locked_reason"] = "At least one admin must remain."
            else:
                normalized["role_locked_reason"] = ""
            users_out.append(normalized)

        return render_template(
            "users.html",
            users=users_out,
            scenario_options=scenario_options,
            scenario_lookup=display_by_norm,
            self_change=False,
        )

    @app.route("/users", methods=["POST"])
    def users_create():
        if not require_admin():
            return redirect(url_for("index"))

        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        role = normalize_role_value(request.form.get("role"))
        scenarios = normalize_scenario_assignments(request.form.getlist("scenarios"))
        if not username or not password:
            flash("Username and password required")
            return redirect(url_for("users_page"))

        db = load_users()
        users = db.get("users", [])
        if any(u.get("username") == username for u in users):
            flash("Username already exists")
            return redirect(url_for("users_page"))

        users.append(
            {
                "username": username,
                "password_hash": generate_password_hash(password),
                "role": role,
                "scenarios": scenarios,
            }
        )
        db["users"] = users
        save_users(db)
        flash("User created")
        return redirect(url_for("users_page"))

    @app.route("/users/delete/<username>", methods=["POST"])
    def users_delete(username: str):
        if not require_admin():
            return redirect(url_for("users_page"))

        username = (username or "").strip()
        if not username:
            flash("Invalid username")
            return redirect(url_for("users_page"))

        cur = current_user_getter()
        db = load_users()
        users = db.get("users", [])
        remain = [u for u in users if u.get("username") != username]
        if cur and username == cur.get("username"):
            flash("Cannot delete your own account")
            return redirect(url_for("users_page"))
        if not any(u.get("role") == "admin" for u in remain):
            flash("At least one admin must remain")
            return redirect(url_for("users_page"))

        db["users"] = remain
        save_users(db)
        flash("User deleted")
        return redirect(url_for("users_page"))

    @app.route("/users/password/<username>", methods=["POST"])
    def users_password(username: str):
        if not require_admin():
            return redirect(url_for("users_page"))

        new_pwd = request.form.get("password") or ""
        if not new_pwd:
            flash("New password required")
            return redirect(url_for("users_page"))

        db = load_users()
        changed = False
        for u in db.get("users", []):
            if u.get("username") == username:
                u["password_hash"] = generate_password_hash(new_pwd)
                changed = True
                break

        if changed:
            save_users(db)
            flash("Password updated")
        else:
            flash("User not found")

        return redirect(url_for("users_page"))

    @app.route("/users/role/<username>", methods=["POST"])
    def users_update_role(username: str):
        if not require_admin():
            return redirect(url_for("users_page"))

        username = (username or "").strip()
        role_value = normalize_role_value(request.form.get("role"))
        if not username or role_value not in allowed_user_roles():
            flash("Invalid role update request")
            return redirect(url_for("users_page"))

        db = load_users()
        users = db.get("users", [])
        target = next((u for u in users if u.get("username") == username), None)
        if not target:
            flash("User not found")
            return redirect(url_for("users_page"))

        current_role = normalize_role_value(target.get("role"))
        if current_role == role_value:
            flash("Role unchanged")
            return redirect(url_for("users_page"))

        if current_role == "admin" and role_value != "admin":
            has_other_admin = any(
                normalize_role_value(u.get("role")) == "admin" and u.get("username") != username
                for u in users
            )
            if not has_other_admin:
                flash("At least one admin must remain")
                return redirect(url_for("users_page"))

        target["role"] = role_value
        db["users"] = users
        save_users(db)

        cur = current_user_getter()
        if cur and cur.get("username") == username:
            set_current_user({"username": username, "role": role_value})

        flash(f"Role updated to {role_value}")
        return redirect(url_for("users_page"))

    @app.route("/users/scenarios/<username>", methods=["POST"])
    def users_assign_scenarios(username: str):
        if not require_admin():
            return redirect(url_for("users_page"))

        username = (username or "").strip()
        if not username:
            flash("Invalid username")
            return redirect(url_for("users_page"))

        selections = normalize_scenario_assignments(request.form.getlist("scenarios"))
        db = load_users()
        users = db.get("users", [])
        updated = False
        for entry in users:
            if entry.get("username") == username:
                entry["scenarios"] = selections
                updated = True
                break

        if updated:
            save_users(db)
            flash("Scenario assignments updated")
        else:
            flash("User not found")

        return redirect(url_for("users_page"))

    @app.route("/me/password", methods=["GET", "POST"])
    def me_password():
        if current_user_getter() is None:
            return redirect(url_for("login"))

        if request.method == "GET":
            return render_template("users.html", self_change=True)

        cur = current_user_getter() or {}
        cur_pwd = request.form.get("current_password") or ""
        new_pwd = request.form.get("password") or ""
        if not cur_pwd or not new_pwd:
            flash("Current and new passwords required")
            return redirect(url_for("me_password"))

        db = load_users()
        updated = False
        for u in db.get("users", []):
            if u.get("username") == cur.get("username"):
                if not check_password_hash(u.get("password_hash", ""), cur_pwd):
                    flash("Current password incorrect")
                    return redirect(url_for("me_password"))
                u["password_hash"] = generate_password_hash(new_pwd)
                updated = True
                break

        if updated:
            save_users(db)
            flash("Password changed")
        else:
            flash("User not found")

        return redirect(url_for("index"))
