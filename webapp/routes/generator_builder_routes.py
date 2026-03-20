from __future__ import annotations

from typing import Any, Callable

from flask import jsonify, render_template, request, send_file

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    require_builder_or_admin: Callable[[], None],
    flag_generators_from_enabled_sources: Callable[[], tuple[list[dict], list[dict]]],
    flag_node_generators_from_enabled_sources: Callable[[], tuple[list[dict], list[dict]]],
    reserved_artifacts: dict[str, dict[str, Any]],
    load_custom_artifacts: Callable[[], dict[str, dict[str, Any]]],
    upsert_custom_artifact: Callable[..., dict[str, Any]],
    build_generator_scaffold: Callable[[dict[str, Any]], tuple[dict[str, str], str, str]],
    sanitize_id: Callable[[Any], str],
    io_module: Any,
    zipfile_module: Any,
) -> None:
    if not begin_route_registration(app, 'generator_builder_routes'):
        return

    @app.route('/generator_builder')
    def generator_builder_page():
        require_builder_or_admin()
        return render_template('generator_builder.html', active_page='generator_builder')

    @app.route('/api/generators/artifacts_index')
    def api_generators_artifacts_index():
        require_builder_or_admin()
        try:
            flag_gens, _errs1 = flag_generators_from_enabled_sources()
            node_gens, _errs2 = flag_node_generators_from_enabled_sources()

            idx: dict[str, dict[str, Any]] = {}

            def _add_from(gens: list[dict], plugin_type: str) -> None:
                for g in gens:
                    if not isinstance(g, dict):
                        continue
                    gid = str(g.get('id') or '').strip()
                    gname = str(g.get('name') or '').strip() or gid
                    outs = g.get('outputs') if isinstance(g.get('outputs'), list) else []
                    for o in outs:
                        if not isinstance(o, dict):
                            continue
                        art = str(o.get('name') or '').strip()
                        if not art:
                            continue
                        tp = str(o.get('type') or '').strip()
                        desc = str(o.get('description') or '').strip()
                        sensitive = o.get('sensitive') is True
                        entry = idx.get(art)
                        if not entry:
                            entry = {'artifact': art, 'type': tp, 'description': desc, 'sensitive': sensitive, 'producers': []}
                            idx[art] = entry
                        if not entry.get('type') and tp:
                            entry['type'] = tp
                        if not str(entry.get('description') or '').strip() and desc:
                            entry['description'] = desc
                        if entry.get('sensitive') is not True and sensitive is True:
                            entry['sensitive'] = True
                        producers = entry.get('producers') if isinstance(entry.get('producers'), list) else []
                        if not any((p.get('plugin_id') == gid and p.get('plugin_type') == plugin_type) for p in producers if isinstance(p, dict)):
                            producers.append({'plugin_id': gid, 'plugin_type': plugin_type, 'name': gname})
                        entry['producers'] = producers

            _add_from(flag_gens, 'flag-generator')
            _add_from(node_gens, 'flag-node-generator')

            try:
                for art, meta in reserved_artifacts.items():
                    if art not in idx:
                        idx[art] = {
                            'artifact': art,
                            'type': str(meta.get('type') or '').strip(),
                            'description': str(meta.get('description') or '').strip(),
                            'sensitive': meta.get('sensitive') is True,
                            'producers': [{'plugin_id': '(reserved)', 'plugin_type': 'reserved', 'name': 'Reserved'}],
                        }
                    else:
                        if not str(idx[art].get('type') or '').strip() and str(meta.get('type') or '').strip():
                            idx[art]['type'] = str(meta.get('type') or '').strip()
                        if not str(idx[art].get('description') or '').strip() and str(meta.get('description') or '').strip():
                            idx[art]['description'] = str(meta.get('description') or '').strip()
                        if idx[art].get('sensitive') is not True and meta.get('sensitive') is True:
                            idx[art]['sensitive'] = True
            except Exception:
                pass

            try:
                custom = load_custom_artifacts()
                for art, meta in custom.items():
                    if art not in idx:
                        idx[art] = {'artifact': art, 'type': str(meta.get('type') or '').strip(), 'producers': []}
                    else:
                        if not str(idx[art].get('type') or '').strip() and str(meta.get('type') or '').strip():
                            idx[art]['type'] = str(meta.get('type') or '').strip()
            except Exception:
                pass

            artifacts = sorted(idx.values(), key=lambda x: str(x.get('artifact') or ''))
            return jsonify({'ok': True, 'artifacts': artifacts})
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 500

    @app.route('/api/generators/artifacts_index/custom', methods=['POST'])
    def api_generators_artifacts_index_custom_add():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        try:
            artifact = str(payload.get('artifact') or '').strip()
            type_value = str(payload.get('type') or '').strip() or None
            item = upsert_custom_artifact(artifact, type_value=type_value)
            return jsonify({'ok': True, 'artifact': item})
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 400

    @app.route('/api/generators/scaffold_meta', methods=['POST'])
    def api_generators_scaffold_meta():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        try:
            scaffold_files, manifest_yaml, _folder_path = build_generator_scaffold(payload)
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 400
        return jsonify({
            'ok': True,
            'manifest_yaml': manifest_yaml,
            'scaffold_paths': sorted(scaffold_files.keys()),
        })

    @app.route('/api/generators/scaffold_zip', methods=['POST'])
    def api_generators_scaffold_zip():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        try:
            scaffold_files, _manifest_yaml, _folder_path = build_generator_scaffold(payload)
            plugin_id = sanitize_id(payload.get('plugin_id')) or 'generator'
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 400

        mem = io_module.BytesIO()
        with zipfile_module.ZipFile(mem, 'w', zipfile_module.ZIP_DEFLATED) as zf:
            for path, content in scaffold_files.items():
                zf.writestr(path, content)
        mem.seek(0)
        return send_file(
            mem,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'generator_scaffold_{plugin_id}.zip',
        )

    mark_routes_registered(app, 'generator_builder_routes')