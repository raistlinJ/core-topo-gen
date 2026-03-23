from __future__ import annotations

import glob
import io
import os
import tempfile
import zipfile
from typing import Callable

from flask import jsonify, request, send_file

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, logger=None) -> None:
    if not begin_route_registration(app, 'script_artifacts_routes'):
        return

    def _resolve_base_dir(kind: str, scope: str) -> tuple[str | None, str | None]:
        if kind not in ('traffic', 'segmentation'):
            return None, 'invalid kind'
        if scope == 'runtime':
            return ('/tmp/traffic' if kind == 'traffic' else '/tmp/segmentation'), None
        if scope == 'preview':
            pattern = 'core-topo-preview-traffic-*' if kind == 'traffic' else 'core-topo-preview-seg-*'
            candidates = sorted(
                glob.glob(os.path.join(tempfile.gettempdir(), pattern)),
                key=lambda path: os.path.getmtime(path),
                reverse=True,
            )
            return (candidates[0] if candidates else None), None
        return None, 'invalid scope'

    def _open_scripts_view():
        kind = request.args.get('kind', 'traffic').lower()
        scope = request.args.get('scope', 'runtime').lower()
        base_dir, error = _resolve_base_dir(kind, scope)
        if error == 'invalid kind':
            return jsonify({'ok': False, 'error': error}), 400
        if scope == 'preview' and not base_dir:
            pattern = 'core-topo-preview-traffic-*' if kind == 'traffic' else 'core-topo-preview-seg-*'
            return jsonify({'ok': False, 'error': 'no preview dir found for kind', 'pattern': pattern}), 404
        if not base_dir or not os.path.isdir(base_dir):
            return jsonify({'ok': False, 'error': 'directory does not exist', 'path': base_dir}), 404
        files = []
        try:
            for name in sorted(os.listdir(base_dir)):
                fp = os.path.join(base_dir, name)
                if not os.path.isfile(fp):
                    continue
                try:
                    size = os.path.getsize(fp)
                except Exception:
                    size = 0
                files.append({'file': name, 'size': size})
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 500
        return jsonify({'ok': True, 'kind': kind, 'path': base_dir, 'files': files})

    def _open_script_file_view():
        kind = request.args.get('kind', 'traffic').lower()
        scope = request.args.get('scope', 'runtime').lower()
        filename = request.args.get('file') or ''
        if kind not in ('traffic', 'segmentation'):
            return jsonify({'ok': False, 'error': 'invalid kind'}), 400
        if not filename or '/' in filename or '..' in filename:
            return jsonify({'ok': False, 'error': 'invalid filename'}), 400
        base_dir, error = _resolve_base_dir(kind, scope)
        if error == 'invalid scope':
            return jsonify({'ok': False, 'error': error}), 400
        if not base_dir or not os.path.isdir(base_dir):
            return jsonify({'ok': False, 'error': 'dir not found', 'path': base_dir}), 404
        file_path = os.path.join(base_dir, filename)
        if not os.path.isfile(file_path):
            return jsonify({'ok': False, 'error': 'file not found', 'file': filename}), 404
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as handle:
                content = handle.read(8000)
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 500
        return jsonify({'ok': True, 'file': filename, 'path': base_dir, 'content': content, 'truncated': len(content) == 8000})

    def _download_scripts_view():
        kind = request.args.get('kind', 'traffic').lower()
        scope = request.args.get('scope', 'runtime').lower()
        if kind not in ('traffic', 'segmentation'):
            return jsonify({'ok': False, 'error': 'invalid kind'}), 400
        if scope not in ('runtime', 'preview'):
            return jsonify({'ok': False, 'error': 'invalid scope'}), 400
        base_dir, _error = _resolve_base_dir(kind, scope)
        if not base_dir or not os.path.isdir(base_dir):
            return jsonify({'ok': False, 'error': 'directory not found'}), 404
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as archive:
            for root, _dirs, files in os.walk(base_dir):
                for file_name in files:
                    fp = os.path.join(root, file_name)
                    if not (file_name.endswith('.py') or file_name.endswith('.json')):
                        continue
                    arcname = os.path.relpath(fp, base_dir)
                    try:
                        archive.write(fp, arcname)
                    except Exception:
                        continue
        buf.seek(0)
        filename = f'{kind}_{scope}_scripts.zip'
        return send_file(buf, mimetype='application/zip', as_attachment=True, download_name=filename)

    app.add_url_rule('/api/open_scripts', endpoint='api_open_scripts', view_func=_open_scripts_view, methods=['GET'])
    app.add_url_rule('/api/open_script_file', endpoint='api_open_script_file', view_func=_open_script_file_view, methods=['GET'])
    app.add_url_rule('/api/download_scripts', endpoint='api_download_scripts', view_func=_download_scripts_view, methods=['GET'])
    mark_routes_registered(app, 'script_artifacts_routes')