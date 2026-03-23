from __future__ import annotations

from typing import Any, Callable

from flask import abort, jsonify, redirect, render_template, send_file, url_for

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    require_builder_or_admin: Callable[[], None],
    vuln_catalog_pack_zip_path: Callable[[str], str],
    vuln_catalog_pack_content_dir: Callable[[str], str],
    safe_path_under: Callable[[str, str], str],
    load_vuln_catalogs_state: Callable[[], dict],
    normalize_vuln_catalog_items: Callable[[dict], list[dict[str, Any]]],
    os_module: Any,
) -> None:
    if not begin_route_registration(app, 'vuln_catalog_pack_files_routes'):
        return

    @app.route('/vuln_catalog_packs/download/<catalog_id>')
    def vuln_catalog_packs_download(catalog_id: str):
        require_builder_or_admin()
        cid = str(catalog_id or '').strip()
        if not cid:
            abort(404)
        zip_path = vuln_catalog_pack_zip_path(cid)
        if not os_module.path.exists(zip_path):
            abort(404)
        return send_file(zip_path, as_attachment=True, download_name=f'vuln_catalog_{cid}.zip')

    @app.route('/vuln_catalog_packs/browse/<catalog_id>')
    @app.route('/vuln_catalog_packs/browse/<catalog_id>/<path:subpath>')
    def vuln_catalog_packs_browse(catalog_id: str, subpath: str = ''):
        require_builder_or_admin()
        cid = str(catalog_id or '').strip()
        if not cid:
            abort(404)
        base_dir = vuln_catalog_pack_content_dir(cid)
        if not os_module.path.isdir(base_dir):
            abort(404)

        try:
            cur_abs = safe_path_under(base_dir, subpath or '')
        except Exception:
            abort(400)

        if os_module.path.isfile(cur_abs):
            rel = os_module.path.relpath(cur_abs, base_dir).replace('\\', '/')
            return redirect(url_for('vuln_catalog_packs_file', catalog_id=cid, subpath=rel))
        if not os_module.path.isdir(cur_abs):
            abort(404)

        rel_dir = os_module.path.relpath(cur_abs, base_dir).replace('\\', '/')
        if rel_dir in ('.', ''):
            rel_dir = ''

        entries: list[dict[str, Any]] = []
        try:
            for name in sorted(os_module.listdir(cur_abs)):
                if name in ('.', '..'):
                    continue
                path = os_module.path.join(cur_abs, name)
                kind = 'dir' if os_module.path.isdir(path) else 'file'
                entries.append({'name': name, 'kind': kind})
        except Exception:
            entries = []

        crumbs: list[dict[str, str]] = [{'name': 'root', 'href': url_for('vuln_catalog_packs_browse', catalog_id=cid)}]
        if rel_dir:
            acc: list[str] = []
            for part in [piece for piece in rel_dir.split('/') if piece]:
                acc.append(part)
                crumbs.append({'name': part, 'href': url_for('vuln_catalog_packs_browse', catalog_id=cid, subpath='/'.join(acc))})

        return render_template(
            'vuln_catalog_browse.html',
            catalog_id=cid,
            rel_dir=rel_dir,
            entries=entries,
            crumbs=crumbs,
            active_page='vuln_catalog',
        )

    @app.route('/vuln_catalog_packs/file/<catalog_id>/<path:subpath>')
    def vuln_catalog_packs_file(catalog_id: str, subpath: str):
        require_builder_or_admin()
        cid = str(catalog_id or '').strip()
        if not cid:
            abort(404)
        base_dir = vuln_catalog_pack_content_dir(cid)
        if not os_module.path.isdir(base_dir):
            abort(404)
        try:
            abs_path = safe_path_under(base_dir, subpath or '')
        except Exception:
            abort(400)
        if not os_module.path.isfile(abs_path):
            abort(404)
        return send_file(abs_path, as_attachment=True, download_name=os_module.path.basename(abs_path))

    @app.route('/vuln_catalog_packs/view/<catalog_id>/<path:subpath>')
    def vuln_catalog_packs_view(catalog_id: str, subpath: str):
        require_builder_or_admin()
        cid = str(catalog_id or '').strip()
        if not cid:
            abort(404)
        base_dir = vuln_catalog_pack_content_dir(cid)
        if not os_module.path.isdir(base_dir):
            abort(404)
        try:
            abs_path = safe_path_under(base_dir, subpath or '')
        except Exception:
            abort(400)
        if not os_module.path.isfile(abs_path):
            abort(404)
        return send_file(abs_path, as_attachment=False, download_name=os_module.path.basename(abs_path))

    @app.route('/vuln_catalog_packs/readme/<catalog_id>/<path:subpath>')
    def vuln_catalog_packs_readme(catalog_id: str, subpath: str):
        require_builder_or_admin()
        cid = str(catalog_id or '').strip()
        if not cid:
            abort(404)
        base_dir = vuln_catalog_pack_content_dir(cid)
        if not os_module.path.isdir(base_dir):
            abort(404)
        try:
            abs_path = safe_path_under(base_dir, subpath or '')
        except Exception:
            abort(400)
        if not os_module.path.isfile(abs_path):
            abort(404)

        ext = os_module.path.splitext(abs_path)[1].lower().lstrip('.')
        if ext not in ('md', 'markdown', 'txt'):
            abort(404)

        try:
            with open(abs_path, 'r', encoding='utf-8', errors='replace') as handle:
                content = handle.read()
        except Exception:
            abort(404)

        readme_title = os_module.path.basename(abs_path)
        readme_rel = os_module.path.relpath(abs_path, base_dir).replace('\\', '/')

        def _rewrite_pack_relative_urls(*, html_in: str, readme_rel_path: str) -> str:
            import html as _html
            import posixpath as _posixpath
            from html.parser import HTMLParser as _HTMLParser
            from urllib.parse import urlparse as _urlparse

            base_rel_dir = _posixpath.dirname(readme_rel_path or '')

            def _is_relative_url(url: str) -> bool:
                url = (url or '').strip()
                if not url or url.startswith('#') or url.startswith('/'):
                    return False
                parsed = _urlparse(url)
                return not bool(parsed.scheme)

            def _resolve_rel(url: str) -> str | None:
                url = (url or '').strip().replace('\\', '/')
                if not url or url.startswith('/'):
                    return None
                resolved = _posixpath.normpath(_posixpath.join(base_rel_dir, url))
                if resolved in ('', '.') or resolved.startswith('..'):
                    return None
                return resolved

            def _rewrite_href(url: str) -> str:
                if not _is_relative_url(url):
                    return url
                resolved = _resolve_rel(url)
                if not resolved:
                    return url
                ext2 = os_module.path.splitext(resolved)[1].lower().lstrip('.')
                if ext2 in ('md', 'markdown', 'txt'):
                    return url_for('vuln_catalog_packs_readme', catalog_id=cid, subpath=resolved)
                return url_for('vuln_catalog_packs_view', catalog_id=cid, subpath=resolved)

            def _rewrite_src(url: str) -> str:
                if not _is_relative_url(url):
                    return url
                resolved = _resolve_rel(url)
                if not resolved:
                    return url
                return url_for('vuln_catalog_packs_view', catalog_id=cid, subpath=resolved)

            class _Rewriter(_HTMLParser):
                def __init__(self) -> None:
                    super().__init__(convert_charrefs=False)
                    self._out: list[str] = []

                def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
                    self._emit_tag(tag, attrs, closed=False)

                def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
                    self._emit_tag(tag, attrs, closed=True)

                def _emit_tag(self, tag: str, attrs: list[tuple[str, str | None]], *, closed: bool) -> None:
                    tag_l = (tag or '').lower()
                    new_attrs: list[tuple[str, str | None]] = []
                    for key, value in (attrs or []):
                        if not key:
                            continue
                        key_l = key.lower()
                        if value is not None and tag_l == 'a' and key_l == 'href':
                            value = _rewrite_href(value)
                        elif value is not None and tag_l == 'img' and key_l == 'src':
                            value = _rewrite_src(value)
                        new_attrs.append((key, value))
                    self._out.append('<')
                    self._out.append(tag)
                    for key, value in new_attrs:
                        if value is None:
                            self._out.append(f' {key}')
                        else:
                            self._out.append(f' {key}="{_html.escape(str(value), quote=True)}"')
                    self._out.append(' />' if closed else '>')

                def handle_endtag(self, tag: str) -> None:
                    self._out.append(f'</{tag}>')

                def handle_data(self, data: str) -> None:
                    self._out.append(data)

                def handle_entityref(self, name: str) -> None:
                    self._out.append(f'&{name};')

                def handle_charref(self, name: str) -> None:
                    self._out.append(f'&#{name};')

                def handle_comment(self, data: str) -> None:
                    self._out.append(f'<!--{data}-->')

                def handle_decl(self, decl: str) -> None:
                    self._out.append(f'<!{decl}>')

            parser = _Rewriter()
            try:
                parser.feed(html_in or '')
                parser.close()
            except Exception:
                return html_in
            return ''.join(parser._out)

        rendered_html = ''
        plain_text = ''
        render_warning = ''
        if ext == 'txt':
            plain_text = content
        else:
            try:
                import markdown as _markdown  # type: ignore
            except Exception:
                _markdown = None
            try:
                import bleach as _bleach  # type: ignore
            except Exception:
                _bleach = None

            if _markdown is None or _bleach is None:
                plain_text = content
                missing = []
                if _markdown is None:
                    missing.append('Markdown')
                if _bleach is None:
                    missing.append('bleach')
                render_warning = f"Markdown rendering unavailable (missing: {', '.join(missing)})." if missing else 'Markdown rendering unavailable.'
                render_warning += ' Showing plain text.'
            else:
                html = _markdown.markdown(content, extensions=['fenced_code', 'tables', 'sane_lists'], output_format='html5')
                html = _rewrite_pack_relative_urls(html_in=html, readme_rel_path=readme_rel)
                allowed_tags = ['a', 'p', 'br', 'hr', 'strong', 'em', 'code', 'pre', 'blockquote', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'img']
                allowed_attrs = {'a': ['href', 'title', 'target', 'rel'], 'code': ['class'], 'pre': ['class'], 'th': ['align'], 'td': ['align'], 'img': ['src', 'alt', 'title']}
                rendered_html = _bleach.clean(html, tags=allowed_tags, attributes=allowed_attrs, protocols=['http', 'https', 'mailto'], strip=True)

        return render_template(
            'vuln_catalog_readme.html',
            active_page='vuln_catalog',
            catalog_id=cid,
            readme_title=readme_title,
            readme_rel=readme_rel,
            rendered_html=rendered_html,
            plain_text=plain_text,
            render_warning=render_warning,
        )

    @app.route('/vuln_catalog_packs/item_files/<catalog_id>/<int:item_id>')
    def vuln_catalog_pack_item_files(catalog_id: str, item_id: int):
        require_builder_or_admin()
        cid = str(catalog_id or '').strip()
        if not cid:
            return jsonify({'ok': False, 'error': 'Missing catalog id'}), 404

        state = load_vuln_catalogs_state()
        entry = None
        for catalog in (state.get('catalogs') or []):
            if isinstance(catalog, dict) and str(catalog.get('id') or '').strip() == cid:
                entry = catalog
                break
        if not entry:
            return jsonify({'ok': False, 'error': 'Unknown catalog id'}), 404

        items = normalize_vuln_catalog_items(entry)
        target = None
        for item in items:
            try:
                if int(item.get('id') or 0) == int(item_id):
                    target = item
                    break
            except Exception:
                continue
        if not target:
            return jsonify({'ok': False, 'error': 'Unknown item id'}), 404

        base_dir = vuln_catalog_pack_content_dir(cid)
        if not os_module.path.isdir(base_dir):
            return jsonify({'ok': False, 'error': 'Pack content missing'}), 404

        rel_dir = str(target.get('rel_dir') or target.get('dir_rel') or '').strip().replace('\\', '/')
        try:
            abs_dir = safe_path_under(base_dir, rel_dir)
        except Exception:
            return jsonify({'ok': False, 'error': 'Invalid item path'}), 400
        if not os_module.path.isdir(abs_dir):
            return jsonify({'ok': False, 'error': 'Item directory missing'}), 404

        files: list[dict[str, str]] = []
        try:
            for name in sorted(os_module.listdir(abs_dir)):
                if name in ('.', '..'):
                    continue
                abs_path = os_module.path.join(abs_dir, name)
                if not os_module.path.isfile(abs_path):
                    continue
                rel = os_module.path.relpath(abs_path, base_dir).replace('\\', '/')
                files.append({'name': name, 'url': url_for('vuln_catalog_packs_file', catalog_id=cid, subpath=rel)})
        except Exception:
            files = []

        return jsonify({'ok': True, 'catalog_id': cid, 'item_id': int(item_id), 'files': files})

    mark_routes_registered(app, 'vuln_catalog_pack_files_routes')