from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any, Callable

from flask import jsonify, request


def register(
    app,
    *,
    flag_base_dir: Callable[[], str],
    safe_name: Callable[[str], str],
    parse_github_url: Callable[[str], dict[str, Any]],
    vuln_repo_subdir: Callable[[], str],
    compose_candidates: Callable[[str], list[str]],
    get_repo_root: Callable[[], str],
) -> None:
    """Register /flag_compose/* endpoints."""

    def _flag_resolve_path(raw_path: str) -> str:
        """Resolve a flag path that may be repo-relative."""
        p = (raw_path or '').strip()
        if not p:
            return ''
        try:
            if p.startswith('file://'):
                p = p[len('file://'):]
        except Exception:
            pass
        if os.path.isabs(p):
            return p
        try:
            return os.path.abspath(os.path.join(get_repo_root(), p))
        except Exception:
            return os.path.abspath(p)

    def _status_view():
        """Return status for a list of flag catalog items."""
        try:
            data = request.get_json(silent=True) or {}
            items = data.get('items') or []
            out = []
            logs: list[str] = []
            base_out = os.path.abspath(flag_base_dir())
            os.makedirs(base_out, exist_ok=True)
            for it in items:
                name = (it.get('name') or it.get('Name') or '').strip()
                path_raw = (it.get('path') or it.get('Path') or '').strip()
                compose_name = (it.get('compose_name') or it.get('compose') or 'docker-compose.yml').strip() or 'docker-compose.yml'
                safe = safe_name(name or 'flag')
                fdir = os.path.join(base_out, safe)
                gh = parse_github_url(path_raw)
                compose_file = None
                base_dir = fdir
                exists = False

                # Local file path support (repo-relative)
                local_path = _flag_resolve_path(path_raw)
                if local_path and os.path.exists(local_path) and local_path.lower().endswith(('.yml', '.yaml')):
                    compose_file = local_path
                    base_dir = os.path.dirname(local_path)
                    exists = True
                    try:
                        logs.append(f"[status] {name}: local compose={compose_file}")
                    except Exception:
                        pass
                elif gh.get('is_github'):
                    repo_dir = os.path.join(fdir, vuln_repo_subdir())
                    sub = gh.get('subpath') or ''
                    is_file_sub = bool(sub) and sub.lower().endswith(('.yml', '.yaml'))
                    if is_file_sub:
                        compose_file = os.path.join(repo_dir, sub)
                        base_dir = os.path.dirname(compose_file)
                        exists = os.path.exists(compose_file)
                    else:
                        base_dir = os.path.join(repo_dir, sub) if sub else repo_dir
                        exists = os.path.isdir(base_dir)
                    if exists and compose_name and not compose_file:
                        pth = os.path.join(base_dir, compose_name)
                        if os.path.exists(pth):
                            compose_file = pth
                    if not compose_file:
                        cand = compose_candidates(base_dir)
                        compose_file = cand[0] if cand else None
                    try:
                        logs.append(f"[status] {name}: github base={base_dir} exists={exists} compose={compose_name}")
                    except Exception:
                        pass
                else:
                    # Legacy direct download into outputs/flags/<safe>/compose_name
                    compose_file = os.path.join(fdir, compose_name)
                    exists = os.path.exists(compose_file)
                    base_dir = fdir

                pulled = False
                if exists and compose_file and shutil.which('docker'):
                    try:
                        proc = subprocess.run(
                            ['docker', 'compose', '-f', compose_file, 'config', '--images'],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                            timeout=30,
                        )
                        if proc.returncode == 0:
                            images = [ln.strip() for ln in (proc.stdout or '').splitlines() if ln.strip()]
                            if images:
                                present = []
                                for img in images:
                                    p2 = subprocess.run(['docker', 'image', 'inspect', img], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                                    present.append(p2.returncode == 0)
                                pulled = all(present)
                    except Exception:
                        pulled = False
                out.append({
                    'name': name,
                    'path': path_raw,
                    'compose_name': compose_name,
                    'compose_path': compose_file,
                    'exists': bool(exists),
                    'pulled': bool(pulled),
                    'dir': base_dir,
                })
            return jsonify({'items': out, 'log': logs})
        except Exception as exc:
            return jsonify({'error': str(exc)}), 500

    def _download_view():
        """Download/clone docker-compose assets for the given flag catalog items."""
        try:
            data = request.get_json(silent=True) or {}
            items = data.get('items') or []
            out = []
            logs: list[str] = []
            base_out = os.path.abspath(flag_base_dir())
            os.makedirs(base_out, exist_ok=True)

            try:
                from core_topo_gen.utils.vuln_process import _github_tree_to_raw as _to_raw
            except Exception:

                def _to_raw(base_url: str, filename: str) -> str | None:
                    try:
                        from urllib.parse import urlparse

                        u = urlparse(base_url)
                        if u.netloc.lower() != 'github.com':
                            return None
                        parts = [p for p in u.path.strip('/').split('/') if p]
                        if len(parts) < 4 or parts[2] != 'tree':
                            return None
                        owner, repo, _tree, branch = parts[:4]
                        rest = '/'.join(parts[4:])
                        return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{rest}/{filename}"
                    except Exception:
                        return None

            import urllib.request
            import shlex

            for it in items:
                name = (it.get('name') or it.get('Name') or '').strip()
                path_raw = (it.get('path') or it.get('Path') or '').strip()
                compose_name = (it.get('compose_name') or it.get('compose') or 'docker-compose.yml').strip() or 'docker-compose.yml'
                safe = safe_name(name or 'flag')
                fdir = os.path.join(base_out, safe)
                os.makedirs(fdir, exist_ok=True)

                # Local compose path support: nothing to download.
                local_path = _flag_resolve_path(path_raw)
                if local_path and os.path.exists(local_path) and local_path.lower().endswith(('.yml', '.yaml')):
                    out.append({'name': name, 'path': path_raw, 'ok': True, 'dir': os.path.dirname(local_path), 'message': 'local compose file'})
                    continue

                gh = parse_github_url(path_raw)
                if gh.get('is_github'):
                    if not shutil.which('git'):
                        logs.append(f"[download] {name}: git not available in PATH")
                        out.append({'name': name, 'path': path_raw, 'ok': False, 'dir': fdir, 'message': 'git not available'})
                        continue
                    repo_dir = os.path.join(fdir, vuln_repo_subdir())
                    if os.path.isdir(os.path.join(repo_dir, '.git')):
                        base_dir = os.path.join(repo_dir, gh.get('subpath') or '') if gh.get('subpath') else repo_dir
                        out.append({'name': name, 'path': path_raw, 'ok': True, 'dir': base_dir, 'message': 'already downloaded'})
                        continue
                    try:
                        if os.path.exists(repo_dir):
                            shutil.rmtree(repo_dir)
                    except Exception:
                        pass
                    cmd = ['git', 'clone', '--depth', '1']
                    if gh.get('branch'):
                        cmd += ['--branch', gh.get('branch')]
                    cmd += [gh.get('git_url'), repo_dir]
                    try:
                        logs.append(f"[download] {name}: running: {' '.join(shlex.quote(c) for c in cmd)}")
                        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
                        if proc.returncode == 0 and os.path.isdir(repo_dir):
                            base_dir = os.path.join(repo_dir, gh.get('subpath') or '') if gh.get('subpath') else repo_dir
                            out.append({'name': name, 'path': path_raw, 'ok': True, 'dir': base_dir, 'message': 'downloaded'})
                        else:
                            msg = (proc.stdout or '').strip()
                            out.append({'name': name, 'path': path_raw, 'ok': False, 'dir': fdir, 'message': msg[-1000:] if msg else 'git clone failed'})
                    except Exception as exc:
                        out.append({'name': name, 'path': path_raw, 'ok': False, 'dir': fdir, 'message': str(exc)})
                else:
                    raw = _to_raw(path_raw, compose_name) or (path_raw.rstrip('/') + '/' + compose_name)
                    yml_path = os.path.join(fdir, compose_name)
                    try:
                        logs.append(f"[download] {name}: GET {raw}")
                        with urllib.request.urlopen(raw, timeout=30) as resp:
                            data_bin = resp.read(1_000_000)
                        with open(yml_path, 'wb') as fh:
                            fh.write(data_bin)
                        out.append({'name': name, 'path': path_raw, 'ok': True, 'dir': fdir, 'message': 'downloaded', 'compose_name': compose_name})
                    except Exception as exc:
                        out.append({'name': name, 'path': path_raw, 'ok': False, 'dir': fdir, 'message': str(exc), 'compose_name': compose_name})
            return jsonify({'items': out, 'log': logs})
        except Exception as exc:
            return jsonify({'error': str(exc)}), 500

    def _pull_view():
        """Run docker compose pull for the given flag catalog items."""
        try:
            data = request.get_json(silent=True) or {}
            items = data.get('items') or []
            out = []
            logs: list[str] = []
            base_out = os.path.abspath(flag_base_dir())
            for it in items:
                name = (it.get('name') or it.get('Name') or '').strip()
                path_raw = (it.get('path') or it.get('Path') or '').strip()
                compose_name = (it.get('compose_name') or it.get('compose') or 'docker-compose.yml').strip() or 'docker-compose.yml'
                safe = safe_name(name or 'flag')
                fdir = os.path.join(base_out, safe)

                local_path = _flag_resolve_path(path_raw)
                if local_path and os.path.exists(local_path) and local_path.lower().endswith(('.yml', '.yaml')):
                    yml_path = local_path
                else:
                    gh = parse_github_url(path_raw)
                    if gh.get('is_github'):
                        repo_dir = os.path.join(fdir, vuln_repo_subdir())
                        sub = gh.get('subpath') or ''
                        is_file_sub = bool(sub) and sub.lower().endswith(('.yml', '.yaml'))
                        base_dir = os.path.join(repo_dir, os.path.dirname(sub)) if is_file_sub else (os.path.join(repo_dir, sub) if sub else repo_dir)
                        yml_path = os.path.join(repo_dir, sub) if is_file_sub else os.path.join(base_dir, compose_name)
                        if not os.path.exists(yml_path):
                            cand = compose_candidates(base_dir)
                            yml_path = cand[0] if cand else None
                    else:
                        yml_path = os.path.join(fdir, compose_name)

                if not yml_path or not os.path.exists(yml_path):
                    out.append({'name': name, 'path': path_raw, 'ok': False, 'message': 'compose file missing', 'compose_name': compose_name})
                    continue
                if not shutil.which('docker'):
                    out.append({'name': name, 'path': path_raw, 'ok': False, 'message': 'docker not available', 'compose_name': compose_name})
                    continue
                try:
                    proc = subprocess.run(['docker', 'compose', '-f', yml_path, 'pull'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    logs.append(f"[pull] {name}: rc={proc.returncode} file={yml_path}")
                    ok = proc.returncode == 0
                    msg = 'ok' if ok else ((proc.stdout or '')[-1000:] if proc.stdout else 'failed')
                    out.append({'name': name, 'path': path_raw, 'ok': ok, 'message': msg, 'compose_name': compose_name})
                except Exception as exc:
                    out.append({'name': name, 'path': path_raw, 'ok': False, 'message': str(exc), 'compose_name': compose_name})
            return jsonify({'items': out, 'log': logs})
        except Exception as exc:
            return jsonify({'error': str(exc)}), 500

    def _remove_view():
        """Remove compose assets and any local outputs for the given flag catalog items."""
        try:
            data = request.get_json(silent=True) or {}
            items = data.get('items') or []
            out = []
            logs: list[str] = []
            base_out = os.path.abspath(flag_base_dir())
            for it in items:
                name = (it.get('name') or it.get('Name') or '').strip()
                path_raw = (it.get('path') or it.get('Path') or '').strip()
                compose_name = (it.get('compose_name') or it.get('compose') or 'docker-compose.yml').strip() or 'docker-compose.yml'
                safe = safe_name(name or 'flag')
                fdir = os.path.join(base_out, safe)

                # Prefer local compose file if path points at one.
                local_path = _flag_resolve_path(path_raw)
                yml_path = None
                if local_path and os.path.exists(local_path) and local_path.lower().endswith(('.yml', '.yaml')):
                    yml_path = local_path
                else:
                    gh = parse_github_url(path_raw)
                    if gh.get('is_github'):
                        repo_dir = os.path.join(fdir, vuln_repo_subdir())
                        sub = gh.get('subpath') or ''
                        is_file_sub = bool(sub) and sub.lower().endswith(('.yml', '.yaml'))
                        base_dir = os.path.join(repo_dir, os.path.dirname(sub)) if is_file_sub else (os.path.join(repo_dir, sub) if sub else repo_dir)
                        yml_path = os.path.join(repo_dir, sub) if is_file_sub else os.path.join(base_dir, compose_name)
                        if not os.path.exists(yml_path):
                            cand = compose_candidates(base_dir)
                            yml_path = cand[0] if cand else None
                    else:
                        yml_path = os.path.join(fdir, compose_name)

                if yml_path and os.path.exists(yml_path) and shutil.which('docker'):
                    try:
                        logs.append(f"[remove] {name}: docker compose down file={yml_path}")
                    except Exception:
                        pass
                    try:
                        subprocess.run(
                            ['docker', 'compose', '-f', yml_path, 'down', '--volumes', '--remove-orphans'],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                        )
                    except Exception:
                        pass

                # Remove downloaded dirs under outputs/flags only (never delete repo-local templates)
                try:
                    gh = parse_github_url(path_raw)
                    if gh.get('is_github'):
                        repo_dir = os.path.join(fdir, vuln_repo_subdir())
                        if os.path.isdir(repo_dir):
                            shutil.rmtree(repo_dir, ignore_errors=True)
                            logs.append(f"[remove] {name}: deleted {repo_dir}")
                    else:
                        yml = os.path.join(fdir, compose_name)
                        if os.path.exists(yml):
                            try:
                                os.remove(yml)
                                logs.append(f"[remove] {name}: deleted {yml}")
                            except Exception:
                                pass
                    try:
                        if os.path.isdir(fdir) and not os.listdir(fdir):
                            os.rmdir(fdir)
                    except Exception:
                        pass
                except Exception as exc:
                    try:
                        logs.append(f"[remove] cleanup error: {exc}")
                    except Exception:
                        pass

                out.append({'name': name, 'path': path_raw, 'ok': True, 'message': 'removed', 'compose_name': compose_name})
            return jsonify({'items': out, 'log': logs})
        except Exception as exc:
            return jsonify({'error': str(exc)}), 500

    app.add_url_rule('/flag_compose/status', endpoint='flag_compose_status', view_func=_status_view, methods=['POST'])
    app.add_url_rule('/flag_compose/download', endpoint='flag_compose_download', view_func=_download_view, methods=['POST'])
    app.add_url_rule('/flag_compose/pull', endpoint='flag_compose_pull', view_func=_pull_view, methods=['POST'])
    app.add_url_rule('/flag_compose/remove', endpoint='flag_compose_remove', view_func=_remove_view, methods=['POST'])
