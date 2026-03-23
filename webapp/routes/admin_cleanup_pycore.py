from __future__ import annotations

import shutil
import time
from pathlib import Path
from typing import Any, Callable, Iterable

from flask import jsonify

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    core_config_for_request: Callable[..., dict[str, Any]],
    list_active_core_sessions: Callable[..., list[dict[str, Any]]],
    core_host_default: Any,
    core_port_default: Any,
    pycore_globber: Callable[[], Iterable[Path]] | None = None,
    time_func: Callable[[], float] = time.time,
    rmtree_func: Callable[[str], None] = shutil.rmtree,
) -> None:
    if not begin_route_registration(app, 'admin_cleanup_pycore_routes'):
        return

    globber = pycore_globber or (lambda: Path('/tmp').glob('pycore.*'))

    def _admin_cleanup_pycore_view():
        try:
            core_cfg = core_config_for_request(include_password=True)
            core_host = core_cfg.get('host', core_host_default)
            core_port = int(core_cfg.get('port', core_port_default))
            active_ids = set()
            try:
                sessions = list_active_core_sessions(core_host, core_port, core_cfg)
                for session in sessions:
                    try:
                        active_ids.add(int(session.get('id')))
                    except Exception:
                        continue
            except Exception:
                pass

            removed: list[str] = []
            kept: list[str] = []
            now = time_func()
            for path in globber() or []:
                try:
                    sid = int(path.name.split('.')[-1])
                except Exception:
                    kept.append(str(path))
                    continue
                if sid in active_ids:
                    kept.append(str(path))
                    continue
                try:
                    age = now - path.stat().st_mtime
                except Exception:
                    age = 999.0
                if age < 30:
                    kept.append(str(path))
                    continue
                try:
                    rmtree_func(str(path))
                    removed.append(str(path))
                except Exception:
                    kept.append(str(path))
            return jsonify({'ok': True, 'removed': removed, 'kept': kept, 'active_session_ids': sorted(active_ids)})
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)})

    app.add_url_rule(
        '/admin/cleanup_pycore',
        endpoint='admin_cleanup_pycore',
        view_func=_admin_cleanup_pycore_view,
        methods=['POST'],
    )
    mark_routes_registered(app, 'admin_cleanup_pycore_routes')