"""Convenience entry point for running the Flask Web UI."""

from __future__ import annotations

import logging
import os
import sys
from typing import Final


def _env_flag(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _configure_webui_stdout_logging() -> None:
    """Ensure Web UI logs go to stdout/stderr (so `docker logs` captures them).

    This is intentionally configured from the entrypoint so it doesn't affect
    pytest imports that load `webapp.app_backend`.
    """
    level_name = os.environ.get('WEBAPP_LOG_LEVEL', 'INFO').strip().upper()
    level = getattr(logging, level_name, logging.INFO)
    root = logging.getLogger()
    try:
        root.setLevel(level)
    except Exception:
        pass

    # Add a StreamHandler to stdout if one isn't already present.
    try:
        has_stream = False
        for h in list(getattr(root, 'handlers', []) or []):
            if isinstance(h, logging.StreamHandler) and getattr(h, 'stream', None) in (sys.stdout, sys.stderr):
                has_stream = True
                break
        if not has_stream:
            sh = logging.StreamHandler(stream=sys.stdout)
            sh.setLevel(level)
            sh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
            root.addHandler(sh)
    except Exception:
        pass

    # Keep werkzeug noise manageable but visible.
    try:
        wz = logging.getLogger('werkzeug')
        wz.setLevel(level)
        # Ensure request logs show up in the root handler.
        wz.propagate = True
    except Exception:
        pass


def main() -> None:
    """Start the Web UI using the in-repo Flask application."""

    _configure_webui_stdout_logging()

    try:
        logging.getLogger(__name__).info(
            "Web UI starting pid=%s port=%s debug=%s",
            os.getpid(),
            os.environ.get("CORETG_PORT", "9090"),
            _env_flag(os.environ.get("CORETG_DEBUG")),
        )
    except Exception:
        # As a last resort, make sure *something* is emitted.
        try:
            print(f"Web UI starting pid={os.getpid()} port={os.environ.get('CORETG_PORT', '9090')}", flush=True)
        except Exception:
            pass

    # Import after logging is configured so Flask app logger inherits handlers.
    from webapp.app_backend import app
    try:
        app.logger.propagate = False
        if not getattr(app.logger, 'handlers', None):
            sh = logging.StreamHandler(stream=sys.stdout)
            sh.setLevel(logging.getLogger().level)
            sh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
            app.logger.addHandler(sh)
    except Exception:
        pass

    default_host: Final[str] = os.environ.get("CORETG_HOST", "0.0.0.0")
    port_str = os.environ.get("CORETG_PORT", "9090")
    debug = _env_flag(os.environ.get("CORETG_DEBUG"))

    try:
        port = int(port_str)
    except ValueError:
        raise SystemExit(f"Invalid CORETG_PORT value: {port_str!r}")

    # Threaded mode is important here because the UI uses Server-Sent Events (SSE)
    # for log streaming; without threads, a single open SSE connection can block
    # other requests (like starting a test run or polling outputs).
    app.run(host=default_host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    main()