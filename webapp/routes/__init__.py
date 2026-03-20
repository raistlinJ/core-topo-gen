"""Flask route modules.

These modules register route handlers onto the main Flask app to keep
`webapp.app_backend` smaller and easier to navigate.

Maintainer note:
- Prefer explicit `register(app, ...)` entry points for extracted route modules.
- Route registration must be safe to call more than once.
- Internally, modules may register routes directly or via blueprints, but keep
  the external registration surface explicit.
- Use `webapp.routes._registration` for shared idempotent registration instead
	of per-module ad hoc guard attributes.
"""
