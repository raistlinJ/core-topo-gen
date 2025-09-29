"""Planning subpackage initialization.

Presence of this file ensures Python treats the planning directory as a
package for environments where an older site-packages installation of
core_topo_gen might otherwise shadow new modules (e.g. full_preview).
"""

__all__ = [
    "pool",
    "constraints",
    "full_preview",
    "plan_builder",
    "router_plan",
]

# Eager import of full_preview to ensure availability for web preview endpoints; fall back silently.
try:  # pragma: no cover
    from . import full_preview  # noqa: F401
except Exception:
    pass
