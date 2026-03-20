from __future__ import annotations


def _registration_attr_name(route_group: str) -> str:
    normalized = ''.join(
        ch if ch.isalnum() else '_'
        for ch in str(route_group or '').strip().lower()
    ).strip('_')
    normalized = normalized or 'routes'
    return f'_coretg_{normalized}_registered'


def begin_route_registration(app, route_group: str) -> bool:
    attr_name = _registration_attr_name(route_group)
    if getattr(app, attr_name, False):
        return False
    return True


def mark_routes_registered(app, route_group: str) -> None:
    setattr(app, _registration_attr_name(route_group), True)