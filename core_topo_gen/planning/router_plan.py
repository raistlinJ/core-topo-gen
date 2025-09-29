from __future__ import annotations
from typing import List, Tuple
from ..types import RoutingInfo


def compute_router_plan(total_hosts: int, base_host_pool: int, routing_density: float, routing_items: List[RoutingInfo]) -> Tuple[int, dict]:
    """Replicate router count derivation used in segmented topology builder.

    Returns (router_count, breakdown_dict)
    breakdown_dict keys:
      density_raw, density_router_count, density_router_abs_component,
      density_router_frac_component, routing_abs_count_total, effective_base
    """
    try:
        count_router_count = sum(int(getattr(ri, 'abs_count', 0) or 0) for ri in (routing_items or []))
    except Exception:
        count_router_count = 0
    effective_base = max(0, int(base_host_pool or 0))
    density_router_count = 0
    abs_density_component = 0
    frac_density_component = 0
    rd_val = 0.0
    if routing_density and routing_density > 0 and effective_base >= 0:
        try:
            rd_val = float(routing_density)
        except Exception:  # pragma: no cover - defensive
            rd_val = 0.0
        if rd_val > 1.0:
            abs_density_component = int(rd_val)
        else:
            import math as _math
            d = max(0.0, min(1.0, rd_val))
            desired = effective_base * d
            frac_density_component = int(_math.floor(desired + 1e-9))
        density_router_count = abs_density_component + frac_density_component
        density_router_count = max(0, min(effective_base, density_router_count))
    router_count = min(total_hosts, density_router_count + count_router_count)
    breakdown = {
        "density_raw": rd_val,
        "density_router_count": density_router_count,
        "density_router_abs_component": abs_density_component,
        "density_router_frac_component": frac_density_component,
        "routing_abs_count_total": count_router_count,
        "effective_base": effective_base,
        "final_router_count": router_count,
    }
    return router_count, breakdown
