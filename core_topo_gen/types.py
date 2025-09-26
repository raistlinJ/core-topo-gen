from __future__ import annotations
from dataclasses import dataclass
from typing import List

@dataclass
class ServiceInfo:
    name: str
    factor: float
    density: float
    # When > 0, indicates an absolute number of hosts to assign this service to.
    # Takes precedence over fractional density.
    abs_count: int = 0

@dataclass
class RoutingInfo:
    protocol: str
    factor: float
    # When > 0, indicates an absolute number of routers to assign this protocol to.
    # Used in addition to density-based routers.
    abs_count: int = 0
    # Optional edge planning directives (from UI Routing row)
    edges_mode: str = ""  # "", Random, Min, Max, Exact
    edges: int = 0         # Used only when edges_mode == Exact (>0)

@dataclass
class NodeInfo:
    node_id: int
    ip4: str
    role: str

@dataclass
class TrafficInfo:
    kind: str
    factor: float
    pattern: str = ""
    rate_kbps: float = 0.0
    period_s: float = 10.0
    jitter_pct: float = 0.0
    content_type: str = ""
    # When > 0, indicates an absolute number of sender/receiver pairs to create for this item.
    abs_count: int = 0

@dataclass
class SegmentationInfo:
    name: str
    factor: float
    # When > 0, indicates an absolute number of segmentation slots to plan for this service.
    abs_count: int = 0
