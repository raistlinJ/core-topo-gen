from __future__ import annotations
from dataclasses import dataclass
from typing import List

@dataclass
class ServiceInfo:
    name: str
    factor: float
    density: float

@dataclass
class RoutingInfo:
    protocol: str
    factor: float

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

@dataclass
class SegmentationInfo:
    name: str
    factor: float
