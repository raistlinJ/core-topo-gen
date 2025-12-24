import pytest

from core_topo_gen.planning.full_preview import build_full_preview
from core_topo_gen.planning.preview_validation import assert_full_preview_valid, validate_full_preview
from core_topo_gen.types import RoutingInfo


def test_full_preview_validation_passes_on_generated_preview():
    role_counts = {"Workstation": 12, "Server": 3}
    routing_items = [RoutingInfo(protocol="OSPFv2", factor=1.0, abs_count=1, r2s_mode="Exact", r2s_edges=1)]
    preview = build_full_preview(
        role_counts=role_counts,
        routers_planned=2,
        services_plan={},
        vulnerabilities_plan={},
        r2r_policy=None,
        r2s_policy={"mode": "Exact", "target_per_router": 1},
        routing_items=routing_items,
        routing_plan={},
        segmentation_density=0.0,
        segmentation_items=None,
        traffic_plan=[],
        seed=2025,
        ip4_prefix="10.0.0.0/16",
        ip_mode="private",
        ip_region="all",
    )
    assert_full_preview_valid(preview)


def test_full_preview_validation_detects_duplicate_subnets():
    bad = {
        "ptp_subnets": ["10.0.0.0/24"],
        "router_switch_subnets": ["10.0.0.0/24"],
        "lan_subnets": [],
        "r2r_subnets": [],
        "switches_detail": [],
        "r2r_links_preview": [],
    }
    issues = validate_full_preview(bad)
    assert any("duplicate subnet" in msg for msg in issues)
    with pytest.raises(ValueError):
        assert_full_preview_valid(bad)
