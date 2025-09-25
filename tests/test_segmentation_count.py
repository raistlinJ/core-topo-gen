import os
import json
from core_topo_gen.types import NodeInfo, SegmentationInfo
from core_topo_gen.utils.segmentation import plan_and_apply_segmentation


def test_segmentation_abs_count_with_zero_density(tmp_path):
    # Prepare minimal nodes: 2 routers, 4 hosts
    routers = [
        NodeInfo(node_id=100, ip4="10.0.0.1/24", role="Router"),
        NodeInfo(node_id=101, ip4="10.0.1.1/24", role="Router"),
    ]
    hosts = [
        NodeInfo(node_id=1, ip4="10.0.0.10/24", role="Workstation"),
        NodeInfo(node_id=2, ip4="10.0.0.11/24", role="Workstation"),
        NodeInfo(node_id=3, ip4="10.0.1.10/24", role="Workstation"),
        NodeInfo(node_id=4, ip4="10.0.1.11/24", role="Workstation"),
    ]

    # Segmentation items with explicit counts (sum = 3)
    items = [
        SegmentationInfo(name="Firewall", factor=1.0, abs_count=2),
        SegmentationInfo(name="NAT", factor=1.0, abs_count=1),
    ]

    out_dir = tmp_path / "segmentation"
    summary = plan_and_apply_segmentation(
        session=None,
        routers=routers,
        hosts=hosts,
        density=0.0,  # zero density should still plan using abs_count
        items=items,
        out_dir=str(out_dir),
        include_hosts=False,
    )

    # Verify the summary has exactly 3 rules (2 Firewall + 1 NAT planned across routers)
    rules = summary.get("rules") or []
    assert len(rules) == 3, f"expected 3 rules from abs_count, got {len(rules)}: {rules}"

    # Ensure the segmentation_summary.json is written and matches the rule count
    seg_path = out_dir / "segmentation_summary.json"
    assert os.path.exists(seg_path)
    data = json.loads(seg_path.read_text("utf-8"))
    assert isinstance(data.get("rules"), list)
    assert len(data["rules"]) == 3
