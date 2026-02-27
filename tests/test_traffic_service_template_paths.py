from pathlib import Path


def test_traffic_service_uses_absolute_paths_and_runtime_dir():
    p = Path("on_core_machine/custom_services/TrafficService.py")
    txt = p.read_text("utf-8", errors="ignore")

    assert 'files: list[str] = ["/runtraffic.sh"]' in txt
    assert 'startup: list[str] = ["/bin/bash /runtraffic.sh &"]' in txt
    assert 'runtime_dir=/tmp/coretg_traffic' in txt
    assert 'cp /tmp/traffic/traffic_${node.id}_*.py "$runtime_dir"/ 2>/dev/null || true' in txt
    assert 'for file in "$runtime_dir"/traffic_${node.id}_*.py; do' in txt
