from pathlib import Path


def test_docker_default_route_service_uses_absolute_paths() -> None:
    p = Path("on_core_machine/custom_services/DockerDefaultRoute.py")
    txt = p.read_text(encoding="utf-8")
    assert 'name: str = "DockerDefaultRoute"' in txt
    assert 'files: list[str] = ["/defaultroute.sh"]' in txt
    assert 'startup: list[str] = ["/bin/sh /defaultroute.sh"]' in txt
