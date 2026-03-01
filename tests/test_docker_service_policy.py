from core_topo_gen.builders import topology


def test_docker_traffic_service_disabled_by_default(monkeypatch):
    monkeypatch.delenv("CORETG_DOCKER_ADD_TRAFFIC", raising=False)
    assert topology._docker_traffic_service_enabled() is False


def test_docker_traffic_service_enabled_via_env(monkeypatch):
    monkeypatch.setenv("CORETG_DOCKER_ADD_TRAFFIC", "1")
    assert topology._docker_traffic_service_enabled() is True


def test_ensure_default_route_for_docker_prunes_traffic(monkeypatch):
    calls = []

    monkeypatch.setenv("CORETG_DOCKER_ADD_DEFAULTROUTE", "1")
    monkeypatch.delenv("CORETG_DOCKER_ADD_TRAFFIC", raising=False)

    def fake_ensure_service(session, node_id, service_name, node_obj=None):
        calls.append(("ensure", int(node_id), service_name))
        return True

    def fake_remove_service(session, node_id, service_name, node_obj=None):
        calls.append(("remove", int(node_id), service_name))
        return True

    monkeypatch.setattr(topology, "ensure_service", fake_ensure_service)
    monkeypatch.setattr(topology, "remove_service", fake_remove_service)

    class _Node:
        id = 34

    topology._ensure_default_route_for_docker(object(), _Node())

    assert ("remove", 34, "DefaultRoute") in calls
    assert ("ensure", 34, "CoreTGPrereqs") in calls
    assert ("ensure", 34, "DockerDefaultRoute") in calls
    assert ("remove", 34, "Traffic") in calls
