import os
import re
from types import SimpleNamespace

from core_topo_gen.builders.topology import _apply_docker_compose_meta, NodeType
from core_topo_gen.utils.vuln_process import prepare_compose_for_assignments


class DummySession:
    def __init__(self):
        self.calls = []

    def edit_node(self, node_id, options=None, **kwargs):
        self.calls.append((node_id, options, kwargs))


def test_prepare_compose_for_assignments_records_compose_path(tmp_path):
    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        """
version: '3'
services:
  app:
    image: nginx:latest
    ports:
      - "8080:80"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    record = {"Type": "docker-compose", "Name": "Example", "Path": str(compose_src)}
    name_to_vuln = {"host-1": record}

    created = prepare_compose_for_assignments(name_to_vuln, out_base=str(tmp_path))

    expected_path = os.path.join(str(tmp_path), "docker-compose-host-1.yml")
    assert expected_path in created
    assert record.get("compose_path") == expected_path

    # Validate iproute2 wrapper injection (best-effort; requires PyYAML)
    try:
        import yaml  # type: ignore
    except Exception:
        yaml = None  # type: ignore
    if yaml is not None:
        obj = yaml.safe_load(open(expected_path, encoding="utf-8"))
        svc = obj["services"]["app"]

        # Option B: no Docker-managed networking, so no docker eth0/default route.
        assert svc.get("network_mode") == "none"
        # With network_mode none we should not be publishing ports at all.
        assert "ports" not in svc
        # CORE services may chmod/create files using relative paths; ensure root workdir.
        assert svc.get("working_dir") == "/"
        assert "build" in svc
        assert svc["build"]["dockerfile"] == "Dockerfile"
        assert "cap_add" in svc and "NET_ADMIN" in (svc["cap_add"] or [])
        wrap_dir = svc["build"]["context"]
        dockerfile = os.path.join(wrap_dir, "Dockerfile")
        assert os.path.exists(dockerfile)
        txt = open(dockerfile, encoding="utf-8").read()
        assert "iproute2" in txt
        assert "ethtool" in txt


def test_apply_docker_compose_meta_pushes_options(tmp_path):
    record = {"Name": "Example Vuln", "compose_path": str(tmp_path / "docker-compose-host-1.yml")}
    node = SimpleNamespace(id=5, name="host-1", options=None, type=NodeType.DOCKER, image="pre-image")
    session = DummySession()

    _apply_docker_compose_meta(node, record, session=session)

    assert getattr(node, "compose") == record["compose_path"]
    assert session.calls, "session.edit_node should be called"
    node_id, options, _ = session.calls[0]
    assert node_id == node.id
    assert getattr(options, "compose") == record["compose_path"]
    assert getattr(node, "options").compose == record["compose_path"]
    assert getattr(node, "type") == NodeType.DOCKER
    assert getattr(node, "image") == ""
    assert getattr(options, "type") == ""
    assert getattr(options, "image") == ""


def test_apply_docker_compose_meta_uses_real_service_name(tmp_path):
    compose_path = tmp_path / "docker-compose-host-1.yml"
    compose_path.write_text(
            """
services:
    app:
        image: nginx:latest
""".strip()
            + "\n",
            encoding="utf-8",
    )

    record = {"Name": "standard-ubuntu-docker-core", "compose_path": str(compose_path)}
    node = SimpleNamespace(id=6, name="host-1", options=None, type=NodeType.DOCKER, image="")
    session = DummySession()

    _apply_docker_compose_meta(node, record, session=session)

    assert getattr(node, "compose_name") == "app"
    assert session.calls, "session.edit_node should be called"
    node_id, options, _ = session.calls[0]
    assert node_id == node.id
    assert getattr(options, "compose_name") == "app"


def test_apply_docker_compose_meta_falls_back_when_service_invalid(tmp_path):
    compose_path = tmp_path / "docker-compose-host-1.yml"
    compose_path.write_text(
            """
services:
    web:
        image: nginx:latest
""".strip()
            + "\n",
            encoding="utf-8",
    )

    record = {
        "Name": "standard-ubuntu-docker-core",
        "compose_path": str(compose_path),
        "compose_service": "standard-ubuntu-docker-core",
    }
    node = SimpleNamespace(id=7, name="host-1", options=None, type=NodeType.DOCKER, image="")
    session = DummySession()

    _apply_docker_compose_meta(node, record, session=session)

    assert getattr(node, "compose_name") == "web"
    assert session.calls, "session.edit_node should be called"
    node_id, options, _ = session.calls[0]
    assert node_id == node.id
    assert getattr(options, "compose_name") == "web"


def test_apply_docker_compose_meta_unsets_invalid_service_when_unreadable_compose(tmp_path):
    compose_path = tmp_path / "docker-compose-host-1.yml"
    compose_path.write_text("services:\n  web: [\n", encoding="utf-8")

    record = {
        "Name": "standard-ubuntu-docker-core",
        "compose_path": str(compose_path),
        "compose_service": "standard-ubuntu-docker-core",
    }
    node = SimpleNamespace(id=8, name="host-1", options=None, type=NodeType.DOCKER, image="")
    session = DummySession()

    _apply_docker_compose_meta(node, record, session=session)

    assert getattr(node, "compose_name", None) is None
    assert session.calls, "session.edit_node should be called"
    _node_id, options, _ = session.calls[0]
    assert getattr(options, "compose_name", None) is None


def test_prepare_compose_escapes_mako_shell_vars(tmp_path):
        compose_src = tmp_path / "base-compose-airflow.yml"
        compose_src.write_text(
                """
version: '3'
services:
    app:
        image: apache/airflow:2.9.0
        environment:
            - AIRFLOW_UID=${AIRFLOW_UID:-50000}
""".strip()
                + "\n",
                encoding="utf-8",
        )

        record = {"Type": "docker-compose", "Name": "Airflow", "Path": str(compose_src)}
        name_to_vuln = {"docker-3": record}
        created = prepare_compose_for_assignments(name_to_vuln, out_base=str(tmp_path))

        out_path = os.path.join(str(tmp_path), "docker-compose-docker-3.yml")
        assert out_path in created
        text = open(out_path, encoding="utf-8").read()

        assert '${"${AIRFLOW_UID:-50000}"}' in text
        assert "\\${AIRFLOW_UID:-50000}" not in text
        assert "$${AIRFLOW_UID:-50000}" not in text
        assert re.search(r"(?<![\"'])\$\{AIRFLOW_UID:-50000\}(?![\"'])", text) is None
        assert re.search(r"\$\{\s*[\"']\$\{AIRFLOW_UID:-50000\}[\"']\s*\}", text) is not None
