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
        # Preserve container-side port intent for reporting/metadata.
        assert "expose" in svc and "80" in [str(x) for x in (svc.get("expose") or [])]
        # CORE services may chmod/create files using relative paths; ensure root workdir.
        assert svc.get("working_dir") == "/"
        # Compose handed to CORE should NOT include `build:`; core-daemon would
        # attempt to build during scenario startup (and therefore pull packages/images).
        assert "build" not in svc
        assert "cap_add" in svc and "NET_ADMIN" in (svc["cap_add"] or [])
        labels = svc.get("labels") or {}
        assert isinstance(labels, dict)
        assert labels.get("coretg.wrapper_build_dockerfile") == "Dockerfile"
        wrap_dir = str(labels.get("coretg.wrapper_build_context") or "").strip()
        assert wrap_dir
        dockerfile = os.path.join(wrap_dir, "Dockerfile")
        assert os.path.exists(dockerfile)
        txt = open(dockerfile, encoding="utf-8").read()
        # Wrapper Dockerfile should ensure an `ip` command exists.
        # Default strategy is offline-safe (busybox injection), with legacy
        # package-manager installs available behind an env var.
        assert "ip" in txt
        assert (
            "busybox injection" in txt
            or "COPY --from=coretg_iptools" in txt
            or "apt-get install" in txt
            or "apk add" in txt
            or "yum install" in txt
            or "dnf install" in txt
        )


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
                healthcheck:
                    test: ["CMD-SHELL", "echo $${HOSTNAME}"]
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

        # `${VAR:-default}` interpolation is resolved to a plain literal so docker-compose
        # (and CORE's Mako templating) can both process the generated compose.
        assert 'AIRFLOW_UID=50000' in text
        assert '${' not in text
        assert '$${HOSTNAME}' not in text
        assert '$HOSTNAME' in text
        assert "\\${AIRFLOW_UID:-50000}" not in text
        assert "$${AIRFLOW_UID:-50000}" not in text
        assert re.search(r"(?<![\"'])\$\{AIRFLOW_UID:-50000\}(?![\"'])", text) is None
        # Wrapper form should not be present after literal resolution.
        assert re.search(r"\$\{\s*[\"']\$\{AIRFLOW_UID:-50000\}[\"']\s*\}", text) is None


def test_prepare_compose_local_template_dot_bind_isolation(tmp_path):
    """Regression: isolating local templates must not recurse copying base_dir into base_dir/node-*.

    This pattern happens with node-generator outputs like:
      volumes:
        - .:/exports
    """
    # Create a local compose that references '.' so it will be absolutized and then isolated.
    src_dir = tmp_path / "local"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "payload.txt").write_text("hello\n", encoding="utf-8")
    compose_src = src_dir / "docker-compose.yml"
    compose_src.write_text(
        (
            "services:\n"
            "  node:\n"
            "    image: alpine:3.19\n"
            "    command: ['sh','-lc','sleep 2']\n"
            "    volumes:\n"
            "      - .:/exports\n"
        ),
        encoding="utf-8",
    )

    record = {"Type": "docker-compose", "Name": "LocalDot", "Path": str(compose_src)}
    out_base = tmp_path / "out"
    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(out_base))
    out_path = out_base / "docker-compose-docker-1.yml"
    assert str(out_path) in created
    assert out_path.exists()

    # Ensure the rewritten compose refers to a bind source under the isolated node dir.
    try:
        import yaml  # type: ignore
    except Exception:
        yaml = None  # type: ignore
    if yaml is None:
        return

    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    svc = (obj.get("services") or {}).get("docker-1") or (obj.get("services") or {}).get("node")
    assert isinstance(svc, dict)
    vols = svc.get("volumes")
    assert isinstance(vols, list)
    # Should be absolute path bind, not '.'
    vol0 = str(vols[0])
    assert vol0.split(":", 1)[0].startswith(str(out_base)), vol0


def test_prepare_compose_prefers_local_path_over_cached(tmp_path):
    # Two different local compose sources but same Name (so same safe base_dir).
    src1 = tmp_path / "run1"
    src1.mkdir(parents=True, exist_ok=True)
    (src1 / "docker-compose.yml").write_text(
        "services:\n  app:\n    image: alpine:3.19\n    command: ['sh','-lc','echo one; sleep 1']\n",
        encoding="utf-8",
    )

    src2 = tmp_path / "run2"
    src2.mkdir(parents=True, exist_ok=True)
    (src2 / "docker-compose.yml").write_text(
        "services:\n  app:\n    image: alpine:3.19\n    command: ['sh','-lc','echo two; sleep 1']\n",
        encoding="utf-8",
    )

    out_base = tmp_path / "out"
    rec1 = {"Type": "docker-compose", "Name": "SameName", "Path": str((src1 / 'docker-compose.yml'))}
    rec2 = {"Type": "docker-compose", "Name": "SameName", "Path": str((src2 / 'docker-compose.yml'))}

    # First run creates base_dir cached compose.
    prepare_compose_for_assignments({"n1": rec1}, out_base=str(out_base))

    # Corrupt/overwrite the cached compose to something else to ensure we don't reuse it.
    safe_dir = out_base / "samename"
    safe_dir.mkdir(parents=True, exist_ok=True)
    (safe_dir / "docker-compose.yml").write_text(
        "services:\n  app:\n    image: alpine:3.19\n    command: ['sh','-lc','echo STALE; sleep 1']\n",
        encoding="utf-8",
    )

    created = prepare_compose_for_assignments({"n2": rec2}, out_base=str(out_base))
    out_path = out_base / "docker-compose-n2.yml"
    assert str(out_path) in created
    txt = out_path.read_text("utf-8", errors="ignore")
    assert "echo two" in txt
    assert "echo STALE" not in txt
