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


def test_prepare_compose_for_assignments_records_compose_path(tmp_path, monkeypatch):
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

    monkeypatch.delenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR", raising=False)

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
        # Auto mode only forces root workdir for base OS-style images.
        assert "working_dir" not in svc
        # Compose handed to CORE should NOT include `build:`; core-daemon would
        # attempt to build during scenario startup (and therefore pull packages/images).
        assert "build" not in svc
        assert "cap_add" in svc and "NET_ADMIN" in (svc["cap_add"] or [])
        assert "NET_RAW" in (svc["cap_add"] or [])
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
        assert "ln -sfn /defaultroute.sh" in txt
        assert "ln -sfn /runtraffic.sh" in txt


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


def test_prepare_compose_wrapper_packages_strategy_keeps_service_script_symlinks(tmp_path, monkeypatch):
    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        """
version: '3'
services:
  app:
    image: nginx:latest
""".strip()
        + "\n",
        encoding="utf-8",
    )

    record = {"Type": "docker-compose", "Name": "Example", "Path": str(compose_src)}
    monkeypatch.setenv("CORETG_IPROUTE2_WRAPPER_STRATEGY", "packages")

    created = prepare_compose_for_assignments({"host-2": record}, out_base=str(tmp_path))
    assert created

    try:
        import yaml  # type: ignore
    except Exception:
        return

    out_path = tmp_path / "docker-compose-host-2.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    svc = (obj or {}).get("services", {}).get("app") or {}
    labels = svc.get("labels") or {}
    wrap_dir = str(labels.get("coretg.wrapper_build_context") or "").strip()
    assert wrap_dir
    dockerfile = os.path.join(wrap_dir, "Dockerfile")
    assert os.path.exists(dockerfile)
    txt = open(dockerfile, encoding="utf-8").read()

    assert "ln -sfn /defaultroute.sh" in txt
    assert "ln -sfn /runtraffic.sh" in txt


def test_prepare_compose_docker34_name_keeps_service_script_symlinks(tmp_path, monkeypatch):
    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        """
version: '3'
services:
  app:
    image: nginx:latest
""".strip()
        + "\n",
        encoding="utf-8",
    )

    record = {"Type": "docker-compose", "Name": "Example", "Path": str(compose_src)}
    monkeypatch.delenv("CORETG_IPROUTE2_WRAPPER_STRATEGY", raising=False)

    created = prepare_compose_for_assignments({"docker-34": record}, out_base=str(tmp_path))
    assert created
    assert str(tmp_path / "docker-compose-docker-34.yml") in created

    try:
        import yaml  # type: ignore
    except Exception:
        return

    out_path = tmp_path / "docker-compose-docker-34.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    svc = (obj or {}).get("services", {}).get("app") or {}
    labels = svc.get("labels") or {}
    wrap_dir = str(labels.get("coretg.wrapper_build_context") or "").strip()
    assert wrap_dir
    dockerfile = os.path.join(wrap_dir, "Dockerfile")
    assert os.path.exists(dockerfile)
    txt = open(dockerfile, encoding="utf-8").read()

    assert "ln -sfn /defaultroute.sh" in txt
    assert "ln -sfn /runtraffic.sh" in txt


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


def test_prepare_compose_inject_copy_uses_busybox_entrypoint_for_wrapper(tmp_path, monkeypatch):
    """Regression: inject_copy must work even if base image lacks /bin/sh/cp.

    When we wrap services into `coretg/*:iproute2`, the wrapper injects a BusyBox
    binary at /usr/local/coretg/bin/busybox. The inject_copy init service should
    use that BusyBox as entrypoint.
    """
    # Create a minimal compose.
    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        (
            "services:\n"
            "  app:\n"
            "    image: nginx:latest\n"
            "    command: ['sh','-lc','sleep 1']\n"
        ),
        encoding="utf-8",
    )

    # Prepare a fake artifacts dir with a file we will inject.
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "flag.txt").write_text("FLAG{X}\n", encoding="utf-8")

    # Force wrapper strategy to busybox injection (default) and enable inject copy mode.
    monkeypatch.setenv("CORETG_INJECT_FILES_MODE", "copy")
    monkeypatch.setenv("CORETG_COMPOSE_SET_CONTAINER_NAME", "1")

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
        "InjectFiles": ["flag.txt -> /tmp"],
        "InjectSourceDir": str(artifacts),
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    try:
        import yaml  # type: ignore
    except Exception:
        return

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    assert "inject_copy" in services or any(str(k).startswith("inject_copy") for k in services.keys())
    # Find the inject_copy service key.
    ik = "inject_copy" if "inject_copy" in services else sorted([k for k in services.keys() if str(k).startswith("inject_copy")])[0]
    inject = services[ik]
    assert isinstance(inject, dict)
    # When the target service is wrapped, inject_copy should use BusyBox entrypoint.
    # We don't assert the exact wrapper tag here, just the entrypoint behavior.
    ep = inject.get("entrypoint")
    if ep is not None:
        # compose can represent entrypoint as list or string
        text = " ".join(ep) if isinstance(ep, list) else str(ep)
        assert "/usr/local/coretg/bin/busybox" in text


def test_prepare_compose_flow_injects_default_to_flow_injects_dir(tmp_path, monkeypatch):
    """Regression: flow inject specs without explicit dest should default to /flow_injects."""
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  app:\n    image: nginx:latest\n    command: ['sh','-lc','sleep 1']\n",
        encoding="utf-8",
    )

    # Emulate a Flow artifacts run directory structure.
    flow_root = tmp_path / "tmp" / "vulns" / "flag_generators_runs" / "flow-x" / "01_gen" / "artifacts"
    flow_root.mkdir(parents=True, exist_ok=True)
    (flow_root / "payload.bin").write_text("x\n", encoding="utf-8")
    # Also include an outputs.json so expansion sees a plausible artifact key.
    (flow_root / "outputs.json").write_text('{"outputs": {"File(path)": "payload.bin"}}\n', encoding="utf-8")

    monkeypatch.setenv("CORETG_INJECT_FILES_MODE", "copy")

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
        "ArtifactsDir": str(flow_root),
        "ArtifactsMountPath": "/flow_artifacts",
        # No explicit dest
        "InjectFiles": ["File(path)"],
        "InjectSourceDir": str(flow_root),
        "OutputsManifest": str(flow_root / "outputs.json"),
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created
    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    # Find inject_copy service and verify volumes include /flow_injects volume mount.
    ikeys = [k for k in services.keys() if str(k).startswith("inject_copy")]
    assert ikeys, "expected inject_copy service"
    # Target service should mount an inject volume at /flow_injects.
    target = services.get("docker-1") or services.get("app")
    assert isinstance(target, dict)
    vols = target.get("volumes") or []
    assert any(str(v).endswith(":/flow_injects") for v in vols), vols


def test_prepare_compose_inject_copy_runtime_guard_nonfatal_by_default(tmp_path, monkeypatch):
    """Regression: inject_copy command should guard missing runtime sources by default."""
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  app:\n    image: nginx:latest\n    command: ['sh','-lc','sleep 1']\n",
        encoding="utf-8",
    )

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "present.txt").write_text("ok\n", encoding="utf-8")

    monkeypatch.setenv("CORETG_INJECT_FILES_MODE", "copy")
    monkeypatch.delenv("CORETG_INJECT_COPY_STRICT", raising=False)

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
        "InjectFiles": ["present.txt"],
        "InjectSourceDir": str(artifacts),
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created
    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    ikeys = [k for k in services.keys() if str(k).startswith("inject_copy")]
    assert ikeys, "expected inject_copy service"
    inject = services[ikeys[0]]
    assert isinstance(inject, dict)
    cmd = inject.get("command")
    cmd_text = " ".join(cmd) if isinstance(cmd, list) else str(cmd or "")
    assert "if [ -e" in cmd_text
    assert "missing /src/" in cmd_text
    assert "skipping" in cmd_text
    assert "exit 1" not in cmd_text


def test_prepare_compose_inject_copy_runs_as_root_for_volume_writes(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  app:\n    image: vulhub/weblogic:12.2.1.3-2018\n",
        encoding="utf-8",
    )

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "challenge.bin").write_text("ok\n", encoding="utf-8")

    monkeypatch.setenv("CORETG_INJECT_FILES_MODE", "copy")

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
        "InjectFiles": ["challenge.bin"],
        "InjectSourceDir": str(artifacts),
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created
    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    ikeys = [k for k in services.keys() if str(k).startswith("inject_copy")]
    assert ikeys, "expected inject_copy service"
    inject = services[ikeys[0]]
    assert isinstance(inject, dict)
    assert str(inject.get("user") or "") == "0:0"


def test_prepare_compose_root_workdir_auto_mode_skips_app_images(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  web:\n    image: vulhub/wordpress:6.0\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR", raising=False)

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    target = services.get("docker-1")
    assert isinstance(target, dict)
    assert "working_dir" not in target


def test_prepare_compose_root_workdir_auto_mode_does_not_force_nextjs(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  web:\n    image: vulhub/nextjs:15.5.6\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR", raising=False)

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    target = services.get("docker-1")
    assert isinstance(target, dict)
    assert "working_dir" not in target


def test_prepare_compose_root_workdir_auto_mode_forces_base_os(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  node:\n    image: ubuntu:22.04\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR", raising=False)

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    target = services.get("docker-1")
    assert isinstance(target, dict)
    assert target.get("working_dir") == "/"


def test_prepare_compose_root_workdir_auto_mode_forces_weblogic(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  web:\n    image: vulhub/weblogic:12.2.1.3-2018\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR", raising=False)

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    target = services.get("docker-1")
    assert isinstance(target, dict)
    assert target.get("working_dir") == "/"


def test_prepare_compose_root_workdir_can_force_all_with_env(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  web:\n    image: vulhub/nextjs:15.5.6\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR", "1")

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    target = services.get("docker-1")
    assert isinstance(target, dict)
    assert target.get("working_dir") == "/"


def test_prepare_compose_can_disable_root_workdir_with_env(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  web:\n    image: vulhub/nextjs:15.5.6\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR", "0")

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    target = services.get("docker-1")
    assert isinstance(target, dict)
    assert "working_dir" not in target


