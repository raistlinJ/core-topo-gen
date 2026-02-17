import os


def test_prepare_compose_injects_keepalive_for_base_os_image(tmp_path):
    from core_topo_gen.utils.vuln_process import prepare_compose_for_assignments

    src = tmp_path / "docker-compose.yml"
    # No command/entrypoint: ubuntu base image would normally exit immediately.
    src.write_text(
        "services:\n  app:\n    image: ubuntu:22.04\n",
        encoding="utf-8",
    )

    rec = {"Type": "docker-compose", "Name": "base", "Path": str(src)}
    created = prepare_compose_for_assignments({"docker-1": rec}, out_base=str(tmp_path))
    out_path = tmp_path / "docker-compose-docker-1.yml"

    assert str(out_path) in created
    text = out_path.read_text(encoding="utf-8", errors="ignore")
    assert "sleep infinity" in text


def test_prepare_compose_does_not_force_keepalive_for_service_image(tmp_path):
    from core_topo_gen.utils.vuln_process import prepare_compose_for_assignments

    src = tmp_path / "docker-compose.yml"
    # nginx has an image entrypoint that should be left alone.
    src.write_text(
        "services:\n  app:\n    image: nginx:latest\n",
        encoding="utf-8",
    )

    rec = {"Type": "docker-compose", "Name": "svc", "Path": str(src)}
    prepare_compose_for_assignments({"docker-2": rec}, out_base=str(tmp_path))
    out_path = tmp_path / "docker-compose-docker-2.yml"
    text = out_path.read_text(encoding="utf-8", errors="ignore")

    assert "sleep infinity" not in text


def test_prepare_compose_does_not_force_keepalive_for_nfs_server_alpine(tmp_path):
    from core_topo_gen.utils.vuln_process import prepare_compose_for_assignments

    src = tmp_path / "docker-compose.yml"
    # This is NOT the base `alpine:*` image; it merely contains the substring.
    src.write_text(
        "services:\n  node:\n    image: itsthenetwork/nfs-server-alpine:latest\n",
        encoding="utf-8",
    )
    rec = {"Type": "docker-compose", "Name": "nfs", "Path": str(src)}
    prepare_compose_for_assignments({"docker-5": rec}, out_base=str(tmp_path))
    out_path = tmp_path / "docker-compose-docker-5.yml"
    text = out_path.read_text(encoding="utf-8", errors="ignore")
    assert "sleep infinity" not in text
