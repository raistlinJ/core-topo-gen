import os


def test_prepare_compose_for_assignments_aliases_service_to_node_name(tmp_path):
    """CORE docker nodes run `docker compose up -d <node_name>`.

    If a compose file uses a generic service key (e.g. `generator`), CORE will fail
    with: `no such service: <node_name>`.
    """

    from core_topo_gen.utils.vuln_process import prepare_compose_for_assignments

    node_name = "standard-ubuntu-docker-core"
    src = tmp_path / "docker-compose.yml"
    src.write_text(
        "services:\n  generator:\n    image: alpine:3.19\n    command: ['sh','-lc','echo ok']\n",
        encoding="utf-8",
    )

    rec = {"Type": "docker-compose", "Name": "test", "Path": str(src)}
    created = prepare_compose_for_assignments({node_name: rec}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / f"docker-compose-{node_name}.yml"
    assert out_path.exists()
    text = out_path.read_text(encoding="utf-8", errors="ignore")
    # Minimal check without YAML parser: ensure the node service key appears.
    assert f"{node_name}:" in text
