from core_topo_gen.cli import _expected_container_config_from_compose


def test_expected_container_config_from_compose_reads_image_and_command(tmp_path):
    p = tmp_path / "docker-compose.yml"
    p.write_text(
        """
services:
  node1:
    image: alpine:3.19
    command: ['sh','-lc','sleep 1']
""".lstrip(),
        encoding="utf-8",
    )
    out = _expected_container_config_from_compose(str(p), "node1")
    assert out is not None
    assert out.get('image') == 'alpine:3.19'
    assert out.get('command') == ['sh', '-lc', 'sleep 1']
