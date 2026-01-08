import os
import tempfile

from core_topo_gen.utils.vuln_process import extract_compose_images_and_container_names


def test_extract_compose_images_and_container_names():
    doc = """
version: '3.8'
services:
  a:
    image: nginx:1.25
    container_name: node-a
  b:
    image: redis:7
    container_name: node-b
""".lstrip()

    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, 'docker-compose.yml')
        with open(p, 'w', encoding='utf-8') as f:
            f.write(doc)

        images, containers = extract_compose_images_and_container_names(p)
        assert images == ['nginx:1.25', 'redis:7']
        assert containers == ['node-a', 'node-b']
