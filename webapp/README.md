# CORE TopoGen Web UI

Flask Web UI for building, previewing, and executing CORE topology scenarios.

Key capabilities:
- Upload/edit scenarios and generate a Full Preview (roles, routers, links, services, vulnerabilities, segmentation).
- Execute the CLI to create/start CORE sessions and write Markdown reports under `./reports/`.
- Manage Generator Packs (flag-generators + flag-node-generators) and build Attack Flows.
- Manage Vulnerability Catalog Packs (docker-compose templates) and test individual catalog items.

Remote CORE VM support:
- Scenario Execute can run remotely on a CORE VM via SSH.
- Generator **Test** runs can optionally execute on the CORE VM (via SSH) to reduce Test-vs-Execute drift.
- Vulnerability catalog item **Test** runs execute on the CORE VM and use offline-friendly preflight steps (build wrapper images, pull pull-only images, start with `--no-build`).

## Local dev

From the repo root:

```bash
python webapp/app_backend.py
open http://localhost:9090
```

## Docker

```bash
docker build -t core-topogen-webapp ./webapp
docker run --rm -p 9090:9090 \
	-e CORE_HOST=host.docker.internal -e CORE_PORT=50051 \
	-v "$(pwd)":/work -w /work \
	core-topogen-webapp
```
