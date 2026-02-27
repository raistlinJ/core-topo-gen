# CORE TopoGen

Generate reproducible CORE network topologies from scenario XML files using a rich Web GUI or a command-line interface.

## Table of contents
- [Highlights](#highlights)
- [Screenshots](docs/screenshots.md)
- [Quick start](docs/QUICK_START.md)
- [Full Preview workflow](docs/FULL_PREVIEW_WORKFLOW.md)
- [Feature deep dive](docs/FEATURE_DEEP_DIVE.md)
- [Architecture overview](docs/ARCHITECTURE_OVERVIEW.md)
- [Restrictions & limitations](docs/RESTRICTIONS_LIMITATIONS.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Additional documentation](#additional-documentation)
- [Contributing](#contributing)

## Highlights
- **Single-source planning** – edit scenarios in the browser or any XML editor and reproduce results with the CLI.
- **Deterministic previews** – optional RNG seed locks in host expansion, router placement, connectivity, services, segmentation, and vulnerability assignment.
- **Live log dock** – stream run output, filter by level or text/regex, and toggle auto-follow for long runs.
- **Rich topology policies** – per-routing-item R2R meshes, R2S aggregation, host grouping bounds, and switch re-homing.
- **Artifacts on disk** – traffic scripts, segmentation rules, docker-compose definitions, Markdown reports, and JSON summaries are written to predictable locations for inspection.
- **Hardware-in-the-Loop friendly** – manage HITL attachments directly in the editor, apply Proxmox bridge rewiring from the browser, and keep topologies deterministic by constraining attachments and generated devices.
	- Participant graph renders HITL interface nodes (e.g., `ens19`) as **HITL** with a prominent “YOU ARE HERE” callout and keeps them visually separated from the main topology.
	- HITL nodes intentionally omit IP labels in the graph to avoid implying that interface/network objects are routable “hosts”.
	- The graph legend labels docker-based vulnerability targets as **vulnerability** and renders them in bright red.

## Screenshots

View the WebUI images gallery [`docs/screenshots.md`](docs/screenshots.md).

## Install
- Prereqs: Python 3.10+ and [uv](https://docs.astral.sh/uv/)
- Install dependencies:
```bash
uv sync --extra dev
```
- Run local Web UI:
```bash
uv run python webapp/app_backend.py
```
- Run HTTPS Web UI with Docker Compose:
```bash
docker compose up -d --build
```
- Open `https://localhost` and verify health:
```bash
curl -k https://localhost/healthz
```
- Safety: in Execute → Advanced, `Delete all docker containers` is disabled when the Web UI is running in Docker.
- Stop Docker stack:
```bash
docker compose down
```
- Run CLI:
```bash
uv run python -m core_topo_gen.cli --xml path/to/scenario.xml --seed 42 --verbose
```
- More setup detail: [docs/QUICK_START.md](docs/QUICK_START.md).

## Guides
- [Quick start](docs/QUICK_START.md)
- [Full Preview workflow](docs/FULL_PREVIEW_WORKFLOW.md)
- [Feature deep dive](docs/FEATURE_DEEP_DIVE.md)
- [Architecture overview](docs/ARCHITECTURE_OVERVIEW.md)
- [Restrictions & limitations](docs/RESTRICTIONS_LIMITATIONS.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

## Additional documentation
- [docs/README.md](docs/README.md) – Index of project documentation pages
- [API.md](./API.md) – REST endpoints exposed by the Web UI backend
- Flag Sequencing (Flow) endpoints and Attack Flow Builder `.afb` export are documented in [API.md](./API.md) and the OpenAPI spec at [`docs/openapi.yaml`](docs/openapi.yaml).
- Generator authoring (flag-generators and flag-node-generators) is documented in [docs/GENERATOR_AUTHORING.md](docs/GENERATOR_AUTHORING.md).
- AI prompt templates for generator authoring (copy/paste) are in [docs/AI_PROMPT_TEMPLATES.md](docs/AI_PROMPT_TEMPLATES.md).
- For generator reliability, validate both UI Test and full Execute paths (remote CORE runtime). See the Test/Execute parity checklist in [docs/GENERATOR_AUTHORING.md](docs/GENERATOR_AUTHORING.md).
- Execute validation now exposes downloadable per-issue logs via `validation_summary.error_logs` in `run_status` (documented in [API.md](./API.md)).
- [SCENARIO_XML_SCHEMA.md](./SCENARIO_XML_SCHEMA.md) – Schema walkthrough and examples

## Contributing
Pull requests and issue reports are welcome! Please run the relevant pytest targets (`pytest -q`) before submitting changes and keep documentation up to date when behaviour changes.

If using uv, run tests with:
```bash
uv run pytest -q
```