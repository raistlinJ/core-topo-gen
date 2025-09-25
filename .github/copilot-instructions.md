# AI Coding Agent Instructions for core-topo-gen

Purpose: Generate CORE network topologies from XML scenarios via CLI or a Web GUI, then start sessions and write a Markdown report.

## Architecture Overview
- Python mono-repo with two primary entry points:
  - CLI: `core-python -m core_topo_gen.cli` (see `core_topo_gen/cli.py`). Use `core-python` if available in your environment to match the CORE install; otherwise `python`.
  - Web GUI: Flask app in `webapp/` (entry `webapp/app_backend.py`).
- Parsing: `core_topo_gen/parsers/xml_parser.py` reads the scenario XML per section (Node Information, Routing, Traffic, Segmentation).
- Topology build: `core_topo_gen/builders/topology.py` composes topologies (segmented, star, multi-switch) using CORE gRPC (`core.api.grpc.client`).
- Utilities:
  - Traffic: `core_topo_gen/utils/traffic.py` generates sender/receiver scripts under `/tmp/traffic` and enables a `Traffic` service.
  - Segmentation: `core_topo_gen/utils/segmentation.py` plans and applies rules; optionally writes `/tmp/segmentation/segmentation_summary.json`.
  - Report: `core_topo_gen/utils/report.py` writes Markdown reports into `./reports/scenario_report_<ts>.md`.
  - Services: `core_topo_gen/utils/services.py` adds CORE services to nodes.
- Plugins: Extensible behaviors in `core_topo_gen/plugins/*` (traffic, segmentation, static profiles).
- Tests: `tests/` validate parsing, traffic density selection, and report contents.

## Core Workflows
- CLI run:
  - Input: `--xml path/to/scenario.xml` (+ optional `--scenario`), CORE host/port.
  - Steps: parse XML -> compute roles -> build topology -> apply segmentation/services -> generate traffic -> write report -> start CORE session.
  - Output: returns 0 on success; logs include: `Scenario report written to <abs_path>`.
- Web run:
  - Save scenarios to `outputs/scenarios-<ts>/scenarios.xml`.
  - Run CLI module from repo root; parse stdout for the report path; fall back to newest `reports/scenario_report_*.md`.
  - Persist a JSON run history in `outputs/run_history.json` with `xml_path`, `report_path`, `pre_xml_path`, `timestamp`, `mode`.
  - Reports page reads history and renders links; deleting a scenario purges matching history and artifacts under `outputs/`.

## Conventions & Patterns
- XML schema:
  - Root `<Scenarios>` with one or more `<Scenario>` containing a `<ScenarioEditor>`.
  - Sections: `Node Information`, `Routing`, `Services`, `Traffic`, `Segmentation`, optional `Notes`.
    - Legacy attribute `total_nodes` (section-level) has been removed. Host counts are now purely additive at the role row level.
    - A scenario-level aggregate attribute `scenario_total_nodes` (on `<Scenario>`) represents the sum of all planned hosts (node roles + routers + vulnerability additive targets, etc.) written by the web UI.
  - Items use attributes `selected`, `factor`, and section-specific extras (e.g., `pattern`, `rate_kbps`).
- Report location: always under repo `./reports/`. The CLI logs an absolute path; the web app converts relative paths to absolute.
- Logs: Web async run tails `cli-<run_id>.log` and emits SSE at `/stream/<run_id>`.
- Safe deletes: Artifact deletion is scoped to `outputs/` only (XML/reports/pre-session captures). Reports in `./reports/` are not deleted.

## Dev Setup & Commands
- Install deps:
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```
- Run CLI locally (from repo root):
```bash
core-python -m core_topo_gen.cli --xml $(pwd)/sample.xml --verbose
```
- Run Web GUI locally:
```bash
python webapp/app_backend.py
open http://localhost:9090
```
- Run Web GUI via Docker:
```bash
docker build -t core-topogen-webapp ./webapp
docker run --rm -p 9090:9090 \
  -e CORE_HOST=host.docker.internal -e CORE_PORT=50051 \
  -v "$(pwd)":/work -w /work \
  core-topogen-webapp
# Open http://localhost:9090
```
- Run tests (pytest is not pinned here; install if needed):
```bash
pip install pytest
pytest -q
```

## Integration Notes (important for agents)
- Always run the CLI from the repo root (cwd) so `./reports` resolves correctly.
- When invoking CLI from code, prefer the module form: `core-python -m core_topo_gen.cli` and pass an absolute `--xml` path.
- Capture the report path by parsing the line `Scenario report written to ...` from stdout; if missing, select the latest `reports/scenario_report_*.md`.
- Ensure `--xml` is an absolute path; if a relative path is received from the webapp, resolve it via `os.path.abspath` before invoking the CLI.
- gRPC CORE connectivity (host/port) is configurable via CLI args and via the web form; Dockerized environments may use `host.docker.internal`.
- Web run history (`outputs/run_history.json`) is the single source of truth for the Reports UI; mutate via `_append_run_history`.
- Purging history due to scenario deletion also removes artifacts under `outputs/` (not from `./reports`).

## File Map (jump starts)
- Entry points: `core_topo_gen/cli.py`, `webapp/app_backend.py`.
- Parsing: `core_topo_gen/parsers/xml_parser.py`.
- Builders: `core_topo_gen/builders/topology.py`.
- Utils: `core_topo_gen/utils/{traffic.py,segmentation.py,services.py,report.py}`.
- Tests: `tests/`.

If anything above is unclear (e.g., additional CLI flags, report format details), indicate which section needs elaboration and I’ll refine this document.
