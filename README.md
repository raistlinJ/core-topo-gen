# CORE TopoGen

Generate reproducible CORE network topologies from scenario XML files using a rich Web GUI or a command-line interface.

## Table of contents
- [Highlights](#highlights)
- [Screenshots](docs/screenshots.md)
- [Quick start](#quick-start)
	- [Prerequisites](#prerequisites)
	- [Install dependencies](#install-dependencies)
	- [Launch the Web UI](#launch-the-web-ui)
	- [Run the CLI](#run-the-cli)
	- [VS Code smoke tasks](#vs-code-smoke-tasks)
- [Full Preview workflow](#full-preview-workflow)
- [Feature deep dive](#feature-deep-dive)
	- [Planning semantics](#planning-semantics)
	- [Router connectivity & aggregation](#router-connectivity--aggregation)
	- [Traffic, segmentation, and services](#traffic-segmentation-and-services)
	- [Reports & artifacts](#reports--artifacts)
	- [Generator packs & manifests](#generator-packs--manifests)
	- [Vulnerability catalog packs](#vulnerability-catalog-packs)
- [Architecture overview](#architecture-overview)
- [Troubleshooting](#troubleshooting)
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

## Quick start

### Prerequisites
- Python 3.10+ (3.11 recommended)
- [CORE](https://www.nrl.navy.mil/Our-Work/Areas-of-Research/CORE/) 9.2 or newer with `core-daemon` running
- Docker (optional) for nginx reverse proxy or vulnerability compose targets

### Install dependencies
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Launch the Web UI
Start the full stack (webapp + HTTPS reverse proxy):
```bash
docker compose up -d --build
```
- Visit `https://localhost`.
- First launch seeds a `coreadmin / coreadmin` account; change it immediately under **Profile → Change Password**.
- Dev certs are generated automatically inside the nginx container (mounted under `nginx/certs/`).
- HITL editor note: the “Attach to” dropdown offers `Existing Router`, `Existing Switch`, or `New Router`. Once Proxmox credentials and VM selections are validated, use **Apply Internal Bridge** to create/update a Proxmox bridge and retarget both the CORE VM and external VM interfaces in one step.

### Run the CLI
```bash
python -m core_topo_gen.cli --xml path/to/scenario.xml --seed 42 --verbose
```
Popular options:
- `--scenario NAME` pick a specific scenario entry
- `--host / --port` override the CORE gRPC endpoint (defaults `127.0.0.1:50051`)
- `--layout-density {compact|normal|spacious}` adjust map spacing
- `--seg-include-hosts`, `--seg-allow-docker-ports`, `--nat-mode`, `--dnat-prob` fine-tune segmentation
- `--traffic-pattern`, `--traffic-rate`, `--traffic-content` override traffic defaults

### VS Code smoke tasks
For Execute retry-prompt validation, use these tasks from **Terminal → Run Task**:

- `Smoke UI Execute Retry Prompt`  
	Runs `scripts/ui_execute_retry_smoke.py` against the currently running Web UI.
- `Restart + Smoke UI Execute Retry Prompt`  
	Restarts Web UI on port 9090, waits for `/healthz`, then runs the same smoke.

Expected success output includes:

- `prompt_seen=True`
- `retry_click=ok`
- `retry_run_id_before=<id>`
- `retry_run_id_after=<different-id>`

## Full Preview workflow
1. **Save XML** – The editor auto-saves, but hitting “Save XML” ensures consistent previews.
2. **(Optional) Set seed** – Enter an integer seed to get deterministic topology output.
3. **Generate Full Preview** – Shows router/host counts, R2R/R2S policies, segmentation, services, traffic, and vulnerability assignments before any CORE call.
4. **Review structured sections** – Toggle between structured cards and raw JSON; history stores the last 25 previews in local storage.
5. **Run (Seed)** – Launches the CLI asynchronously, streams logs into the dock, and writes a Markdown report to `./reports/`.

## Feature deep dive

### Planning semantics
- Host planning honours **Base Hosts** (density) and **Count** rows; metadata is written into XML (`base_nodes`, `additive_nodes`, `combined_nodes`, etc.) for round-trip fidelity.
- Router and vulnerability planning capture derived vs explicit counts via `explicit_count`, `derived_count`, and `total_planned`.
- Scenario-level `scenario_total_nodes` summarises planned hosts, routers, and vulnerability targets.
- Parser helpers expose metadata programmatically: `core_topo_gen.parsers.planning_metadata.parse_planning_metadata()`.
- Hardware-in-the-Loop plans persist per-scenario preferences (enabled state, interface list, attachment choice). Attachments normalize to `existing_router`, `existing_switch`, `new_router`, or `proxmox_vm`. When interfaces map to Proxmox VMs, the apply flow ensures the selected bridge exists on the node (creating it if needed) and rewrites the CORE/external VM adapters to land on that bridge.

### Router connectivity & aggregation
- Per-routing-item `r2r_mode` supports `Exact`, `Uniform`, `NonUniform`, `Min`, `Max`.
- R2S policies (`r2s_mode`, `r2s_edges`, optional `r2s_hosts_min/max`) regroup hosts behind dedicated switches, with “Exact=1” aggregating all hosts per router into a single switch.
- Preview JSON and runtime stats capture router degrees, aggregation counts, and Gini coefficients for quick balance checks.

### Traffic, segmentation, and services
- Traffic scripts land in `/tmp/traffic` (with companion services) and respect overrides for pattern, rate, jitter, and content hints.
- Segmentation scripts land in `/tmp/segmentation` alongside a `segmentation_summary.json`; NAT mode, DNAT probability, host inclusion, and docker port allowances are configurable.
- Docker vulnerabilities attach per-node docker-compose files in `/tmp/vulns` with `network_mode: none` enforced per service (to prevent Docker-injected `eth0`/default gateways), and metadata embedded into CORE nodes.
- Custom traffic plugins can register via `core_topo_gen.plugins.traffic.register()` for bespoke sender/receiver code.

### Reports & artifacts
- Markdown reports (`./reports/scenario_report_<timestamp>.md`) enumerate topology stats, planning metadata, segmentation results, and runtime artefacts. Each run also emits a JSON summary alongside the Markdown file (`scenario_report_<timestamp>.json`) plus per-run connectivity CSVs when router degree data is available.
- Run history is persisted in `outputs/run_history.json` for the Reports page.
- Safe deletion keeps reports while purging associated outputs under `outputs/` when scenarios are removed via the GUI.

### Generator packs & manifests
- The Web UI treats **installed generators** as the source of truth: it discovers generators from `manifest.yaml`/`manifest.yml` under `outputs/installed_generators/`.
- Installed generators are managed as **Generator Packs** (ZIP files). You can upload/import packs from the Flag Catalog page.
- Disable semantics:
	- Packs and individual generators can be disabled.
	- Disabled generators are hidden from Flow substitution and are rejected at preview/execute time.

### Flag sequencing (Flow) highlights
- Initial/Goal facts steer sequencing (flag facts are filtered out); synthesized inputs like `seed`, `node_name`, and `flag_prefix` are treated as known inputs.
- Sequencing uses goal-aware scoring with pruning/backtracking (bounded by a 30s timeout) to find feasible generator assignments.
- Attack Flow Builder export is the native `.afb` format (OpenChart DiagramViewExport).
- The Flow UI marks required inputs with `*` based on manifest inputs (`required: true`) and artifact `requires` (optional artifacts live in `optional_requires`).
- Goal Facts list shows per-variable source badges (e.g., `Seq I`) derived from the chain assignments.
- If a chain length exceeds unique eligible generators, the UI prompts to allow generator reuse; declining clears the chain.

### Vulnerability catalog packs
- The Web UI exposes a **Vuln-Catalog** page that mirrors the Flag Catalog pack UX.
- You can upload/import a ZIP containing directories/subdirectories.
	- Any directory that contains a `docker-compose.yml` is treated as a valid vulnerability template.
	- All other files in those directories are preserved.
	- The UI provides a per-pack file browser so users can download/view the extracted files.
	- The server generates a `vuln_list_w_url.csv` internally so downstream vulnerability selection/processing remains unchanged.

## Architecture overview
| Folder | Purpose |
| --- | --- |
| `core_topo_gen/cli.py` | CLI entry point; orchestrates parsing, planning, building, and report generation |
| `core_topo_gen/parsers/` | Modular XML parsers per scenario section (node info, routing, traffic, services, vulnerabilities, segmentation) |
| `core_topo_gen/builders/topology.py` | Builds star, multi-switch, and segmented topologies using CORE gRPC APIs |
| `core_topo_gen/utils/` | Supporting allocators, report writers, traffic/segmentation/service helpers |
| `webapp/` | Flask Web UI, templates, SSE log streaming, history persistence |
| `webapp/templates/partials/dock.html` | Persistent logs/XML dock with follow toggle and filters |
| `tests/` | Pytest suite covering planning semantics, policy enforcement, preview parity, and CLI behaviours |
| `docs/` | Additional documentation assets (screenshots, notes) |

## Troubleshooting
- **`core-python` not found`** – set `WEBUI_PY` before `make host-web` or rely on `python3`; the backend falls back to `sys.executable` if needed.
- **Empty TLS cert folder (`nginx/certs`)** – run `scripts/dev_gen_certs.sh` or `make dev-certs` before composing nginx.
- **`core-daemon` unreachable`** – verify daemon status and host/port; GUI run modal will surface connection issues immediately.
- **Docker vulnerabilities skipped** – ensure images are downloaded/pulled via the Vulnerabilities catalog and Docker is available to the host.
- **Log dock won’t auto-scroll** – click the “Follow Off/On” toggle to re-enable auto-follow.
- **Proxmox validate returns 502 (nginx)** – run `python scripts/proxmox_validate_smoke.py --base-url https://localhost` and confirm you get a clean `401 Authentication failed` (bad creds) or `success: true` (good creds) rather than a 502.

## Additional documentation
- [API.md](./API.md) – REST endpoints exposed by the Web UI backend
- Flag Sequencing (Flow) endpoints and Attack Flow Builder `.afb` export are documented in [API.md](./API.md) and the OpenAPI spec at [`docs/openapi.yaml`](docs/openapi.yaml).
- Generator authoring (flag-generators and flag-node-generators) is documented in [docs/GENERATOR_AUTHORING.md](docs/GENERATOR_AUTHORING.md).
- AI prompt templates for generator authoring (copy/paste) are in [docs/AI_PROMPT_TEMPLATES.md](docs/AI_PROMPT_TEMPLATES.md).
- For generator reliability, validate both UI Test and full Execute paths (remote CORE runtime). See the Test/Execute parity checklist in [docs/GENERATOR_AUTHORING.md](docs/GENERATOR_AUTHORING.md).
- Execute validation now exposes downloadable per-issue logs via `validation_summary.error_logs` in `run_status` (documented in [API.md](./API.md)).
- [SCENARIO_XML_SCHEMA.md](./SCENARIO_XML_SCHEMA.md) – Schema walkthrough and examples

## Contributing
Pull requests and issue reports are welcome! Please run the relevant pytest targets (`pytest -q`) before submitting changes and keep documentation up to date when behaviour changes.