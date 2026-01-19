# CORE Topology Generator API

This guide documents the HTTP surface exposed by the CORE Topology Generator web backend (`webapp/app_backend.py`) and the CLI entry point (`core_topo_gen.cli`). Use it to script scenario management, trigger runs, download artifacts, and integrate with external systems.

## Base Environment

- **Default base URL:** `http://localhost:9090`
- **Entry modules:**
	- Web server: `python webapp/app_backend.py`
	- CLI: `core-python -m core_topo_gen.cli` (fall back to `python -m core_topo_gen.cli` if `core-python` is unavailable)
- **Artifacts:**
	- Scenario XML snapshots: `outputs/scenarios-<timestamp>/`
	- Run history index: `outputs/run_history.json`
	- Reports: `./reports/scenario_report_<timestamp>.md`

## Authentication

The web UI uses cookie sessions. Script clients must authenticate once and reuse the cookie for subsequent requests.

1. `POST /login`
	 - Form fields: `username`, `password`
	 - Success: HTTP 302 redirect to `/` with a `session` cookie.
	 - Failure: HTTP 200 with an error message rendered in HTML.
2. `POST /logout`
	 - Clears the session and redirects to `/`.

**First run:** The app may create a default admin user. Refer to the README for the bootstrap credentials and rotate them immediately.

## Request & Response Conventions

- JSON payloads and responses are UTF-8 encoded.
- Unless noted, endpoints return `{ "ok": boolean, ... }` or redirect to HTML views.
- File parameters must be provided using `multipart/form-data`.
- Absolute paths are recommended (`os.path.abspath`). When a relative path is supplied, the server resolves it against the repo root where possible.
- Safe-delete operations only touch files under `uploads/` or `outputs/`; reports in `./reports/` are preserved.
- Planning preview results are cached in `outputs/plan_cache.json`, keyed by `(xml_hash, scenario, seed)`. Override the location with `TOPO_PLAN_CACHE_PATH`.

## Endpoint Groups

- [Health](#health)
- [Scenario Lifecycle](#scenario-lifecycle)
- [Planning Preview](#planning-preview)
- [Flag Sequencing (Flow)](#flag-sequencing-flow)
- [Run Execution & Reports](#run-execution--reports)
- [Script Inspection](#script-inspection)
- [Docker Helpers](#docker-helpers)
- [CORE Session Management](#core-session-management)
- [Data Sources & Vulnerability Catalog](#data-sources--vulnerability-catalog)
- [Generator Builder](#generator-builder)
- [Generator Packs & Installed Generators](#generator-packs--installed-generators)
- [Diagnostics & Maintenance](#diagnostics--maintenance)
- [User Administration](#user-administration)

### Health

`GET /healthz`

- Returns plain-text `OK` when the server is running.

### Scenario Lifecycle

`POST /load_xml`
: Multipart upload (`scenarios_xml` `.xml` file). Loads the file into the editor state and renders the main page.

`POST /save_xml`
: Form field `scenarios_json` (stringified JSON). Persists the editor payload to `outputs/scenarios-<timestamp>/scenarios.xml` and re-renders the editor. The saved XML includes additive planning attributes (`base_nodes`, `combined_nodes`, `explicit_count`, etc.) for lossless round-tripping.

`POST /save_xml_api`
: JSON body `{ "scenarios": [...], "active_index"?: int }`. Returns `{ "ok": true, "result_path": ".../scenarios.xml" }` on success or `{ "ok": false, "error": "..." }` with HTTP 400/500 on failure.

`GET /api/host_interfaces`
: Returns `{ "interfaces": [...] }` describing host NICs on the web host (`name`, `mac`, `ipv4`, `ipv6`, `mtu`, `speed`, `flags`, `is_up`). Requires `psutil`; if unavailable, returns an empty list with a warning in logs. Primarily a legacy/debug fallback when CORE credentials are not configured.

`POST /api/host_interfaces`
: JSON body `{ "core_secret_id": "...", "core_vm": { "vm_key": "node::vmid", "vm_name": "...", "vm_node": "...", "vmid": "...", "interfaces": [...] }, "include_down"?: bool }`. Enumerates network interfaces from the selected CORE VM over SSH using stored credentials. Response `{ "success": true, "interfaces": [...], "source": "core_vm", "metadata": { ... }, "fetched_at": "<iso8601>" }` includes Proxmox VM/interface metadata when MAC addresses match the supplied `core_vm.interfaces`. Only physical adapters (those backed by `/sys/class/net/<iface>/device`) are returned. Errors return `{ "success": false, "error": "..." }` with HTTP 4xx/5xx.

`POST /upload_base`
: Multipart upload (`base_xml`). Attaches a CORE base topology XML to the active scenario. Redirects to `/`.

`POST /remove_base`
: Optional `scenarios_json` to retain other edits while clearing the base topology. Renders the updated editor view.

`GET /base_details`
: Query `path=<abs_xml_path>`. Renders an HTML summary validating the CORE XML.

### Planning Preview

`POST /api/plan/preview_full`

Generates a deterministic planning preview without starting a CORE session.

**Request JSON**

```json
{
	"xml_path": "/abs/path/to/scenarios.xml",
	"scenario": "Scenario Name",        // optional
	"seed": 12345                        // optional; random when omitted (returned in response)
}
```

**Response JSON**

```json
{
	"ok": true,
	"full_preview": {
		"routers": [...],
		"hosts": [...],
		"switches": [...],
		"services_preview": {...},
		"vulnerabilities_preview": {...},
		"segmentation_preview": {...},
		"traffic_preview": {...},
		"seed": 12345,
		"seed_generated": false
	},
	"plan": {
		"role_counts": {"Workstation": 12, ...},
		"routers_planned": 3,
		"service_plan": {...},
		"vulnerability_plan": {...},
		"segmentation_plan": {...},
		"traffic_plan": {...}
	},
	"breakdowns": {
		"node": {...},
		"router": {...},
		"services": {...},
		"vulnerabilities": {...},
		"segmentation": {...},
		"traffic": {...}
	}
}
```

**Notes**

- `seed` is echoed or generated automatically. Store it to reproduce the same topology.
- `r2s_policy_preview.per_router_bounds` includes min/max bounds when NonUniform host grouping is requested via XML attributes (`r2s_hosts_min`/`r2s_hosts_max`).
- Exact aggregation (`r2s_mode=Exact` and `r2s_edges=1`) collapses hosts behind a single switch and ignores bounds.
- Preview responses are cached; purge `outputs/plan_cache.json` to invalidate.

### Flag Sequencing (Flow)

These endpoints power the **Flow** page (Flag Sequencing) in the Web UI.

Important notes:
- **STIX/AttackFlow bundle export has been removed.** Legacy STIX endpoints now return HTTP `410 Gone`.
- The supported export format is **Attack Flow Builder native `.afb`**.
- **Eligibility rules:** `flag-generators` are placed on vulnerability nodes only; `flag-node-generators` require non-vulnerability Docker-role nodes.
- **Initial Facts / Goal Facts:** Flow accepts optional `initial_facts` and `goal_facts` overrides (artifacts + fields). Flag facts (`Flag(...)`) are filtered out.
- **Sequencing algorithm:** Goal-aware scoring with pruning/backtracking (bounded by a 30s timeout) is used to select feasible generator assignments.

`GET /api/flag-sequencing/attackflow_preview`
: Returns a chain preview derived from the latest preview plan for the scenario. Response includes `chain`, `flag_assignments`, and validity metadata (`flow_valid`, `flow_errors`, `flags_enabled`).

Common query params:
- `scenario=<name>` (optional; best to provide explicitly)
- `length=<int>` (default 5)
- `preset=<name>` (optional; forces a fixed chain)
- `best_effort=1` (optional; clamps to available eligible nodes)
- `debug_dag=1` (optional; include sequencing DAG diagnostics)

`POST /api/flag-sequencing/prepare_preview_for_execute`
: Resolves hint placeholders and materializes generator outputs for a chain (used for “Resolve hint values…” in the Flow UI).

Request JSON (typical):
```json
{
	"scenario": "My Scenario",
	"length": 5,
	"preset": "",
	"chain_ids": ["n1", "n2"],
	"preview_plan": "/abs/path/to/outputs/plans/plan_from_preview_....json",
	"mode": "hint",
	"best_effort": true,
	"allow_node_duplicates": false,
	"timeout_s": 30
}
```

`POST /api/flag-sequencing/afb_from_chain`
: Generates an Attack Flow Builder export for a user-specified ordered chain.

Request JSON:
```json
{
	"scenario": "My Scenario",
	"chain": [{"id": "n1", "name": "Node 1"}, {"id": "n2", "name": "Node 2"}]
}
```

Response JSON includes:
- `afb` (an OpenChart DiagramViewExport document)
- `attack_graph` (simple node/edge JSON derived from the chain)
- `attack_graph_dot` (Graphviz DOT for the attack graph)
- `attack_graph_pdf_base64` (base64-encoded PDF; requires Graphviz `dot`)
- `flag_assignments` and validity metadata

`POST /api/flag-sequencing/save_flow_substitutions`
: Persists a user-edited chain + generator overrides into a `plan_from_flow_*.json` plan. This is used by “Save Overrides” and the Flow tab state persistence.

Request JSON (typical):
```json
{
	"scenario": "My Scenario",
	"chain_ids": ["n1", "n2"],
	"preview_plan": "/abs/path/to/outputs/plans/plan_from_preview_....json",
	"allow_node_duplicates": false,
	"flag_assignments": [
		{
			"node_id": "n1",
			"id": "123",
			"config_overrides": {"host_ip": "10.0.0.5"},
			"output_overrides": {"Credential(user)": "alice"},
			"inject_files_override": ["File(path) -> /opt/bin"],
			"hint_overrides": ["Next: ..."],
			"flag_override": "FLAG{OVERRIDE}",
			"resolved_inputs": {"host_ip": "10.0.0.5"},
			"resolved_outputs": {"Credential(user)": "alice"},
			"flag_value": "FLAG{OVERRIDE}"
		}
	],
	"initial_facts": {"artifacts": ["Knowledge(ip)"], "fields": ["host_ip"]},
	"goal_facts": {"artifacts": ["Credential(user,password)"], "fields": []}
}
```

`POST /api/flag-sequencing/upload_flow_input_file`
: Uploads a file for a generator input override. Returns a stored file path to reference in `config_overrides`.

`POST /api/flag-sequencing/upload_flow_inject_file`
: Uploads a file for `inject_files_override`. Returns an `inject_value` token (`upload:<abs_path>`) that can be used in the override list.

Deprecated endpoints (removed):
- `POST /api/flag-sequencing/bundle_from_chain` → returns `410 Gone`
- `GET /api/flag-sequencing/attackflow` → returns `410 Gone`

### Generator Builder

These endpoints power the **Generator-Builder** page in the Web UI.

`GET /generator_builder`
: HTML page that helps scaffold new generators.

`POST /api/generators/scaffold_meta`
: JSON request describing the generator you want. Returns `{ ok, manifest_yaml, scaffold_paths }`.

UI terminology:
- The Generator Builder page labels artifact dependencies as **Inputs (artifacts)** and **Outputs (artifacts)**.
- The API field names remain `requires` / `optional_requires` / `produces` to match generator manifest fields.

Example request:

```json
{
	"plugin_type": "flag-generator",
	"plugin_id": "my_ssh_creds",
	"folder_name": "py_my_ssh_creds",
	"name": "SSH Credentials",
	"description": "Emits deterministic SSH credentials.",
	"requires": [
		{"artifact": "Credential(user)", "optional": true},
		{"artifact": "Credential(user, password)", "optional": false}
	],
	"optional_requires": [],
	"produces": ["Flag(flag_id)", "Credential(user)", "Credential(user, password)"],
	"inputs": {"seed": true, "secret": true, "flag_prefix": true},
	"hint_templates": ["Next: SSH using {{OUTPUT.Credential(user)}} / {{OUTPUT.Credential(user,password)}}"],
	"inject_files": ["File(path)"],
	"compose_text": "(optional full docker-compose.yml override)",
	"readme_text": "(optional full README.md override)"
}
```

Notes:
- `requires` must be a list of objects `{ artifact, optional }`.
- `inputs` is a list of runtime input definitions (name/type/required/etc) written into `manifest.yaml`.
- `inject_files` is optional; when present it is written into `manifest.yaml` as `injects`.
- Optional destination directory syntax: `inject_files: ["File(path) -> /opt/bin"]`. If omitted or invalid, files default to `/tmp`.

`POST /api/generators/scaffold_zip`
: Same JSON request body as `/api/generators/scaffold_meta`, but returns a ZIP you can unzip into the repo root.

Registering the scaffolded generator:
- The scaffold ZIP creates a folder under `flag_generators/<folder>/...` or `flag_node_generators/<folder>/...`.
- Package/install workflow: add a `manifest.yaml` to the generator folder, zip it as a Generator Pack, and install it via the Flag Catalog page.

### Generator Packs & Installed Generators

These endpoints support Generator Packs (ZIP files) and the installed generator set used by the Web UI + Flow.

Important behavior:
- Installed generators live under `outputs/installed_generators/`.
- On install, each generator is assigned a **new numeric ID** (string) and the installed `manifest.yaml` is rewritten to that ID.
- Packs and generators can be disabled; disabled generators are rejected by Flow preview/execute.

#### Pack lifecycle (HTML form endpoints)

`POST /generator_packs/upload`
: Multipart form with `zip_file` (a `.zip`). Installs a pack and redirects back to the Flag Catalog page. If called with `X-Requested-With: XMLHttpRequest`, returns JSON `{ ok, message|error }`.

`POST /generator_packs/import_url`
: Form field `zip_url` (HTTP/HTTPS URL to a `.zip`). Downloads and installs the pack.

`POST /generator_packs/delete/<pack_id>`
: Uninstalls the pack. Deletes installed generator directories recorded in the pack state (scoped to the installed-generators root).

`POST /generator_packs/set_disabled/<pack_id>`
: Toggles pack disabled state (form endpoint).

`GET /generator_packs/download/<pack_id>`
: Downloads a ZIP representing the installed pack (including installed manifests).

`GET /generator_packs/export_all`
: Downloads a bundle ZIP containing one ZIP per installed pack under `packs/<pack_id>.zip`.

#### Pack/generator disable + delete (JSON endpoints)

`POST /api/generator_packs/set_disabled`
: JSON `{ "pack_id": "...", "disabled": true|false }`.

`POST /api/flag_generators/set_disabled`
: JSON `{ "generator_id": "...", "disabled": true|false }`.

`POST /api/flag_node_generators/set_disabled`
: JSON `{ "generator_id": "...", "disabled": true|false }`.

`POST /api/flag_generators/delete`
: JSON `{ "generator_id": "..." }`. Deletes an installed flag-generator.

`POST /api/flag_node_generators/delete`
: JSON `{ "generator_id": "..." }`. Deletes an installed flag-node-generator.

#### Installed generator listings

`GET /flag_generators_data`
: Returns `{ "generators": [...], "errors": [...] }` for installed flag-generators (manifest-based). Generator entries may include `_pack_id`, `_pack_label`, and `_disabled`.

`GET /flag_node_generators_data`
: Returns `{ "generators": [...], "errors": [...] }` for installed flag-node-generators (manifest-based).

### Run Execution & Reports

`POST /run_cli`
: Form field `xml_path` (absolute path). Runs the CLI synchronously with forwarded args `--xml`, `--host`, `--port`, `--verbose` (values derived from the saved XML when available). Returns the main page with logs. Side effects:

- Markdown report written to `./reports/`
- JSON summary (`scenario_report_<timestamp>.json`) next to the report with counts and metadata
- Router aggregation metrics appended when routers are generated
- Pre/post CORE session XML captured under `outputs/core-sessions/` when available
- Run history appended to `outputs/run_history.json`

`POST /run_cli_async`
: Same args as synchronous run. Returns `{ "run_id": "<uuid>" }` immediately and writes logs to `outputs/scenarios-<timestamp>/cli-<run_id>.log`.

`GET /run_status/<run_id>`
: Polling endpoint returning:

```json
{
	"done": false,
	"returncode": null,
	"report_path": null,
	"xml_path": null,
	"log_path": "outputs/.../cli-<run_id>.log",
	"scenario_xml_path": "outputs/.../scenarios.xml",
	"pre_xml_path": null,
	"full_scenario_path": null
}
```

`GET /stream/<run_id>`
: Server-Sent Events (SSE) endpoint streaming live CLI log lines for async runs.

`POST /cancel_run/<run_id>`
: Attempts to terminate a running async job.

`GET /reports`
: Renders the Reports UI.

`GET /reports_data`
: Returns `{ "history": [...], "scenarios": [...] }`, combining run metadata and known scenario files. Each history entry includes `timestamp`, `mode`, `returncode`, `scenario_xml_path`, `report_path`, `pre_xml_path`, `post_xml_path`, `full_scenario_path`, `run_id`, and parsed `scenario_names`.

`GET /download_report?path=<path>`
: Streams a report or artifact file. Accepts absolute or repo-relative paths.

`POST /reports/delete`
: JSON body `{ "run_ids": ["..."] }`. Removes matching run history entries and deletes their artifacts under `outputs/`. Reports in `./reports/` remain untouched. Responds with `{ "deleted": <count> }`.

`POST /purge_history_for_scenario`
: JSON body `{ "name": "Scenario" }`. Removes all history entries tied to the scenario name and deletes associated artifacts under `outputs/`. Returns `{ "removed": <count>, "error"?: string }`.

**Report path detection:** The backend parses the CLI log line `Scenario report written to ...`. If missing, it falls back to the most recent `./reports/scenario_report_*.md`.

### Script Inspection

`GET /api/open_scripts`
: Query params `kind=traffic|segmentation` (default `traffic`), `scope=runtime|preview` (default `runtime`). Returns `{ "ok": true, "kind": "traffic", "scope": "runtime", "path": "/tmp/traffic", "files": [...] }`.

`GET /api/open_script_file`
: Same parameters, plus `file=<filename>`. Returns `{ "content": "...", "truncated": false }` with up to 8KB per request.

`GET /api/download_scripts`
: Same parameters, responds with a ZIP archive containing the filtered scripts.

### Docker Helpers

`GET /docker/status`
: Enumerates tracked Docker assignments with compose status:

```json
{
	"items": [{
		"name": "node1",
		"compose": "docker-compose.yml",
		"exists": true,
		"pulled": false,
		"container_exists": false,
		"running": false
	}],
	"timestamp": 1733422330
}
```

`POST /docker/cleanup`
: Optional JSON body `{ "names": ["node1"] }`. Stops and removes containers via `docker stop` / `docker rm`, returning `{ "ok": true, "results": [{ "name": "node1", "stopped": true, "removed": true }] }`.

### CORE Session Management

`GET /core`
: Renders the CORE session dashboard.

`GET /core/data`
: Returns `{ "sessions": [...], "xmls": [...] }`. Sessions include gRPC metadata (id, state, node count, backing XML). XML entries list discovered CORE files and their validation status.

`POST /core/upload`
: Multipart field `xml_file`. Saves validated CORE XML under `uploads/core/`.

`POST /core/start`
: Form field `path=<abs_xml_path>`. Starts a new CORE session using the provided XML.

`POST /core/stop`
: Form field `session_id=<int>`.

`POST /core/delete`
: Form fields:
	- `session_id` (optional) to delete a running CORE session
	- `path` (optional) to remove a CORE XML under `uploads/` or `outputs/`

`GET /core/details`
: Query parameters `path=<abs_xml_path>` and/or `session_id=<int>`. Renders validation results. When only `session_id` is provided, the server exports the current session XML for inspection.

`POST /core/save_xml`
: Form field `session_id=<int>`. Saves the running session’s XML into `outputs/core-sessions/` and streams it back as a download.

`POST /core/start_session`
: Form field `session_id=<int>` to start an existing session.

`GET /core/session/<sid>`
: Convenience view for a single session.

`POST /test_core`
: Form or JSON body with `host` (string) and `port` (int). Returns `{ "ok": true }` when gRPC connectivity succeeds.

`GET /vuln_catalog`
: Returns the vulnerability catalog as JSON (types/vectors/items).

`GET /vuln_catalog_page`
: HTML page that mirrors the Flag Catalog pack UX, but for vulnerability catalog packs.

`POST /vuln_catalog_packs/upload`
: Form upload endpoint. Expects multipart field `zip_file` containing a ZIP with directories/subdirectories.
	Each valid vulnerability directory must include `docker-compose.yml`. The server extracts the ZIP and
	generates a `vuln_list_w_url.csv` for selection.

`POST /vuln_catalog_packs/import_url`
: Form endpoint. Field `zip_url` points to a ZIP containing compose directories.

`GET /vuln_catalog_packs/download/<catalog_id>`
: Downloads the previously uploaded ZIP.

`GET /vuln_catalog_packs/browse/<catalog_id>`
: HTML directory browser for the extracted pack content.

`GET /vuln_catalog_packs/browse/<catalog_id>/<subpath>`
: Browse a subdirectory under the extracted content.

`GET /vuln_catalog_packs/file/<catalog_id>/<subpath>`
: Download a specific extracted file.

`POST /vuln_catalog_packs/set_active/<catalog_id>`
: Marks the selected catalog pack as active.

`POST /vuln_catalog_packs/delete/<catalog_id>`
: Deletes the selected catalog pack.

`POST /vuln_compose/status`
: JSON `{ "items": [{ "Name": "Node1", "Path": "...", "compose"?: "docker-compose.yml" }] }`. Returns `{ "items": [...], "log": [...] }` with compose availability and Docker pull state.

`POST /vuln_compose/download`
: Same payload. Supports GitHub URLs (cloned via `git`), direct download URLs, and local compose paths (as produced by installed vulnerability packs). Responds with `{ "items": [...], "log": [...] }` summarizing results.

`POST /vuln_compose/pull`
: Performs `docker compose pull` for each item. Requires Docker CLI access.

`POST /vuln_compose/remove`
: Runs `docker compose down --volumes --remove-orphans`, removes images, and deletes downloaded directories under `outputs/`.

### Diagnostics & Maintenance

`GET /diag/modules`
: Returns imported module metadata to help troubleshoot environment issues.

`POST /admin/cleanup_pycore`
: Removes stale `/tmp/pycore.*` directories. Response `{ "ok": true, "removed": [...], "kept": [...], "active_session_ids": [...] }`.

### User Administration

`GET /users`
: Admin-only view listing users.

`POST /users`
: Form fields `username`, `password`, `role` (`user`|`admin`, default `user`). Fails with a flash error if the username already exists.

`POST /users/delete/<username>`
: Removes the specified user (admin only).

`POST /users/password/<username>`
: Admin resets another user’s password. Form field `password` (new value).

`GET /me/password`
: Renders self-service password form.

`POST /me/password`
: Form fields `current_password`, `password`. Allows users to update their own credential.

## CLI Reference (`core_topo_gen.cli`)

Invoke from the repo root to ensure generated reports land in `./reports/`:

```bash
core-python -m core_topo_gen.cli --xml /abs/path/scenarios.xml --verbose
```

### Core Arguments

- `--xml` (required): Scenario XML path.
- `--scenario`: Scenario name (defaults to the first in the file).
- `--host`, `--port`: CORE gRPC endpoint (defaults `127.0.0.1:50051`).
- `--prefix`: IPv4 prefix for auto-assigned addresses (default `10.0.0.0/24`).
- `--ip-mode`: `private | mixed | public` (default `private`).
- `--ip-region`: `all | na | eu | apac | latam | africa | middle-east` (default `all`).
- `--max-nodes`: Hard cap on node creation.
- `--verbose`: Enables debug logging.
- `--seed`: RNG seed for deterministic randomness.
- `--layout-density`: `compact | normal | spacious` (default `normal`).
- `--router-mesh-style`: `full | ring | tree` (fallback when routing items omit `r2r_mode`).

### Traffic Overrides

- `--traffic-pattern`: `continuous | burst | periodic | poisson | ramp`
- `--traffic-rate`: Float KB/s
- `--traffic-period`: Float seconds
- `--traffic-jitter`: Float percentage (0–100)
- `--traffic-content`: `text | photo | audio | video`

### Segmentation & Allow Rules

- `--allow-src-subnet-prob`: Float 0–1 (default 0.3)
- `--allow-dst-subnet-prob`: Float 0–1 (default 0.3)
- `--nat-mode`: `SNAT | MASQUERADE` (default `SNAT`)
- `--dnat-prob`: Float 0–1 (default 0.0)
- `--seg-include-hosts`: Include hosts when deriving segmentation rules.
- `--seg-allow-docker-ports`: Ensure host INPUT chains allow docker-compose ports when default deny is applied.

### Planning Metadata Integration

- CLI automatically parses additive planning metadata via `parse_planning_metadata`. Detected values are merged into scenario metadata with a `plan_` prefix and appear in reports under **Planning Metadata (from XML)**.
- CORE host/port defaults are overridden by `core.host` and `core.port` saved in the editor payload when present.
- Extend the web backend if additional CLI flags must be surfaced to the UI.

## Routing Connectivity Example

```xml
<section name="Routing" density="0.5">
	<!-- Balanced degree distribution among density-derived routers -->
	<item selected="OSPF" factor="1" r2r_mode="Uniform" />
	<!-- Two absolute routers with NonUniform aggregation targeting five hosts per switch -->
	<item selected="BGP" v_metric="Count" v_count="2" r2r_mode="NonUniform"
				r2s_mode="aggregate" r2s_edges="5" />
</section>
```

- Density `0.5` over 12 base hosts yields 6 density routers.
- Two `Count` routers bring the total to `min(total_hosts, 6 + 2)`.
- NonUniform aggregation introduces additional layer-2 switches sized to approximately five hosts each.

## Planning Metadata Quick Reference

The web UI writes additive planning attributes onto section tags to support round-tripping and external tooling.

### Node Information Section

- `base_nodes`: Density-derived hosts.
- `additive_nodes`: Hosts from Count rows.
- `combined_nodes`: Total planned hosts (`base_nodes + additive_nodes`).
- `weight_rows` / `count_rows`: Row counts by type.
- `weight_sum`: Sum of weight factors.

### Routing & Vulnerabilities Sections

- `explicit_count`: Count-based entries with absolute values.
- `derived_count`: Density-derived totals.
- `total_planned`: `explicit_count + derived_count`.
- `weight_rows`, `count_rows`, `weight_sum`: Analogous to Node Information.

### Parsing Helper

```python
from core_topo_gen.parsers.planning_metadata import parse_planning_metadata

meta = parse_planning_metadata("outputs/scenarios-123/scenarios.xml", "Scenario 1")
print(meta["node_info"]["combined_nodes"])
```

- The legacy `core_topo_gen.parsers.xml_parser` module was removed in 2025-10; import section-specific parsers instead.
- When attributes are absent (legacy XML), parsing gracefully recomputes approximate values.

### Experimental Sections (Services / Traffic / Segmentation)

- Currently expose structural placeholders (`explicit_count`, `weight_rows`, `count_rows`, `weight_sum`).
- Derived totals may be added in future releases as semantics mature.

