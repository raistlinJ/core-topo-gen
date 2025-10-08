### /api/plan/preview_full (POST)
Returns unified full preview (routers, hosts, IP allocations, segmentation placeholder) without building a CORE session.

Request JSON:
{
  "xml_path": "/abs/path/to/scenarios.xml",
  "scenario": "Optional Scenario Name",
  "seed": 1234
}

Response JSON:
{
  "ok": true,
  "full_preview": { ... },
  "plan": {  # orchestrator root with role_counts, routers_planned, service_plan, vulnerability_plan, segmentation_plan, traffic_plan
    "role_counts": {"Workstation": 12, ...},
    "routers_planned": 3,
    ...
  },
  "breakdowns": {  # per-section breakdowns
    "node": { ... },
    "router": {"has_weight_based_items": true, ...},
    "services": { ... },
    "vulnerabilities": { ... },
    "segmentation": { ... },
    "traffic": { ... }
  }
}

Notes:
- Plans are cached on disk (outputs/plan_cache.json) keyed by (xml_hash, scenario, seed). Set TOPO_PLAN_CACHE_PATH to override location.
- Router count, service allocations, vulnerability density pool, and segmentation item serialization are single-sourced from the orchestrator.
# HTTP API Reference (Flask)

This document describes the HTTP endpoints exposed by the Web GUI backend (`webapp/app_backend.py`). Use these for automation and integrations.

Base URL: http://localhost:9090 (default)

Authentication
- The Web UI uses cookie-based auth. For scripts/clients, POST to `/login` with `username` and `password` to obtain a session cookie.
- On first run, a default admin may be created (see README Authentication section). Store and resend cookies in subsequent requests.

Conventions
- All JSON responses use UTF‑8.
- File downloads are sent via `/download_report?path=...` and may accept absolute or repo-relative paths. The server resolves common variants.
- Safe deletes and file operations are scoped under `uploads/` and `outputs/` to avoid accidental removal of arbitrary files.

Planning & Defaults Snapshot
- Default base host pool (when omitted) is 10; explicit zero requires setting `total_nodes="0"` (or `base_nodes="0"`).
- Router count formula (builder): `routers = min(total_hosts, density_contribution + sum(abs_count))` where:
  - If `0 < density <= 1`: `density_contribution = floor(base_host_pool * density)` (base host pool excludes additive Count rows).
  - If `density > 1`: `density_contribution = int(density)` (legacy absolute form).
  - `abs_count` gathered from routing items with `v_metric="Count"`.
- Per-routing-item connectivity shaping: `r2r_mode` (Uniform|NonUniform|Exact|Min|Random) with fallback to global mesh style (`--router-mesh-style` full|ring|tree) when omitted.
- Host aggregation / rehoming via `r2s_mode` and `r2s_edges` (XML attributes) producing extra layer‑2 switches and balance statistics.
- Vulnerability assignment lenient mode: downloaded-but-not-pulled catalog entries can still be assigned for planning/report purposes.

Endpoints

- POST `/login`
  - Form fields: `username`, `password`
  - Response: 302 redirect (on success) to `/`; or 200 with error message.

- POST `/logout`
  - Clears session; redirects to `/`.

- GET `/healthz`
  - Liveness check; returns 200 OK (text).

Scenario editor & runs

- POST `/load_xml`
  - Multipart form with `scenarios_xml` (file, `.xml`). Loads into the editor state.

- POST `/save_xml`
  - Form fields: `scenarios_json` (JSON string). Writes to `outputs/scenarios-<ts>/scenarios.xml`.
  - Response: renders `index.html` with updated payload.
  - Planning metadata: The saved XML includes optional additive planning attributes (see README "Additive Planning Semantics & XML Metadata"). These appear on section tags for lossless round-trip (e.g. `base_nodes`, `combined_nodes`, `explicit_count`, `derived_count`, `total_planned`). Clients can rely on them when re-importing instead of recomputing derived values.

- POST `/upload_base`
  - Multipart form with `base_xml` (file, CORE `.xml`). Validates against CORE schema and attaches to the first scenario as the base topology.
  - Response: redirects to `/` with flash message.

- POST `/remove_base`
  - Optional form field: `scenarios_json` (JSON string) to preserve other edits while clearing the base XML from the first scenario.
  - Response: renders `index.html` with base cleared.

- GET `/base_details`
  - Query: `path` (absolute path to a CORE XML).
  - Response: details HTML (validity and summary) for the provided base XML.

- POST `/run_cli` (synchronous)
  - Form fields: `xml_path` (absolute path to the editor-saved XML).
  - Internally forwarded CLI args: `--xml`, `--host`, `--port`, `--verbose`.
  - CORE host/port are derived from the saved editor payload `core.host`/`core.port` when available; otherwise defaults are used.
  - Starts a CLI run and waits for completion; renders `index.html` with logs.
  - Side effects:
    - Writes a Markdown report under `./reports/`.
    - If planning metadata attributes are present in the XML, they are merged into the report under a "Planning Metadata (from XML)" section with namespaced keys (`plan_*`).
    - Connectivity metrics (router degree distribution, aggregation switch stats) appended when routers are generated.
    - Attempts to capture pre- and post-run CORE session XML into `outputs/core-sessions/`.
    - Appends an entry to `outputs/run_history.json` (even on failure) with `report_path` if found.

- POST `/run_cli_async` (asynchronous)
  - Form fields: `xml_path` (absolute path to the editor-saved XML).
  - Internally forwarded CLI args: `--xml`, `--host`, `--port`, `--verbose`.
  - CORE host/port are derived from the saved editor payload `core.host`/`core.port` when available; otherwise defaults are used.
  - Returns JSON: `{ "run_id": "<uuid>" }`.
  - The process writes logs to `outputs/scenarios-<ts>/cli-<run_id>.log`.
  - Planning metadata behavior matches synchronous run (merged into report if present).

- GET `/run_status/<run_id>`
  - Returns JSON with live progress and final artifacts:
    - `done`: bool
    - `returncode`: int|null
    - `report_path`: string|null (abs path when report exists)
    - `xml_path`: string|null (post-run CORE session XML if captured)
    - `log_path`: string (path to CLI log file)
    - `scenario_xml_path`: string
    - `pre_xml_path`: string|null
    - `full_scenario_path`: string|null (zip bundle of artifacts)

- GET `/reports`
  - Renders the Reports page.

- GET `/reports_data`
  - Returns JSON: `{ history: [...], scenarios: [...] }`.
  - Each history entry includes: `timestamp`, `mode`, `returncode`, `scenario_xml_path`, `report_path`, `pre_xml_path`, `post_xml_path`, `full_scenario_path`, `run_id` (async), and parsed `scenario_names`.

- GET `/download_report?path=<path>`
- GET `/planning_meta`
  - Query params: `path` (XML path absolute or repo-relative), `scenario` (optional).
  - Returns parsed planning metadata JSON as produced by `parse_planning_metadata`. Useful for tooling that needs counts without running a full CLI build.

  - Streams a report or artifact file. `path` can be absolute or repo-relative.

- POST `/api/plan/preview_full`
  - JSON body: `{ "xml_path": "/abs/path/scenarios.xml", "scenario": "Scenario 1"?, "seed": 12345? }`
  - Computes a deterministic full planning preview (no CORE session) including:
    - Routers / Hosts / Switches (aggregation) with IP samples
    - `r2r_policy_preview`, `r2r_edges_preview`, degree stats
    - `r2s_policy_preview` (counts, per-router bounds, host pair saturation)
    - `r2s_grouping_preview` array (per-router host grouping: groups, group_sizes, bounds)
    - `services_preview`, `vulnerabilities_preview`
    - `segmentation_preview` (planned rule names)
    - `seed` (echo / auto-generated) and `seed_generated` flag
  - Response: `{ ok: true, full_preview: { ... } }` or `{ ok: false, error }` on failure.
  - Notes:
    - If `seed` omitted, a random seed is generated and returned so clients can rerun with identical topology decisions.
    - Host grouping bounds supplied in the XML via `r2s_hosts_min` / `r2s_hosts_max` (NonUniform R2S) appear under `r2s_policy_preview.per_router_bounds` and in each grouping entry.
    - Exact aggregation (`r2s_mode=Exact` & `r2s_edges=1`) produces one switch per router with all its hosts; bounds are ignored for this mode.


Script inspection & downloads

- GET `/api/open_scripts`
  - Query params:
    - `kind` (`traffic`|`segmentation`, default `traffic`)
    - `scope` (`runtime`|`preview`, default `runtime`)
  - Returns JSON `{ ok, kind, path, files }` listing available generated scripts.
  - Runtime scope targets `/tmp/traffic` or `/tmp/segmentation`. Preview scope resolves the most recent `core-topo-preview-*` temp directory.

- GET `/api/open_script_file`
  - Query params:
    - `kind` (`traffic`|`segmentation`)
    - `scope` (`runtime`|`preview`)
    - `file` (filename within the selected directory)
  - Returns JSON `{ ok, file, path, content, truncated }` with up to 8KB of script content for quick inspection.

- GET `/api/download_scripts`
  - Query params:
    - `kind` (`traffic`|`segmentation`)
    - `scope` (`runtime`|`preview`)
  - Streams a ZIP download containing the filtered `.py` and `.json` artifacts for the requested scope.

CORE management

- GET `/core`
  - Renders the CORE page.

- GET `/core/data`
  - Returns JSON: `{ sessions: [...], xmls: [...] }`
  - `sessions`: best-effort gRPC info (id, state, nodes, file)
  - `xmls`: discovered and validated CORE XML files with run/valid status

- POST `/core/upload`
  - Multipart form with `xml_file` (file, `.xml`). Validated and placed under `uploads/core/`.

- POST `/core/start`
  - Form field: `path` (abs path to a validated XML). Starts a session via gRPC.

- POST `/core/stop`
  - Form field: `session_id`.

- POST `/core/delete`
  - Form fields (any):
    - `session_id` (optional): delete the given CORE session via gRPC.
    - `path` (optional): delete a CORE XML file if it resides under `uploads/` or `outputs/` (safe delete). Both may be provided.

- GET `/core/details`
  - Query params:
    - `path` (abs path to a CORE XML) to analyze; and/or
    - `session_id` (if provided without a `path`, the server attempts to export the current session XML for analysis).
  - Response: details HTML.

- POST `/core/save_xml`
  - Form field: `session_id` (int). Saves current session XML via gRPC into `outputs/core-sessions/` and streams the file back as a download.

- POST `/core/start_session`
  - Form field: `session_id` (int). Starts an existing session via gRPC.

- GET `/core/session/<sid>`
  - Path param: `sid` (int). Convenience view for a specific session’s details.

- POST `/test_core`
  - Either JSON body or form fields with: `host` (string), `port` (int).
  - Response JSON: `{ ok: boolean, error?: string }`.

Data sources & Vulnerability catalog

- GET `/data_sources`
  - Renders the data sources page.

- POST `/data_sources/upload`
  - Multipart form with `csv_file` (file, `.csv`).

- POST `/data_sources/toggle/<sid>`
  - Toggle enabled/disabled.

- POST `/data_sources/delete/<sid>`
  - Delete a data source.

- POST `/data_sources/refresh/<sid>`
  - Refresh a source (implementation-specific).

- GET `/data_sources/download/<sid>`
  - Download a CSV.

- GET `/data_sources/export_all`
  - Download all sources as a CSV bundle.

- GET `/data_sources/edit/<sid>`
  - Renders an HTML table editor for the CSV with id `sid`.

- POST `/data_sources/save/<sid>`
  - JSON body: `{ "rows": string[][] }` (entire CSV content). On success, normalizes and saves CSV, then redirects back to the editor.
  - On invalid payload: returns JSON error with HTTP 400.

- GET `/vuln_catalog`
  - Renders catalog page.

- POST `/vuln_compose/status`
  - JSON body: `{ "items": [{ "Name": string, "Path": string, "compose"?: string }] }` (`compose` defaults to `docker-compose.yml`).
  - Response JSON: `{ items: [{ Name, Path, compose, compose_path, exists: bool, pulled: bool, dir }], log: string[] }`.

- POST `/vuln_compose/download`
  - JSON body: `{ "items": [{ "Name": string, "Path": string, "compose"?: string }] }`.
  - Notes: `Path` can be a GitHub URL to a repo, tree, or blob; requires `git` when cloning repos. Non‑GitHub paths are treated as direct download bases for `compose` files.
  - Response JSON: `{ items: [{ Name, Path, ok: bool, dir: string, message: string, compose?: string }], log: string[] }`.

- POST `/vuln_compose/pull`
  - JSON body: `{ "items": [{ "Name": string, "Path": string, "compose"?: string }] }`.
  - Requires Docker CLI available. Performs `docker compose pull` for each item’s compose file.
  - Response JSON: `{ items: [{ Name, Path, ok: bool, message: string, compose: string }], log: string[] }`.

- POST `/vuln_compose/remove`
  - JSON body: `{ "items": [{ "Name": string, "Path": string, "compose"?: string }] }`.
  - Performs `docker compose down --volumes --remove-orphans`, attempts to remove images, and cleans downloaded files/dirs under outputs.
  - Response JSON: `{ items: [{ Name, Path, ok: bool, message: string, compose: string }], log: string[] }`.

Streaming and cancellation

- GET `/stream/<run_id>`
  - Server-Sent Events (SSE) stream of live CLI logs for async runs.

- POST `/cancel_run/<run_id>`
  - Attempts to terminate an async run.

Users

- GET `/users`
  - Renders users page (admin only).

- POST `/users/create`
  - Form fields: `username` (string), `password` (string), `role` (`user|admin`, default `user`).
- POST `/users/delete/<username>`
  - Path param: `username` (string). Admin-only.
- POST `/users/password/<username>`
  - Path param: `username` (string). Form field: `password` (new password). Admin-only.
- GET/POST `/me/password`
  - Manage users and passwords; admin and self-service flows.
  - GET: renders HTML. POST form fields: `current_password`, `password`.

Notes
- Report path detection parses the CLI log line: `Scenario report written to ...`. If missing, the backend falls back to the most recent `reports/scenario_report_*.md`.
- Artifact deletion is scoped to `outputs/` only when purging run history for a scenario; reports under `./reports/` are not deleted.

- POST `/purge_history_for_scenario`
  - JSON body: `{ "name": string }` to remove history entries for a given scenario name and delete associated artifacts under `outputs/`.
  - Response JSON: `{ removed: number, error?: string }`.

CLI run arguments (core_topo_gen.cli)

The CLI supports the following arguments. The Web endpoints currently forward only `--xml`, `--host`, `--port`, and `--verbose`. All other arguments are available when running the CLI directly.

- General/core
  - `--xml` (string, required): path to XML scenario file
  - `--scenario` (string): specific scenario name in the XML; defaults to the first
  - `--host` (string, default `127.0.0.1`): core-daemon gRPC host
  - `--port` (int, default `50051`): core-daemon gRPC port
  - `--prefix` (CIDR, default `10.0.0.0/24`): IPv4 prefix for auto-assigned addresses
  - `--ip-mode` (`private|mixed|public`, default `private`): IP pool selection
  - `--ip-region` (`all|na|eu|apac|latam|africa|middle-east`, default `all`): region for public pools
  - `--max-nodes` (int): cap on hosts to create
  - `--verbose` (flag): enable debug logging
  - `--seed` (int): RNG seed for reproducible randomness
  - `--layout-density` (`compact|normal|spacious`, default `normal`): affects node spacing
    - Additive planning metadata parsing: The CLI automatically detects and parses section-level planning attributes when present (via `parse_planning_metadata`). Resulting keys are merged into generation metadata with a `plan_` prefix and surfaced in scenario reports.
  - `--router-mesh-style` (`full|ring|tree`, default `full`): fallback mesh style applied to router set when routing items omit `r2r_mode`.

- Traffic overrides (apply to all traffic items if provided)
  - `--traffic-pattern` (`continuous|burst|periodic|poisson|ramp`)
  - `--traffic-rate` (float KB/s)
  - `--traffic-period` (float seconds)
  - `--traffic-jitter` (float percent 0–100)
  - `--traffic-content` (`text|photo|audio|video`)

- Segmentation and allow rules
  - `--allow-src-subnet-prob` (float 0..1, default `0.3`): widen allows to source subnet
  - `--allow-dst-subnet-prob` (float 0..1, default `0.3`): widen allows to destination subnet
  - `--nat-mode` (`SNAT|MASQUERADE`, default `SNAT`): NAT mode for routers
  - `--dnat-prob` (float 0..1, default `0.0`): probability of DNAT (port-forward) on routers
  - `--seg-include-hosts` (flag): include host nodes as candidates for segmentation placement

Important
- The web backend derives CORE `host`/`port` from the saved editor XML’s `core` section when present; otherwise defaults apply.
- If you need to use additional CLI flags via the Web endpoints, extend the backend to accept and forward those parameters.

### Connectivity Attribute Examples (Routing Section XML)

```xml
<section name="Routing" density="0.5">
  <!-- Balanced degree distribution among density-derived routers -->
  <item selected="OSPF" factor="1" r2r_mode="Uniform" />
  <!-- Absolute router addition (2) with heterogeneous links and host aggregation (target 5 hosts per new switch) -->
  <item selected="BGP" v_metric="Count" v_count="2" r2r_mode="NonUniform" r2s_mode="aggregate" r2s_edges="5" />
</section>
```

Interpretation:
- Density 0.5 over a base host pool of 12 hosts -> 6 density routers.
- 2 BGP count routers => total planned routers = min(total_hosts, 6 + 2).
- First item influences balanced edge placement; second item contributes NonUniform extra edges and triggers host rehoming behind aggregation switches sized ~5 hosts each.

## Planning Metadata Quick Reference

Optional section attributes written by the Web UI for additive planning round-trip:

`<section name="Node Information">`:
- `base_nodes`: base (density) hosts distributed across weight rows.
- `additive_nodes`: sum of Count row host additions.
- `combined_nodes`: total planned hosts (`base_nodes + additive_nodes`).
- `weight_rows`: number of Weight rows.
- `count_rows`: number of Count rows.
- `weight_sum`: raw sum of weight factors.

`<section name="Routing">` / `<section name="Vulnerabilities">`:
- `explicit_count`: sum of absolute Count/Specific entries.
- `derived_count`: density-derived amount (rules differ for routers vs vulnerabilities; see README).
- `total_planned`: `explicit_count + derived_count`.
- `weight_rows`, `count_rows`, `weight_sum`: analogous to Node Information.

Parsing helper (server-side or external tooling):
```python
from core_topo_gen.parsers.planning_metadata import parse_planning_metadata
meta = parse_planning_metadata('outputs/scenarios-123/scenarios.xml', 'Scenario 1')
print(meta['node_info']['combined_nodes'])
```
Note: the legacy `core_topo_gen.parsers.xml_parser` module was removed (2025-10); import the specific section module instead.
Fallback: If attributes are absent (legacy XML), parsing gracefully recomputes approximate values from existing elements.

Experimental (Services / Traffic / Segmentation):

The XML builder now also writes structural placeholders for these sections:
- `explicit_count`, `weight_rows`, `count_rows`, `weight_sum`

They currently expose raw structure only (no derived_count or total_planned yet); future versions may introduce density-derived semantics similar to Routers/Vulnerabilities.
