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
from core_topo_gen.parsers.xml_parser import parse_planning_metadata
meta = parse_planning_metadata('outputs/scenarios-123/scenarios.xml', 'Scenario 1')
print(meta['node_info']['combined_nodes'])
```
Fallback: If attributes are absent (legacy XML), parsing gracefully recomputes approximate values from existing elements.

Experimental (Services / Traffic / Segmentation):

The XML builder now also writes structural placeholders for these sections:
- `explicit_count`, `weight_rows`, `count_rows`, `weight_sum`

They currently expose raw structure only (no derived_count or total_planned yet); future versions may introduce density-derived semantics similar to Routers/Vulnerabilities.
