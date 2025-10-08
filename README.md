# core-topo-gen

Generate CORE topologies from XML scenarios via a GUI or CLI. Supports services/routing assignment, segmented or star layouts, optional traffic script generation, and per-router host grouping bounds for switch aggregation.

## Recent Workflow Simplification (2025-09/10)

The planning and execution workflow has been streamlined:

- Single authoritative "Full Preview" action (no separate lightweight preview, no approval step, no stored plan JSON file). The preview is always computed directly from the saved scenario XML.
- Deterministic runs via an optional seed. Enter a seed before clicking Full Preview (or reuse/copy one from preview history) to reproduce identical role expansions, service/vulnerability assignments, segmentation picks, switch regrouping, and R2R/R2S edge decisions.
- A new "Run (Seed)" button will launch the asynchronous CLI using the explicit seed input; if the seed input is empty but a preview has been generated, it reuses the preview's seed for bit‑for‑bit reproducibility.
- Preview history (last 25) with per‑seed diffs lets you compare topology scale changes across edits or random seeds.
- Removed concepts: plan approval, drift detection mode, strict plan checkbox, secondary preview buttons, intermediate plan JSON persistence.

Upgrade note: Legacy endpoints and flags (`/api/plan/preview`, `/api/plan/approve*`, `/api/plan/status`, `--approve-plan`, `--use-plan`) are removed. Use `/api/plan/preview_full` followed by Run; reproducibility comes from supplying a seed.

## Prerequisites

- Python 3.10+ recommended
- CORE 9.2+ installed and `core-daemon` running (for starting sessions)
- Install Python dependencies:

```bash
pip install -r requirements.txt
```

If you use a virtual environment, activate it before installing.

## Host Planning Semantics

The Node Information section supports an optional Base Hosts value (edited via the spinner near the Scenario name in the Web UI).

Updated defaults & rules:

- Default Base Hosts (density base) when omitted is now **10** (previously 8). This improves small-scenario proportional allocation stability.
- To request an explicit zero base you must now set the value to 0 in the UI (or include `total_nodes="0"` / `base_nodes="0"` in XML). Leaving it blank no longer implies 0.
- Base hosts are distributed proportionally across Weight rows using their raw (unnormalized) factors.
- Count rows add absolute hosts on top of the proportional distribution.
- If there are no Weight rows the base hosts value is still recorded, but with no Weight rows it effectively contributes 0 allocated hosts; only Count rows produce hosts.

Scenario aggregate `scenario_total_nodes` = base_nodes + additive_nodes + total_planned_routers + total_planned_vulnerabilities (plus any future additive categories).

XML metadata attributes written for Node Information:
- `base_nodes`, `additive_nodes`, `combined_nodes`, `weight_rows`, `count_rows`, `weight_sum`.

Routing/Vulnerabilities sections add:
- `explicit_count`, `derived_count`, `total_planned`, `weight_rows`, `count_rows`, `weight_sum`.

These enable precise round‑trip planning without recomputing from factors alone. Older XML without them still parses—fallback logic recomputes approximate values.

## Run the GUI

The GUI lets you edit scenarios, generate a deterministic Full Preview (with optional seed), and start CORE sessions asynchronously with live log streaming.

```bash
python main.py
```

### Run with HTTPS (nginx container + host Web UI)

By default, an `nginx` reverse proxy service in Docker terminates TLS on port 443 and proxies to a Web UI running on the host at `127.0.0.1:9090`. This lets you use your host `core-python` environment directly.

1. Generate a self-signed certificate (development only). Fast one-liner (idempotent):
	```bash
	bash scripts/dev_gen_certs.sh
	```
   Customize:
	```bash
	CERT_DAYS=30 CERT_SUBJECT="/CN=localhost" CERT_SANS="DNS:localhost,IP:127.0.0.1" bash scripts/dev_gen_certs.sh
	```
   Force re-generation (overwrite existing):
	```bash
	FORCE_REGEN=1 bash scripts/dev_gen_certs.sh
	```

   Makefile alternative (also auto-runs before `make up`):
	```bash
	make dev-certs            # ensure certs
	make force-certs          # force regenerate
	make up                   # generate if needed, then docker compose up --build
	```

2. Or manual OpenSSL invocation:
	```bash
	mkdir -p nginx/certs
	openssl req -x509 -nodes -newkey rsa:4096 \
	  -keyout nginx/certs/server.key \
	  -out nginx/certs/server.crt \
	  -days 365 -subj "/CN=localhost"
	```

3. Start the Web UI on the host and choose your proxy (nginx default, or envoy):
	```bash
	# Default (nginx)
	make host-web

	# Explicit (nginx)
	make host-web-nginx

	# Envoy instead of nginx
	make host-web PROXY=envoy
	# or
	make host-web-envoy
	```
4. Access the UI:
	- HTTPS: https://localhost/
	- HTTP will redirect to HTTPS automatically.

Certificate files are mounted read-only into the nginx container at `/etc/nginx/certs/server.crt` and `/etc/nginx/certs/server.key`.

For production, replace the self‑signed cert with certificates from a trusted CA (e.g., Let’s Encrypt) and adjust:
- nginx mode: `server_name` in `nginx/nginx-hostweb.conf`
- envoy mode: TLS certs in `envoy/envoy.yaml` and optional HSTS/security header settings via Envoy filters

Self-signed SANs: The script accepts `CERT_SANS` as a comma-separated list (e.g. `DNS:localhost,IP:127.0.0.1`). Browsers increasingly require SANs even if the CN is set.

Automatic certificate generation in compose:
- The `nginx` container self-generates a self-signed cert on startup if `nginx/certs/server.crt` or `server.key` is missing.
- Generation runs via a `/docker-entrypoint.d/10-gen-certs.sh` hook in the custom nginx image (see `nginx/Dockerfile`).
- Customize at compose runtime:
	```bash
	CERT_DAYS=30 CERT_SUBJECT="/CN=localhost" docker compose up --build
	```
- SAN support still requires the script: `CERT_SANS="DNS:localhost,IP:127.0.0.1" bash scripts/dev_gen_certs.sh` (run before `docker compose up`).
- To force regeneration: delete `nginx/certs/server.*` then rerun compose, or regenerate via the script with `FORCE_REGEN=1`.

Troubleshooting empty `nginx/certs` after startup:
- Ensure you launched from the repository root (where `docker-compose.yml` lives).
- Check container logs:
	```bash
	docker compose logs -f nginx | grep nginx-init
	```
- Inspect inside the container:
	```bash
	docker exec -it core-topo-gen-proxy ls -l /etc/nginx/certs
	```
- If directory is empty inside: verify the host path exists and is writable:
	```bash
	ls -ld nginx/certs
	```
- Recreate nginx cleanly:
	```bash
	docker compose rm -sf nginx
	docker compose up -d --build nginx
	```
- Still empty? Regenerate explicitly with SAN support:
	```bash
	CERT_SANS="DNS:localhost,IP:127.0.0.1" bash scripts/dev_gen_certs.sh
	docker compose up -d --build nginx
	```

gRPC connectivity to host CORE:
- The Web UI runs on the host, so it connects to your host `core-daemon` directly (default port 50051). Adjust in the UI if needed.
- The nginx container doesn’t need gRPC access—it only proxies HTTP(S).

Tips:
- Use the context menu action “Generate in CORE…” to build and start a session.
- If CORE isn’t available, you’ll see a clear error. Ensure `core-daemon` is running.
- Pretty save writes human-readable XML.

## Run via CLI

The CLI is useful for automation and quick runs. It parses the XML, builds the session, optionally generates traffic scripts, and starts CORE after applying services.

Basic usage:

```bash
python -m core_topo_gen.cli --xml path/to/scenario.xml [options]
```

Common options:
- `--scenario NAME`         scenario name in the XML (defaults to first)
- `--host HOST`             core-daemon host (default: 127.0.0.1)
- `--port PORT`             core-daemon gRPC port (default: 50051)
- `--prefix CIDR`           IPv4 prefix for auto-assigned addresses (default: 10.0.0.0/24)
- `--ip-mode {private|mixed|public}` control address pool selection (RFC1918 only, mix with public, or public-only)
- `--ip-region {all|na|eu|apac|latam|africa|middle-east}` region for public pools (default: all = random from all regions)
- `--max-nodes N`           cap total hosts created
- `--verbose`               enable debug logging
- `--seed N`                RNG seed for reproducible randomness
- `--layout-density {compact|normal|spacious}` adjust node spacing for readability
 - Segmentation:
	 - `--nat-mode {SNAT|MASQUERADE}` NAT mode for router NAT rules (default: SNAT)
	 - `--dnat-prob <0..1>` probability to create DNAT (port-forward) for generated flows on routers (default: 0)
	 - `--seg-include-hosts` include host nodes as candidates for segmentation placement (default: routers only)
 - Traffic overrides:
	 - `--traffic-pattern {continuous|burst|periodic|poisson|ramp}`
	 - `--traffic-rate <KB/s>`
	 - `--traffic-period <seconds>`
	 - `--traffic-jitter <0-100>`
	- `--traffic-content {text|photo|audio|video}`

Example:

```bash
python -m core_topo_gen.cli \
	--xml validation/core-xml-syntax/auto-valid-testset/xml_scenarios/sample1.xml \
	--ip-mode mixed --verbose --seed 42

### Additive Planning Semantics & XML Metadata

The scenario editor (Web UI) and CLI share an additive planning model for hosts, routers, and vulnerabilities. A scenario-level attribute `scenario_total_nodes` is now written on `<Scenario>` summarizing the aggregate planned nodes across sections (hosts + routers + vulnerability explicit targets when applicable). Older XML without this attribute remains valid.

- Hosts ("Node Information" section):
	- Base (density) hosts are distributed proportionally only across Weight rows.
	- Count rows add absolute host counts on top of the proportional allocation.
- Routers ("Routing" section):
	- Section `density` in (0,1]: treated as a fractional multiplier of the effective base host pool (the base portion only; additive host Count rows are not multiplied).
	- Section `density` > 1.0: interpreted as an absolute router count contribution (legacy compatibility for earlier tests specifying integers like `5`).
	- Count rows (items with `v_metric="Count"`) add absolute routers (per protocol) in addition to any density-derived routers.
	- Final router total = `min(total_hosts, density_contribution + sum(abs_count))`.
	- This is additive even when both forms are present (earlier semantics sometimes replaced density when count rows existed—now unified for predictability).
- Vulnerabilities ("Vulnerabilities" section):
	- Section `density` fraction (clipped to 1.0) of the base host pool only (not including additive host rows) for derived vulnerabilities.
	- Count rows or `Specific` entries with `v_count` supply explicit counts added to the derived amount.

To enable lossless round‑trip of these semantics, additional attributes are written into the XML by the Web UI (`_build_scenarios_xml`). They are optional; older XML remains valid. The CLI now parses and merges this metadata into reports when present.

Section attribute summary (all optional):

"Node Information":
- `base_nodes`: integer base (density) host count used for proportional allocation (0 if no weight rows).
- `additive_nodes`: sum of Count row host additions.
- `combined_nodes`: `base_nodes + additive_nodes`.
- `weight_rows`: number of Weight rows.
- `count_rows`: number of Count rows.
- `weight_sum`: sum of raw (unnormalized) weight factors.

"Routing" and "Vulnerabilities":
- `explicit_count`: sum of absolute Count (or Specific) item counts.
- `derived_count`: derived count from density logic (see rules above).
- `total_planned`: `explicit_count + derived_count`.
- `weight_rows`: number of weight-factor items in the section.
- `count_rows`: number of explicit count items.
- `weight_sum`: sum of weight item factors.

These attributes appear only when the section has relevant items or user input. Downstream tooling can prefer them rather than recomputing from density + factors, ensuring reproducible planning even if factor normalization or remainder distribution algorithms change in future versions.

Programmatic access (Python):

```python
from core_topo_gen.parsers.planning_metadata import parse_planning_metadata
meta = parse_planning_metadata('scenario.xml', 'ScenarioName')
print(meta['node_info']['combined_nodes'])
```

Report integration: When present, planning metadata is rendered under a dedicated "Planning Metadata" section in the scenario Markdown report with namespaced keys (e.g. `plan_node_base_nodes`).

Runtime API access: A lightweight endpoint `/planning_meta?path=<xml>&scenario=<name>` returns the parsed metadata JSON (see `API.md`). This allows external tools to quickly inspect planned counts without invoking the full CLI run.

Backward compatibility: If attributes are absent, the parser falls back to recomputation (exact values for some legacy scenarios—like precise derived router counts tied to a changing host pool—may differ slightly, but overall semantics are preserved).

### Full Preview & Seed Usage

Web UI sequence:

1. Edit scenarios (unsaved edits still allow generating a preview; an auto‑save is attempted if XML is missing when you request a preview).
2. (Optional) Enter a numeric seed in the Seed box.
3. Click Full Preview.
4. Inspect structured sections (Overview, Routers, Hosts, Switches, Subnets, R2R, Seg Rules, History) or toggle Raw JSON.
5. Copy or reuse the seed (Copy Seed button or History "Use Seed").
6. Click Run (Seed) to launch an async run using either the explicit seed input or, if blank, the last preview's seed.

Determinism contract:

| Element | Deterministic with same seed & unchanged XML |
|---------|----------------------------------------------|
| Router count & IDs | Yes |
| Host role expansion & ordering | Yes |
| Switch regrouping (R2S) | Yes |
| R2R edge set (order may differ; set identical) | Yes |
| Service assignments | Yes |
| Vulnerability assignments | Yes |
| Segmentation planned rule list | Yes |
| Subnet CIDRs (allocator path) | Yes (given ip4_prefix & mode) |

If any source data (XML, env vars influencing allocator, IP mode/region) changes, results can diverge even with identical seed.

API quick start:

POST /api/plan/preview_full
```json
{ "xml_path": "/abs/path/scenarios.xml", "seed": 12345 }
```
Response includes: `seed`, `seed_generated` (boolean), `routers`, `hosts`, `switches_detail`, `r2r_edges_preview`, `segmentation_preview`, and distribution stats.

The front‑end does not persist previews server‑side; history is stored locally in `localStorage` under `coretg_full_preview_history`.

Experimental structural metadata (Services / Traffic / Segmentation): the XML builder also emits `explicit_count`, `weight_rows`, `count_rows`, and `weight_sum` for these sections to support future additive extensions and analytical tooling.

To inspect generated traffic or segmentation scripts without leaving the UI, use:

```
GET /api/open_scripts?kind=traffic&scope=runtime
GET /api/open_script_file?kind=traffic&scope=runtime&file=traffic_run.py
GET /api/download_scripts?kind=segmentation&scope=preview
```

These endpoints surface the files written under `/tmp/traffic` or `/tmp/segmentation` (runtime runs) and the latest temporary preview directories, returning JSON listings, truncated file content, or a ZIP archive suitable for reuse.

Schema documentation: see `SCENARIO_XML_SCHEMA.md` for a human-readable summary and examples; machine validation via `validation/scenarios.xsd`.

## Router Connectivity & Switch Aggregation Policies

The routing section now supports richer topology shaping beyond simple full meshes. Two orthogonal policy dimensions can be set per routing item via XML attributes (the Web UI exposes these controls):

1. Router-to-Router (R2R) Connectivity Mode (`r2r_mode` attribute)
	- `Uniform`: Attempts to produce a near-regular (balanced) degree distribution. Internally starts with a ring (ensuring connectivity) then incrementally adds edges while selecting the currently lowest-degree routers first. Guarantees max degree - min degree is small (typically ≤ 1 when target edge budget is feasible).
	- `NonUniform`: Produces a heterogeneous degree distribution by preferentially attaching extra edges to already higher-degree routers (rich‑get‑richer bias) after a minimal connectivity backbone.
	- (Omitted / empty): Falls back to the global mesh style (`--router-mesh-style` / GUI selection) which can be `full`, `ring`, or `tree` and applies when no explicit per‑item policy is set.

2. Router-to-Switch (R2S) Aggregation (`r2s_mode` / `r2s_edges` attributes)
	- When enabled, host nodes (originally directly connected to the core access switch) are rehomed behind auxiliary layer‑2 switches to simulate aggregation / distribution tiers or load concentration. Existing direct links are removed (rehoming is idempotent per run).
	- `r2s_edges` sets a target host count per aggregation switch (approximate; remainder hosts are balanced). Statistics are recorded: number of new switches, min/max/avg host counts per switch, std dev, and Gini coefficient.

### Aggregated Exact=1 Semantics (R2S)

When a routing item sets `r2s_mode="Exact"` and `r2s_edges="1"`, the planner applies a special aggregated semantics:

* Each router that has one or more directly attached hosts receives exactly one new aggregation switch.
* All of that router's hosts are migrated (rehomed) behind the single switch (not just a pair).
* A router–switch /30 is allocated plus a host LAN sized just large enough to contain every host plus the switch gateway (prefix chosen dynamically; may be larger than /28 when many hosts aggregate).
* This differs from `Exact` with a target > 1 (or other non-Exact modes) where switches are created in host pairs (each switch typically serving two hosts) until the target (or feasible pairs) is exhausted.
* If `Exact` mode is declared but `r2s_edges` is 0 or missing, the planner auto-derives a target from the first routing item that has a positive `r2s_edges`; if none is found and hosts exist it defaults to 1 (entering the aggregated behavior) to honor the user's intent to enable aggregation.

Implications:
* Provides a fast way to collapse all access hosts under a single distribution/aggregation layer per router (common campus style) without hand-tuning per-switch counts.
* Deterministic: given a seed and unchanged XML, the same switch IDs, LAN subnet prefixes, and host interface assignments repeat.
* Metrics: In the preview JSON the field `r2s_policy_preview` will include:
	* `mode` (`Exact`, `NonUniform`, `Min`, etc. — reflects the applied policy in the builder)
	* `mode_requested` (`Exact`, `Uniform`, `Min`, `NonUniform`, `Random`, or `ratio` depending on routing item input)
	* `target_per_router` (the declared or derived target, often 1 here)
	* `target_per_router_effective` when the system derived a fallback (e.g. default from 0 to 1)
	* `counts` mapping router_id -> created switch count (all 1's for routers with hosts under aggregated behavior)

Example XML enabling aggregated behavior for routers introduced purely via Count rows:

```xml
<section name="Node Information" total_nodes="0">
	<item selected="Workstation" v_metric="Count" v_count="9" />
</section>
<section name="Routing">
	<!-- Three absolute routers; exact aggregation with one switch each rehoming all of its hosts -->
	<item selected="OSPF" v_metric="Count" v_count="3" r2s_mode="Exact" r2s_edges="1" />
</section>
```

In the Full Preview you should observe:
* 3 routers (`r1..r3`)
* 9 hosts (`h1..h9-*`) distributed round‑robin among routers (3 each)
* 3 aggregation switches (`rsw-<rid>-1`) each listing all 3 hosts of its router in `switches_detail`.

Contrast (pair-based) example creating multiple small switches per router:

```xml
<section name="Node Information" base_nodes="12">
	<item selected="Workstation" factor="1" />
</section>
<section name="Routing" density="3">
	<!-- Exact target 2 => planner attempts up to 2 switches per router, each serving a host pair (2 hosts per switch) -->
	<item selected="OSPF" factor="1" r2s_mode="Exact" r2s_edges="2" />
</section>
```

Here each router (3 total) receives up to 2 switches (subject to available host pairs), each switch normally serving 2 hosts; any remainder host without a pair is left directly connected (or, if enhanced later, may be grouped in a final uneven switch).

### Host Grouping Bounds (NonUniform R2S)

When `r2s_mode="NonUniform"` you can specify per-item bounds `r2s_hosts_min` / `r2s_hosts_max` to influence stochastic grouping of hosts behind switches. The preview exposes:

* `r2s_policy_preview.per_router_bounds` (router_id -> {min,max})
* `r2s_grouping_preview[]` entries with `group_sizes` honoring provided bounds where feasible.

Rules:
* Bounds optional; defaults fall back to [2,4].
* Remainder smaller than min merges into the previous group (may exceed max) to avoid undersized trailing groups.
* Equal min==max enforces fixed group sizes except for final merged remainder.
* Exact=1 aggregated behavior ignores bounds.

Example fixed grouping of 3:
```xml
<item selected="RIP" v_metric="Count" v_count="4" r2s_mode="NonUniform" r2s_hosts_min="3" r2s_hosts_max="3" />
```

### Additive (Count-Based) Routing Items & R2S

Count-based routing items (`v_metric="Count"`) now preserve their R2R and R2S attributes (`r2r_mode`, `r2r_edges`, `r2s_mode`, `r2s_edges`). This means you can drive both router presence and aggregation policy solely from Count rows (no density / factor rows required). The preview and runtime builders treat these items equivalently to factor-based ones for policy derivation. If both factor (density) and count items exist, switch aggregation policy is derived from the first item declaring an R2S mode (precedence: first Exact, else first any mode).

### Mesh Styles (Global Fallback)

If no `r2r_mode` is set on a routing item, the builder applies the selected mesh style to the entire router set:

- `full`: Complete graph (n*(n-1)/2 links)
- `ring`: Simple cycle (n links)
- `tree`: Spanning chain (n-1 links) to guarantee minimal connectivity

These styles are computed exactly (no over-linking) and coexist with per-item policies when those are explicitly defined.

### Report Metrics

The generated Markdown scenario report now includes advanced connectivity statistics when routers are present:

- Router degree stats: min / max / average / standard deviation / Gini coefficient
- Router-to-switch aggregation stats: number of aggregation switches, host count distribution stats (min/max/avg/std/Gini), and total rehomed hosts

These metrics help evaluate balance (Uniform) versus intentional skew (NonUniform) and validate aggregation design.

## Vulnerability Assignment Leniency

When the Web UI marks vulnerability images as "downloaded" but not yet pulled locally, the assignment phase can operate in a lenient mode (no strict filesystem/image existence check) so that planning and reports are still produced. This behavior improves testability and CI workflows where image pulls are intentionally skipped. Production deployments should still ensure images are pulled for successful runtime compose launches.

## XML Quick Examples (Connectivity & Aggregation)

Balanced + Skewed Routers with Aggregation:
```xml
<section name="Routing" density="0.4">
	<!-- Derive routers from 40% of base host pool; balanced degree distribution -->
	<item selected="OSPF" factor="1" r2r_mode="Uniform" />
	<!-- Add two absolute routers with heterogeneous links and rehome hosts into ~5-host switches -->
	<item selected="BGP" v_metric="Count" v_count="2" r2r_mode="NonUniform" r2s_mode="aggregate" r2s_edges="5" />
</section>
```

Count-Only Routers (no density contribution):
```xml
<section name="Routing">
	<item selected="OSPF" v_metric="Count" v_count="3" />
</section>
```

Explicit Zero Base Hosts with Pure Count Additions:
```xml
<section name="Node Information" total_nodes="0">
	<item selected="Workstation" v_metric="Count" v_count="6" />
	<item selected="Server" v_metric="Count" v_count="2" />
</section>
```

Router Density as Absolute Count:
```xml
<section name="Routing" density="6">
	<item selected="OSPF" factor="1" />
</section>
```

Host Segmentation + Traffic (abridged):
```xml
<section name="Traffic" density="0.3">
	<item selected="Generic" factor="1" pattern="burst" rate_kbps="128" />
</section>
<section name="Segmentation" density="0.5">
	<item selected="Firewall" factor="1" />
	<item selected="NAT" v_metric="Count" v_count="1" />
</section>
```

Use these snippets as starting points; the Web UI will enrich them with planning metadata on save.
```

## HTTP API (for automation)

If you prefer to drive runs from scripts or external tools, the Web UI exposes a simple HTTP API. See the full reference here:

- API Reference: [API.md](./API.md)

Typical flow:
- POST `/run_cli_async` with the saved `xml_path`
- Poll `GET /run_status/<run_id>` until `done: true`
- Download the generated report via `GET /download_report?path=<abs_or_repo_path>`

Traffic generation:
- If Traffic is defined in the XML, scripts are written to `/tmp/traffic` and a `Traffic` service is enabled on relevant nodes before the session starts.
- Filenames use the pattern:
	- Receivers: `traffic_{receiverNodeId}_r{n}.py`
	- Senders:   `traffic_{senderNodeId}_s{n}.py`
- The directory is cleaned before generation.

Traffic XML attributes (optional):
- In the `<section name="Traffic">`, each `<item>` can define additional behavior:
		- `pattern`: continuous | burst | periodic | poisson | ramp (default: continuous)
	- `rate` or `rate_kbps`: desired sending rate in KB/s (default: 0 = minimal)
	- `period` or `period_s`: on-duration for a sending burst in seconds (default: 10)
	- `jitter` or `jitter_pct`: +/- percentage variation applied to sleep intervals (default: 0)
	- `content` or `content_type`: shape payload to mimic data types:
		- `text` (HTTP-like lines), `photo`/`image` (JPEG-like markers), `audio` (frame-ish bytes), `video` (NAL-like segments)

These attributes influence only sender scripts. Receivers are simple listeners. For burst/periodic, senders transmit for `period` seconds, then idle for roughly the same duration before repeating. Content type changes only the byte patterns; it does not produce valid media files, but it better approximates media-like flows for testing.

### Python interpreter selection (CLI + Web UI backend)

The project previously assumed a `core-python` executable (a convenience name some CORE installs provide). The backend and documentation now use a resilient interpreter selection order:

Priority order used by the Web UI when invoking the CLI:
1. `CORE_PY` environment variable (absolute path or command name)
2. `core-python` (if found in `PATH`)
3. `python3`
4. `python`
5. `sys.executable` (the interpreter running the Flask app)

Override explicitly (examples):
```bash
# When starting the host Web UI
WEBUI_PY=/usr/bin/python3 make host-web
```

Inside the running container you can verify which interpreter was chosen by looking at the web container logs; each run logs a line like:
```
[sync] Using python interpreter: /usr/bin/python3
```
or
```
[async] Using python interpreter: /usr/local/bin/python
```

If you encounter `core-python: not found` when running on the host, export `WEBUI_PY` to point at the desired interpreter, or activate your `core-python` venv before `make host-web`.

Segmentation generation:
- If Segmentation is defined in the XML, scripts are written to `/tmp/segmentation` and a custom service named `Segmentation` is enabled on the affected nodes.
- The generator supports three selection labels in XML/GUI: `Firewall`, `NAT`, and `CUSTOM` (plus `Random`). Internally, all enable a unified `Segmentation` service in CORE.
- Placement defaults to routers only. Use `--seg-include-hosts` to allow host-level firewall/custom rules when desired. NAT is always router-only and never placed on hosts.
- NAT mode can be set via `--nat-mode` (SNAT or MASQUERADE). NAT setup enforces default-deny on the router `FORWARD` chain with a stateful allow for ESTABLISHED,RELATED; scripts are idempotent.
- Allow rules: after traffic generation, allow rules are inserted only when a flow would otherwise be blocked by segmentation policies. These are written into the same `/tmp/segmentation` folder and appended to `segmentation_summary.json`.
- Optional DNAT: with `--dnat-prob > 0`, per-router DNAT (port-forward) rules for some flows are generated.
- The directory `/tmp/segmentation` is cleaned before each run. A summary JSON (`segmentation_summary.json`) records all rules and is used to avoid duplicates across runs.
- Logging mirrors traffic: planning and per-node actions are logged, along with final counts of rules by type and nodes affected.

### Custom traffic profile (pluggable)

You can defer to a custom implementation by setting `pattern="custom"` on a traffic item. The generator will call a registered plugin if present:

- Register a plugin at runtime:
	- Import `core_topo_gen.plugins.traffic` and call `register(sender, receiver=None)`.
	- `sender(host, port, rate_kbps, period_s, jitter_pct, content_type, protocol) -> str` should return a full Python script.
	- `receiver(port, protocol) -> str` is optional; built-ins are used if omitted.

If no plugin is registered, `pattern="custom"` falls back to the built-in TCP/UDP generators.

## Configure CORE custom service (Traffic)

To auto-start generated traffic scripts inside nodes, CORE needs a custom service named "Traffic".

1) On the CORE machine, place `on_core_machine/custom_services/TrafficService.py` into your custom services folder, e.g.:

	- `/usr/local/share/core/custom_services/` (system-wide)
	- or your configured custom services directory

2) Point CORE to this folder in the CORE configuration file. Edit `~/.core/core.conf` (user) or `/etc/core/core.conf` (system) and set:

```ini
[gui]
custom_services_path = /usr/local/share/core/custom_services
```

Adjust the path to match where you placed `TrafficService.py`.

3) Restart `core-daemon` (and CORE GUI if open) so the new service is discovered.

When enabled on a node, the Traffic service will copy `/tmp/traffic/traffic_<nodeId>_*.py` into the node and run them in the background.

## Configure CORE custom service (Segmentation)

To auto-start generated segmentation scripts, CORE needs a custom service named "Segmentation".

1) On the CORE machine, install a Segmentation service definition (for example `SegmentationService.py`) into your custom services folder, e.g.:

	- `/usr/local/share/core/custom_services/` (system-wide)
	- or your configured custom services directory

2) Ensure CORE is pointed at that folder in `~/.core/core.conf` or `/etc/core/core.conf` via `custom_services_path` (see Traffic section above).

3) Restart `core-daemon` so the service is discovered.

When enabled on a node, the Segmentation service will copy and execute `/tmp/segmentation/seg_*_<nodeId>_*.py` scripts.

## Docker-compose vulnerabilities runtime

Docker-compose vulnerabilities are realized using CORE's built-in Docker node type (no custom service required).

Behavior and requirements:

- During topology build, a subset of host slots are converted to Docker nodes based on your Vulnerabilities selection (Category/Specific, Count/Weight, Vector).
- For each Docker node, the generator writes a per-node compose file at `/tmp/vulns/docker-compose-<node>.yml`, injecting `container_name: <node>`.
- The generator makes a best-effort to run `docker compose up -d` on the host for those files. You can also manage them manually.
- Ensure Docker is installed and images are pre-pulled via the Web UI Vulnerability Catalog (Download + Pull). Only downloaded and pulled items are eligible for assignment.
## CORE management page (Web UI)

The Web UI includes a dedicated page to manage CORE sessions and topologies. Open the Web UI and click the `CORE` link in the navbar.

What you’ll see:

- Active Sessions (left)
	- Lists active sessions discovered via gRPC: session id, state, nodes count, and (when available) the source XML file path.
	- Actions:
		- Details: summary info and nodes list for the session’s XML (if available).
		- Stop: request the daemon to stop the session.
		- Delete: request the daemon to delete the session.
		- Save XML: snapshot the current session to `outputs/core-sessions/` (validated against the XSD).

- Available Topologies (right)
	- Scans `uploads/` and `outputs/` for `.xml` files that look like CORE scenario XMLs and validates them against the schema.
	- Each file shows validity, whether it’s currently running, and the mapped session id (best‑effort).
	- Actions:
		- Start: open the XML in CORE and start the session (enabled only for valid XMLs).
		- Details: analyze XML (nodes/networks/links/services) and view a quick summary.
		- Download: download the XML via the safe `/download_report?path=...` route.
		- Delete: remove the XML file safely. For safety, deletion is limited to files under `uploads/` or `outputs/`.
	- Upload form: add a new XML; the server validates it before it appears in the list.

Connectivity and environment:

- gRPC access to `core-daemon` is optional for browsing/uploading XMLs. When gRPC isn’t available, actions requiring it (start/stop/delete/save) show a friendly error but the page remains usable for XML management.
- Default daemon address is `CORE_HOST:CORE_PORT` (defaults `localhost:50051`). You can override via environment when launching the Web UI:

```bash
export CORE_HOST=127.0.0.1
export CORE_PORT=50051
python webapp/app_backend.py
```

Security and safety:

- Delete operations from the CORE page are restricted to `uploads/` and `outputs/` to prevent accidental removal of arbitrary files.
- Session XML snapshots are validated against the same XSD as uploads; invalid snapshots are discarded with a log message.

## Scenario Deletion and Reports

Deleting a scenario from the Web GUI now prompts for confirmation. If there are historical runs (entries on the Reports page) associated with the scenario name, the dialog will warn and display how many will be removed. Confirming the deletion will:

- Remove the scenario from the in-browser editor state.
- Purge any run history entries whose parsed `scenario_names` include the deleted scenario.
- Delete associated artifact files (scenario XML, generated report.md, and any pre-session CORE XML snapshot) that reside under the `outputs/` tree.

Directories that become empty in `outputs/` after artifact removal are also cleaned up when safe (only if empty). This helps keep the artifacts directory lean.

## Troubleshooting

- “No module named core” or connection errors:
	- Ensure CORE is installed and `core-daemon` is running.
	- Check gRPC host/port with `--host` and `--port`.
- Long pause after “Traffic scripts written…”:
	- Starting a CORE session can take time while services initialize. Use `--verbose` and check `core-daemon` logs for details.

## Authentication and users

The Web UI requires login. On first boot (when no users exist), it seeds a default administrator account:

- Username: `coreadmin`
- Password: `coreadmin`

Change this password immediately after your first login.

Managing users:
- Admins can open the `Users` page in the navbar to create/delete users and reset passwords.
- Any user can change their own password from `Profile` → `Change Password` or at `/me/password`.
- The user database lives at `outputs/users/users.json`.

Admin fallback safety:
- If the users file exists but contains no admin, the app will create an `admin` account with a random password (or the value of `ADMIN_PASSWORD`). The generated password is logged on startup.