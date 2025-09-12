# core-topo-gen

Generate CORE topologies from XML scenarios via a GUI or CLI. Supports services/routing assignment, segmented or star layouts, and optional traffic script generation.

## Prerequisites

- Python 3.10+ recommended
- CORE 9.2+ installed and `core-daemon` running (for starting sessions)
- Install Python dependencies:

```bash
pip install -r requirements.txt
```

If you use a virtual environment, activate it before installing.

## Run the GUI

The GUI lets you load an XML scenario, analyze it, and generate the CORE session asynchronously with progress feedback.

```bash
python main.py
```

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
```

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