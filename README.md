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
- `--max-nodes N`           cap total hosts created
- `--verbose`               enable debug logging
- `--seed N`                RNG seed for reproducible randomness

Example:

```bash
python -m core_topo_gen.cli \
	--xml validation/core-xml-syntax/auto-valid-testset/xml_scenarios/sample1.xml \
	--verbose --seed 42
```

Traffic generation:
- If Traffic is defined in the XML, scripts are written to `/tmp/traffic` and a `Traffic` service is enabled on relevant nodes before the session starts.
- Filenames use the pattern:
	- Receivers: `traffic_{receiverNodeId}_r{n}.py`
	- Senders:   `traffic_{senderNodeId}_s{n}.py`
- The directory is cleaned before generation.

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

## Troubleshooting

- “No module named core” or connection errors:
	- Ensure CORE is installed and `core-daemon` is running.
	- Check gRPC host/port with `--host` and `--port`.
- Long pause after “Traffic scripts written…”:
	- Starting a CORE session can take time while services initialize. Use `--verbose` and check `core-daemon` logs for details.