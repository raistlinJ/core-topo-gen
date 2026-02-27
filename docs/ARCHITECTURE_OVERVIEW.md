# Architecture Overview

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
