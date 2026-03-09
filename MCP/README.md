# CORE Topo Gen MCP Server

This directory contains a repo-native Model Context Protocol server for scenario authoring.

Current entrypoint:

```bash
./.venv312/bin/python MCP/server.py
```

The server speaks JSON-RPC over stdio and currently supports these MCP methods:

- `initialize`
- `tools/list`
- `tools/call`

Current tool surface:

- `scenario.create_draft`
- `scenario.get_draft`
- `scenario.list_drafts`
- `scenario.get_authoring_schema`
- `scenario.set_notes`
- `scenario.replace_section`
- `scenario.add_node_role_item`
- `scenario.add_service_item`
- `scenario.add_traffic_item`
- `scenario.add_segmentation_item`
- `scenario.search_vulnerability_catalog`
- `scenario.add_vulnerability_item`
- `scenario.preview_draft`
- `scenario.save_xml`
- `scenario.delete_draft`

Design goals:

- Keep the model out of raw XML generation.
- Reuse repo-native backend validation and preview logic.
- Persist XML only through the existing save path.
- Keep the tool surface narrow and scenario-authoring specific.

Example initialize request:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
```

Example tool list request:

```json
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
```

Example draft flow:

1. `scenario.create_draft`
2. `scenario.get_authoring_schema`
3. `scenario.add_node_role_item`
4. `scenario.add_service_item`
5. `scenario.add_traffic_item`
6. `scenario.add_segmentation_item`
7. `scenario.search_vulnerability_catalog`
8. `scenario.add_vulnerability_item`
9. `scenario.replace_section`
10. `scenario.preview_draft`
11. `scenario.save_xml`

Vulnerability authoring flow:

1. Search with a vague request such as `mysql vulnerability` using `scenario.search_vulnerability_catalog`.
2. Append the selected match to the draft via `scenario.add_vulnerability_item`.
3. The tool writes a concrete `Specific` vulnerability row with `v_name` and `v_path`, which is compatible with the existing planner and XML save path.

Node and traffic authoring flow:

1. Start with `scenario.get_authoring_schema` to discover current backend values and defaults for Node Information, Traffic, Services, and Segmentation.
2. Use `scenario.add_node_role_item` for explicit host counts, especially Docker hosts. Example: add three Docker nodes with `role="docker"` and `count=3`.
3. Use `scenario.add_service_item` for Services rows and `scenario.add_segmentation_item` for Segmentation rows when the prompt asks for those sections directly.
4. Use `scenario.add_traffic_item` for concrete TCP or UDP traffic. The tool fills in backend-safe defaults such as `pattern="continuous"`, `content_type="text"`, and explicit counts so preview flows materialize.
5. The schema response distinguishes suggested/random values from explicit runtime values, which is important because not every parser/runtime path is a strict enum.

This is the first slice. It is intentionally draft-centric and in-memory. The next likely step is an orchestration tool that interprets natural-language goals into a sequence of these draft mutations.