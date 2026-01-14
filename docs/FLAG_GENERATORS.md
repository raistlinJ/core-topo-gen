# Flag Generators: Vocabulary + Chaining

A **flag generator** is a runnable workload (currently `docker-compose`) that produces *information/capability* needed to reach the next node(s) in an Attack Flow.

The Flow system treats each generator as a small contract:

- **inputs**: keys the user must already have (from earlier generators)
- **outputs**: keys the generator provides
- **hint_template**: a human-readable hint that tells the user where to go next

## Standard Key Vocabulary

Use these keys consistently so chains can be validated and composed.

### SSH
- `ssh.username`
- `ssh.password`
- `ssh.private_key`

### HTTP / Web
- `http.basic.username`
- `http.basic.password`
- `api.token`

### Progress / Targets
- `next.node_name`
- `next.node_id`
- `flag`

### Filesystem / Files
- `filesystem.file` (path to a generated file, typically under `artifacts/...`)
- `filesystem.dir`
- `filesystem.path`

### Networking
- `network.ip`
- `network.port`
- `network.subnet`

## Hint Templates

Every generator should include a `hint_template`.

Flow will substitute these placeholders (if present):
- `{{THIS_NODE_NAME}}`, `{{THIS_NODE_ID}}`
- `{{NEXT_NODE_NAME}}`, `{{NEXT_NODE_ID}}`
- `{{SCENARIO}}`

Example:

`Next: SSH to {{NEXT_NODE_NAME}} (id={{NEXT_NODE_ID}}) using ssh.username/ssh.password.`

Notes:
- At the moment, Flow provides **node name/id** as the “address-like” hint. If you later want real IPs, we can extend the preview pipeline to compute and expose them.
- For templates that expose files, we recommend including a `hint.txt` in the payload (served over HTTP or mounted into the container) that contains the rendered hint.

## Schemas (Generator Authors)

This repo includes JSON schemas to make generator behavior consistent across both:
- **flag-generators** (artifacts inserted into existing docker nodes), and
- **flag-node-generators** (generators that emit a per-node docker-compose environment).

Files:
- `validation/flag_generator_catalog.schema.json` — schema for generator-catalog JSON sources under `data_sources/flag_generators/` and `data_sources/flag_node_generators/`.
- `validation/flag_generator_outputs.schema.json` — schema for the runtime `/outputs/outputs.json` manifest emitted by a generator.

### v3 Contract Notes (`requires` vs `inputs`)

In schema version 3 catalogs:

- `plugins[].requires` is **artifacts-only**: keys that must be produced by earlier chain steps.
- Flow-synthesized runtime fields **must not** appear in `requires` (they belong in `plugins[].inputs`).
	- Currently enforced forbidden names: `seed`, `secret`, `env_name`, `challenge`, `flag_prefix`, `username_prefix`, `key_len`, `node_name`.

### Output Placeholder Substitution

In addition to `{{THIS_*}}`/`{{NEXT_*}}` placeholders, Flow supports substituting runtime generator outputs into the hint:

- `{{OUTPUT.<key>}}`

Where `<key>` is a key inside `outputs.json` under the `outputs` object.

Example hint template:

`Next: SSH to {{NEXT_NODE_NAME}} using {{OUTPUT.ssh.username}} / {{OUTPUT.ssh.password}}`

## Injected artifacts (`inject_files`)

Some generators need to deliver a file/binary that will be mounted/copied into other containers (or uploaded for remote execution). Use the `implementations[].inject_files` allowlist.

Key rules:

- Write the generated file under `/outputs/artifacts/...` and reference it from `outputs.json`.
- Prefer declaring `inject_files` using an output key, not a path.

Example:

- `outputs.json.outputs.filesystem.file = "artifacts/challenge"`
- `implementations[].inject_files = ["filesystem.file"]`

The runner will stage only allowlisted items into `<out_dir>/injected/`.
