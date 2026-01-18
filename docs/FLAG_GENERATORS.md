# Flag Generators: Vocabulary + Chaining

A **flag generator** is a runnable workload (currently `docker-compose`) that produces *information/capability* needed to reach the next node(s) in an Attack Flow.

The Flow system treats each generator as a small contract:

- **inputs**: keys the user must already have (from earlier generators)
- **outputs**: keys the generator provides
- **hint_template**: a human-readable hint that tells the user where to go next

## Standard Key Vocabulary

Use these keys consistently so chains can be validated and composed.

### SSH
- `Credential(user)`
- `Credential(user, password)`
- `Credential(user, hash)`

### HTTP / Web
- `Credential(user, password)`
- `Token(service)`
- `APIKey(service)`

### Progress / Targets
- `Flag(flag_id)`
- `PartialFlag(flag_id, part)`

### Filesystem / Files
- `File(path)` (path to a generated file, typically under `artifacts/...`)
- `Directory(host, path)`

### Networking
- `Knowledge(value)` (e.g., an IP address)
- `PortForward(host, port)`
- `InternalNetwork(subnet)`

## Hint Templates

Every generator should include a `hint_template`.

Flow will substitute these placeholders (if present):
- `{{THIS_NODE_NAME}}`, `{{THIS_NODE_ID}}`
- `{{NEXT_NODE_NAME}}`, `{{NEXT_NODE_ID}}`
- `{{SCENARIO}}`

Example:

`Next: SSH to {{NEXT_NODE_NAME}} (id={{NEXT_NODE_ID}}) using {{OUTPUT.Credential(user,password)}}.`

Notes:
- At the moment, Flow provides **node name/id** as the “address-like” hint. If you later want real IPs, we can extend the preview pipeline to compute and expose them.
- For templates that expose files, we recommend including a `hint.txt` in the payload (served over HTTP or mounted into the container) that contains the rendered hint.

## Schemas (Generator Authors)

This repo includes JSON schemas to make generator behavior consistent across both:
- **flag-generators** (artifacts inserted into existing docker nodes), and
- **flag-node-generators** (generators that emit a per-node docker-compose environment).

Files:
- `validation/generator_manifest_v1.schema.json` — schema for `manifest.yaml` (manifest_version: 1), including canonical input types.
- `validation/flag_generator_outputs.schema.json` — schema for the runtime `/outputs/outputs.json` manifest emitted by a generator.

### Output Placeholder Substitution

In addition to `{{THIS_*}}`/`{{NEXT_*}}` placeholders, Flow supports substituting runtime generator outputs into the hint:

- `{{OUTPUT.<key>}}`

Where `<key>` is a key inside `outputs.json` under the `outputs` object.

Example hint template:

`Next: SSH to {{NEXT_NODE_NAME}} using {{OUTPUT.Credential(user)}} / {{OUTPUT.Credential(user,password)}}`

## Injected artifacts (`injects`)

Some generators need to deliver a file/binary that will be mounted/copied into other containers (or uploaded for remote execution). Use the manifest `injects` allowlist.

Key rules:

Destination directory (optional):

- `injects: ["File(path) -> /opt/bin"]`
- If unspecified or invalid, files default to `/tmp`.

- `outputs.json.outputs.File(path) = "artifacts/challenge"`
- `manifest.yaml: injects: ["File(path)"]`

The runner will stage only allowlisted items into `<out_dir>/injected/`.
