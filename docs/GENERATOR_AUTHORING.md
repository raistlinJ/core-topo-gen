# Generator Authoring Guide (Manifests + Generator Packs)

This repo supports **two generator families** used by the Flag Sequencing (Flow) system:

- **flag-generators**: run *on an existing Docker node* to produce artifacts (credentials, URLs, next-step hints, etc.).
- **flag-node-generators**: generate a **per-node `docker-compose.yml`** used to *create* a challenge node (SSH/HTTPS/NFS/local-file flag nodes, etc.).

Both families share the same runtime output contract: a machine-readable `outputs.json`.

AI prompt templates (copy/paste):
- [docs/AI_PROMPT_TEMPLATES.md](AI_PROMPT_TEMPLATES.md)

---

## 1) How generators are discovered

### Installed generators (Web UI + Flow)
The Web UI treats **installed generators** as the source of truth.

- Install location: `outputs/installed_generators/`
- Discovery: `manifest.yaml` / `manifest.yml` inside each generator directory
- Disable semantics:
  - Packs and individual generators can be disabled.
  - Disabled generators are hidden from Flow substitution and rejected at preview/execute time.

Installed generators are managed as **Generator Packs** (ZIP files) uploaded/imported from the Flag Catalog page.

### Repo-local manifests (developer workflow)
For local development you can also place manifests directly under:

- `flag_generators/<your_generator_dir>/manifest.yaml`
- `flag_node_generators/<your_generator_dir>/manifest.yaml`

The runner and discovery logic will pick these up (in addition to installed generators).

---

## 2) The manifest format (`manifest_version: 1`)

Each generator directory contains a manifest file:

- `manifest.yaml` (preferred) or `manifest.yml`

Minimum viable manifest (flag-generator):

```yaml
manifest_version: 1
id: my_source_id
kind: flag-generator
name: My Generator
description: Emits deterministic SSH credentials.

runtime:
  type: docker-compose
  compose_file: docker-compose.yml
  service: generator

inputs:
  - name: seed
    type: string
    required: true
  - name: secret
    type: string
    required: true
    sensitive: true

artifacts:
  requires: []
  produces:
    - flag
    - Credential(user)
    - Credential(user, password)

hint_templates:
  - "Next: use {{OUTPUT.Credential(user)}} / {{OUTPUT.Credential(user,password)}}"

# If you produce files/binaries that should be safe to mount into other containers.
injects:
  - File(path)

# Optional fixed env vars passed to the runtime.
env:
  SOME_FIXED_ENV: "value"
```

Notes:
- `kind` must be `flag-generator` or `flag-node-generator`.
- `inputs` is a list of input descriptors (used by UI forms and Flow).
- `artifacts.requires` / `artifacts.produces` drive Flow dependency chaining.

### Input types (mandatory convention)
Generator input `type` values are normalized to a small canonical set. If your manifest omits `type` or uses an unknown value, it **falls back to** `string`.

Canonical values:
- `string`
- `int`, `float`, `number`
- `boolean`
- `json`
- `file` (or `path`/`filepath` aliases)
- `string_list`
- `file_list`

Schema reference:
- `validation/generator_manifest_v1.schema.json`

### Important: IDs are rewritten on install
When you install a Generator Pack via the Web UI, each generator is assigned a **new numeric** `id` (as a string) and the installed manifest is rewritten to use that numeric ID.

- The installed generator directory also contains `.coretg_pack.json` with:
  - `source_generator_id` (your original manifest `id`)
  - `generator_id` (the assigned installed numeric ID)

This means:
- Treat the manifest `id` in your source pack as a *source identifier*.
- Don’t assume it will remain stable after installation.

---

## 3) Runtime contract (what the generator writes)

Generators run with:

- `/inputs/config.json` mounted read-only
- `/outputs/` mounted read-write

Every run must write an `outputs.json` file in the output directory.

Schema:
- `validation/flag_generator_outputs.schema.json`

Minimum valid `outputs.json`:

```json
{
  "generator_id": "<some string>",
  "outputs": {
    "flag": "FLAG{...}"
  }
}
```

Practical guidance on `generator_id`:
- The schema requires it, but it is currently treated as provenance/metadata.
- If your generator can know the invoked generator ID, write that.
- Otherwise, writing your source manifest ID is acceptable.

---

## 4) Injected artifacts (`injects` allowlist)

If a generator produces files that should be safely mountable/copiable into other containers, use `injects` in the manifest.

How it works:

- Generators should write files under `/outputs/artifacts/...`.
- After the generator finishes, `scripts/run_flag_generator.py` stages **only** allowlisted items into `<out_dir>/injected/`.
- If the generator produces a `docker-compose.yml`, the runner rewrites **relative bind mounts** to use a named volume and adds an **init-copy** service that copies allowlisted files into the volume before the main service runs.

`injects` entries can be:

- A relative path like `artifacts/my_binary` (prefix `artifacts/` is optional), or
- An **output artifact key** like `File(path)` which is resolved via `outputs.json.outputs`.

Optional destination directory syntax:

- `artifacts/my_binary -> /opt/bin`
- `File(path) => /var/tmp`

If no destination is provided (or it fails validation), files default to `/tmp`.

---

## 5) Hint templates and substitution

Manifests can declare:

- `hint_template` (single string)
- `hint_templates` (list of strings; typically least → most revealing)

Flow substitutions include:

- `{{THIS_NODE_NAME}}`, `{{THIS_NODE_ID}}`
- `{{NEXT_NODE_NAME}}`, `{{NEXT_NODE_ID}}`
- `{{SCENARIO}}`
- `{{OUTPUT.<key>}}` where `<key>` comes from `outputs.json.outputs`

Example:

```
Next: SSH to {{NEXT_NODE_NAME}} using {{OUTPUT.Credential(user)}} / {{OUTPUT.Credential(user,password)}}
```

---

## 6) Local testing

The canonical runner is:

- `scripts/run_flag_generator.py`

It runs manifest-based generators (repo-local or installed).

### Test a flag-generator

```bash
python scripts/run_flag_generator.py \
  --kind flag-generator \
  --generator-id <generator_id> \
  --out-dir /tmp/fg_test \
  --config '{"seed":"123","secret":"demo"}'

cat /tmp/fg_test/outputs.json
```

### Test a flag-node-generator

```bash
python scripts/run_flag_generator.py \
  --kind flag-node-generator \
  --generator-id <generator_id> \
  --out-dir /tmp/nodegen_test \
  --config '{"seed":"123","node_name":"node1","flag_prefix":"FLAG"}'

cat /tmp/nodegen_test/docker-compose.yml
cat /tmp/nodegen_test/outputs.json
```

---

## 7) Packaging a Generator Pack (ZIP)

A Generator Pack ZIP is a zip archive containing one or more generator directories under either (or both):

- `flag_generators/<generator_dir>/...`
- `flag_node_generators/<generator_dir>/...`

Each generator dir must include a `manifest.yaml`/`manifest.yml`.

Example:

```text
flag_generators/
  py_my_ssh_creds/
    manifest.yaml
    docker-compose.yml
    generator.py
flag_node_generators/
  py_my_node_challenge/
    manifest.yaml
    docker-compose.yml
    generator.py
```

Create a ZIP (example):

```bash
zip -r my_generator_pack.zip flag_generators/py_my_ssh_creds flag_node_generators/py_my_node_challenge
```

Install it in the Web UI via the Flag Catalog page (upload/import URL).
