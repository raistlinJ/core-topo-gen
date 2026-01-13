# Generator Authoring Guide (Tutorial + Templates)

This repo supports **two generator families** used by the Flag Sequencing (Flow) system:

- **flag-generators**: run *on an existing Docker node* to produce artifacts (credentials, URLs, next-step hints, etc.).
- **flag-node-generators**: generate a **per-node `docker-compose.yml`** used to *create* a challenge node (SSH/HTTPS/NFS/local-file flag nodes, etc.).

Both families share the same runtime output contract: a machine-readable `outputs.json`.

---

## 1) Concepts and file layout

### Catalog files (what Flow loads)
Generators are described in JSON “catalog source” files under:

- `data_sources/flag_generators/*.json`
- `data_sources/flag_node_generators/*.json`

Each catalog file contains:

- `plugins[]`: the *contract* (`requires`, `produces`, `inputs`)
- `implementations[]`: how to run it (`source.path`, `compose.file/service`, `hint_templates`, etc.)

Schema:
- `validation/flag_generator_catalog.schema.json`

Enable/disable catalog sources via:
- `data_sources/flag_generators/_state.json`
- `data_sources/flag_node_generators/_state.json`

### Runtime output files (what the generator writes)
Every generator run writes to an output directory (host path), typically:

- `outputs.json` (required)
- `hint.txt` (optional but recommended)
- `flag.txt` (optional, but many generators write it)
- other artifacts (e.g., `ssh_creds.json`, binaries, configs)

Schema:
- `validation/flag_generator_outputs.schema.json`

Minimum valid `outputs.json`:

```json
{
  "generator_id": "my.plugin_id",
  "outputs": {
    "flag": "FLAG{...}"
  }
}
```

---

## 2) Key vocabulary (artifacts)

Artifacts are the “typed keys” that let generators chain.

Common examples (from `docs/FLAG_GENERATORS.md`):
- `ssh.username`, `ssh.password`, `ssh.private_key`
- `http.basic.username`, `http.basic.password`, `api.token`
- `next.node_name`, `next.node_id`
- `flag`

Guidelines:
- Prefer stable, namespaced keys (`ssh.username` not `user`).
- Put **Flow-synthesized** runtime values in `plugins[].inputs`, not `plugins[].requires`.
  - Forbidden in `requires`: `seed`, `secret`, `env_name`, `challenge`, `flag_prefix`, `username_prefix`, `key_len`, `node_name`.

---

## 3) Hint templates and substitution

Catalog implementations can define:

- `hint_template` (single string)
- `hint_templates` (list of strings; typically least → most revealing)

Flow substitutions:
- `{{THIS_NODE_NAME}}`, `{{THIS_NODE_ID}}`
- `{{NEXT_NODE_NAME}}`, `{{NEXT_NODE_ID}}`
- `{{SCENARIO}}`
- `{{OUTPUT.<key>}}` where `<key>` comes from `outputs.json.outputs`.

Example:

```
Next: SSH to {{NEXT_NODE_NAME}} using {{OUTPUT.ssh_username}} / {{OUTPUT.ssh_password}}
```

Best practice:
- Include 2–4 `hint_templates` that progressively reveal more detail.
- Write a `hint.txt` at runtime with the resolved hint content (Flow materializes this after output substitution).

---

## 4) How generators run (local testing)

The canonical runner is:

- `scripts/run_flag_generator.py`

It:
- Reads enabled catalog sources (`data_sources/<catalog>/_state.json`)
- Finds an implementation by `--generator-id`
- Writes `/inputs/config.json` and mounts it into the container
- Mounts the output directory to `/outputs`
- Runs `docker compose run --rm <service>`

### Test a flag-generator locally

```bash
python scripts/run_flag_generator.py \
  --catalog flag_generators \
  --generator-id binary_embed_text \
  --out-dir /tmp/fg_test \
  --config '{"seed":"123","secret":"demo"}'

cat /tmp/fg_test/outputs.json
```

### Test a flag-node-generator locally

```bash
python scripts/run_flag_generator.py \
  --catalog flag_node_generators \
  --generator-id nodegen-py-ssh_flag_node \
  --out-dir /tmp/nodegen_test \
  --config '{"seed":"123","node_name":"node1","flag_prefix":"FLAG"}'

cat /tmp/nodegen_test/docker-compose.yml
cat /tmp/nodegen_test/outputs.json
```

---

## 5) Tutorial: create a new **flag-generator**

Goal: create `my_ssh_creds` that produces `ssh_username` + `ssh_password`.

### Step A — create implementation folder

Create a folder:
- `flag_generators/py_my_ssh_creds/`

Add `generator.py` and `docker-compose.yml`.

Minimal `docker-compose.yml` pattern (matches existing generators):

```yaml
services:
  generator:
    image: python:3.12-slim
    working_dir: /app
    command: ["python", "/app/generator.py"]
    environment:
      INPUTS_DIR: ${INPUTS_DIR}
      OUTPUTS_DIR: ${OUTPUTS_DIR}
    volumes:
      - ./generator.py:/app/generator.py:ro
      - ${INPUTS_DIR}:/inputs:ro
      - ${OUTPUTS_DIR}:/outputs
```

Minimal `generator.py` pattern:

```py
import json
import hashlib
from pathlib import Path


def read_config() -> dict:
    try:
        return json.loads(Path('/inputs/config.json').read_text('utf-8'))
    except Exception:
        return {}


def main():
    cfg = read_config()
    seed = str(cfg.get('seed') or '')
    secret = str(cfg.get('secret') or '')
    if not seed:
        raise SystemExit('Missing seed')
    if not secret:
        raise SystemExit('Missing secret')

    digest = hashlib.sha256(f"{seed}|{secret}|ssh".encode('utf-8')).hexdigest()
    ssh_username = 'user_' + digest[:8]
    ssh_password = 'P@' + digest[8:20]
    flag = 'FLAG{' + digest[20:36] + '}'

    out_dir = Path('/outputs')
    out_dir.mkdir(parents=True, exist_ok=True)

    outputs = {
        'generator_id': 'my_ssh_creds',
        'outputs': {
            'flag': flag,
            'ssh_username': ssh_username,
            'ssh_password': ssh_password,
        },
    }
    (out_dir / 'outputs.json').write_text(json.dumps(outputs, indent=2) + '\n', encoding='utf-8')
    (out_dir / 'hint.txt').write_text(
        f"Next: SSH using {ssh_username} / {ssh_password}\n",
        encoding='utf-8',
    )


if __name__ == '__main__':
    main()
```

### Step B — add a catalog source JSON

Create a new catalog source file:
- `data_sources/flag_generators/2026xxxx-my_generators.json`

Skeleton:

```json
{
  "schema_version": 3,
  "plugin_type": "flag-generator",
  "plugins": [
    {
      "plugin_id": "my_ssh_creds",
      "plugin_type": "flag-generator",
      "version": "1.0",
      "description": "Emits deterministic SSH credentials.",
      "requires": [],
      "produces": [
        {"artifact": "flag"},
        {"artifact": "ssh_username"},
        {"artifact": "ssh_password"}
      ],
      "inputs": {
        "seed": {"type": "text", "required": true},
        "secret": {"type": "text", "required": true, "sensitive": true}
      }
    }
  ],
  "implementations": [
    {
      "plugin_id": "my_ssh_creds",
      "name": "SSH Credentials",
      "language": "python",
      "source": {"type": "local-path", "path": "flag_generators/py_my_ssh_creds"},
      "compose": {"file": "docker-compose.yml", "service": "generator"},
      "hint_templates": [
        "Next: use {{OUTPUT.ssh_username}} / {{OUTPUT.ssh_password}}"
      ]
    }
  ]
}
```

Enable it by adding it to `data_sources/flag_generators/_state.json` as an enabled source.

---

## 6) Tutorial: create a new **flag-node-generator**

Goal: create a per-node compose that runs an SSH server and drops `/flag.txt`.

Pattern:
- Your generator writes `/outputs/docker-compose.yml`.
- Your `outputs.json.outputs.compose_path` points to that file name.

Use the existing reference:
- `flag_node_generators/py_compose_ssh_flag_node/`

---

## 7) Templates

Ready-to-copy templates live under:
- `generator_templates/`

Each template folder includes:
- `generator.py`
- `docker-compose.yml`
- `catalog_source.json` (a full schema v3 catalog file you can drop into `data_sources/...`)

---

## 8) AI-assisted workflow

Use the Web UI page:
- `GET /generator_builder`

It can:
- Generate a **prompt** you can paste into an AI assistant
- Download a **scaffold zip** you can unzip into the repo
- Produce a **catalog JSON snippet** to register the generator

Important: the Generator Builder does **not** automatically install/register the generator into the catalog. You still need to add a catalog source file and enable it.

### Step-by-step: ZIP → repo → catalog

1) Download the scaffold ZIP and unzip it into the repo root.

This creates a folder under one of:
- `flag_generators/<your_folder>/...` (for `flag-generator`)
- `flag_node_generators/<your_folder>/...` (for `flag-node-generator`)

2) Register the generated `catalog_source.json` as a catalog source.

The scaffold includes `catalog_source.json` inside the new folder. You must copy its contents into a catalog source JSON file under:
- `data_sources/flag_generators/*.json` (for `flag-generator`)
- `data_sources/flag_node_generators/*.json` (for `flag-node-generator`)

Example (flag-generators):
- Create: `data_sources/flag_generators/20260112-my_generators.json`
- Paste the full `catalog_source.json` content into it (or merge multiple generators into one source file).

3) Enable the new source in the corresponding `_state.json`.

Update one of:
- `data_sources/flag_generators/_state.json`
- `data_sources/flag_node_generators/_state.json`

Add a `sources[]` entry with `enabled: true` pointing at your new catalog file path.

4) Verify it shows up.

- In the Web UI: open **Flag-Catalog** and confirm the new generator appears.
- Or locally: run `python scripts/run_flag_generator.py ...` using your `--generator-id`.

Tip: ask the AI to keep the generator deterministic from `(seed, secret, node_name)` and always write `outputs.json`.
