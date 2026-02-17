# AI Prompt Templates for Generator Authoring

This page is copy/paste prompt text you can use with an AI assistant to help author generators.

These prompts assume you start from the **Generator Builder scaffold** (or the examples in [docs/GENERATOR_AUTHORING.md](GENERATOR_AUTHORING.md)).

---

## What you should paste into the AI

For best results, paste:

- Your target **generator type**: `flag-generator` or `flag-node-generator`
- Your intended generator **source id** (the `id` in `manifest.yaml`)
- Your intended artifact **inputs/outputs** (Generator Builder labels these as “Inputs (artifacts)” and “Outputs (artifacts)”; underlying schemas may call them `requires`/`produces`)
- Your `manifest.yaml` (or at least the relevant fields: `id`, `kind`, `runtime`, `inputs`, `artifacts`, `hint_templates`, `injects`)
- The current scaffolded `generator.py` (and optionally your `docker-compose.yml` / README)
- A short description of the generator behavior you want

---

## Non‑negotiable runtime contract

Tell the AI these are strict requirements:

- Read config JSON from `/inputs/config.json`.
- Write `/outputs/outputs.json` with:

```json
{
  "generator_id": "<SOME STABLE STRING>",
  "outputs": {
    "Flag(flag_id)": "FLAG{...}",
    "<other_artifact_keys>": "..."
  }
}
```

- `generator_id` is required by schema and used as provenance.
  - Generator Packs: the Web UI assigns a *new numeric installed ID* at install time, so don’t hardcode the installed ID into your generator; using your source manifest `id` is acceptable.
- Outputs should be **deterministic** for the same inputs.
- `outputs.json.outputs` must always include `Flag(flag_id)` (required by schema).
- `hint.txt` is optional. Prefer `hint_templates` in the catalog; only write `/outputs/hint.txt` if you explicitly need a standalone hint file.
- Treat Flow-synthesized values as **inputs**, not artifacts:
  - Never put `seed`, `secret`, `node_name`, `flag_prefix` into artifact inputs (aka `requires`).
- Input descriptors default to `required: true` when omitted. Set `required: false` for optional runtime inputs.
- Keep shared imports (`json`, `sys`, etc.) at module scope; avoid function-local imports in enclosing scopes that define nested helpers.

If the generator needs to deliver a file/binary to participants:

- Write the file(s) under `/outputs/artifacts/...` (so they appear under `<out_dir>/artifacts/...`).
- Allowlist injected files:
  - Manifest workflow: declare `injects` in `manifest.yaml`.
  - Prefer referencing an **output artifact key** so the allowlist stays stable, e.g. `injects: ["File(path)"]`.
  - `injects` supports resolving output keys via `outputs.json` (e.g. `File(path)` -> `artifacts/my_binary`).

Execution parity requirements (must include in generated code/README):

- The generator must behave the same under UI **Test** and full **Execute** paths.
- Do not rely on package-manager/internet availability for successful generator completion.
- Include both verification commands in README:
  1. local runner test (`scripts/run_flag_generator.py`)
  2. installed-pack execute check (run through Flow/Execute and verify no generator warnings in run log)

Compose + CORE docker-node constraints (important for `flag-node-generator` outputs):

- Compose files attached to CORE docker nodes are treated as templates by CORE (Mako). Avoid docker-compose env interpolation like `${VAR}` / `${VAR:-default}` in the compose you ship unless you know it will be resolved before CORE consumes it.
- Assume containers may run with `network_mode: none` enforced and may have no outbound internet.
- Do not rely on `ports:` for connectivity between CORE nodes. Clients should connect to the server using the server node’s CORE IP.
- Prefer single-port protocols (one TCP port) to reduce segmentation/firewall complexity.

---

## Prompt Template: flag-generator

Paste this, then fill in the placeholders.

```text
You are helping me implement a CORE TopoGen generator.

TYPE: flag-generator
SOURCE_ID: <my_source_id>

Hard requirements (do not violate):
- Read /inputs/config.json (JSON).
- Write /outputs/outputs.json with:
  {
    "generator_id": "<SOME STABLE STRING>",
    "outputs": {
      "Flag(flag_id)": "FLAG{...}",
      "...": "..."
    }
  }
- generator_id requirements:
  - Do not assume the installed numeric ID is stable; using SOURCE_ID is acceptable.
- Do NOT write /outputs/hint.txt unless I explicitly ask; prefer hint_templates in the catalog.
- Deterministic outputs: same (seed, secret, flag_prefix) => same outputs.
- Inputs (NOT artifacts): seed (required), secret (required), flag_prefix (optional).

If this generator outputs a file/binary:
- Write it under /outputs/artifacts/<name>
- Put a path to it in outputs.json.outputs (example key: File(path) => artifacts/<name>)

Catalog intent:
- inputs artifacts: <list artifacts or '(none)'>
- outputs artifacts: <list artifacts; must include 'Flag(flag_id)'>

Artifact input strictness:
- Default to optional inputs.
- Mark any input as required only if the generator truly cannot run without it.
- For artifact inputs, put optional ones in `artifacts.optional_requires` and required ones in `artifacts.requires`.

Task:
- Modify ONLY generator.py to implement this behavior: <describe behavior>.
- Use only the Python standard library.
- Keep error messages clear when required inputs are missing.
- Keep imports at module scope; do not add function-local `import json`/`import sys` in scopes with nested helpers.

Here is my current scaffolded generator.py:

<PASTE generator.py HERE>

Output:
- Reply with ONLY the full updated generator.py content.
```

---

## Prompt Template: flag-node-generator

Paste this, then fill in the placeholders.

```text
You are helping me implement a CORE TopoGen generator.

TYPE: flag-node-generator
SOURCE_ID: <my_source_id>

Hard requirements (do not violate):
- Read /inputs/config.json (JSON).
- Write a per-node docker compose file to /outputs/docker-compose.yml.
- Write /outputs/outputs.json with:
  {
    "generator_id": "<SOME STABLE STRING>",
    "outputs": {
      "File(path)": "docker-compose.yml",
      "Flag(flag_id)": "FLAG{...}",
      "...": "..."
    }
  }
- generator_id requirements:
  - Do not assume the installed numeric ID is stable; using SOURCE_ID is acceptable.
- Deterministic outputs: same (seed, node_name, flag_prefix) => same outputs and compose.
- Inputs (NOT artifacts): seed (required), node_name (required), flag_prefix (optional).

CORE docker-node constraints:
- Avoid `${...}` patterns in the emitted docker-compose.yml (CORE treats compose as a template and `${...}` can be interpreted as Mako).
- Do not rely on `ports:` for in-CORE reachability; clients in CORE should connect to the node’s CORE IP.
- Assume `network_mode: none` may be enforced; do not assume default Docker networking or internet access.

Catalog intent:
- inputs artifacts: <list artifacts or '(none)'>
- outputs artifacts: <list artifacts; typically includes 'File(path)' and 'Flag(flag_id)'>

Artifact input strictness:
- Default to optional inputs.
- Mark any input as required only if the generator truly cannot run without it.

Task:
- Modify ONLY generator.py to implement this behavior: <describe behavior>.
- The docker-compose.yml you write should define the node service(s) needed for the challenge.
- Use only the Python standard library.
- Keep imports at module scope; do not add function-local `import json`/`import sys` in scopes with nested helpers.

Here is my current scaffolded generator.py:

<PASTE generator.py HERE>

Output:
- Reply with ONLY the full updated generator.py content.
```

---

## Optional: prompt add-ons (use when needed)

### Include README updates

If you want the AI to update the README too:

```text
Also update README.md to explain:
- What artifact inputs/outputs it uses
- How it is tested locally using scripts/run_flag_generator.py
- Any environment variables or assumptions
Output BOTH files: generator.py then README.md (clearly separated).
```

### Make “outputs” align to the catalog

If you already created an Outputs (artifacts) list in the Generator Builder UI:

```text
Important: The keys in outputs.json.outputs MUST exactly match my intended outputs list.
If you add new outputs, tell me what catalog changes I should make.
```

---

## Notes / common failure modes

- Don’t let the AI introduce third-party deps unless you explicitly want that.
- Ensure `outputs.json` is always written even on “success with minimal outputs”.
- Always include `Flag(flag_id)` in produced outputs.
- Keep file paths exactly `/inputs/config.json` and `/outputs/...`.
- Prefer fact-ontology keys (e.g., `Credential(user,password)`, `Knowledge(ip)`, `File(path)`) over ad-hoc keys (e.g., `user`, `ip`).
