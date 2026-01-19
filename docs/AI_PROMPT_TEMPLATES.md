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
  - If you are using a legacy v3 JSON catalog, set `generator_id` to the catalog `plugin_id`.
  - If you are using `manifest.yaml` / Generator Packs, the Web UI assigns a *new numeric installed ID* at install time, so don’t hardcode the installed ID into your generator; using your source manifest `id` is acceptable.
- Outputs should be **deterministic** for the same inputs.
- `outputs.json.outputs` must always include `Flag(flag_id)` (required by schema).
- `hint.txt` is optional. Prefer `hint_templates` in the catalog; only write `/outputs/hint.txt` if you explicitly need a standalone hint file.
- Treat Flow-synthesized values as **inputs**, not artifacts:
  - Never put `seed`, `secret`, `node_name`, `flag_prefix` into artifact inputs (aka `requires`).

If the generator needs to deliver a file/binary to participants:

- Write the file(s) under `/outputs/artifacts/...` (so they appear under `<out_dir>/artifacts/...`).
- Allowlist injected files:
  - Manifest workflow: declare `injects` in `manifest.yaml`.
  - Legacy v3 JSON workflow: declare `inject_files` in the implementation.
  - Prefer referencing an **output artifact key** so the allowlist stays stable, e.g. `inject_files: ["File(path)"]`.
  - `inject_files` supports resolving output keys via `outputs.json` (e.g. `File(path)` -> `artifacts/my_binary`).

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
  - If using legacy v3 JSON catalogs, set generator_id == plugin_id.
  - If using manifest/packs, do not assume the installed numeric ID is stable; using SOURCE_ID is acceptable.
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

Task:
- Modify ONLY generator.py to implement this behavior: <describe behavior>.
- Use only the Python standard library.
- Keep error messages clear when required inputs are missing.

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
  - If using legacy v3 JSON catalogs, set generator_id == plugin_id.
  - If using manifest/packs, do not assume the installed numeric ID is stable; using SOURCE_ID is acceptable.
- Deterministic outputs: same (seed, node_name, flag_prefix) => same outputs and compose.
- Inputs (NOT artifacts): seed (required), node_name (required), flag_prefix (optional).

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
