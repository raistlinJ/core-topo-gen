# AI Prompt Templates for Generator Authoring

This page is copy/paste prompt text you can use with an AI assistant to help author generators.

These prompts assume you start from the **Generator Builder scaffold** (or the examples in [docs/GENERATOR_AUTHORING.md](GENERATOR_AUTHORING.md)).

---

## What you should paste into the AI

For best results, paste:

- Your target **generator type**: `flag-generator` or `flag-node-generator`
- Your intended `plugin_id`
- Your intended `requires` and `produces` artifacts
- The current scaffolded `generator.py` (and optionally your `docker-compose.yml` / README)
- A short description of the generator behavior you want

---

## Non‑negotiable runtime contract

Tell the AI these are strict requirements:

- Read config JSON from `/inputs/config.json`.
- Write `/outputs/outputs.json` with:

```json
{
  "generator_id": "<PLUGIN_ID>",
  "outputs": {
    "flag": "FLAG{...}",
    "<other_artifact_keys>": "..."
  }
}
```

- `generator_id` **must exactly match** the catalog’s `plugin_id`.
- Outputs should be **deterministic** for the same inputs.
- `hint.txt` is optional. Prefer `hint_templates` in the catalog; only write `/outputs/hint.txt` if you explicitly need a standalone hint file.
- Treat Flow-synthesized values as **inputs**, not artifacts:
  - Never put `seed`, `secret`, `node_name`, `flag_prefix` into `requires`.

If the generator needs to deliver a file/binary to participants:

- Write the file(s) under `/outputs/artifacts/...` (so they appear under `<out_dir>/artifacts/...`).
- In the catalog implementation, declare `inject_files` as an allowlist.
  - Prefer referencing an **output artifact key** so the allowlist stays stable, e.g. `inject_files: ["filesystem.file"]`.
  - `inject_files` supports resolving output keys via `outputs.json` (e.g. `filesystem.file` -> `artifacts/my_binary`).

---

## Prompt Template: flag-generator

Paste this, then fill in the placeholders.

```text
You are helping me implement a CORE TopoGen generator.

TYPE: flag-generator
PLUGIN_ID: <my.plugin_id>

Hard requirements (do not violate):
- Read /inputs/config.json (JSON).
- Write /outputs/outputs.json with:
  {
    "generator_id": "<PLUGIN_ID>",
    "outputs": {
      "flag": "FLAG{...}",
      "...": "..."
    }
  }
- generator_id MUST exactly match PLUGIN_ID.
- Do NOT write /outputs/hint.txt unless I explicitly ask; prefer hint_templates in the catalog.
- Deterministic outputs: same (seed, secret, flag_prefix) => same outputs.
- Inputs (NOT artifacts): seed (required), secret (required), flag_prefix (optional).

If this generator outputs a file/binary:
- Write it under /outputs/artifacts/<name>
- Put a path to it in outputs.json.outputs (example key: filesystem.file => artifacts/<name>)

Catalog intent:
- requires artifacts: <list artifacts or '(none)'>
- produces artifacts: <list artifacts; must include 'flag'>

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
PLUGIN_ID: <my.plugin_id>

Hard requirements (do not violate):
- Read /inputs/config.json (JSON).
- Write a per-node docker compose file to /outputs/docker-compose.yml.
- Write /outputs/outputs.json with:
  {
    "generator_id": "<PLUGIN_ID>",
    "outputs": {
      "compose_path": "docker-compose.yml",
      "flag": "FLAG{...}",
      "...": "..."
    }
  }
- generator_id MUST exactly match PLUGIN_ID.
- Deterministic outputs: same (seed, node_name, flag_prefix) => same outputs and compose.
- Inputs (NOT artifacts): seed (required), node_name (required), flag_prefix (optional).

Catalog intent:
- requires artifacts: <list artifacts or '(none)'>
- produces artifacts: <list artifacts; typically includes 'compose_path' and 'flag'>

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
- What artifacts it requires/produces
- How it is tested locally using scripts/run_flag_generator.py
- Any environment variables or assumptions
Output BOTH files: generator.py then README.md (clearly separated).
```

### Make “produces” align to the catalog

If you already created a `produces` list in the Generator Builder UI:

```text
Important: The keys in outputs.json.outputs MUST exactly match my catalog produces list.
If you add new outputs, tell me what catalog changes I should make.
```

---

## Notes / common failure modes

- Don’t let the AI introduce third-party deps unless you explicitly want that.
- Ensure `outputs.json` is always written even on “success with minimal outputs”.
- Always include `flag` in produced outputs.
- Keep file paths exactly `/inputs/config.json` and `/outputs/...`.
- Prefer namespaced artifact keys (e.g., `ssh.username`, `network.ip`, `filesystem.file`) over ad-hoc keys (e.g., `user`, `ip`).
