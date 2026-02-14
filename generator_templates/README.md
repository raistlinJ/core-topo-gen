# Generator Templates

These templates are starter skeletons for building new generators that integrate with the Flow/Flag Sequencing system.

Folders:
- `flag-generator-python-compose/`: runs a generator inside a container and writes `outputs.json`.
- `flag-node-generator-python-compose/`: generates a per-node `docker-compose.yml` and writes `outputs.json`.

How to use:
1. Copy a template folder into the appropriate repo directory and rename it:
	- `flag_generators/<your_generator_dir>/...` or
	- `flag_node_generators/<your_generator_dir>/...`
2. Edit `generator.py` and `docker-compose.yml`.
3. Add a `manifest.yaml` in the generator directory (required by the Web UI / installed workflow).
4. (Option A) Pack install via Web UI:
	- Create a ZIP containing `flag_generators/<your_generator_dir>/...` and/or `flag_node_generators/<your_generator_dir>/...`.
	- Upload/import it from the Flag Catalog page (Generator Packs).
5. (Option B) Repo-local development:
	- Keep the generator in `flag_generators/` or `flag_node_generators/` and run it directly with the runner.
6. Test with `python scripts/run_flag_generator.py ...`.

See [docs/GENERATOR_AUTHORING.md](docs/GENERATOR_AUTHORING.md) for a full tutorial.

## Parity checklist (Test vs Execute)

When adapting templates, apply these defaults so UI Test and full Execute behave the same:

- Keep imports (`json`, `sys`, etc.) at module scope.
- Do not depend on live internet/package-manager success for core generator output.
- Always write `outputs.json` with valid keys before exiting successfully.
- Ensure `injects` entries map to real generated files.
- Verify once as repo-local test and once as installed pack execute path.
