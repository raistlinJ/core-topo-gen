# Generator Templates

These templates are starter skeletons for building new generators that integrate with the Flow/Flag Sequencing system.

Folders:
- `flag-generator-python-compose/`: runs a generator inside a container and writes `outputs.json`.
- `flag-node-generator-python-compose/`: generates a per-node `docker-compose.yml` and writes `outputs.json`.

How to use:
1. Copy a template folder and rename it.
2. Edit `generator.py` and `docker-compose.yml`.
3. Add or update a catalog source JSON under `data_sources/flag_generators/` or `data_sources/flag_node_generators/`.
4. Enable the catalog source in the corresponding `_state.json`.
5. Test with `python scripts/run_flag_generator.py ...`.

See [docs/GENERATOR_AUTHORING.md](docs/GENERATOR_AUTHORING.md) for a full tutorial.
