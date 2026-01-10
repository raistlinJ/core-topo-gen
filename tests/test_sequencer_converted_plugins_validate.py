from pathlib import Path

from core_topo_gen.sequencer.schemas import load_generator_plugin_schema, validate_against_schema


def test_converted_generator_plugins_validate_against_plugin_schema():
    repo_root = Path(__file__).resolve().parents[1]
    schema = load_generator_plugin_schema(repo_root)

    plugins_dir = repo_root / "sequencer-examples" / "generators" / "plugins"
    assert plugins_dir.is_dir()

    plugin_files = sorted([p for p in plugins_dir.glob("*.json") if p.name != "_catalog_mapping.json"])
    assert plugin_files, "Expected converted plugin docs under sequencer-examples/generators/plugins"

    for p in plugin_files:
        doc = __import__("json").loads(p.read_text(encoding="utf-8"))
        ok, errors = validate_against_schema(doc, schema)
        assert ok, f"{p.name} failed schema validation: {errors}"
