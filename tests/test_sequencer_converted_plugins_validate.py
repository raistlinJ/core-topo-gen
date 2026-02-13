from pathlib import Path

def test_converted_generator_plugins_validate_against_baseline_contract():
    repo_root = Path(__file__).resolve().parents[1]

    plugins_dir = repo_root / "sequencer-examples" / "generators" / "plugins"
    assert plugins_dir.is_dir()

    plugin_files = sorted([p for p in plugins_dir.glob("*.json") if p.name != "_catalog_mapping.json"])
    assert plugin_files, "Expected converted plugin docs under sequencer-examples/generators/plugins"

    for p in plugin_files:
        doc = __import__("json").loads(p.read_text(encoding="utf-8"))
        assert isinstance(doc, dict), f"{p.name} must be a JSON object"
        assert str(doc.get("plugin_id") or "").strip(), f"{p.name} missing plugin_id"
        assert str(doc.get("plugin_type") or "").strip() in {"flag-generator", "flag-node-generator"}, f"{p.name} invalid plugin_type"
        assert str(doc.get("version") or "").strip(), f"{p.name} missing version"
        assert isinstance(doc.get("requires"), list), f"{p.name} requires must be a list"
        assert isinstance(doc.get("produces"), list), f"{p.name} produces must be a list"
        assert isinstance(doc.get("inputs"), dict), f"{p.name} inputs must be an object"
