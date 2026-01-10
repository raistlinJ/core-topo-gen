import json
import os
import tempfile

from webapp import app_backend


def _write_tmp_json(doc: dict) -> str:
    fd, path = tempfile.mkstemp(suffix='-flag_generators.json')
    os.close(fd)
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(doc, fh)
    return path


def test_catalog_schema_v3_rejects_missing_plugins():
    path = _write_tmp_json({
        "schema_version": 3,
        "plugin_type": "flag-generator",
        "implementations": [],
    })
    try:
        ok, note, doc, skipped = app_backend._validate_and_normalize_flag_generator_source_json(path)
        assert ok is False
        assert doc is None
        assert "schema" in (note or "").lower() or "missing" in (note or "").lower()
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def test_catalog_schema_v3_allows_missing_hint_template_and_defaults_it():
    path = _write_tmp_json({
        "schema_version": 3,
        "plugin_type": "flag-generator",
        "plugins": [
            {
                "plugin_id": "gen-py-test",
                "plugin_type": "flag-generator",
                "version": "1.0",
                "requires": ["seed"],
                "produces": [{"artifact": "flag"}],
                "inputs": {"seed": {"type": "string", "required": True}},
            }
        ],
        "implementations": [
            {
                "plugin_id": "gen-py-test",
                "name": "Test",
                "language": "python",
                "source": {"type": "local-path", "path": "./somewhere", "entry": "generator.py"},
                "compose": {"file": "docker-compose.yml", "service": "generator"},
            }
        ],
    })
    try:
        ok, note, doc, skipped = app_backend._validate_and_normalize_flag_generator_source_json(path)
        assert ok is True
        assert isinstance(doc, dict)
        assert doc.get("schema_version") == 3
        assert doc.get("plugin_type") == "flag-generator"
        assert isinstance(doc.get("plugins"), list)
        assert isinstance(doc.get("implementations"), list)
        assert len(doc["implementations"]) == 1
        assert doc["implementations"][0].get("hint_template")
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
