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


def test_catalog_schema_v2_requires_hint_template_at_catalog_level():
    # v2 catalog with a generator missing hint_template should be rejected by JSON Schema.
    path = _write_tmp_json({
        "schema_version": 2,
        "generators": [
            {
                "id": "gen.py.missing_hint",
                "name": "Missing Hint",
                "language": "python",
                "source": {"type": "local-path", "path": "./somewhere"},
                "outputs": [{"name": "flag", "type": "flag"}],
            }
        ],
    })
    try:
        ok, note, doc, skipped = app_backend._validate_and_normalize_flag_generator_source_json(path)
        assert ok is False
        assert doc is None
        assert "schema" in (note or "").lower()
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def test_catalog_schema_v1_still_allows_missing_hint_template():
    path = _write_tmp_json({
        "schema_version": 1,
        "generators": [
            {
                "id": "gen.py.v1_no_hint",
                "name": "V1 No Hint",
                "language": "python",
                "source": {"type": "local-path", "path": "./somewhere"},
                "outputs": [{"name": "flag", "type": "flag"}],
            }
        ],
    })
    try:
        ok, note, doc, skipped = app_backend._validate_and_normalize_flag_generator_source_json(path)
        assert ok is True
        assert isinstance(doc, dict)
        assert doc.get("schema_version") == 1
        assert isinstance(doc.get("generators"), list)
        assert len(doc["generators"]) == 1
        assert doc["generators"][0].get("hint_template")
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
