from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from jsonschema import Draft7Validator


def load_json(path: str | Path) -> Any:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def validate_against_schema(instance: Any, schema: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate `instance` against a JSON Schema (draft-07).

    Returns: (ok, errors)
    """
    v = Draft7Validator(schema)
    errors = sorted(v.iter_errors(instance), key=lambda e: list(e.path))
    if not errors:
        return True, []

    msgs: List[str] = []
    for e in errors:
        loc = ".".join([str(p) for p in e.path])
        if loc:
            msgs.append(f"{loc}: {e.message}")
        else:
            msgs.append(e.message)
    return False, msgs


def load_generator_plugin_schema(repo_root: str | Path) -> Dict[str, Any]:
    return load_json(Path(repo_root) / "sequencer-examples" / "generators" / "generator_plugin.schema.json")


def load_challenge_instance_schema(repo_root: str | Path) -> Dict[str, Any]:
    return load_json(Path(repo_root) / "sequencer-examples" / "generators" / "challenge_instance.schema.json")


def validate_generator_plugin(plugin_doc: Dict[str, Any], *, schema: Dict[str, Any]) -> Tuple[bool, List[str]]:
    return validate_against_schema(plugin_doc, schema)


def validate_challenge_instance(challenge_doc: Dict[str, Any], *, schema: Dict[str, Any]) -> Tuple[bool, List[str]]:
    return validate_against_schema(challenge_doc, schema)
