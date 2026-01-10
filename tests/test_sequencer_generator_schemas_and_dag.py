from pathlib import Path

from core_topo_gen.sequencer.dag import build_dag
from core_topo_gen.sequencer.schemas import (
    load_challenge_instance_schema,
    load_generator_plugin_schema,
    validate_against_schema,
)


def test_generator_plugin_schema_accepts_minimal_valid_plugin():
    repo_root = Path(__file__).resolve().parents[1]
    schema = load_generator_plugin_schema(repo_root)

    plugin = {
        "plugin_id": "binary_embed_text",
        "plugin_type": "flag-generator",
        "version": "1.0",
        "requires": [],
        "produces": [{"artifact": "network.ip"}],
        "inputs": {
            "difficulty": {"type": "string", "required": False, "values": ["easy", "medium", "hard"]}
        },
    }

    ok, errors = validate_against_schema(plugin, schema)
    assert ok, errors


def test_challenge_instance_schema_accepts_minimal_valid_instance():
    repo_root = Path(__file__).resolve().parents[1]
    schema = load_challenge_instance_schema(repo_root)

    inst = {
        "challenge_id": "reverse_binary_for_ip",
        "plugin": "binary_embed_text",
        "requires": [],
        "overrides": {},
        "points": 100,
    }

    ok, errors = validate_against_schema(inst, schema)
    assert ok, errors


def test_dag_builds_and_toposorts_sample_like_chain():
    plugins = {
        "binary_embed_text": {
            "plugin_id": "binary_embed_text",
            "plugin_type": "flag-generator",
            "version": "1.0",
            "requires": [],
            "produces": [{"artifact": "network.ip"}],
            "inputs": {},
        },
        "nfs_sensitive_file": {
            "plugin_id": "nfs_sensitive_file",
            "plugin_type": "flag-node-generator",
            "version": "1.0",
            "requires": ["network.ip"],
            "produces": [{"artifact": "credential.pair"}],
            "inputs": {},
        },
        "textfile_username_password": {
            "plugin_id": "textfile_username_password",
            "plugin_type": "flag-generator",
            "version": "1.0",
            "requires": ["credential.pair"],
            "produces": [{"artifact": "filesystem.file"}],
            "inputs": {},
        },
    }

    challenges = [
        {"challenge_id": "reverse_binary_for_ip", "plugin": "binary_embed_text"},
        {"challenge_id": "access_nfs_share", "plugin": "nfs_sensitive_file"},
        {"challenge_id": "ssh_password_dump", "plugin": "textfile_username_password"},
    ]

    res, errors = build_dag(challenges, plugins_by_id=plugins)
    assert res is not None, errors

    assert list(res.order) == [
        "reverse_binary_for_ip",
        "access_nfs_share",
        "ssh_password_dump",
    ]


def test_dag_respects_explicit_source_binding():
    plugins = {
        "p1": {
            "plugin_id": "p1",
            "plugin_type": "flag-generator",
            "version": "1.0",
            "requires": [],
            "produces": [{"artifact": "network.ip"}],
            "inputs": {},
        },
        "p2": {
            "plugin_id": "p2",
            "plugin_type": "flag-generator",
            "version": "1.0",
            "requires": [],
            "produces": [{"artifact": "network.ip"}],
            "inputs": {},
        },
        "consumer": {
            "plugin_id": "consumer",
            "plugin_type": "flag-generator",
            "version": "1.0",
            "requires": ["network.ip"],
            "produces": [{"artifact": "filesystem.file"}],
            "inputs": {},
        },
    }

    challenges = [
        {"challenge_id": "a", "plugin": "p1"},
        {"challenge_id": "b", "plugin": "p2"},
        {
            "challenge_id": "c",
            "plugin": "consumer",
            "requires": [{"artifact": "network.ip", "source": "b"}],
        },
    ]

    res, errors = build_dag(challenges, plugins_by_id=plugins)
    assert res is not None, errors

    # Ensure there's an edge b -> c for network.ip.
    assert any(e.src == "b" and e.dst == "c" and e.artifact == "network.ip" for e in res.edges)


def test_dag_rejects_instance_requires_not_declared_by_plugin():
    plugins = {
        "consumer": {
            "plugin_id": "consumer",
            "plugin_type": "flag-generator",
            "version": "1.0",
            "requires": [],
            "produces": [{"artifact": "filesystem.file"}],
            "inputs": {},
        }
    }

    challenges = [
        {
            "challenge_id": "c",
            "plugin": "consumer",
            "requires": [{"artifact": "network.ip"}],
        }
    ]

    res, errors = build_dag(challenges, plugins_by_id=plugins)
    assert res is None
    assert any("instance requires artifacts not declared by plugin" in e for e in errors)


def test_dag_detects_cycle():
    plugins = {
        "a": {
            "plugin_id": "a",
            "plugin_type": "flag-generator",
            "version": "1.0",
            "requires": ["b.out"],
            "produces": [{"artifact": "a.out"}],
            "inputs": {},
        },
        "b": {
            "plugin_id": "b",
            "plugin_type": "flag-generator",
            "version": "1.0",
            "requires": ["a.out"],
            "produces": [{"artifact": "b.out"}],
            "inputs": {},
        },
    }

    challenges = [
        {"challenge_id": "ca", "plugin": "a"},
        {"challenge_id": "cb", "plugin": "b"},
    ]

    res, errors = build_dag(challenges, plugins_by_id=plugins)
    assert res is None
    assert any("cycle detected" in e for e in errors)


def test_dag_rejects_required_artifact_with_no_producer():
    plugins = {
        "consumer": {
            "plugin_id": "consumer",
            "plugin_type": "flag-generator",
            "version": "1.0",
            "requires": ["network.ip"],
            "produces": [{"artifact": "filesystem.file"}],
            "inputs": {},
        }
    }

    challenges = [{"challenge_id": "c", "plugin": "consumer"}]

    res, errors = build_dag(challenges, plugins_by_id=plugins)
    assert res is None
    assert any("no plugin produces it" in e for e in errors)


def test_dag_rejects_unknown_plugin_id():
    plugins = {}
    challenges = [{"challenge_id": "c", "plugin": "does_not_exist"}]

    res, errors = build_dag(challenges, plugins_by_id=plugins)
    assert res is None
    assert any("unknown plugin" in e for e in errors)
