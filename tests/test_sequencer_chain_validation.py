from pathlib import Path

from core_topo_gen.sequencer.chain import load_chain_yaml, validate_chain_doc, validate_linear_chain


def test_sample_chain_yaml_validates_and_is_solvable():
    repo_root = Path(__file__).resolve().parents[1]
    sample = repo_root / "sequencer-examples" / "sample_chain_reverse_nfs_ssh.yaml"

    doc = load_chain_yaml(sample)
    ok, errors, norm = validate_chain_doc(doc)
    assert ok, errors

    ok2, errors2 = validate_linear_chain(norm)
    assert ok2, errors2


def test_chain_requires_must_be_produced_before_use():
    doc = {
        "challenges": [
            {
                "challenge_id": "step2",
                "kind": "flag-generator",
                "requires": [{"artifact": "Knowledge(ip)"}],
                "produces": [{"name": "creds", "artifact": "Credential(user, password)"}],
                "generator": {"plugin": "x"},
            },
            {
                "challenge_id": "step1",
                "kind": "flag-generator",
                "produces": [{"name": "ip", "artifact": "Knowledge(ip)"}],
                "generator": {"plugin": "y"},
            },
        ]
    }

    ok, errors, norm = validate_chain_doc(doc)
    assert ok, errors

    ok2, errors2 = validate_linear_chain(norm)
    assert not ok2
    assert any("requires Knowledge(ip)" in e for e in errors2)


def test_chain_requires_with_source_must_match_that_producer():
    doc = {
        "challenges": [
            {
                "challenge_id": "a",
                "kind": "flag-generator",
                "produces": [{"name": "x", "artifact": "Knowledge(ip)"}],
                "generator": {"plugin": "x"},
            },
            {
                "challenge_id": "b",
                "kind": "flag-generator",
                "requires": [{"artifact": "Knowledge(ip)", "source": "c"}],
                "generator": {"plugin": "y"},
            },
        ]
    }

    ok, errors, norm = validate_chain_doc(doc)
    assert ok, errors

    ok2, errors2 = validate_linear_chain(norm)
    assert not ok2
    assert any("has not run yet" in e for e in errors2)
