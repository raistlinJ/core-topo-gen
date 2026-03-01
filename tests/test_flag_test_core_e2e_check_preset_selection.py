from __future__ import annotations

from scripts import flag_test_core_e2e_check as smoke


def test_preset_preferred_ids_sample() -> None:
    assert smoke._preset_preferred_ids("sample", kind="flag-generator") == [
        "binary_embed_text",
        "textfile_username_password",
    ]
    assert smoke._preset_preferred_ids("sample", kind="flag-node-generator") == [
        "nfs_sensitive_file",
    ]


def test_ordered_candidates_prioritizes_preset_ids_when_available() -> None:
    available = ["textfile_username_password", "other_gen", "binary_embed_text"]
    preferred = ["binary_embed_text", "nfs_sensitive_file", "textfile_username_password"]

    ordered = smoke._ordered_candidates(available, preferred)

    assert ordered == ["binary_embed_text", "textfile_username_password", "other_gen"]


def test_ordered_candidates_falls_back_to_available_when_preset_missing() -> None:
    available = ["gen_a", "gen_b"]
    preferred = ["missing_1", "missing_2"]

    ordered = smoke._ordered_candidates(available, preferred)

    assert ordered == ["gen_a", "gen_b"]
