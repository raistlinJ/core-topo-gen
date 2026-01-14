from scripts.run_flag_generator import expand_inject_files


def test_expand_inject_files_substitutes_env_vars():
    env = {"CHALLENGE": "challenge_node_1"}
    assert expand_inject_files(["${CHALLENGE}", "hint.txt"], env) == ["challenge_node_1", "hint.txt"]
