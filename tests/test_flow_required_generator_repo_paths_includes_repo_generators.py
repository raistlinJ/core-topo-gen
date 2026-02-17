import os

from webapp.app_backend import _flow_required_generator_repo_paths


def test_flow_required_generator_repo_paths_includes_repo_flag_generator():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    # Repo-based sample generator lives at flag_generators/py_sample_binary_embed_text
    required = _flow_required_generator_repo_paths(
        repo_root=repo_root,
        flag_assignments=[
            {
                "flag_id": "flag_1",
                "generator_id": "binary_embed_text",
            }
        ]
    )

    required_norm = {p.replace("\\", "/") for p in required}
    assert "flag_generators/py_sample_binary_embed_text" in required_norm

    # Sanity: it should be a directory in the repo checkout.
    assert os.path.isdir(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "flag_generators",
            "py_sample_binary_embed_text",
        )
    )
