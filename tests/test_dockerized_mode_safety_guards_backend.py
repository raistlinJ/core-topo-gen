from pathlib import Path


BACKEND_PATH = Path(__file__).resolve().parent.parent / "webapp" / "app_backend.py"


def test_dockerized_mode_backend_ignores_docker_repair_cleanup_toggles() -> None:
    text = BACKEND_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "if _webui_running_in_docker() and (docker_cleanup_before_run or docker_remove_all_containers):",
        "if _webui_running_in_docker() and (adv_fix_docker_daemon or docker_cleanup_before_run or docker_remove_all_containers):",
        "Ignoring docker cleanup/restart toggles because web UI is running in Docker",
        "Ignoring docker repair/cleanup toggles because web UI is running in Docker",
        "forced docker repair/cleanup toggles off (web UI in Docker)",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing dockerized-mode backend safety snippets: " + "; ".join(missing)
