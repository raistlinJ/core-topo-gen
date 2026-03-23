from pathlib import Path


ROUTES_PATH = Path(__file__).resolve().parent.parent / "webapp" / "routes" / "app_entry_routes.py"
BACKEND_PATH = Path(__file__).resolve().parent.parent / "webapp" / "app_backend.py"


def test_dockerized_mode_backend_ignores_docker_repair_cleanup_toggles() -> None:
    routes_text = ROUTES_PATH.read_text(encoding="utf-8", errors="ignore")
    backend_text = BACKEND_PATH.read_text(encoding="utf-8", errors="ignore")

    route_expected_snippets = [
        "if backend._webui_running_in_docker() and (docker_cleanup_before_run or docker_remove_all_containers):",
        "if backend._webui_running_in_docker() and (adv_fix_docker_daemon or docker_cleanup_before_run or docker_remove_all_containers):",
        "Ignoring docker cleanup/restart toggles because web UI is running in Docker",
        "Ignoring docker repair/cleanup toggles because web UI is running in Docker",
    ]
    backend_expected_snippets = [
        "forced docker repair/cleanup toggles off (web UI in Docker)",
    ]

    missing_routes = [snippet for snippet in route_expected_snippets if snippet not in routes_text]
    missing_backend = [snippet for snippet in backend_expected_snippets if snippet not in backend_text]
    missing = missing_routes + missing_backend
    assert not missing, "Missing dockerized-mode backend safety snippets: " + "; ".join(missing)
