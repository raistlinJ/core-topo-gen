from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def test_execute_docker_repair_cleanup_toggles_disabled_in_dockerized_mode() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        '{% if not webui_running_in_docker %}',
        'id="executeAdvFixDockerDaemon"',
        'id="executeAdvDockerCleanupBeforeRun"',
        'id="executeAdvDockerNukeAll"',
        'Docker repair/cleanup options are hidden while Web UI runs in Docker.',
        'fixDockerDaemon: remoteExecution && !WEBUI_RUNNING_IN_DOCKER',
        'dockerCleanupBeforeRun: remoteExecution && !WEBUI_RUNNING_IN_DOCKER',
        'dockerNukeAll: remoteExecution && !WEBUI_RUNNING_IN_DOCKER',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing dockerized-mode UI safety snippets: " + "; ".join(missing)
