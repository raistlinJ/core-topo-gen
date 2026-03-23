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


def test_core_vm_modal_hides_fix_docker_toggle_in_dockerized_mode() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        '{% if not webui_running_in_docker %}',
        'id="coreAdvFixDockerDaemon"',
        "if (WEBUI_RUNNING_IN_DOCKER && scen.hitl.core.adv_fix_docker_daemon !== false) {",
        'scen.hitl.core.adv_fix_docker_daemon = false;',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing CORE VM dockerized-mode safety snippets: " + "; ".join(missing)

    forbidden_snippets = [
        'Docker daemon repair controls are hidden while Web UI runs in Docker.',
    ]

    present = [snippet for snippet in forbidden_snippets if snippet in text]
    assert not present, "Unexpected CORE VM docker-mode placeholder text still present: " + "; ".join(present)
