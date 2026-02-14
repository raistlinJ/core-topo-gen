from pathlib import Path


TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def test_build_run_form_data_includes_advanced_flags() -> None:
    text = TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_lines = [
        "if (adv && adv.fixDockerDaemon) form.append('adv_fix_docker_daemon', '1');",
        "if (adv && adv.runCoreCleanup) form.append('adv_run_core_cleanup', '1');",
        "if (adv && adv.checkCoreVersion) form.append('adv_check_core_version', '1');",
        "if (adv && adv.restartCoreDaemon) form.append('adv_restart_core_daemon', '1');",
        "if (adv && adv.startCoreDaemon) form.append('adv_start_core_daemon', '1');",
        "if (adv && adv.autoKillSessions) form.append('adv_auto_kill_sessions', '1');",
    ]

    missing = [line for line in expected_lines if line not in text]
    assert not missing, "Missing execute advanced FormData mapping lines: " + "; ".join(missing)


def test_execute_summary_uses_validation_unavailable_details() -> None:
    text = TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const unavailableItems = Array.isArray(summary.validation_unavailable_details)",
        "summary.validation_unavailable_details.filter(Boolean)",
        "renderExecuteSummaryItem(",
        "unavailableItems",
        "unavailableItems.forEach((item) => {",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing validation_unavailable details summary wiring: " + "; ".join(missing)


def test_execute_summary_includes_flow_live_paths() -> None:
    text = TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const flowLivePathsMissing = Array.isArray(summary.flow_live_paths_missing)",
        "const flowLivePathsChecked = Number.isFinite(Number(summary.flow_live_paths_checked))",
        "const flowLivePathsMissingCount = Number.isFinite(Number(summary.flow_live_paths_missing_count))",
        "'Flow live paths present',",
        "flowLivePathsMissingCount > 0",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing flow live-path execute summary wiring: " + "; ".join(missing)
