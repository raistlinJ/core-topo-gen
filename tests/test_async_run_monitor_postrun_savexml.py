from __future__ import annotations

from flask import Flask

from webapp.routes import async_run_monitor


def test_async_run_status_reapplies_core_secret_before_postrun_save_xml(tmp_path):
    app = Flask(__name__)

    xml_path = tmp_path / "scenario.xml"
    xml_path.write_text("<Scenarios><Scenario name=\"NewScenario1\" /></Scenarios>\n", encoding="utf-8")

    log_path = tmp_path / "run.log"
    log_path.write_text("session id: 1\n", encoding="utf-8")

    captured = {}

    def _fake_save_xml(cfg, out_dir, session_id=None):
        captured["cfg"] = dict(cfg)
        return None

    class _Proc:
        def poll(self):
            return 0

    runs_store = {
        "run-1": {
            "proc": _Proc(),
            "returncode": 0,
            "done": True,
            "history_added": False,
            "log_path": str(log_path),
            "xml_path": str(xml_path),
            "scenario_name": "NewScenario1",
            "core_cfg": {
                "host": "localhost",
                "port": 50051,
                "ssh_host": "localhost",
                "ssh_port": 22,
                "ssh_username": "core",
                "ssh_password": "pw",
                "core_secret_id": "secret-1",
            },
        }
    }

    async_run_monitor.register(
        app,
        runs_store=runs_store,
        maybe_copy_flow_artifacts_into_containers=lambda *args, **kwargs: None,
        sync_remote_artifacts=lambda meta: None,
        scenario_names_from_xml=lambda path: ["NewScenario1"],
        extract_report_path_from_text=lambda text: None,
        find_latest_report_path=lambda: None,
        extract_summary_path_from_text=lambda text: None,
        derive_summary_from_report=lambda report_path: None,
        find_latest_summary_path=lambda: None,
        outputs_dir=lambda: str(tmp_path),
        extract_session_id_from_text=lambda text: "1",
        record_session_mapping=lambda *args, **kwargs: None,
        write_remote_session_scenario_meta=lambda *args, **kwargs: None,
        normalize_core_config=lambda cfg, **kwargs: cfg,
        load_run_history=lambda: [],
        select_core_config_for_page=lambda *args, **kwargs: {},
        merge_core_configs=lambda left, right, **kwargs: dict(left or {}, **(right or {})),
        apply_core_secret_to_config=lambda cfg, scenario_norm: {
            **cfg,
            "host": "10.10.10.20",
            "ssh_host": "10.10.10.20",
        },
        grpc_save_current_session_xml_with_config=_fake_save_xml,
        append_async_run_log_line=lambda meta, line: None,
        append_session_scenario_discrepancies=lambda *args, **kwargs: None,
        validate_session_nodes_and_injects=lambda *args, **kwargs: {"ok": True},
        coerce_bool=lambda value: bool(value),
        extract_async_error_from_text=lambda text: None,
        persist_execute_validation_artifacts=lambda *args, **kwargs: None,
        write_single_scenario_xml=lambda *args, **kwargs: None,
        build_full_scenario_archive=lambda *args, **kwargs: None,
        append_run_history=lambda entry: True,
        local_timestamp_display=lambda: "2026-03-20T00:00:00Z",
        close_async_run_tunnel=lambda meta: None,
        cleanup_remote_workspace=lambda meta: None,
        extract_docker_conflicts_from_text=lambda text: [],
        build_execute_error_logs=lambda *args, **kwargs: [],
        normalize_core_config_public=lambda cfg: cfg,
        sse_marker_prefix="SSEMARK",
        download_report_endpoint="download_report",
    )

    client = app.test_client()
    resp = client.get("/run_status/run-1")

    assert resp.status_code == 200
    assert captured["cfg"]["host"] == "10.10.10.20"
    assert captured["cfg"]["ssh_host"] == "10.10.10.20"