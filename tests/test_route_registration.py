from flask import Flask

from webapp.routes import ai_provider
from webapp.routes import admin_cleanup_pycore
from webapp.routes import app_entry_routes
from webapp.routes import auth_users
from webapp.routes import async_run_monitor
from webapp.routes import base_uploads
from webapp.routes import client_exec_diag
from webapp.routes import core_details
from webapp.routes import core_daemon_admin
from webapp.routes import core_data
from webapp.routes import core_execute_support
from webapp.routes import core_lifecycle
from webapp.routes import core_connection_validation
from webapp.routes import core_page
from webapp.routes import core_push_progress
from webapp.routes import core_repo_push
from webapp.routes import core_session_actions
from webapp.routes import core_session_tools
from webapp.routes import core_test_prepare
from webapp.routes import core_venv_probe
from webapp.routes import core_credentials
from webapp.routes import core_remote_repo
from webapp.routes import diagnostics_health
from webapp.routes import docker_routes
from webapp.routes import editor_snapshot
from webapp.routes import flag_compose
from webapp.routes import flag_catalog_pages
from webapp.routes import generator_catalog_data
from webapp.routes import generator_catalog_mutations
from webapp.routes import generator_builder_routes
from webapp.routes import generator_pack_routes
from webapp.routes import flag_generators_test
from webapp.routes import flag_generators_test_core_credentials
from webapp.routes import flag_node_generators_test
from webapp.routes import flag_sequencing_attackflow_preview
from webapp.routes import flag_sequencing_candidates
from webapp.routes import flag_sequencing_exports
from webapp.routes import flag_sequencing_latest_preview
from webapp.routes import flag_sequencing_prepare_preview
from webapp.routes import flag_sequencing_progress
from webapp.routes import flag_sequencing_sequence_preview
from webapp.routes import flag_sequencing_state
from webapp.routes import flag_sequencing_substitutions
from webapp.routes import flag_sequencing_uploads
from webapp.routes import flag_sequencing_values
from webapp.routes import flag_sequencing_validation
from webapp.routes import host_interfaces
from webapp.routes import hitl_bridge
from webapp.routes import hitl_clear
from webapp.routes import node_schema
from webapp.routes import planner
from webapp.routes import plan_preview_api
from webapp.routes import plan_preview_pages
from webapp.routes import participant_ui
from webapp.routes import proxmox
from webapp.routes import reports_downloads
from webapp.routes import scenario_latest
from webapp.routes import scenario_delete_purge
from webapp.routes import scenarios_pages
from webapp.routes import seed_hints
from webapp.routes import script_artifacts
from webapp.routes import vuln_catalog_mutations
from webapp.routes import vuln_catalog_api
from webapp.routes import vuln_catalog_overview
from webapp.routes import vuln_catalog_pack_ingest
from webapp.routes import vuln_catalog_pack_files
from webapp.routes import vuln_catalog_test_control
from webapp.routes import vuln_catalog_test_start
from webapp.routes import vuln_compose
from webapp.routes import webui_logs


def _noop_purge_run_history_for_scenario(_name: str, _delete_artifacts: bool) -> int:
    return 0


def _noop_purge_planner_state_for_scenarios(_names: list[str]) -> int:
    return 0


def _noop_purge_plan_artifacts_for_scenarios(_names: list[str]) -> int:
    return 0


def _noop_remove_scenarios_from_catalog(_names: list[str]) -> dict:
    return {'removed': []}


def _noop_delete_saved_scenario_xml_artifacts(_names: list[str]) -> dict:
    return {'deleted_files': []}


def _noop_remove_scenarios_from_all_editor_snapshots(_names: list[str]) -> dict:
    return {'snapshots_updated': 0}


def test_scenario_delete_purge_register_is_idempotent():
    app = Flask(__name__)

    scenario_delete_purge.register(
        app,
        purge_run_history_for_scenario=_noop_purge_run_history_for_scenario,
        purge_planner_state_for_scenarios=_noop_purge_planner_state_for_scenarios,
        purge_plan_artifacts_for_scenarios=_noop_purge_plan_artifacts_for_scenarios,
        remove_scenarios_from_catalog=_noop_remove_scenarios_from_catalog,
        delete_saved_scenario_xml_artifacts=_noop_delete_saved_scenario_xml_artifacts,
        remove_scenarios_from_all_editor_snapshots=_noop_remove_scenarios_from_all_editor_snapshots,
    )
    scenario_delete_purge.register(
        app,
        purge_run_history_for_scenario=_noop_purge_run_history_for_scenario,
        purge_planner_state_for_scenarios=_noop_purge_planner_state_for_scenarios,
        purge_plan_artifacts_for_scenarios=_noop_purge_plan_artifacts_for_scenarios,
        remove_scenarios_from_catalog=_noop_remove_scenarios_from_catalog,
        delete_saved_scenario_xml_artifacts=_noop_delete_saved_scenario_xml_artifacts,
        remove_scenarios_from_all_editor_snapshots=_noop_remove_scenarios_from_all_editor_snapshots,
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/purge_history_for_scenario' in rules
    assert '/delete_scenarios' in rules


def test_ai_provider_register_is_idempotent():
    app = Flask(__name__)

    ai_provider.register(app)
    ai_provider.register(app)

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/ai/providers' in rules
    assert '/api/ai/provider/validate' in rules
    assert '/api/ai/generate_scenario_preview' in rules
    assert '/api/ai/generate_scenario_preview_stream' in rules
    assert '/api/ai/generate_scenario_preview_stream/cancel' in rules


def test_app_entry_routes_register_is_idempotent():
    app = Flask(__name__)

    backend_module = type(
        'BackendModule',
        (),
        {
            '_current_user': staticmethod(lambda: None),
            '_is_participant_role': staticmethod(lambda role: False),
            '_default_core_dict': staticmethod(lambda: {}),
            '_normalize_role_value': staticmethod(lambda role: ''),
            '_scenario_catalog_force_empty': staticmethod(lambda: False),
            '_scenario_catalog_for_user': staticmethod(lambda _history, user=None: ([], {}, {})),
            '_default_scenarios_payload_for_names': staticmethod(lambda names: {'scenarios': [], 'core': {}, 'result_path': None}),
            '_attach_base_upload': staticmethod(lambda payload: None),
            '_hydrate_base_upload_from_disk': staticmethod(lambda payload: None),
            '_enumerate_host_interfaces': staticmethod(lambda: []),
            '_save_base_upload_state': staticmethod(lambda payload: None),
            '_prepare_payload_for_index': staticmethod(lambda payload, user=None: payload),
            '_delete_editor_state_snapshot': staticmethod(lambda user=None: None),
            '_load_editor_state_snapshot': staticmethod(lambda user=None: None),
            '_latest_xml_path_for_scenario': staticmethod(lambda norm: ''),
            '_normalize_scenario_label': staticmethod(lambda value: ''),
            '_parse_scenarios_xml': staticmethod(lambda path: {}),
            '_get_repo_root': staticmethod(lambda: '.'),
            '_outputs_dir': staticmethod(lambda: 'outputs'),
            '_build_scenarios_xml': staticmethod(lambda data: None),
            '_WEBUI_BUILD_ID': 'test-build',
        },
    )()

    app_entry_routes.register(app, backend_module=backend_module)
    app_entry_routes.register(app, backend_module=backend_module)

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    endpoints = {rule.endpoint for rule in app.url_map.iter_rules()}
    assert '/' in rules
    assert '/run_cli' in rules
    assert '/run_cli_async' in rules
    assert 'index' in endpoints
    assert 'run_cli' in endpoints
    assert 'run_cli_async' in endpoints


def test_admin_cleanup_pycore_register_is_idempotent():
    app = Flask(__name__)

    admin_cleanup_pycore.register(
        app,
        core_config_for_request=lambda **kwargs: {'host': '127.0.0.1', 'port': 50051},
        list_active_core_sessions=lambda *_args, **_kwargs: [],
        core_host_default='127.0.0.1',
        core_port_default=50051,
        pycore_globber=lambda: [],
    )
    admin_cleanup_pycore.register(
        app,
        core_config_for_request=lambda **kwargs: {'host': '127.0.0.1', 'port': 50051},
        list_active_core_sessions=lambda *_args, **_kwargs: [],
        core_host_default='127.0.0.1',
        core_port_default=50051,
        pycore_globber=lambda: [],
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    endpoints = {rule.endpoint for rule in app.url_map.iter_rules()}
    assert '/admin/cleanup_pycore' in rules
    assert 'admin_cleanup_pycore' in endpoints


def test_diagnostics_health_register_is_idempotent():
    app = Flask(__name__)
    app.secret_key = 'test-secret'

    diagnostics_health.register(
        app,
        current_user_getter=lambda: {'role': 'admin'},
        is_admin_view_role=lambda role: str(role or '').strip().lower() == 'admin',
        normalize_role_value=lambda role: str(role or '').strip().lower(),
        ui_view_allowed={'admin', 'builder', 'participant'},
        ui_view_default='admin',
        admin_view_roles={'admin'},
        ui_view_session_key='ui_view',
        urlparse_func=lambda value: __import__('urllib.parse').parse.urlparse(value),
        parse_qs_func=lambda value: __import__('urllib.parse').parse.parse_qs(value),
        resolve_ui_view_redirect_target=lambda target: target or '/',
    )
    diagnostics_health.register(
        app,
        current_user_getter=lambda: {'role': 'admin'},
        is_admin_view_role=lambda role: str(role or '').strip().lower() == 'admin',
        normalize_role_value=lambda role: str(role or '').strip().lower(),
        ui_view_allowed={'admin', 'builder', 'participant'},
        ui_view_default='admin',
        admin_view_roles={'admin'},
        ui_view_session_key='ui_view',
        urlparse_func=lambda value: __import__('urllib.parse').parse.urlparse(value),
        parse_qs_func=lambda value: __import__('urllib.parse').parse.parse_qs(value),
        resolve_ui_view_redirect_target=lambda target: target or '/',
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/diag/modules' in rules
    assert '/ui-view' in rules
    assert '/healthz' in rules
    assert '/favicon.ico' in rules


def test_auth_users_register_is_idempotent():
    app = Flask(__name__)
    app.secret_key = 'test-secret'

    auth_users.register(
        app,
        load_users=lambda: {'users': []},
        save_users=lambda data: None,
        require_admin=lambda: True,
        current_user_getter=lambda: {'username': 'coreadmin', 'role': 'admin'},
        set_current_user=lambda user: None,
        normalize_role_value=lambda role: str(role or '').strip().lower(),
        allowed_user_roles=lambda: {'admin', 'builder', 'participant'},
        normalize_scenario_label=lambda value: str(value or '').strip(),
        normalize_scenario_assignments=lambda values: list(values or []),
        scenario_catalog_for_user=lambda *args, **kwargs: ([], {}, {}),
        default_ui_view_mode_for_role=lambda role: 'admin',
        is_participant_role=lambda role: str(role or '').strip().lower() == 'participant',
        ui_view_session_key='ui_view_mode',
    )
    auth_users.register(
        app,
        load_users=lambda: {'users': []},
        save_users=lambda data: None,
        require_admin=lambda: True,
        current_user_getter=lambda: {'username': 'coreadmin', 'role': 'admin'},
        set_current_user=lambda user: None,
        normalize_role_value=lambda role: str(role or '').strip().lower(),
        allowed_user_roles=lambda: {'admin', 'builder', 'participant'},
        normalize_scenario_label=lambda value: str(value or '').strip(),
        normalize_scenario_assignments=lambda values: list(values or []),
        scenario_catalog_for_user=lambda *args, **kwargs: ([], {}, {}),
        default_ui_view_mode_for_role=lambda role: 'admin',
        is_participant_role=lambda role: str(role or '').strip().lower() == 'participant',
        ui_view_session_key='ui_view_mode',
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/login' in rules
    assert '/logout' in rules
    assert '/users' in rules
    assert '/users/delete/<username>' in rules
    assert '/users/password/<username>' in rules
    assert '/users/role/<username>' in rules
    assert '/users/scenarios/<username>' in rules
    assert '/me/password' in rules


def test_editor_snapshot_register_is_idempotent():
    app = Flask(__name__)

    editor_snapshot.register(
        app,
        current_user_getter=lambda: {'username': 'tester'},
        build_editor_snapshot_payload=lambda payload: payload,
        write_editor_state_snapshot=lambda snapshot, user=None: None,
    )
    editor_snapshot.register(
        app,
        current_user_getter=lambda: {'username': 'tester'},
        build_editor_snapshot_payload=lambda payload: payload,
        write_editor_state_snapshot=lambda snapshot, user=None: None,
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/editor_snapshot' in rules


def test_host_interfaces_register_is_idempotent():
    app = Flask(__name__)

    host_interfaces.register(
        app,
        coerce_bool=lambda value: bool(value),
        find_proxmox_vm_config=lambda *args, **kwargs: [],
        enumerate_core_vm_interfaces_from_secret=lambda *args, **kwargs: [],
        ssh_tunnel_error_type=RuntimeError,
        local_timestamp_display=lambda: 'now',
        enumerate_host_interfaces=lambda: [],
    )
    host_interfaces.register(
        app,
        coerce_bool=lambda value: bool(value),
        find_proxmox_vm_config=lambda *args, **kwargs: [],
        enumerate_core_vm_interfaces_from_secret=lambda *args, **kwargs: [],
        ssh_tunnel_error_type=RuntimeError,
        local_timestamp_display=lambda: 'now',
        enumerate_host_interfaces=lambda: [],
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/host_interfaces' in rules


def test_scenarios_pages_register_is_idempotent():
    app = Flask(__name__)

    backend_module = object()

    scenarios_pages.register(app, backend_module=backend_module)
    scenarios_pages.register(app, backend_module=backend_module)

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    endpoints = {rule.endpoint for rule in app.url_map.iter_rules()}
    assert '/scenarios/flag-sequencing' in rules
    assert '/scenarios/preview' in rules
    assert 'flow_page' in endpoints
    assert 'scenarios_preview_page' in endpoints
    assert 'scenarios_preview' in endpoints


def test_core_credentials_register_is_idempotent():
    app = Flask(__name__)

    core_credentials.register(
        app,
        current_user_getter=lambda: {'role': 'admin'},
        normalize_role_value=lambda role: str(role or '').strip().lower(),
        delete_core_credentials=lambda secret_id: bool(secret_id),
        load_core_credentials=lambda secret_id: {'identifier': secret_id, 'port': 50051, 'grpc_port': 50051, 'ssh_port': 22},
        clear_hitl_validation_in_scenario_catalog=lambda *args, **kwargs: None,
        default_core_venv_bin='/tmp/core-python',
    )
    core_credentials.register(
        app,
        current_user_getter=lambda: {'role': 'admin'},
        normalize_role_value=lambda role: str(role or '').strip().lower(),
        delete_core_credentials=lambda secret_id: bool(secret_id),
        load_core_credentials=lambda secret_id: {'identifier': secret_id, 'port': 50051, 'grpc_port': 50051, 'ssh_port': 22},
        clear_hitl_validation_in_scenario_catalog=lambda *args, **kwargs: None,
        default_core_venv_bin='/tmp/core-python',
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/core/credentials/clear' in rules
    assert '/api/core/credentials/get' in rules


def test_core_lifecycle_register_is_idempotent():
    app = Flask(__name__)

    core_lifecycle.register(
        app,
        redirect_core_page_with_scenario=lambda **kwargs: None,
        local_timestamp_safe=lambda: '20260101-000000',
        uuid_hex=lambda: 'abcdef123456',
        validate_core_xml=lambda path: (True, []),
        core_config_for_request=lambda **kwargs: {'host': '127.0.0.1', 'port': 50051},
        normalize_core_config=lambda cfg, **kwargs: cfg,
        upload_file_to_core_host=lambda cfg, path: '/tmp/uploaded.xml',
        remote_core_open_xml_script=lambda *args, **kwargs: 'print(1)',
        run_remote_python_json=lambda *args, **kwargs: {'session_id': 1},
        remove_remote_file=lambda cfg, path: None,
        update_xml_session_mapping=lambda *args, **kwargs: None,
        write_remote_session_scenario_meta=lambda *args, **kwargs: None,
        execute_remote_core_session_action=lambda *args, **kwargs: None,
        remote_docker_status_script=lambda password: 'status',
        remote_docker_cleanup_script=lambda names, password: 'cleanup',
        remote_docker_remove_wrapper_images_script=lambda password: 'remove',
        core_host_default='127.0.0.1',
        core_port_default=50051,
    )
    core_lifecycle.register(
        app,
        redirect_core_page_with_scenario=lambda **kwargs: None,
        local_timestamp_safe=lambda: '20260101-000000',
        uuid_hex=lambda: 'abcdef123456',
        validate_core_xml=lambda path: (True, []),
        core_config_for_request=lambda **kwargs: {'host': '127.0.0.1', 'port': 50051},
        normalize_core_config=lambda cfg, **kwargs: cfg,
        upload_file_to_core_host=lambda cfg, path: '/tmp/uploaded.xml',
        remote_core_open_xml_script=lambda *args, **kwargs: 'print(1)',
        run_remote_python_json=lambda *args, **kwargs: {'session_id': 1},
        remove_remote_file=lambda cfg, path: None,
        update_xml_session_mapping=lambda *args, **kwargs: None,
        write_remote_session_scenario_meta=lambda *args, **kwargs: None,
        execute_remote_core_session_action=lambda *args, **kwargs: None,
        remote_docker_status_script=lambda password: 'status',
        remote_docker_cleanup_script=lambda names, password: 'cleanup',
        remote_docker_remove_wrapper_images_script=lambda password: 'remove',
        core_host_default='127.0.0.1',
        core_port_default=50051,
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/core/upload' in rules
    assert '/core/start' in rules
    assert '/core/stop' in rules


def test_core_push_progress_register_is_idempotent():
    app = Flask(__name__)

    core_push_progress.register(
        app,
        get_repo_push_progress=lambda progress_id: None,
        update_repo_push_progress=lambda *args, **kwargs: None,
        get_repo_push_cancel_ctx=lambda progress_id: None,
        open_ssh_client=lambda core_cfg: object(),
        exec_ssh_command=lambda *args, **kwargs: (0, '', ''),
        shlex_quote=lambda value: repr(value),
    )
    core_push_progress.register(
        app,
        get_repo_push_progress=lambda progress_id: None,
        update_repo_push_progress=lambda *args, **kwargs: None,
        get_repo_push_cancel_ctx=lambda progress_id: None,
        open_ssh_client=lambda core_cfg: object(),
        exec_ssh_command=lambda *args, **kwargs: (0, '', ''),
        shlex_quote=lambda value: repr(value),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/core/push_repo/status/<progress_id>' in rules
    assert '/core/push_repo/cancel/<progress_id>' in rules


def test_core_daemon_admin_register_is_idempotent():
    app = Flask(__name__)
    app.secret_key = 'test-secret'

    core_daemon_admin.register(
        app,
        login_required=lambda fn: fn,
        normalize_scenario_label=lambda value: value,
        select_core_config_for_page=lambda *args, **kwargs: {'ssh_host': '127.0.0.1'},
        open_ssh_client=lambda core_cfg: object(),
    )
    core_daemon_admin.register(
        app,
        login_required=lambda fn: fn,
        normalize_scenario_label=lambda value: value,
        select_core_config_for_page=lambda *args, **kwargs: {'ssh_host': '127.0.0.1'},
        open_ssh_client=lambda core_cfg: object(),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/core/restart_core_daemon' in rules


def test_core_repo_push_register_is_idempotent():
    app = Flask(__name__)

    class _FakeTunnelError(Exception):
        pass

    core_repo_push.register(
        app,
        parse_scenarios_xml=lambda path: {},
        merge_core_configs=lambda *args, **kwargs: {},
        init_repo_push_progress=lambda *args, **kwargs: None,
        schedule_repo_push_to_remote=lambda *args, **kwargs: None,
        update_repo_push_progress=lambda *args, **kwargs: None,
        ssh_tunnel_error_type=_FakeTunnelError,
        uuid_hex=lambda: 'demo-progress',
    )
    core_repo_push.register(
        app,
        parse_scenarios_xml=lambda path: {},
        merge_core_configs=lambda *args, **kwargs: {},
        init_repo_push_progress=lambda *args, **kwargs: None,
        schedule_repo_push_to_remote=lambda *args, **kwargs: None,
        update_repo_push_progress=lambda *args, **kwargs: None,
        ssh_tunnel_error_type=_FakeTunnelError,
        uuid_hex=lambda: 'demo-progress',
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/core/push_repo' in rules


def test_core_data_register_is_idempotent():
    app = Flask(__name__)

    core_data.register(
        app,
        load_run_history=lambda: [],
        current_user_getter=lambda: None,
        scenario_catalog_for_user=lambda history, user=None: ([], {}, {}),
        collect_scenario_participant_urls=lambda scenario_paths, scenario_url_hints: {},
        normalize_scenario_label=lambda value: str(value or '').strip().lower(),
        resolve_scenario_display=lambda scenario_norm, scenario_names, scenario_query: scenario_query or '',
        select_core_config_for_page=lambda *args, **kwargs: {'host': '127.0.0.1', 'port': 50051},
        ensure_core_vm_metadata=lambda core_cfg: core_cfg,
        build_core_vm_summary=lambda core_cfg: (False, {}),
        list_active_core_sessions=lambda *args, **kwargs: [],
        scan_core_xmls=lambda: [],
        load_core_sessions_store=lambda: {},
        migrate_core_sessions_store_with_core_targets=lambda mapping, history: mapping,
        filter_core_sessions_store_for_core=lambda mapping, host, port: mapping,
        build_session_scenario_labels=lambda mapping, scenario_names, scenario_paths: {},
        session_ids_for_scenario=lambda mapping, scenario_norm, scenario_paths: set(),
        annotate_sessions_with_scenarios=lambda *args, **kwargs: None,
        read_remote_session_scenario_meta_bulk=lambda *args, **kwargs: {},
        filter_sessions_by_scenario=lambda *args, **kwargs: ([], False),
        path_matches_scenario=lambda path, scenario_norm, scenario_paths: False,
        session_store_updated_at_for_session_id=lambda *args, **kwargs: None,
        scenario_timestamped_filename=lambda scenario_name, ts_epoch: 'scenario.xml',
        attach_hitl_metadata_to_sessions=lambda *args, **kwargs: None,
        attach_participant_urls_to_sessions=lambda *args, **kwargs: None,
        session_store_entry_session_id=lambda value: None,
        filter_xmls_by_scenario=lambda *args, **kwargs: ([], False),
        current_core_ui_logs=lambda: [],
        core_host_default='127.0.0.1',
        core_port_default=50051,
    )
    core_data.register(
        app,
        load_run_history=lambda: [],
        current_user_getter=lambda: None,
        scenario_catalog_for_user=lambda history, user=None: ([], {}, {}),
        collect_scenario_participant_urls=lambda scenario_paths, scenario_url_hints: {},
        normalize_scenario_label=lambda value: str(value or '').strip().lower(),
        resolve_scenario_display=lambda scenario_norm, scenario_names, scenario_query: scenario_query or '',
        select_core_config_for_page=lambda *args, **kwargs: {'host': '127.0.0.1', 'port': 50051},
        ensure_core_vm_metadata=lambda core_cfg: core_cfg,
        build_core_vm_summary=lambda core_cfg: (False, {}),
        list_active_core_sessions=lambda *args, **kwargs: [],
        scan_core_xmls=lambda: [],
        load_core_sessions_store=lambda: {},
        migrate_core_sessions_store_with_core_targets=lambda mapping, history: mapping,
        filter_core_sessions_store_for_core=lambda mapping, host, port: mapping,
        build_session_scenario_labels=lambda mapping, scenario_names, scenario_paths: {},
        session_ids_for_scenario=lambda mapping, scenario_norm, scenario_paths: set(),
        annotate_sessions_with_scenarios=lambda *args, **kwargs: None,
        read_remote_session_scenario_meta_bulk=lambda *args, **kwargs: {},
        filter_sessions_by_scenario=lambda *args, **kwargs: ([], False),
        path_matches_scenario=lambda path, scenario_norm, scenario_paths: False,
        session_store_updated_at_for_session_id=lambda *args, **kwargs: None,
        scenario_timestamped_filename=lambda scenario_name, ts_epoch: 'scenario.xml',
        attach_hitl_metadata_to_sessions=lambda *args, **kwargs: None,
        attach_participant_urls_to_sessions=lambda *args, **kwargs: None,
        session_store_entry_session_id=lambda value: None,
        filter_xmls_by_scenario=lambda *args, **kwargs: ([], False),
        current_core_ui_logs=lambda: [],
        core_host_default='127.0.0.1',
        core_port_default=50051,
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/core/data' in rules


def test_core_page_register_is_idempotent():
    app = Flask(__name__)

    core_page.register(
        app,
        load_run_history=lambda: [],
        current_user_getter=lambda: None,
        scenario_catalog_for_user=lambda history, user=None: ([], {}, {}),
        collect_scenario_participant_urls=lambda scenario_paths, scenario_url_hints: {},
        normalize_scenario_label=lambda value: str(value or '').strip().lower(),
        resolve_scenario_display=lambda scenario_norm, scenario_names, scenario_query: scenario_query or '',
        select_core_config_for_page=lambda *args, **kwargs: {'host': '127.0.0.1', 'port': 50051},
        ensure_core_vm_metadata=lambda core_cfg: core_cfg,
        build_core_vm_summary=lambda core_cfg: (False, {}),
        list_active_core_sessions=lambda *args, **kwargs: [],
        scan_core_xmls=lambda: [],
        load_core_sessions_store=lambda: {},
        migrate_core_sessions_store_with_core_targets=lambda mapping, history: mapping,
        filter_core_sessions_store_for_core=lambda mapping, host, port: mapping,
        build_session_scenario_labels=lambda mapping, scenario_names, scenario_paths: {},
        session_ids_for_scenario=lambda mapping, scenario_norm, scenario_paths: set(),
        annotate_sessions_with_scenarios=lambda *args, **kwargs: None,
        filter_sessions_by_scenario=lambda *args, **kwargs: ([], False),
        filter_xmls_by_scenario=lambda *args, **kwargs: ([], False),
        read_remote_session_scenario_meta_bulk=lambda *args, **kwargs: {},
        session_store_updated_at_for_session_id=lambda *args, **kwargs: None,
        scenario_timestamped_filename=lambda scenario_name, ts_epoch: 'scenario.xml',
        attach_hitl_metadata_to_sessions=lambda *args, **kwargs: None,
        attach_participant_urls_to_sessions=lambda *args, **kwargs: None,
        session_store_entry_session_id=lambda value: None,
        current_core_ui_logs=lambda: [],
        core_host_default='127.0.0.1',
        core_port_default=50051,
    )
    core_page.register(
        app,
        load_run_history=lambda: [],
        current_user_getter=lambda: None,
        scenario_catalog_for_user=lambda history, user=None: ([], {}, {}),
        collect_scenario_participant_urls=lambda scenario_paths, scenario_url_hints: {},
        normalize_scenario_label=lambda value: str(value or '').strip().lower(),
        resolve_scenario_display=lambda scenario_norm, scenario_names, scenario_query: scenario_query or '',
        select_core_config_for_page=lambda *args, **kwargs: {'host': '127.0.0.1', 'port': 50051},
        ensure_core_vm_metadata=lambda core_cfg: core_cfg,
        build_core_vm_summary=lambda core_cfg: (False, {}),
        list_active_core_sessions=lambda *args, **kwargs: [],
        scan_core_xmls=lambda: [],
        load_core_sessions_store=lambda: {},
        migrate_core_sessions_store_with_core_targets=lambda mapping, history: mapping,
        filter_core_sessions_store_for_core=lambda mapping, host, port: mapping,
        build_session_scenario_labels=lambda mapping, scenario_names, scenario_paths: {},
        session_ids_for_scenario=lambda mapping, scenario_norm, scenario_paths: set(),
        annotate_sessions_with_scenarios=lambda *args, **kwargs: None,
        filter_sessions_by_scenario=lambda *args, **kwargs: ([], False),
        filter_xmls_by_scenario=lambda *args, **kwargs: ([], False),
        read_remote_session_scenario_meta_bulk=lambda *args, **kwargs: {},
        session_store_updated_at_for_session_id=lambda *args, **kwargs: None,
        scenario_timestamped_filename=lambda scenario_name, ts_epoch: 'scenario.xml',
        attach_hitl_metadata_to_sessions=lambda *args, **kwargs: None,
        attach_participant_urls_to_sessions=lambda *args, **kwargs: None,
        session_store_entry_session_id=lambda value: None,
        current_core_ui_logs=lambda: [],
        core_host_default='127.0.0.1',
        core_port_default=50051,
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/core' in rules


def test_core_connection_validation_register_is_idempotent():
    app = Flask(__name__)

    class _FakeTunnelError(Exception):
        pass

    core_connection_validation.register(
        app,
        current_user_getter=lambda: {'role': 'admin'},
        normalize_role_value=lambda value: str(value or '').strip().lower(),
        merge_core_configs=lambda *args, **kwargs: {},
        load_core_credentials=lambda identifier: None,
        ensure_paramiko_available=lambda: None,
        paramiko_getter=lambda: None,
        collect_remote_core_daemon_pids=lambda ssh_client: [],
        stop_remote_core_daemon_conflict=lambda *args, **kwargs: None,
        install_custom_services_to_core_vm=lambda *args, **kwargs: None,
        start_remote_core_daemon=lambda *args, **kwargs: None,
        run_core_connection_advanced_checks=lambda *args, **kwargs: {},
        ensure_core_daemon_listening=lambda *args, **kwargs: None,
        core_connection=lambda cfg: None,
        save_core_credentials=lambda payload: {'identifier': 'demo'},
        merge_hitl_validation_into_scenario_catalog=lambda *args, **kwargs: None,
        normalize_core_config=lambda *args, **kwargs: {},
        local_timestamp_display=lambda: '2026-03-19T00:00:00Z',
        ssh_tunnel_error_type=_FakeTunnelError,
        webui_running_in_docker=lambda: False,
        json_module=__import__('json'),
        os_module=__import__('os'),
        sys_module=__import__('sys'),
        socket_module=__import__('socket'),
    )
    core_connection_validation.register(
        app,
        current_user_getter=lambda: {'role': 'admin'},
        normalize_role_value=lambda value: str(value or '').strip().lower(),
        merge_core_configs=lambda *args, **kwargs: {},
        load_core_credentials=lambda identifier: None,
        ensure_paramiko_available=lambda: None,
        paramiko_getter=lambda: None,
        collect_remote_core_daemon_pids=lambda ssh_client: [],
        stop_remote_core_daemon_conflict=lambda *args, **kwargs: None,
        install_custom_services_to_core_vm=lambda *args, **kwargs: None,
        start_remote_core_daemon=lambda *args, **kwargs: None,
        run_core_connection_advanced_checks=lambda *args, **kwargs: {},
        ensure_core_daemon_listening=lambda *args, **kwargs: None,
        core_connection=lambda cfg: None,
        save_core_credentials=lambda payload: {'identifier': 'demo'},
        merge_hitl_validation_into_scenario_catalog=lambda *args, **kwargs: None,
        normalize_core_config=lambda *args, **kwargs: {},
        local_timestamp_display=lambda: '2026-03-19T00:00:00Z',
        ssh_tunnel_error_type=_FakeTunnelError,
        webui_running_in_docker=lambda: False,
        json_module=__import__('json'),
        os_module=__import__('os'),
        sys_module=__import__('sys'),
        socket_module=__import__('socket'),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/test_core' in rules


def test_flag_generators_test_core_credentials_register_is_idempotent():
    app = Flask(__name__)

    flag_generators_test_core_credentials.register(
        app,
        current_user_getter=lambda: {'username': 'coreadmin'},
        outputs_dir=lambda: '/tmp/core-topo-gen-test',
        save_core_credentials=lambda payload: {
            'identifier': 'secret-id',
            'stored_at': 'now',
            'ssh_host': payload.get('ssh_host'),
            'ssh_port': payload.get('ssh_port'),
            'ssh_username': payload.get('ssh_username'),
        },
        load_core_credentials=lambda secret_id: {'identifier': secret_id, 'port': 50051, 'grpc_port': 50051, 'ssh_port': 22},
        core_port=50051,
        default_core_venv_bin='/tmp/core-python',
    )
    flag_generators_test_core_credentials.register(
        app,
        current_user_getter=lambda: {'username': 'coreadmin'},
        outputs_dir=lambda: '/tmp/core-topo-gen-test',
        save_core_credentials=lambda payload: {
            'identifier': 'secret-id',
            'stored_at': 'now',
            'ssh_host': payload.get('ssh_host'),
            'ssh_port': payload.get('ssh_port'),
            'ssh_username': payload.get('ssh_username'),
        },
        load_core_credentials=lambda secret_id: {'identifier': secret_id, 'port': 50051, 'grpc_port': 50051, 'ssh_port': 22},
        core_port=50051,
        default_core_venv_bin='/tmp/core-python',
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/flag_generators_test/core_credentials/save' in rules
    assert '/api/flag_generators_test/core_credentials/get' in rules


def test_flag_compose_register_is_idempotent():
    app = Flask(__name__)

    flag_compose.register(
        app,
        flag_base_dir=lambda: '/tmp/core-topo-gen-flags',
        safe_name=lambda value: str(value or '').strip().replace(' ', '_'),
        parse_github_url=lambda value: {'is_github': False, 'subpath': '', 'branch': '', 'git_url': value},
        vuln_repo_subdir=lambda: 'repo',
        compose_candidates=lambda base_dir: [],
        get_repo_root=lambda: '/tmp/core-topo-gen',
    )
    flag_compose.register(
        app,
        flag_base_dir=lambda: '/tmp/core-topo-gen-flags',
        safe_name=lambda value: str(value or '').strip().replace(' ', '_'),
        parse_github_url=lambda value: {'is_github': False, 'subpath': '', 'branch': '', 'git_url': value},
        vuln_repo_subdir=lambda: 'repo',
        compose_candidates=lambda base_dir: [],
        get_repo_root=lambda: '/tmp/core-topo-gen',
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/flag_compose/status' in rules
    assert '/flag_compose/download' in rules
    assert '/flag_compose/pull' in rules
    assert '/flag_compose/remove' in rules


def test_flag_node_generators_test_register_is_idempotent():
    app = Flask(__name__)

    flag_node_generators_test.register(
        app,
        runs={},
        outputs_dir=lambda: '/tmp/core-topo-gen-test',
        flagnodegen_run_dir_for_id=lambda run_id: f'/tmp/core-topo-gen-test/{run_id}',
        write_sse_marker=lambda *args, **kwargs: None,
        open_ssh_client=lambda core_cfg: None,
        remote_remove_path=lambda *args, **kwargs: None,
        find_enabled_node_generator_by_id=lambda generator_id: {'id': generator_id, 'inputs': []},
        is_installed_generator_view=lambda generator: False,
        is_installed_generator_disabled=lambda **kwargs: False,
        flag_node_generators_runs_dir=lambda: '/tmp/core-topo-gen-test',
        parse_flag_test_core_cfg_from_form=lambda form: None,
        ensure_core_vm_idle_for_test=lambda core_cfg: None,
        start_remote_flag_test_process=lambda **kwargs: {},
        sync_remote_flag_test_outputs=lambda meta: None,
        purge_remote_flag_test_dir=lambda meta: None,
        resolve_python_executable=lambda: '/tmp/python',
        get_repo_root=lambda: '/tmp/core-topo-gen',
        local_timestamp_safe=lambda: '20260101-000000',
        coerce_bool=lambda value: bool(value),
        cleanup_remote_test_runtime=lambda meta: None,
        flagnodegen_run_ephemeral_execute=lambda run_id: None,
    )
    flag_node_generators_test.register(
        app,
        runs={},
        outputs_dir=lambda: '/tmp/core-topo-gen-test',
        flagnodegen_run_dir_for_id=lambda run_id: f'/tmp/core-topo-gen-test/{run_id}',
        write_sse_marker=lambda *args, **kwargs: None,
        open_ssh_client=lambda core_cfg: None,
        remote_remove_path=lambda *args, **kwargs: None,
        find_enabled_node_generator_by_id=lambda generator_id: {'id': generator_id, 'inputs': []},
        is_installed_generator_view=lambda generator: False,
        is_installed_generator_disabled=lambda **kwargs: False,
        flag_node_generators_runs_dir=lambda: '/tmp/core-topo-gen-test',
        parse_flag_test_core_cfg_from_form=lambda form: None,
        ensure_core_vm_idle_for_test=lambda core_cfg: None,
        start_remote_flag_test_process=lambda **kwargs: {},
        sync_remote_flag_test_outputs=lambda meta: None,
        purge_remote_flag_test_dir=lambda meta: None,
        resolve_python_executable=lambda: '/tmp/python',
        get_repo_root=lambda: '/tmp/core-topo-gen',
        local_timestamp_safe=lambda: '20260101-000000',
        coerce_bool=lambda value: bool(value),
        cleanup_remote_test_runtime=lambda meta: None,
        flagnodegen_run_ephemeral_execute=lambda run_id: None,
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/flag_node_generators_test/run' in rules
    assert '/flag_node_generators_test/outputs/<run_id>' in rules
    assert '/flag_node_generators_test/download/<run_id>' in rules
    assert '/flag_node_generators_test/cleanup/<run_id>' in rules


def test_flag_generators_test_register_is_idempotent():
    app = Flask(__name__)

    flag_generators_test.register(
        app,
        runs={},
        outputs_dir=lambda: '/tmp/core-topo-gen-test',
        flaggen_run_dir_for_id=lambda run_id: f'/tmp/core-topo-gen-test/{run_id}',
        write_sse_marker=lambda *args, **kwargs: None,
        open_ssh_client=lambda core_cfg: None,
        remote_remove_path=lambda *args, **kwargs: None,
        find_enabled_generator_by_id=lambda generator_id: {'id': generator_id, 'inputs': []},
        is_installed_generator_view=lambda generator: False,
        is_installed_generator_disabled=lambda **kwargs: False,
        flag_generators_runs_dir=lambda: '/tmp/core-topo-gen-test',
        parse_flag_test_core_cfg_from_form=lambda form: None,
        ensure_core_vm_idle_for_test=lambda core_cfg: None,
        start_remote_flag_test_process=lambda **kwargs: {},
        sync_remote_flag_test_outputs=lambda meta: None,
        purge_remote_flag_test_dir=lambda meta: None,
        resolve_python_executable=lambda: '/tmp/python',
        get_repo_root=lambda: '/tmp/core-topo-gen',
        local_timestamp_safe=lambda: '20260101-000000',
        coerce_bool=lambda value: bool(value),
        cleanup_remote_test_runtime=lambda meta: None,
        flaggen_run_ephemeral_execute=lambda run_id: None,
    )
    flag_generators_test.register(
        app,
        runs={},
        outputs_dir=lambda: '/tmp/core-topo-gen-test',
        flaggen_run_dir_for_id=lambda run_id: f'/tmp/core-topo-gen-test/{run_id}',
        write_sse_marker=lambda *args, **kwargs: None,
        open_ssh_client=lambda core_cfg: None,
        remote_remove_path=lambda *args, **kwargs: None,
        find_enabled_generator_by_id=lambda generator_id: {'id': generator_id, 'inputs': []},
        is_installed_generator_view=lambda generator: False,
        is_installed_generator_disabled=lambda **kwargs: False,
        flag_generators_runs_dir=lambda: '/tmp/core-topo-gen-test',
        parse_flag_test_core_cfg_from_form=lambda form: None,
        ensure_core_vm_idle_for_test=lambda core_cfg: None,
        start_remote_flag_test_process=lambda **kwargs: {},
        sync_remote_flag_test_outputs=lambda meta: None,
        purge_remote_flag_test_dir=lambda meta: None,
        resolve_python_executable=lambda: '/tmp/python',
        get_repo_root=lambda: '/tmp/core-topo-gen',
        local_timestamp_safe=lambda: '20260101-000000',
        coerce_bool=lambda value: bool(value),
        cleanup_remote_test_runtime=lambda meta: None,
        flaggen_run_ephemeral_execute=lambda run_id: None,
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/flag_generators_test/cleanup/<run_id>' in rules
    assert '/flag_generators_test/run' in rules
    assert '/flag_generators_test/outputs/<run_id>' in rules
    assert '/flag_generators_test/download/<run_id>' in rules
    assert '/flag_generators_test/bundle/<run_id>' in rules


def test_vuln_compose_register_is_idempotent():
    app = Flask(__name__)

    vuln_compose.register(
        app,
        vuln_base_dir=lambda: '/tmp/core-topo-gen-vulns',
        safe_name=lambda value: str(value or '').strip().replace(' ', '_'),
        parse_github_url=lambda value: {'is_github': False, 'subpath': '', 'branch': '', 'git_url': value},
        vuln_repo_subdir=lambda: 'repo',
        compose_candidates=lambda base_dir: [],
        get_repo_root=lambda: '/tmp/core-topo-gen',
    )
    vuln_compose.register(
        app,
        vuln_base_dir=lambda: '/tmp/core-topo-gen-vulns',
        safe_name=lambda value: str(value or '').strip().replace(' ', '_'),
        parse_github_url=lambda value: {'is_github': False, 'subpath': '', 'branch': '', 'git_url': value},
        vuln_repo_subdir=lambda: 'repo',
        compose_candidates=lambda base_dir: [],
        get_repo_root=lambda: '/tmp/core-topo-gen',
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/vuln_compose/status' in rules
    assert '/vuln_compose/status_images' in rules
    assert '/vuln_compose/download' in rules
    assert '/vuln_compose/pull' in rules
    assert '/vuln_compose/remove' in rules


def test_script_artifacts_register_is_idempotent():
    app = Flask(__name__)

    script_artifacts.register(app)
    script_artifacts.register(app)

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/open_scripts' in rules
    assert '/api/open_script_file' in rules
    assert '/api/download_scripts' in rules


def test_node_schema_register_is_idempotent():
    app = Flask(__name__)

    node_schema.register(app, node_schema_authoring_path=lambda: '/tmp/node_authoring.yaml')
    node_schema.register(app, node_schema_authoring_path=lambda: '/tmp/node_authoring.yaml')

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/schemas/node_authoring.yaml' in rules


def test_scenario_latest_register_is_idempotent():
    app = Flask(__name__)

    scenario_latest.register(
        app,
        normalize_scenario_label=lambda value: str(value or '').strip().lower(),
        latest_xml_path_for_scenario=lambda scenario_name: f'/tmp/{scenario_name}.xml',
        abs_path_or_original=lambda value: str(value or '').strip(),
        parse_scenarios_xml=lambda path: {'scenarios': [], 'core': {}},
        merge_hitl_hints_into_scenario_state=lambda state, scenario_norm: state,
    )
    scenario_latest.register(
        app,
        normalize_scenario_label=lambda value: str(value or '').strip().lower(),
        latest_xml_path_for_scenario=lambda scenario_name: f'/tmp/{scenario_name}.xml',
        abs_path_or_original=lambda value: str(value or '').strip(),
        parse_scenarios_xml=lambda path: {'scenarios': [], 'core': {}},
        merge_hitl_hints_into_scenario_state=lambda state, scenario_norm: state,
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/scenario/latest_xml' in rules
    assert '/api/scenario/latest_state' in rules


def test_core_remote_repo_register_is_idempotent():
    app = Flask(__name__)

    class _MissingRepoError(RuntimeError):
        def __init__(self, repo_path: str):
            super().__init__(repo_path)
            self.repo_path = repo_path

    core_remote_repo.register(
        app,
        merge_core_configs=lambda cfg, include_password=True: dict(cfg or {}),
        require_core_ssh_credentials=lambda cfg: dict(cfg or {}),
        open_ssh_client=lambda cfg: None,
        remote_static_repo_dir=lambda sftp: '/tmp/repo',
        remote_path_join=lambda *parts: '/'.join(str(part).strip('/') for part in parts if str(part)),
        remote_repo_missing_error_type=_MissingRepoError,
    )
    core_remote_repo.register(
        app,
        merge_core_configs=lambda cfg, include_password=True: dict(cfg or {}),
        require_core_ssh_credentials=lambda cfg: dict(cfg or {}),
        open_ssh_client=lambda cfg: None,
        remote_static_repo_dir=lambda sftp: '/tmp/repo',
        remote_path_join=lambda *parts: '/'.join(str(part).strip('/') for part in parts if str(part)),
        remote_repo_missing_error_type=_MissingRepoError,
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/core/check_remote_repo' in rules


def test_seed_hints_register_is_idempotent():
    app = Flask(__name__)

    seed_hints.register(app, derive_seed_for_scenario=lambda xml_hash, scenario_name: 123)
    seed_hints.register(app, derive_seed_for_scenario=lambda xml_hash, scenario_name: 123)

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/seed_hints' in rules


def test_client_exec_diag_register_is_idempotent():
    app = Flask(__name__)

    client_exec_diag.register(app, require_builder_or_admin=lambda: None)
    client_exec_diag.register(app, require_builder_or_admin=lambda: None)

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/client_exec_diag' in rules


def test_base_uploads_register_is_idempotent():
    app = Flask(__name__)
    app.config['UPLOAD_FOLDER'] = '/tmp/core-topo-gen-uploads'

    base_uploads.register(
        app,
        current_user_getter=lambda: {'username': 'coreadmin'},
        local_timestamp_safe=lambda: '20260101-000000',
        validate_core_xml=lambda path: (True, []),
        default_scenarios_payload=lambda: {'scenarios': [{'base': {}}]},
        attach_base_upload=lambda payload: None,
        save_base_upload_state=lambda meta: None,
        prepare_payload_for_index=lambda payload, **kwargs: payload,
        clear_base_upload_state=lambda: None,
        load_editor_state_snapshot=lambda user=None: None,
        persist_editor_state_snapshot=lambda *args, **kwargs: None,
        analyze_core_xml=lambda path: {'nodes': []},
        ui_build_id='test-build',
    )
    base_uploads.register(
        app,
        current_user_getter=lambda: {'username': 'coreadmin'},
        local_timestamp_safe=lambda: '20260101-000000',
        validate_core_xml=lambda path: (True, []),
        default_scenarios_payload=lambda: {'scenarios': [{'base': {}}]},
        attach_base_upload=lambda payload: None,
        save_base_upload_state=lambda meta: None,
        prepare_payload_for_index=lambda payload, **kwargs: payload,
        clear_base_upload_state=lambda: None,
        load_editor_state_snapshot=lambda user=None: None,
        persist_editor_state_snapshot=lambda *args, **kwargs: None,
        analyze_core_xml=lambda path: {'nodes': []},
        ui_build_id='test-build',
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/upload_base' in rules
    assert '/remove_base' in rules
    assert '/base_details' in rules


def test_async_run_monitor_register_is_idempotent():
    app = Flask(__name__)

    async_run_monitor.register(
        app,
        runs_store={},
        maybe_copy_flow_artifacts_into_containers=lambda *args, **kwargs: None,
        sync_remote_artifacts=lambda meta: None,
        scenario_names_from_xml=lambda path: [],
        extract_report_path_from_text=lambda text: None,
        find_latest_report_path=lambda: None,
        extract_summary_path_from_text=lambda text: None,
        derive_summary_from_report=lambda report_path: None,
        find_latest_summary_path=lambda: None,
        outputs_dir=lambda: '/tmp/core-topo-gen-outputs',
        extract_session_id_from_text=lambda text: None,
        record_session_mapping=lambda *args, **kwargs: None,
        write_remote_session_scenario_meta=lambda *args, **kwargs: None,
        normalize_core_config=lambda cfg, **kwargs: cfg,
        load_run_history=lambda: [],
        select_core_config_for_page=lambda *args, **kwargs: {},
        merge_core_configs=lambda *args, **kwargs: {},
        grpc_save_current_session_xml_with_config=lambda *args, **kwargs: None,
        append_async_run_log_line=lambda meta, line: None,
        append_session_scenario_discrepancies=lambda *args, **kwargs: None,
        validate_session_nodes_and_injects=lambda *args, **kwargs: {'ok': True},
        coerce_bool=lambda value: bool(value),
        extract_async_error_from_text=lambda text: None,
        persist_execute_validation_artifacts=lambda *args, **kwargs: None,
        write_single_scenario_xml=lambda *args, **kwargs: None,
        build_full_scenario_archive=lambda *args, **kwargs: None,
        append_run_history=lambda entry: True,
        local_timestamp_display=lambda: '2026-01-01T00:00:00Z',
        close_async_run_tunnel=lambda meta: None,
        cleanup_remote_workspace=lambda meta: None,
        extract_docker_conflicts_from_text=lambda text: [],
        build_execute_error_logs=lambda *args, **kwargs: [],
        normalize_core_config_public=lambda cfg: cfg,
        sse_marker_prefix='SSEMARK',
        download_report_endpoint='download_report',
    )
    async_run_monitor.register(
        app,
        runs_store={},
        maybe_copy_flow_artifacts_into_containers=lambda *args, **kwargs: None,
        sync_remote_artifacts=lambda meta: None,
        scenario_names_from_xml=lambda path: [],
        extract_report_path_from_text=lambda text: None,
        find_latest_report_path=lambda: None,
        extract_summary_path_from_text=lambda text: None,
        derive_summary_from_report=lambda report_path: None,
        find_latest_summary_path=lambda: None,
        outputs_dir=lambda: '/tmp/core-topo-gen-outputs',
        extract_session_id_from_text=lambda text: None,
        record_session_mapping=lambda *args, **kwargs: None,
        write_remote_session_scenario_meta=lambda *args, **kwargs: None,
        normalize_core_config=lambda cfg, **kwargs: cfg,
        load_run_history=lambda: [],
        select_core_config_for_page=lambda *args, **kwargs: {},
        merge_core_configs=lambda *args, **kwargs: {},
        grpc_save_current_session_xml_with_config=lambda *args, **kwargs: None,
        append_async_run_log_line=lambda meta, line: None,
        append_session_scenario_discrepancies=lambda *args, **kwargs: None,
        validate_session_nodes_and_injects=lambda *args, **kwargs: {'ok': True},
        coerce_bool=lambda value: bool(value),
        extract_async_error_from_text=lambda text: None,
        persist_execute_validation_artifacts=lambda *args, **kwargs: None,
        write_single_scenario_xml=lambda *args, **kwargs: None,
        build_full_scenario_archive=lambda *args, **kwargs: None,
        append_run_history=lambda entry: True,
        local_timestamp_display=lambda: '2026-01-01T00:00:00Z',
        close_async_run_tunnel=lambda meta: None,
        cleanup_remote_workspace=lambda meta: None,
        extract_docker_conflicts_from_text=lambda text: [],
        build_execute_error_logs=lambda *args, **kwargs: [],
        normalize_core_config_public=lambda cfg: cfg,
        sse_marker_prefix='SSEMARK',
        download_report_endpoint='download_report',
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/run_status/<run_id>' in rules
    assert '/stream/<run_id>' in rules
    assert '/cancel_run/<run_id>' in rules


def test_core_session_tools_register_is_idempotent():
    app = Flask(__name__)

    core_session_tools.register(
        app,
        outputs_dir=lambda: '/tmp/core-topo-gen-outputs',
        core_config_for_request=lambda **kwargs: {'host': '127.0.0.1', 'port': 50051},
        grpc_save_current_session_xml_with_config=lambda *args, **kwargs: None,
        extract_session_id_from_core_path=lambda text: None,
        load_run_history=lambda: [],
        current_user_getter=lambda: {'username': 'coreadmin'},
        scenario_catalog_for_user=lambda history, user=None: ([], {}, None),
        load_core_sessions_store=lambda: {},
        migrate_core_sessions_store_with_core_targets=lambda store, history: store,
        filter_core_sessions_store_for_core=lambda store, host, port: store,
        session_store_scenario_for_session_id=lambda *args, **kwargs: None,
        read_remote_session_scenario_meta=lambda *args, **kwargs: None,
        builder_allowed_norms=lambda user=None: None,
        resolve_scenario_display=lambda scenario_norm, scenario_names, scenario_query: scenario_query,
        normalize_scenario_label=lambda value: str(value).strip().lower(),
        list_active_core_sessions=lambda *args, **kwargs: [],
        validate_core_xml=lambda path: (True, ''),
        analyze_core_xml=lambda path: {},
        core_host_default='127.0.0.1',
        core_port_default=50051,
    )
    core_session_tools.register(
        app,
        outputs_dir=lambda: '/tmp/core-topo-gen-outputs',
        core_config_for_request=lambda **kwargs: {'host': '127.0.0.1', 'port': 50051},
        grpc_save_current_session_xml_with_config=lambda *args, **kwargs: None,
        extract_session_id_from_core_path=lambda text: None,
        load_run_history=lambda: [],
        current_user_getter=lambda: {'username': 'coreadmin'},
        scenario_catalog_for_user=lambda history, user=None: ([], {}, None),
        load_core_sessions_store=lambda: {},
        migrate_core_sessions_store_with_core_targets=lambda store, history: store,
        filter_core_sessions_store_for_core=lambda store, host, port: store,
        session_store_scenario_for_session_id=lambda *args, **kwargs: None,
        read_remote_session_scenario_meta=lambda *args, **kwargs: None,
        builder_allowed_norms=lambda user=None: None,
        resolve_scenario_display=lambda scenario_norm, scenario_names, scenario_query: scenario_query,
        normalize_scenario_label=lambda value: str(value).strip().lower(),
        list_active_core_sessions=lambda *args, **kwargs: [],
        validate_core_xml=lambda path: (True, ''),
        analyze_core_xml=lambda path: {},
        core_host_default='127.0.0.1',
        core_port_default=50051,
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/core/save_xml' in rules
    assert '/core/session_scenario' in rules
    assert '/core/session/<int:sid>' in rules


class _FakeParamikoModule:
    class SSHClient:
        def set_missing_host_key_policy(self, *_args, **_kwargs):
            return None

        def connect(self, **_kwargs):
            return None

        def exec_command(self, *_args, **_kwargs):
            raise RuntimeError('not used in registration test')

        def close(self):
            return None

    class AutoAddPolicy:
        pass


def test_core_venv_probe_register_is_idempotent():
    app = Flask(__name__)

    core_venv_probe.register(
        app,
        sanitize_venv_bin_path=lambda value: '/tmp/core/bin',
        ensure_paramiko_available=lambda: None,
        paramiko_getter=lambda: _FakeParamikoModule,
        python_executable_names=('core-python', 'python3', 'python'),
    )
    core_venv_probe.register(
        app,
        sanitize_venv_bin_path=lambda value: '/tmp/core/bin',
        ensure_paramiko_available=lambda: None,
        paramiko_getter=lambda: _FakeParamikoModule,
        python_executable_names=('core-python', 'python3', 'python'),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/test_core_venv' in rules


def test_generator_catalog_data_register_is_idempotent():
    app = Flask(__name__)

    generator_catalog_data.register(
        app,
        flag_generators_from_enabled_sources=lambda: ([], []),
        flag_node_generators_from_enabled_sources=lambda: ([], []),
        is_installed_generator_view=lambda gen: True,
        annotate_disabled_state=lambda generators, kind: generators,
    )
    generator_catalog_data.register(
        app,
        flag_generators_from_enabled_sources=lambda: ([], []),
        flag_node_generators_from_enabled_sources=lambda: ([], []),
        is_installed_generator_view=lambda gen: True,
        annotate_disabled_state=lambda generators, kind: generators,
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/flag_generators_data' in rules
    assert '/flag_node_generators_data' in rules


def test_generator_builder_routes_register_is_idempotent():
    app = Flask(__name__)

    generator_builder_routes.register(
        app,
        require_builder_or_admin=lambda: None,
        flag_generators_from_enabled_sources=lambda: ([], []),
        flag_node_generators_from_enabled_sources=lambda: ([], []),
        reserved_artifacts={},
        load_custom_artifacts=lambda: {},
        upsert_custom_artifact=lambda *args, **kwargs: {'artifact': 'demo'},
        build_generator_scaffold=lambda payload: ({'demo/manifest.yaml': 'x'}, 'manifest', 'demo'),
        sanitize_id=lambda value: 'demo',
        io_module=__import__('io'),
        zipfile_module=__import__('zipfile'),
    )
    generator_builder_routes.register(
        app,
        require_builder_or_admin=lambda: None,
        flag_generators_from_enabled_sources=lambda: ([], []),
        flag_node_generators_from_enabled_sources=lambda: ([], []),
        reserved_artifacts={},
        load_custom_artifacts=lambda: {},
        upsert_custom_artifact=lambda *args, **kwargs: {'artifact': 'demo'},
        build_generator_scaffold=lambda payload: ({'demo/manifest.yaml': 'x'}, 'manifest', 'demo'),
        sanitize_id=lambda value: 'demo',
        io_module=__import__('io'),
        zipfile_module=__import__('zipfile'),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/generator_builder' in rules
    assert '/api/generators/artifacts_index' in rules
    assert '/api/generators/artifacts_index/custom' in rules
    assert '/api/generators/scaffold_meta' in rules
    assert '/api/generators/scaffold_zip' in rules


def test_generator_pack_routes_register_is_idempotent():
    app = Flask(__name__)

    generator_pack_routes.register(
        app,
        install_generator_pack_or_bundle=lambda *args, **kwargs: (True, 'ok'),
        load_installed_generator_packs_state=lambda: {'packs': []},
        save_installed_generator_packs_state=lambda state: None,
        installed_generators_root=lambda: '/tmp/installed_generators',
        get_repo_root=lambda: '/tmp/repo',
        local_timestamp_display=lambda: '2026-03-19T00:00:00Z',
        local_timestamp_safe=lambda: '20260319-000000',
        compute_next_numeric_generator_id=lambda **kwargs: 1,
        install_generator_pack_payload=lambda **kwargs: (True, 'ok', [], 1, []),
        download_zip_from_url=lambda url: b'PK',
        pack_to_zip_bytes=lambda pack: b'PK',
        os_module=__import__('os'),
        tempfile_module=__import__('tempfile'),
        uuid_module=__import__('uuid'),
        shutil_module=__import__('shutil'),
        io_module=__import__('io'),
        zipfile_module=__import__('zipfile'),
    )
    generator_pack_routes.register(
        app,
        install_generator_pack_or_bundle=lambda *args, **kwargs: (True, 'ok'),
        load_installed_generator_packs_state=lambda: {'packs': []},
        save_installed_generator_packs_state=lambda state: None,
        installed_generators_root=lambda: '/tmp/installed_generators',
        get_repo_root=lambda: '/tmp/repo',
        local_timestamp_display=lambda: '2026-03-19T00:00:00Z',
        local_timestamp_safe=lambda: '20260319-000000',
        compute_next_numeric_generator_id=lambda **kwargs: 1,
        install_generator_pack_payload=lambda **kwargs: (True, 'ok', [], 1, []),
        download_zip_from_url=lambda url: b'PK',
        pack_to_zip_bytes=lambda pack: b'PK',
        os_module=__import__('os'),
        tempfile_module=__import__('tempfile'),
        uuid_module=__import__('uuid'),
        shutil_module=__import__('shutil'),
        io_module=__import__('io'),
        zipfile_module=__import__('zipfile'),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/generator_packs/upload' in rules
    assert '/generator_packs/import_url' in rules
    assert '/generator_packs/delete/<pack_id>' in rules
    assert '/generator_packs/download/<pack_id>' in rules
    assert '/generator_packs/export_all' in rules


def test_flag_catalog_pages_register_is_idempotent():
    app = Flask(__name__)

    flag_catalog_pages.register(
        app,
        load_installed_generator_packs_state=lambda: {'packs': []},
    )
    flag_catalog_pages.register(
        app,
        load_installed_generator_packs_state=lambda: {'packs': []},
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/flag_catalog' in rules
    assert '/data_sources' in rules


def test_vuln_catalog_overview_register_is_idempotent():
    app = Flask(__name__)

    vuln_catalog_overview.register(
        app,
        require_builder_or_admin=lambda: None,
        load_vuln_catalogs_state=lambda: {'catalogs': [], 'active_id': ''},
        get_active_vuln_catalog_entry=lambda state: None,
        normalize_vuln_catalog_items=lambda entry: [],
        vuln_catalog_pack_content_dir=lambda catalog_id: '/tmp/vuln-pack',
        safe_path_under=lambda base_dir, subpath: '/tmp/vuln-pack',
        get_repo_root=lambda: '/tmp/repo',
        load_vuln_catalog=lambda repo_root: [],
        os_module=__import__('os'),
    )
    vuln_catalog_overview.register(
        app,
        require_builder_or_admin=lambda: None,
        load_vuln_catalogs_state=lambda: {'catalogs': [], 'active_id': ''},
        get_active_vuln_catalog_entry=lambda state: None,
        normalize_vuln_catalog_items=lambda entry: [],
        vuln_catalog_pack_content_dir=lambda catalog_id: '/tmp/vuln-pack',
        safe_path_under=lambda base_dir, subpath: '/tmp/vuln-pack',
        get_repo_root=lambda: '/tmp/repo',
        load_vuln_catalog=lambda repo_root: [],
        os_module=__import__('os'),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/vuln_catalog_page' in rules
    assert '/vuln_catalog_items_data' in rules


def test_vuln_catalog_pack_files_register_is_idempotent():
    app = Flask(__name__)

    vuln_catalog_pack_files.register(
        app,
        require_builder_or_admin=lambda: None,
        vuln_catalog_pack_zip_path=lambda catalog_id: '/tmp/pack.zip',
        vuln_catalog_pack_content_dir=lambda catalog_id: '/tmp/pack',
        safe_path_under=lambda base_dir, subpath: '/tmp/pack',
        load_vuln_catalogs_state=lambda: {'catalogs': []},
        normalize_vuln_catalog_items=lambda entry: [],
        os_module=__import__('os'),
    )
    vuln_catalog_pack_files.register(
        app,
        require_builder_or_admin=lambda: None,
        vuln_catalog_pack_zip_path=lambda catalog_id: '/tmp/pack.zip',
        vuln_catalog_pack_content_dir=lambda catalog_id: '/tmp/pack',
        safe_path_under=lambda base_dir, subpath: '/tmp/pack',
        load_vuln_catalogs_state=lambda: {'catalogs': []},
        normalize_vuln_catalog_items=lambda entry: [],
        os_module=__import__('os'),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/vuln_catalog_packs/download/<catalog_id>' in rules
    assert '/vuln_catalog_packs/browse/<catalog_id>' in rules
    assert '/vuln_catalog_packs/browse/<catalog_id>/<path:subpath>' in rules
    assert '/vuln_catalog_packs/file/<catalog_id>/<path:subpath>' in rules
    assert '/vuln_catalog_packs/view/<catalog_id>/<path:subpath>' in rules
    assert '/vuln_catalog_packs/readme/<catalog_id>/<path:subpath>' in rules
    assert '/vuln_catalog_packs/item_files/<catalog_id>/<int:item_id>' in rules


def test_vuln_catalog_mutations_register_is_idempotent():
    app = Flask(__name__)

    @app.route('/vuln_catalog_page')
    def vuln_catalog_page():
        return 'ok'

    shutil_module = type('ShutilModule', (), {'rmtree': lambda self, path, ignore_errors=True: None})()

    vuln_catalog_mutations.register(
        app,
        require_builder_or_admin=lambda: None,
        load_vuln_catalogs_state=lambda: {'catalogs': []},
        write_vuln_catalogs_state=lambda state: None,
        get_active_vuln_catalog_entry=lambda state: None,
        normalize_vuln_catalog_items=lambda entry: [],
        write_vuln_catalog_csv_from_items=lambda **kwargs: [],
        vuln_catalog_pack_dir=lambda catalog_id: '/tmp/pack',
        shutil_module=shutil_module,
    )
    vuln_catalog_mutations.register(
        app,
        require_builder_or_admin=lambda: None,
        load_vuln_catalogs_state=lambda: {'catalogs': []},
        write_vuln_catalogs_state=lambda state: None,
        get_active_vuln_catalog_entry=lambda state: None,
        normalize_vuln_catalog_items=lambda entry: [],
        write_vuln_catalog_csv_from_items=lambda **kwargs: [],
        vuln_catalog_pack_dir=lambda catalog_id: '/tmp/pack',
        shutil_module=shutil_module,
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/vuln_catalog_packs/set_active/<catalog_id>' in rules
    assert '/vuln_catalog_packs/delete/<catalog_id>' in rules
    assert '/vuln_catalog_items/set_disabled' in rules
    assert '/vuln_catalog_items/delete' in rules


def test_vuln_catalog_pack_ingest_register_is_idempotent():
    app = Flask(__name__)

    @app.route('/vuln_catalog_page')
    def vuln_catalog_page():
        return 'ok'

    vuln_catalog_pack_ingest.register(
        app,
        require_builder_or_admin=lambda: None,
        install_vuln_catalog_zip_file=lambda **kwargs: {'id': 'cat-1'},
        install_vuln_catalog_zip_bytes=lambda **kwargs: {'id': 'cat-1'},
        is_safe_remote_zip_url=lambda url: (True, ''),
        download_zip_from_url=lambda url: b'PK',
        request_entity_too_large_type=RuntimeError,
        secure_filename_func=lambda value: value,
        tempfile_module=type('TempfileModule', (), {'NamedTemporaryFile': lambda self, **kwargs: None})(),
        os_module=__import__('os'),
        urlparse_func=lambda url: type('Parsed', (), {'path': '/demo.zip'})(),
    )
    vuln_catalog_pack_ingest.register(
        app,
        require_builder_or_admin=lambda: None,
        install_vuln_catalog_zip_file=lambda **kwargs: {'id': 'cat-1'},
        install_vuln_catalog_zip_bytes=lambda **kwargs: {'id': 'cat-1'},
        is_safe_remote_zip_url=lambda url: (True, ''),
        download_zip_from_url=lambda url: b'PK',
        request_entity_too_large_type=RuntimeError,
        secure_filename_func=lambda value: value,
        tempfile_module=type('TempfileModule', (), {'NamedTemporaryFile': lambda self, **kwargs: None})(),
        os_module=__import__('os'),
        urlparse_func=lambda url: type('Parsed', (), {'path': '/demo.zip'})(),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/vuln_catalog_packs/upload' in rules
    assert '/vuln_catalog_packs/import_url' in rules


def test_vuln_catalog_test_control_register_is_idempotent():
    app = Flask(__name__)

    vuln_catalog_test_control.register(
        app,
        require_builder_or_admin=lambda: None,
        runs_store={},
        stop_vuln_test_meta=lambda meta, user_ok: ('ok', 200),
    )
    vuln_catalog_test_control.register(
        app,
        require_builder_or_admin=lambda: None,
        runs_store={},
        stop_vuln_test_meta=lambda meta, user_ok: ('ok', 200),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/vuln_catalog_items/test/stop' in rules
    assert '/vuln_catalog_items/test/stop_active' in rules
    assert '/vuln_catalog_items/test/status' in rules


def test_vuln_catalog_test_start_register_is_idempotent():
    app = Flask(__name__)

    vuln_catalog_test_start.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )
    vuln_catalog_test_start.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/vuln_catalog_items/test/start' in rules


def test_generator_catalog_mutations_register_is_idempotent():
    app = Flask(__name__)
    app.secret_key = 'test-secret'

    @app.route('/flag_catalog')
    def flag_catalog_page():
        return 'ok'

    generator_catalog_mutations.register(
        app,
        require_builder_or_admin=lambda: None,
        set_pack_disabled_state=lambda **kwargs: (True, 'ok'),
        set_generator_disabled_state=lambda **kwargs: (True, 'ok'),
        delete_installed_generator=lambda **kwargs: (True, 'ok'),
    )
    generator_catalog_mutations.register(
        app,
        require_builder_or_admin=lambda: None,
        set_pack_disabled_state=lambda **kwargs: (True, 'ok'),
        set_generator_disabled_state=lambda **kwargs: (True, 'ok'),
        delete_installed_generator=lambda **kwargs: (True, 'ok'),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/generator_packs/set_disabled/<pack_id>' in rules
    assert '/api/flag_generators/delete' in rules
    assert '/api/flag_node_generators/delete' in rules
    assert '/api/generator_packs/set_disabled' in rules
    assert '/api/flag_generators/set_disabled' in rules
    assert '/api/flag_node_generators/set_disabled' in rules


def test_flag_sequencing_progress_register_is_idempotent():
    app = Flask(__name__)

    flag_sequencing_progress.register(
        app,
        outputs_dir=lambda: '/tmp/outputs',
        os_module=__import__('os'),
    )
    flag_sequencing_progress.register(
        app,
        outputs_dir=lambda: '/tmp/outputs',
        os_module=__import__('os'),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/flag-sequencing/flow_progress' in rules


def test_core_test_prepare_register_is_idempotent():
    app = Flask(__name__)

    core_test_prepare.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )
    core_test_prepare.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/test/core_sessions/prepare' in rules


def test_flag_sequencing_validation_register_is_idempotent():
    app = Flask(__name__)

    flag_sequencing_validation.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )
    flag_sequencing_validation.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/flag-sequencing/test_core_connection' in rules
    assert '/api/flag-sequencing/revalidate_flow' in rules


def test_flag_sequencing_substitutions_register_is_idempotent():
    app = Flask(__name__)

    flag_sequencing_substitutions.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )
    flag_sequencing_substitutions.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/flag-sequencing/save_flow_substitutions' in rules


def test_flag_sequencing_uploads_register_is_idempotent():
    app = Flask(__name__)

    flag_sequencing_uploads.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )
    flag_sequencing_uploads.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/flag-sequencing/upload_flow_input_file' in rules
    assert '/api/flag-sequencing/upload_flow_inject_file' in rules


def test_flag_sequencing_candidates_register_is_idempotent():
    app = Flask(__name__)

    flag_sequencing_candidates.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )
    flag_sequencing_candidates.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/flag-sequencing/substitution_candidates' in rules


def test_flag_sequencing_exports_register_is_idempotent():
    app = Flask(__name__)

    flag_sequencing_exports.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )
    flag_sequencing_exports.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/flag-sequencing/bundle_from_chain' in rules
    assert '/api/flag-sequencing/afb_from_chain' in rules
    assert '/api/flag-sequencing/attackflow' in rules


def test_flag_sequencing_state_register_is_idempotent():
    app = Flask(__name__)

    flag_sequencing_state.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )
    flag_sequencing_state.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/flag-sequencing/save_flow_state_to_xml' in rules


def test_flag_sequencing_values_register_is_idempotent():
    app = Flask(__name__)

    flag_sequencing_values.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )
    flag_sequencing_values.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/flag-sequencing/flag_values_for_node' in rules


def test_flag_sequencing_latest_preview_register_is_idempotent():
    app = Flask(__name__)

    flag_sequencing_latest_preview.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )
    flag_sequencing_latest_preview.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/flag-sequencing/latest_preview_plan' in rules


def test_flag_sequencing_sequence_preview_register_is_idempotent():
    app = Flask(__name__)

    flag_sequencing_sequence_preview.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )
    flag_sequencing_sequence_preview.register(
        app,
        backend_module=type('BackendModule', (), {})(),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/flag-sequencing/sequence_preview_plan' in rules


def test_flag_sequencing_attackflow_preview_register_is_idempotent():
    app = Flask(__name__)

    flag_sequencing_attackflow_preview.register(app, backend_module=type('BackendModule', (), {})())
    flag_sequencing_attackflow_preview.register(app, backend_module=type('BackendModule', (), {})())

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/flag-sequencing/attackflow_preview' in rules


def test_flag_sequencing_prepare_preview_register_is_idempotent():
    app = Flask(__name__)

    flag_sequencing_prepare_preview.register(app, backend_module=type('BackendModule', (), {})())
    flag_sequencing_prepare_preview.register(app, backend_module=type('BackendModule', (), {})())

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/flag-sequencing/prepare_preview_for_execute' in rules


def test_flag_sequencing_prepare_preview_route_delegates_to_module(monkeypatch):
    app = Flask(__name__)
    backend_module = type('BackendModule', (), {})()
    calls: list[object] = []

    def _fake_execute(*, backend):
        calls.append(backend)
        return ('delegated', 200)

    monkeypatch.setattr(flag_sequencing_prepare_preview.flow_prepare_preview_execute, 'execute', _fake_execute)

    flag_sequencing_prepare_preview.register(app, backend_module=backend_module)

    with app.test_client() as client:
        resp = client.post('/api/flag-sequencing/prepare_preview_for_execute', json={})

    assert resp.status_code == 200
    assert resp.get_data(as_text=True) == 'delegated'
    assert calls == [backend_module]


def test_backend_prepare_preview_wrapper_delegates_to_module(monkeypatch):
    from webapp import app_backend as backend
    from webapp import flow_prepare_preview_execute

    calls: list[object] = []

    def _fake_execute(*, backend):
        calls.append(backend)
        return 'delegated-backend-wrapper'

    monkeypatch.setattr(flow_prepare_preview_execute, 'execute', _fake_execute)

    result = backend._flow_prepare_preview_for_execute()

    assert result == 'delegated-backend-wrapper'
    assert calls == [backend]


def test_vuln_catalog_api_register_is_idempotent():
    app = Flask(__name__)

    vuln_catalog_api.register(
        app,
        load_vuln_catalogs_state=lambda: {'catalogs': []},
        get_active_vuln_catalog_entry=lambda state: None,
        normalize_vuln_catalog_items=lambda entry: [],
        vuln_catalog_item_abs_compose_path=lambda **kwargs: '/tmp/docker-compose.yml',
        os_module=__import__('os'),
    )
    vuln_catalog_api.register(
        app,
        load_vuln_catalogs_state=lambda: {'catalogs': []},
        get_active_vuln_catalog_entry=lambda state: None,
        normalize_vuln_catalog_items=lambda entry: [],
        vuln_catalog_item_abs_compose_path=lambda **kwargs: '/tmp/docker-compose.yml',
        os_module=__import__('os'),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/vuln_catalog' in rules


def test_core_details_register_is_idempotent():
    app = Flask(__name__)

    core_details.register(
        app,
        normalize_scenario_label=lambda value: str(value).strip().lower(),
        load_run_history=lambda: [],
        current_user_getter=lambda: {'username': 'coreadmin'},
        scenario_catalog_for_user=lambda history, user=None: ([], {}, None),
        resolve_scenario_display=lambda scenario_norm, scenario_names, scenario_query: scenario_query,
        core_config_for_request=lambda **kwargs: {'host': '127.0.0.1', 'port': 50051},
        uploads_dir=lambda: '/tmp/core-topo-gen-uploads',
        outputs_dir=lambda: '/tmp/core-topo-gen-outputs',
        grpc_save_current_session_xml_with_config=lambda *args, **kwargs: None,
        select_existing_path=lambda candidates: None,
        summarize_planner_scenarios=lambda path: {},
        validate_core_xml=lambda path: (True, ''),
        analyze_core_xml=lambda path: {},
        build_topology_graph_from_session_xml=lambda path: ([], [], {}),
        flow_state_from_latest_xml=lambda scenario_norm: None,
        list_active_core_sessions=lambda *args, **kwargs: [],
        latest_session_xml_for_scenario_norm=lambda scenario_norm: None,
        builder_allowed_norms=lambda user=None: None,
        latest_preview_plan_for_scenario_norm=lambda *args, **kwargs: None,
        load_preview_payload_from_path=lambda *args, **kwargs: None,
        build_topology_graph_from_preview_plan=lambda preview: ([], [], {}),
        core_host_default='127.0.0.1',
        core_port_default=50051,
    )
    core_details.register(
        app,
        normalize_scenario_label=lambda value: str(value).strip().lower(),
        load_run_history=lambda: [],
        current_user_getter=lambda: {'username': 'coreadmin'},
        scenario_catalog_for_user=lambda history, user=None: ([], {}, None),
        resolve_scenario_display=lambda scenario_norm, scenario_names, scenario_query: scenario_query,
        core_config_for_request=lambda **kwargs: {'host': '127.0.0.1', 'port': 50051},
        uploads_dir=lambda: '/tmp/core-topo-gen-uploads',
        outputs_dir=lambda: '/tmp/core-topo-gen-outputs',
        grpc_save_current_session_xml_with_config=lambda *args, **kwargs: None,
        select_existing_path=lambda candidates: None,
        summarize_planner_scenarios=lambda path: {},
        validate_core_xml=lambda path: (True, ''),
        analyze_core_xml=lambda path: {},
        build_topology_graph_from_session_xml=lambda path: ([], [], {}),
        flow_state_from_latest_xml=lambda scenario_norm: None,
        list_active_core_sessions=lambda *args, **kwargs: [],
        latest_session_xml_for_scenario_norm=lambda scenario_norm: None,
        builder_allowed_norms=lambda user=None: None,
        latest_preview_plan_for_scenario_norm=lambda *args, **kwargs: None,
        load_preview_payload_from_path=lambda *args, **kwargs: None,
        build_topology_graph_from_preview_plan=lambda preview: ([], [], {}),
        core_host_default='127.0.0.1',
        core_port_default=50051,
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/core/details' in rules
    assert '/api/core-details/topology' in rules


def test_core_session_actions_register_is_idempotent():
    app = Flask(__name__)

    core_session_actions.register(
        app,
        redirect_core_page_with_scenario=lambda **kwargs: None,
        core_config_for_request=lambda **kwargs: {'host': '127.0.0.1', 'port': 50051},
        execute_remote_core_session_action=lambda *args, **kwargs: None,
        uploads_dir=lambda: '/tmp/core-topo-gen-uploads',
        outputs_dir=lambda: '/tmp/core-topo-gen-outputs',
        update_xml_session_mapping=lambda path, session_id: None,
    )
    core_session_actions.register(
        app,
        redirect_core_page_with_scenario=lambda **kwargs: None,
        core_config_for_request=lambda **kwargs: {'host': '127.0.0.1', 'port': 50051},
        execute_remote_core_session_action=lambda *args, **kwargs: None,
        uploads_dir=lambda: '/tmp/core-topo-gen-uploads',
        outputs_dir=lambda: '/tmp/core-topo-gen-outputs',
        update_xml_session_mapping=lambda path, session_id: None,
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/core/start_session' in rules
    assert '/core/delete' in rules


def test_core_execute_support_register_is_idempotent():
    app = Flask(__name__)

    core_execute_support.register(
        app,
        core_config_for_request=lambda **kwargs: {'host': '127.0.0.1', 'port': 50051},
        list_active_core_sessions=lambda *args, **kwargs: [],
        execute_remote_core_session_action=lambda *args, **kwargs: None,
        ensure_paramiko_available=lambda: None,
        paramiko_getter=lambda: _FakeParamikoModule,
        collect_remote_core_daemon_pids=lambda ssh_client: [],
        stop_remote_core_daemon_conflict=lambda *args, **kwargs: None,
        core_host_default='127.0.0.1',
        core_port_default=50051,
    )
    core_execute_support.register(
        app,
        core_config_for_request=lambda **kwargs: {'host': '127.0.0.1', 'port': 50051},
        list_active_core_sessions=lambda *args, **kwargs: [],
        execute_remote_core_session_action=lambda *args, **kwargs: None,
        ensure_paramiko_available=lambda: None,
        paramiko_getter=lambda: _FakeParamikoModule,
        collect_remote_core_daemon_pids=lambda ssh_client: [],
        stop_remote_core_daemon_conflict=lambda *args, **kwargs: None,
        core_host_default='127.0.0.1',
        core_port_default=50051,
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/core/kill_active_sessions_api' in rules
    assert '/core/stop_duplicate_daemons_api' in rules


def test_proxmox_register_is_idempotent():
    app = Flask(__name__)

    proxmox.register(
        app,
        current_user_getter=lambda: {'role': 'admin'},
        normalize_role_value=lambda role: str(role or '').strip().lower(),
        proxmox_api_getter=lambda: object,
        urlparse_func=lambda value: __import__('urllib.parse').parse.urlparse(value),
        coerce_bool=lambda value: bool(value),
        load_proxmox_credentials=lambda secret_id: None,
        save_proxmox_credentials=lambda payload: {'identifier': 'secret', **payload, 'stored_at': 'now'},
        delete_proxmox_credentials=lambda secret_id: bool(secret_id),
        enumerate_proxmox_vms=lambda secret_id: [],
        merge_hitl_validation_into_scenario_catalog=lambda *args, **kwargs: None,
        clear_hitl_validation_in_scenario_catalog=lambda *args, **kwargs: None,
        local_timestamp_display=lambda: 'now',
    )
    proxmox.register(
        app,
        current_user_getter=lambda: {'role': 'admin'},
        normalize_role_value=lambda role: str(role or '').strip().lower(),
        proxmox_api_getter=lambda: object,
        urlparse_func=lambda value: __import__('urllib.parse').parse.urlparse(value),
        coerce_bool=lambda value: bool(value),
        load_proxmox_credentials=lambda secret_id: None,
        save_proxmox_credentials=lambda payload: {'identifier': 'secret', **payload, 'stored_at': 'now'},
        delete_proxmox_credentials=lambda secret_id: bool(secret_id),
        enumerate_proxmox_vms=lambda secret_id: [],
        merge_hitl_validation_into_scenario_catalog=lambda *args, **kwargs: None,
        clear_hitl_validation_in_scenario_catalog=lambda *args, **kwargs: None,
        local_timestamp_display=lambda: 'now',
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/proxmox/validate' in rules
    assert '/api/proxmox/clear' in rules
    assert '/api/proxmox/credentials/get' in rules
    assert '/api/proxmox/vms' in rules


def test_hitl_clear_register_is_idempotent():
    app = Flask(__name__)

    hitl_clear.register(
        app,
        current_user_getter=lambda: {'role': 'admin'},
        normalize_role_value=lambda role: str(role or '').strip().lower(),
        clear_hitl_config_in_scenario_catalog=lambda *args, **kwargs: None,
    )
    hitl_clear.register(
        app,
        current_user_getter=lambda: {'role': 'admin'},
        normalize_role_value=lambda role: str(role or '').strip().lower(),
        clear_hitl_config_in_scenario_catalog=lambda *args, **kwargs: None,
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/hitl/core_vm/clear' in rules
    assert '/api/hitl/config/clear' in rules


def test_hitl_bridge_register_is_idempotent():
    app = Flask(__name__)

    hitl_bridge.register(
        app,
        current_user_getter=lambda: {'role': 'admin'},
        normalize_role_value=lambda role: str(role or '').strip().lower(),
        normalize_internal_bridge_name=lambda value: str(value),
        normalize_hitl_attachment=lambda value: str(value or ''),
        parse_proxmox_vm_key=lambda value: ('node1', 100),
        connect_proxmox_from_secret=lambda secret_id: (object(), {'identifier': secret_id}),
        ensure_proxmox_bridge=lambda *args, **kwargs: {'created': False, 'already_exists': True, 'reload_ok': True, 'reload_error': None},
        rewrite_bridge_in_net_config=lambda net_config, bridge_name: (net_config, False, bridge_name),
        merge_hitl_config_into_scenario_catalog=lambda *args, **kwargs: None,
    )
    hitl_bridge.register(
        app,
        current_user_getter=lambda: {'role': 'admin'},
        normalize_role_value=lambda role: str(role or '').strip().lower(),
        normalize_internal_bridge_name=lambda value: str(value),
        normalize_hitl_attachment=lambda value: str(value or ''),
        parse_proxmox_vm_key=lambda value: ('node1', 100),
        connect_proxmox_from_secret=lambda secret_id: (object(), {'identifier': secret_id}),
        ensure_proxmox_bridge=lambda *args, **kwargs: {'created': False, 'already_exists': True, 'reload_ok': True, 'reload_error': None},
        rewrite_bridge_in_net_config=lambda net_config, bridge_name: (net_config, False, bridge_name),
        merge_hitl_config_into_scenario_catalog=lambda *args, **kwargs: None,
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/hitl/apply_bridge' in rules
    assert '/api/hitl/validate_bridge' in rules


def test_planner_register_is_idempotent():
    app = Flask(__name__)

    planner.register(
        app,
        planner_persist_flow_plan=lambda **kwargs: {
            'xml_path': kwargs.get('xml_path'),
            'scenario': kwargs.get('scenario'),
            'seed': kwargs.get('seed'),
            'preview_plan_path': '/tmp/preview-plan.json',
        },
        normalize_scenario_label=lambda value: str(value or '').strip(),
        latest_xml_path_for_scenario=lambda scenario_name: f'/tmp/{scenario_name}.xml',
    )
    planner.register(
        app,
        planner_persist_flow_plan=lambda **kwargs: {
            'xml_path': kwargs.get('xml_path'),
            'scenario': kwargs.get('scenario'),
            'seed': kwargs.get('seed'),
            'preview_plan_path': '/tmp/preview-plan.json',
        },
        normalize_scenario_label=lambda value: str(value or '').strip(),
        latest_xml_path_for_scenario=lambda scenario_name: f'/tmp/{scenario_name}.xml',
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/planner/ensure_plan' in rules
    assert '/api/planner/latest_plan' in rules


def test_plan_preview_api_register_is_idempotent():
    app = Flask(__name__)

    backend_module = object()

    plan_preview_api.register(app, backend_module=backend_module)
    plan_preview_api.register(app, backend_module=backend_module)

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    endpoints = {rule.endpoint for rule in app.url_map.iter_rules()}
    assert '/api/plan/preview_full' in rules
    assert '/api/plan/persist_flow_plan' in rules
    assert 'api_plan_preview_full' in endpoints
    assert 'api_plan_persist_flow_plan' in endpoints


def test_plan_preview_pages_register_is_idempotent():
    app = Flask(__name__)

    backend_module = type(
        'BackendModule',
        (),
        {
            '_outputs_dir': staticmethod(lambda: '/tmp'),
        },
    )()

    plan_preview_pages.register(app, backend_module=backend_module)
    plan_preview_pages.register(app, backend_module=backend_module)

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    endpoints = {rule.endpoint for rule in app.url_map.iter_rules()}
    assert '/plan/full_preview_page' in rules
    assert '/plan/full_preview_from_plan' in rules
    assert '/plan/full_preview_from_xml' in rules
    assert 'plan_full_preview_page' in endpoints
    assert 'plan_full_preview_from_plan' in endpoints
    assert 'plan_full_preview_from_xml' in endpoints


def test_webui_logs_register_is_idempotent():
    app = Flask(__name__)

    webui_logs.register(
        app,
        current_user_getter=lambda: {'role': 'admin'},
        normalize_role_value=lambda role: str(role or '').strip().lower(),
        webui_log_path_getter=lambda: '/tmp/webui.log',
    )
    webui_logs.register(
        app,
        current_user_getter=lambda: {'role': 'admin'},
        normalize_role_value=lambda role: str(role or '').strip().lower(),
        webui_log_path_getter=lambda: '/tmp/webui.log',
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/api/webui/log_tail' in rules
    assert '/api/webui/log_clear' in rules


def test_docker_routes_register_is_idempotent():
    app = Flask(__name__)

    docker_routes.register(
        app,
        load_run_history=lambda: [],
        current_user_getter=lambda: {'role': 'admin'},
        scenario_catalog_for_user=lambda history, user=None: ([], {}, {}),
        normalize_scenario_label=lambda value: str(value or '').strip(),
        select_core_config_for_page=lambda *args, **kwargs: {},
        ensure_core_vm_metadata=lambda config: config,
        run_remote_python_json=lambda *args, **kwargs: {'items': [], 'timestamp': 0},
        remote_docker_status_script_builder=lambda password: 'print(1)',
        remote_docker_cleanup_script_builder=lambda names, password: 'print(1)',
    )
    docker_routes.register(
        app,
        load_run_history=lambda: [],
        current_user_getter=lambda: {'role': 'admin'},
        scenario_catalog_for_user=lambda history, user=None: ([], {}, {}),
        normalize_scenario_label=lambda value: str(value or '').strip(),
        select_core_config_for_page=lambda *args, **kwargs: {},
        ensure_core_vm_metadata=lambda config: config,
        run_remote_python_json=lambda *args, **kwargs: {'items': [], 'timestamp': 0},
        remote_docker_status_script_builder=lambda password: 'print(1)',
        remote_docker_cleanup_script_builder=lambda names, password: 'print(1)',
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/docker/status' in rules
    assert '/docker/compose_text' in rules
    assert '/docker/cleanup' in rules


def test_reports_downloads_register_is_idempotent():
    app = Flask(__name__)

    reports_downloads.register(
        app,
        get_repo_root=lambda: '/tmp/repo',
        outputs_dir=lambda: '/tmp/outputs',
        load_run_history=lambda: [],
        derive_summary_from_report=lambda path: None,
        load_summary_counts=lambda path: {},
        summary_text_from_counts=lambda counts: '',
        current_user_getter=lambda: {'role': 'admin'},
        scenario_catalog_for_user=lambda history, user=None: ([], {}, {}),
        collect_scenario_participant_urls=lambda paths, hints: {},
        normalize_scenario_label=lambda value: str(value or '').strip(),
        builder_filter_report_scenarios=lambda scenarios, active, user=None: (scenarios, active, []),
        filter_history_by_scenario=lambda history, scenario: history,
        resolve_scenario_display=lambda active, scenarios, query: active or query,
        scenario_names_from_xml=lambda path: [],
        run_history_path='/tmp/run_history.json',
    )
    reports_downloads.register(
        app,
        get_repo_root=lambda: '/tmp/repo',
        outputs_dir=lambda: '/tmp/outputs',
        load_run_history=lambda: [],
        derive_summary_from_report=lambda path: None,
        load_summary_counts=lambda path: {},
        summary_text_from_counts=lambda counts: '',
        current_user_getter=lambda: {'role': 'admin'},
        scenario_catalog_for_user=lambda history, user=None: ([], {}, {}),
        collect_scenario_participant_urls=lambda paths, hints: {},
        normalize_scenario_label=lambda value: str(value or '').strip(),
        builder_filter_report_scenarios=lambda scenarios, active, user=None: (scenarios, active, []),
        filter_history_by_scenario=lambda history, scenario: history,
        resolve_scenario_display=lambda active, scenarios, query: active or query,
        scenario_names_from_xml=lambda path: [],
        run_history_path='/tmp/run_history.json',
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/download_report' in rules
    assert '/reports' in rules
    assert '/reports_data' in rules
    assert '/reports/delete' in rules


def test_participant_ui_register_is_idempotent():
    app = Flask(__name__)

    participant_ui.register(
        app,
        participant_ui_state_getter=lambda: {'listing': [], 'selected_norm': '', 'selected_url': '', 'selected_label': '', 'selected_nearest_gateway': ''},
        normalize_scenario_label=lambda value: str(value or '').strip(),
        normalize_participant_proxmox_url=lambda value: str(value or '').strip(),
        load_run_history=lambda: [],
        latest_run_history_for_scenario=lambda scenario_norm, history=None: None,
        hitl_details_from_path=lambda path: [],
        scenario_catalog_for_user=lambda *args, **kwargs: ([], {}, {}),
        current_user_getter=lambda: {'role': 'admin'},
        nearest_gateway_address_for_scenario=lambda *args, **kwargs: '',
        load_participant_ui_stats=lambda: {'totals': {}, 'scenarios': {}},
        save_participant_ui_stats=lambda payload: None,
        local_timestamp_display=lambda: 'now',
        format_local_timestamp=lambda raw: str(raw or ''),
        load_summary_counts=lambda summary_path: {},
        load_summary_metadata=lambda summary_path: {},
        subnet_cidrs_from_session_xml=lambda session_xml_path: [],
        vulnerability_ipv4s_from_session_xml=lambda session_xml_path: [],
        counts_from_session_xml=lambda session_xml_path: {},
        recent_session_id_for_scenario=lambda *args, **kwargs: (None, 0.0),
        live_core_session_status_for_scenario=lambda *args, **kwargs: None,
        flow_state_from_latest_xml=lambda scenario_norm: None,
        latest_session_xml_for_scenario_norm=lambda scenario_norm: None,
        build_topology_graph_from_session_xml=lambda xml_path: ([], [], None),
    )
    participant_ui.register(
        app,
        participant_ui_state_getter=lambda: {'listing': [], 'selected_norm': '', 'selected_url': '', 'selected_label': '', 'selected_nearest_gateway': ''},
        normalize_scenario_label=lambda value: str(value or '').strip(),
        normalize_participant_proxmox_url=lambda value: str(value or '').strip(),
        load_run_history=lambda: [],
        latest_run_history_for_scenario=lambda scenario_norm, history=None: None,
        hitl_details_from_path=lambda path: [],
        scenario_catalog_for_user=lambda *args, **kwargs: ([], {}, {}),
        current_user_getter=lambda: {'role': 'admin'},
        nearest_gateway_address_for_scenario=lambda *args, **kwargs: '',
        load_participant_ui_stats=lambda: {'totals': {}, 'scenarios': {}},
        save_participant_ui_stats=lambda payload: None,
        local_timestamp_display=lambda: 'now',
        format_local_timestamp=lambda raw: str(raw or ''),
        load_summary_counts=lambda summary_path: {},
        load_summary_metadata=lambda summary_path: {},
        subnet_cidrs_from_session_xml=lambda session_xml_path: [],
        vulnerability_ipv4s_from_session_xml=lambda session_xml_path: [],
        counts_from_session_xml=lambda session_xml_path: {},
        recent_session_id_for_scenario=lambda *args, **kwargs: (None, 0.0),
        live_core_session_status_for_scenario=lambda *args, **kwargs: None,
        flow_state_from_latest_xml=lambda scenario_norm: None,
        latest_session_xml_for_scenario_norm=lambda scenario_norm: None,
        build_topology_graph_from_session_xml=lambda xml_path: ([], [], None),
    )

    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert '/participant-ui' in rules
    assert '/participant-ui/gateway' in rules
    assert '/participant-ui/details' in rules
    assert '/participant-ui/topology' in rules
    assert '/participant-ui/stats' in rules
    assert '/participant-ui/record-open' in rules
    assert '/participant-ui/open' in rules