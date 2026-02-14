from webapp import app_backend as backend


def _patch_validation_dependencies(monkeypatch):
    monkeypatch.setattr(backend, '_expected_from_plan_preview', lambda *a, **k: {})
    monkeypatch.setattr(backend, '_parse_session_xml_for_compare', lambda *a, **k: {})
    monkeypatch.setattr(backend, '_extract_inject_specs_from_flow_state', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_inject_expected_by_node', lambda *a, **k: {})
    monkeypatch.setattr(backend, '_extract_inject_dirs_from_plan_xml', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_inject_files_from_plan_xml', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_expected_docker_and_vuln_nodes_from_plan_xml', lambda *a, **k: ([], []))
    monkeypatch.setattr(backend, '_session_docker_nodes_from_xml', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_run_remote_python_json', lambda *a, **k: {'items': []})


def test_validate_flow_live_paths_flags_local_missing(monkeypatch):
    _patch_validation_dependencies(monkeypatch)
    monkeypatch.setattr(backend.os.path, 'exists', lambda p: str(p).strip() == '/tmp/vulns/mount-ok')

    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '7',
                    'id': 'nfs_sensitive_file',
                    'resolved_paths': {
                        'artifacts_dir': {
                            'path': '/tmp/vulns/missing-artifacts',
                            'is_remote': False,
                        },
                        'mount_dir': {
                            'path': '/tmp/vulns/mount-ok',
                            'is_remote': False,
                        },
                        'inject_sources': [],
                    },
                }
            ]
        },
    )

    summary = backend._validate_session_nodes_and_injects(
        scenario_xml_path='/tmp/scenario.xml',
        session_xml_path='/tmp/session.xml',
        core_cfg={},
        preview_plan_path=None,
        scenario_label='NewScenario1',
    )

    assert summary.get('flow_live_paths_checked') == 2
    assert summary.get('flow_live_paths_missing_count') == 1
    missing = summary.get('flow_live_paths_missing') or []
    assert any('artifacts_dir' in str(item) for item in missing)
    assert summary.get('ok') is False


def test_validate_flow_live_paths_ignores_remote_missing(monkeypatch):
    _patch_validation_dependencies(monkeypatch)
    monkeypatch.setattr(backend.os.path, 'exists', lambda p: False)

    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '9',
                    'id': 'remote_flow_gen',
                    'resolved_paths': {
                        'artifacts_dir': {
                            'path': '/tmp/vulns/remote-artifacts',
                            'is_remote': True,
                        },
                        'mount_dir': {
                            'path': '/tmp/vulns/remote-mount',
                            'is_remote': True,
                        },
                        'inject_sources': [
                            {
                                'path': '/tmp/vulns/remote-source',
                                'is_remote': True,
                            }
                        ],
                    },
                }
            ]
        },
    )

    summary = backend._validate_session_nodes_and_injects(
        scenario_xml_path='/tmp/scenario.xml',
        session_xml_path='/tmp/session.xml',
        core_cfg={},
        preview_plan_path=None,
        scenario_label='NewScenario1',
    )

    assert summary.get('flow_live_paths_checked') == 3
    assert summary.get('flow_live_paths_missing_count') == 0
    assert summary.get('flow_live_paths_missing') == []
    assert summary.get('ok') is True


def test_validate_injects_missing_respects_per_node_expectations(monkeypatch):
    monkeypatch.setattr(backend, '_expected_from_plan_preview', lambda *a, **k: {5: {'name': 'docker-5'}})
    monkeypatch.setattr(backend, '_parse_session_xml_for_compare', lambda *a, **k: {})
    monkeypatch.setattr(backend, '_extract_inject_specs_from_flow_state', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_inject_expected_by_node', lambda *a, **k: {'docker-1': ['/tmp/secrets.txt']})
    monkeypatch.setattr(backend, '_extract_inject_dirs_from_plan_xml', lambda *a, **k: ['/tmp'])
    monkeypatch.setattr(backend, '_extract_inject_files_from_plan_xml', lambda *a, **k: ['/tmp/secrets.txt'])
    monkeypatch.setattr(backend, '_extract_expected_docker_and_vuln_nodes_from_plan_xml', lambda *a, **k: ([], []))
    monkeypatch.setattr(backend, '_session_docker_nodes_from_xml', lambda *a, **k: ['docker-5'])
    monkeypatch.setattr(backend, '_extract_inject_node_ids_from_flow_state', lambda *a, **k: {5})
    monkeypatch.setattr(backend, '_flow_state_from_xml_path', lambda *a, **k: {'flag_assignments': []})

    def _fake_remote_json(_cfg, _script, logger=None, label='', timeout=0):
        if label == 'docker.exec.injects_status':
            return {
                'items': [
                    {
                        'container': 'docker-5',
                        'exists': True,
                        'running': True,
                        'inject_count': 0,
                        'inject_samples': [],
                        'inject_dirs_found': [],
                        'debug_logs': [],
                    }
                ]
            }
        if label == 'docker.compose.assignments':
            return {'nodes': []}
        if label == 'flow.artifacts.validate':
            return {'items': []}
        return {'items': []}

    monkeypatch.setattr(backend, '_run_remote_python_json', _fake_remote_json)

    summary = backend._validate_session_nodes_and_injects(
        scenario_xml_path='/tmp/scenario.xml',
        session_xml_path='/tmp/session.xml',
        core_cfg={'ssh_enabled': True},
        preview_plan_path=None,
        scenario_label='NewScenario1',
    )

    assert summary.get('injects_missing') == []


def test_validate_non_running_container_not_counted_as_missing_inject(monkeypatch):
    monkeypatch.setattr(backend, '_expected_from_plan_preview', lambda *a, **k: {3: {'name': 'docker-3'}})
    monkeypatch.setattr(backend, '_parse_session_xml_for_compare', lambda *a, **k: {})
    monkeypatch.setattr(backend, '_extract_inject_specs_from_flow_state', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_inject_expected_by_node', lambda *a, **k: {'docker-3': ['/tmp/challenge.txt']})
    monkeypatch.setattr(backend, '_extract_inject_dirs_from_plan_xml', lambda *a, **k: ['/tmp'])
    monkeypatch.setattr(backend, '_extract_inject_files_from_plan_xml', lambda *a, **k: ['/tmp/challenge.txt'])
    monkeypatch.setattr(backend, '_extract_expected_docker_and_vuln_nodes_from_plan_xml', lambda *a, **k: ([], []))
    monkeypatch.setattr(backend, '_session_docker_nodes_from_xml', lambda *a, **k: ['docker-3'])
    monkeypatch.setattr(backend, '_extract_inject_node_ids_from_flow_state', lambda *a, **k: {3})
    monkeypatch.setattr(backend, '_flow_state_from_xml_path', lambda *a, **k: {'flag_assignments': []})

    def _fake_remote_json(_cfg, _script, logger=None, label='', timeout=0):
        if label == 'docker.exec.injects_status':
            return {
                'items': [
                    {
                        'container': 'docker-3',
                        'exists': True,
                        'running': False,
                        'state_status': 'exited',
                        'state_exit_code': 1,
                        'state_error': '',
                        'inject_count': 0,
                        'inject_samples': [
                            'Error response from daemon: container deadbeef is not running'
                        ],
                        'inject_dirs_found': [],
                        'debug_logs': [],
                    }
                ]
            }
        if label == 'docker.compose.assignments':
            return {'nodes': []}
        if label == 'flow.artifacts.validate':
            return {'items': []}
        return {'items': []}

    monkeypatch.setattr(backend, '_run_remote_python_json', _fake_remote_json)

    summary = backend._validate_session_nodes_and_injects(
        scenario_xml_path='/tmp/scenario.xml',
        session_xml_path='/tmp/session.xml',
        core_cfg={'ssh_enabled': True},
        preview_plan_path=None,
        scenario_label='NewScenario1',
    )

    assert summary.get('docker_not_running') == ['docker-3']
    details = summary.get('docker_not_running_details') or []
    assert details and details[0].get('container') == 'docker-3'
    assert details[0].get('status') == 'exited'
    assert details[0].get('exit_code') == 1
    assert summary.get('injects_missing') == []
    injects_detail = summary.get('injects_detail') or []
    assert any('docker-3: not running' in str(line) for line in injects_detail)
    assert not any('docker-3: 0 file(s)' in str(line) for line in injects_detail)


def test_validate_flow_enabled_without_per_node_expectations_does_not_require_all_nodes(monkeypatch):
    monkeypatch.setattr(backend, '_expected_from_plan_preview', lambda *a, **k: {})
    monkeypatch.setattr(backend, '_parse_session_xml_for_compare', lambda *a, **k: {})
    monkeypatch.setattr(backend, '_extract_inject_specs_from_flow_state', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_inject_expected_by_node', lambda *a, **k: {})
    monkeypatch.setattr(backend, '_extract_inject_dirs_from_plan_xml', lambda *a, **k: ['/tmp'])
    monkeypatch.setattr(backend, '_extract_inject_files_from_plan_xml', lambda *a, **k: ['/tmp/expected.txt'])
    monkeypatch.setattr(backend, '_extract_expected_docker_and_vuln_nodes_from_plan_xml', lambda *a, **k: ([], []))
    monkeypatch.setattr(backend, '_session_docker_nodes_from_xml', lambda *a, **k: ['docker-1', 'docker-2', 'docker-4', 'docker-5'])
    monkeypatch.setattr(backend, '_extract_inject_node_ids_from_flow_state', lambda *a, **k: set())
    monkeypatch.setattr(backend, '_flow_state_from_xml_path', lambda *a, **k: {'flag_assignments': []})

    def _fake_remote_json(_cfg, _script, logger=None, label='', timeout=0):
        if label == 'docker.exec.injects_status':
            return {
                'items': [
                    {'container': 'docker-1', 'exists': True, 'running': True, 'inject_count': 0, 'inject_samples': [], 'inject_dirs_found': [], 'debug_logs': []},
                    {'container': 'docker-2', 'exists': True, 'running': True, 'inject_count': 0, 'inject_samples': [], 'inject_dirs_found': [], 'debug_logs': []},
                    {'container': 'docker-4', 'exists': True, 'running': True, 'inject_count': 0, 'inject_samples': [], 'inject_dirs_found': [], 'debug_logs': []},
                    {'container': 'docker-5', 'exists': True, 'running': True, 'inject_count': 0, 'inject_samples': [], 'inject_dirs_found': [], 'debug_logs': []},
                ]
            }
        if label == 'docker.compose.assignments':
            return {'nodes': []}
        if label == 'flow.artifacts.validate':
            return {'items': []}
        return {'items': []}

    monkeypatch.setattr(backend, '_run_remote_python_json', _fake_remote_json)

    summary = backend._validate_session_nodes_and_injects(
        scenario_xml_path='/tmp/scenario.xml',
        session_xml_path='/tmp/session.xml',
        core_cfg={'ssh_enabled': True},
        preview_plan_path=None,
        scenario_label='NewScenario1',
        flow_enabled=True,
    )

    assert summary.get('injects_missing') == []
