from webapp import app_backend as backend


def test_extract_inject_expected_by_node_maps_absolute_source_to_tmp(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '7',
                    'inject_files': ['/Users/me/project/exports', '/opt/data/seed.txt'],
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {7: {'name': 'docker-1'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert 'docker-1' in out
    assert '/exports' in out['docker-1']
    assert '/tmp/seed.txt' in out['docker-1']
    assert all(not str(p).startswith('/Users/') for p in out['docker-1'])


def test_extract_inject_expected_by_node_normalizes_detail_absolute_paths(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '9',
                    'inject_files_detail': [
                        {'path': '/Users/me/project/File(path)'},
                        {'path': '/exports'},
                    ],
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {9: {'name': 'docker-9'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert 'docker-9' in out
    assert '/tmp/File(path)' not in out['docker-9']
    assert '/exports' in out['docker-9']
    assert all(not str(p).startswith('/Users/') for p in out['docker-9'])


def test_extract_inject_expected_by_node_maps_tmp_vulns_source_to_tmp_basename(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '6',
                    'inject_files': ['File(path)'],
                    'resolved_paths': {
                        'inject_sources': [
                            {'path': '/tmp/vulns/flag_generators_runs/run1/artifacts/secrets.txt', 'is_remote': True},
                        ]
                    },
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {6: {'name': 'docker-1'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert 'docker-1' in out
    assert out['docker-1'] == ['/tmp/secrets.txt']


def test_extract_inject_expected_by_node_prefers_resolved_runtime_sources(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '5',
                    'inject_files': ['exports'],
                    'resolved_paths': {
                        'inject_sources': [
                            {'path': '/exports', 'is_remote': True},
                        ]
                    },
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {5: {'name': 'docker-5'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert 'docker-5' in out
    assert '/exports' in out['docker-5']


def test_extract_inject_expected_by_node_resolved_sources_override_detail(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '5',
                    'inject_files': ['exports'],
                    'inject_files_detail': [
                        {'path': '/tmp/exports'},
                    ],
                    'resolved_paths': {
                        'inject_sources': [
                            {'path': '/exports', 'is_remote': True},
                        ]
                    },
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {5: {'name': 'docker-5'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert 'docker-5' in out
    assert out['docker-5'] == ['/exports']


def test_extract_inject_expected_by_node_ignores_resolved_sources_without_inject_intent(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '5',
                    'inject_files': [],
                    'resolved_paths': {
                        'inject_sources': [
                            {'path': '/exports', 'is_remote': True},
                        ]
                    },
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {5: {'name': 'docker-5'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert 'docker-5' not in out


def test_extract_inject_expected_by_node_ignores_node_generator_mount_root(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '5',
                    'id': 'nfs_sensitive_file',
                    'type': 'flag-node-generator',
                    'inject_files': ['/Users/me/project/exports'],
                    'resolved_paths': {
                        'inject_sources': [
                            {'path': '/exports', 'is_remote': True},
                        ]
                    },
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {5: {'name': 'docker-5'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert 'docker-5' not in out
