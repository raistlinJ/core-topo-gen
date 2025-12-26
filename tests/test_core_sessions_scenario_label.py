import webapp.app_backend as backend


def test_scenario_label_from_pycore_path_is_blank() -> None:
    # /tmp/pycore.* is a CORE internal session dir; should never be shown as a scenario label.
    assert backend._scenario_label_from_path('/tmp/pycore.12345', ['Scenario A'], {}) == ''
    assert backend._scenario_label_from_path('/tmp/pycore', ['Scenario A'], {}) == ''


def test_annotate_sessions_does_not_use_pycore_as_scenario() -> None:
    sessions = [{'id': 1, 'file': None, 'dir': '/tmp/pycore.12345'}]
    backend._annotate_sessions_with_scenarios(
        sessions=sessions,
        session_labels={},
        scenario_norm='',
        scenario_names=['Scenario A'],
        scenario_paths={},
    )
    assert sessions[0].get('scenario_name') == ''


def test_list_active_core_sessions_prefers_store_xml_path(monkeypatch) -> None:
    # If remote session doesn't provide a usable file path, fall back to our local store mapping.
    monkeypatch.setattr(backend, '_normalize_core_config', lambda cfg, include_password=True: cfg)
    monkeypatch.setattr(
        backend,
        '_list_active_core_sessions_via_remote_python',
        lambda cfg, errors=None, meta=None, logger=None: [
            {'id': 7, 'state': 1, 'file': None, 'dir': None, 'nodes': 2}
        ],
    )
    monkeypatch.setattr(
        backend,
        '_load_core_sessions_store',
        lambda: {
            '/tmp/exports/session_7.xml': {
                'session_id': 7,
                'scenario_name': 'Scenario A',
                'scenario_norm': 'scenario-a',
            }
        },
    )

    sessions = backend._list_active_core_sessions(host='127.0.0.1', port=50051)
    assert sessions and sessions[0].get('file') == '/tmp/exports/session_7.xml'
