import os

from webapp.app_backend import app


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_core_data_filters_sessions_by_selected_scenario(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    def fake_outputs_dir():
        return str(outdir)

    monkeypatch.setattr(backend, '_outputs_dir', fake_outputs_dir)

    # Ensure scenario catalog has Alpha.
    run_history_path = outdir / 'run_history.json'
    monkeypatch.setattr(backend, 'RUN_HISTORY_PATH', str(run_history_path))
    run_history_path.write_text(
        '[{"timestamp":"2025-12-26T00:00:00Z","mode":"async","scenario_name":"Alpha","returncode":0}]',
        encoding='utf-8',
    )

    def fake_list_active_core_sessions(host, port, core_cfg, errors=None, meta=None):
        return [
            {'id': 1, 'state': 'RUNNING', 'nodes': 10, 'scenario_name': 'Alpha', 'file': '/tmp/alpha.xml'},
            {'id': 2, 'state': 'RUNNING', 'nodes': 10, 'scenario_name': 'Beta', 'file': '/tmp/beta.xml'},
        ]

    monkeypatch.setattr(backend, '_list_active_core_sessions', fake_list_active_core_sessions)
    monkeypatch.setattr(backend, '_scan_core_xmls', lambda: [])
    monkeypatch.setattr(backend, '_load_core_sessions_store', lambda: {})
    monkeypatch.setattr(backend, '_attach_hitl_metadata_to_sessions', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_attach_participant_urls_to_sessions', lambda *args, **kwargs: None)

    # Avoid dependency on real core config selection.
    monkeypatch.setattr(backend, '_select_core_config_for_page', lambda scenario_norm, history, include_password=True: {
        'host': '127.0.0.1',
        'port': 50051,
        'ssh_host': '127.0.0.1',
        'ssh_port': 22,
        'ssh_username': 'u',
        'ssh_password': 'p',
    })

    resp = client.get('/core/data?scenario=Alpha')
    assert resp.status_code == 200
    payload = resp.get_json()
    sessions = payload.get('sessions')
    assert isinstance(sessions, list)
    assert [s.get('id') for s in sessions] == [1]

    # SPA support: payload includes scenario-specific CORE instance metadata.
    assert payload.get('host') == '127.0.0.1'
    assert payload.get('port') == 50051
    assert isinstance(payload.get('core_modal_href'), str)


def test_core_stop_redirect_preserves_scenario(monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    # Avoid depending on remote execution.
    monkeypatch.setattr(backend, '_execute_remote_core_session_action', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_core_config_for_request', lambda include_password=True: {
        'host': '127.0.0.1',
        'port': 50051,
        'ssh_host': '127.0.0.1',
        'ssh_port': 22,
        'ssh_username': 'u',
        'ssh_password': 'p',
    })

    resp = client.post('/core/stop', data={'session_id': '1', 'scenario': 'Scenario 2'})
    assert resp.status_code in (302, 303)
    loc = resp.headers.get('Location') or ''
    assert '/core' in loc
    assert 'scenario=' in loc
    assert ('Scenario%202' in loc) or ('Scenario+2' in loc)

    def test_scenario_label_from_path_does_not_use_missing_remote_path_basename():
        import webapp.app_backend as backend

        scenario_names = ['Scenario 1', 'Scenario 2']
        scenario_paths = {
            'scenario 1': set(['/abs/path/Scenario_1.xml']),
            'scenario 2': set(['/abs/path/Scenario_2.xml']),
        }

        # CORE can report remote paths like /tmp/Scenario_1.xml; if that file doesn't exist
        # locally we must not infer Scenario 1 just from the basename.
        label = backend._scenario_label_from_path('/tmp/Scenario_1.xml', scenario_names, scenario_paths)
        assert label == ''

    def test_build_session_scenario_labels_prefers_newest_updated_at_for_reused_session_id():
        import webapp.app_backend as backend

        mapping = {
            '/abs/path/Scenario_1.xml': {
                'session_id': 1,
                'scenario_name': 'Scenario 1',
                'scenario_norm': 'scenario 1',
                'core_host': 'localhost',
                'core_port': 50051,
                'updated_at': '2025-12-27T00:00:00Z',
            },
            '/abs/path/Scenario_2.xml': {
                'session_id': 1,
                'scenario_name': 'Scenario 2',
                'scenario_norm': 'scenario 2',
                'core_host': 'localhost',
                'core_port': 50051,
                'updated_at': '2025-12-27T01:00:00Z',
            },
        }

        labels = backend._build_session_scenario_labels(mapping, ['Scenario 1', 'Scenario 2'], {})
        assert labels[1] == 'Scenario 2'


    def test_path_matches_scenario_does_not_use_missing_remote_basename():
        import webapp.app_backend as backend

        scenario_paths = {
            'scenario 1': set(['/abs/path/Scenario_1.xml']),
        }
        assert backend._path_matches_scenario('/tmp/Scenario_1.xml', 'scenario 1', scenario_paths) is False


    def test_session_ids_for_scenario_uses_latest_owner_mapping():
        import webapp.app_backend as backend

        mapping = {
            '/abs/path/Scenario_1.xml': {
                'session_id': 1,
                'scenario_name': 'Scenario 1',
                'scenario_norm': 'scenario 1',
                'core_host': 'localhost',
                'core_port': 50051,
                'updated_at': '2025-12-27T00:00:00Z',
            },
            '/abs/path/Scenario_2.xml': {
                'session_id': 1,
                'scenario_name': 'Scenario 2',
                'scenario_norm': 'scenario 2',
                'core_host': 'localhost',
                'core_port': 50051,
                'updated_at': '2025-12-27T01:00:00Z',
            },
        }
        # With session_id reuse, the ID should only belong to the newest mapping's scenario.
        assert 1 not in backend._session_ids_for_scenario(mapping, 'scenario 1', {})
        assert 1 in backend._session_ids_for_scenario(mapping, 'scenario 2', {})

def test_hitl_details_does_not_infer_from_rj45(tmp_path, monkeypatch):
    from webapp import app_backend as backend

    # Create a dummy file so _hitl_details_from_path sees it exists.
    xml_path = tmp_path / 'dummy.xml'
    xml_path.write_text('<xml/>', encoding='utf-8')

    # Analyzer returns an RJ45 node but no explicit hitl_nodes and no hitl* router interfaces.
    def fake_analyze(_path):
        return {
            'nodes': [
                {
                    'type': 'rj45',
                    'name': 'RJ45-1',
                    'interfaces': [{'ipv4': '10.0.0.5', 'ipv4_mask': '24'}],
                }
            ],
            'hitl_nodes': [],
        }

    monkeypatch.setattr(backend, '_analyze_core_xml', fake_analyze)

    details = backend._hitl_details_from_path(str(xml_path))
    assert details == []


def test_hitl_details_does_not_infer_from_hitl_iface_without_rj45(tmp_path, monkeypatch):
    from webapp import app_backend as backend

    xml_path = tmp_path / 'dummy2.xml'
    xml_path.write_text('<xml/>', encoding='utf-8')

    # Router has a hitl* interface IP, but there is no RJ45 node and no explicit hitl_nodes.
    def fake_analyze(_path):
        return {
            'nodes': [
                {
                    'type': 'router',
                    'name': 'r1',
                    'interfaces': [
                        {'name': 'hitl0', 'ipv4': '192.0.2.10', 'ipv4_mask': '24'},
                    ],
                }
            ],
            'hitl_nodes': [],
        }

    monkeypatch.setattr(backend, '_analyze_core_xml', fake_analyze)

    details = backend._hitl_details_from_path(str(xml_path))
    assert details == []


def test_session_hitl_metadata_prefers_existing_session_file_over_store(tmp_path):
        """If CORE reuses a session id, store lookups by session id can be stale.

        When the session already provides an existing XML file path, that path must be
        treated as authoritative and must not be overridden by a stale store entry.
        """

        from webapp.app_backend import _session_hitl_metadata

        xml_no_hitl = tmp_path / "scenario2.xml"
        xml_no_hitl.write_text(
                """<?xml version=\"1.0\"?>
<scenario name=\"core\">
    <networks/>
    <nodes>
        <node id=\"1\" name=\"r1\" type=\"router\"/>
    </nodes>
</scenario>
""",
                encoding="utf-8",
        )

        xml_with_hitl = tmp_path / "scenario1.xml"
        xml_with_hitl.write_text(
                """<?xml version=\"1.0\"?>
<scenario name=\"core\">
    <networks/>
    <nodes>
        <node id=\"1\" name=\"r1\" type=\"router\">
            <interface id=\"1\" name=\"hitl0\" mac=\"00:00:00:00:00:01\">
                <ip4>192.0.2.10</ip4>
            </interface>
        </node>
    </nodes>
</scenario>
""",
                encoding="utf-8",
        )

        session = {"id": 7, "file": str(xml_no_hitl)}
        stale_store = {str(xml_with_hitl): {"session_id": 7, "scenario_name": "Scenario 1"}}

        details = _session_hitl_metadata(session, session_store=stale_store)
        assert details == []


def test_session_hitl_metadata_prefers_grpc_fetch_when_session_file_not_local(tmp_path, monkeypatch):
        """If session.file points to a remote CORE VM path, it won't exist locally.

        In that case, when core_cfg is available, we should fetch the current session XML via gRPC
        instead of using stale store mappings by session id.
        """

        from webapp import app_backend as backend

        xml_with_hitl = tmp_path / "stale.xml"
        xml_with_hitl.write_text(
                """<?xml version="1.0"?>
<scenario name="core">
    <nodes>
        <node id="1" name="r1" type="router">
            <interface id="1" name="hitl0"><ip4>192.0.2.10</ip4></interface>
        </node>
        <node id="2" name="RJ45-1" type="rj45"/>
    </nodes>
</scenario>
""",
                encoding="utf-8",
        )

        xml_no_hitl = tmp_path / "fresh.xml"
        xml_no_hitl.write_text(
                """<?xml version="1.0"?>
<scenario name="core">
    <nodes>
        <node id="1" name="r1" type="router"/>
    </nodes>
</scenario>
""",
                encoding="utf-8",
        )

        # Force analyzer to yield HITL for stale.xml but none for fresh.xml.
        def fake_analyze(path):
                ap = str(path)
                if ap.endswith("stale.xml"):
                        return {
                                'nodes': [
                                        {'type': 'router', 'name': 'r1', 'interfaces': [{'name': 'hitl0', 'ipv4': '192.0.2.10', 'ipv4_mask': '24'}]},
                                        {'type': 'rj45', 'name': 'RJ45-1', 'interfaces': []},
                                ],
                                'hitl_nodes': [],
                        }
                return {
                        'nodes': [{'type': 'router', 'name': 'r1', 'interfaces': []}],
                        'hitl_nodes': [],
                }

        monkeypatch.setattr(backend, '_analyze_core_xml', fake_analyze)

        # Stale store maps session id 7 to stale.xml (with HITL)
        stale_store = {str(xml_with_hitl): {'session_id': 7, 'scenario_name': 'Scenario 1'}}

        # gRPC save should return fresh.xml
        def fake_grpc_save(_core_cfg, _out_dir, session_id=None):
                assert str(session_id) == '7'
                return str(xml_no_hitl)

        monkeypatch.setattr(backend, '_grpc_save_current_session_xml_with_config', fake_grpc_save)
        monkeypatch.setattr(backend, '_outputs_dir', lambda: str(tmp_path))

        session = {'id': 7, 'file': '/remote/core/session7.xml', 'scenario_name': 'Scenario 2'}
        details = backend._session_hitl_metadata(session, core_cfg={'host': 'h', 'port': 1}, session_store=stale_store)
        assert details == []
        assert session.get('file') == str(xml_no_hitl)
