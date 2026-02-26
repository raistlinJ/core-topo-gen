import os
from unittest.mock import patch

from webapp.app_backend import app


def _stats_path() -> str:
    # Keep in sync with app_backend's stats path.
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    return os.path.join(root, 'outputs', 'participant_ui_stats.json')


def test_participant_ui_stats_record_and_fetch():
    app.config['TESTING'] = True
    client = app.test_client()

    # Authenticate with default seeded admin user for protected routes
    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    # Start from a clean file for determinism
    stats_path = _stats_path()
    try:
        if os.path.exists(stats_path):
            os.remove(stats_path)
    except Exception:
        pass

    resp = client.get('/participant-ui/stats?scenario=test-scenario')
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload and payload.get('ok') is True
    assert payload.get('scenario_norm') == 'test-scenario'
    assert payload['scenario']['open_count'] == 0
    assert payload['scenario']['last_open_ts'] == ''

    rec = client.post('/participant-ui/record-open', json={'scenario_norm': 'test-scenario', 'href': 'https://example.com'})
    assert rec.status_code == 200
    rec_payload = rec.get_json()
    assert rec_payload and rec_payload.get('ok') is True
    assert rec_payload.get('last_open_ts'), 'expected last_open_ts'

    after = client.get('/participant-ui/stats?scenario=test-scenario')
    assert after.status_code == 200
    after_payload = after.get_json()
    assert after_payload and after_payload.get('ok') is True
    assert after_payload['scenario']['open_count'] == 1
    assert after_payload['scenario']['last_open_ts']

    # Allow recording same-origin redirect hrefs (used by restricted Participant UI view)
    rec2 = client.post('/participant-ui/record-open', json={'scenario_norm': 'test-scenario', 'href': '/participant-ui/open?scenario=test-scenario'})
    assert rec2.status_code == 200


def test_participant_ui_open_redirect():
    app.config['TESTING'] = True
    client = app.test_client()

    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    fake_state = {
        'selected_url': '',
        'selected_norm': 'test-scenario',
        'listing': [
            {'norm': 'test-scenario', 'display': 'Test Scenario', 'url': 'https://example.com', 'has_url': True, 'active': True},
        ],
    }
    with patch('webapp.app_backend._participant_ui_state', return_value=fake_state):
        resp = client.get('/participant-ui/open?scenario=test-scenario')
        assert resp.status_code in (302, 303)
        assert resp.headers.get('Location') == 'https://example.com'


def test_participant_ui_gateway_api_ok_shape():
    app.config['TESTING'] = True
    client = app.test_client()

    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    # No guarantee of a gateway in test env; just assert shape.
    resp = client.get('/participant-ui/gateway?scenario=test-scenario')
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload and payload.get('ok') is True
    assert payload.get('scenario_norm') == 'test-scenario'
    assert isinstance(payload.get('nearest_gateway') or '', str)


def test_participant_ui_details_api_ok_shape(tmp_path):
    app.config['TESTING'] = True
    client = app.test_client()

    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    # Create a minimal summary JSON with counts + seed.
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    out_dir = os.path.join(repo_root, 'outputs')
    os.makedirs(out_dir, exist_ok=True)
    summary_path = os.path.join(out_dir, 'test_summary.json')
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write(
            '{\n'
            '  "counts": {"total_nodes": 10, "routers": 2, "switches": 3, "hosts": 5},\n'
            '  "metadata": {"seed": 123, "vuln_total_planned_additive": 7}\n'
            '}\n'
        )

    fake_history = [
        {
            'timestamp': '2025-01-01T00:00:00Z',
            'scenario_names': ['Test Scenario'],
            'returncode': 0,
            'summary_path': summary_path,
            'session_xml_path': str(tmp_path / 'core-session.xml'),
        }
    ]
    fake_state = {
        'selected_norm': 'test scenario',
        'selected_nearest_gateway': '',
        'listing': [
            {
                'norm': 'test scenario',
                'display': 'Test Scenario',
                'url': 'https://example.com',
                'has_url': True,
                'assigned': True,
                'active': True,
            }
        ],
    }

    with patch('webapp.app_backend._participant_ui_state', return_value=fake_state), \
         patch('webapp.app_backend._load_run_history', return_value=fake_history), \
         patch('webapp.app_backend._hitl_details_from_path', return_value=[{'ips': ['10.0.0.1/24']}]):
        resp = client.get('/participant-ui/details?scenario=test%20scenario')
        assert resp.status_code == 200
        payload = resp.get_json()
        assert payload and payload.get('ok') is True
        assert payload.get('scenario_norm') == 'test scenario'
        assert payload['scenario']['participant_link_configured'] is True
        assert payload['gateway'] == '10.0.0.1'
        assert payload['execute']['ok'] is True
        assert 'planning' not in payload
        assert payload['counts']['nodes'] == 10
        assert payload['counts']['routers'] == 2
        assert payload['counts']['switches'] == 3
        assert payload['counts']['vulnerabilities'] == 7
        assert payload.get('vulnerability_ips') == []


def test_participant_ui_details_populates_vulnerability_ips_from_session_xml(tmp_path):
        app.config['TESTING'] = True
        client = app.test_client()

        login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
        assert login_resp.status_code in (302, 303)

        session_xml_path = tmp_path / 'core-session.xml'
        session_xml_path.write_text(
                """<?xml version='1.0' encoding='UTF-8'?>
<scenario>
    <devices>
        <device id=\"30\" name=\"h15\" type=\"docker\" class=\"docker\" compose=\"/tmp/vulns/docker-compose-h15.yml\" compose_name=\"mysql\"/>
        <device id=\"51\" name=\"rsw\" type=\"switch\"/>
    </devices>
    <links>
        <link node1=\"30\" node2=\"51\">
            <iface1 id=\"0\" name=\"eth0\" ip4=\"192.168.50.10\" ip4_mask=\"24\"/>
            <iface2 id=\"0\" name=\"veth51.0.1\"/>
        </link>
    </links>
</scenario>
""",
                encoding='utf-8',
        )

        fake_history = [
                {
                        'timestamp': '2025-01-01T00:00:00Z',
                        'scenario_names': ['Test Scenario'],
                        'returncode': 0,
                        'summary_path': None,
                        'session_xml_path': str(session_xml_path),
                }
        ]
        fake_state = {
                'selected_norm': 'test scenario',
                'selected_nearest_gateway': '',
                'listing': [
                        {
                                'norm': 'test scenario',
                                'display': 'Test Scenario',
                                'url': 'https://example.com',
                                'has_url': True,
                                'assigned': True,
                                'active': True,
                        }
                ],
        }

        with patch('webapp.app_backend._participant_ui_state', return_value=fake_state), \
                 patch('webapp.app_backend._load_run_history', return_value=fake_history), \
                 patch('webapp.app_backend._hitl_details_from_path', return_value=[]):
                resp = client.get('/participant-ui/details?scenario=test%20scenario')
                assert resp.status_code == 200
                payload = resp.get_json()
                assert payload and payload.get('ok') is True
                assert payload.get('vulnerability_ips') == ['192.168.50.10']


        def test_participant_ui_details_vulnerability_ips_fallback_from_device_descendant_ip_attr(tmp_path):
            app.config['TESTING'] = True
            client = app.test_client()

            login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
            assert login_resp.status_code in (302, 303)

            session_xml_path = tmp_path / 'core-session.xml'
            session_xml_path.write_text(
                """<?xml version='1.0' encoding='UTF-8'?>
        <scenario>
            <devices>
            <device id=\"30\" name=\"h15\" type=\"docker\" class=\"docker\" compose=\"/tmp/vulns/docker-compose-h15.yml\" compose_name=\"mysql\">
                <netif name=\"eth0\" ip=\"172.16.99.7/24\"/>
            </device>
            </devices>
        </scenario>
        """,
                encoding='utf-8',
            )

            fake_history = [
                {
                    'timestamp': '2025-01-01T00:00:00Z',
                    'scenario_names': ['Test Scenario'],
                    'returncode': 0,
                    'summary_path': None,
                    'session_xml_path': str(session_xml_path),
                }
            ]
            fake_state = {
                'selected_norm': 'test scenario',
                'selected_nearest_gateway': '',
                'listing': [
                    {
                        'norm': 'test scenario',
                        'display': 'Test Scenario',
                        'url': 'https://example.com',
                        'has_url': True,
                        'assigned': True,
                        'active': True,
                    }
                ],
            }

            with patch('webapp.app_backend._participant_ui_state', return_value=fake_state), \
                 patch('webapp.app_backend._load_run_history', return_value=fake_history), \
                 patch('webapp.app_backend._hitl_details_from_path', return_value=[]):
                resp = client.get('/participant-ui/details?scenario=test%20scenario')
                assert resp.status_code == 200
                payload = resp.get_json()
                assert payload and payload.get('ok') is True
                assert payload.get('vulnerability_ips') == ['172.16.99.7']


def test_participant_ui_details_reports_running_when_core_session_active():
    app.config['TESTING'] = True
    client = app.test_client()

    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    fake_history = [
        {
            'timestamp': '2025-01-01T00:00:00Z',
            'scenario_names': ['Test Scenario'],
            'returncode': 0,
            'core': {
                'host': '127.0.0.1',
                'port': 50051,
                'ssh_host': '127.0.0.1',
                'ssh_port': 22,
                'ssh_username': 'u',
                'ssh_password': 'p',
                'ssh_enabled': True,
            },
        }
    ]
    fake_state = {
        'selected_norm': 'test scenario',
        'selected_nearest_gateway': '10.0.0.1',
        'listing': [
            {
                'norm': 'test scenario',
                'display': 'Test Scenario',
                'url': 'https://example.com',
                'has_url': True,
                'assigned': True,
                'active': True,
            }
        ],
    }

    fake_sessions = [
        {
            'id': 7,
            'state': 'RUNTIME',
            'file': '/tmp/test.xml',
        }
    ]

    with patch('webapp.app_backend._participant_ui_state', return_value=fake_state), \
         patch('webapp.app_backend._load_run_history', return_value=fake_history), \
         patch('webapp.app_backend._scenario_catalog_for_user', return_value=(['Test Scenario'], {'test scenario': set()}, {})), \
         patch('webapp.app_backend._load_core_sessions_store', return_value={}), \
         patch('webapp.app_backend._list_active_core_sessions', return_value=fake_sessions):
        resp = client.get('/participant-ui/details?scenario=test%20scenario')
        assert resp.status_code == 200
        payload = resp.get_json()
        assert payload and payload.get('ok') is True
        assert payload['session']['running'] is True
        assert payload['session']['session_id'] == 7


def test_latest_session_xml_falls_back_to_core_post_path_in_last_run(tmp_path):
    from webapp import app_backend as backend

    scenario = 'LiveTopologySmoke'
    scenario_norm = backend._normalize_scenario_label(scenario)
    xml_path = tmp_path / 'scenarios-01' / 'core-post' / 'scenario-post.xml'
    xml_path.parent.mkdir(parents=True, exist_ok=True)
    xml_path.write_text(
        f"<Scenarios><Scenario name=\"{scenario}\"><ScenarioEditor/></Scenario></Scenarios>",
        encoding='utf-8',
    )

    fake_history = [
        {
            'timestamp': '2026-02-25T10:00:00Z',
            'scenario_names': [scenario],
            'post_xml_path': str(xml_path),
        }
    ]

    with patch('webapp.app_backend._load_run_history', return_value=fake_history):
        resolved = backend._latest_session_xml_for_scenario_norm(scenario_norm)

    assert resolved == str(xml_path)


def test_participant_ui_details_uses_latest_session_xml_fallback_when_history_path_missing(tmp_path):
    app.config['TESTING'] = True
    client = app.test_client()

    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    scenario = 'Test Scenario'
    scenario_norm = 'test scenario'
    fallback_xml = tmp_path / 'scenarios-01' / 'core-post' / 'scenario-post.xml'
    fallback_xml.parent.mkdir(parents=True, exist_ok=True)
    fallback_xml.write_text(
        """<?xml version='1.0' encoding='UTF-8'?>
<scenario>
  <devices>
    <device id=\"1\" name=\"docker-1\" type=\"docker\" class=\"docker\" compose=\"/tmp/vulns/docker-compose-docker-1.yml\"/>
    <device id=\"2\" name=\"r1\" type=\"router\"/>
    <device id=\"3\" name=\"sw1\" type=\"switch\"/>
  </devices>
  <links>
    <link node1=\"1\" node2=\"3\">
      <iface1 id=\"0\" name=\"eth0\" ip4=\"10.20.30.40\" ip4_mask=\"24\"/>
      <iface2 id=\"0\" name=\"swp0\"/>
    </link>
  </links>
</scenario>
""",
        encoding='utf-8',
    )

    fake_history = [
        {
            'timestamp': '2026-02-25T10:00:00Z',
            'scenario_names': [scenario],
            # Deliberately omit session_xml_path/post_xml_path so endpoint must use fallback resolver.
            'summary_path': None,
            'returncode': 0,
        }
    ]
    fake_state = {
        'selected_norm': scenario_norm,
        'selected_nearest_gateway': '',
        'listing': [
            {
                'norm': scenario_norm,
                'display': scenario,
                'url': 'https://example.com',
                'has_url': True,
                'assigned': True,
                'active': True,
            }
        ],
    }

    with patch('webapp.app_backend._participant_ui_state', return_value=fake_state), \
         patch('webapp.app_backend._load_run_history', return_value=fake_history), \
         patch('webapp.app_backend._latest_session_xml_for_scenario_norm', return_value=str(fallback_xml)), \
         patch('webapp.app_backend._hitl_details_from_path', return_value=[]):
        resp = client.get('/participant-ui/details?scenario=test%20scenario')
        assert resp.status_code == 200
        payload = resp.get_json()

    assert payload and payload.get('ok') is True
    assert payload.get('counts', {}).get('nodes') == 3
    assert payload.get('counts', {}).get('routers') == 1
    assert payload.get('counts', {}).get('switches') == 1
    assert payload.get('vulnerability_ips') == ['10.20.30.40']
    assert payload.get('subnetworks') == ['10.20.30.0/24']


def test_latest_run_history_prefers_newer_slash_timestamp():
    from webapp import app_backend as backend

    history = [
        {
            'timestamp': '02/25/26/17/28/11',
            'scenario_names': ['LiveTopologySmoke'],
            'returncode': 1,
        },
        {
            'timestamp': '02/25/26/22/17/17',
            'scenario_names': ['LiveTopologySmoke'],
            'returncode': 0,
        },
    ]

    latest = backend._latest_run_history_for_scenario('livetopologysmoke', history)

    assert isinstance(latest, dict)
    assert latest.get('returncode') == 0
    assert latest.get('timestamp') == '02/25/26/22/17/17'


def test_participant_ui_details_normalizes_legacy_execute_timestamp():
    app.config['TESTING'] = True
    client = app.test_client()

    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    fake_history = [
        {
            'timestamp': '02/25/26/22/17/17',
            'scenario_names': ['Test Scenario'],
            'returncode': 0,
            'summary_path': None,
        }
    ]
    fake_state = {
        'selected_norm': 'test scenario',
        'selected_nearest_gateway': '',
        'listing': [
            {
                'norm': 'test scenario',
                'display': 'Test Scenario',
                'url': 'https://example.com',
                'has_url': True,
                'assigned': True,
                'active': True,
            }
        ],
    }

    with patch('webapp.app_backend._participant_ui_state', return_value=fake_state), \
         patch('webapp.app_backend._load_run_history', return_value=fake_history), \
         patch('webapp.app_backend._hitl_details_from_path', return_value=[]):
        resp = client.get('/participant-ui/details?scenario=test%20scenario')
        assert resp.status_code == 200
        payload = resp.get_json()

    assert payload and payload.get('ok') is True
    ts = str(payload.get('execute', {}).get('last_execute_ts') or '')
    assert ts
    assert 'T' in ts
    assert '/' not in ts


def test_participant_ui_stats_normalizes_legacy_last_open_ts():
    app.config['TESTING'] = True
    client = app.test_client()

    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    fake_stats = {
        'totals': {
            'open_count': 3,
            'last_open_ts': '02/25/26/17/28/11',
        },
        'scenarios': {
            'test-scenario': {
                'open_count': 2,
                'last_open_ts': '02/25/26/16/11/09',
            }
        },
    }

    with patch('webapp.app_backend._load_participant_ui_stats', return_value=fake_stats):
        resp = client.get('/participant-ui/stats?scenario=test-scenario')
        assert resp.status_code == 200
        payload = resp.get_json()

    assert payload and payload.get('ok') is True
    scenario_ts = str(payload.get('scenario', {}).get('last_open_ts') or '')
    totals_ts = str(payload.get('totals', {}).get('last_open_ts') or '')
    assert 'T' in scenario_ts and '/' not in scenario_ts
    assert 'T' in totals_ts and '/' not in totals_ts


def test_participant_ui_details_normalizes_legacy_open_stats_last_open_ts():
    app.config['TESTING'] = True
    client = app.test_client()

    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    fake_state = {
        'selected_norm': 'test scenario',
        'selected_nearest_gateway': '',
        'listing': [
            {
                'norm': 'test scenario',
                'display': 'Test Scenario',
                'url': 'https://example.com',
                'has_url': True,
                'assigned': True,
                'active': True,
            }
        ],
    }
    fake_stats = {
        'scenarios': {
            'test scenario': {
                'open_count': 4,
                'last_open_ts': '02/25/26/18/10/12',
            }
        }
    }

    with patch('webapp.app_backend._participant_ui_state', return_value=fake_state), \
         patch('webapp.app_backend._load_participant_ui_stats', return_value=fake_stats), \
         patch('webapp.app_backend._load_run_history', return_value=[]), \
         patch('webapp.app_backend._hitl_details_from_path', return_value=[]):
        resp = client.get('/participant-ui/details?scenario=test%20scenario')
        assert resp.status_code == 200
        payload = resp.get_json()

    assert payload and payload.get('ok') is True
    ts = str(payload.get('open_stats', {}).get('last_open_ts') or '')
    assert 'T' in ts
    assert '/' not in ts
