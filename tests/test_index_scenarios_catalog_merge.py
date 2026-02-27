from webapp import app_backend as backend


def test_prepare_payload_includes_catalog_scenario_stubs(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_scenario_catalog_for_user',
        lambda history, user=None: (
            ['NewScenario1', 'NewScenario12'],
            {'newscenario1': {'/tmp/NewScenario1.xml'}, 'newscenario12': {'/tmp/NewScenario12.xml'}},
            {},
        ),
    )

    payload = {
        'scenarios': [
            {
                'name': 'NewScenario1',
                'sections': {
                    'Node Information': {'items': []},
                },
                'density_count': 10,
            }
        ]
    }

    out = backend._prepare_payload_for_index(payload, user=None)
    names = [str((s or {}).get('name') or '') for s in (out.get('scenarios') or []) if isinstance(s, dict)]

    assert 'NewScenario1' in names
    assert 'NewScenario12' in names


def test_merge_catalog_scenario_stubs_into_payload_adds_missing_names():
    payload = {
        'scenario_catalog_names': ['NewScenario1', 'NewScenario12'],
        'scenarios': [
            {
                'name': 'NewScenario1',
                'sections': {'Node Information': {'items': []}},
                'density_count': 10,
            }
        ],
    }

    out = backend._merge_catalog_scenario_stubs_into_payload(payload)
    names = [str((s or {}).get('name') or '') for s in (out.get('scenarios') or []) if isinstance(s, dict)]

    assert 'NewScenario1' in names
    assert 'NewScenario12' in names
