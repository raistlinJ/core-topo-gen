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


def test_prepare_payload_preserves_hitl_proxmox_validation_state(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_scenario_catalog_for_user',
        lambda history, user=None: (
            ['Anatest'],
            {'anatest': {'/tmp/Anatest.xml'}},
            {},
        ),
    )

    payload = {
        'scenarios': [
            {
                'name': 'Anatest',
                'density_count': 10,
                'sections': {'Node Information': {'items': []}},
                'hitl': {
                    'enabled': True,
                    'proxmox': {
                        'url': 'https://proxmox.local',
                        'port': 8006,
                        'verify_ssl': False,
                        'secret_id': 'prox-secret-1',
                        'validated': True,
                        'last_validated_at': '2026-03-03T00:00:00',
                    },
                },
            }
        ]
    }

    out = backend._prepare_payload_for_index(payload, user=None)
    scenarios = out.get('scenarios') if isinstance(out.get('scenarios'), list) else []
    anatest = next((s for s in scenarios if isinstance(s, dict) and str(s.get('name') or '') == 'Anatest'), {})
    hitl = anatest.get('hitl') if isinstance(anatest.get('hitl'), dict) else {}
    prox = hitl.get('proxmox') if isinstance(hitl.get('proxmox'), dict) else {}

    assert prox.get('secret_id') == 'prox-secret-1'
    assert prox.get('validated') is True
    assert prox.get('url') == 'https://proxmox.local'


def test_prepare_payload_admin_merges_hitl_hints_when_scenario_missing_fields(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_scenario_catalog_for_user',
        lambda history, user=None: (
            ['Anatest'],
            {'anatest': {'/tmp/Anatest.xml'}},
            {},
        ),
    )
    monkeypatch.setattr(
        backend,
        '_load_scenario_hitl_validation_from_disk',
        lambda: {
            'anatest': {
                'proxmox': {'secret_id': 'prox-secret-1', 'validated': True},
                'core': {'core_secret_id': 'core-secret-1', 'validated': True, 'vm_key': 'pve::101'},
            }
        },
    )
    monkeypatch.setattr(backend, '_load_scenario_hitl_config_from_disk', lambda: {})

    payload = {
        'scenarios': [
            {
                'name': 'Anatest',
                'sections': {'Node Information': {'items': []}},
                'density_count': 10,
                'hitl': {'enabled': True},
            }
        ]
    }

    out = backend._prepare_payload_for_index(payload, user=None)
    scenarios = out.get('scenarios') if isinstance(out.get('scenarios'), list) else []
    anatest = next((s for s in scenarios if isinstance(s, dict) and str(s.get('name') or '') == 'Anatest'), {})
    hitl = anatest.get('hitl') if isinstance(anatest.get('hitl'), dict) else {}
    prox = hitl.get('proxmox') if isinstance(hitl.get('proxmox'), dict) else {}
    core = hitl.get('core') if isinstance(hitl.get('core'), dict) else {}

    assert prox.get('secret_id') == 'prox-secret-1'
    assert prox.get('validated') is True
    assert core.get('core_secret_id') == 'core-secret-1'
    assert core.get('validated') is True


def test_sanitize_hitl_config_hint_preserves_external_interface_metadata():
    hint = backend._sanitize_hitl_config_hint({
        'enabled': True,
        'participant_proxmox_url': 'https://participant.local:8006',
        'interfaces': [
            {
                'name': 'eth1',
                'attachment': 'proxmox_vm',
                'external_vm': {
                    'vm_key': 'pve1::202',
                    'vmid': '202',
                    'vm_node': 'pve1',
                    'vm_name': 'External',
                    'status': 'running',
                    'interface_id': 'net1',
                    'interface_bridge': 'vmbr0',
                    'interface_mac': 'aa:bb:cc:dd:ee:ff',
                    'interface_model': 'virtio',
                },
                'proxmox_target': {
                    'node': 'pve1',
                    'vmid': '101',
                    'interface_id': 'net0',
                    'vm_name': 'CORE-VM',
                    'label': 'CORE-VM',
                    'macaddr': '11:22:33:44:55:66',
                    'bridge': 'vmbr1',
                    'model': 'virtio',
                },
            }
        ],
    })

    assert isinstance(hint, dict)
    interfaces = hint.get('interfaces') if isinstance(hint.get('interfaces'), list) else []
    assert len(interfaces) == 1
    ext = interfaces[0].get('external_vm') if isinstance(interfaces[0].get('external_vm'), dict) else {}
    assert ext.get('status') == 'running'
    assert ext.get('interface_bridge') == 'vmbr0'
    assert ext.get('interface_mac') == 'aa:bb:cc:dd:ee:ff'
    assert ext.get('interface_model') == 'virtio'
    prox_target = interfaces[0].get('proxmox_target') if isinstance(interfaces[0].get('proxmox_target'), dict) else {}
    assert prox_target.get('label') == 'CORE-VM'
