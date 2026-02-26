from webapp import app_backend


def test_apply_core_secret_to_config_overrides_localhost_placeholders(monkeypatch):
    cfg = {
        'host': 'localhost',
        'port': 50051,
        'ssh_host': 'localhost',
        'ssh_port': 22,
        'ssh_username': 'coreadmin',
        'core_secret_id': 'secret-1',
    }

    monkeypatch.setattr(
        app_backend,
        '_select_latest_core_secret_record',
        lambda *_a, **_k: {
            'identifier': 'secret-1',
            'host': '10.10.10.20',
            'port': 50051,
            'ssh_host': '10.10.10.20',
            'ssh_port': 22,
            'ssh_username': 'coreadmin',
            'ssh_password_plain': 'pw',
            'validated': True,
            'last_tested_status': 'success',
        },
    )

    out = app_backend._apply_core_secret_to_config(cfg, 'ScenarioX')

    assert str(out.get('host')) == '10.10.10.20'
    assert str(out.get('ssh_host')) == '10.10.10.20'
    assert str(out.get('ssh_username')) == 'coreadmin'
    assert str(out.get('ssh_password') or '') == 'pw'


def test_apply_core_secret_to_config_keeps_explicit_non_local_hosts(monkeypatch):
    cfg = {
        'host': '192.168.56.99',
        'port': 50051,
        'ssh_host': '192.168.56.99',
        'ssh_port': 22,
        'ssh_username': 'coreadmin',
        'core_secret_id': 'secret-1',
    }

    monkeypatch.setattr(
        app_backend,
        '_select_latest_core_secret_record',
        lambda *_a, **_k: {
            'identifier': 'secret-1',
            'host': '10.10.10.20',
            'port': 50051,
            'ssh_host': '10.10.10.20',
            'ssh_port': 22,
            'ssh_username': 'coreadmin',
            'ssh_password_plain': 'pw',
            'validated': True,
            'last_tested_status': 'success',
        },
    )

    out = app_backend._apply_core_secret_to_config(cfg, 'ScenarioX')

    assert str(out.get('host')) == '192.168.56.99'
    assert str(out.get('ssh_host')) == '192.168.56.99'
    assert str(out.get('ssh_password') or '') == 'pw'


def test_apply_core_secret_to_config_prefers_configured_secret_id(monkeypatch):
    cfg = {
        'host': 'localhost',
        'port': 50051,
        'ssh_host': 'localhost',
        'ssh_port': 22,
        'ssh_username': 'coreadmin',
        'core_secret_id': 'secret-specific',
    }

    monkeypatch.setattr(
        app_backend,
        '_select_latest_core_secret_record',
        lambda *_a, **_k: {
            'identifier': 'secret-latest',
            'host': '10.0.0.99',
            'ssh_host': '10.0.0.99',
            'ssh_username': 'wrong-user',
            'ssh_password_plain': 'wrong-pass',
        },
    )

    monkeypatch.setattr(
        app_backend,
        '_load_core_credentials',
        lambda sid: {
            'identifier': sid,
            'host': '10.0.0.10',
            'port': 50051,
            'ssh_host': '10.0.0.10',
            'ssh_port': 22,
            'ssh_username': 'right-user',
            'ssh_password_plain': 'right-pass',
            'validated': True,
            'last_tested_status': 'success',
        } if sid == 'secret-specific' else None,
    )

    out = app_backend._apply_core_secret_to_config(cfg, 'ScenarioX')

    assert str(out.get('host')) == '10.0.0.10'
    assert str(out.get('ssh_host')) == '10.0.0.10'
    assert str(out.get('ssh_username')) == 'right-user'
    assert str(out.get('ssh_password') or '') == 'right-pass'
