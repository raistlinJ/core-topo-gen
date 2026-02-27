import re

from webapp import app_backend as backend


def test_stale_core_veth_cleanup_enabled_default(monkeypatch):
    monkeypatch.delenv('CORETG_CLEAN_STALE_CORE_VETH', raising=False)
    assert backend._stale_core_veth_cleanup_enabled() is True


def test_stale_core_veth_cleanup_enabled_respects_false_values(monkeypatch):
    for raw in ('0', 'false', 'no', 'off', ''):
        monkeypatch.setenv('CORETG_CLEAN_STALE_CORE_VETH', raw)
        assert backend._stale_core_veth_cleanup_enabled() is False


def test_stale_core_veth_cleanup_command_targets_core_name_patterns():
    cmd = backend._stale_core_veth_cleanup_command()
    assert "ip -o link show" in cmd
    assert "grep -E ^[bv]eth" in cmd
    assert "tr -d \\040" in cmd
    assert "ip link del" in cmd
    assert "while IFS= read -r i; do" in cmd
    assert "'" not in cmd
    assert re.search(r"\[bv\]eth", cmd)
