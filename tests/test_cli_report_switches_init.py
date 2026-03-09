from types import SimpleNamespace

import pytest

import core_topo_gen.cli as cli
import core_topo_gen.planning.orchestrator as orchestrator


class _FakeCoreClient:
    def connect(self):
        return None


class _FakeSession:
    topo_stats = {}


def test_cli_report_handles_segmented_build_without_router_nodes(tmp_path, monkeypatch):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="s"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')

    captured = {}
    argv0 = cli.sys.argv[:]

    def fake_write_report(*args, **kwargs):
        captured['switches'] = kwargs.get('switches')
        raise SystemExit(0)

    try:
        cli.sys.argv = ['core_topo_gen.cli', '--xml', str(xml_path), '--scenario', 's']
        monkeypatch.setattr(cli, '_maybe_seed_docker_sudo_password_from_stdin', lambda: None)
        monkeypatch.setattr(cli, '_load_preview_plan', lambda *a, **k: (None, None))
        monkeypatch.setattr(cli, '_export_flow_assignments_to_env', lambda *a, **k: None)
        monkeypatch.setattr(cli, 'parse_node_info', lambda *a, **k: (1, [('Host', 1.0)], [], []))
        monkeypatch.setattr(cli, 'parse_planning_metadata', lambda *a, **k: {})
        monkeypatch.setattr(cli, 'parse_hitl_info', lambda *a, **k: {'enabled': False, 'interfaces': []})
        monkeypatch.setattr(cli, 'compute_role_counts', lambda *a, **k: {'Host': 1})
        monkeypatch.setattr(cli, 'parse_routing_info', lambda *a, **k: (0.1, []))
        monkeypatch.setattr(cli, 'parse_segmentation_info', lambda *a, **k: (0.0, []))
        monkeypatch.setattr(cli, 'parse_traffic_info', lambda *a, **k: (0.0, []))
        monkeypatch.setattr(cli, '_flow_state_from_xml', lambda *a, **k: None)
        monkeypatch.setattr(cli, 'parse_vulnerabilities_info', lambda *a, **k: (0.0, [], None))
        monkeypatch.setattr(cli, 'load_vuln_catalog', lambda *a, **k: [])
        monkeypatch.setattr(cli, 'assign_compose_to_nodes', lambda *a, **k: {})
        monkeypatch.setattr(cli, 'attach_hitl_rj45_nodes', lambda *a, **k: {'enabled': False, 'interfaces': []})
        monkeypatch.setattr(cli, 'write_report', fake_write_report)
        monkeypatch.setattr(cli, 'CORE_GRPC_AVAILABLE', True)
        monkeypatch.setattr(cli, 'client', SimpleNamespace(CoreGrpcClient=lambda address: _FakeCoreClient()))
        monkeypatch.setattr(cli, 'build_segmented_topology', lambda *a, **k: (_FakeSession(), [], [], {}, {}, {}))
        monkeypatch.setattr(orchestrator, 'compute_full_plan', lambda *a, **k: {
            'routers_planned': 1,
            'service_plan': {},
            'breakdowns': {},
            'vulnerability_plan': None,
            'vulnerability_items_raw': [],
            'segmentation_items_raw': [],
        })

        with pytest.raises(SystemExit) as excinfo:
            cli.main()

        assert excinfo.value.code == 0
        assert captured['switches'] == []
    finally:
        cli.sys.argv = argv0