from __future__ import annotations

from types import SimpleNamespace

from webapp.app_backend import app
from webapp import flow_prepare_preview_execute


def test_prepare_preview_context_uses_saved_page_core_cfg_when_xml_lacks_password(tmp_path):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="Scenario One"><ScenarioEditor/></Scenario></Scenarios>', encoding='utf-8')

    deps = SimpleNamespace(
        _coerce_bool=lambda value: bool(value),
        _normalize_scenario_label=lambda value: str(value or '').strip().lower(),
        _flow_preset_steps=lambda preset: [],
        _existing_xml_path_or_none=lambda value: str(xml_path) if value and str(value) == str(xml_path) else None,
        _planner_get_plan=lambda scenario_norm: None,
        _latest_preview_plan_for_scenario_norm_origin=lambda scenario_norm, origin=None: None,
        _latest_preview_plan_for_scenario_norm=lambda scenario_norm: None,
        _core_config_from_xml_path=lambda *args, **kwargs: {
            'host': 'localhost',
            'port': 50051,
            'ssh_enabled': True,
            'ssh_host': '',
            'ssh_username': 'core',
            'ssh_password': '',
        },
        _load_run_history=lambda: [],
        _select_core_config_for_page=lambda scenario_norm, include_password=True: {
            'host': '10.0.0.8',
            'port': 50051,
            'ssh_enabled': True,
            'validated': True,
            'ssh_host': '10.0.0.8',
            'ssh_username': 'core',
            'ssh_password': 'saved-secret',
            'core_secret_id': 'core-secret-1',
        },
        _merge_core_configs=lambda *parts, include_password=True: {
            key: value
            for part in parts
            if isinstance(part, dict)
            for key, value in part.items()
        },
        _apply_core_secret_to_config=lambda cfg, scenario_norm: dict(cfg),
        _flow_normalize_fact_override=lambda value: None,
        _load_preview_payload_from_path=lambda *args, **kwargs: {'full_preview': {}},
        _canonicalize_payload_flow_from_xml=lambda payload, xml_path=None, scenario_label=None: ({}, {}),
    )

    with app.app_context():
        with app.test_request_context(
            '/api/flag-sequencing/prepare_preview_for_execute',
            method='POST',
            json={
                'scenario': 'Scenario One',
                'preview_plan': str(xml_path),
                'mode': 'resolve',
            },
        ):
            result = flow_prepare_preview_execute._load_prepare_preview_request_context(
                deps=deps,
                flow_progress=lambda message: None,
            )

    assert result.get('response') is None
    assert result.get('flow_run_remote') is True
    assert result.get('flow_core_cfg') == {
        'host': 'localhost',
        'port': 50051,
        'ssh_enabled': True,
        'ssh_host': '10.0.0.8',
        'ssh_username': 'core',
        'ssh_password': 'saved-secret',
        'validated': True,
        'core_secret_id': 'core-secret-1',
        'grpc_host': 'localhost',
        'grpc_port': 50051,
    }