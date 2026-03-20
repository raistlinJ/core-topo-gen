import json
from unittest.mock import patch

from webapp.ai_generator_accuracy_eval import compare_reports
from webapp.ai_generator_accuracy_eval import DEFAULT_CASES_PATH
from webapp.ai_generator_accuracy_eval import _endpoint_case
from webapp.ai_generator_accuracy_eval import _write_live_fixture_bridge_config
from webapp.ai_generator_accuracy_eval import evaluate_cases
from webapp.ai_generator_accuracy_eval import render_markdown_report
from webapp.ai_generator_accuracy_eval import render_text_report


class _StubResponse:
    def __init__(self, status_code: int, payload: dict[str, object]):
        self.status_code = status_code
        self._payload = payload

    def get_json(self, silent: bool = True):
        return self._payload


class _StubClient:
    def __init__(self, responses: list[_StubResponse]):
        self._responses = list(responses)
        self.calls: list[tuple[str, dict[str, object] | None]] = []

    def post(self, path: str, json=None, data=None):
        payload = json if json is not None else data
        self.calls.append((path, payload))
        if not self._responses:
            raise AssertionError(f'No stub response left for {path}')
        return self._responses.pop(0)


def test_ai_generator_accuracy_eval_corpus_passes():
    report = evaluate_cases(cases_path=DEFAULT_CASES_PATH)

    compiler = report['summary']['compiler']
    endpoint = report['summary']['endpoint']

    assert compiler['failed'] == 0
    assert endpoint['failed'] == 0
    assert compiler['passed'] == compiler['total']
    assert endpoint['passed'] == endpoint['total']


def test_ai_generator_accuracy_eval_can_filter_cases():
    report = evaluate_cases(cases_path=DEFAULT_CASES_PATH, case_ids=['routers_hosts_basic'])

    assert report['summary']['overall_cases'] == 1
    assert report['compiler_results'][0]['id'] == 'routers_hosts_basic'
    assert report['endpoint_results'][0]['id'] == 'routers_hosts_basic'
    text = render_text_report(report)
    assert 'Compiler exact-match: 1/1' in text
    assert 'Endpoint exact-match+preview: 1/1' in text


def test_ai_generator_accuracy_eval_compare_reports_tracks_deltas():
    previous = {
        'summary': {
            'compiler': {'passed': 1, 'failed': 1, 'pass_rate': 50.0, 'failed_ids': ['a']},
            'endpoint': {'passed': 1, 'failed': 1, 'pass_rate': 50.0, 'failed_ids': ['b']},
        },
        'cases_path': 'previous.json',
    }
    current = {
        'summary': {
            'compiler': {'passed': 2, 'failed': 0, 'pass_rate': 100.0, 'failed_ids': []},
            'endpoint': {'passed': 1, 'failed': 1, 'pass_rate': 50.0, 'failed_ids': ['c']},
        },
    }

    comparison = compare_reports(current, previous)

    assert comparison['compiler']['pass_rate_delta'] == 50.0
    assert comparison['compiler']['resolved_failures'] == ['a']
    assert comparison['endpoint']['pass_rate_delta'] == 0.0
    assert comparison['endpoint']['new_failures'] == ['c']

    current['comparison'] = comparison
    text = render_text_report(current)
    assert 'Compiler delta vs previous: +50.00 pts' in text
    assert 'New endpoint failures: c' in text


def test_ai_generator_accuracy_eval_renders_markdown_summary():
    report = evaluate_cases(cases_path=DEFAULT_CASES_PATH, case_ids=['routers_hosts_basic'])
    report['comparison'] = {
        'compiler': {'pass_rate_delta': 0.0, 'new_failures': [], 'resolved_failures': []},
        'endpoint': {'pass_rate_delta': 0.0, 'new_failures': [], 'resolved_failures': []},
    }

    markdown = render_markdown_report(report)

    assert '# AI Generator Accuracy Evaluation' in markdown
    assert '## Compiler Cases' in markdown
    assert '## Endpoint Cases' in markdown
    assert '`routers_hosts_basic`: pass' in markdown


def test_ai_generator_accuracy_eval_renders_skip_reasons():
    report = {
        'summary': {
            'overall_cases': 1,
            'compiler': {'passed': 0, 'total': 0, 'pass_rate': 0.0, 'skipped': 1, 'failed_ids': []},
            'endpoint': {'passed': 0, 'total': 0, 'pass_rate': 0.0, 'skipped': 1, 'failed_ids': []},
        },
        'compiler_results': [
            {'id': 'case-a', 'skipped': True, 'error': 'compiler reason'},
        ],
        'endpoint_results': [
            {'id': 'case-a', 'skipped': True, 'error': 'endpoint reason'},
        ],
    }

    text = render_text_report(report)
    markdown = render_markdown_report(report)

    assert 'Compiler skipped cases:' in text
    assert '- case-a: compiler reason' in text
    assert 'Endpoint skipped cases:' in text
    assert '- case-a: endpoint reason' in text
    assert '`case-a`: skipped' in markdown
    assert 'reason: compiler reason' in markdown
    assert 'reason: endpoint reason' in markdown


def test_ai_generator_accuracy_eval_records_live_target_config():
    report = evaluate_cases(
        cases_path=DEFAULT_CASES_PATH,
        case_ids=['routers_hosts_basic'],
        live_config={
            'provider': 'ollama',
            'model': 'gpt-oss:120b',
            'base_url': 'http://192.168.6.65:11434/',
            'timeout_seconds': 180,
        },
    )

    assert report['live_config']['enabled'] is True
    assert report['live_config']['provider'] == 'ollama'
    assert report['live_config']['model'] == 'gpt-oss:120b'
    assert report['live_config']['base_url'] == 'http://192.168.6.65:11434/'
    assert report['live_config']['timeout_seconds'] == 180
    assert report['live_config']['retry_count'] == 1


def test_ai_generator_accuracy_eval_retries_live_timeout_once():
    stub_client = _StubClient([
        _StubResponse(302, {}),
        _StubResponse(502, {'success': False, 'error': 'Ollama chat request timed out after 180s.'}),
        _StubResponse(
            200,
            {
                'success': True,
                'generated_scenario': {
                    'sections': {
                        'Services': {
                            'density': 0.0,
                            'items': [{'selected': 'SSH', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0}],
                        },
                        'Traffic': {
                            'density': 0.0,
                            'items': [{'selected': 'TCP', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0, 'pattern': 'periodic', 'content_type': 'text'}],
                        },
                    },
                },
                'preview': {
                    'hosts': [{} for _ in range(8)],
                    'routers': [{} for _ in range(2)],
                    'switches': [],
                },
                'provider_attempts': [],
            },
        ),
    ])
    case = {
        'id': 'services_traffic_basic',
        'prompt': 'prompt',
        'scenario_name': 'EvalServicesTraffic',
        'expected_endpoint': {
            'success': True,
            'sections': {'Services': {}, 'Traffic': {}},
            'preview_counts': {'hosts_count': 8, 'routers_count': 2},
        },
    }

    with patch('webapp.ai_generator_accuracy_eval.app.test_client', return_value=stub_client):
        result = _endpoint_case(
            case,
            live_config={
                'provider': 'ollama',
                'model': 'qwen3.5:35b',
                'base_url': 'http://grain.utep.edu:11434/',
                'timeout_seconds': 180,
                'retry_count': 1,
            },
        )

    assert result['ok'] is True
    assert len(result['live_attempts']) == 2
    assert result['live_attempts'][0]['status_code'] == 502
    assert result['live_attempts'][1]['status_code'] == 200
    api_calls = [payload for path, payload in stub_client.calls if path == '/api/ai/generate_scenario_preview']
    assert len(api_calls) == 2
    assert api_calls[0]['timeout_seconds'] == 180.0
    assert api_calls[1]['timeout_seconds'] == 240.0


def test_ai_generator_accuracy_eval_does_not_retry_non_timeout_live_failure():
    stub_client = _StubClient([
        _StubResponse(302, {}),
        _StubResponse(400, {'success': False, 'error': 'Specific vulnerability must match an enabled catalog entry by v_path or v_name'}),
    ])
    case = {
        'id': 'reject_vuln_outside_catalog',
        'prompt': 'prompt',
        'scenario_name': 'EvalRejectVuln',
        'expected_endpoint': {
            'success': False,
            'status_code': 400,
            'error': 'Specific vulnerability must match an enabled catalog entry by v_path or v_name',
            'preview_counts': {'hosts_count': 0, 'routers_count': 0},
        },
    }

    with patch('webapp.ai_generator_accuracy_eval.app.test_client', return_value=stub_client):
        result = _endpoint_case(
            case,
            live_config={
                'provider': 'ollama',
                'model': 'qwen3.5:35b',
                'base_url': 'http://grain.utep.edu:11434/',
                'timeout_seconds': 180,
                'retry_count': 1,
            },
        )

    assert result['ok'] is True
    assert len(result['live_attempts']) == 1
    api_calls = [payload for path, payload in stub_client.calls if path == '/api/ai/generate_scenario_preview']
    assert len(api_calls) == 1


def test_ai_generator_accuracy_eval_writes_fixture_bridge_config(tmp_path):
    config_path = _write_live_fixture_bridge_config(
        outputs_dir=tmp_path,
        case={
            'id': 'case-a',
            'vuln_catalog': [{'Name': 'Demo Vuln', 'Path': 'demo/path', 'Description': 'Demo'}],
        },
        live_config={
            'provider': 'ollama',
            'model': 'qwen3.5:35b',
            'base_url': 'http://grain.utep.edu:11434/',
        },
    )

    assert config_path is not None
    config = json.loads((tmp_path / 'case-a_mcp_servers.json').read_text(encoding='utf-8'))
    catalog = json.loads((tmp_path / 'case-a_vuln_catalog.json').read_text(encoding='utf-8'))

    assert catalog == [{'Name': 'Demo Vuln', 'Path': 'demo/path', 'Description': 'Demo'}]
    server_cfg = config['mcpServers']['server']
    assert server_cfg['command']
    assert server_cfg['args']
    assert server_cfg['env']['CORE_TOPO_GEN_VULN_CATALOG_JSON_PATH'].endswith('case-a_vuln_catalog.json')