from __future__ import annotations

import json
import tempfile
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Any
from urllib.request import Request
from unittest.mock import patch

from core_topo_gen.planning.ai_topology_intent import compile_ai_topology_intent
from webapp.app_backend import app


DEFAULT_CASES_PATH = Path(__file__).resolve().parents[1] / 'tests' / 'fixtures' / 'ai_generator_accuracy_cases.json'
_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_MCP_SERVER_PATH = _REPO_ROOT / 'MCP' / 'server.py'
_VULN_CATALOG_JSON_PATH_ENV = 'CORE_TOPO_GEN_VULN_CATALOG_JSON_PATH'


def _normalize_live_config(live_config: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(live_config, dict):
        return None
    provider = str(live_config.get('provider') or '').strip().lower()
    model = str(live_config.get('model') or '').strip()
    base_url = str(live_config.get('base_url') or '').strip()
    if not provider or not model or not base_url:
        return None
    normalized = {
        'provider': provider,
        'model': model,
        'base_url': base_url,
    }
    for key in ('api_key', 'bridge_mode', 'mcp_server_path', 'mcp_server_url', 'servers_json_path', 'enforce_ssl', 'skip_bridge', 'timeout_seconds', 'retry_count'):
        if key in live_config:
            normalized[key] = live_config.get(key)
    normalized['retry_count'] = _normalize_live_retry_count(normalized.get('retry_count'))
    return normalized


def _normalize_live_retry_count(raw_value: Any, *, default: int = 1, low: int = 0, high: int = 3) -> int:
    try:
        value = int(raw_value) if raw_value is not None else default
    except (TypeError, ValueError):
        value = default
    return min(max(value, low), high)


def _normalize_live_timeout_seconds(raw_value: Any, *, default: float = 90.0, low: float = 5.0, high: float = 240.0) -> float:
    try:
        value = float(raw_value) if raw_value is not None else default
    except (TypeError, ValueError):
        value = default
    return min(max(value, low), high)


def _retry_live_timeout_seconds(base_timeout_seconds: float, *, attempt_number: int) -> float:
    if attempt_number <= 1:
        return base_timeout_seconds
    bumped = base_timeout_seconds + (60.0 * float(attempt_number - 1))
    return _normalize_live_timeout_seconds(bumped, default=base_timeout_seconds)


def _is_retryable_live_failure(status_code: int | None, error: Any) -> bool:
    try:
        status = int(status_code) if status_code is not None else 0
    except (TypeError, ValueError):
        status = 0
    if status not in {502, 504}:
        return False
    message = str(error or '').strip().lower()
    if not message:
        return False
    return 'timed out' in message or 'timeout' in message


@dataclass(frozen=True)
class _FakeResponse:
    payload: dict[str, Any]

    def read(self) -> bytes:
        return json.dumps(self.payload).encode('utf-8')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


def _load_cases(cases_path: str | Path | None = None) -> list[dict[str, Any]]:
    path = Path(cases_path or DEFAULT_CASES_PATH)
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, list):
        raise ValueError(f'Expected a list of cases in {path}')
    return [item for item in data if isinstance(item, dict)]


def _scenario_payload(name: str = 'AiScenario') -> dict[str, Any]:
    return {
        'name': name,
        'base': {'filepath': ''},
        'sections': {
            'Node Information': {'density': 0, 'items': [{'selected': 'PC', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0}]},
            'Routing': {'density': 0.0, 'items': []},
            'Services': {'density': 0.0, 'items': []},
            'Traffic': {'density': 0.0, 'items': []},
            'Vulnerabilities': {'density': 0.0, 'items': [], 'flag_type': 'text'},
            'Segmentation': {'density': 0.0, 'items': []},
        },
        'notes': '',
    }


def _login(client) -> None:
    response = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    if response.status_code not in (302, 303):
        raise RuntimeError(f'Login failed with status {response.status_code}')


def _fake_ollama_urlopen_factory(*, generated_payload: dict[str, Any], models: list[str] | None = None):
    discovered_models = list(models or ['llama3.1'])

    def fake_urlopen(request_obj: Request, timeout: int = 0):
        url = request_obj.full_url
        if url.endswith('/api/tags'):
            return _FakeResponse({'models': [{'name': name} for name in discovered_models]})
        if not url.endswith('/api/generate'):
            raise AssertionError(f'Unexpected URL {url}')
        body = json.loads((request_obj.data or b'{}').decode('utf-8'))
        if body.get('model') not in discovered_models:
            raise AssertionError(f'Unexpected model {body.get("model")}')
        return _FakeResponse({'response': json.dumps(generated_payload)})

    return fake_urlopen


def _compare_subset(expected: Any, actual: Any, *, path: str = '') -> list[str]:
    mismatches: list[str] = []
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return [f'{path or "root"}: expected object, got {type(actual).__name__}']
        for key, expected_value in expected.items():
            next_path = f'{path}.{key}' if path else str(key)
            if key not in actual:
                mismatches.append(f'{next_path}: missing key')
                continue
            mismatches.extend(_compare_subset(expected_value, actual.get(key), path=next_path))
        return mismatches
    if isinstance(expected, list):
        if not isinstance(actual, list):
            return [f'{path or "root"}: expected list, got {type(actual).__name__}']
        if len(expected) != len(actual):
            return [f'{path or "root"}: expected list length {len(expected)}, got {len(actual)}']
        for index, expected_item in enumerate(expected):
            next_path = f'{path}[{index}]' if path else f'[{index}]'
            mismatches.extend(_compare_subset(expected_item, actual[index], path=next_path))
        return mismatches
    if expected != actual:
        return [f'{path or "root"}: expected {expected!r}, got {actual!r}']
    return mismatches


def _compile_case(case: dict[str, Any]) -> dict[str, Any]:
    expected = case.get('expected_compiled') if isinstance(case.get('expected_compiled'), dict) else None
    if expected is None:
        return {
            'ok': None,
            'skipped': True,
            'mismatches': [],
            'actual': None,
        }
    compiled = compile_ai_topology_intent(
        str(case.get('prompt') or ''),
        vuln_catalog=case.get('vuln_catalog') if isinstance(case.get('vuln_catalog'), list) else None,
    )
    actual = {
        'locked_sections': list(compiled.locked_sections),
        'applied_actions': list(compiled.applied_actions),
        'section_payloads': compiled.section_payloads,
    }
    mismatches = _compare_subset(expected, actual)
    return {
        'ok': not mismatches,
        'skipped': False,
        'mismatches': mismatches,
        'actual': actual,
    }


def _preview_counts(preview: dict[str, Any]) -> dict[str, int]:
    return {
        'hosts_count': len(preview.get('hosts') or []) if isinstance(preview.get('hosts'), list) else 0,
        'routers_count': len(preview.get('routers') or []) if isinstance(preview.get('routers'), list) else 0,
        'switches_count': len(preview.get('switches') or []) if isinstance(preview.get('switches'), list) else 0,
    }


def _default_provider_scenario(case: dict[str, Any]) -> dict[str, Any]:
    scenario_name = str(case.get('scenario_name') or case.get('id') or 'AiEvalScenario')
    llm_sections = case.get('llm_sections') if isinstance(case.get('llm_sections'), dict) else {}
    scenario = {
        'name': scenario_name,
        'density_count': 0,
        'notes': 'Generated by ai-generator accuracy eval.',
        'sections': {
            'Node Information': {'density': 0, 'items': []},
            'Routing': {'density': 0.0, 'items': []},
            'Services': {'density': 0.0, 'items': []},
            'Traffic': {'density': 0.0, 'items': []},
            'Vulnerabilities': {'density': 0.0, 'items': [], 'flag_type': 'text'},
            'Segmentation': {'density': 0.0, 'items': []},
        },
    }
    for section_name, section_payload in llm_sections.items():
        if section_name in scenario['sections'] and isinstance(section_payload, dict):
            scenario['sections'][section_name] = deepcopy(section_payload)
    return {'scenario': scenario}


def _write_live_fixture_bridge_config(
    *,
    outputs_dir: Path,
    case: dict[str, Any],
    live_config: dict[str, Any],
) -> str | None:
    vuln_catalog = case.get('vuln_catalog')
    if not isinstance(vuln_catalog, list):
        return None

    catalog_path = outputs_dir / f"{str(case.get('id') or 'case')}_vuln_catalog.json"
    catalog_path.write_text(json.dumps(vuln_catalog, indent=2), encoding='utf-8')

    server_script = Path(str(live_config.get('mcp_server_path') or _DEFAULT_MCP_SERVER_PATH)).resolve()
    config_path = outputs_dir / f"{str(case.get('id') or 'case')}_mcp_servers.json"
    config_payload = {
        'mcpServers': {
            'server': {
                'command': sys.executable,
                'args': [str(server_script)],
                'cwd': str(_REPO_ROOT),
                'env': {
                    _VULN_CATALOG_JSON_PATH_ENV: str(catalog_path),
                },
            }
        }
    }
    config_path.write_text(json.dumps(config_payload, indent=2), encoding='utf-8')
    return str(config_path)


def _endpoint_case(case: dict[str, Any], *, live_config: dict[str, Any] | None = None) -> dict[str, Any]:
    expected = case.get('expected_endpoint') if isinstance(case.get('expected_endpoint'), dict) else None
    if expected is None:
        return {
            'ok': None,
            'skipped': True,
            'status_code': None,
            'mismatches': [],
            'actual': None,
            'error': None,
        }

    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend
    from webapp.routes import ai_provider
    import MCP.server as mcp_server

    with tempfile.TemporaryDirectory(prefix='ai-generator-eval-') as temp_dir:
        outputs_dir = Path(temp_dir) / 'outputs'
        outputs_dir.mkdir(parents=True, exist_ok=True)

        scenario = _scenario_payload(str(case.get('scenario_name') or case.get('id') or 'AiEvalScenario'))
        scenario['ai_generator'] = {
            'provider': str((live_config or {}).get('provider') or 'ollama'),
            'base_url': str((live_config or {}).get('base_url') or 'http://127.0.0.1:11434'),
            'model': str((live_config or {}).get('model') or 'llama3.1'),
        }

        payload = {
            'provider': str((live_config or {}).get('provider') or 'ollama'),
            'base_url': str((live_config or {}).get('base_url') or 'http://127.0.0.1:11434'),
            'model': str((live_config or {}).get('model') or 'llama3.1'),
            'prompt': str(case.get('prompt') or ''),
            'scenarios': [scenario],
            'scenario_index': 0,
            'core': {},
        }
        for key in ('api_key', 'bridge_mode', 'mcp_server_path', 'mcp_server_url', 'servers_json_path', 'enforce_ssl', 'skip_bridge', 'timeout_seconds'):
            if isinstance(live_config, dict) and key in live_config:
                payload[key] = live_config.get(key)
        if live_config:
            fixture_servers_json_path = _write_live_fixture_bridge_config(
                outputs_dir=outputs_dir,
                case=case,
                live_config=live_config,
            )
            if fixture_servers_json_path:
                payload.pop('mcp_server_path', None)
                payload['servers_json_path'] = fixture_servers_json_path

        patchers: list[Any] = [patch.object(backend, '_outputs_dir', lambda: str(outputs_dir))]
        if not live_config:
            fake_generation = _default_provider_scenario(case)
            patchers.append(
                patch.object(ai_provider, 'urlopen', _fake_ollama_urlopen_factory(generated_payload=fake_generation, models=[str(payload['model'])]))
            )
        if isinstance(case.get('vuln_catalog'), list):
            patchers.append(patch.object(backend, '_load_backend_vuln_catalog_items', lambda: deepcopy(case['vuln_catalog'])))
            patchers.append(patch.object(ai_provider, '_load_vulnerability_catalog_for_prompt', lambda: deepcopy(case['vuln_catalog'])))
            if not live_config:
                patchers.append(patch.object(mcp_server, 'load_vuln_catalog', lambda _repo_root: deepcopy(case['vuln_catalog'])))

        max_attempts = 1
        live_attempts: list[dict[str, Any]] = []
        if live_config:
            max_attempts += _normalize_live_retry_count(live_config.get('retry_count'))
        base_timeout_seconds = _normalize_live_timeout_seconds(payload.get('timeout_seconds'))
        response = None
        data: dict[str, Any] = {}

        with ExitStack() as stack:
            for patcher in patchers:
                stack.enter_context(patcher)
            for attempt_index in range(max_attempts):
                attempt_number = attempt_index + 1
                attempt_payload = deepcopy(payload)
                if live_config:
                    attempt_payload['timeout_seconds'] = _retry_live_timeout_seconds(
                        base_timeout_seconds,
                        attempt_number=attempt_number,
                    )
                response = client.post('/api/ai/generate_scenario_preview', json=attempt_payload)
                data = response.get_json(silent=True) or {}
                live_attempts.append({
                    'attempt': attempt_number,
                    'timeout_seconds': attempt_payload.get('timeout_seconds'),
                    'status_code': response.status_code,
                    'error': str(data.get('error') or ''),
                })
                if not live_config:
                    break
                if attempt_number >= max_attempts:
                    break
                if not _is_retryable_live_failure(response.status_code, data.get('error')):
                    break

        assert response is not None
        generated_scenario = data.get('generated_scenario') if isinstance(data.get('generated_scenario'), dict) else {}
        preview = data.get('preview') if isinstance(data.get('preview'), dict) else {}
        actual = {
            'success': bool(data.get('success')),
            'status_code': response.status_code,
            'error': str(data.get('error') or ''),
            'sections': (generated_scenario.get('sections') if isinstance(generated_scenario.get('sections'), dict) else {}),
            'preview_counts': _preview_counts(preview),
            'provider_attempts_count': len(data.get('provider_attempts') or []) if isinstance(data.get('provider_attempts'), list) else 0,
        }
        mismatches = _compare_subset(expected, actual)
        return {
            'ok': not mismatches,
            'skipped': False,
            'status_code': response.status_code,
            'mismatches': mismatches,
            'actual': actual,
            'error': data.get('error'),
            'provider_response': str(data.get('provider_response') or ''),
            'provider_attempts': data.get('provider_attempts') if isinstance(data.get('provider_attempts'), list) else [],
            'live': bool(live_config),
            'live_attempts': live_attempts,
        }


def _score(results: list[dict[str, Any]]) -> dict[str, Any]:
    scored_results = [item for item in results if not item.get('skipped')]
    total = len(scored_results)
    passed = sum(1 for item in scored_results if item.get('ok'))
    failed_ids = [str(item.get('id') or '') for item in scored_results if item.get('ok') is False]
    skipped_ids = [str(item.get('id') or '') for item in results if item.get('skipped')]
    return {
        'total': total,
        'passed': passed,
        'failed': total - passed,
        'pass_rate': round((passed / total) * 100.0, 2) if total else 0.0,
        'failed_ids': failed_ids,
        'skipped': len(skipped_ids),
        'skipped_ids': skipped_ids,
    }


def compare_reports(current_report: dict[str, Any], previous_report: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(previous_report, dict):
        return None
    current_summary = current_report.get('summary') if isinstance(current_report.get('summary'), dict) else {}
    previous_summary = previous_report.get('summary') if isinstance(previous_report.get('summary'), dict) else {}

    def _delta(area: str) -> dict[str, Any]:
        current_area = current_summary.get(area) if isinstance(current_summary.get(area), dict) else {}
        previous_area = previous_summary.get(area) if isinstance(previous_summary.get(area), dict) else {}
        current_pass_rate = float(current_area.get('pass_rate') or 0.0)
        previous_pass_rate = float(previous_area.get('pass_rate') or 0.0)
        current_failed = set(current_area.get('failed_ids') or [])
        previous_failed = set(previous_area.get('failed_ids') or [])
        return {
            'pass_rate_delta': round(current_pass_rate - previous_pass_rate, 2),
            'passed_delta': int(current_area.get('passed') or 0) - int(previous_area.get('passed') or 0),
            'failed_delta': int(current_area.get('failed') or 0) - int(previous_area.get('failed') or 0),
            'new_failures': sorted(current_failed - previous_failed),
            'resolved_failures': sorted(previous_failed - current_failed),
        }

    return {
        'compiler': _delta('compiler'),
        'endpoint': _delta('endpoint'),
        'previous_cases_path': str(previous_report.get('cases_path') or ''),
    }


def load_latest_report(reports_dir: str | Path, *, exclude_path: str | Path | None = None) -> dict[str, Any] | None:
    reports_path = Path(reports_dir)
    if not reports_path.exists():
        return None
    excluded = Path(exclude_path).resolve() if exclude_path else None
    candidates = sorted(reports_path.glob('ai_generator_accuracy_*.json'))
    for candidate in reversed(candidates):
        if excluded and candidate.resolve() == excluded:
            continue
        try:
            return json.loads(candidate.read_text(encoding='utf-8'))
        except Exception:
            continue
    return None


def evaluate_cases(
    *,
    cases_path: str | Path | None = None,
    case_ids: list[str] | None = None,
    live_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cases = _load_cases(cases_path)
    normalized_live_config = _normalize_live_config(live_config)
    selected = [case for case in cases if not case_ids or str(case.get('id') or '') in set(case_ids)]

    compiler_results: list[dict[str, Any]] = []
    endpoint_results: list[dict[str, Any]] = []
    for case in selected:
        compiler = _compile_case(case)
        endpoint = _endpoint_case(case, live_config=normalized_live_config)
        compiler_results.append({
            'id': str(case.get('id') or ''),
            'prompt': str(case.get('prompt') or ''),
            **compiler,
        })
        endpoint_results.append({
            'id': str(case.get('id') or ''),
            'prompt': str(case.get('prompt') or ''),
            **endpoint,
        })

    summary = {
        'compiler': _score(compiler_results),
        'endpoint': _score(endpoint_results),
        'overall_cases': len(selected),
    }
    return {
        'summary': summary,
        'compiler_results': compiler_results,
        'endpoint_results': endpoint_results,
        'cases_path': str(Path(cases_path or DEFAULT_CASES_PATH)),
        'live_config': {
            'enabled': bool(normalized_live_config),
            'provider': str(normalized_live_config.get('provider') or '') if normalized_live_config else '',
            'model': str(normalized_live_config.get('model') or '') if normalized_live_config else '',
            'base_url': str(normalized_live_config.get('base_url') or '') if normalized_live_config else '',
            'timeout_seconds': normalized_live_config.get('timeout_seconds') if normalized_live_config else None,
            'retry_count': normalized_live_config.get('retry_count') if normalized_live_config else None,
        },
    }


def render_text_report(report: dict[str, Any]) -> str:
    summary = report.get('summary') if isinstance(report.get('summary'), dict) else {}
    compiler = summary.get('compiler') if isinstance(summary.get('compiler'), dict) else {}
    endpoint = summary.get('endpoint') if isinstance(summary.get('endpoint'), dict) else {}
    comparison = report.get('comparison') if isinstance(report.get('comparison'), dict) else {}
    live_config = report.get('live_config') if isinstance(report.get('live_config'), dict) else {}
    lines = [
        'AI Generator Accuracy Evaluation',
        f"Cases: {summary.get('overall_cases', 0)}",
        f"Compiler exact-match: {compiler.get('passed', 0)}/{compiler.get('total', 0)} ({compiler.get('pass_rate', 0.0)}%)",
        f"Endpoint exact-match+preview: {endpoint.get('passed', 0)}/{endpoint.get('total', 0)} ({endpoint.get('pass_rate', 0.0)}%)",
    ]
    if live_config.get('enabled'):
        lines.append(
            f"Live target: {live_config.get('provider')} {live_config.get('model')} @ {live_config.get('base_url')}"
        )
    if int(compiler.get('skipped') or 0):
        lines.append(f"Compiler skipped: {compiler.get('skipped', 0)}")
    if int(endpoint.get('skipped') or 0):
        lines.append(f"Endpoint skipped: {endpoint.get('skipped', 0)}")
    failed_compiler = compiler.get('failed_ids') or []
    failed_endpoint = endpoint.get('failed_ids') or []
    if failed_compiler:
        lines.append(f"Compiler failures: {', '.join(failed_compiler)}")
    if failed_endpoint:
        lines.append(f"Endpoint failures: {', '.join(failed_endpoint)}")
    if comparison:
        compiler_cmp = comparison.get('compiler') if isinstance(comparison.get('compiler'), dict) else {}
        endpoint_cmp = comparison.get('endpoint') if isinstance(comparison.get('endpoint'), dict) else {}
        lines.append(
            f"Compiler delta vs previous: {compiler_cmp.get('pass_rate_delta', 0.0):+0.2f} pts"
        )
        lines.append(
            f"Endpoint delta vs previous: {endpoint_cmp.get('pass_rate_delta', 0.0):+0.2f} pts"
        )
        if endpoint_cmp.get('new_failures'):
            lines.append(f"New endpoint failures: {', '.join(endpoint_cmp.get('new_failures') or [])}")
        if endpoint_cmp.get('resolved_failures'):
            lines.append(f"Resolved endpoint failures: {', '.join(endpoint_cmp.get('resolved_failures') or [])}")

    def _append_skips(title: str, results: list[dict[str, Any]]) -> None:
        skipped = [item for item in results if item.get('skipped')]
        if not skipped:
            return
        lines.append(title)
        for item in skipped:
            reason = str(item.get('error') or 'Skipped')
            lines.append(f"- {str(item.get('id') or '')}: {reason}")

    _append_skips('Compiler skipped cases:', report.get('compiler_results') if isinstance(report.get('compiler_results'), list) else [])
    _append_skips('Endpoint skipped cases:', report.get('endpoint_results') if isinstance(report.get('endpoint_results'), list) else [])
    return '\n'.join(lines)


def render_markdown_report(report: dict[str, Any]) -> str:
    summary = report.get('summary') if isinstance(report.get('summary'), dict) else {}
    compiler = summary.get('compiler') if isinstance(summary.get('compiler'), dict) else {}
    endpoint = summary.get('endpoint') if isinstance(summary.get('endpoint'), dict) else {}
    comparison = report.get('comparison') if isinstance(report.get('comparison'), dict) else {}
    live_config = report.get('live_config') if isinstance(report.get('live_config'), dict) else {}

    lines = [
        '# AI Generator Accuracy Evaluation',
        '',
        f"- Cases: {summary.get('overall_cases', 0)}",
        f"- Compiler exact-match: {compiler.get('passed', 0)}/{compiler.get('total', 0)} ({compiler.get('pass_rate', 0.0)}%)",
        f"- Endpoint exact-match+preview: {endpoint.get('passed', 0)}/{endpoint.get('total', 0)} ({endpoint.get('pass_rate', 0.0)}%)",
    ]
    if live_config.get('enabled'):
        lines.append(f"- Live target: {live_config.get('provider')} {live_config.get('model')} @ {live_config.get('base_url')}")

    if int(compiler.get('skipped') or 0):
        lines.append(f"- Compiler skipped: {compiler.get('skipped', 0)}")
    if int(endpoint.get('skipped') or 0):
        lines.append(f"- Endpoint skipped: {endpoint.get('skipped', 0)}")

    failed_compiler = compiler.get('failed_ids') or []
    failed_endpoint = endpoint.get('failed_ids') or []
    if failed_compiler:
        lines.append(f"- Compiler failures: {', '.join(failed_compiler)}")
    if failed_endpoint:
        lines.append(f"- Endpoint failures: {', '.join(failed_endpoint)}")

    if comparison:
        compiler_cmp = comparison.get('compiler') if isinstance(comparison.get('compiler'), dict) else {}
        endpoint_cmp = comparison.get('endpoint') if isinstance(comparison.get('endpoint'), dict) else {}
        lines.extend([
            '',
            '## Delta Vs Previous',
            '',
            f"- Compiler pass-rate delta: {compiler_cmp.get('pass_rate_delta', 0.0):+0.2f} pts",
            f"- Endpoint pass-rate delta: {endpoint_cmp.get('pass_rate_delta', 0.0):+0.2f} pts",
        ])
        if compiler_cmp.get('new_failures'):
            lines.append(f"- New compiler failures: {', '.join(compiler_cmp.get('new_failures') or [])}")
        if compiler_cmp.get('resolved_failures'):
            lines.append(f"- Resolved compiler failures: {', '.join(compiler_cmp.get('resolved_failures') or [])}")
        if endpoint_cmp.get('new_failures'):
            lines.append(f"- New endpoint failures: {', '.join(endpoint_cmp.get('new_failures') or [])}")
        if endpoint_cmp.get('resolved_failures'):
            lines.append(f"- Resolved endpoint failures: {', '.join(endpoint_cmp.get('resolved_failures') or [])}")

    def _append_results(title: str, results: list[dict[str, Any]]) -> None:
        lines.extend(['', f'## {title}', ''])
        for item in results:
            case_id = str(item.get('id') or '')
            if item.get('skipped'):
                reason = str(item.get('error') or 'Skipped')
                lines.append(f"- `{case_id}`: skipped")
                lines.append(f"  - reason: {reason}")
                continue
            status = 'pass' if item.get('ok') else 'fail'
            lines.append(f"- `{case_id}`: {status}")
            mismatches = item.get('mismatches') or []
            for mismatch in mismatches[:5]:
                lines.append(f"  - {mismatch}")

    _append_results('Compiler Cases', report.get('compiler_results') if isinstance(report.get('compiler_results'), list) else [])
    _append_results('Endpoint Cases', report.get('endpoint_results') if isinstance(report.get('endpoint_results'), list) else [])
    return '\n'.join(lines) + '\n'
