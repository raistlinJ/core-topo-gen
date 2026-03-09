from __future__ import annotations

import json
import sys

from webapp import app_backend


def main() -> int:
    xml_path = 'outputs/scenarios-03-07-26-23-48-40/NewScenario1.xml'
    parsed = app_backend._parse_scenarios_xml(xml_path)
    scenarios = parsed.get('scenarios') or []
    scenario = next((item for item in scenarios if (item or {}).get('name') == 'NewScenario1'), None)
    if not scenario:
        print('scenario not found', file=sys.stderr)
        return 1

    ai_state = scenario.get('ai_generator') if isinstance(scenario.get('ai_generator'), dict) else {}
    payload = {
        'request_id': 'debug-newscenario1-stream',
        'provider': ai_state.get('provider') or 'ollama',
        'bridge_mode': ai_state.get('bridge_mode') or 'ollmcp',
        'base_url': ai_state.get('base_url') or 'http://127.0.0.1:11434',
        'model': ai_state.get('model') or '',
        'mcp_server_path': ai_state.get('mcp_server_path') or 'MCP/server.py',
        'mcp_server_url': ai_state.get('mcp_server_url') or '',
        'servers_json_path': ai_state.get('servers_json_path') or 'MCP/ollmcp-servers.json',
        'auto_discovery': bool(ai_state.get('auto_discovery')),
        'hil_enabled': bool(ai_state.get('hil_enabled')),
        'enabled_tools': ai_state.get('enabled_tools') or [],
        'prompt': ai_state.get('draft_prompt') or 'create a scenario with a small number of nodes and an sql vulnerability',
        'scenarios': scenarios,
        'scenario_index': scenarios.index(scenario),
        'core': app_backend._normalize_core_config(parsed.get('core'), include_password=True),
    }

    app = app_backend.app
    client = app.test_client()
    client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'}, follow_redirects=True)
    response = client.open('/api/ai/generate_scenario_preview_stream', method='POST', json=payload, buffered=False)
    print(f'STATUS {response.status_code}')
    for chunk in response.response:
        if not chunk:
            continue
        text = chunk.decode('utf-8', errors='replace')
        print(text, end='')
        sys.stdout.flush()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())