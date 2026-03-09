from __future__ import annotations

import asyncio

from webapp import app_backend
from webapp.routes import ai_provider


def main() -> int:
    xml_path = 'outputs/scenarios-03-07-26-23-48-40/NewScenario1.xml'
    parsed = app_backend._parse_scenarios_xml(xml_path)
    scenarios = parsed.get('scenarios') or []
    scenario = next((item for item in scenarios if (item or {}).get('name') == 'NewScenario1'), None)
    if not scenario:
        print('scenario not found')
        return 1

    ai_state = scenario.get('ai_generator') if isinstance(scenario.get('ai_generator'), dict) else {}
    payload = {
        'provider': ai_state.get('provider') or 'ollama',
        'bridge_mode': ai_state.get('bridge_mode') or 'ollmcp',
        'base_url': ai_state.get('base_url') or 'http://127.0.0.1:11434',
        'model': ai_state.get('model') or '',
        'mcp_server_path': ai_state.get('mcp_server_path') or 'MCP/server.py',
        'mcp_server_url': ai_state.get('mcp_server_url') or '',
        'servers_json_path': ai_state.get('servers_json_path') or 'MCP/mcp-bridge-servers.json',
        'auto_discovery': bool(ai_state.get('auto_discovery')),
        'hil_enabled': bool(ai_state.get('hil_enabled')),
        'enabled_tools': ai_state.get('enabled_tools') or [],
        'prompt': ai_state.get('draft_prompt') or 'create a scenario with a small number of nodes and an sql vulnerability',
        'core': app_backend._normalize_core_config(parsed.get('core'), include_password=True),
    }
    host = ai_provider._normalize_base_url(payload['base_url'])
    result = asyncio.run(
        ai_provider._ollmcp_generate(
            payload,
            current_scenario=scenario,
            user_prompt=payload['prompt'],
            model=payload['model'],
            host=host,
        )
    )
    generated_scenario = result.get('generated_scenario') if isinstance(result.get('generated_scenario'), dict) else {}
    preview = result.get('preview') if isinstance(result.get('preview'), dict) else {}
    print('scenario_name', generated_scenario.get('name'))
    print('notes', generated_scenario.get('notes'))
    print('preview_hosts', len(preview.get('hosts') or []))
    print('preview_routers', len(preview.get('routers') or []))
    print('preview_switches', len(preview.get('switches') or []))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())