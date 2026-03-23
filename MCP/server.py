from __future__ import annotations

import json
import os
import re
import sys
import uuid
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core_topo_gen.utils.vuln_process import load_vuln_catalog, resolve_vulnerability_catalog_entry
from core_topo_gen.utils.segmentation import SEGMENTATION_GUI_TYPES
from core_topo_gen.utils.services import DEFAULT_SERVICE_POOL
from webapp import app_backend


JSONRPC_VERSION = '2.0'
PROTOCOL_VERSION = '2025-11-05'
PROTOCOL_VERSION = '2025-03-26'
_VULN_CATALOG_JSON_PATH_ENV = 'CORE_TOPO_GEN_VULN_CATALOG_JSON_PATH'
_VULN_CATALOG_JSON_ENV = 'CORE_TOPO_GEN_VULN_CATALOG_JSON'


def _jsonrpc_result(message_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {'jsonrpc': JSONRPC_VERSION, 'id': message_id, 'result': result}


def _jsonrpc_error(message_id: Any, code: int, message: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        'jsonrpc': JSONRPC_VERSION,
        'id': message_id,
        'error': {
            'code': code,
            'message': message,
        },
    }
    if data:
        payload['error']['data'] = data
    return payload


def _load_vulnerability_catalog_override() -> list[dict[str, str]] | None:
    raw_path = str(os.environ.get(_VULN_CATALOG_JSON_PATH_ENV) or '').strip()
    raw_json = str(os.environ.get(_VULN_CATALOG_JSON_ENV) or '').strip()

    payload: Any = None
    if raw_path:
        try:
            with open(raw_path, 'r', encoding='utf-8') as handle:
                payload = json.load(handle)
        except Exception:
            return None
    elif raw_json:
        try:
            payload = json.loads(raw_json)
        except Exception:
            return None
    else:
        return None

    if not isinstance(payload, list):
        return None
    return [dict(entry) for entry in payload if isinstance(entry, dict)]


@dataclass
class ScenarioDraft:
    draft_id: str
    scenario: dict[str, Any]
    core: dict[str, Any]
    created_at: str
    updated_at: str
    preview: dict[str, Any] | None = None
    preview_plan: dict[str, Any] | None = None
    flow_meta: dict[str, Any] | None = None
    last_saved_xml_path: str | None = None

    def to_summary(self) -> dict[str, Any]:
        preview = self.preview if isinstance(self.preview, dict) else {}
        return {
            'draft_id': self.draft_id,
            'name': str(self.scenario.get('name') or ''),
            'notes': str(self.scenario.get('notes') or ''),
            'updated_at': self.updated_at,
            'preview_summary': {
                'routers': len(preview.get('routers') or []),
                'hosts': len(preview.get('hosts') or []),
                'switches': len(preview.get('switches') or []),
                'seed': preview.get('seed'),
            } if preview else None,
            'last_saved_xml_path': self.last_saved_xml_path,
        }


class DraftStore:
    def __init__(self) -> None:
        self._drafts: dict[str, ScenarioDraft] = {}

    def create(self, *, name: str | None = None, core: dict[str, Any] | None = None, scenario: dict[str, Any] | None = None) -> ScenarioDraft:
        now = app_backend._utc_now_iso() if hasattr(app_backend, '_utc_now_iso') else app_backend._local_timestamp_safe()
        display_name = str(name or '').strip() or f'Scenario {len(self._drafts) + 1}'
        scenario_payload = deepcopy(scenario) if isinstance(scenario, dict) else deepcopy(app_backend._default_scenario_payload(display_name))
        if not str(scenario_payload.get('name') or '').strip():
            scenario_payload['name'] = display_name
        draft_id = f'draft-{uuid.uuid4()}'
        normalized_core = app_backend._normalize_core_config(core, include_password=True) if isinstance(core, dict) else app_backend._default_core_dict()
        draft = ScenarioDraft(
            draft_id=draft_id,
            scenario=scenario_payload,
            core=normalized_core,
            created_at=now,
            updated_at=now,
        )
        self._drafts[draft_id] = draft
        return draft

    def get(self, draft_id: str) -> ScenarioDraft:
        draft = self._drafts.get(str(draft_id or ''))
        if draft is None:
            raise KeyError(f'Unknown draft_id: {draft_id}')
        return draft

    def delete(self, draft_id: str) -> bool:
        return self._drafts.pop(str(draft_id or ''), None) is not None

    def list(self) -> list[dict[str, Any]]:
        return [draft.to_summary() for draft in self._drafts.values()]


@dataclass(frozen=True)
class MCPTool:
    name: str
    description: str
    input_schema: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            'name': self.name,
            'description': self.description,
            'inputSchema': self.input_schema,
        }


class ScenarioAuthoringMCPServer:
    def __init__(self) -> None:
        self._drafts = DraftStore()
        self._tools = self._build_tools()
        self._vulnerability_catalog: list[dict[str, str]] | None = None
        self._last_vulnerability_search: dict[str, Any] | None = None

    def _build_tools(self) -> dict[str, MCPTool]:
        return {
            'scenario.create_draft': MCPTool(
                name='scenario.create_draft',
                description='Create an in-memory scenario draft with default backend-compatible sections.',
                input_schema={
                    'type': 'object',
                    'properties': {
                        'name': {'type': 'string'},
                        'scenario': {'type': 'object'},
                        'core': {'type': 'object'},
                    },
                    'additionalProperties': False,
                },
            ),
            'scenario.get_draft': MCPTool(
                name='scenario.get_draft',
                description='Fetch the current state of a draft, including the latest preview summary if available.',
                input_schema={
                    'type': 'object',
                    'properties': {
                        'draft_id': {'type': 'string'},
                    },
                    'required': ['draft_id'],
                    'additionalProperties': False,
                },
            ),
            'scenario.list_drafts': MCPTool(
                name='scenario.list_drafts',
                description='List currently loaded in-memory scenario drafts.',
                input_schema={
                    'type': 'object',
                    'properties': {},
                    'additionalProperties': False,
                },
            ),
            'scenario.get_authoring_schema': MCPTool(
                name='scenario.get_authoring_schema',
                description='Return backend-backed authoring values, defaults, and section semantics for Node Information, Traffic, Services, Segmentation, and related sections.',
                input_schema={
                    'type': 'object',
                    'properties': {
                        'section_name': {'type': 'string'},
                    },
                    'additionalProperties': False,
                },
            ),
            'scenario.set_notes': MCPTool(
                name='scenario.set_notes',
                description='Set freeform scenario notes on a draft.',
                input_schema={
                    'type': 'object',
                    'properties': {
                        'draft_id': {'type': 'string'},
                        'notes': {'type': 'string'},
                        'note': {'type': 'string'},
                        'text': {'type': 'string'},
                        'content': {'type': 'string'},
                        'summary': {'type': 'string'},
                        'description': {'type': 'string'},
                    },
                    'required': ['draft_id'],
                    'additionalProperties': False,
                },
            ),
            'scenario.replace_section': MCPTool(
                name='scenario.replace_section',
                description='Replace one section payload with a backend-compatible object.',
                input_schema={
                    'type': 'object',
                    'properties': {
                        'draft_id': {'type': 'string'},
                        'section_name': {'type': 'string'},
                        'section_payload': {
                            'oneOf': [
                                {'type': 'object'},
                                {'type': 'string'},
                            ],
                        },
                    },
                    'required': ['draft_id', 'section_name', 'section_payload'],
                    'additionalProperties': False,
                },
            ),
            'scenario.add_node_role_item': MCPTool(
                name='scenario.add_node_role_item',
                description='Append a concrete Node Information row for explicit host counts, including Docker hosts. This tool is only for host nodes, not routers. If the user asks for total topology nodes plus a separate router count, host rows should cover only the non-router remainder.',
                input_schema={
                    'type': 'object',
                    'properties': {
                        'draft_id': {'type': 'string'},
                        'selected': {'type': 'string'},
                        'role': {'type': 'string'},
                        'node_type': {'type': 'string'},
                        'count': {'type': 'integer'},
                        'v_count': {'type': 'integer'},
                        'factor': {'type': 'number'},
                        'v_metric': {'type': 'string'},
                        'total_nodes': {'type': 'integer'},
                    },
                    'required': ['draft_id'],
                    'additionalProperties': False,
                },
            ),
            'scenario.add_service_item': MCPTool(
                name='scenario.add_service_item',
                description='Append a concrete Services row with explicit count or section density defaults that materialize in preview/runtime.',
                input_schema={
                    'type': 'object',
                    'properties': {
                        'draft_id': {'type': 'string'},
                        'selected': {'type': 'string'},
                        'service': {'type': 'string'},
                        'name': {'type': 'string'},
                        'count': {'type': 'integer'},
                        'v_count': {'type': 'integer'},
                        'factor': {'type': 'number'},
                        'density': {'type': 'number'},
                        'v_metric': {'type': 'string'},
                    },
                    'required': ['draft_id'],
                    'additionalProperties': False,
                },
            ),
            'scenario.add_routing_item': MCPTool(
                name='scenario.add_routing_item',
                description='Append a concrete Routing row with explicit router count and optional router-edge planning fields. Use this tool for router quantity. If the user asks for total topology nodes plus a separate router count, this tool should carry the router portion while Node Information covers the non-router host remainder.',
                input_schema={
                    'type': 'object',
                    'properties': {
                        'draft_id': {'type': 'string'},
                        'selected': {'type': 'string'},
                        'protocol': {'type': 'string'},
                        'kind': {'type': 'string'},
                        'type': {'type': 'string'},
                        'count': {'type': 'integer'},
                        'v_count': {'type': 'integer'},
                        'factor': {'type': 'number'},
                        'density': {'type': 'number'},
                        'v_metric': {'type': 'string'},
                        'r2r_mode': {'type': 'string'},
                        'r2r_edges': {'type': 'integer'},
                        'r2s_mode': {'type': 'string'},
                        'r2s_edges': {'type': 'integer'},
                        'r2s_hosts_min': {'type': 'integer'},
                        'r2s_hosts_max': {'type': 'integer'},
                    },
                    'required': ['draft_id'],
                    'additionalProperties': False,
                },
            ),
            'scenario.add_traffic_item': MCPTool(
                name='scenario.add_traffic_item',
                description='Append a concrete Traffic row for TCP or UDP flows with backend-compatible defaults.',
                input_schema={
                    'type': 'object',
                    'properties': {
                        'draft_id': {'type': 'string'},
                        'selected': {'type': 'string'},
                        'protocol': {'type': 'string'},
                        'kind': {'type': 'string'},
                        'count': {'type': 'integer'},
                        'v_count': {'type': 'integer'},
                        'factor': {'type': 'number'},
                        'v_metric': {'type': 'string'},
                        'density': {'type': 'number'},
                        'pattern': {'type': 'string'},
                        'rate_kbps': {'type': 'number'},
                        'period_s': {'type': 'number'},
                        'jitter_pct': {'type': 'number'},
                        'content_type': {'type': 'string'},
                        'content': {'type': 'string'},
                        'payload': {'type': 'string'},
                    },
                    'required': ['draft_id'],
                    'additionalProperties': False,
                },
            ),
            'scenario.add_segmentation_item': MCPTool(
                name='scenario.add_segmentation_item',
                description='Append a concrete Segmentation row with explicit count or factor plus section density defaults.',
                input_schema={
                    'type': 'object',
                    'properties': {
                        'draft_id': {'type': 'string'},
                        'selected': {'type': 'string'},
                        'kind': {'type': 'string'},
                        'type': {'type': 'string'},
                        'name': {'type': 'string'},
                        'count': {'type': 'integer'},
                        'v_count': {'type': 'integer'},
                        'factor': {'type': 'number'},
                        'density': {'type': 'number'},
                        'v_metric': {'type': 'string'},
                    },
                    'required': ['draft_id'],
                    'additionalProperties': False,
                },
            ),
            'scenario.search_vulnerability_catalog': MCPTool(
                name='scenario.search_vulnerability_catalog',
                description='Search the local vulnerability catalog by free text, catalog metadata, and available README content to find concrete vulnerabilities the draft can reference.',
                input_schema={
                    'type': 'object',
                    'properties': {
                        'query': {'type': 'string'},
                        'v_type': {'type': 'string'},
                        'v_vector': {'type': 'string'},
                        'limit': {'type': 'integer'},
                    },
                    'additionalProperties': False,
                },
            ),
            'scenario.add_vulnerability_item': MCPTool(
                name='scenario.add_vulnerability_item',
                description='Append exactly one concrete vulnerability item to the draft Vulnerabilities section. Prefer search_vulnerability_catalog first, then pass explicit v_name and v_path from the chosen result. For requests like "3 different vulnerabilities", call this tool three separate times with one vulnerability per call. Do not pass factor.',
                input_schema={
                    'type': 'object',
                    'properties': {
                        'draft_id': {'type': 'string'},
                        'v_name': {'type': 'string'},
                        'v_path': {'type': 'string'},
                        'v_type': {'type': 'string'},
                        'v_vector': {'type': 'string'},
                        'v_count': {'type': 'integer'},
                    },
                    'required': ['draft_id'],
                    'additionalProperties': False,
                },
            ),
            'scenario.preview_draft': MCPTool(
                name='scenario.preview_draft',
                description='Run the existing preview planner against the in-memory draft and return the computed preview.',
                input_schema={
                    'type': 'object',
                    'properties': {
                        'draft_id': {'type': 'string'},
                        'seed': {'type': 'integer'},
                        'core': {'type': 'object'},
                    },
                    'required': ['draft_id'],
                    'additionalProperties': False,
                },
            ),
            'scenario.save_xml': MCPTool(
                name='scenario.save_xml',
                description='Persist the in-memory draft through the existing XML save path and return the written XML path.',
                input_schema={
                    'type': 'object',
                    'properties': {
                        'draft_id': {'type': 'string'},
                        'core': {'type': 'object'},
                    },
                    'required': ['draft_id'],
                    'additionalProperties': False,
                },
            ),
            'scenario.delete_draft': MCPTool(
                name='scenario.delete_draft',
                description='Delete an in-memory draft from the MCP session.',
                input_schema={
                    'type': 'object',
                    'properties': {
                        'draft_id': {'type': 'string'},
                    },
                    'required': ['draft_id'],
                    'additionalProperties': False,
                },
            ),
        }

    def handle_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(message, dict):
            return _jsonrpc_error(None, -32600, 'Invalid Request')
        method = message.get('method')
        message_id = message.get('id')
        params = message.get('params') if isinstance(message.get('params'), dict) else {}
        if method == 'initialize':
            return _jsonrpc_result(message_id, {
                'protocolVersion': PROTOCOL_VERSION,
                'serverInfo': {'name': 'core-topo-gen-mcp', 'version': '0.1.0'},
                'capabilities': {'tools': {'listChanged': False}},
                'instructions': 'Use the scenario.* tools to author drafts, preview them, and persist XML through repo-native backend logic.',
            })
        if method == 'notifications/initialized':
            return None
        if method == 'tools/list':
            return _jsonrpc_result(message_id, {'tools': [tool.to_dict() for tool in self._tools.values()]})
        if method == 'tools/call':
            try:
                tool_name = str(params.get('name') or '').strip()
                tool_args = params.get('arguments') if isinstance(params.get('arguments'), dict) else {}
                result = self._call_tool(tool_name, tool_args)
                return _jsonrpc_result(message_id, {
                    'content': [
                        {
                            'type': 'text',
                            'text': json.dumps(result, indent=2, sort_keys=True),
                        }
                    ],
                    'structuredContent': result,
                    'isError': False,
                })
            except KeyError as exc:
                return _jsonrpc_error(message_id, -32001, str(exc))
            except ValueError as exc:
                return _jsonrpc_error(message_id, -32602, str(exc))
            except Exception as exc:
                return _jsonrpc_error(message_id, -32000, str(exc))
        return _jsonrpc_error(message_id, -32601, f'Method not found: {method}')

    def _call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool_name not in self._tools:
            raise ValueError(f'Unknown tool: {tool_name}')
        if tool_name == 'scenario.create_draft':
            draft = self._drafts.create(name=arguments.get('name'), core=arguments.get('core'), scenario=arguments.get('scenario'))
            return {'draft': self._serialize_draft(draft)}
        if tool_name == 'scenario.get_draft':
            draft = self._drafts.get(str(arguments.get('draft_id') or ''))
            return {'draft': self._serialize_draft(draft)}
        if tool_name == 'scenario.list_drafts':
            return {'drafts': self._drafts.list()}
        if tool_name == 'scenario.get_authoring_schema':
            return self._get_authoring_schema(arguments)
        if tool_name == 'scenario.set_notes':
            draft = self._drafts.get(str(arguments.get('draft_id') or ''))
            notes_text = self._coerce_notes_text(arguments)
            if not notes_text:
                raise ValueError('notes is required')
            draft.scenario['notes'] = notes_text
            draft.updated_at = app_backend._local_timestamp_safe()
            return {'draft': self._serialize_draft(draft)}
        if tool_name == 'scenario.replace_section':
            draft = self._drafts.get(str(arguments.get('draft_id') or ''))
            section_name = self._normalize_section_name(arguments.get('section_name'))
            if not section_name:
                raise ValueError('section_name is required')
            sections = draft.scenario.get('sections') if isinstance(draft.scenario.get('sections'), dict) else {}
            if section_name not in sections:
                raise ValueError(f'Unknown section_name: {section_name}')
            section_payload = self._coerce_section_payload(arguments.get('section_payload'), section_name=section_name)
            if not isinstance(section_payload, dict):
                raise ValueError('section_payload must be an object')
            section_payload = self._normalize_replaced_section_payload(section_name, section_payload)
            sections[section_name] = deepcopy(section_payload)
            draft.scenario['sections'] = sections
            draft.updated_at = app_backend._local_timestamp_safe()
            draft.preview = None
            draft.preview_plan = None
            draft.flow_meta = None
            return {'draft': self._serialize_draft(draft)}
        if tool_name == 'scenario.add_node_role_item':
            draft = self._drafts.get(str(arguments.get('draft_id') or ''))
            return self._add_node_role_item(draft, arguments)
        if tool_name == 'scenario.add_service_item':
            draft = self._drafts.get(str(arguments.get('draft_id') or ''))
            return self._add_service_item(draft, arguments)
        if tool_name == 'scenario.add_routing_item':
            draft = self._drafts.get(str(arguments.get('draft_id') or ''))
            return self._add_routing_item(draft, arguments)
        if tool_name == 'scenario.add_traffic_item':
            draft = self._drafts.get(str(arguments.get('draft_id') or ''))
            return self._add_traffic_item(draft, arguments)
        if tool_name == 'scenario.add_segmentation_item':
            draft = self._drafts.get(str(arguments.get('draft_id') or ''))
            return self._add_segmentation_item(draft, arguments)
        if tool_name == 'scenario.search_vulnerability_catalog':
            return self._search_vulnerability_catalog(arguments)
        if tool_name == 'scenario.add_vulnerability_item':
            draft = self._drafts.get(str(arguments.get('draft_id') or ''))
            return self._add_vulnerability_item(draft, arguments)
        if tool_name == 'scenario.preview_draft':
            draft = self._drafts.get(str(arguments.get('draft_id') or ''))
            core = arguments.get('core') if isinstance(arguments.get('core'), dict) else draft.core
            result = self._preview_draft(draft, core=core, seed=arguments.get('seed'))
            return result
        if tool_name == 'scenario.save_xml':
            draft = self._drafts.get(str(arguments.get('draft_id') or ''))
            core = arguments.get('core') if isinstance(arguments.get('core'), dict) else draft.core
            result = self._save_draft(draft, core=core)
            return result
        if tool_name == 'scenario.delete_draft':
            draft_id = str(arguments.get('draft_id') or '')
            deleted = self._drafts.delete(draft_id)
            return {'deleted': deleted, 'draft_id': draft_id}
        raise ValueError(f'Unknown tool: {tool_name}')

    def _normalize_section_name(self, value: Any) -> str:
        text = str(value or '').strip()
        if not text:
            return ''
        canonical_map = {
            'nodeinformation': 'Node Information',
            'nodeinfo': 'Node Information',
            'nodes': 'Node Information',
            'scenarioinfo': 'Node Information',
            'routing': 'Routing',
            'routinginfo': 'Routing',
            'services': 'Services',
            'service': 'Services',
            'servicesinfo': 'Services',
            'traffic': 'Traffic',
            'trafficinfo': 'Traffic',
            'vulnerabilities': 'Vulnerabilities',
            'vulnerability': 'Vulnerabilities',
            'vulns': 'Vulnerabilities',
            'vuln': 'Vulnerabilities',
            'vulnerabilityinfo': 'Vulnerabilities',
            'segmentation': 'Segmentation',
            'segments': 'Segmentation',
            'segmentationinfo': 'Segmentation',
            'notes': 'Notes',
            'notesection': 'Notes',
        }
        collapsed = ''.join(ch for ch in text.lower() if ch.isalnum())
        return canonical_map.get(collapsed, text)

    def _coerce_notes_text(self, value: Any) -> str:
        if not isinstance(value, dict):
            return str(value or '').strip()
        for key in ('notes', 'note', 'text', 'content', 'summary', 'description'):
            text = str(value.get(key) or '').strip()
            if text:
                return text
        return ''

    def _default_section_payload(self, section_name: str) -> dict[str, Any]:
        if section_name == 'Node Information':
            return {'total_nodes': 0, 'density': 0, 'items': []}
        if section_name == 'Vulnerabilities':
            return {'density': 0, 'items': [], 'flag_type': 'text'}
        if section_name == 'Notes':
            return {'notes': ''}
        return {'density': 0, 'items': []}

    def _build_authoring_schema(self) -> dict[str, Any]:
        random_options = getattr(app_backend, '_RANDOM_OPTIONS_BY_SECTION', {}) or {}
        traffic_defaults = getattr(app_backend, '_TRAFFIC_NUMERIC_DEFAULTS', {}) or {}
        traffic_content_types = list(getattr(app_backend, '_TRAFFIC_CONTENT_TYPE_OPTIONS', []) or [])
        traffic_patterns = list(getattr(app_backend, '_TRAFFIC_PATTERN_OPTIONS', []) or [])
        routing_edge_modes = list(getattr(app_backend, '_ROUTING_EDGE_MODE_OPTIONS', []) or [])
        routing_protocols = list(random_options.get('Routing') or [])
        node_roles = list(random_options.get('Node Information') or [])
        traffic_protocols = list(random_options.get('Traffic') or [])
        service_suggestions = list(random_options.get('Services') or list(DEFAULT_SERVICE_POOL))
        segmentation_random = list(random_options.get('Segmentation') or [])
        segmentation_explicit = list(SEGMENTATION_GUI_TYPES or segmentation_random)
        vuln_catalog = self._load_vulnerability_catalog()

        def field_schema(
            *,
            value_type: str,
            required: bool = False,
            enum: list[Any] | None = None,
            default: Any | None = None,
            aliases: list[str] | None = None,
            notes: list[str] | None = None,
            minimum: int | float | None = None,
        ) -> dict[str, Any]:
            payload: dict[str, Any] = {
                'type': value_type,
                'required': required,
            }
            if enum:
                payload['enum'] = list(enum)
            if default is not None:
                payload['default'] = default
            if aliases:
                payload['aliases'] = list(aliases)
            if notes:
                payload['notes'] = list(notes)
            if minimum is not None:
                payload['minimum'] = minimum
            return payload

        return {
            'schema_version': '2025-03-26',
            'top_level': {
                'section_order': [
                    'Node Information',
                    'Routing',
                    'Services',
                    'Traffic',
                    'Vulnerabilities',
                    'Segmentation',
                    'Notes',
                ],
                'scenario_fields': {
                    'name': field_schema(value_type='string', required=True, notes=['Scenario display name.']),
                    'notes': field_schema(value_type='string', notes=['Freeform scenario notes.']),
                    'density_count': field_schema(value_type='integer', default=10, minimum=0, notes=['Global density helper used by parts of the web workflow.']),
                },
                'notes': [
                    'Use section payloads that match the per-section contracts below.',
                    'Prefer explicit Count rows when the prompt asks for exact quantities.',
                    'Some sections support Random placeholders, but explicit concrete rows give the model more control.',
                    'When a section exposes ui_selected_values, treat those as the authoritative selectable labels and do not invent free-text selected values.',
                    'Free-text fields still exist for scenario name, notes, and vulnerability identifiers such as v_name/v_path.',
                ],
            },
            'sections': {
                'Node Information': {
                    'parser_backed': True,
                    'section_aliases': ['nodeinfo', 'nodes', 'scenarioinfo'],
                    'ui_selected_values': ['Server', 'Workstation', 'PC', 'Docker', 'Random'],
                    'selected_values': node_roles,
                    'supports_random_selected': True,
                    'random_selected_values': node_roles,
                    'section_fields': {
                        'density': field_schema(value_type='number', default=0, minimum=0, notes=['Section density is present in normalized payloads, but explicit node counts usually matter more than density here.']),
                        'density_count': field_schema(value_type='integer', default=10, minimum=0, notes=['UI/planning helper for density-based workflows.']),
                        'base_nodes': field_schema(value_type='integer', minimum=0, notes=['Optional planning hint.']),
                        'total_nodes': field_schema(value_type='integer', default=0, minimum=0, notes=['Scenario-level planned total for this section.']),
                    },
                    'item_fields': {
                        'selected': field_schema(value_type='string', required=True, enum=node_roles, default='PC', notes=['Concrete node role to materialize. Random is also accepted if you want backend concretization.']),
                        'factor': field_schema(value_type='number', default=1.0, minimum=0, notes=['Weight used when not pinning explicit counts.']),
                        'v_metric': field_schema(value_type='string', default='Count', enum=['Count'], notes=['Use Count when the prompt specifies exact host counts.']),
                        'v_count': field_schema(value_type='integer', default=1, minimum=0, notes=['Explicit number of hosts for the selected role.']),
                    },
                    'item_defaults': {'factor': 1.0, 'v_metric': 'Count', 'v_count': 1},
                    'notes': [
                        'Use selected with one of the concrete host roles.',
                        'For explicit host counts, prefer v_metric="Count" with v_count.',
                    ],
                },
                'Routing': {
                    'parser_backed': True,
                    'section_aliases': ['routinginfo'],
                    'ui_selected_values': ['RIP', 'RIPNG', 'BGP', 'OSPFv2', 'OSPFv3', 'Random'],
                    'selected_values': routing_protocols,
                    'supports_random_selected': True,
                    'random_selected_values': routing_protocols,
                    'edge_mode_values': routing_edge_modes,
                    'section_fields': {
                        'density': field_schema(value_type='number', default=0.5, minimum=0),
                    },
                    'item_fields': {
                        'selected': field_schema(value_type='string', required=True, enum=routing_protocols, default=routing_protocols[0] if routing_protocols else 'OSPFv2'),
                        'factor': field_schema(value_type='number', default=1.0, minimum=0),
                        'v_metric': field_schema(value_type='string', default='Count', enum=['Count']),
                        'v_count': field_schema(value_type='integer', default=1, minimum=0, notes=['Explicit router count for this routing protocol row.']),
                        'r2r_mode': field_schema(value_type='string', enum=routing_edge_modes, notes=['Router-to-router edge planning mode.']),
                        'r2r_edges': field_schema(value_type='integer', minimum=0, notes=['Concrete router-to-router edge count when the selected mode uses explicit counts.']),
                        'r2s_mode': field_schema(value_type='string', enum=routing_edge_modes, notes=['Router-to-switch/router-to-segment edge planning mode.']),
                        'r2s_edges': field_schema(value_type='integer', minimum=0, notes=['Concrete router-to-segment edge count when the selected mode uses explicit counts.']),
                        'r2s_hosts_min': field_schema(value_type='integer', minimum=0, notes=['Minimum hosts attached per routed segment.']),
                        'r2s_hosts_max': field_schema(value_type='integer', minimum=0, notes=['Maximum hosts attached per routed segment.']),
                    },
                    'item_defaults': {'factor': 1.0, 'v_metric': 'Count', 'v_count': 1},
                    'notes': [
                        'Routing rows can carry advanced edge-shape hints in addition to protocol/count selection.',
                        'When prompts mention hub/spoke or sparse/meshed routers, use the r2r_* and r2s_* fields rather than only selected.',
                    ],
                },
                'Services': {
                    'parser_backed': True,
                    'section_aliases': ['service', 'servicesinfo'],
                    'ui_selected_values': ['SSH', 'HTTP', 'DHCPClient', 'Random'],
                    'selected_values': service_suggestions,
                    'random_selected_values': service_suggestions,
                    'supports_random_selected': True,
                    'supports_custom_selected_value': False,
                    'section_fields': {
                        'density': field_schema(value_type='number', default=0.5, minimum=0, notes=['Used when factor-weighted rows are expanded into concrete assignments.']),
                    },
                    'item_fields': {
                        'selected': field_schema(value_type='string', required=True, enum=service_suggestions, aliases=['service', 'name'], notes=['Use one of the UI-selectable service values.']),
                        'factor': field_schema(value_type='number', default=1.0, minimum=0),
                        'v_metric': field_schema(value_type='string', default='Count', enum=['Count']),
                        'v_count': field_schema(value_type='integer', default=1, minimum=0, notes=['Exact number of service assignments to materialize.']),
                    },
                    'item_defaults': {'factor': 1.0, 'v_metric': 'Count', 'v_count': 1},
                    'section_defaults': {'density': 0.5},
                    'notes': [
                        'Use only the known service labels from ui_selected_values.',
                        'Services materialize through section density or explicit item count overrides.',
                    ],
                },
                'Traffic': {
                    'parser_backed': True,
                    'section_aliases': ['trafficinfo'],
                    'ui_selected_values': ['Random', 'TCP', 'UDP'],
                    'selected_values': traffic_protocols,
                    'supports_random_selected': True,
                    'random_selected_values': traffic_protocols,
                    'content_type_values': traffic_content_types,
                    'pattern_values': traffic_patterns,
                    'section_fields': {
                        'density': field_schema(value_type='number', default=0.5, minimum=0, notes=['Used when factor-weighted traffic rows are materialized into flows.']),
                    },
                    'numeric_defaults': {
                        'rate_kbps': float(traffic_defaults.get('rate_kbps', 64.0) or 64.0),
                        'period_s': float(traffic_defaults.get('period_s', 1.0) or 1.0),
                        'jitter_pct': float(traffic_defaults.get('jitter_pct', 10.0) or 10.0),
                    },
                    'item_fields': {
                        'selected': field_schema(value_type='string', required=True, enum=traffic_protocols, default='TCP'),
                        'factor': field_schema(value_type='number', default=0.0, minimum=0, notes=['Traffic rows only materialize when factor > 0 or an explicit Count is supplied.']),
                        'v_metric': field_schema(value_type='string', default='Count', enum=['Count']),
                        'v_count': field_schema(value_type='integer', default=1, minimum=0, notes=['Exact number of traffic flows to materialize.']),
                        'pattern': field_schema(value_type='string', enum=traffic_patterns, default='continuous'),
                        'rate_kbps': field_schema(value_type='number', aliases=['rate'], default=float(traffic_defaults.get('rate_kbps', 64.0) or 64.0), minimum=0),
                        'period_s': field_schema(value_type='number', aliases=['period'], default=float(traffic_defaults.get('period_s', 1.0) or 1.0), minimum=0),
                        'jitter_pct': field_schema(value_type='number', aliases=['jitter'], default=float(traffic_defaults.get('jitter_pct', 10.0) or 10.0), minimum=0),
                        'content_type': field_schema(value_type='string', aliases=['content'], enum=traffic_content_types, default='text'),
                    },
                    'item_defaults': {'factor': 0.0, 'v_metric': 'Count', 'v_count': 1},
                    'notes': [
                        'Preview/runtime traffic only materializes when factor > 0 or v_metric="Count" with v_count > 0.',
                        'Use concrete content_type and pattern values rather than vague free text.',
                        'The parser accepts legacy aliases rate, period, jitter, and content in addition to rate_kbps, period_s, jitter_pct, and content_type.',
                    ],
                },
                'Vulnerabilities': {
                    'parser_backed': True,
                    'section_aliases': ['vulnerability', 'vulns', 'vuln', 'vulnerabilityinfo'],
                    'ui_selected_values': ['Random', 'Specific'],
                    'selected_values': ['Specific', 'Type/Vector'],
                    'legacy_selected_values': ['Type/Vector'],
                    'supports_random_selected': True,
                    'random_selected_values': ['Specific'],
                    'flag_type_values': ['text'],
                    'catalog_size': len(vuln_catalog),
                    'section_fields': {
                        'density': field_schema(value_type='number', default=0.5, minimum=0),
                        'flag_type': field_schema(value_type='string', default='text', enum=['text']),
                    },
                    'item_fields': {
                        'selected': field_schema(value_type='string', required=True, enum=['Specific', 'Type/Vector'], notes=['Category is accepted as an alias for Type/Vector.']),
                        'v_metric': field_schema(value_type='string', default='Count', enum=['Count']),
                        'v_count': field_schema(value_type='integer', default=1, minimum=0),
                        'v_name': field_schema(value_type='string', notes=['Required when selected is Specific.']),
                        'v_path': field_schema(value_type='string', notes=['Optional but recommended alongside v_name for Specific rows.']),
                        'v_type': field_schema(value_type='string', notes=['Required when selected is Type/Vector.']),
                        'v_vector': field_schema(value_type='string', notes=['Required when selected is Type/Vector.']),
                    },
                    'selection_modes': {
                        'Specific': {
                            'required_item_fields': ['selected', 'v_name'],
                            'recommended_item_fields': ['v_path', 'v_metric', 'v_count'],
                        },
                        'Type/Vector': {
                            'required_item_fields': ['selected', 'v_type', 'v_vector'],
                            'recommended_item_fields': ['v_metric', 'v_count'],
                            'selected_aliases': ['Category'],
                        },
                    },
                    'notes': [
                        'Current UI selection is Random or Specific; Type/Vector remains legacy parser/MCP support rather than a current dropdown value.',
                        'Use search_vulnerability_catalog before add_vulnerability_item when selecting a specific vulnerability.',
                        'For multiple different vulnerabilities, add separate rows instead of using factor weighting.',
                    ],
                },
                'Segmentation': {
                    'parser_backed': True,
                    'section_aliases': ['segments', 'segmentationinfo'],
                    'ui_selected_values': ['Random', 'Firewall', 'NAT'],
                    'selected_values': segmentation_explicit,
                    'legacy_selected_values': ['CUSTOM'] if 'CUSTOM' in segmentation_explicit else [],
                    'supports_random_selected': True,
                    'random_selected_values': segmentation_random,
                    'supports_custom_selected_value': 'CUSTOM' in segmentation_explicit,
                    'section_fields': {
                        'density': field_schema(value_type='number', default=0.5, minimum=0),
                    },
                    'item_fields': {
                        'selected': field_schema(value_type='string', required=True, enum=segmentation_explicit, aliases=['kind', 'type', 'name']),
                        'factor': field_schema(value_type='number', default=1.0, minimum=0),
                        'v_metric': field_schema(value_type='string', default='Count', enum=['Count']),
                        'v_count': field_schema(value_type='integer', default=1, minimum=0),
                    },
                    'item_defaults': {'factor': 1.0, 'v_metric': 'Count', 'v_count': 1},
                    'section_defaults': {'density': 0.5},
                    'notes': [
                        'Explicit CUSTOM segmentation is supported by the runtime plugin path.',
                        'Random concretization currently selects from the non-custom subset.',
                        'Segmentation factor rows need positive section density to materialize.',
                    ],
                },
                'Notes': {
                    'parser_backed': False,
                    'section_aliases': ['notesection'],
                    'section_fields': {
                        'notes': field_schema(value_type='string', required=True),
                    },
                    'notes': [
                        'Use scenario.set_notes for freeform narrative instructions or context that should persist with the draft.',
                    ],
                },
            }
        }

    def _get_authoring_schema(self, arguments: dict[str, Any]) -> dict[str, Any]:
        schema = self._build_authoring_schema()
        requested_section = self._normalize_section_name(arguments.get('section_name')) if arguments else ''
        if requested_section:
            section_payload = ((schema.get('sections') or {}).get(requested_section) or None)
            if section_payload is None:
                raise ValueError(f'Unknown section_name: {requested_section}')
            return {'section_name': requested_section, 'section': section_payload}
        return schema

    def _normalize_node_role(self, value: Any) -> str:
        text = str(value or '').strip()
        if not text:
            return ''
        normalized = ''.join(ch for ch in text.lower() if ch.isalnum())
        aliases = {
            'docker': 'Docker',
            'container': 'Docker',
            'containers': 'Docker',
            'containerized': 'Docker',
            'compose': 'Docker',
            'server': 'Server',
            'servers': 'Server',
            'workstation': 'Workstation',
            'workstations': 'Workstation',
            'desktop': 'Workstation',
            'pc': 'PC',
            'pcs': 'PC',
            'host': 'PC',
            'hosts': 'PC',
            'client': 'PC',
            'clients': 'PC',
            'random': 'Random',
        }
        return aliases.get(normalized, '')

    def _normalize_traffic_protocol(self, value: Any) -> str:
        text = str(value or '').strip()
        if not text:
            return ''
        normalized = ''.join(ch for ch in text.lower() if ch.isalnum())
        aliases = {
            'tcp': 'TCP',
            'udp': 'UDP',
            'random': 'Random',
        }
        return aliases.get(normalized, '')

    def _normalize_routing_protocol(self, value: Any) -> str:
        text = str(value or '').strip()
        if not text:
            return ''
        normalized = ''.join(ch for ch in text.lower() if ch.isalnum())
        aliases = {
            'rip': 'RIP',
            'ripng': 'RIPNG',
            'bgp': 'BGP',
            'ospf': 'OSPFv2',
            'ospfv2': 'OSPFv2',
            'ospf2': 'OSPFv2',
            'ospfv3': 'OSPFv3',
            'ospf3': 'OSPFv3',
            'random': 'Random',
        }
        return aliases.get(normalized, '')

    def _normalize_routing_edge_mode(self, value: Any) -> str:
        text = str(value or '').strip()
        if not text:
            return ''
        normalized = ''.join(ch for ch in text.lower() if ch.isalnum())
        aliases = {
            'count': 'count',
            'counts': 'count',
            'explicit': 'count',
            'factor': 'factor',
            'weighted': 'factor',
            'weight': 'factor',
            'density': 'factor',
            'fullmesh': 'full_mesh',
            'mesh': 'full_mesh',
            'full': 'full_mesh',
            'sparse': 'sparse',
            'ring': 'ring',
            'line': 'line',
            'star': 'star',
            'random': 'random',
        }
        return aliases.get(normalized, text.lower())

    def _normalize_traffic_pattern(self, value: Any) -> str:
        text = str(value or '').strip()
        if not text:
            return 'continuous'
        normalized = ''.join(ch for ch in text.lower() if ch.isalnum())
        aliases = {
            'continuous': 'continuous',
            'alwayson': 'continuous',
            'constantrate': 'continuous',
            'periodic': 'periodic',
            'burst': 'burst',
            'bursty': 'burst',
            'poisson': 'poisson',
            'ramp': 'ramp',
            'random': 'continuous',
        }
        return aliases.get(normalized, '')

    def _normalize_traffic_content_type(self, value: Any) -> str:
        text = str(value or '').strip()
        if not text:
            return 'text'
        normalized = ''.join(ch for ch in text.lower() if ch.isalnum())
        aliases = {
            'text': 'text',
            'txt': 'text',
            'photo': 'photo',
            'image': 'photo',
            'images': 'photo',
            'audio': 'audio',
            'video': 'video',
            'gibberish': 'gibberish',
            'random': 'text',
        }
        return aliases.get(normalized, '')

    def _normalize_service_name(self, value: Any) -> str:
        text = str(value or '').strip()
        if not text:
            return ''
        normalized = ''.join(ch for ch in text.lower() if ch.isalnum())
        aliases = {
            'ssh': 'SSH',
            'http': 'HTTP',
            'https': 'HTTP',
            'web': 'HTTP',
            'dhcpclient': 'DHCPClient',
            'dhcp': 'DHCPClient',
            'random': 'Random',
        }
        return aliases.get(normalized, '')

    def _normalize_segmentation_kind(self, value: Any) -> str:
        text = str(value or '').strip()
        if not text:
            return ''
        normalized = ''.join(ch for ch in text.lower() if ch.isalnum())
        aliases = {
            'firewall': 'Firewall',
            'fw': 'Firewall',
            'nat': 'NAT',
            'snat': 'NAT',
            'dnat': 'NAT',
            'custom': 'CUSTOM',
            'plugin': 'CUSTOM',
            'random': 'Random',
        }
        return aliases.get(normalized, '')

    def _normalize_vulnerability_selected(self, value: Any) -> str:
        text = str(value or '').strip()
        if not text:
            return ''
        normalized = ''.join(ch for ch in text.lower() if ch.isalnum())
        aliases = {
            'random': 'Random',
            'specific': 'Specific',
            'typevector': 'Type/Vector',
            'category': 'Type/Vector',
        }
        return aliases.get(normalized, '')

    def _normalize_replaced_section_payload(self, section_name: str, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = deepcopy(payload)
        if section_name == 'Notes':
            notes_text = self._coerce_notes_text(normalized)
            return {'notes': notes_text} if notes_text else normalized

        items = normalized.get('items') if isinstance(normalized.get('items'), list) else None
        if items is None:
            return normalized

        next_items: list[dict[str, Any]] = []
        for index, raw_item in enumerate(items):
            if not isinstance(raw_item, dict):
                raise ValueError(f'{section_name} items[{index}] must be objects')
            item = deepcopy(raw_item)

            if section_name == 'Node Information':
                selected = self._normalize_node_role(item.get('selected'))
                if not selected:
                    raise ValueError('Node Information selected must be one of: Server, Workstation, PC, Docker, or Random')
                item['selected'] = selected
            elif section_name == 'Routing':
                selected = self._normalize_routing_protocol(item.get('selected'))
                if not selected:
                    raise ValueError('Routing selected must be one of: RIP, RIPNG, BGP, OSPFv2, OSPFv3, or Random')
                item['selected'] = selected
            elif section_name == 'Services':
                selected = self._normalize_service_name(item.get('selected'))
                if not selected:
                    raise ValueError('Services selected must be one of: SSH, HTTP, DHCPClient, or Random')
                item['selected'] = selected
            elif section_name == 'Traffic':
                selected = self._normalize_traffic_protocol(item.get('selected'))
                if not selected:
                    raise ValueError('Traffic selected must be one of: TCP, UDP, or Random')
                item['selected'] = selected
                pattern_raw = item.get('pattern')
                if pattern_raw not in (None, ''):
                    pattern = self._normalize_traffic_pattern(pattern_raw)
                    if not pattern:
                        raise ValueError('Traffic pattern must be one of: continuous, periodic, burst, poisson, or ramp')
                    item['pattern'] = pattern
                content_raw = item.get('content_type')
                if content_raw in (None, ''):
                    content_raw = item.get('content')
                if content_raw not in (None, ''):
                    content_type = self._normalize_traffic_content_type(content_raw)
                    if not content_type:
                        raise ValueError('Traffic content_type must be one of: text, photo, audio, video, or gibberish')
                    item['content_type'] = content_type
            elif section_name == 'Vulnerabilities':
                selected = self._normalize_vulnerability_selected(item.get('selected'))
                if not selected:
                    raise ValueError('Vulnerabilities selected must be one of: Random, Specific, or legacy Type/Vector')
                item['selected'] = selected
                if selected == 'Specific':
                    resolved = self._resolve_specific_vulnerability_catalog_entry(
                        v_name=item.get('v_name'),
                        v_path=item.get('v_path') or item.get('path'),
                    )
                    item['v_name'] = resolved['name']
                    item['v_path'] = resolved['path']
            elif section_name == 'Segmentation':
                selected = self._normalize_segmentation_kind(item.get('selected'))
                if not selected:
                    raise ValueError('Segmentation selected must be one of: Firewall, NAT, Random, or legacy CUSTOM')
                item['selected'] = selected

            next_items.append(item)

        normalized['items'] = next_items
        return normalized

    def _coerce_section_payload(self, value: Any, *, section_name: str | None = None) -> Any:
        if isinstance(value, dict):
            direct_payload = value.get('section_payload') or value.get('payload') or value.get('section') or value.get('content') or value.get('data') or value.get('value')
            if isinstance(direct_payload, (dict, str)):
                return self._coerce_section_payload(direct_payload, section_name=section_name)
            if len(value) == 1:
                only_value = next(iter(value.values()))
                if isinstance(only_value, (dict, str, list)):
                    return self._coerce_section_payload(only_value, section_name=section_name)
            return value
        if isinstance(value, list):
            if not section_name:
                return value
            wrapped = self._default_section_payload(section_name)
            if section_name == 'Notes':
                joined = '\n'.join(str(item or '').strip() for item in value if str(item or '').strip())
                wrapped['notes'] = joined
            else:
                wrapped['items'] = deepcopy(value)
            return wrapped
        if not isinstance(value, str):
            return value
        text = value.strip()
        if not text:
            return value
        if text.startswith('```'):
            lines = text.splitlines()
            if len(lines) >= 3:
                text = '\n'.join(lines[1:-1]).strip()
        try:
            parsed = json.loads(text)
        except Exception:
            obj_start = text.find('{')
            obj_end = text.rfind('}')
            if obj_start != -1 and obj_end > obj_start:
                try:
                    parsed = json.loads(text[obj_start:obj_end + 1])
                except Exception:
                    return value
            else:
                return value
        return self._coerce_section_payload(parsed, section_name=section_name)

    def _load_vulnerability_catalog(self) -> list[dict[str, str]]:
        if self._vulnerability_catalog is None:
            override_catalog = _load_vulnerability_catalog_override()
            if isinstance(override_catalog, list):
                self._vulnerability_catalog = override_catalog
            else:
                self._vulnerability_catalog = list(load_vuln_catalog(ROOT_DIR) or [])
        return self._vulnerability_catalog

    def _find_vulnerability_catalog_readme(self, entry: dict[str, Any]) -> str:
        raw_path = str(entry.get('Path') or '').strip()
        if not raw_path:
            return ''
        if re.match(r'^https?://', raw_path, re.IGNORECASE):
            return ''
        candidate_path = raw_path
        if os.path.isfile(candidate_path):
            base_dir = os.path.dirname(candidate_path)
        elif os.path.isdir(candidate_path):
            base_dir = candidate_path
        else:
            return ''
        preferred_names = [
            'README.md',
            'README.markdown',
            'README.txt',
            'README',
            'readme.md',
            'readme.markdown',
            'readme.txt',
            'readme',
        ]
        for name in preferred_names:
            readme_path = os.path.join(base_dir, name)
            if os.path.isfile(readme_path):
                return readme_path
        try:
            for name in sorted(os.listdir(base_dir)):
                lowered = str(name or '').strip().lower()
                if not lowered.startswith('readme'):
                    continue
                readme_path = os.path.join(base_dir, name)
                if os.path.isfile(readme_path):
                    return readme_path
        except Exception:
            return ''
        return ''

    def _read_vulnerability_catalog_readme(self, entry: dict[str, Any]) -> str:
        cache = getattr(self, '_vulnerability_readme_cache', None)
        if not isinstance(cache, dict):
            cache = {}
            self._vulnerability_readme_cache = cache
        cache_key = str(entry.get('Path') or '').strip()
        if cache_key in cache:
            return str(cache.get(cache_key) or '')
        readme_path = self._find_vulnerability_catalog_readme(entry)
        if not readme_path:
            cache[cache_key] = ''
            return ''
        try:
            with open(readme_path, 'r', encoding='utf-8', errors='ignore') as handle:
                text = handle.read(20000)
        except Exception:
            text = ''
        cache[cache_key] = text
        return text

    def _tokenize_vulnerability_catalog_query(self, query: str) -> list[str]:
        raw_tokens = [token for token in re.findall(r'[a-z0-9]+', str(query or '').lower()) if token]
        stopwords = {
            'a', 'an', 'and', 'any', 'attack', 'attacks', 'add', 'catalog', 'concrete', 'different', 'few', 'find',
            'for', 'from', 'in', 'into', 'of', 'on', 'or', 'related', 'request', 'requests', 'some', 'that', 'the',
            'these', 'this', 'to', 'use', 'user', 'with', 'vulnerability', 'vulnerabilities', 'vuln', 'vulns',
        }
        return [token for token in raw_tokens if token not in stopwords]

    def _search_vulnerability_catalog(self, arguments: dict[str, Any]) -> dict[str, Any]:
        catalog = self._load_vulnerability_catalog()
        query = str(
            arguments.get('query')
            or arguments.get('search')
            or arguments.get('text')
            or arguments.get('prompt')
            or arguments.get('description')
            or arguments.get('vulnerability')
            or ''
        ).strip()
        v_type = str(arguments.get('v_type') or arguments.get('type') or arguments.get('category') or '').strip().lower()
        v_vector = str(arguments.get('v_vector') or arguments.get('vector') or '').strip().lower()
        try:
            limit = int(arguments.get('limit') or 10)
        except Exception:
            limit = 10
        limit = max(1, min(limit, 50))

        query_tokens = self._tokenize_vulnerability_catalog_query(query)
        matches: list[tuple[int, dict[str, str]]] = []
        for entry in catalog:
            entry_type = str(entry.get('Type') or '').strip().lower()
            entry_vector = str(entry.get('Vector') or '').strip().lower()
            if v_type and entry_type != v_type:
                continue
            if v_vector and entry_vector != v_vector:
                continue

            readme_text = self._read_vulnerability_catalog_readme(entry)

            haystack = ' '.join([
                str(entry.get('Name') or ''),
                str(entry.get('CVE') or ''),
                str(entry.get('Description') or ''),
                str(entry.get('Type') or ''),
                str(entry.get('Vector') or ''),
                str(entry.get('Path') or ''),
                readme_text,
            ]).lower()
            name_text = str(entry.get('Name') or '').lower()
            cve_text = str(entry.get('CVE') or '').lower()
            path_text = str(entry.get('Path') or '').lower()
            description_text = str(entry.get('Description') or '').lower()
            readme_lower = readme_text.lower()
            score = 0
            if not query_tokens:
                score = 1
            else:
                for token in query_tokens:
                    if token in haystack:
                        score += 3
                    if token in name_text:
                        score += 4
                    if token in cve_text:
                        score += 5
                    if token in path_text:
                        score += 2
                    if token in description_text:
                        score += 2
                    if token in readme_lower:
                        score += 2
                if query and query.lower() in readme_lower:
                    score += 6
            if score > 0:
                matches.append((score, entry))

        matches.sort(key=lambda item: (
            -item[0],
            str(item[1].get('Name') or '').lower(),
            str(item[1].get('CVE') or '').lower(),
        ))
        results = []
        for score, entry in matches[:limit]:
            results.append({
                'name': str(entry.get('Name') or ''),
                'path': str(entry.get('Path') or ''),
                'type': str(entry.get('Type') or ''),
                'vector': str(entry.get('Vector') or ''),
                'cve': str(entry.get('CVE') or ''),
                'description': str(entry.get('Description') or ''),
                'readme_available': bool(readme_text),
                'score': score,
            })
        response = {
            'query': query,
            'v_type': v_type,
            'v_vector': v_vector,
            'count': len(results),
            'results': results,
        }
        self._last_vulnerability_search = deepcopy(response)
        return response

    def _resolve_specific_vulnerability_catalog_entry(self, *, v_name: Any = None, v_path: Any = None) -> dict[str, str]:
        catalog = self._load_vulnerability_catalog()
        resolved = resolve_vulnerability_catalog_entry(
            catalog,
            v_name=str(v_name or ''),
            v_path=str(v_path or ''),
        )
        if resolved:
            return resolved

        normalized_name = str(v_name or '').strip().lower()
        normalized_path = str(v_path or '').strip().lower().rstrip('/')
        fallback_matches: list[dict[str, str]] = []
        for entry in catalog:
            entry_name = str(entry.get('Name') or '').strip()
            entry_path = str(entry.get('Path') or '').strip()
            entry_name_lower = entry_name.lower()
            entry_path_lower = entry_path.lower().rstrip('/')

            path_match = bool(normalized_path) and (
                entry_path_lower == normalized_path
                or entry_path_lower.endswith(normalized_path)
                or normalized_path.endswith(entry_path_lower)
            )
            name_match = bool(normalized_name) and (
                entry_name_lower == normalized_name
                or entry_name_lower.startswith(normalized_name + '/')
                or normalized_name in entry_name_lower
            )
            if not path_match and not name_match:
                continue
            fallback_matches.append({
                'name': canonical_vulnerability_name(entry_name, entry_path, str(entry.get('CVE') or '')),
                'path': entry_path,
            })

        if len(fallback_matches) == 1:
            return fallback_matches[0]

        raise ValueError('Specific vulnerability must match an enabled catalog entry by v_path or v_name')

    def _touch_draft_after_mutation(self, draft: ScenarioDraft) -> None:
        draft.updated_at = app_backend._local_timestamp_safe()
        draft.preview = None
        draft.preview_plan = None
        draft.flow_meta = None

    def _upsert_explicit_count_item(self, items: list[Any], *, selected: str, new_item: dict[str, Any]) -> list[Any]:
        normalized_selected = str(selected or '').strip().lower()
        if not normalized_selected:
            return list(items) + [new_item]
        next_items = list(items)
        for index, existing in enumerate(next_items):
            if not isinstance(existing, dict):
                continue
            existing_selected = str(existing.get('selected') or '').strip().lower()
            existing_metric = str(existing.get('v_metric') or '').strip().lower()
            if existing_selected != normalized_selected or existing_metric != 'count':
                continue
            merged = dict(existing)
            merged.update(new_item)
            next_items[index] = merged
            return next_items
        next_items.append(new_item)
        return next_items

    def _add_node_role_item(self, draft: ScenarioDraft, arguments: dict[str, Any]) -> dict[str, Any]:
        sections = draft.scenario.get('sections') if isinstance(draft.scenario.get('sections'), dict) else {}
        node_section = sections.get('Node Information') if isinstance(sections.get('Node Information'), dict) else {}
        items = node_section.get('items') if isinstance(node_section.get('items'), list) else []

        raw_selected = (
            arguments.get('selected')
            or arguments.get('role')
            or arguments.get('node_type')
            or arguments.get('type')
            or arguments.get('kind')
        )
        routing_selected = app_backend._normalize_routing_item_selection(raw_selected)
        if routing_selected:
            raise ValueError(
                'Router counts belong in Routing. Use scenario.add_routing_item instead of scenario.add_node_role_item.'
            )

        selected = self._normalize_node_role(
            raw_selected
        )
        if not selected:
            raise ValueError('selected or role is required for node role items')

        try:
            count = int(arguments.get('count') or arguments.get('v_count') or 1)
        except Exception:
            count = 1
        count = max(1, count)

        try:
            factor = float(arguments.get('factor') or 1.0)
        except Exception:
            factor = 1.0

        new_item: dict[str, Any] = {
            'selected': selected,
            'factor': factor,
            'v_metric': 'Count',
            'v_count': count,
        }

        total_nodes = arguments.get('total_nodes')
        if total_nodes not in (None, ''):
            try:
                node_section['total_nodes'] = max(0, int(total_nodes))
            except Exception:
                pass
        elif 'total_nodes' not in node_section:
            node_section['total_nodes'] = 0
        if 'density' not in node_section:
            node_section['density'] = 0

        node_section['items'] = self._upsert_explicit_count_item(items, selected=selected, new_item=new_item)
        sections['Node Information'] = node_section
        draft.scenario['sections'] = sections
        self._touch_draft_after_mutation(draft)
        return {
            'draft': self._serialize_draft(draft),
            'added_item': deepcopy(new_item),
        }

    def _add_service_item(self, draft: ScenarioDraft, arguments: dict[str, Any]) -> dict[str, Any]:
        sections = draft.scenario.get('sections') if isinstance(draft.scenario.get('sections'), dict) else {}
        service_section = sections.get('Services') if isinstance(sections.get('Services'), dict) else {}
        items = service_section.get('items') if isinstance(service_section.get('items'), list) else []

        raw_selected = (
            arguments.get('selected')
            or arguments.get('service')
            or arguments.get('name')
            or arguments.get('type')
        )
        selected = self._normalize_service_name(raw_selected)
        if not selected:
            raise ValueError('selected or service must be one of: SSH, HTTP, DHCPClient, or Random')

        count_raw = arguments.get('count')
        if count_raw in (None, ''):
            count_raw = arguments.get('v_count')
        count: int | None = None
        if count_raw not in (None, ''):
            try:
                count = max(1, int(count_raw))
            except Exception:
                count = 1

        try:
            density = float(arguments.get('density')) if arguments.get('density') not in (None, '') else None
        except Exception:
            density = None
        if density is not None:
            service_section['density'] = min(max(density, 0.0), 1.0)
        elif 'density' not in service_section:
            service_section['density'] = 0.0 if count is not None else 0.5

        try:
            factor = float(arguments.get('factor') or 1.0)
        except Exception:
            factor = 1.0
        factor = max(0.0, factor)
        if count is None and factor <= 0:
            factor = 1.0

        new_item: dict[str, Any] = {
            'selected': selected,
            'factor': factor,
        }
        if count is not None:
            new_item['v_metric'] = 'Count'
            new_item['v_count'] = count

        service_section['items'] = list(items) + [new_item]
        sections['Services'] = service_section
        draft.scenario['sections'] = sections
        self._touch_draft_after_mutation(draft)
        return {
            'draft': self._serialize_draft(draft),
            'added_item': deepcopy(new_item),
        }

    def _add_routing_item(self, draft: ScenarioDraft, arguments: dict[str, Any]) -> dict[str, Any]:
        sections = draft.scenario.get('sections') if isinstance(draft.scenario.get('sections'), dict) else {}
        routing_section = sections.get('Routing') if isinstance(sections.get('Routing'), dict) else {}
        items = routing_section.get('items') if isinstance(routing_section.get('items'), list) else []

        selected = self._normalize_routing_protocol(
            arguments.get('selected')
            or arguments.get('protocol')
            or arguments.get('kind')
            or arguments.get('type')
        )
        if not selected:
            raise ValueError('selected or protocol is required for routing items')

        count_raw = arguments.get('count')
        if count_raw in (None, ''):
            count_raw = arguments.get('v_count')
        count: int | None = None
        if count_raw not in (None, ''):
            try:
                count = max(1, int(count_raw))
            except Exception:
                count = 1

        try:
            density = float(arguments.get('density')) if arguments.get('density') not in (None, '') else None
        except Exception:
            density = None
        if density is not None:
            routing_section['density'] = min(max(density, 0.0), 1.0)
        elif routing_section.get('density') in (None, ''):
            routing_section['density'] = 0.0 if count is not None else 0.5

        try:
            factor = float(arguments.get('factor') or 1.0)
        except Exception:
            factor = 1.0
        factor = max(0.0, factor)
        if count is None and factor <= 0:
            factor = 1.0

        def optional_int(*keys: str) -> int | None:
            for key in keys:
                raw = arguments.get(key)
                if raw in (None, ''):
                    continue
                try:
                    return max(0, int(raw))
                except Exception:
                    return 0
            return None

        new_item: dict[str, Any] = {
            'selected': selected,
            'factor': factor,
        }
        if count is not None:
            new_item['v_metric'] = 'Count'
            new_item['v_count'] = count

        r2r_mode = self._normalize_routing_edge_mode(arguments.get('r2r_mode'))
        if r2r_mode:
            new_item['r2r_mode'] = r2r_mode
        r2r_edges = optional_int('r2r_edges')
        if r2r_edges is not None:
            new_item['r2r_edges'] = r2r_edges

        r2s_mode = self._normalize_routing_edge_mode(arguments.get('r2s_mode'))
        if r2s_mode:
            new_item['r2s_mode'] = r2s_mode
        r2s_edges = optional_int('r2s_edges')
        if r2s_edges is not None:
            new_item['r2s_edges'] = r2s_edges

        r2s_hosts_min = optional_int('r2s_hosts_min')
        if r2s_hosts_min is not None:
            new_item['r2s_hosts_min'] = r2s_hosts_min
        r2s_hosts_max = optional_int('r2s_hosts_max')
        if r2s_hosts_max is not None:
            new_item['r2s_hosts_max'] = r2s_hosts_max

        routing_section['items'] = self._upsert_explicit_count_item(items, selected=selected, new_item=new_item)
        sections['Routing'] = routing_section
        draft.scenario['sections'] = sections
        self._touch_draft_after_mutation(draft)
        return {
            'draft': self._serialize_draft(draft),
            'added_item': deepcopy(new_item),
        }

    def _add_traffic_item(self, draft: ScenarioDraft, arguments: dict[str, Any]) -> dict[str, Any]:
        sections = draft.scenario.get('sections') if isinstance(draft.scenario.get('sections'), dict) else {}
        traffic_section = sections.get('Traffic') if isinstance(sections.get('Traffic'), dict) else {}
        items = traffic_section.get('items') if isinstance(traffic_section.get('items'), list) else []

        raw_selected = (
            arguments.get('selected')
            or arguments.get('protocol')
            or arguments.get('kind')
            or arguments.get('type')
        )
        selected = self._normalize_traffic_protocol(raw_selected or 'TCP')
        if not selected:
            raise ValueError('selected or protocol must be one of: TCP, UDP, or Random')

        count_raw = arguments.get('count')
        if count_raw in (None, ''):
            count_raw = arguments.get('v_count')
        count: int | None = None
        if count_raw not in (None, ''):
            try:
                count = max(1, int(count_raw))
            except Exception:
                count = 1

        try:
            factor = float(arguments.get('factor') or 0.0)
        except Exception:
            factor = 0.0

        if count is None and factor <= 0:
            count = 1

        try:
            density = float(arguments.get('density')) if arguments.get('density') not in (None, '') else None
        except Exception:
            density = None
        if density is not None:
            traffic_section['density'] = min(max(density, 0.0), 1.0)
        elif 'density' not in traffic_section:
            traffic_section['density'] = 0.5

        try:
            rate_kbps = float(arguments.get('rate_kbps') or 64.0)
        except Exception:
            rate_kbps = 64.0
        try:
            period_s = float(arguments.get('period_s') or 1.0)
        except Exception:
            period_s = 1.0
        try:
            jitter_pct = float(arguments.get('jitter_pct') or 10.0)
        except Exception:
            jitter_pct = 10.0

        raw_pattern = arguments.get('pattern')
        normalized_pattern = self._normalize_traffic_pattern(raw_pattern)
        if raw_pattern not in (None, '') and not normalized_pattern:
            raise ValueError('pattern must be one of: continuous, periodic, burst, poisson, or ramp')

        raw_content_type = (
            arguments.get('content_type')
            or arguments.get('content')
            or arguments.get('payload')
        )
        normalized_content_type = self._normalize_traffic_content_type(raw_content_type)
        if raw_content_type not in (None, '') and not normalized_content_type:
            raise ValueError('content_type must be one of: text, photo, audio, video, or gibberish')

        new_item: dict[str, Any] = {
            'selected': selected,
            'factor': factor,
            'pattern': normalized_pattern or 'continuous',
            'rate_kbps': max(0.0, rate_kbps),
            'period_s': max(0.0, period_s),
            'jitter_pct': min(max(jitter_pct, 0.0), 100.0),
            'content_type': normalized_content_type or 'text',
        }
        if count is not None:
            new_item['v_metric'] = 'Count'
            new_item['v_count'] = count

        traffic_section['items'] = list(items) + [new_item]
        sections['Traffic'] = traffic_section
        draft.scenario['sections'] = sections
        self._touch_draft_after_mutation(draft)
        return {
            'draft': self._serialize_draft(draft),
            'added_item': deepcopy(new_item),
        }

    def _add_segmentation_item(self, draft: ScenarioDraft, arguments: dict[str, Any]) -> dict[str, Any]:
        sections = draft.scenario.get('sections') if isinstance(draft.scenario.get('sections'), dict) else {}
        seg_section = sections.get('Segmentation') if isinstance(sections.get('Segmentation'), dict) else {}
        items = seg_section.get('items') if isinstance(seg_section.get('items'), list) else []

        selected = self._normalize_segmentation_kind(
            arguments.get('selected')
            or arguments.get('kind')
            or arguments.get('type')
            or arguments.get('name')
        )
        if not selected:
            raise ValueError('selected or kind is required for segmentation items')

        count_raw = arguments.get('count')
        if count_raw in (None, ''):
            count_raw = arguments.get('v_count')
        count: int | None = None
        if count_raw not in (None, ''):
            try:
                count = max(1, int(count_raw))
            except Exception:
                count = 1

        try:
            density = float(arguments.get('density')) if arguments.get('density') not in (None, '') else None
        except Exception:
            density = None
        if density is not None:
            seg_section['density'] = min(max(density, 0.0), 1.0)
        elif 'density' not in seg_section:
            seg_section['density'] = 0.0 if count is not None else 0.5

        try:
            factor = float(arguments.get('factor') or 0.0)
        except Exception:
            factor = 0.0
        factor = max(0.0, factor)
        if count is None and factor <= 0:
            factor = 1.0

        new_item: dict[str, Any] = {
            'selected': selected,
            'factor': factor,
        }
        if count is not None:
            new_item['v_metric'] = 'Count'
            new_item['v_count'] = count

        seg_section['items'] = list(items) + [new_item]
        sections['Segmentation'] = seg_section
        draft.scenario['sections'] = sections
        self._touch_draft_after_mutation(draft)
        return {
            'draft': self._serialize_draft(draft),
            'added_item': deepcopy(new_item),
        }

    def _add_vulnerability_item(self, draft: ScenarioDraft, arguments: dict[str, Any]) -> dict[str, Any]:
        sections = draft.scenario.get('sections') if isinstance(draft.scenario.get('sections'), dict) else {}
        vuln_section = sections.get('Vulnerabilities') if isinstance(sections.get('Vulnerabilities'), dict) else {}
        items = vuln_section.get('items') if isinstance(vuln_section.get('items'), list) else []

        selected = str(arguments.get('selected') or arguments.get('mode') or '').strip()
        inferred_v_type = str(arguments.get('v_type') or arguments.get('type') or arguments.get('category') or '').strip()
        inferred_v_vector = str(arguments.get('v_vector') or arguments.get('vector') or '').strip()
        inferred_v_name = str(arguments.get('v_name') or arguments.get('name') or arguments.get('title') or '').strip()
        inferred_query = str(
            arguments.get('query')
            or arguments.get('search')
            or arguments.get('text')
            or arguments.get('prompt')
            or arguments.get('description')
            or arguments.get('vulnerability')
            or ''
        ).strip()
        if not selected:
            selected = 'Type/Vector' if ((inferred_v_type or inferred_v_vector) and not (inferred_v_name or inferred_query)) else 'Specific'
        if selected == 'Category':
            selected = 'Type/Vector'
        v_metric = str(arguments.get('v_metric') or 'Count').strip() or 'Count'
        try:
            v_count = int(arguments.get('v_count') or 1)
        except Exception:
            v_count = 1
        v_count = max(1, v_count)
        try:
            factor = float(arguments.get('factor') or 1.0)
        except Exception:
            factor = 1.0

        new_item: dict[str, Any] = {
            'selected': selected,
            'v_metric': v_metric,
            'v_count': v_count,
            'factor': factor,
        }

        if selected == 'Type/Vector':
            v_type = inferred_v_type
            v_vector = inferred_v_vector
            if not v_type and not v_vector:
                raise ValueError('v_type or v_vector is required for Type/Vector vulnerability items')
            if v_type:
                new_item['v_type'] = v_type
            if v_vector:
                new_item['v_vector'] = v_vector
        else:
            v_name = inferred_v_name
            v_path = str(arguments.get('v_path') or arguments.get('path') or arguments.get('url') or '').strip()
            if not v_name or not v_path:
                results: list[dict[str, Any]] = []
                prior_search = deepcopy(self._last_vulnerability_search) if isinstance(self._last_vulnerability_search, dict) else None
                search_arguments = dict(arguments)
                if not search_arguments.get('query'):
                    search_arguments['query'] = inferred_query or inferred_v_name
                if str(search_arguments.get('query') or '').strip() or str(search_arguments.get('v_type') or search_arguments.get('type') or '').strip() or str(search_arguments.get('v_vector') or search_arguments.get('vector') or '').strip():
                    search_result = self._search_vulnerability_catalog(search_arguments)
                    results = search_result.get('results') if isinstance(search_result.get('results'), list) else []
                if not results and isinstance(prior_search, dict):
                    cached_results = prior_search.get('results')
                    if isinstance(cached_results, list):
                        results = cached_results
                try:
                    match_index = int(arguments.get('match_index') or 0)
                except Exception:
                    match_index = 0
                if not results:
                    raise ValueError('No vulnerability catalog match found; provide v_name/v_path or refine the query')
                if match_index < 0 or match_index >= len(results):
                    raise ValueError('match_index is out of range for catalog search results')
                chosen = results[match_index]
                v_name = str(chosen.get('name') or '').strip()
                v_path = str(chosen.get('path') or '').strip()
            if not v_name or not v_path:
                raise ValueError('Specific vulnerability items require v_name and v_path')
            resolved = self._resolve_specific_vulnerability_catalog_entry(v_name=v_name, v_path=v_path)
            new_item['selected'] = 'Specific'
            new_item['v_name'] = resolved['name']
            new_item['v_path'] = resolved['path']

        if 'flag_type' in arguments and str(arguments.get('flag_type') or '').strip():
            vuln_section['flag_type'] = str(arguments.get('flag_type') or '').strip()
        elif 'flag_type' not in vuln_section:
            vuln_section['flag_type'] = 'text'

        vuln_section['items'] = list(items) + [new_item]
        if 'density' not in vuln_section:
            vuln_section['density'] = 0.0
        sections['Vulnerabilities'] = vuln_section
        draft.scenario['sections'] = sections
        self._touch_draft_after_mutation(draft)
        return {
            'draft': self._serialize_draft(draft),
            'added_item': deepcopy(new_item),
        }

    def _preview_draft(self, draft: ScenarioDraft, *, core: dict[str, Any], seed: Any = None) -> dict[str, Any]:
        draft.scenario = app_backend._concretize_preview_placeholders(draft.scenario, seed=seed)
        payload = {
            'scenarios': [draft.scenario],
            'core': app_backend._normalize_core_config(core, include_password=True) if isinstance(core, dict) else draft.core,
            'scenario': draft.scenario.get('name'),
        }
        if seed is not None:
            payload['seed'] = seed
        with app_backend.app.test_request_context('/api/plan/preview_full', method='POST', json=payload):
            response = app_backend.app.make_response(app_backend.app.dispatch_request())
            data = response.get_json(silent=True) or {}
        if response.status_code >= 400 or data.get('ok') is False:
            raise ValueError(data.get('error') or f'Preview failed (HTTP {response.status_code})')
        draft.core = payload['core']
        draft.preview = data.get('full_preview') if isinstance(data.get('full_preview'), dict) else {}
        draft.preview_plan = data.get('plan') if isinstance(data.get('plan'), dict) else {}
        draft.flow_meta = data.get('flow_meta') if isinstance(data.get('flow_meta'), dict) else {}
        draft.updated_at = app_backend._local_timestamp_safe()
        return {
            'draft': self._serialize_draft(draft),
            'preview': draft.preview,
            'plan': draft.preview_plan,
            'flow_meta': draft.flow_meta,
        }

    def _save_draft(self, draft: ScenarioDraft, *, core: dict[str, Any]) -> dict[str, Any]:
        preview_seed = None
        if isinstance(draft.preview, dict):
            preview_seed = draft.preview.get('seed')
        draft.scenario = app_backend._concretize_preview_placeholders(draft.scenario, seed=preview_seed)
        normalized_core = app_backend._normalize_core_config(core, include_password=True) if isinstance(core, dict) else draft.core
        with app_backend.app.test_request_context(
            '/save_xml_api',
            method='POST',
            data=json.dumps({'scenarios': [draft.scenario], 'core': normalized_core}),
            content_type='application/json',
        ):
            response = app_backend.app.make_response(app_backend.save_xml_api())
            data = response.get_json(silent=True) or {}
        if response.status_code >= 400 or data.get('ok') is False:
            raise ValueError(data.get('error') or f'Save failed (HTTP {response.status_code})')
        draft.core = normalized_core
        draft.last_saved_xml_path = data.get('result_path')
        draft.updated_at = app_backend._local_timestamp_safe()
        return {
            'draft': self._serialize_draft(draft),
            'xml_path': draft.last_saved_xml_path,
            'result': data,
        }

    def _serialize_draft(self, draft: ScenarioDraft) -> dict[str, Any]:
        return {
            'draft_id': draft.draft_id,
            'scenario': deepcopy(draft.scenario),
            'core': deepcopy(draft.core),
            'created_at': draft.created_at,
            'updated_at': draft.updated_at,
            'preview_summary': draft.to_summary().get('preview_summary'),
            'last_saved_xml_path': draft.last_saved_xml_path,
        }


def main() -> int:
    server = ScenarioAuthoringMCPServer()
    for line in sys.stdin:
        raw = line.strip()
        if not raw:
            continue
        try:
            message = json.loads(raw)
        except Exception:
            response = _jsonrpc_error(None, -32700, 'Parse error')
        else:
            response = server.handle_message(message)
        if response is not None:
            sys.stdout.write(json.dumps(response) + '\n')
            sys.stdout.flush()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())