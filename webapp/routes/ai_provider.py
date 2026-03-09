from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
import json
import os
import queue
import re
import sys
import threading
import uuid
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from flask import Response, jsonify, request, stream_with_context
from webapp import app_backend

try:
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    from mcp.client.streamable_http import streamable_http_client
except Exception:  # pragma: no cover
    ClientSession = None
    StdioServerParameters = None
    stdio_client = None
    streamable_http_client = None


_SUPPORTED_SECTION_NAMES = [
    'Node Information',
    'Routing',
    'Services',
    'Traffic',
    'Vulnerabilities',
    'Segmentation',
    'Notes',
]

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_CANONICAL_AI_BRIDGE_MODE = 'mcp-python-sdk'
_LEGACY_AI_BRIDGE_MODE_ALIASES = {'ollmcp', 'mcp-python-sdk', 'mcp_python_sdk', 'python-sdk', 'mcp-sdk'}
_DEFAULT_MCP_SERVER_PATH = os.path.join(_REPO_ROOT, 'MCP', 'server.py')
_DEFAULT_MCP_SERVERS_JSON_PATH = os.path.join(_REPO_ROOT, 'MCP', 'mcp-bridge-servers.json')
_LEGACY_MCP_SERVERS_JSON_PATH = os.path.join(_REPO_ROOT, 'MCP', 'ollmcp-servers.json')
_ACTIVE_AI_STREAMS: dict[str, dict[str, Any]] = {}
_ACTIVE_AI_STREAMS_LOCK = threading.Lock()


def _env_flag(name: str, default: bool = False) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return str(raw_value).strip().lower() in {'1', 'true', 'yes', 'on'}


class ProviderAdapterError(Exception):
    def __init__(self, message: str, *, status_code: int = 400, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


@dataclass(frozen=True)
class _McpBridgeRepairDecision:
    category: str
    retryable: bool = False
    status_message: str = ''
    retry_prompt: str | None = None
    recreate_draft: bool = False
    tool_response: str | None = None


def _is_ollama_tool_parse_error(exc: BaseException) -> bool:
    message = str(exc or '').lower()
    return 'error parsing tool call' in message


def _build_mcp_bridge_tool_parse_retry_prompt(prompt: str) -> str:
    retry_lines = [
        '',
        'Retry note: your previous response failed because Ollama could not parse a generated tool call.',
        'Every tool call arguments object must be strict valid JSON with no duplicate keys, no dangling text, and no partial numbers or strings.',
        'For vulnerabilities, do not pass factor.',
        'For vulnerabilities, use scenario.search_vulnerability_catalog first, then call scenario.add_vulnerability_item with only draft_id plus explicit v_name and v_path, or use v_type and v_vector for a Type/Vector row.',
        'If the user asks for multiple different vulnerabilities, make multiple separate add_vulnerability_item calls with v_count=1 instead of trying to encode them in one weighted row.',
    ]
    return prompt + '\n'.join(retry_lines)


def _extract_count_intent(user_prompt: str) -> dict[str, int]:
    text = str(user_prompt or '').strip().lower()
    if not text:
        return {}

    count_intent: dict[str, int] = {}

    total_nodes_match = re.search(r'\b(?:topology|scenario)\s+with\s+(\d+)\s+nodes?\b', text)
    if not total_nodes_match:
        total_nodes_match = re.search(r'\b(\d+)\s+total\s+nodes?\b', text)
    if not total_nodes_match:
        total_nodes_match = re.search(r'\b(\d+)\s+nodes?\b', text)
    if total_nodes_match:
        try:
            count_intent['total_nodes'] = max(0, int(total_nodes_match.group(1)))
        except Exception:
            pass

    router_match = re.search(r'\b(\d+)\s+routers?\b', text)
    if router_match:
        try:
            count_intent['router_count'] = max(0, int(router_match.group(1)))
        except Exception:
            pass

    if count_intent.get('total_nodes') is not None and count_intent.get('router_count') is not None:
        count_intent['derived_host_count'] = max(0, count_intent['total_nodes'] - count_intent['router_count'])

    return count_intent


def _build_count_intent_guidance(user_prompt: str) -> list[str]:
    intent = _extract_count_intent(user_prompt)
    total_nodes = intent.get('total_nodes')
    router_count = intent.get('router_count')
    derived_host_count = intent.get('derived_host_count')

    guidance: list[str] = []
    if total_nodes is not None and router_count is not None and derived_host_count is not None:
        guidance.append(
            f'User count intent detected: total topology nodes={total_nodes}, router nodes={router_count}, so Node Information host counts should sum to {derived_host_count} and Routing router count should be {router_count}.'
        )
        guidance.append(
            'Do not satisfy a separate router request by reducing router rows to zero or by treating routers as host rows under Node Information.'
        )
    elif total_nodes is not None:
        guidance.append(
            f'User count intent detected: node count={total_nodes}. If no separate router count is requested, treat this as the host-node target for Node Information.'
        )
    return guidance


def _preview_count_summary(preview: dict[str, Any] | None) -> dict[str, int]:
    preview_payload = preview if isinstance(preview, dict) else {}
    return {
        'routers': len(preview_payload.get('routers') or []) if isinstance(preview_payload.get('routers'), list) else 0,
        'hosts': len(preview_payload.get('hosts') or []) if isinstance(preview_payload.get('hosts'), list) else 0,
        'switches': len(preview_payload.get('switches') or []) if isinstance(preview_payload.get('switches'), list) else 0,
    }


def _get_count_intent_mismatch(user_prompt: str, preview: dict[str, Any] | None) -> dict[str, Any] | None:
    intent = _extract_count_intent(user_prompt)
    total_nodes = intent.get('total_nodes')
    router_count = intent.get('router_count')
    expected_hosts = intent.get('derived_host_count')
    if total_nodes is None and router_count is None:
        return None

    actual = _preview_count_summary(preview)
    mismatches: list[str] = []
    if router_count is not None and actual['routers'] != router_count:
        mismatches.append(f'router count expected {router_count} but preview produced {actual["routers"]}')

    host_target = expected_hosts if expected_hosts is not None else total_nodes
    if host_target is not None and actual['hosts'] != host_target:
        mismatches.append(f'host count expected {host_target} but preview produced {actual["hosts"]}')

    if not mismatches:
        return None

    return {
        'requested_total_nodes': total_nodes,
        'requested_router_count': router_count,
        'expected_host_count': host_target,
        'actual_routers': actual['routers'],
        'actual_hosts': actual['hosts'],
        'actual_switches': actual['switches'],
        'reasons': mismatches,
    }


def _build_count_mismatch_retry_prompt(prompt: str, mismatch: dict[str, Any]) -> str:
    requested_total_nodes = mismatch.get('requested_total_nodes')
    requested_router_count = mismatch.get('requested_router_count')
    expected_host_count = mismatch.get('expected_host_count')
    actual_routers = mismatch.get('actual_routers')
    actual_hosts = mismatch.get('actual_hosts')
    actual_switches = mismatch.get('actual_switches')
    reasons = mismatch.get('reasons') if isinstance(mismatch.get('reasons'), list) else []

    retry_lines = [
        '',
        'Retry note: the previous preview did not satisfy the user\'s explicit count request.',
        f'Previous preview counts: routers={actual_routers}, hosts={actual_hosts}, switches={actual_switches}.',
    ]
    requested_bits = []
    if requested_total_nodes is not None:
        requested_bits.append(f'total topology nodes={requested_total_nodes}')
    if requested_router_count is not None:
        requested_bits.append(f'router nodes={requested_router_count}')
    if expected_host_count is not None:
        requested_bits.append(f'Node Information host total={expected_host_count}')
    if requested_bits:
        retry_lines.append('Requested counts: ' + ', '.join(requested_bits) + '.')
    if reasons:
        retry_lines.append('Mismatch detected: ' + '; '.join(str(reason) for reason in reasons) + '.')
    retry_lines.append('Fix the draft so the next preview matches those explicit counts exactly before you finish.')
    return prompt + '\n'.join(retry_lines)


def _build_prompt_repair_decision(*, prompt: str, exc: ProviderAdapterError | None = None, mismatch: dict[str, Any] | None = None) -> _McpBridgeRepairDecision:
    if exc is not None and _is_ollama_tool_parse_error(exc):
        return _McpBridgeRepairDecision(
            category='ollama-tool-parse-error',
            retryable=True,
            status_message='Retrying after Ollama tool-call parse failure...',
            retry_prompt=_build_mcp_bridge_tool_parse_retry_prompt(prompt),
        )
    if isinstance(mismatch, dict):
        return _McpBridgeRepairDecision(
            category='count-intent-mismatch',
            retryable=True,
            status_message='Preview counts did not match the requested totals. Retrying once with stricter count guidance...',
            retry_prompt=_build_count_mismatch_retry_prompt(prompt, mismatch),
        )
    return _McpBridgeRepairDecision(category='none')


def _build_generation_repair_decision(exc: ProviderAdapterError) -> _McpBridgeRepairDecision:
    if _is_unknown_draft_id_error(exc):
        return _McpBridgeRepairDecision(
            category='unknown-draft-id',
            retryable=True,
            status_message='Draft state was lost in the MCP bridge. Recreating the draft and retrying once...',
            recreate_draft=True,
        )
    return _McpBridgeRepairDecision(category='none')


def _classify_tool_repair(tool_response: str, *, qualified_tool_name: str) -> tuple[str, str]:
    category = 'recoverable-tool-error'
    status_message = f'Auto-healing a recoverable tool error for {qualified_tool_name}.'
    try:
        payload = json.loads(tool_response)
    except Exception:
        return category, status_message
    if not isinstance(payload, dict):
        return category, status_message

    retry_hint = payload.get('retry_hint') if isinstance(payload.get('retry_hint'), dict) else {}
    tool_name = str(retry_hint.get('tool') or '').strip()
    section_name = str(retry_hint.get('section_name') or '').strip().lower()

    if tool_name == 'scenario.add_routing_item' or (tool_name == 'scenario.replace_section' and section_name == 'routing'):
        return 'routing-tool-error', f'Auto-healing a routing tool error for {qualified_tool_name}.'
    if tool_name == 'scenario.add_traffic_item' or (tool_name == 'scenario.replace_section' and section_name == 'traffic'):
        return 'traffic-tool-error', f'Auto-healing a traffic tool error for {qualified_tool_name}.'
    if tool_name in {'scenario.add_vulnerability_item', 'scenario.search_vulnerability_catalog'} or (tool_name == 'scenario.replace_section' and section_name == 'vulnerabilities'):
        return 'vulnerability-tool-error', f'Auto-healing a vulnerability tool error for {qualified_tool_name}.'
    return category, status_message


def _build_tool_repair_decision(
    qualified_tool_name: str,
    tool_args: dict[str, Any],
    exc: ProviderAdapterError,
    *,
    enabled_tool_names: list[str] | None = None,
) -> _McpBridgeRepairDecision:
    tool_response = _build_recoverable_mcp_bridge_tool_error(
        qualified_tool_name,
        tool_args,
        exc,
        enabled_tool_names=enabled_tool_names,
    )
    if tool_response is None:
        return _McpBridgeRepairDecision(category='none')
    category, status_message = _classify_tool_repair(tool_response, qualified_tool_name=qualified_tool_name)
    return _McpBridgeRepairDecision(
        category=category,
        retryable=True,
        status_message=status_message,
        tool_response=tool_response,
    )


async def _execute_mcp_bridge_prompt_with_preview_retry(
    client: Any,
    *,
    draft_id: str,
    prompt: str,
    user_prompt: str,
    model: str,
    get_tool: str,
    preview_tool: str,
    emit: Callable[..., None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
    on_response_open: Callable[[Any], None] | None = None,
) -> dict[str, Any]:
    current_prompt = prompt
    retry_used = False
    final_mismatch: dict[str, Any] | None = None

    for attempt in range(2):
        if cancel_check and cancel_check():
            raise ProviderAdapterError('Generation cancelled by user.', status_code=499)
        model_response = await _mcp_bridge_process_query_server_side(
            client,
            prompt=current_prompt,
            model=model,
            emit=emit,
            cancel_check=cancel_check,
            on_response_open=on_response_open,
        )
        if cancel_check and cancel_check():
            raise ProviderAdapterError('Generation cancelled by user.', status_code=499)
        fetched = await _mcp_bridge_call_tool(client, get_tool, {'draft_id': draft_id})
        previewed = await _mcp_bridge_call_tool(client, preview_tool, {'draft_id': draft_id})

        draft_payload = fetched.get('draft') if isinstance(fetched.get('draft'), dict) else {}
        effective_draft_id = str(draft_payload.get('draft_id') or draft_id).strip()
        final_mismatch = _get_count_intent_mismatch(
            user_prompt,
            previewed.get('preview') if isinstance(previewed.get('preview'), dict) else {},
        )
        if final_mismatch and attempt == 0:
            retry_used = True
            repair = _build_prompt_repair_decision(prompt=prompt, mismatch=final_mismatch)
            if emit is not None and repair.status_message:
                emit('status', message=repair.status_message)
            current_prompt = repair.retry_prompt or prompt
            draft_id = effective_draft_id
            continue
        return {
            'prompt_used': current_prompt,
            'provider_response': model_response,
            'draft_payload': draft_payload,
            'previewed': previewed,
            'count_intent_mismatch': final_mismatch,
            'count_intent_retry_used': retry_used,
        }

    raise ProviderAdapterError('MCP bridge generation failed to produce a preview result.', status_code=502)


def _describe_mcp_bridge_exception(exc: Exception, *, fallback: str) -> str:
    message = str(exc or '').strip()
    if not message:
        return fallback
    if message.lower().startswith('unexpected generation failure while contacting ollama'):
        return fallback
    return message


def _describe_mcp_bridge_base_exception(exc: BaseException, *, fallback: str) -> str:
    message = str(exc or '').strip()
    if message:
        return _describe_mcp_bridge_exception(Exception(message), fallback=fallback)
    exc_name = type(exc).__name__.strip() or 'BaseException'
    return f'{fallback} ({exc_name})'


def _is_unknown_draft_id_error(exc: ProviderAdapterError) -> bool:
    message = str(getattr(exc, 'message', '') or str(exc) or '').strip().lower()
    if 'unknown draft_id' in message:
        return True
    details = getattr(exc, 'details', None)
    if isinstance(details, dict):
        for key in ('error', 'message', 'tool_response'):
            value = str(details.get(key) or '').strip().lower()
            if 'unknown draft_id' in value:
                return True
    return False


def _build_recoverable_mcp_bridge_tool_error(
    qualified_tool_name: str,
    tool_args: dict[str, Any],
    exc: ProviderAdapterError,
    *,
    enabled_tool_names: list[str] | None = None,
) -> str | None:
    message = str(getattr(exc, 'message', '') or str(exc) or '').strip()
    tool_name = str(qualified_tool_name or '').strip()
    if not message:
        return None

    def normalize_traffic_pattern_for_retry(value: Any) -> str:
        text = ''.join(ch for ch in str(value or '').lower() if ch.isalnum())
        aliases = {
            'continuous': 'continuous',
            'alwayson': 'continuous',
            'constantrate': 'continuous',
            'periodic': 'periodic',
            'burst': 'burst',
            'bursty': 'burst',
            'bursts': 'burst',
            'poisson': 'poisson',
            'ramp': 'ramp',
        }
        return aliases.get(text, '')

    def normalize_traffic_protocol_for_retry(value: Any) -> str:
        text = ''.join(ch for ch in str(value or '').lower() if ch.isalnum())
        aliases = {
            'tcp': 'TCP',
            'udp': 'UDP',
            'random': 'TCP',
        }
        return aliases.get(text, 'TCP')

    def infer_vulnerability_vector(value: Any) -> str:
        text = ' '.join(str(value or '').lower().split())
        aliases = (
            ('web', 'web'),
            ('http', 'web'),
            ('browser', 'web'),
            ('sql', 'sql'),
            ('database', 'sql'),
            ('db', 'sql'),
            ('network', 'network'),
            ('remote', 'remote'),
            ('local', 'local'),
        )
        for needle, normalized in aliases:
            if needle in text:
                return normalized
        return ''

    vulnerability_catalog_error = 'specific vulnerability must match an enabled catalog entry by v_path or v_name' in message.lower()
    if tool_name.endswith('scenario.add_vulnerability_item') and vulnerability_catalog_error:
        enabled = [str(name or '').strip() for name in (enabled_tool_names or []) if str(name or '').strip()]
        search_available = any(name.endswith('scenario.search_vulnerability_catalog') for name in enabled)
        add_vulnerability_available = any(name.endswith('scenario.add_vulnerability_item') for name in enabled)
        raw_query = ' '.join(
            part for part in [
                str((tool_args or {}).get('query') or '').strip(),
                str((tool_args or {}).get('search') or '').strip(),
                str((tool_args or {}).get('text') or '').strip(),
                str((tool_args or {}).get('description') or '').strip(),
                str((tool_args or {}).get('vulnerability') or '').strip(),
                str((tool_args or {}).get('v_name') or '').strip(),
            ]
            if part
        ).strip()
        inferred_vector = infer_vulnerability_vector(raw_query)
        try:
            count = max(1, int((tool_args or {}).get('v_count') or 1))
        except Exception:
            count = 1

        guidance = (
            'Do not invent a Specific vulnerability name/path for broad category requests. '
            'If the request is broad, such as web-related vulnerabilities, either call '
            'scenario.search_vulnerability_catalog first and use one returned result, or add a '
            'Type/Vector vulnerability row instead. For web-related vulnerability coverage, use '
            'selected="Type/Vector", v_type="docker-compose", and v_vector="web".'
        )

        if inferred_vector == 'web' and (add_vulnerability_available or not enabled):
            return json.dumps({
                'error': message,
                'recoverable': True,
                'guidance': guidance,
                'retry_hint': {
                    'tool': 'scenario.add_vulnerability_item',
                    'selected': 'Type/Vector',
                    'v_type': 'docker-compose',
                    'v_vector': 'web',
                    'v_count': count,
                },
            })

        if search_available:
            return json.dumps({
                'error': message,
                'recoverable': True,
                'guidance': guidance,
                'retry_hint': {
                    'tool': 'scenario.search_vulnerability_catalog',
                    'query': raw_query or 'web vulnerability',
                    'limit': max(3, count),
                },
            })

        return json.dumps({
            'error': message,
            'recoverable': True,
            'guidance': guidance,
        })

    traffic_pattern_error = 'pattern must be one of: continuous, periodic, burst, poisson, or ramp' in message.lower()
    traffic_replace_error = tool_name.endswith('scenario.replace_section') and str((tool_args or {}).get('section_name') or '').strip().lower() == 'traffic' and 'traffic pattern must be one of:' in message.lower()
    traffic_add_error = tool_name.endswith('scenario.add_traffic_item') and traffic_pattern_error
    if traffic_replace_error or traffic_add_error:
        enabled = [str(name or '').strip() for name in (enabled_tool_names or []) if str(name or '').strip()]
        add_traffic_available = any(name.endswith('scenario.add_traffic_item') for name in enabled)
        replace_section_available = any(name.endswith('scenario.replace_section') for name in enabled)

        item = None
        if traffic_add_error:
            item = tool_args if isinstance(tool_args, dict) else {}
        else:
            payload = tool_args.get('section_payload') if isinstance(tool_args, dict) else None
            items = payload.get('items') if isinstance(payload, dict) and isinstance(payload.get('items'), list) else []
            item = items[0] if items and isinstance(items[0], dict) else {}
        item = item if isinstance(item, dict) else {}

        pattern_raw = item.get('pattern')
        retry_pattern = normalize_traffic_pattern_for_retry(pattern_raw) or 'continuous'
        retry_protocol = normalize_traffic_protocol_for_retry(item.get('selected') or item.get('protocol') or item.get('kind') or item.get('type'))
        count_raw = item.get('v_count') if item.get('v_count') not in (None, '') else item.get('count')
        try:
            count = max(1, int(count_raw)) if count_raw not in (None, '') else 1
        except Exception:
            count = 1

        guidance = (
            'Traffic rows must use exact pattern values: continuous, periodic, burst, poisson, or ramp. '
            'For varied traffic profiles, create multiple Traffic rows and give each row one exact pattern value rather than vague free text such as "various" or non-canonical labels. '
            f'Retry with pattern="{retry_pattern}" for this row.'
        )

        if add_traffic_available or not enabled:
            return json.dumps({
                'error': message,
                'recoverable': True,
                'guidance': guidance,
                'retry_hint': {
                    'tool': 'scenario.add_traffic_item',
                    'protocol': retry_protocol,
                    'count': count,
                    'pattern': retry_pattern,
                    'content_type': str(item.get('content_type') or item.get('content') or 'text'),
                },
            })
        if replace_section_available:
            return json.dumps({
                'error': message,
                'recoverable': True,
                'guidance': guidance,
                'retry_hint': {
                    'tool': 'scenario.replace_section',
                    'section_name': 'Traffic',
                    'section_payload': {
                        'items': [{
                            'selected': retry_protocol,
                            'v_metric': 'Count',
                            'v_count': count,
                            'factor': 0.0,
                            'pattern': retry_pattern,
                            'content_type': str(item.get('content_type') or item.get('content') or 'text'),
                        }],
                    },
                },
            })
        return None

    if not tool_name.endswith('scenario.replace_section'):
        return None

    section_name = str((tool_args or {}).get('section_name') or '').strip().lower()
    node_information_section_names = {'node information', 'nodeinformation', 'node info', 'nodeinfo', 'scenarioinfo'}
    is_node_information_error = section_name in node_information_section_names and 'Node Information selected must be one of:' in message
    is_routing_error = section_name == 'routing' and 'Routing selected must be one of:' in message
    if not (is_node_information_error or is_routing_error):
        return None

    payload = tool_args.get('section_payload') if isinstance(tool_args, dict) else None
    items = payload.get('items') if isinstance(payload, dict) and isinstance(payload.get('items'), list) else []

    def normalize_router_like_selection(item: dict[str, Any]) -> str:
        for key in ('selected', 'protocol', 'role', 'node_type', 'type', 'kind', 'name'):
            normalized = app_backend._normalize_routing_item_selection(item.get(key))
            if normalized:
                return normalized
        return ''

    router_like_item = None
    for item in items:
        if not isinstance(item, dict):
            continue
        normalized = normalize_router_like_selection(item)
        if normalized:
            router_like_item = item
            break
    if not isinstance(router_like_item, dict):
        return None

    def optional_int(value: Any) -> int | None:
        if value in (None, ''):
            return None
        try:
            return max(0, int(value))
        except Exception:
            return None

    count_raw = router_like_item.get('v_count')
    if count_raw in (None, ''):
        count_raw = router_like_item.get('count')
    try:
        count = max(1, int(count_raw)) if count_raw not in (None, '') else 1
    except Exception:
        count = 1

    retry_protocol = normalize_router_like_selection(router_like_item) or 'OSPFv2'
    if retry_protocol in {'Routing', 'Random'}:
        retry_protocol = 'OSPFv2'
    retry_edge_hints: dict[str, Any] = {}
    retry_hint_suffix_parts: list[str] = []

    r2r_mode = str(router_like_item.get('r2r_mode') or '').strip()
    if r2r_mode:
        retry_edge_hints['r2r_mode'] = r2r_mode
        retry_hint_suffix_parts.append(f'r2r_mode={r2r_mode}')
    r2r_edges = optional_int(router_like_item.get('r2r_edges'))
    if r2r_edges is not None:
        retry_edge_hints['r2r_edges'] = r2r_edges
        retry_hint_suffix_parts.append(f'r2r_edges={r2r_edges}')

    r2s_mode = str(router_like_item.get('r2s_mode') or '').strip()
    if r2s_mode:
        retry_edge_hints['r2s_mode'] = r2s_mode
        retry_hint_suffix_parts.append(f'r2s_mode={r2s_mode}')
    r2s_edges = optional_int(router_like_item.get('r2s_edges'))
    if r2s_edges is not None:
        retry_edge_hints['r2s_edges'] = r2s_edges
        retry_hint_suffix_parts.append(f'r2s_edges={r2s_edges}')

    r2s_hosts_min = optional_int(router_like_item.get('r2s_hosts_min'))
    if r2s_hosts_min is not None:
        retry_edge_hints['r2s_hosts_min'] = r2s_hosts_min
        retry_hint_suffix_parts.append(f'r2s_hosts_min={r2s_hosts_min}')
    r2s_hosts_max = optional_int(router_like_item.get('r2s_hosts_max'))
    if r2s_hosts_max is not None:
        retry_edge_hints['r2s_hosts_max'] = r2s_hosts_max
        retry_hint_suffix_parts.append(f'r2s_hosts_max={r2s_hosts_max}')

    retry_hint_suffix = ''
    if retry_hint_suffix_parts:
        retry_hint_suffix = ' Preserve routing edge hints: ' + ', '.join(retry_hint_suffix_parts) + '.'

    enabled = [str(name or '').strip() for name in (enabled_tool_names or []) if str(name or '').strip()]
    add_routing_available = any(name.endswith('scenario.add_routing_item') for name in enabled)
    replace_section_available = any(name.endswith('scenario.replace_section') for name in enabled)

    if add_routing_available or not enabled:
        if is_node_information_error:
            guidance = (
                'Router counts belong in Routing, not Node Information. '
                'Retry with scenario.add_routing_item using protocol="' + retry_protocol + '" and count=' + str(count) + '. '
                'For router-to-router or router-to-host connectivity hints, use Routing r2r_* and r2s_* fields rather than Node Information.'
                + retry_hint_suffix + ' '
                'Do not call scenario.replace_section for Node Information with Router/Routing/gateway values.'
            )
        else:
            guidance = (
                'Routing rows must use a concrete protocol such as RIP, RIPNG, BGP, OSPFv2, or OSPFv3. '
                'Retry with scenario.add_routing_item using protocol="' + retry_protocol + '" and count=' + str(count) + '. '
                'For router-to-router or router-to-host connectivity hints, use Routing r2r_* and r2s_* fields.'
                + retry_hint_suffix + ' '
                'Do not use selected="Routing" or other generic router labels inside the Routing section.'
            )
        retry_hint = {
            'tool': 'scenario.add_routing_item',
            'protocol': retry_protocol,
            'count': count,
            **retry_edge_hints,
        }
    elif replace_section_available:
        if is_node_information_error:
            guidance = (
                'Router counts belong in Routing, not Node Information. '
                'Retry with scenario.replace_section for the Routing section using a Count row with '
                'selected="' + retry_protocol + '" and v_count=' + str(count) + '. '
                'For router-to-router or router-to-host connectivity hints, use Routing r2r_* and r2s_* fields rather than Node Information.'
                + retry_hint_suffix + ' '
                'Do not call scenario.replace_section for Node Information with Router/Routing/gateway values.'
            )
        else:
            guidance = (
                'Routing rows must use a concrete protocol such as RIP, RIPNG, BGP, OSPFv2, or OSPFv3. '
                'Retry with scenario.replace_section for the Routing section using a Count row with '
                'selected="' + retry_protocol + '" and v_count=' + str(count) + '. '
                'For router-to-router or router-to-host connectivity hints, use Routing r2r_* and r2s_* fields.'
                + retry_hint_suffix + ' '
                'Do not use selected="Routing" or other generic router labels inside the Routing section.'
            )
        retry_hint = {
            'tool': 'scenario.replace_section',
            'section_name': 'Routing',
            'section_payload': {
                'items': [
                    {'selected': retry_protocol, 'v_metric': 'Count', 'v_count': count, 'factor': 1.0, **retry_edge_hints},
                ],
            },
        }
    else:
        return None

    return json.dumps({
        'error': message,
        'recoverable': True,
        'guidance': guidance,
        'retry_hint': retry_hint,
    })


def _normalize_ai_bridge_mode(raw_value: Any, *, default: str = _CANONICAL_AI_BRIDGE_MODE) -> str:
    bridge_mode = str(raw_value or default).strip().lower()
    if bridge_mode in _LEGACY_AI_BRIDGE_MODE_ALIASES:
        return _CANONICAL_AI_BRIDGE_MODE
    raise ProviderAdapterError(f'Unsupported bridge_mode {bridge_mode!r}.', status_code=400)


def _is_mcp_python_sdk_bridge_mode(raw_value: Any) -> bool:
    if raw_value is None:
        return False
    if isinstance(raw_value, str) and not raw_value.strip():
        return False
    try:
        return _normalize_ai_bridge_mode(raw_value) == _CANONICAL_AI_BRIDGE_MODE
    except ProviderAdapterError:
        return False


@dataclass(frozen=True)
class ProviderCapability:
    provider: str
    label: str
    enabled: bool
    mode: str
    description: str
    default_base_url: str = ''
    requires_model: bool = True
    requires_api_key: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            'provider': self.provider,
            'label': self.label,
            'enabled': self.enabled,
            'mode': self.mode,
            'description': self.description,
            'default_base_url': self.default_base_url,
            'requires_model': self.requires_model,
            'requires_api_key': self.requires_api_key,
        }


class ProviderAdapter:
    capability: ProviderCapability

    def validate(self, payload: dict[str, Any], *, log: Any = None) -> dict[str, Any]:
        raise NotImplementedError

    def generate(self, payload: dict[str, Any], *, current_scenario: dict[str, Any], user_prompt: str, log: Any = None) -> dict[str, Any]:
        raise NotImplementedError


class UnsupportedProviderAdapter(ProviderAdapter):
    def __init__(self, capability: ProviderCapability):
        self.capability = capability

    def validate(self, payload: dict[str, Any], *, log: Any = None) -> dict[str, Any]:
        raise ProviderAdapterError(
            f'Provider {self.capability.label} is not supported yet. Start with ollama.',
            status_code=400,
            details={'checked_at': _utc_timestamp()},
        )

    def generate(self, payload: dict[str, Any], *, current_scenario: dict[str, Any], user_prompt: str, log: Any = None) -> dict[str, Any]:
        raise ProviderAdapterError(
            f'Provider {self.capability.label} is not wired for generation yet.',
            status_code=400,
        )


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_base_url(raw_value: Any) -> str:
    text = str(raw_value or '').strip()
    if not text:
        return 'http://127.0.0.1:11434'
    if '://' not in text:
        text = f'http://{text}'
    parsed = urlparse(text)
    scheme = (parsed.scheme or '').lower()
    if scheme not in {'http', 'https'}:
        raise ValueError('Base URL must use http or https.')
    if not parsed.netloc:
        raise ValueError('Base URL must include a host.')
    normalized = f'{scheme}://{parsed.netloc}'
    if parsed.path and parsed.path not in {'', '/'}:
        normalized = f'{normalized}{parsed.path.rstrip("/")}'
    return normalized.rstrip('/')


def _fetch_json(url: str, *, timeout: float) -> dict[str, Any]:
    request_obj = Request(url, headers={'Accept': 'application/json'})
    with urlopen(request_obj, timeout=timeout) as response:
        payload = response.read().decode('utf-8')
    data = json.loads(payload)
    if not isinstance(data, dict):
        raise ValueError('Provider returned a non-object JSON payload.')
    return data


def _post_json(url: str, payload: dict[str, Any], *, timeout: float) -> dict[str, Any]:
    body = json.dumps(payload).encode('utf-8')
    request_obj = Request(
        url,
        data=body,
        headers={'Accept': 'application/json', 'Content-Type': 'application/json'},
        method='POST',
    )
    with urlopen(request_obj, timeout=timeout) as response:
        raw = response.read().decode('utf-8')
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError('Provider returned a non-object JSON payload.')
    return data


def _stream_json_lines(
    url: str,
    payload: dict[str, Any],
    *,
    timeout: float,
    cancellation_check: Callable[[], bool] | None = None,
    on_open: Callable[[Any], None] | None = None,
):
    body = json.dumps(payload).encode('utf-8')
    request_obj = Request(
        url,
        data=body,
        headers={'Accept': 'application/json', 'Content-Type': 'application/json'},
        method='POST',
    )
    with urlopen(request_obj, timeout=timeout) as response:
        if callable(on_open):
            on_open(response)
        for raw_line in response:
            if cancellation_check and cancellation_check():
                break
            line = raw_line.decode('utf-8').strip()
            if not line:
                continue
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                yield parsed


def _ndjson_event(event_type: str, **payload: Any) -> str:
    return json.dumps({'type': event_type, **payload}, ensure_ascii=True) + '\n'


def _create_stream_request_id() -> str:
    return uuid.uuid4().hex


def _register_ai_stream(request_id: str) -> dict[str, Any]:
    entry = {
        'request_id': request_id,
        'cancelled': threading.Event(),
        'response': None,
        'client': None,
    }
    with _ACTIVE_AI_STREAMS_LOCK:
        _ACTIVE_AI_STREAMS[request_id] = entry
    return entry


def _get_ai_stream(request_id: str) -> dict[str, Any] | None:
    with _ACTIVE_AI_STREAMS_LOCK:
        return _ACTIVE_AI_STREAMS.get(request_id)


def _unregister_ai_stream(request_id: str) -> None:
    with _ACTIVE_AI_STREAMS_LOCK:
        _ACTIVE_AI_STREAMS.pop(request_id, None)


def _cancel_ai_stream(request_id: str) -> bool:
    entry = _get_ai_stream(request_id)
    if not entry:
        return False
    entry['cancelled'].set()
    client = entry.get('client')
    if client is not None:
        try:
            setattr(client, 'abort_current_query', True)
        except Exception:
            pass
    response_obj = entry.get('response')
    if response_obj is not None:
        try:
            response_obj.close()
        except Exception:
            pass
    return True


def _scenario_generation_schema() -> dict[str, Any]:
    item_schema = {
        'type': 'object',
        'additionalProperties': True,
        'properties': {
            'selected': {'type': ['string', 'boolean', 'number', 'null']},
            'factor': {'type': ['number', 'integer', 'string', 'null']},
            'pattern': {'type': ['string', 'null']},
            'rate_kbps': {'type': ['number', 'integer', 'string', 'null']},
            'period_s': {'type': ['number', 'integer', 'string', 'null']},
            'jitter_pct': {'type': ['number', 'integer', 'string', 'null']},
            'content_type': {'type': ['string', 'null']},
            'v_metric': {'type': ['string', 'null']},
            'v_count': {'type': ['number', 'integer', 'string', 'null']},
            'v_name': {'type': ['string', 'null']},
            'v_type': {'type': ['string', 'null']},
            'v_vector': {'type': ['string', 'null']},
        },
    }
    section_schema = {
        'type': 'object',
        'additionalProperties': True,
        'properties': {
            'density': {'type': ['number', 'integer', 'string', 'null']},
            'total_nodes': {'type': ['number', 'integer', 'string', 'null']},
            'flag_type': {'type': ['string', 'null']},
            'items': {'type': 'array', 'items': item_schema},
        },
    }
    sections_schema = {
        'type': 'object',
        'additionalProperties': False,
        'properties': {name: section_schema for name in _SUPPORTED_SECTION_NAMES},
    }
    return {
        'type': 'object',
        'additionalProperties': False,
        'required': ['scenario'],
        'properties': {
            'scenario': {
                'type': 'object',
                'additionalProperties': True,
                'properties': {
                    'name': {'type': ['string', 'null']},
                    'density_count': {'type': ['number', 'integer', 'string', 'null']},
                    'notes': {'type': ['string', 'null']},
                    'base': {
                        'type': 'object',
                        'additionalProperties': True,
                        'properties': {
                            'filepath': {'type': ['string', 'null']},
                            'display_name': {'type': ['string', 'null']},
                        },
                    },
                    'sections': sections_schema,
                },
                'required': ['sections'],
            },
        },
    }


def _extract_json_candidate(raw_text: str) -> dict[str, Any] | None:
    text = (raw_text or '').strip()
    if not text:
        return None
    candidates = [text]
    if '```' in text:
        parts = text.split('```')
        for part in parts:
            trimmed = part.strip()
            if not trimmed:
                continue
            if trimmed.startswith('json'):
                trimmed = trimmed[4:].strip()
            candidates.append(trimmed)
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
        start = candidate.find('{')
        end = candidate.rfind('}')
        if start >= 0 and end > start:
            try:
                parsed = json.loads(candidate[start:end + 1])
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
    return None


def _default_section_payload(name: str) -> dict[str, Any]:
    if name == 'Node Information':
        return {'total_nodes': 0, 'density': 0, 'items': []}
    if name == 'Vulnerabilities':
        return {'density': 0.5, 'items': [], 'flag_type': 'text'}
    return {'density': 0.5, 'items': []}


def _build_ai_seed_scenario(current_scenario: dict[str, Any]) -> dict[str, Any]:
    scenario_name = str((current_scenario or {}).get('name') or '').strip() or 'Scenario'
    current_base = current_scenario.get('base') if isinstance(current_scenario.get('base'), dict) else {}
    next_base = {}
    for key in ('filepath', 'display_name'):
        value = current_base.get(key)
        if isinstance(value, str):
            next_base[key] = value

    next_sections: dict[str, Any] = {}
    for section_name in _SUPPORTED_SECTION_NAMES:
        section_payload = _default_section_payload(section_name)
        if section_name != 'Node Information':
            section_payload['density'] = 0
        if section_name == 'Vulnerabilities':
            section_payload['flag_type'] = 'text'
        next_sections[section_name] = section_payload

    seed_scenario = {
        'name': scenario_name,
        'density_count': 0,
        'notes': '',
        'sections': next_sections,
    }
    if next_base:
        seed_scenario['base'] = next_base
    return seed_scenario


def _restore_preserved_scenario_metadata(source_scenario: dict[str, Any], target_scenario: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(target_scenario if isinstance(target_scenario, dict) else {})
    source_name = str(source_scenario.get('name') or '').strip()
    if source_name:
        result['name'] = source_name
    if isinstance(source_scenario.get('ai_generator'), dict):
        result['ai_generator'] = deepcopy(source_scenario.get('ai_generator'))
    if isinstance(source_scenario.get('hitl'), dict):
        result['hitl'] = deepcopy(source_scenario.get('hitl'))
    if source_scenario.get('_sid') is not None and result.get('_sid') is None:
        result['_sid'] = source_scenario.get('_sid')
    return result


def _normalize_generated_scenario(current_scenario: dict[str, Any], generated_payload: dict[str, Any]) -> dict[str, Any]:
    generated_scenario = generated_payload.get('scenario') if isinstance(generated_payload.get('scenario'), dict) else generated_payload
    result = deepcopy(current_scenario)

    if generated_scenario.get('density_count') not in (None, ''):
        try:
            result['density_count'] = int(generated_scenario.get('density_count'))
        except Exception:
            pass
    if isinstance(generated_scenario.get('notes'), str):
        result['notes'] = generated_scenario.get('notes')

    current_base = result.get('base') if isinstance(result.get('base'), dict) else {}
    generated_base = generated_scenario.get('base') if isinstance(generated_scenario.get('base'), dict) else {}
    if current_base or generated_base:
        next_base = dict(current_base)
        for key in ('filepath', 'display_name'):
            value = generated_base.get(key)
            if isinstance(value, str):
                next_base[key] = value
        result['base'] = next_base

    current_sections = result.get('sections') if isinstance(result.get('sections'), dict) else {}
    generated_sections = generated_scenario.get('sections') if isinstance(generated_scenario.get('sections'), dict) else {}
    next_sections: dict[str, Any] = {}
    for section_name in _SUPPORTED_SECTION_NAMES:
        current_section = deepcopy(current_sections.get(section_name)) if isinstance(current_sections.get(section_name), dict) else _default_section_payload(section_name)
        generated_section = generated_sections.get(section_name) if isinstance(generated_sections.get(section_name), dict) else None
        if not generated_section:
            next_sections[section_name] = current_section
            continue
        merged_section = deepcopy(current_section)
        if section_name == 'Node Information':
            if generated_section.get('total_nodes') not in (None, ''):
                try:
                    merged_section['total_nodes'] = int(generated_section.get('total_nodes'))
                except Exception:
                    pass
        else:
            if generated_section.get('density') not in (None, ''):
                try:
                    merged_section['density'] = float(generated_section.get('density'))
                except Exception:
                    pass
        if section_name == 'Vulnerabilities' and isinstance(generated_section.get('flag_type'), str):
            merged_section['flag_type'] = generated_section.get('flag_type').strip() or merged_section.get('flag_type') or 'text'
        items = generated_section.get('items')
        if isinstance(items, list):
            merged_items = []
            for item in items:
                if isinstance(item, dict):
                    merged_items.append(item)
            merged_section['items'] = merged_items
        next_sections[section_name] = merged_section
    result['sections'] = next_sections
    return _restore_preserved_scenario_metadata(current_scenario, result)


def _canonicalize_generated_vulnerabilities_or_raise(scenario_payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return app_backend._canonicalize_specific_vulnerability_items(scenario_payload, strict=True)
    except ValueError as exc:
        raise ProviderAdapterError(str(exc), status_code=400) from exc


def _build_ollama_prompt(current_scenario: dict[str, Any], user_prompt: str) -> str:
    template = _build_ai_seed_scenario(current_scenario)
    template.pop('hitl', None)
    template.pop('flow_state', None)
    template.pop('plan_preview', None)
    template.pop('ai_generator', None)
    template.pop('_sid', None)
    rules = {
        'instructions': [
            'Return JSON only.',
            'Top-level object must be {"scenario": {...}}.',
            'Recreate the scenario from scratch using the clean template.',
            'Populate sections with backend-friendly values only.',
            'If the prompt specifies host counts, encode them in Node Information items using v_metric="Count" and v_count.',
            'If the prompt specifies how many routers should exist, encode that as a Routing item using v_metric="Count" and v_count. Router count means the number of router nodes, not link density.',
            'If the prompt specifies router-to-router or router-to-host connectivity or ratios, encode them in Routing items using r2r_mode/r2r_edges and r2s_mode/r2s_edges/r2s_hosts_min/r2s_hosts_max. These fields control connectivity density, not how many routers exist.',
            'There is no r2h field. Map router-to-host wording to Routing r2s_* fields because hosts attach through routed segments/switches.',
            'Do not leave prior scenario rows in place unless they are explicitly requested in the prompt.',
            'Do not include markdown, commentary, or code fences.',
            *_build_count_intent_guidance(user_prompt),
        ],
        'section_expectations': {
            'Node Information': 'items contain selected, factor, and optional v_metric/v_count. Use selected="Docker" for docker hosts. Use v_metric="Count" with v_count for explicit host counts.',
            'Routing': 'items contain selected, factor, optional v_metric/v_count for router counts, and optional r2r_mode/r2r_edges/r2s_mode/r2s_edges/r2s_hosts_min/r2s_hosts_max. v_count is the number of routers. r2r_edges is router-to-router link density. r2s_edges and r2s_hosts_* describe router-to-segment attachment density.',
            'Services': 'items contain selected and factor.',
            'Traffic': 'items contain selected, factor, pattern, rate_kbps, period_s, jitter_pct, content_type. Use selected="TCP" or "UDP" plus either v_metric="Count" with v_count or a positive factor so traffic flows materialize.',
            'Vulnerabilities': 'items contain selected plus vulnerability fields such as v_metric, v_count, v_name, v_type, v_vector.',
            'Segmentation': 'items contain selected and factor.',
        },
        'user_request': user_prompt,
        'template': template,
    }
    return json.dumps(rules, indent=2)


def _build_ollama_repair_prompt(current_scenario: dict[str, Any], user_prompt: str, raw_generation: str) -> str:
    template = _build_ai_seed_scenario(current_scenario)
    template.pop('hitl', None)
    template.pop('flow_state', None)
    template.pop('plan_preview', None)
    template.pop('ai_generator', None)
    template.pop('_sid', None)
    rules = {
        'instructions': [
            'Your previous answer was not valid JSON for the required schema.',
            'Return JSON only.',
            'Top-level object must be {"scenario": {...}}.',
            'Do not include commentary, markdown, or code fences.',
            'Ensure sections remain backend-friendly and rebuild the scenario from the clean template.',
            'Use Node Information items with v_metric="Count" and v_count for host counts.',
            'Use selected="Docker" in Node Information for docker hosts.',
            'Use Routing items with v_metric="Count" and v_count when the prompt specifies how many routers should exist. v_count is router quantity, not connectivity.',
            'Use Routing r2r_* and r2s_* fields only for router-to-router or router-to-host connectivity hints and ratios. Those fields describe connectivity density, not router quantity.',
            'There is no r2h field. Map router-to-host wording to Routing r2s_* fields.',
            'Use Traffic items with selected="TCP" or "UDP" and either v_metric="Count" with v_count or a positive factor so flows appear in preview.',
            *_build_count_intent_guidance(user_prompt),
        ],
        'user_request': user_prompt,
        'template': template,
        'previous_invalid_response': raw_generation[:4000],
    }
    return json.dumps(rules, indent=2)


def _normalize_tool_selection(raw_value: Any) -> list[str]:
    if isinstance(raw_value, dict):
        selected = []
        for name, enabled in raw_value.items():
            if enabled:
                text = str(name or '').strip()
                if text:
                    selected.append(text)
        return selected
    if not isinstance(raw_value, list):
        return []
    selected = []
    for entry in raw_value:
        text = str(entry or '').strip()
        if text:
            selected.append(text)
    return selected


def _normalize_local_path(raw_value: Any, *, default_path: str | None = None) -> str:
    text = str(raw_value or '').strip()
    if not text and default_path:
        text = default_path
    if not text:
        return ''
    if not os.path.isabs(text):
        text = os.path.join(_REPO_ROOT, text)
    return os.path.abspath(text)


def _normalize_mcp_servers_json_path(raw_value: Any) -> str:
    normalized = _normalize_local_path(raw_value)
    if not normalized:
        return ''
    if os.path.normpath(normalized) == os.path.normpath(_LEGACY_MCP_SERVERS_JSON_PATH):
        return _DEFAULT_MCP_SERVERS_JSON_PATH
    return normalized


def _normalize_mcp_bridge_payload(payload: dict[str, Any]) -> dict[str, Any]:
    bridge_mode = _normalize_ai_bridge_mode(payload.get('bridge_mode'))

    mcp_server_path = _normalize_local_path(payload.get('mcp_server_path'), default_path=_DEFAULT_MCP_SERVER_PATH)
    mcp_server_url = str(payload.get('mcp_server_url') or '').strip()
    servers_json_path = _normalize_mcp_servers_json_path(payload.get('servers_json_path'))
    auto_discovery = bool(payload.get('auto_discovery'))
    if not any([mcp_server_path, mcp_server_url, servers_json_path, auto_discovery]):
        mcp_server_path = _DEFAULT_MCP_SERVER_PATH

    if mcp_server_path and not os.path.exists(mcp_server_path):
        raise ProviderAdapterError(f'MCP server script not found: {mcp_server_path}', status_code=400)
    if servers_json_path and not os.path.exists(servers_json_path):
        raise ProviderAdapterError(f'servers_json_path not found: {servers_json_path}', status_code=400)

    enabled_tools = _normalize_tool_selection(payload.get('enabled_tools'))
    hil_enabled_raw = payload.get('hil_enabled')
    if hil_enabled_raw is None:
        hil_enabled = _env_flag('CORETG_MCP_PYTHON_SDK_HIL_ENABLED', _env_flag('CORETG_OLLMCP_HIL_ENABLED', False))
    else:
        hil_enabled = bool(hil_enabled_raw)
    return {
        'bridge_mode': bridge_mode,
        'mcp_server_path': mcp_server_path,
        'mcp_server_url': mcp_server_url,
        'servers_json_path': servers_json_path,
        'auto_discovery': auto_discovery,
        'enabled_tools': enabled_tools,
        'hil_enabled': hil_enabled,
    }


def _mcp_bridge_tool_payload(tool: Any, enabled_map: dict[str, bool]) -> dict[str, Any]:
    name = str(getattr(tool, 'name', '') or '').strip()
    description = str(getattr(tool, 'description', '') or '').strip()
    input_schema = getattr(tool, 'inputSchema', None)
    server_name, tool_name = name.split('.', 1) if '.' in name else ('default', name)
    return {
        'name': name,
        'server_name': server_name,
        'tool_name': tool_name,
        'description': description,
        'enabled': bool(enabled_map.get(name, True)),
        'input_schema': input_schema if isinstance(input_schema, dict) else {},
    }


_OLL_MCP_INTERNAL_TOOL_SUFFIXES = {
    'scenario.create_draft',
    'scenario.get_draft',
    'scenario.preview_draft',
    'scenario.delete_draft',
    'scenario.save_xml',
    'scenario.list_drafts',
}


def _is_user_exposed_mcp_bridge_tool(tool_name: str) -> bool:
    name = str(tool_name or '').strip()
    if not name:
        return False
    return not any(name.endswith(suffix) for suffix in _OLL_MCP_INTERNAL_TOOL_SUFFIXES)


def _extract_tool_text(result: Any) -> str:
    structured = getattr(result, 'structuredContent', None)
    if structured is not None:
        try:
            return json.dumps(structured, indent=2, sort_keys=True)
        except Exception:
            pass
    contents = getattr(result, 'content', None)
    if not isinstance(contents, list):
        return ''
    parts: list[str] = []
    for entry in contents:
        text = getattr(entry, 'text', None)
        if isinstance(text, str) and text:
            parts.append(text)
    return '\n'.join(parts).strip()


@dataclass(frozen=True)
class _BridgeToolDefinition:
    name: str
    description: str
    inputSchema: dict[str, Any]


class _BridgeToolManager:
    def __init__(self) -> None:
        self._tools: list[_BridgeToolDefinition] = []
        self._enabled: dict[str, bool] = {}

    def set_available_tools(self, tools: list[_BridgeToolDefinition]) -> None:
        self._tools = list(tools)
        known = {tool.name for tool in self._tools}
        self._enabled = {name: self._enabled.get(name, True) for name in known}

    def get_available_tools(self) -> list[_BridgeToolDefinition]:
        return list(self._tools)

    def get_enabled_tool_objects(self) -> list[_BridgeToolDefinition]:
        return [tool for tool in self._tools if self._enabled.get(tool.name, True)]

    def get_enabled_tools(self) -> dict[str, bool]:
        return dict(self._enabled)

    def set_tool_status(self, tool_name: str, enabled: bool) -> None:
        self._enabled[str(tool_name or '').strip()] = bool(enabled)


class _BridgeHilManager:
    def __init__(self) -> None:
        self.enabled = True
        self.session_auto_execute = False

    def set_enabled(self, enabled: bool) -> None:
        self.enabled = bool(enabled)

    def set_session_auto_execute(self, enabled: bool) -> None:
        self.session_auto_execute = bool(enabled)


def _normalize_bridge_timeout_seconds(raw_value: Any, *, default: float = 90.0, low: float = 5.0, high: float = 240.0) -> float:
    try:
        value = float(raw_value) if raw_value is not None else default
    except (TypeError, ValueError):
        value = default
    return min(max(value, low), high)


def _ensure_bridge_client_sdk_available() -> None:
    if ClientSession is None or StdioServerParameters is None or stdio_client is None or streamable_http_client is None:
        raise ProviderAdapterError('The official MCP Python SDK is not installed in the active environment.', status_code=500)


def _normalize_bridge_server_name(raw_name: Any, *, fallback: str = 'server') -> str:
    text = str(raw_name or '').strip()
    return text or fallback


def _looks_like_python_command(command: str) -> bool:
    normalized = os.path.basename(str(command or '').strip()).lower()
    return normalized in {'python', 'python3', 'python3.12', os.path.basename(sys.executable).lower()}


def _canonicalize_bridge_server_config(raw_config: dict[str, Any]) -> tuple[dict[str, Any], tuple[Any, ...] | None]:
    config = dict(raw_config)
    transport = str(config.get('transport') or '').strip().lower()

    if transport == 'http':
        url = _normalize_base_url(config.get('url'))
        config['url'] = url
        return config, ('http', url)

    command = str(config.get('command') or '').strip() or sys.executable
    cwd = os.path.abspath(str(config.get('cwd') or _REPO_ROOT).strip() or _REPO_ROOT)
    args = [str(arg).strip() for arg in (config.get('args') or []) if str(arg or '').strip()]
    env = config.get('env') if isinstance(config.get('env'), dict) else None

    config['transport'] = 'stdio'
    config['command'] = command
    config['args'] = args
    config['cwd'] = cwd
    config['env'] = {str(key): str(value) for key, value in env.items()} if env else None

    if args and _looks_like_python_command(command):
        script_arg = args[0]
        script_path = script_arg if os.path.isabs(script_arg) else os.path.abspath(os.path.join(cwd, script_arg))
        return config, ('python-script', script_path)

    resolved_command = command if not os.path.isabs(command) else os.path.abspath(command)
    resolved_args = tuple(
        arg if not os.path.isabs(arg) else os.path.abspath(arg)
        for arg in args
    )
    return config, ('stdio', resolved_command, resolved_args, cwd)


def _resolve_bridge_server_configs(
    *,
    server_paths: list[str] | None,
    server_urls: list[str] | None,
    config_path: str | None,
    auto_discovery: bool,
) -> list[dict[str, Any]]:
    configs: list[dict[str, Any]] = []
    used_names: set[str] = set()
    seen_signatures: set[tuple[Any, ...]] = set()

    def _next_name(base: str) -> str:
        candidate = base
        counter = 2
        while candidate in used_names:
            candidate = f'{base}{counter}'
            counter += 1
        used_names.add(candidate)
        return candidate

    def _append_config(raw_config: dict[str, Any], *, preferred_name: str) -> None:
        normalized_config, signature = _canonicalize_bridge_server_config(raw_config)
        if signature is not None and signature in seen_signatures:
            return
        if signature is not None:
            seen_signatures.add(signature)
        normalized_config['server_name'] = _next_name(preferred_name)
        configs.append(normalized_config)

    path_list = [str(path).strip() for path in (server_paths or []) if str(path or '').strip()]
    for index, path in enumerate(path_list):
        _append_config({
            'transport': 'stdio',
            'command': sys.executable,
            'args': [os.path.abspath(path)],
            'cwd': _REPO_ROOT,
            'env': None,
        }, preferred_name='server' if index == 0 else f'server{index + 1}')

    url_list = [str(url).strip() for url in (server_urls or []) if str(url or '').strip()]
    for index, url in enumerate(url_list):
        _append_config({
            'transport': 'http',
            'url': url,
        }, preferred_name='server' if not configs and index == 0 else f'http{index + 1}')

    if config_path:
        with open(config_path, 'r', encoding='utf-8') as handle:
            config_data = json.load(handle)
        raw_servers = config_data.get('mcpServers') if isinstance(config_data, dict) else None
        if isinstance(raw_servers, dict):
            entries = [(name, value) for name, value in raw_servers.items() if isinstance(value, dict) and not value.get('disabled')]
            single_entry = len(entries) == 1
            for raw_name, raw_cfg in entries:
                preferred_name = 'server' if single_entry else _normalize_bridge_server_name(raw_name, fallback='server')
                url = str(raw_cfg.get('url') or '').strip()
                if url:
                    _append_config({
                        'transport': 'http',
                        'url': url,
                    }, preferred_name=preferred_name)
                    continue
                command = str(raw_cfg.get('command') or '').strip() or sys.executable
                args = [str(arg) for arg in (raw_cfg.get('args') or []) if str(arg or '').strip()]
                env = raw_cfg.get('env') if isinstance(raw_cfg.get('env'), dict) else None
                cwd = str(raw_cfg.get('cwd') or '').strip() or _REPO_ROOT
                _append_config({
                    'transport': 'stdio',
                    'command': command,
                    'args': args,
                    'cwd': cwd,
                    'env': {str(key): str(value) for key, value in env.items()} if env else None,
                }, preferred_name=preferred_name)

    if not configs and auto_discovery:
        _append_config({
            'transport': 'stdio',
            'command': sys.executable,
            'args': [os.path.abspath(_DEFAULT_MCP_SERVER_PATH)],
            'cwd': _REPO_ROOT,
            'env': None,
        }, preferred_name='server')
    return configs


def _normalize_mcp_bridge_tool_name(tool_name: Any, *, known_server_names: list[str] | None = None) -> str:
    text = str(tool_name or '').strip()
    if not text:
        return ''
    if isinstance(known_server_names, list):
        known = {str(name or '').strip() for name in known_server_names if str(name or '').strip()}
    else:
        known = set()

    if '.' in text:
        server_name, _rest = text.split('.', 1)
        if not known or server_name in known:
            return text
        underscore_idx = server_name.find('_')
        if underscore_idx > 0:
            candidate = f'{server_name[:underscore_idx]}.{server_name[underscore_idx + 1:]}.{text.split(".", 1)[1]}'
            candidate_server, _candidate_rest = candidate.split('.', 1)
            if not known or candidate_server in known:
                return candidate
    return text


def _normalize_ollama_chat_tool_calls(raw_tool_calls: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_tool_calls, list):
        return []
    tool_calls: list[dict[str, Any]] = []
    for entry in raw_tool_calls:
        if not isinstance(entry, dict):
            continue
        function = entry.get('function') if isinstance(entry.get('function'), dict) else {}
        tool_name = _normalize_mcp_bridge_tool_name(function.get('name'))
        if not tool_name:
            continue
        tool_args = function.get('arguments')
        if isinstance(tool_args, str):
            try:
                tool_args = json.loads(tool_args)
            except Exception:
                tool_args = {'raw': tool_args}
        if not isinstance(tool_args, dict):
            tool_args = {'value': tool_args}
        tool_calls.append({
            'function': {
                'name': tool_name,
                'arguments': tool_args,
            },
        })
    return tool_calls


def _extract_ollama_chat_message(raw_payload: dict[str, Any]) -> dict[str, Any]:
    message = raw_payload.get('message') if isinstance(raw_payload.get('message'), dict) else {}
    role = str(message.get('role') or 'assistant').strip() or 'assistant'
    content = str(message.get('content') or '')
    thinking = str(message.get('thinking') or '')
    tool_calls = _normalize_ollama_chat_tool_calls(message.get('tool_calls'))
    result = {
        'role': role,
        'content': content,
    }
    if thinking:
        result['thinking'] = thinking
    if tool_calls:
        result['tool_calls'] = tool_calls
    return result


class _RepoMcpBridgeClient:
    def __init__(self, *, model: str, host: str):
        self.model = model
        self.host = host
        self.sessions: dict[str, dict[str, Any]] = {}
        self.connection_errors: dict[str, str] = {}
        self.tool_manager = _BridgeToolManager()
        self.hil_manager = _BridgeHilManager()
        self.abort_current_query = False
        self.loop_limit = 8
        self.timeout_seconds = 120.0
        self._exit_stack: AsyncExitStack | None = None

    async def connect_to_servers(
        self,
        *,
        server_paths: list[str] | None = None,
        server_urls: list[str] | None = None,
        config_path: str | None = None,
        auto_discovery: bool = False,
    ) -> None:
        _ensure_bridge_client_sdk_available()
        server_configs = _resolve_bridge_server_configs(
            server_paths=server_paths,
            server_urls=server_urls,
            config_path=config_path,
            auto_discovery=auto_discovery,
        )
        if not server_configs:
            return

        exit_stack = AsyncExitStack()
        await exit_stack.__aenter__()
        try:
            for server_cfg in server_configs:
                server_name = server_cfg['server_name']
                try:
                    if server_cfg['transport'] == 'http':
                        read_stream, write_stream, _get_session_id = await exit_stack.enter_async_context(
                            streamable_http_client(server_cfg['url'])
                        )
                    else:
                        params = StdioServerParameters(
                            command=server_cfg['command'],
                            args=server_cfg.get('args') or [],
                            cwd=server_cfg.get('cwd') or None,
                            env=server_cfg.get('env'),
                        )
                        read_stream, write_stream = await exit_stack.enter_async_context(stdio_client(params))
                    session = await exit_stack.enter_async_context(ClientSession(read_stream, write_stream))
                    await session.initialize()
                    self.sessions[server_name] = {'session': session, 'config': server_cfg}
                except Exception as exc:
                    self.connection_errors[server_name] = str(exc or '').strip() or type(exc).__name__
            await self._refresh_tools()
            self._exit_stack = exit_stack
        except Exception:
            await exit_stack.aclose()
            self.sessions = {}
            self.connection_errors = {}
            raise

    async def _refresh_tools(self) -> None:
        tools: list[_BridgeToolDefinition] = []
        for server_name, entry in self.sessions.items():
            result = await entry['session'].list_tools()
            for tool in list(result.tools or []):
                tools.append(_BridgeToolDefinition(
                    name=f'{server_name}.{str(getattr(tool, "name", "") or "").strip()}',
                    description=str(getattr(tool, 'description', '') or '').strip(),
                    inputSchema=getattr(tool, 'inputSchema', None) if isinstance(getattr(tool, 'inputSchema', None), dict) else {},
                ))
        self.tool_manager.set_available_tools(tools)

    def _is_cancelled(self, cancel_check: Callable[[], bool] | None = None) -> bool:
        if self.abort_current_query:
            return True
        if callable(cancel_check):
            try:
                return bool(cancel_check())
            except Exception:
                return False
        return False

    def _build_chat_tools_payload(self) -> list[dict[str, Any]]:
        payload: list[dict[str, Any]] = []
        for tool in self.tool_manager.get_enabled_tool_objects():
            payload.append({
                'type': 'function',
                'function': {
                    'name': tool.name,
                    'description': tool.description,
                    'parameters': tool.inputSchema if isinstance(tool.inputSchema, dict) else {},
                },
            })
        return payload

    def _post_chat(self, *, messages: list[dict[str, Any]]) -> dict[str, Any]:
        try:
            return _post_json(
                f'{self.host}/api/chat',
                {
                    'model': self.model,
                    'messages': messages,
                    'tools': self._build_chat_tools_payload(),
                    'stream': False,
                    'options': {'temperature': 0.1},
                },
                timeout=self.timeout_seconds,
            )
        except HTTPError as exc:
            detail = ''
            try:
                detail = exc.read().decode('utf-8').strip()
            except Exception:
                detail = ''
            message = f'Ollama returned HTTP {exc.code}.'
            if detail:
                message = f'{message} {detail[:240]}'
            raise ProviderAdapterError(message, status_code=502) from exc
        except URLError as exc:
            reason = getattr(exc, 'reason', exc)
            raise ProviderAdapterError(f'Could not reach Ollama at {self.host}: {reason}', status_code=502) from exc

    def _stream_chat(
        self,
        *,
        messages: list[dict[str, Any]],
        emit: Callable[..., None],
        cancel_check: Callable[[], bool] | None = None,
        on_response_open: Callable[[Any], None] | None = None,
    ) -> dict[str, Any]:
        accumulated_text = ''
        accumulated_thinking = ''
        tool_calls: list[dict[str, Any]] = []
        try:
            for chunk in _stream_json_lines(
                f'{self.host}/api/chat',
                {
                    'model': self.model,
                    'messages': messages,
                    'tools': self._build_chat_tools_payload(),
                    'stream': True,
                    'options': {'temperature': 0.1},
                },
                timeout=self.timeout_seconds,
                cancellation_check=lambda: self._is_cancelled(cancel_check),
                on_open=on_response_open,
            ):
                if self._is_cancelled(cancel_check):
                    raise ProviderAdapterError('Generation cancelled by user.', status_code=499)
                message = chunk.get('message') if isinstance(chunk.get('message'), dict) else {}
                thinking_text = str(message.get('thinking') or '')
                if thinking_text:
                    accumulated_thinking += thinking_text
                    emit('llm_thinking', text=thinking_text)
                content_delta = str(message.get('content') or '')
                if content_delta:
                    accumulated_text += content_delta
                    emit('llm_delta', text=content_delta)
                for tool_call in _normalize_ollama_chat_tool_calls(message.get('tool_calls')):
                    tool_calls.append(tool_call)
                    emit('tool_call', tool_name=str(((tool_call.get('function') or {}).get('name')) or ''))
        except HTTPError as exc:
            detail = ''
            try:
                detail = exc.read().decode('utf-8').strip()
            except Exception:
                detail = ''
            message = f'Ollama returned HTTP {exc.code}.'
            if detail:
                message = f'{message} {detail[:240]}'
            raise ProviderAdapterError(message, status_code=502) from exc
        except URLError as exc:
            reason = getattr(exc, 'reason', exc)
            raise ProviderAdapterError(f'Could not reach Ollama at {self.host}: {reason}', status_code=502) from exc
        assistant_message = {
            'role': 'assistant',
            'content': accumulated_text,
        }
        if accumulated_thinking:
            assistant_message['thinking'] = accumulated_thinking
        if tool_calls:
            assistant_message['tool_calls'] = tool_calls
        return assistant_message

    async def _run_query(
        self,
        prompt: str,
        *,
        emit: Callable[..., None] | None = None,
        cancel_check: Callable[[], bool] | None = None,
        on_response_open: Callable[[Any], None] | None = None,
    ) -> str:
        messages: list[dict[str, Any]] = [{'role': 'user', 'content': prompt}]
        final_text = ''

        for _ in range(max(1, int(self.loop_limit or 8))):
            if self._is_cancelled(cancel_check):
                return final_text
            if emit is not None:
                assistant_message = self._stream_chat(
                    messages=messages,
                    emit=emit,
                    cancel_check=cancel_check,
                    on_response_open=on_response_open,
                )
            else:
                assistant_message = _extract_ollama_chat_message(self._post_chat(messages=messages))

            content = str(assistant_message.get('content') or '')
            if content:
                final_text = content
            messages.append({
                'role': 'assistant',
                'content': content,
                **({'tool_calls': assistant_message.get('tool_calls')} if assistant_message.get('tool_calls') else {}),
            })

            tool_calls = assistant_message.get('tool_calls') if isinstance(assistant_message.get('tool_calls'), list) else []
            if not tool_calls:
                break

            for tool_call in tool_calls:
                if self._is_cancelled(cancel_check):
                    return final_text
                function = tool_call.get('function') if isinstance(tool_call.get('function'), dict) else {}
                qualified_tool_name = str(function.get('name') or '').strip()
                tool_args = function.get('arguments') if isinstance(function.get('arguments'), dict) else {}
                if emit is not None:
                    emit('tool', stage='start', tool_name=qualified_tool_name, message=f'Running {qualified_tool_name}')
                try:
                    tool_result = await _mcp_bridge_call_tool(self, qualified_tool_name, tool_args)
                    tool_response = _structured_text_payload(tool_result)
                except ProviderAdapterError as exc:
                    enabled_tool_names: list[str] = []
                    tool_manager = getattr(self, 'tool_manager', None)
                    if tool_manager is not None:
                        try:
                            enabled_tool_names = [
                                str(getattr(tool, 'name', '') or '').strip()
                                for tool in (tool_manager.get_enabled_tool_objects() or [])
                                if str(getattr(tool, 'name', '') or '').strip()
                            ]
                        except Exception:
                            try:
                                enabled_map = tool_manager.get_enabled_tools() or {}
                                enabled_tool_names = [
                                    str(name or '').strip()
                                    for name, enabled in enabled_map.items()
                                    if enabled and str(name or '').strip()
                                ]
                            except Exception:
                                enabled_tool_names = []
                    repair = _build_tool_repair_decision(
                        qualified_tool_name,
                        tool_args,
                        exc,
                        enabled_tool_names=enabled_tool_names,
                    )
                    if not repair.retryable:
                        raise
                    if emit is not None and repair.status_message:
                        emit('status', message=repair.status_message)
                    tool_response = repair.tool_response or ''
                if emit is not None:
                    emit('tool', stage='result', tool_name=qualified_tool_name, message=tool_response)
                messages.append({
                    'role': 'tool',
                    'tool_name': qualified_tool_name,
                    'content': tool_response,
                })

        return final_text

    async def process_query(self, prompt: str) -> str:
        return await self._run_query(prompt)

    async def process_query_with_events(
        self,
        prompt: str,
        *,
        emit: Callable[..., None],
        cancel_check: Callable[[], bool] | None = None,
        on_response_open: Callable[[Any], None] | None = None,
    ) -> str:
        return await self._run_query(prompt, emit=emit, cancel_check=cancel_check, on_response_open=on_response_open)

    async def cleanup(self) -> None:
        self.abort_current_query = True
        if self._exit_stack is not None:
            await self._exit_stack.aclose()
            self._exit_stack = None
        self.sessions = {}
        self.connection_errors = {}
        self.tool_manager.set_available_tools([])


McpBridgeClient = _RepoMcpBridgeClient


async def _mcp_bridge_process_query_server_side(
    client: Any,
    *,
    prompt: str,
    model: str,
    emit: Callable[..., None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
    on_response_open: Callable[[Any], None] | None = None,
) -> str:
    process_query = None
    if emit is not None:
        process_with_events = getattr(client, 'process_query_with_events', None)
        if callable(process_with_events):
            process_query = lambda current_prompt: process_with_events(
                current_prompt,
                emit=emit,
                cancel_check=cancel_check,
                on_response_open=on_response_open,
            )
    if process_query is None:
        process_query = client.process_query

    try:
        return await process_query(prompt)
    except ProviderAdapterError as exc:
        repair = _build_prompt_repair_decision(prompt=prompt, exc=exc)
        if not repair.retryable:
            raise
        if emit is not None and repair.status_message:
            emit('status', message=repair.status_message)
        return await process_query(repair.retry_prompt or prompt)


def _structured_text_payload(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


def _configure_mcp_bridge_client_for_web(client: Any, *, hil_enabled: bool) -> None:
    hil_manager = getattr(client, 'hil_manager', None)
    if hil_manager is None:
        return
    set_enabled = getattr(hil_manager, 'set_enabled', None)
    if callable(set_enabled):
        set_enabled(hil_enabled)
    set_session_auto_execute = getattr(hil_manager, 'set_session_auto_execute', None)
    if callable(set_session_auto_execute):
        set_session_auto_execute(not hil_enabled)


async def _mcp_bridge_connect(payload: dict[str, Any], *, model: str, host: str) -> tuple[Any, dict[str, Any]]:
    bridge_cfg = _normalize_mcp_bridge_payload(payload)
    client = McpBridgeClient(model=model, host=host)
    _configure_mcp_bridge_client_for_web(client, hil_enabled=bridge_cfg['hil_enabled'])
    setattr(client, 'timeout_seconds', _normalize_bridge_timeout_seconds(payload.get('timeout_seconds')))
    server_paths = [bridge_cfg['mcp_server_path']] if bridge_cfg['mcp_server_path'] else None
    server_urls = [bridge_cfg['mcp_server_url']] if bridge_cfg['mcp_server_url'] else None
    config_path = bridge_cfg['servers_json_path'] or None
    await client.connect_to_servers(
        server_paths=server_paths,
        server_urls=server_urls,
        config_path=config_path,
        auto_discovery=bridge_cfg['auto_discovery'],
    )
    if not client.sessions:
        await client.cleanup()
        connection_errors = getattr(client, 'connection_errors', None)
        details = {'connection_errors': connection_errors} if isinstance(connection_errors, dict) and connection_errors else None
        raise ProviderAdapterError('MCP bridge could not connect to any MCP servers.', status_code=502, details=details)
    return client, bridge_cfg


def _apply_mcp_bridge_tool_selection(client: Any, enabled_tools: list[str]) -> dict[str, bool]:
    enabled_map = client.tool_manager.get_enabled_tools().copy()
    selected = {tool_name for tool_name in enabled_tools if _is_user_exposed_mcp_bridge_tool(tool_name)}
    for tool_name in list(enabled_map.keys()):
        if not _is_user_exposed_mcp_bridge_tool(tool_name):
            new_state = False
        elif not selected:
            new_state = True
        else:
            new_state = tool_name in selected
        client.tool_manager.set_tool_status(tool_name, new_state)
        enabled_map[tool_name] = new_state
    return enabled_map


async def _mcp_bridge_discover(payload: dict[str, Any], *, model: str, host: str) -> dict[str, Any]:
    client, bridge_cfg = await _mcp_bridge_connect(payload, model=model, host=host)
    try:
        enabled_map = _apply_mcp_bridge_tool_selection(client, bridge_cfg['enabled_tools'])
        tools = [
            _mcp_bridge_tool_payload(tool, enabled_map)
            for tool in client.tool_manager.get_available_tools()
            if _is_user_exposed_mcp_bridge_tool(str(getattr(tool, 'name', '') or '').strip())
        ]
        return {
            'bridge_mode': bridge_cfg['bridge_mode'],
            'mcp_server_path': bridge_cfg['mcp_server_path'],
            'mcp_server_url': bridge_cfg['mcp_server_url'],
            'servers_json_path': bridge_cfg['servers_json_path'],
            'auto_discovery': bridge_cfg['auto_discovery'],
            'hil_enabled': bridge_cfg['hil_enabled'],
            'tools': tools,
            'enabled_tools': [tool['name'] for tool in tools if tool['enabled']],
        }
    finally:
        await client.cleanup()


async def _mcp_bridge_call_tool(client: Any, qualified_tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    session_names = list(client.sessions.keys()) if isinstance(getattr(client, 'sessions', None), dict) else []
    qualified_tool_name = _normalize_mcp_bridge_tool_name(qualified_tool_name, known_server_names=session_names)
    server_name, tool_name = qualified_tool_name.split('.', 1) if '.' in qualified_tool_name else ('', qualified_tool_name)
    if not server_name or server_name not in client.sessions:
        raise ProviderAdapterError(f'Unknown MCP server for tool {qualified_tool_name!r}.', status_code=500)
    try:
        result = await client.sessions[server_name]['session'].call_tool(tool_name, arguments)
    except ProviderAdapterError:
        raise
    except Exception as exc:
        raise ProviderAdapterError(
            _describe_mcp_bridge_base_exception(exc, fallback=f'Tool {qualified_tool_name} failed.'),
            status_code=502,
            details={'tool_name': qualified_tool_name},
        ) from exc

    if getattr(result, 'isError', False):
        raw_text = _extract_tool_text(result)
        parsed_error = _extract_json_candidate(raw_text)
        if isinstance(parsed_error, dict):
            message = str(parsed_error.get('error') or parsed_error.get('message') or '').strip()
            details = parsed_error if parsed_error else {'tool_response': raw_text[:4000]}
        else:
            message = str(raw_text or '').strip()
            details = {'tool_response': raw_text[:4000]}
        raise ProviderAdapterError(
            message or f'Tool {qualified_tool_name} failed.',
            status_code=502,
            details=details,
        )

    parsed = getattr(result, 'structuredContent', None)
    if not isinstance(parsed, dict):
        raw_text = _extract_tool_text(result)
        parsed = _extract_json_candidate(raw_text)
    else:
        raw_text = _extract_tool_text(result)
    if not isinstance(parsed, dict):
        raise ProviderAdapterError(
            f'Tool {qualified_tool_name} did not return parseable JSON.',
            status_code=502,
            details={'tool_response': raw_text[:4000]},
        )
    return parsed


def _find_required_mcp_bridge_tool(available_tools: list[str], suffix: str) -> str:
    for tool_name in available_tools:
        if tool_name.endswith(suffix):
            return tool_name
    raise ProviderAdapterError(f'Required MCP tool {suffix!r} is not available.', status_code=500)


def _build_mcp_bridge_goal_prompt(*, draft_id: str, enabled_tools: list[str], scenario_name: str, user_prompt: str) -> str:
    return '\n'.join([
        'Use MCP tools to rebuild the current scenario draft from scratch. Do not create a second draft.',
        f'Target draft_id: {draft_id}',
        f'Scenario name: {scenario_name}',
        f'Enabled tools: {", ".join(enabled_tools) if enabled_tools else "(none)"}',
        'You must work only through enabled tools.',
        'Keep all section payloads backend-compatible.',
        'Treat the existing draft as a clean replacement target, not as content to preserve.',
        'If scenario.get_authoring_schema is enabled, call it before authoring so you discover concrete section values and defaults instead of guessing labels.',
        'When schema fields expose ui_selected_values, use only those selected labels for section items; do not invent free-text dropdown values.',
        'Do not rename the scenario; its current name is fixed and must be preserved.',
        'For explicit host counts, write Node Information items with v_metric="Count" and v_count.',
        'When the user asks for Docker nodes, create Node Information rows with selected="Docker" and an explicit count.',
        'Node Information is only for host nodes such as Server, Workstation, PC, and Docker. Never use it to satisfy router counts.',
        'For explicit router counts, write Routing items with v_metric="Count" and v_count. Router count means how many router nodes exist.',
        'For router-to-router or router-to-host ratio/connectivity requests, use Routing r2r_* and r2s_* fields. Those fields describe connectivity density, not router count. There is no r2h field; router-to-host requests map to r2s_* because hosts attach to routed segments.',
        'Never place Router, Routing, gateway, or protocol rows under Node Information; router counts always belong in Routing.',
        'Interpret Routing fields precisely: v_count is router quantity, r2r_edges is router-to-router links per router, and r2s_edges with r2s_hosts_min or r2s_hosts_max describes router-to-segment or routed-host attachment density.',
        *_build_count_intent_guidance(user_prompt),
        'If the user asks for routers without naming a protocol, use scenario.add_routing_item with protocol="OSPFv2" and the requested count when that tool is enabled; otherwise replace only the Routing section with a Count row selected="OSPFv2".',
        'When dedicated tools are available, prefer scenario.add_node_role_item for host or Docker counts, scenario.add_routing_item for explicit router/protocol rows and routing edge hints, scenario.add_service_item for Services rows, scenario.add_traffic_item for TCP or UDP traffic, and scenario.add_segmentation_item for Segmentation rows.',
        'For vulnerabilities, prefer scenario.search_vulnerability_catalog first, then call scenario.add_vulnerability_item with explicit v_name and v_path from the chosen result. Do not pass factor. If the user asks for multiple different vulnerabilities, make separate add_vulnerability_item calls with v_count=1 for each chosen vulnerability.',
        'For broad vulnerability categories such as web-related vulnerabilities, do not invent a Specific vulnerability name. Prefer a Type/Vector row such as selected="Type/Vector", v_type="docker-compose", v_vector="web", or search the vulnerability catalog first and choose concrete results.',
        'For services and segmentation, prefer schema-discovered values and the dedicated mutation tools; otherwise use replace_section with backend-compatible items.',
        'For traffic requests, ensure each Traffic row uses selected="TCP" or "UDP", a concrete content_type, and one exact pattern from: continuous, periodic, burst, poisson, or ramp. For varied traffic profiles, create multiple Traffic rows rather than vague free-text profile labels. Each Traffic row must also use either v_metric="Count" with v_count or a positive factor so preview flows materialize.',
        'Only use free-text fields where the schema explicitly expects them, such as notes or vulnerability identifiers like v_name/v_path.',
        'Preview the draft before you finish if preview_draft is enabled.',
        'Do not save XML unless save_xml is explicitly enabled and necessary.',
        f'User goal: {user_prompt}',
        'Respond with a short plain summary of what you changed after using tools.',
    ])


async def _mcp_bridge_generate(payload: dict[str, Any], *, current_scenario: dict[str, Any], user_prompt: str, model: str, host: str) -> dict[str, Any]:
    client, bridge_cfg = await _mcp_bridge_connect(payload, model=model, host=host)
    try:
        seed_scenario = _build_ai_seed_scenario(current_scenario)
        enabled_map = _apply_mcp_bridge_tool_selection(client, bridge_cfg['enabled_tools'])
        available_tools = [str(getattr(tool, 'name', '') or '').strip() for tool in client.tool_manager.get_available_tools()]
        enabled_tools = [name for name in available_tools if enabled_map.get(name, True) and _is_user_exposed_mcp_bridge_tool(name)]

        create_tool = _find_required_mcp_bridge_tool(available_tools, 'scenario.create_draft')
        get_tool = _find_required_mcp_bridge_tool(available_tools, 'scenario.get_draft')
        preview_tool = _find_required_mcp_bridge_tool(available_tools, 'scenario.preview_draft')

        draft_id = ''
        execution_result: dict[str, Any] | None = None
        for attempt in range(2):
            created = await _mcp_bridge_call_tool(client, create_tool, {
                'name': current_scenario.get('name'),
                'scenario': seed_scenario,
                'core': payload.get('core') if isinstance(payload.get('core'), dict) else {},
            })
            draft = created.get('draft') if isinstance(created.get('draft'), dict) else {}
            draft_id = str(draft.get('draft_id') or '').strip()
            if not draft_id:
                raise ProviderAdapterError('MCP draft creation did not return a draft_id.', status_code=500)

            prompt = _build_mcp_bridge_goal_prompt(
                draft_id=draft_id,
                enabled_tools=enabled_tools,
                scenario_name=str(current_scenario.get('name') or '').strip() or 'Scenario',
                user_prompt=user_prompt,
            )
            try:
                execution_result = await _execute_mcp_bridge_prompt_with_preview_retry(
                    client,
                    draft_id=draft_id,
                    prompt=prompt,
                    user_prompt=user_prompt,
                    model=model,
                    get_tool=get_tool,
                    preview_tool=preview_tool,
                )
                break
            except ProviderAdapterError as exc:
                repair = _build_generation_repair_decision(exc)
                if attempt == 0 and repair.recreate_draft:
                    continue
                raise
            except BaseException as exc:
                raise ProviderAdapterError(
                    _describe_mcp_bridge_base_exception(
                        exc,
                        fallback='MCP bridge generation failed while executing model-requested tool calls.',
                    ),
                    status_code=502,
                ) from exc
        if not isinstance(execution_result, dict):
            raise ProviderAdapterError('MCP bridge generation failed to produce a preview result.', status_code=502)
        draft_payload = execution_result.get('draft_payload') if isinstance(execution_result.get('draft_payload'), dict) else {}
        previewed = execution_result.get('previewed') if isinstance(execution_result.get('previewed'), dict) else {}
        scenario_payload = draft_payload.get('scenario') if isinstance(draft_payload.get('scenario'), dict) else deepcopy(current_scenario)
        scenario_payload = _canonicalize_generated_vulnerabilities_or_raise(scenario_payload)
        return {
            'provider': 'ollama',
            'bridge_mode': bridge_cfg['bridge_mode'],
            'base_url': host,
            'model': model,
            'prompt_used': execution_result.get('prompt_used') or prompt,
            'provider_response': execution_result.get('provider_response') or '',
            'generated_scenario': scenario_payload,
            'preview': previewed.get('preview') if isinstance(previewed.get('preview'), dict) else {},
            'plan': previewed.get('plan') if isinstance(previewed.get('plan'), dict) else {},
            'flow_meta': previewed.get('flow_meta') if isinstance(previewed.get('flow_meta'), dict) else {},
            'breakdowns': None,
            'count_intent_mismatch': execution_result.get('count_intent_mismatch'),
            'count_intent_retry_used': bool(execution_result.get('count_intent_retry_used')),
            'bridge_tools': [
                _mcp_bridge_tool_payload(tool, enabled_map)
                for tool in client.tool_manager.get_available_tools()
                if _is_user_exposed_mcp_bridge_tool(str(getattr(tool, 'name', '') or '').strip())
            ],
            'enabled_tools': enabled_tools,
            'draft_id': draft_id,
        }
    finally:
        await client.cleanup()


async def _mcp_bridge_generate_with_events(
    payload: dict[str, Any],
    *,
    current_scenario: dict[str, Any],
    user_prompt: str,
    model: str,
    host: str,
    emit: Callable[..., None],
    cancel_check: Callable[[], bool] | None = None,
    on_client_ready: Callable[[Any], None] | None = None,
    on_response_open: Callable[[Any], None] | None = None,
) -> dict[str, Any]:
    client, bridge_cfg = await _mcp_bridge_connect(payload, model=model, host=host)
    seed_scenario = _build_ai_seed_scenario(current_scenario)
    if callable(on_client_ready):
        on_client_ready(client)

    try:
        enabled_map = _apply_mcp_bridge_tool_selection(client, bridge_cfg['enabled_tools'])
        available_tools = [str(getattr(tool, 'name', '') or '').strip() for tool in client.tool_manager.get_available_tools()]
        enabled_tools = [name for name in available_tools if enabled_map.get(name, True) and _is_user_exposed_mcp_bridge_tool(name)]

        create_tool = _find_required_mcp_bridge_tool(available_tools, 'scenario.create_draft')
        get_tool = _find_required_mcp_bridge_tool(available_tools, 'scenario.get_draft')
        preview_tool = _find_required_mcp_bridge_tool(available_tools, 'scenario.preview_draft')

        draft_id = ''
        execution_result: dict[str, Any] | None = None
        for attempt in range(2):
            emit('status', message='Creating scenario draft...')
            if cancel_check and cancel_check():
                raise ProviderAdapterError('Generation cancelled by user.', status_code=499)
            created = await _mcp_bridge_call_tool(client, create_tool, {
                'name': current_scenario.get('name'),
                'scenario': seed_scenario,
                'core': payload.get('core') if isinstance(payload.get('core'), dict) else {},
            })
            draft = created.get('draft') if isinstance(created.get('draft'), dict) else {}
            draft_id = str(draft.get('draft_id') or '').strip()
            if not draft_id:
                raise ProviderAdapterError('MCP draft creation did not return a draft_id.', status_code=500)

            prompt = _build_mcp_bridge_goal_prompt(
                draft_id=draft_id,
                enabled_tools=enabled_tools,
                scenario_name=str(current_scenario.get('name') or '').strip() or 'Scenario',
                user_prompt=user_prompt,
            )
            emit('status', message='Sending prompt to Ollama...')
            if cancel_check and cancel_check():
                raise ProviderAdapterError('Generation cancelled by user.', status_code=499)
            try:
                execution_result = await _execute_mcp_bridge_prompt_with_preview_retry(
                    client,
                    draft_id=draft_id,
                    prompt=prompt,
                    user_prompt=user_prompt,
                    model=model,
                    get_tool=get_tool,
                    preview_tool=preview_tool,
                    emit=emit,
                    cancel_check=cancel_check,
                    on_response_open=on_response_open,
                )
                break
            except ProviderAdapterError as exc:
                repair = _build_generation_repair_decision(exc)
                if attempt == 0 and repair.recreate_draft:
                    if repair.status_message:
                        emit('status', message=repair.status_message)
                    continue
                raise
            except BaseException as exc:
                raise ProviderAdapterError(
                    _describe_mcp_bridge_base_exception(
                        exc,
                        fallback='MCP bridge generation failed while executing model-requested tool calls.',
                    ),
                    status_code=502,
                ) from exc
        if not isinstance(execution_result, dict):
            raise ProviderAdapterError('MCP bridge generation failed to produce a preview result.', status_code=502)
        if cancel_check and cancel_check():
            raise ProviderAdapterError('Generation cancelled by user.', status_code=499)

        emit('status', message='Refreshing draft after tool calls...')
        draft_payload = execution_result.get('draft_payload') if isinstance(execution_result.get('draft_payload'), dict) else {}
        previewed = execution_result.get('previewed') if isinstance(execution_result.get('previewed'), dict) else {}
        scenario_payload = draft_payload.get('scenario') if isinstance(draft_payload.get('scenario'), dict) else deepcopy(current_scenario)
        scenario_payload = _canonicalize_generated_vulnerabilities_or_raise(scenario_payload)
        return {
            'provider': 'ollama',
            'bridge_mode': bridge_cfg['bridge_mode'],
            'base_url': host,
            'model': model,
            'prompt_used': execution_result.get('prompt_used') or prompt,
            'provider_response': execution_result.get('provider_response') or '',
            'generated_scenario': scenario_payload,
            'preview': previewed.get('preview') if isinstance(previewed.get('preview'), dict) else {},
            'plan': previewed.get('plan') if isinstance(previewed.get('plan'), dict) else {},
            'flow_meta': previewed.get('flow_meta') if isinstance(previewed.get('flow_meta'), dict) else {},
            'breakdowns': None,
            'count_intent_mismatch': execution_result.get('count_intent_mismatch'),
            'count_intent_retry_used': bool(execution_result.get('count_intent_retry_used')),
            'bridge_tools': [
                _mcp_bridge_tool_payload(tool, enabled_map)
                for tool in client.tool_manager.get_available_tools()
                if _is_user_exposed_mcp_bridge_tool(str(getattr(tool, 'name', '') or '').strip())
            ],
            'enabled_tools': enabled_tools,
            'draft_id': draft_id,
        }
    finally:
        await client.cleanup()


def _build_stream_success_payload(
    app: Any,
    payload: dict[str, Any],
    *,
    scenarios: list[Any],
    scenario_index: int,
    current_scenario: dict[str, Any],
    generation_result: dict[str, Any],
) -> dict[str, Any]:
    bridge_mode = str(generation_result.get('bridge_mode') or '').strip().lower()
    if _is_mcp_python_sdk_bridge_mode(bridge_mode):
        generated_scenario = _restore_preserved_scenario_metadata(
            current_scenario,
            generation_result.get('generated_scenario') or current_scenario,
        )
        generated_scenario = app_backend._concretize_preview_placeholders(generated_scenario, seed=payload.get('seed'))
        next_scenarios = deepcopy(scenarios)
        next_scenarios[scenario_index] = generated_scenario
        return {
            'success': True,
            'provider': generation_result.get('provider') or 'ollama',
            'bridge_mode': _normalize_ai_bridge_mode(generation_result.get('bridge_mode')),
            'base_url': generation_result.get('base_url') or '',
            'model': generation_result.get('model') or '',
            'prompt_used': generation_result.get('prompt_used') or '',
            'provider_response': generation_result.get('provider_response') or '',
            'count_intent_mismatch': generation_result.get('count_intent_mismatch'),
            'count_intent_retry_used': bool(generation_result.get('count_intent_retry_used')),
            'generated_scenario': generated_scenario,
            'generated_scenarios': next_scenarios,
            'preview': generation_result.get('preview') or {},
            'flow_meta': generation_result.get('flow_meta') or {},
            'plan': generation_result.get('plan') or {},
            'breakdowns': generation_result.get('breakdowns'),
            'bridge_tools': generation_result.get('bridge_tools') or [],
            'enabled_tools': generation_result.get('enabled_tools') or [],
            'draft_id': generation_result.get('draft_id') or '',
            'checked_at': _utc_timestamp(),
        }

    provider = generation_result.get('provider') or str(payload.get('provider') or 'ollama').strip().lower()
    base_url = generation_result.get('base_url') or ''
    model = generation_result.get('model') or str(payload.get('model') or '').strip()
    prompt = generation_result.get('prompt_used') or ''
    raw_generation = str(generation_result.get('provider_response') or '').strip()
    seed_scenario = _build_ai_seed_scenario(current_scenario)
    merged_scenario = _normalize_generated_scenario(seed_scenario, generation_result.get('parsed_generation') or {})
    merged_scenario = _restore_preserved_scenario_metadata(current_scenario, merged_scenario)
    merged_scenario = _canonicalize_generated_vulnerabilities_or_raise(merged_scenario)
    merged_scenario = app_backend._concretize_preview_placeholders(merged_scenario, seed=payload.get('seed'))
    next_scenarios = deepcopy(scenarios)
    next_scenarios[scenario_index] = merged_scenario
    preview_body = {
        'scenarios': next_scenarios,
        'core': payload.get('core') if isinstance(payload.get('core'), dict) else None,
        'scenario': merged_scenario.get('name') or current_scenario.get('name') or None,
    }
    if payload.get('seed') is not None:
        preview_body['seed'] = payload.get('seed')

    with app.test_request_context('/api/plan/preview_full', method='POST', json=preview_body):
        preview_view = app.view_functions.get('api_plan_preview_full')
        if preview_view is None:
            raise ProviderAdapterError('Preview route is unavailable.', status_code=500)
        preview_resp = app.make_response(preview_view())
        preview_json = preview_resp.get_json(silent=True) or {}

    if not preview_resp.status_code or preview_resp.status_code >= 400 or preview_json.get('ok') is False:
        raise ProviderAdapterError(
            preview_json.get('error') or f'Preview failed (HTTP {preview_resp.status_code}).',
            status_code=400,
            details={
                'generated_scenario': merged_scenario,
                'provider_response': raw_generation[:4000],
            },
        )

    return {
        'success': True,
        'provider': provider,
        'base_url': base_url,
        'model': model,
        'prompt_used': prompt,
        'provider_response': raw_generation,
        'provider_attempts': generation_result.get('provider_attempts') or [],
        'generated_scenario': merged_scenario,
        'generated_scenarios': next_scenarios,
        'preview': preview_json.get('full_preview') or {},
        'flow_meta': preview_json.get('flow_meta') or {},
        'plan': preview_json.get('plan') or {},
        'breakdowns': preview_json.get('breakdowns'),
        'checked_at': _utc_timestamp(),
    }


def _generate_ollama_streaming_result(
    payload: dict[str, Any],
    *,
    current_scenario: dict[str, Any],
    user_prompt: str,
    emit: Callable[..., None],
    cancellation_check: Callable[[], bool] | None = None,
    on_response_open: Callable[[Any], None] | None = None,
) -> dict[str, Any]:
    adapter = OllamaProviderAdapter()
    model = str(payload.get('model') or '').strip()
    if not model:
        raise ProviderAdapterError('model is required.')

    try:
        base_url = _normalize_base_url(payload.get('base_url'))
    except ValueError as exc:
        raise ProviderAdapterError(str(exc)) from exc

    timeout_raw = payload.get('timeout_seconds')
    try:
        timeout_seconds = float(timeout_raw) if timeout_raw is not None else 90.0
    except (TypeError, ValueError):
        timeout_seconds = 90.0
    timeout_seconds = min(max(timeout_seconds, 5.0), 240.0)

    def _generate_once_streaming(*, prompt: str) -> tuple[str, dict[str, Any], str]:
        format_mode: dict[str, Any] | str = _scenario_generation_schema()

        def _request_stream(response_format: dict[str, Any] | str) -> str:
            body = adapter._build_generate_payload(model=model, prompt=prompt, response_format=response_format)
            body['stream'] = True
            raw_parts: list[str] = []
            for chunk in _stream_json_lines(
                f'{base_url}/api/generate',
                body,
                timeout=timeout_seconds,
                cancellation_check=cancellation_check,
                on_open=on_response_open,
            ):
                if cancellation_check and cancellation_check():
                    raise ProviderAdapterError('Generation cancelled by user.', status_code=499)
                delta = str(chunk.get('response') or '')
                if delta:
                    raw_parts.append(delta)
                    emit('llm_delta', text=delta)
            return ''.join(raw_parts).strip()

        try:
            raw_generation = _request_stream(format_mode)
        except HTTPError as exc:
            detail = ''
            try:
                detail = exc.read().decode('utf-8').strip()
            except Exception:
                detail = ''
            detail_lower = detail.lower()
            if exc.code >= 500 and 'required for format' in detail_lower:
                emit('status', message='Model rejected schema mode. Retrying with plain JSON…')
                format_mode = 'json'
                raw_generation = _request_stream(format_mode)
            else:
                raise

        parsed_generation = _extract_json_candidate(raw_generation)
        return raw_generation, parsed_generation or {}, ('schema' if format_mode != 'json' else 'json')

    prompt = _build_ollama_prompt(current_scenario, user_prompt)
    provider_attempts: list[dict[str, Any]] = []
    emit('status', message='Sending prompt to Ollama…')
    try:
        raw_generation, parsed_generation, format_mode = _generate_once_streaming(prompt=prompt)
        provider_attempts.append({'attempt': 'initial', 'format_mode': format_mode, 'response': raw_generation})
        if not isinstance(parsed_generation, dict) or not parsed_generation:
            if cancellation_check and cancellation_check():
                raise ProviderAdapterError('Generation cancelled by user.', status_code=499)
            emit('status', message='Initial draft was not valid JSON. Requesting a repair pass…')
            repair_prompt = _build_ollama_repair_prompt(current_scenario, user_prompt, raw_generation)
            raw_generation, parsed_generation, format_mode = _generate_once_streaming(prompt=repair_prompt)
            provider_attempts.append({'attempt': 'repair', 'format_mode': format_mode, 'response': raw_generation})
            prompt = repair_prompt
        if not isinstance(parsed_generation, dict) or not parsed_generation:
            raise ProviderAdapterError(
                'Ollama did not return valid JSON for scenario generation.',
                status_code=502,
                details={
                    'provider_response': provider_attempts[-1]['response'][:4000] if provider_attempts else '',
                    'provider_attempts': provider_attempts,
                },
            )
        return {
            'provider': 'ollama',
            'base_url': base_url,
            'model': model,
            'prompt_used': prompt,
            'provider_response': provider_attempts[-1]['response'],
            'provider_attempts': provider_attempts,
            'parsed_generation': parsed_generation,
        }
    except ProviderAdapterError:
        raise
    except HTTPError as exc:
        detail = ''
        try:
            detail = exc.read().decode('utf-8').strip()
        except Exception:
            detail = ''
        message = f'Ollama returned HTTP {exc.code}.'
        if detail:
            message = f'{message} {detail[:240]}'
        raise ProviderAdapterError(message, status_code=502) from exc
    except URLError as exc:
        reason = getattr(exc, 'reason', exc)
        raise ProviderAdapterError(f'Could not reach Ollama at {base_url}: {reason}', status_code=502) from exc


class OllamaProviderAdapter(ProviderAdapter):
    capability = ProviderCapability(
        provider='ollama',
        label='Ollama',
        enabled=True,
        mode='offline-first',
        description='Local or LAN-hosted Ollama models for offline-capable scenario authoring.',
        default_base_url='http://127.0.0.1:11434',
        requires_model=True,
        requires_api_key=False,
    )

    def validate(self, payload: dict[str, Any], *, log: Any = None) -> dict[str, Any]:
        model = str(payload.get('model') or '').strip()
        timeout_raw = payload.get('timeout_seconds')
        try:
            timeout_seconds = float(timeout_raw) if timeout_raw is not None else 5.0
        except (TypeError, ValueError):
            timeout_seconds = 5.0
        timeout_seconds = min(max(timeout_seconds, 1.0), 15.0)

        try:
            base_url = _normalize_base_url(payload.get('base_url'))
        except ValueError as exc:
            raise ProviderAdapterError(str(exc), details={'checked_at': _utc_timestamp()}) from exc

        tags_url = f'{base_url}/api/tags'
        try:
            data = _fetch_json(tags_url, timeout=timeout_seconds)
            raw_models = data.get('models') if isinstance(data, dict) else []
            models = []
            if isinstance(raw_models, list):
                for entry in raw_models:
                    if isinstance(entry, dict):
                        name = str(entry.get('name') or '').strip()
                    else:
                        name = str(entry or '').strip()
                    if name:
                        models.append(name)
            model_found = (not model) or (model in models)
            message = f'Reached Ollama at {base_url}.'
            if model and not model_found:
                message = f'Reached Ollama at {base_url}, but model {model!r} was not found.'
            return {
                'success': True,
                'provider': 'ollama',
                'base_url': base_url,
                'models': models,
                'model': model,
                'model_found': model_found,
                'message': message,
                'checked_at': _utc_timestamp(),
            }
        except HTTPError as exc:
            detail = ''
            try:
                detail = exc.read().decode('utf-8').strip()
            except Exception:
                detail = ''
            message = f'Ollama returned HTTP {exc.code}.'
            if detail:
                message = f'{message} {detail[:240]}'
            raise ProviderAdapterError(message, status_code=502, details={'checked_at': _utc_timestamp()}) from exc
        except URLError as exc:
            reason = getattr(exc, 'reason', exc)
            raise ProviderAdapterError(
                f'Could not reach Ollama at {base_url}: {reason}',
                status_code=502,
                details={'checked_at': _utc_timestamp()},
            ) from exc
        except Exception as exc:  # pragma: no cover
            try:
                if log is not None:
                    log.exception('[ai-provider] validation failed: %s', exc)
            except Exception:
                pass
            raise ProviderAdapterError(
                'Unexpected validation failure while contacting the provider.',
                status_code=500,
                details={'checked_at': _utc_timestamp()},
            ) from exc

    def _build_generate_payload(self, *, model: str, prompt: str, response_format: dict[str, Any] | str) -> dict[str, Any]:
        return {
            'model': model,
            'prompt': prompt,
            'stream': False,
            'format': response_format,
            'options': {
                'temperature': 0.1,
            },
        }

    def _generate_once(self, *, base_url: str, model: str, prompt: str, timeout_seconds: float) -> tuple[str, dict[str, Any], str]:
        format_mode: dict[str, Any] | str = _scenario_generation_schema()
        try:
            response = _post_json(
                f'{base_url}/api/generate',
                self._build_generate_payload(model=model, prompt=prompt, response_format=format_mode),
                timeout=timeout_seconds,
            )
        except HTTPError as exc:
            detail = ''
            try:
                detail = exc.read().decode('utf-8').strip()
            except Exception:
                detail = ''
            detail_lower = detail.lower()
            if exc.code >= 500 and 'required for format' in detail_lower:
                format_mode = 'json'
                response = _post_json(
                    f'{base_url}/api/generate',
                    self._build_generate_payload(model=model, prompt=prompt, response_format=format_mode),
                    timeout=timeout_seconds,
                )
            else:
                raise
        raw_generation = str(response.get('response') or '').strip()
        parsed_generation = _extract_json_candidate(raw_generation)
        return raw_generation, parsed_generation or {}, ('schema' if format_mode != 'json' else 'json')

    def generate(self, payload: dict[str, Any], *, current_scenario: dict[str, Any], user_prompt: str, log: Any = None) -> dict[str, Any]:
        model = str(payload.get('model') or '').strip()
        if not model:
            raise ProviderAdapterError('model is required.')

        try:
            base_url = _normalize_base_url(payload.get('base_url'))
        except ValueError as exc:
            raise ProviderAdapterError(str(exc)) from exc

        timeout_raw = payload.get('timeout_seconds')
        try:
            timeout_seconds = float(timeout_raw) if timeout_raw is not None else 90.0
        except (TypeError, ValueError):
            timeout_seconds = 90.0
        timeout_seconds = min(max(timeout_seconds, 5.0), 240.0)

        prompt = _build_ollama_prompt(current_scenario, user_prompt)
        provider_attempts: list[dict[str, Any]] = []
        try:
            raw_generation, parsed_generation, format_mode = self._generate_once(
                base_url=base_url,
                model=model,
                prompt=prompt,
                timeout_seconds=timeout_seconds,
            )
            provider_attempts.append({'attempt': 'initial', 'format_mode': format_mode, 'response': raw_generation})
            if not isinstance(parsed_generation, dict) or not parsed_generation:
                repair_prompt = _build_ollama_repair_prompt(current_scenario, user_prompt, raw_generation)
                raw_generation, parsed_generation, format_mode = self._generate_once(
                    base_url=base_url,
                    model=model,
                    prompt=repair_prompt,
                    timeout_seconds=timeout_seconds,
                )
                provider_attempts.append({'attempt': 'repair', 'format_mode': format_mode, 'response': raw_generation})
                prompt = repair_prompt
            if not isinstance(parsed_generation, dict) or not parsed_generation:
                raise ProviderAdapterError(
                    'Ollama did not return valid JSON for scenario generation.',
                    status_code=502,
                    details={
                        'provider_response': provider_attempts[-1]['response'][:4000] if provider_attempts else '',
                        'provider_attempts': provider_attempts,
                    },
                )
            return {
                'provider': 'ollama',
                'base_url': base_url,
                'model': model,
                'prompt_used': prompt,
                'provider_response': provider_attempts[-1]['response'],
                'provider_attempts': provider_attempts,
                'parsed_generation': parsed_generation,
            }
        except ProviderAdapterError:
            raise
        except HTTPError as exc:
            detail = ''
            try:
                detail = exc.read().decode('utf-8').strip()
            except Exception:
                detail = ''
            message = f'Ollama returned HTTP {exc.code}.'
            if detail:
                message = f'{message} {detail[:240]}'
            raise ProviderAdapterError(message, status_code=502) from exc
        except URLError as exc:
            reason = getattr(exc, 'reason', exc)
            raise ProviderAdapterError(f'Could not reach Ollama at {base_url}: {reason}', status_code=502) from exc
        except Exception as exc:  # pragma: no cover
            try:
                if log is not None:
                    log.exception('[ai-provider] generation failed: %s', exc)
            except Exception:
                pass
            raise ProviderAdapterError(
                'Unexpected generation failure while contacting Ollama.',
                status_code=500,
            ) from exc


_PROVIDER_REGISTRY: dict[str, ProviderAdapter] = {
    'ollama': OllamaProviderAdapter(),
    'openai': UnsupportedProviderAdapter(
        ProviderCapability(
            provider='openai',
            label='OpenAI',
            enabled=False,
            mode='remote',
            description='Planned adapter for hosted OpenAI chat or responses APIs.',
            requires_model=True,
            requires_api_key=True,
        )
    ),
    'anthropic': UnsupportedProviderAdapter(
        ProviderCapability(
            provider='anthropic',
            label='Claude / Anthropic',
            enabled=False,
            mode='remote',
            description='Planned adapter for hosted Anthropic messages APIs.',
            requires_model=True,
            requires_api_key=True,
        )
    ),
}


def _get_provider_adapter(provider: Any) -> ProviderAdapter:
    provider_key = str(provider or 'ollama').strip().lower()
    adapter = _PROVIDER_REGISTRY.get(provider_key)
    if adapter is None:
        raise ProviderAdapterError(f'Unknown provider {provider_key!r}.', status_code=400)
    return adapter


def register(app, *, logger=None) -> None:
    log = logger or getattr(app, 'logger', None)

    @app.route('/api/ai/download_transcript', methods=['POST'])
    def api_ai_download_transcript():
        payload = request.get_json(silent=True) if request.is_json else None
        transcript = ''
        filename = ''
        if isinstance(payload, dict):
            transcript = str(payload.get('transcript') or '')
            filename = str(payload.get('filename') or '')
        else:
            transcript = str(request.form.get('transcript') or '')
            filename = str(request.form.get('filename') or '')

        if not transcript.strip():
            return jsonify({'success': False, 'error': 'transcript is required.'}), 400

        safe_name = re.sub(r'[^a-z0-9]+', '-', filename.strip().lower()).strip('-') or 'ai-generator-transcript'
        response = Response(transcript, mimetype='text/plain; charset=utf-8')
        response.headers['Content-Disposition'] = f'attachment; filename="{safe_name}.txt"'
        response.headers['Cache-Control'] = 'no-store, max-age=0'
        return response

    @app.route('/api/ai/providers', methods=['GET'])
    def api_ai_provider_catalog():
        providers = [adapter.capability.to_dict() for _, adapter in sorted(_PROVIDER_REGISTRY.items())]
        return jsonify({
            'success': True,
            'providers': providers,
            'default_provider': 'ollama',
            'checked_at': _utc_timestamp(),
        })

    @app.route('/api/ai/provider/validate', methods=['POST'])
    def api_ai_provider_validate():
        payload = request.get_json(silent=True) or {}
        try:
            adapter = _get_provider_adapter(payload.get('provider'))
            response = adapter.validate(payload, log=log)
            skip_bridge = bool(payload.get('skip_bridge'))
            if _is_mcp_python_sdk_bridge_mode(payload.get('bridge_mode')) and not skip_bridge:
                bridge = asyncio.run(_mcp_bridge_discover(
                    payload,
                    model=str(response.get('model') or payload.get('model') or '').strip() or 'qwen2.5:7b',
                    host=str(response.get('base_url') or payload.get('base_url') or '').strip(),
                ))
                response['bridge'] = bridge
                response['tools'] = bridge.get('tools') or []
                response['enabled_tools'] = bridge.get('enabled_tools') or []
            return jsonify(response)
        except ProviderAdapterError as exc:
            return jsonify({
                'success': False,
                'error': exc.message,
                **exc.details,
            }), exc.status_code

    @app.route('/api/ai/generate_scenario_preview', methods=['POST'])
    def api_ai_generate_scenario_preview():
        payload = request.get_json(silent=True) or {}
        try:
            adapter = _get_provider_adapter(payload.get('provider'))
        except ProviderAdapterError as exc:
            return jsonify({'success': False, 'error': exc.message, **exc.details}), exc.status_code

        scenarios = payload.get('scenarios') if isinstance(payload.get('scenarios'), list) else None
        if not scenarios:
            return jsonify({'success': False, 'error': 'scenarios payload is required.'}), 400

        scenario_index = payload.get('scenario_index')
        try:
            scenario_index = int(scenario_index)
        except Exception:
            scenario_index = 0
        if scenario_index < 0 or scenario_index >= len(scenarios):
            return jsonify({'success': False, 'error': 'scenario_index is out of range.'}), 400

        current_scenario = scenarios[scenario_index] if isinstance(scenarios[scenario_index], dict) else None
        if not current_scenario:
            return jsonify({'success': False, 'error': 'Selected scenario payload is invalid.'}), 400

        user_prompt = str(payload.get('prompt') or '').strip()
        if not user_prompt:
            return jsonify({'success': False, 'error': 'prompt is required.'}), 400

        if _is_mcp_python_sdk_bridge_mode(payload.get('bridge_mode')):
            model = str(payload.get('model') or '').strip()
            if not model:
                return jsonify({'success': False, 'error': 'model is required.'}), 400
            try:
                base_url = _normalize_base_url(payload.get('base_url'))
            except ValueError as exc:
                return jsonify({'success': False, 'error': str(exc)}), 400
            try:
                generation_result = asyncio.run(_mcp_bridge_generate(
                    payload,
                    current_scenario=current_scenario,
                    user_prompt=user_prompt,
                    model=model,
                    host=base_url,
                ))
            except ProviderAdapterError as exc:
                return jsonify({'success': False, 'error': exc.message, **exc.details}), exc.status_code

            next_scenarios = deepcopy(scenarios)
            next_scenarios[scenario_index] = app_backend._concretize_preview_placeholders(_restore_preserved_scenario_metadata(
                current_scenario,
                generation_result.get('generated_scenario') or current_scenario,
            ), seed=payload.get('seed'))
            return jsonify({
                'success': True,
                'provider': generation_result.get('provider') or 'ollama',
                'bridge_mode': _normalize_ai_bridge_mode(generation_result.get('bridge_mode')),
                'base_url': generation_result.get('base_url') or base_url,
                'model': generation_result.get('model') or model,
                'prompt_used': generation_result.get('prompt_used') or '',
                'provider_response': generation_result.get('provider_response') or '',
                'count_intent_mismatch': generation_result.get('count_intent_mismatch'),
                'count_intent_retry_used': bool(generation_result.get('count_intent_retry_used')),
                'generated_scenario': next_scenarios[scenario_index],
                'generated_scenarios': next_scenarios,
                'preview': generation_result.get('preview') or {},
                'flow_meta': generation_result.get('flow_meta') or {},
                'plan': generation_result.get('plan') or {},
                'breakdowns': generation_result.get('breakdowns'),
                'bridge_tools': generation_result.get('bridge_tools') or [],
                'enabled_tools': generation_result.get('enabled_tools') or [],
                'draft_id': generation_result.get('draft_id') or '',
                'checked_at': _utc_timestamp(),
            })
        try:
            generation_result = adapter.generate(
                payload,
                current_scenario=current_scenario,
                user_prompt=user_prompt,
                log=log,
            )
        except ProviderAdapterError as exc:
            return jsonify({'success': False, 'error': exc.message, **exc.details}), exc.status_code

        try:
            provider = generation_result.get('provider') or str(payload.get('provider') or 'ollama').strip().lower()
            base_url = generation_result.get('base_url') or ''
            model = generation_result.get('model') or str(payload.get('model') or '').strip()
            prompt = generation_result.get('prompt_used') or ''
            raw_generation = str(generation_result.get('provider_response') or '').strip()
            seed_scenario = _build_ai_seed_scenario(current_scenario)
            merged_scenario = _normalize_generated_scenario(seed_scenario, generation_result.get('parsed_generation') or {})
            merged_scenario = _restore_preserved_scenario_metadata(current_scenario, merged_scenario)
            merged_scenario = _canonicalize_generated_vulnerabilities_or_raise(merged_scenario)
            merged_scenario = app_backend._concretize_preview_placeholders(merged_scenario, seed=payload.get('seed'))
            next_scenarios = deepcopy(scenarios)
            next_scenarios[scenario_index] = merged_scenario
            preview_body = {
                'scenarios': next_scenarios,
                'core': payload.get('core') if isinstance(payload.get('core'), dict) else None,
                'scenario': merged_scenario.get('name') or current_scenario.get('name') or None,
            }
            if payload.get('seed') is not None:
                preview_body['seed'] = payload.get('seed')

            with app.test_request_context('/api/plan/preview_full', method='POST', json=preview_body):
                preview_view = app.view_functions.get('api_plan_preview_full')
                if preview_view is None:
                    return jsonify({'success': False, 'error': 'Preview route is unavailable.'}), 500
                preview_resp = app.make_response(preview_view())
                preview_json = preview_resp.get_json(silent=True) or {}

            if not preview_resp.status_code or preview_resp.status_code >= 400 or preview_json.get('ok') is False:
                return jsonify({
                    'success': False,
                    'error': preview_json.get('error') or f'Preview failed (HTTP {preview_resp.status_code}).',
                    'generated_scenario': merged_scenario,
                    'provider_response': raw_generation[:4000],
                }), 400

            return jsonify({
                'success': True,
                'provider': provider,
                'base_url': base_url,
                'model': model,
                'prompt_used': prompt,
                'provider_response': raw_generation,
                'provider_attempts': generation_result.get('provider_attempts') or [],
                'generated_scenario': merged_scenario,
                'generated_scenarios': next_scenarios,
                'preview': preview_json.get('full_preview') or {},
                'flow_meta': preview_json.get('flow_meta') or {},
                'plan': preview_json.get('plan') or {},
                'breakdowns': preview_json.get('breakdowns'),
                'checked_at': _utc_timestamp(),
            })
        except ProviderAdapterError as exc:
            return jsonify({'success': False, 'error': exc.message, **exc.details}), exc.status_code

    @app.route('/api/ai/generate_scenario_preview_stream', methods=['POST'])
    def api_ai_generate_scenario_preview_stream():
        payload = request.get_json(silent=True) or {}
        try:
            _get_provider_adapter(payload.get('provider'))
        except ProviderAdapterError as exc:
            return jsonify({'success': False, 'error': exc.message, **exc.details}), exc.status_code

        scenarios = payload.get('scenarios') if isinstance(payload.get('scenarios'), list) else None
        if not scenarios:
            return jsonify({'success': False, 'error': 'scenarios payload is required.'}), 400

        scenario_index = payload.get('scenario_index')
        try:
            scenario_index = int(scenario_index)
        except Exception:
            scenario_index = 0
        if scenario_index < 0 or scenario_index >= len(scenarios):
            return jsonify({'success': False, 'error': 'scenario_index is out of range.'}), 400

        current_scenario = scenarios[scenario_index] if isinstance(scenarios[scenario_index], dict) else None
        if not current_scenario:
            return jsonify({'success': False, 'error': 'Selected scenario payload is invalid.'}), 400

        user_prompt = str(payload.get('prompt') or '').strip()
        if not user_prompt:
            return jsonify({'success': False, 'error': 'prompt is required.'}), 400

        bridge_mode = payload.get('bridge_mode')
        request_id = str(payload.get('request_id') or '').strip() or _create_stream_request_id()
        stream_entry = _register_ai_stream(request_id)

        @stream_with_context
        def _stream_events():
            try:
                if _is_mcp_python_sdk_bridge_mode(bridge_mode):
                    model = str(payload.get('model') or '').strip()
                    if not model:
                        yield _ndjson_event('error', error='model is required.')
                        return
                    try:
                        base_url = _normalize_base_url(payload.get('base_url'))
                    except ValueError as exc:
                        yield _ndjson_event('error', error=str(exc))
                        return

                    event_queue: queue.Queue[str | None] = queue.Queue()

                    def emit(event_type: str, **event_payload: Any) -> None:
                        event_queue.put(_ndjson_event(event_type, request_id=request_id, **event_payload))

                    def is_cancelled() -> bool:
                        return bool(stream_entry['cancelled'].is_set())

                    def on_client_ready(client: Any) -> None:
                        stream_entry['client'] = client

                    def on_response_open(response_obj: Any) -> None:
                        stream_entry['response'] = response_obj

                    def worker() -> None:
                        try:
                            emit('status', message='Connecting MCP bridge...')
                            generation_result = asyncio.run(_mcp_bridge_generate_with_events(
                                payload,
                                current_scenario=current_scenario,
                                user_prompt=user_prompt,
                                model=model,
                                host=base_url,
                                emit=emit,
                                cancel_check=is_cancelled,
                                on_client_ready=on_client_ready,
                                on_response_open=on_response_open,
                            ))
                            if is_cancelled():
                                emit('error', error='Generation cancelled by user.', status_code=499)
                                return
                            final_payload = _build_stream_success_payload(
                                app,
                                payload,
                                scenarios=scenarios,
                                scenario_index=scenario_index,
                                current_scenario=current_scenario,
                                generation_result=generation_result,
                            )
                            emit('result', data=final_payload)
                        except ProviderAdapterError as exc:
                            emit('error', error=exc.message, status_code=exc.status_code, details=exc.details)
                        except Exception as exc:  # pragma: no cover
                            try:
                                if log is not None:
                                    log.exception('[ai-provider] streaming bridge generation failed: %s', exc)
                            except Exception:
                                pass
                            emit('error', error=_describe_mcp_bridge_exception(exc, fallback='Unexpected bridge generation failure.'))
                        finally:
                            stream_entry['client'] = None
                            stream_entry['response'] = None
                            event_queue.put(None)

                    threading.Thread(target=worker, daemon=True).start()
                    while True:
                        next_event = event_queue.get()
                        if next_event is None:
                            break
                        yield next_event
                    return

                event_queue: queue.Queue[str | None] = queue.Queue()

                def emit(event_type: str, **event_payload: Any) -> None:
                    event_queue.put(_ndjson_event(event_type, request_id=request_id, **event_payload))

                def is_cancelled() -> bool:
                    return bool(stream_entry['cancelled'].is_set())

                def on_response_open(response_obj: Any) -> None:
                    stream_entry['response'] = response_obj

                def worker() -> None:
                    try:
                        generation_result = _generate_ollama_streaming_result(
                            payload,
                            current_scenario=current_scenario,
                            user_prompt=user_prompt,
                            emit=emit,
                            cancellation_check=is_cancelled,
                            on_response_open=on_response_open,
                        )
                        if is_cancelled():
                            emit('error', error='Generation cancelled by user.', status_code=499)
                            return
                        emit('status', message='Running backend preview…')
                        final_payload = _build_stream_success_payload(
                            app,
                            payload,
                            scenarios=scenarios,
                            scenario_index=scenario_index,
                            current_scenario=current_scenario,
                            generation_result=generation_result,
                        )
                        emit('result', data=final_payload)
                    except ProviderAdapterError as exc:
                        emit('error', error=exc.message, status_code=exc.status_code, details=exc.details)
                    except Exception as exc:  # pragma: no cover
                        try:
                            if log is not None:
                                log.exception('[ai-provider] streaming generation failed: %s', exc)
                        except Exception:
                            pass
                        emit('error', error='Unexpected generation failure while contacting Ollama.')
                    finally:
                        stream_entry['response'] = None
                        event_queue.put(None)

                threading.Thread(target=worker, daemon=True).start()
                while True:
                    next_event = event_queue.get()
                    if next_event is None:
                        break
                    yield next_event
            finally:
                _unregister_ai_stream(request_id)

        return Response(
            _stream_events(),
            mimetype='application/x-ndjson',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no',
            },
        )

    @app.route('/api/ai/generate_scenario_preview_stream/cancel', methods=['POST'])
    def api_ai_generate_scenario_preview_stream_cancel():
        payload = request.get_json(silent=True) or {}
        request_id = str(payload.get('request_id') or '').strip()
        if not request_id:
            return jsonify({'success': False, 'error': 'request_id is required.'}), 400
        cancelled = _cancel_ai_stream(request_id)
        if not cancelled:
            return jsonify({'success': False, 'error': 'No active generation stream found for request_id.', 'request_id': request_id}), 404
        return jsonify({'success': True, 'request_id': request_id, 'message': 'Cancellation requested.'})