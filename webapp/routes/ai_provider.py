from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
import json
import os
import queue
import re
import socket
import sys
import threading
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from flask import Response, jsonify, request, stream_with_context
from core_topo_gen.planning.ai_topology_intent import apply_compiled_sections_to_scenario
from core_topo_gen.planning.ai_topology_intent import build_seeded_traffic_rows as _compiler_build_seeded_traffic_rows
from core_topo_gen.planning.ai_topology_intent import compile_ai_topology_intent
from core_topo_gen.planning.ai_topology_intent import explicit_host_role_count_total as _compiler_explicit_host_role_count_total
from core_topo_gen.planning.ai_topology_intent import extract_node_role_count_intent as _compiler_extract_node_role_count_intent
from core_topo_gen.planning.ai_topology_intent import extract_r2r_density_intent as _compiler_extract_r2r_density_intent
from core_topo_gen.planning.ai_topology_intent import extract_requested_traffic_patterns as _compiler_extract_requested_traffic_patterns
from core_topo_gen.planning.ai_topology_intent import extract_segmentation_control_count_intent as _compiler_extract_segmentation_control_count_intent
from core_topo_gen.planning.ai_topology_intent import extract_service_count_intent as _compiler_extract_service_count_intent
from core_topo_gen.planning.ai_topology_intent import extract_traffic_pattern_count_intent as _compiler_extract_traffic_pattern_count_intent
from core_topo_gen.planning.ai_topology_intent import extract_traffic_protocol_count_intent as _compiler_extract_traffic_protocol_count_intent
from core_topo_gen.planning.ai_topology_intent import extract_vulnerability_query_hint as _compiler_extract_vulnerability_query_hint
from core_topo_gen.planning.ai_topology_intent import has_low_r2r_intent as _compiler_has_low_r2r_intent
from core_topo_gen.planning.ai_topology_intent import search_vulnerability_catalog_for_prompt as _compiler_search_vulnerability_catalog_for_prompt
from webapp import app_backend
from webapp.routes._registration import begin_route_registration, mark_routes_registered

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
_SUPPORTED_AI_BRIDGE_MODE_ALIASES = {'mcp-python-sdk', 'mcp_python_sdk', 'python-sdk', 'mcp-sdk', 'ollmcp'}
_DEFAULT_MCP_SERVER_PATH = os.path.join(_REPO_ROOT, 'MCP', 'server.py')
_DEFAULT_MCP_SERVERS_JSON_PATH = os.path.join(_REPO_ROOT, 'MCP', 'mcp-bridge-servers.json')
_ACTIVE_AI_STREAMS: dict[str, dict[str, Any]] = {}
_ACTIVE_AI_STREAMS_LOCK = threading.Lock()
_PROMPT_VULNERABILITY_CATALOG_CACHE: list[dict[str, str]] | None = None
_EXPLICIT_VULNERABILITY_QUERY_KEYWORDS: tuple[str, ...] = (
    'appweb',
    'jboss',
    'tomcat',
    'nginx',
    'apache',
    'openssh',
    'jwt',
    'oauth',
    'mysql',
    'postgres',
    'mongodb',
    'redis',
)


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


def _build_mcp_bridge_tool_parse_retry_prompt(prompt: str, *, user_prompt: str | None = None) -> str:
    source_prompt = str(user_prompt or prompt or '')
    retry_lines = [
        '',
        'Retry note: your previous response failed because Ollama could not parse a generated tool call.',
        'Every tool call arguments object must be strict valid JSON with no duplicate keys, no dangling text, and no partial numbers or strings.',
        'For vulnerabilities, do not pass factor.',
        'For traffic, if you provide count then do not also send factor or density for the same row.',
        'For vulnerabilities, use scenario.search_vulnerability_catalog first, then call scenario.add_vulnerability_item with only draft_id plus explicit v_name and v_path from the chosen concrete catalog match.',
        'For broad vulnerability requests, call scenario.search_vulnerability_catalog with only a free-text query from the user wording. Do not pass v_type or v_vector filters unless the user explicitly asked for those exact filters.',
        'If the user asks for multiple different vulnerabilities, make multiple separate add_vulnerability_item calls with v_count=1 instead of trying to encode them in one weighted row.',
        'For scenario.add_vulnerability_item, pass only strict JSON keys draft_id, v_name, v_path, and v_count unless the user explicitly requested exact type/vector filters.',
        'When v_path contains dots or slashes, keep it as one quoted JSON string copied exactly from a catalog search result. Never emit bare path fragments, ellipses, comments, or truncated JSON.',
    ]
    vulnerability_target_count = _extract_vulnerability_target_count(source_prompt)
    if vulnerability_target_count > 0:
        retry_lines.extend(_build_vulnerability_grounding_guidance(source_prompt))
        retry_lines.append('If you choose a vulnerability match, copy the exact v_name and v_path returned by scenario.search_vulnerability_catalog before calling scenario.add_vulnerability_item.')
        query_hint = _extract_vulnerability_query_hint(source_prompt)
        if query_hint:
            retry_lines.append(f'For this request, run scenario.search_vulnerability_catalog with query="{query_hint}" before any vulnerability add call.')
            candidates = _search_vulnerability_catalog_for_prompt(query_hint, limit=max(1, vulnerability_target_count))
            formatted_candidates = []
            for candidate in candidates:
                candidate_name = str(candidate.get('name') or '').strip()
                candidate_path = str(candidate.get('path') or '').strip()
                if candidate_name and candidate_path:
                    formatted_candidates.append(f'"{candidate_name}" -> "{candidate_path}"')
            if formatted_candidates:
                retry_lines.append('Example concrete catalog matches: ' + '; '.join(formatted_candidates[:3]) + '.')
    traffic_rows = _build_seeded_traffic_rows(source_prompt)
    requested_traffic_patterns = _extract_requested_traffic_patterns(source_prompt)
    if traffic_rows or requested_traffic_patterns or re.search(r'\b(?:tcp|udp|traffic\s+flows?|flows?|traffic\s+streams?|streams?)\b', source_prompt.lower()):
        retry_lines.extend([
            'For scenario.add_traffic_item, pass only strict JSON keys draft_id, protocol or selected, count, pattern, and content_type unless you intentionally need one of the numeric traffic tuning fields.',
            'When count is present, omit factor entirely instead of sending factor="0", blank factor strings, or duplicate factor keys.',
            'Use one exact pattern per traffic row from: continuous, periodic, burst, poisson, or ramp.',
            'Use content_type="text" unless the user explicitly requested photo, audio, video, or gibberish traffic.',
        ])
        formatted_rows = []
        for row in traffic_rows[:3]:
            protocol = str(row.get('protocol') or '').strip()
            count = row.get('count')
            pattern = str(row.get('pattern') or '').strip()
            content_type = str(row.get('content_type') or 'text').strip() or 'text'
            if protocol and pattern and count not in (None, ''):
                formatted_rows.append(
                    f'{{"draft_id":"<draft_id>","protocol":"{protocol}","count":{int(count)},"pattern":"{pattern}","content_type":"{content_type}"}}'
                )
        if formatted_rows:
            retry_lines.append('Example valid traffic tool call JSON: ' + '; '.join(formatted_rows) + '.')
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


def _extract_vulnerability_target_count(user_prompt: str) -> int:
    text = str(user_prompt or '').strip().lower()
    if not text:
        return 0

    match = re.search(r'\b(\d+)\s+(?:[a-z][a-z0-9-]*\s+){0,3}vulnerabilit(?:y|ies)\b', text)
    if match:
        try:
            return max(0, int(match.group(1)))
        except Exception:
            return 0

    if re.search(r'\bvulnerabilit(?:y|ies)\b|\bvulns?\b', text):
        return 1
    return 0


def _load_vulnerability_catalog_for_prompt() -> list[dict[str, str]]:
    global _PROMPT_VULNERABILITY_CATALOG_CACHE
    if _PROMPT_VULNERABILITY_CATALOG_CACHE is not None:
        return list(_PROMPT_VULNERABILITY_CATALOG_CACHE)
    try:
        from core_topo_gen.utils.vuln_process import load_vuln_catalog
        _PROMPT_VULNERABILITY_CATALOG_CACHE = list(load_vuln_catalog(_REPO_ROOT) or [])
    except Exception:
        _PROMPT_VULNERABILITY_CATALOG_CACHE = []
    return list(_PROMPT_VULNERABILITY_CATALOG_CACHE)


def _get_ai_compiler_vulnerability_catalog() -> list[dict[str, Any]]:
    loader = getattr(app_backend, '_load_backend_vuln_catalog_items', None)
    if callable(loader):
        try:
            return list(loader() or [])
        except Exception:
            return []
    return []


def _compile_ai_intent(user_prompt: str):
    return compile_ai_topology_intent(
        user_prompt,
        vuln_catalog=_get_ai_compiler_vulnerability_catalog(),
    )


def _extract_vulnerability_query_hint(user_prompt: str) -> str:
    return _compiler_extract_vulnerability_query_hint(user_prompt)


def _extract_explicit_vulnerability_query_keyword(user_prompt: str) -> str:
    query_hint = _extract_vulnerability_query_hint(user_prompt).strip().lower()
    if query_hint in _EXPLICIT_VULNERABILITY_QUERY_KEYWORDS:
        return query_hint
    return ''


def _ensure_explicit_vulnerability_query_matches_or_raise(user_prompt: str, scenario_payload: dict[str, Any]) -> None:
    keyword = _extract_explicit_vulnerability_query_keyword(user_prompt)
    if not keyword:
        return

    sections = scenario_payload.get('sections') if isinstance(scenario_payload.get('sections'), dict) else {}
    vulnerabilities = sections.get('Vulnerabilities') if isinstance(sections.get('Vulnerabilities'), dict) else {}
    items = vulnerabilities.get('items') if isinstance(vulnerabilities.get('items'), list) else []
    specific_items = [
        item
        for item in items
        if isinstance(item, dict) and str(item.get('selected') or '').strip().lower() == 'specific'
    ]
    if not specific_items:
        return

    for item in specific_items:
        haystack = ' '.join([
            str(item.get('v_name') or '').strip().lower(),
            str(item.get('v_path') or '').strip().lower(),
        ])
        if keyword in haystack:
            return

    raise ProviderAdapterError('Specific vulnerability must match an enabled catalog entry by v_path or v_name', status_code=400)


def _search_vulnerability_catalog_for_prompt(query: str, *, limit: int = 3) -> list[dict[str, str]]:
    return _compiler_search_vulnerability_catalog_for_prompt(
        query,
        catalog=_load_vulnerability_catalog_for_prompt(),
        limit=limit,
    )


def _build_vulnerability_grounding_guidance(user_prompt: str) -> list[str]:
    query_hint = _extract_vulnerability_query_hint(user_prompt)
    if not query_hint:
        return []

    requested_count = max(1, _extract_vulnerability_target_count(user_prompt))
    candidates = _search_vulnerability_catalog_for_prompt(query_hint, limit=requested_count)
    guidance = [
        f'For this request, keep the vulnerability catalog query narrow: query="{query_hint}".',
        'Do one focused vulnerability search, choose concrete matches, and stop. Do not wander through multiple broad catalog searches once you already have viable results.',
    ]
    if candidates:
        candidate_names = ', '.join(
            f'"{str(candidate.get("name") or "").strip()}"'
            for candidate in candidates
            if str(candidate.get('name') or '').strip()
        )
        if candidate_names:
            guidance.append(
                f'Likely concrete matches for that query include: {candidate_names}. Prefer these before exploring unrelated catalog entries.'
            )
    if requested_count == 1:
        guidance.append(
            'The request only needs one vulnerability target. Choose one concrete catalog match and stop after adding that single vulnerability item.'
        )
    else:
        guidance.append(
            f'The request needs {requested_count} vulnerability target(s). Add only that many concrete vulnerability items unless the user explicitly asks for more.'
        )
    return guidance


def _has_low_r2r_intent(user_prompt: str) -> bool:
    return _compiler_has_low_r2r_intent(user_prompt)


def _build_mcp_bridge_execution_guidance(user_prompt: str) -> list[str]:
    intent = _extract_count_intent(user_prompt)
    router_count = intent.get('router_count')
    derived_host_count = intent.get('derived_host_count')
    vulnerability_target_count = _extract_vulnerability_target_count(user_prompt)
    explicit_host_total = _explicit_host_role_count_total(user_prompt)

    guidance: list[str] = []
    if router_count is not None and vulnerability_target_count > 0:
        guidance.append(
            'Complete this request in order: author Routing first, then Node Information host rows, then Vulnerabilities, and only then any optional remaining sections.'
        )
        guidance.append(
            'Do not postpone the Routing section until after vulnerability search. Add the requested router row before you search the vulnerability catalog so the draft already satisfies the router-count part of the request.'
        )
    elif router_count is not None:
        guidance.append(
            'Author the Routing section before you finish. Do not stop after editing only Node Information when the prompt explicitly requests routers.'
        )

    if vulnerability_target_count > 0:
        guidance.extend(_build_vulnerability_grounding_guidance(user_prompt))

    if derived_host_count is not None and vulnerability_target_count > 0:
        if explicit_host_total >= derived_host_count:
            guidance.append(
                'The explicit host-role counts already fill the available host budget. Do not add extra Docker hosts for vulnerabilities in that case; attach the requested vulnerabilities to those existing hosts instead.'
            )
        else:
            remaining_non_vuln_hosts = max(0, derived_host_count - vulnerability_target_count)
            guidance.append(
                f'Because the prompt asks for {vulnerability_target_count} vulnerability target(s), reserve {vulnerability_target_count} Docker host slots inside the {derived_host_count}-host budget before adding vulnerabilities. That leaves {remaining_non_vuln_hosts} non-Docker host slots for the other Node Information rows unless Docker hosts are already explicit.'
            )

    if router_count is not None and _has_low_r2r_intent(user_prompt):
        guidance.append(
            'For low router-to-router link ratio requests, use a sparse Routing setting such as r2r_mode="Min" or another low-edge configuration instead of a dense mesh.'
        )

    return guidance


def _extract_node_role_count_intent(user_prompt: str) -> dict[str, int]:
    return _compiler_extract_node_role_count_intent(user_prompt)


def _explicit_host_role_count_total(user_prompt: str) -> int:
    return _compiler_explicit_host_role_count_total(user_prompt)


def _extract_r2r_density_intent(user_prompt: str) -> str:
    return _compiler_extract_r2r_density_intent(user_prompt)


_COUNT_WORDS: dict[str, int] = {
    'a': 1,
    'an': 1,
    'one': 1,
    'two': 2,
    'three': 3,
    'four': 4,
    'five': 5,
    'six': 6,
    'seven': 7,
    'eight': 8,
    'nine': 9,
    'ten': 10,
    'eleven': 11,
    'twelve': 12,
    'pair of': 2,
    'a pair of': 2,
    'couple of': 2,
    'a couple of': 2,
}

_COUNT_TOKEN_PATTERN = r'\d+|a\s+pair\s+of|pair\s+of|a\s+couple\s+of|couple\s+of|an?|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve'


def _parse_count_token(value: Any) -> int | None:
    text = str(value or '').strip().lower()
    if not text:
        return None
    if text.isdigit():
        try:
            number = int(text)
        except Exception:
            return None
        return number if number > 0 else None
    return _COUNT_WORDS.get(text)


def _sum_count_matches(text: str, pattern: str) -> int:
    total = 0
    for match in re.finditer(pattern, text):
        number = _parse_count_token(match.group(1))
        if number is not None:
            total += number
    return total


def _extract_shared_suffix_count_intent(
    text: str,
    *,
    suffix_pattern: str,
    label_patterns: tuple[tuple[str, str], ...],
    qualifier_max_words: int = 3,
) -> dict[str, int]:
    if not text:
        return {}

    separator_pattern = r'(?:\s*,\s*and\s+|\s+and\s+|\s*,\s*)'
    forbidden_qualifier_words = r'and|or|plus|a|an|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|pair|couple'
    qualifier_words = rf'(?:(?!(?:{forbidden_qualifier_words})\b)[a-z][a-z0-9-]*\s+){{0,{qualifier_max_words}}}'

    counts: dict[str, int] = {}
    for canonical, label_pattern in label_patterns:
        segment_pattern = re.compile(
            rf'\b(?P<count>{_COUNT_TOKEN_PATTERN})\s+{qualifier_words}(?P<label>{label_pattern})(?=(?:{separator_pattern}(?:{_COUNT_TOKEN_PATTERN})\s+|\s+{suffix_pattern}\b))'
        )
        total = 0
        for match in segment_pattern.finditer(text):
            number = _parse_count_token(match.group('count'))
            if number is None:
                continue
            total += number
        if total > 0:
            counts[canonical] = counts.get(canonical, 0) + total
    return counts


def _extract_service_count_intent(user_prompt: str) -> dict[str, int]:
    return _compiler_extract_service_count_intent(user_prompt)


def _extract_traffic_protocol_count_intent(user_prompt: str) -> dict[str, int]:
    return _compiler_extract_traffic_protocol_count_intent(user_prompt)


def _extract_traffic_pattern_count_intent(user_prompt: str) -> dict[str, int]:
    return _compiler_extract_traffic_pattern_count_intent(user_prompt)


def _extract_requested_traffic_patterns(user_prompt: str) -> list[str]:
    return _compiler_extract_requested_traffic_patterns(user_prompt)


def _extract_segmentation_control_count_intent(user_prompt: str) -> dict[str, int]:
    return _compiler_extract_segmentation_control_count_intent(user_prompt)


def _build_count_intent_guidance(user_prompt: str) -> list[str]:
    intent = _extract_count_intent(user_prompt)
    total_nodes = intent.get('total_nodes')
    router_count = intent.get('router_count')
    derived_host_count = intent.get('derived_host_count')
    vulnerability_target_count = _extract_vulnerability_target_count(user_prompt)
    explicit_host_total = _explicit_host_role_count_total(user_prompt)

    guidance: list[str] = []
    if total_nodes is not None and router_count is not None and derived_host_count is not None:
        if vulnerability_target_count > 0:
            guidance.append(
                f'User count intent detected: total topology nodes={total_nodes}, router nodes={router_count}, so the final preview host count should be {derived_host_count} and Routing router count should be {router_count}.'
            )
            if explicit_host_total >= derived_host_count:
                guidance.append(
                    'The explicit host-role counts already consume the full host budget, so satisfy the requested vulnerabilities on those existing hosts instead of adding extra Docker host rows.'
                )
            else:
                remaining_non_vuln_hosts = max(0, derived_host_count - vulnerability_target_count)
                guidance.append(
                    f'The prompt also asks for {vulnerability_target_count} vulnerability target(s), and those targets consume Docker host slots inside that {derived_host_count}-host budget. Unless you explicitly include those Docker hosts already, keep the other Node Information host rows to {remaining_non_vuln_hosts} so preview repair does not overshoot the requested total nodes.'
                )
        else:
            guidance.append(
                f'User count intent detected: total topology nodes={total_nodes}, router nodes={router_count}, so Node Information host counts should sum to {derived_host_count} and Routing router count should be {router_count}.'
            )
        guidance.append(
            'Do not satisfy a separate router request by reducing router rows to zero or by treating routers as host rows under Node Information.'
        )
    elif total_nodes is not None:
        if vulnerability_target_count > 0:
            guidance.append(
                f'User count intent detected: node count={total_nodes}. The final preview host count should stay at {total_nodes}.'
            )
            if explicit_host_total >= total_nodes:
                guidance.append(
                    'The explicit host-role counts already consume the full host budget, so satisfy the requested vulnerabilities on those existing hosts instead of adding extra Docker host rows.'
                )
            else:
                remaining_non_vuln_hosts = max(0, total_nodes - vulnerability_target_count)
                guidance.append(
                    f'The prompt also asks for {vulnerability_target_count} vulnerability target(s), and those targets consume Docker host slots inside that {total_nodes}-host budget. Unless you explicitly include those Docker hosts already, keep the other Node Information host rows to {remaining_non_vuln_hosts} so preview repair does not overshoot the requested total nodes.'
                )
        else:
            guidance.append(
                f'User count intent detected: node count={total_nodes}. If no separate router count is requested, treat this as the host-node target for Node Information.'
            )
    return guidance


def _extract_prompt_coverage_intent(user_prompt: str) -> dict[str, dict[str, Any]]:
    text = str(user_prompt or '').strip().lower()
    if not text:
        return {}

    qualifier_words = r'(?:[a-z][a-z0-9-]*\s+){0,3}'

    def _match_count(pattern: str) -> int | None:
        match = re.search(pattern, text)
        if not match:
            return None
        try:
            return max(1, int(match.group(1)))
        except Exception:
            return None

    def _has_any(patterns: list[str]) -> bool:
        return any(re.search(pattern, text) for pattern in patterns)

    def _routing_protocols_requested() -> list[str]:
        matches: list[str] = []
        for pattern, canonical in (
            (r'\bospfv3\b', 'OSPFv3'),
            (r'\bospf(?:v2)?\b', 'OSPFv2'),
            (r'\bripng\b', 'RIPNG'),
            (r'\brip\b', 'RIP'),
            (r'\bbgp\b', 'BGP'),
        ):
            if re.search(pattern, text) and canonical not in matches:
                matches.append(canonical)
        return matches

    coverage: dict[str, dict[str, Any]] = {}

    node_role_counts = _extract_node_role_count_intent(user_prompt)
    for role, count in node_role_counts.items():
        role_suffix = '' if count == 1 else 's'
        coverage[f'Node Information:{role}'] = {
            'exact_items': count,
            'reason': f'user requested exactly {count} {role} host{role_suffix}',
        }

    service_counts = _extract_service_count_intent(user_prompt)
    for service, count in service_counts.items():
        coverage[f'Services:{service}'] = {
            'exact_items': count,
            'reason': f'user requested exactly {count} {service} service row{'s' if count != 1 else ''}',
        }

    traffic_protocol_counts = _extract_traffic_protocol_count_intent(user_prompt)
    for protocol, count in traffic_protocol_counts.items():
        coverage[f'Traffic:{protocol}'] = {
            'exact_items': count,
            'reason': f'user requested exactly {count} {protocol} traffic row{'s' if count != 1 else ''}',
        }

    traffic_pattern_counts = _extract_traffic_pattern_count_intent(user_prompt)
    for pattern_name, count in traffic_pattern_counts.items():
        coverage[f'Traffic Pattern:{pattern_name}'] = {
            'exact_items': count,
            'reason': f'user requested exactly {count} {pattern_name} traffic row{'s' if count != 1 else ''}',
        }

    segmentation_control_counts = _extract_segmentation_control_count_intent(user_prompt)
    for control, count in segmentation_control_counts.items():
        coverage[f'Segmentation:{control}'] = {
            'exact_items': count,
            'reason': f'user requested exactly {count} {control} segmentation row{'s' if count != 1 else ''}',
        }

    vuln_count = _match_count(r'\b(\d+)\s+' + qualifier_words + r'vulnerabilit(?:y|ies)\b')
    if vuln_count is None and _has_any([r'\bvulnerabilit(?:y|ies)\b', r'\bvulns?\b']):
        vuln_count = 1
    if vuln_count is not None:
        coverage['Vulnerabilities'] = {
            'min_items': vuln_count,
            'reason': f'user requested at least {vuln_count} vulnerabilit{'y' if vuln_count == 1 else 'ies'}',
        }

    traffic_count = _match_count(r'\b(\d+)\s+' + qualifier_words + r'(?:traffic\s+flows?|flows?|traffic\s+streams?|streams?)\b')
    if traffic_count is None and _has_any([r'\btraffic\b', r'\btraffic\s+profile', r'\btraffic\s+profiles\b', r'\btcp\b', r'\budp\b', r'\bflows?\b']):
        traffic_count = 1
    if traffic_count is not None:
        coverage['Traffic'] = {
            'min_items': traffic_count,
            'reason': f'user requested at least {traffic_count} traffic row{'s' if traffic_count != 1 else ''}',
        }
        traffic_values: list[dict[str, Any]] = []
        selected_values = [
            canonical
            for pattern, canonical in ((r'\btcp\b', 'TCP'), (r'\budp\b', 'UDP'))
            if re.search(pattern, text)
        ]
        if selected_values:
            traffic_values.append({
                'field': 'selected_values',
                'values': selected_values,
                'reason': 'user explicitly requested these traffic protocols',
            })
        pattern_values = _extract_requested_traffic_patterns(user_prompt)
        if pattern_values:
            traffic_values.append({
                'field': 'pattern_values',
                'values': pattern_values,
                'reason': 'user explicitly requested these traffic patterns',
            })
        if traffic_values:
            coverage['Traffic']['required_values'] = traffic_values

    service_count = _match_count(r'\b(\d+)\s+' + qualifier_words + r'services?\b')
    if service_count is None and _has_any([r'\bservices?\b']):
        service_count = 1
    if service_count is not None:
        coverage['Services'] = {
            'min_items': service_count,
            'reason': f'user requested at least {service_count} service row{'s' if service_count != 1 else ''}',
        }
    service_values = [
        canonical
        for pattern, canonical in (
            (r'\bssh\b', 'SSH'),
            (r'\bhttps?\b|\bweb\b', 'HTTP'),
            (r'\bdhcp\b', 'DHCPClient'),
        )
        if re.search(pattern, text)
    ]
    if service_values and ('Services' in coverage or _has_any([r'\bservice\b', r'\bservices\b'])):
        coverage.setdefault('Services', {
            'min_items': 1,
            'reason': 'user requested services',
        })
        coverage['Services']['required_values'] = [{
            'field': 'selected_values',
            'values': list(dict.fromkeys(service_values)),
            'reason': 'user explicitly requested these services',
        }]

    segmentation_count = _match_count(r'\b(\d+)\s+' + qualifier_words + r'segments?\b')
    if segmentation_count is None and _has_any([r'\bsegmentation\b', r'\bsegmented\b', r'\bnetwork\s+segments?\b']):
        segmentation_count = 1
    if segmentation_count is not None:
        coverage['Segmentation'] = {
            'min_items': segmentation_count,
            'reason': f'user requested at least {segmentation_count} segmentation row{'s' if segmentation_count != 1 else ''}',
        }
    segmentation_values = [
        canonical
        for pattern, canonical in ((r'\bfirewall\b|\bfw\b', 'Firewall'), (r'\bnat\b|\bsnat\b|\bdnat\b', 'NAT'))
        if re.search(pattern, text)
    ]
    if segmentation_values and ('Segmentation' in coverage or _has_any([r'\bsegmentation\b', r'\bsegmented\b', r'\bsegment\b'])):
        coverage.setdefault('Segmentation', {
            'min_items': 1,
            'reason': 'user requested segmentation controls',
        })
        coverage['Segmentation']['required_values'] = [{
            'field': 'selected_values',
            'values': list(dict.fromkeys(segmentation_values)),
            'reason': 'user explicitly requested these segmentation controls',
        }]

    routing_values = _routing_protocols_requested()
    if routing_values:
        coverage['Routing'] = {
            'min_items': 1,
            'reason': 'user explicitly requested routing protocols',
            'required_values': [{
                'field': 'selected_values',
                'values': routing_values,
                'reason': 'user explicitly requested these routing protocols',
            }],
        }
    r2r_density_intent = _extract_r2r_density_intent(user_prompt)
    if r2r_density_intent:
        coverage.setdefault('Routing', {
            'min_items': 1,
            'reason': 'user explicitly requested routing configuration',
        })
        routing_required_values = coverage['Routing'].get('required_values') if isinstance(coverage['Routing'].get('required_values'), list) else []
        routing_required_values.append({
            'field': 'r2r_density_values',
            'values': [r2r_density_intent],
            'reason': 'user explicitly requested router-to-router density semantics',
        })
        coverage['Routing']['required_values'] = routing_required_values

    if _has_any([r'\bdocker\b']):
        docker_count = _match_count(r'\b(\d+)\s+' + qualifier_words + r'docker\s+(?:hosts?|nodes?|containers?)\b')
        coverage['Docker'] = {
            'min_items': docker_count or 1,
            'reason': f'user requested at least {docker_count or 1} docker host row{'s' if (docker_count or 1) != 1 else ''}',
        }

    return coverage


def _coerce_positive_int(value: Any) -> int | None:
    try:
        number = int(value)
    except Exception:
        return None
    return number if number > 0 else None


def _count_section_coverage_units(scenario_payload: dict[str, Any] | None, section_name: str) -> int:
    scenario = scenario_payload if isinstance(scenario_payload, dict) else {}
    sections = scenario.get('sections') if isinstance(scenario.get('sections'), dict) else {}
    section = sections.get(section_name) if isinstance(sections.get(section_name), dict) else {}
    items = section.get('items') if isinstance(section.get('items'), list) else []
    total = 0
    for item in items:
        if not isinstance(item, dict) or not item:
            continue
        total += _coerce_positive_int(item.get('v_count')) or _coerce_positive_int(item.get('count')) or 1
    return total


def _count_docker_rows(scenario_payload: dict[str, Any] | None) -> int:
    scenario = scenario_payload if isinstance(scenario_payload, dict) else {}
    sections = scenario.get('sections') if isinstance(scenario.get('sections'), dict) else {}
    node_info = sections.get('Node Information') if isinstance(sections.get('Node Information'), dict) else {}
    items = node_info.get('items') if isinstance(node_info.get('items'), list) else []
    total = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        if str(item.get('selected') or '').strip().lower() != 'docker':
            continue
        total += _coerce_positive_int(item.get('v_count')) or _coerce_positive_int(item.get('count')) or 1
    return total


def _count_node_role_rows(scenario_payload: dict[str, Any] | None, role: str) -> int:
    scenario = scenario_payload if isinstance(scenario_payload, dict) else {}
    sections = scenario.get('sections') if isinstance(scenario.get('sections'), dict) else {}
    node_info = sections.get('Node Information') if isinstance(sections.get('Node Information'), dict) else {}
    items = node_info.get('items') if isinstance(node_info.get('items'), list) else []
    total = 0
    canonical_role = app_backend._normalize_node_information_role(role)
    for item in items:
        if not isinstance(item, dict):
            continue
        selected = app_backend._normalize_node_information_role(item.get('selected'))
        if selected != canonical_role:
            continue
        total += _coerce_positive_int(item.get('v_count')) or _coerce_positive_int(item.get('count')) or 1
    return total


def _count_section_selected_rows(
    scenario_payload: dict[str, Any] | None,
    section_name: str,
    target_value: str,
    *,
    normalizer: Callable[[Any], str],
    field_names: tuple[str, ...] = ('selected',),
) -> int:
    scenario = scenario_payload if isinstance(scenario_payload, dict) else {}
    sections = scenario.get('sections') if isinstance(scenario.get('sections'), dict) else {}
    section = sections.get(section_name) if isinstance(sections.get(section_name), dict) else {}
    items = section.get('items') if isinstance(section.get('items'), list) else []
    total = 0
    canonical_target = normalizer(target_value)
    for item in items:
        if not isinstance(item, dict):
            continue
        selected = ''
        for field_name in field_names:
            selected = normalizer(item.get(field_name))
            if selected:
                break
        if selected != canonical_target:
            continue
        total += _coerce_positive_int(item.get('v_count')) or _coerce_positive_int(item.get('count')) or 1
    return total


def _count_traffic_pattern_rows(scenario_payload: dict[str, Any] | None, pattern_name: str) -> int:
    scenario = scenario_payload if isinstance(scenario_payload, dict) else {}
    sections = scenario.get('sections') if isinstance(scenario.get('sections'), dict) else {}
    traffic = sections.get('Traffic') if isinstance(sections.get('Traffic'), dict) else {}
    items = traffic.get('items') if isinstance(traffic.get('items'), list) else []
    canonical_target = app_backend._normalize_traffic_pattern_value(pattern_name)
    if canonical_target == 'bursty':
        canonical_target = 'burst'
    total = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        current = app_backend._normalize_traffic_pattern_value(item.get('pattern'))
        if current == 'bursty':
            current = 'burst'
        if current != canonical_target:
            continue
        total += _coerce_positive_int(item.get('v_count')) or _coerce_positive_int(item.get('count')) or 1
    return total


def _classify_r2r_density_from_item(item: dict[str, Any]) -> str:
    mode = str(item.get('r2r_mode') or '').strip().lower()
    try:
        edges = int(item.get('r2r_edges') or 0)
    except Exception:
        edges = 0

    if mode == 'min':
        return 'low'
    if mode == 'max':
        return 'high'
    if mode == 'exact':
        if edges <= 1:
            return 'low'
        if edges >= 4:
            return 'high'
    if mode in {'uniform', 'nonuniform'}:
        if edges > 0 and edges <= 1:
            return 'low'
        if edges >= 4:
            return 'high'
        if edges > 0:
            return 'medium'
    return ''


def _extract_actual_prompt_coverage_values(scenario_payload: dict[str, Any] | None) -> dict[str, dict[str, list[str]]]:
    scenario = scenario_payload if isinstance(scenario_payload, dict) else {}
    sections = scenario.get('sections') if isinstance(scenario.get('sections'), dict) else {}

    def _section_items(section_name: str) -> list[dict[str, Any]]:
        section = sections.get(section_name) if isinstance(sections.get(section_name), dict) else {}
        items = section.get('items') if isinstance(section.get('items'), list) else []
        return [item for item in items if isinstance(item, dict)]

    def _ordered(values: list[str]) -> list[str]:
        return list(dict.fromkeys([value for value in values if value]))

    routing_selected = _ordered([
        app_backend._normalize_routing_item_selection(item.get('selected')) or app_backend._normalize_routing_item_selection(item.get('protocol'))
        for item in _section_items('Routing')
    ])
    routing_r2r_density = _ordered([
        _classify_r2r_density_from_item(item)
        for item in _section_items('Routing')
    ])
    service_selected = _ordered([
        app_backend._normalize_service_item_selection(item.get('selected'))
        for item in _section_items('Services')
    ])
    traffic_selected = _ordered([
        app_backend._normalize_traffic_item_selection(item.get('selected')) or app_backend._normalize_traffic_item_selection(item.get('protocol'))
        for item in _section_items('Traffic')
    ])
    traffic_patterns = _ordered([
        'burst' if app_backend._normalize_traffic_pattern_value(item.get('pattern')) == 'bursty'
        else app_backend._normalize_traffic_pattern_value(item.get('pattern'))
        for item in _section_items('Traffic')
    ])
    segmentation_selected = _ordered([
        app_backend._normalize_segmentation_item_selection(item.get('selected'))
        for item in _section_items('Segmentation')
    ])

    vector_values: list[str] = []
    for item in _section_items('Vulnerabilities'):
        raw_vector = str(item.get('v_vector') or '').strip().lower()
        if raw_vector:
            vector_values.append(raw_vector)
            continue
        raw_name = ' '.join([
            str(item.get('v_name') or '').strip().lower(),
            str(item.get('v_path') or '').strip().lower(),
        ])
        if 'web' in raw_name:
            vector_values.append('web')

    return {
        'Routing': {'selected_values': routing_selected, 'r2r_density_values': routing_r2r_density},
        'Services': {'selected_values': service_selected},
        'Traffic': {'selected_values': traffic_selected, 'pattern_values': traffic_patterns},
        'Segmentation': {'selected_values': segmentation_selected},
        'Vulnerabilities': {'vector_values': _ordered(vector_values)},
        'Docker': {'selected_values': ['Docker'] if _count_docker_rows(scenario_payload) > 0 else []},
    }


def _get_prompt_coverage_mismatch(user_prompt: str, scenario_payload: dict[str, Any] | None) -> dict[str, Any] | None:
    intent = _extract_prompt_coverage_intent(user_prompt)
    if not intent:
        return None

    actual = {
        'Routing': _count_section_coverage_units(scenario_payload, 'Routing'),
        'Services': _count_section_coverage_units(scenario_payload, 'Services'),
        'Traffic': _count_section_coverage_units(scenario_payload, 'Traffic'),
        'Vulnerabilities': _count_section_coverage_units(scenario_payload, 'Vulnerabilities'),
        'Segmentation': _count_section_coverage_units(scenario_payload, 'Segmentation'),
        'Docker': _count_docker_rows(scenario_payload),
    }
    for role in ('Server', 'Workstation', 'PC', 'Docker'):
        actual[f'Node Information:{role}'] = _count_node_role_rows(scenario_payload, role)
    for service in ('SSH', 'HTTP', 'DHCPClient'):
        actual[f'Services:{service}'] = _count_section_selected_rows(
            scenario_payload,
            'Services',
            service,
            normalizer=app_backend._normalize_service_item_selection,
            field_names=('selected', 'service', 'name'),
        )
    for protocol in ('TCP', 'UDP'):
        actual[f'Traffic:{protocol}'] = _count_section_selected_rows(
            scenario_payload,
            'Traffic',
            protocol,
            normalizer=app_backend._normalize_traffic_item_selection,
            field_names=('selected', 'protocol'),
        )
    for pattern_name in ('continuous', 'periodic', 'burst', 'poisson', 'ramp'):
        actual[f'Traffic Pattern:{pattern_name}'] = _count_traffic_pattern_rows(scenario_payload, pattern_name)
    for control in ('Firewall', 'NAT'):
        actual[f'Segmentation:{control}'] = _count_section_selected_rows(
            scenario_payload,
            'Segmentation',
            control,
            normalizer=app_backend._normalize_segmentation_item_selection,
            field_names=('selected', 'kind', 'type', 'name'),
        )
    actual_values = _extract_actual_prompt_coverage_values(scenario_payload)

    missing: list[dict[str, Any]] = []
    missing_values: list[dict[str, Any]] = []
    reasons: list[str] = []
    for key, requirement in intent.items():
        actual_items = actual.get(key, 0)
        exact_items_raw = requirement.get('exact_items')
        if exact_items_raw not in (None, ''):
            exact_items = max(0, int(exact_items_raw or 0))
            if actual_items != exact_items:
                reason = str(requirement.get('reason') or f'user requested exact {key} counts').strip()
                missing.append({
                    'target': key,
                    'expected_items': exact_items,
                    'expected_min_items': exact_items,
                    'actual_items': actual_items,
                    'reason': reason,
                })
                reasons.append(f'{key} expected exactly {exact_items} item(s) but draft has {actual_items}')
        else:
            min_items = max(1, int(requirement.get('min_items') or 1))
            if actual_items >= min_items:
                pass
            else:
                reason = str(requirement.get('reason') or f'user requested {key}').strip()
                missing.append({
                    'target': key,
                    'expected_min_items': min_items,
                    'actual_items': actual_items,
                    'reason': reason,
                })
                reasons.append(f'{key} expected at least {min_items} item(s) but draft has {actual_items}')

        for value_requirement in requirement.get('required_values') or []:
            if not isinstance(value_requirement, dict):
                continue
            field = str(value_requirement.get('field') or '').strip()
            expected_values = [
                str(value or '').strip()
                for value in (value_requirement.get('values') or [])
                if str(value or '').strip()
            ]
            if not field or not expected_values:
                continue
            actual_field_values = [
                str(value or '').strip()
                for value in (actual_values.get(key, {}).get(field) or [])
                if str(value or '').strip()
            ]
            missing_field_values = [value for value in expected_values if value not in actual_field_values]
            if not missing_field_values:
                continue
            reason = str(value_requirement.get('reason') or requirement.get('reason') or f'user requested {key} values').strip()
            missing_values.append({
                'target': key,
                'field': field,
                'expected_values': expected_values,
                'missing_values': missing_field_values,
                'actual_values': actual_field_values,
                'reason': reason,
            })
            reasons.append(f'{key} missing requested {field}: {", ".join(missing_field_values)}')

    if not missing and not missing_values:
        return None

    return {
        'required': intent,
        'actual': actual,
        'actual_values': actual_values,
        'missing': missing,
        'missing_values': missing_values,
        'reasons': reasons,
    }


def _build_prompt_coverage_retry_prompt(prompt: str, mismatch: dict[str, Any]) -> str:
    missing = mismatch.get('missing') if isinstance(mismatch.get('missing'), list) else []
    actual = mismatch.get('actual') if isinstance(mismatch.get('actual'), dict) else {}
    missing_values = mismatch.get('missing_values') if isinstance(mismatch.get('missing_values'), list) else []
    actual_values = mismatch.get('actual_values') if isinstance(mismatch.get('actual_values'), dict) else {}

    retry_lines = [
        '',
        'Retry note: the previous draft omitted one or more requested prompt items.',
        'Previous draft item counts: '
        + ', '.join(
            f'{name}={actual.get(name, 0)}'
            for name in ('Services', 'Traffic', 'Vulnerabilities', 'Segmentation', 'Docker')
        )
        + '.',
    ]

    def _quote_csv(values: list[str]) -> str:
        cleaned = [str(value or '').strip() for value in values if str(value or '').strip()]
        return ', '.join(f'"{value}"' for value in cleaned)

    for item in missing:
        target = str(item.get('target') or '').strip()
        expected = int(item.get('expected_min_items') or 1)
        actual_items = int(item.get('actual_items') or 0)
        reason = str(item.get('reason') or '').strip()
        exact_requested = item.get('expected_items') not in (None, '')
        comparator_text = 'exactly' if exact_requested else 'at least'
        retry_lines.append(
            f'Missing requirement: {target} expected {comparator_text} {expected} item(s) but draft has {actual_items}. {reason}.'
        )
        if target == 'Vulnerabilities':
            retry_lines.append(
                'Add the missing Vulnerabilities rows before finishing. Search the vulnerability catalog using the user\'s wording, then add concrete Specific rows from the chosen matches; for multiple requested vulnerabilities, add separate rows.'
            )
        elif target.startswith('Node Information:'):
            retry_lines.append(
                'Add or repair Node Information rows so the requested host-role counts are present before finishing. Use selected with the exact host role label and explicit Count rows.'
            )
        elif target.startswith('Services:'):
            service_label = target.split(':', 1)[1].strip()
            retry_lines.append(
                'Add or repair Services rows so the requested service labels and exact counts are present before finishing. Use only schema-backed service labels, create distinct rows for distinct requested labels, and do not duplicate one label to satisfy another requested label.'
            )
            if service_label:
                retry_lines.append(
                    f'Use scenario.add_service_item to add or repair a row with selected="{service_label}" and count={expected}. Do not treat a {service_label} row as satisfying any other requested service label.'
                )
        elif target.startswith('Traffic Pattern:'):
            pattern_label = target.split(':', 1)[1].strip()
            retry_lines.append(
                'Add or repair Traffic rows so the requested exact traffic patterns are present at the requested counts before finishing. When multiple patterns are requested, create rows with those exact pattern labels instead of repeating one pattern for all requested counts, and include each missing pattern explicitly rather than duplicating another pattern.'
            )
            if pattern_label:
                retry_lines.append(
                    f'Use scenario.add_traffic_item to add or repair row(s) with pattern="{pattern_label}", content_type="text", and count={expected}. Preserve distinct pattern labels across rows.'
                )
        elif target.startswith('Traffic:'):
            protocol_label = target.split(':', 1)[1].strip()
            retry_lines.append(
                'Add or repair Traffic rows so the requested traffic protocol labels and exact counts are present before finishing. Create distinct rows for distinct requested protocols and do not reuse one protocol label to satisfy another requested protocol.'
            )
            if protocol_label:
                retry_lines.append(
                    f'Use scenario.add_traffic_item to add or repair row(s) with selected="{protocol_label}", content_type="text", and count={expected}. Do not treat a {protocol_label} row as satisfying another requested protocol label.'
                )
        elif target.startswith('Segmentation:'):
            retry_lines.append(
                'Add or repair Segmentation rows so the requested segmentation control labels and exact counts are present before finishing.'
            )
        elif target == 'Traffic':
            retry_lines.append(
                'Add the missing Traffic rows before finishing. Use selected="TCP" or "UDP", one exact pattern, and either v_count or a positive factor.'
            )
        elif target == 'Services':
            retry_lines.append(
                'Add the missing Services rows before finishing. Use only schema-backed service labels.'
            )
        elif target == 'Segmentation':
            retry_lines.append(
                'Add the missing Segmentation rows before finishing. Use schema-backed values and dedicated mutation tools when available.'
            )
        elif target == 'Docker':
            retry_lines.append(
                'Add the missing Docker host rows before finishing. Docker host requests must become Node Information rows with selected="Docker" and an explicit count when available.'
            )
    for item in missing_values:
        target = str(item.get('target') or '').strip()
        field = str(item.get('field') or '').strip()
        missing_value_names = ', '.join(str(value or '').strip() for value in (item.get('missing_values') or []) if str(value or '').strip())
        actual_value_names = ', '.join(str(value or '').strip() for value in (item.get('actual_values') or []) if str(value or '').strip()) or 'none'
        reason = str(item.get('reason') or '').strip()
        retry_lines.append(
            f'Missing value coverage: {target} is missing requested {field}: {missing_value_names}. Current values: {actual_value_names}. {reason}.'
        )
        if target == 'Traffic' and field == 'selected_values':
            retry_lines.append('Add Traffic rows that explicitly use the missing selected protocol values before finishing. If both TCP and UDP were requested, include both labels rather than repeating only one of them.')
            missing_protocols = [str(value or '').strip() for value in (item.get('missing_values') or []) if str(value or '').strip()]
            if missing_protocols:
                retry_lines.append(
                    f'Use scenario.add_traffic_item for the missing protocol labels: {_quote_csv(missing_protocols)}. Set content_type="text" unless the user asked for another traffic content type.'
                )
        elif target == 'Traffic' and field == 'pattern_values':
            retry_lines.append('Add or repair Traffic rows so the missing exact traffic patterns are present before finishing. If multiple patterns were requested, include each missing pattern explicitly rather than duplicating another pattern.')
            missing_patterns = [str(value or '').strip() for value in (item.get('missing_values') or []) if str(value or '').strip()]
            if missing_patterns:
                retry_lines.append(
                    f'Use scenario.add_traffic_item for the missing pattern labels: {_quote_csv(missing_patterns)}. Set content_type="text" unless the user asked for another traffic content type.'
                )
        elif target == 'Routing' and field == 'r2r_density_values':
            retry_lines.append('Add or repair Routing rows so the router-to-router density semantics match the request before finishing.')
        elif target == 'Routing':
            retry_lines.append('Add or repair Routing rows so the requested routing protocols are present before finishing.')
        elif target == 'Node Information' and field == 'role_count_values':
            retry_lines.append('Add or repair Node Information rows so the requested host-role counts are present before finishing.')
        elif target == 'Services':
            retry_lines.append('Add or repair Services rows so the requested services are present before finishing. If multiple service labels were requested, include each missing label explicitly rather than duplicating another service row.')
            missing_services = [str(value or '').strip() for value in (item.get('missing_values') or []) if str(value or '').strip()]
            if missing_services:
                retry_lines.append(
                    f'Use scenario.add_service_item for the missing service labels: {_quote_csv(missing_services)}.'
                )
        elif target == 'Segmentation':
            retry_lines.append('Add or repair Segmentation rows so the requested segmentation controls are present before finishing.')
        elif target == 'Vulnerabilities':
            retry_lines.append('Add or repair Vulnerabilities rows so the requested vulnerability coverage is present before finishing.')
    retry_lines.append('Fix every missing requirement before you finish, then preview again.')
    return prompt + '\n'.join(retry_lines)


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


def _build_count_mismatch_retry_prompt(prompt: str, mismatch: dict[str, Any], *, user_prompt: str | None = None) -> str:
    requested_total_nodes = mismatch.get('requested_total_nodes')
    requested_router_count = mismatch.get('requested_router_count')
    expected_host_count = mismatch.get('expected_host_count')
    actual_routers = mismatch.get('actual_routers')
    actual_hosts = mismatch.get('actual_hosts')
    actual_switches = mismatch.get('actual_switches')
    reasons = mismatch.get('reasons') if isinstance(mismatch.get('reasons'), list) else []
    vulnerability_target_count = _extract_vulnerability_target_count(user_prompt or prompt)

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
    if expected_host_count is not None and vulnerability_target_count > 0:
        explicit_host_total = _explicit_host_role_count_total(user_prompt or prompt)
        if explicit_host_total >= int(expected_host_count):
            retry_lines.append(
                'The explicit host-role counts already consume the full requested host budget. Repair the draft by placing the requested vulnerabilities on those existing hosts instead of adding extra Docker host rows.'
            )
        else:
            remaining_non_vuln_hosts = max(0, int(expected_host_count) - vulnerability_target_count)
            retry_lines.append(
                f'The prompt also asks for {vulnerability_target_count} vulnerability target(s). Reserve those as Docker host slots inside the {expected_host_count}-host total; unless you already add those Docker hosts explicitly, keep the other Node Information host rows to {remaining_non_vuln_hosts} so the repaired preview still lands on the requested counts.'
            )
        retry_lines.append(
            'Search broad vulnerability requests with free-text only. Do not pass v_type or v_vector filters unless the user explicitly asked for those exact filters.'
        )
    for line in _build_mcp_bridge_execution_guidance(user_prompt or prompt):
        retry_lines.append(line)
    retry_lines.append('Fix the draft so the next preview matches those explicit counts exactly before you finish.')
    return prompt + '\n'.join(retry_lines)


def _build_prompt_repair_decision(
    *,
    prompt: str,
    user_prompt: str | None = None,
    exc: ProviderAdapterError | None = None,
    mismatch: dict[str, Any] | None = None,
) -> _McpBridgeRepairDecision:
    if exc is not None and _is_ollama_tool_parse_error(exc):
        return _McpBridgeRepairDecision(
            category='ollama-tool-parse-error',
            retryable=True,
            status_message='Retrying after Ollama tool-call parse failure...',
            retry_prompt=_build_mcp_bridge_tool_parse_retry_prompt(prompt, user_prompt=user_prompt),
        )
    if isinstance(mismatch, dict):
        if isinstance(mismatch.get('missing'), list):
            return _McpBridgeRepairDecision(
                category='prompt-coverage-mismatch',
                retryable=True,
                status_message='The draft missed requested prompt items. Retrying once with stricter coverage guidance...',
                retry_prompt=_build_prompt_coverage_retry_prompt(prompt, mismatch),
            )
        return _McpBridgeRepairDecision(
            category='count-intent-mismatch',
            retryable=True,
            status_message='Preview counts did not match the requested totals. Retrying once with stricter count guidance...',
            retry_prompt=_build_count_mismatch_retry_prompt(prompt, mismatch, user_prompt=user_prompt),
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
    if tool_name == 'scenario.add_service_item' or (tool_name == 'scenario.replace_section' and section_name == 'services'):
        return 'service-tool-error', f'Auto-healing a service tool error for {qualified_tool_name}.'
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
    count_retry_used = False
    coverage_retry_count = 0
    final_mismatch: dict[str, Any] | None = None
    final_coverage_mismatch: dict[str, Any] | None = None

    for _ in range(4):
        if cancel_check and cancel_check():
            raise ProviderAdapterError('Generation cancelled by user.', status_code=499)
        model_response = await _mcp_bridge_process_query_server_side(
            client,
            prompt=current_prompt,
            model=model,
            user_prompt=user_prompt,
            initial_draft_id=draft_id,
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
        scenario_payload = draft_payload.get('scenario') if isinstance(draft_payload.get('scenario'), dict) else {}
        final_mismatch = _get_count_intent_mismatch(
            user_prompt,
            previewed.get('preview') if isinstance(previewed.get('preview'), dict) else {},
        )
        final_coverage_mismatch = _get_prompt_coverage_mismatch(user_prompt, scenario_payload)
        if final_mismatch and not count_retry_used:
            count_retry_used = True
            repair = _build_prompt_repair_decision(prompt=prompt, user_prompt=user_prompt, mismatch=final_mismatch)
            if emit is not None and repair.status_message:
                emit('status', message=repair.status_message)
            current_prompt = repair.retry_prompt or prompt
            draft_id = effective_draft_id
            continue
        if final_coverage_mismatch and coverage_retry_count < 2:
            coverage_retry_count += 1
            repair = _build_prompt_repair_decision(prompt=prompt, user_prompt=user_prompt, mismatch=final_coverage_mismatch)
            if emit is not None and repair.status_message:
                emit('status', message=repair.status_message)
            current_prompt = repair.retry_prompt or current_prompt
            draft_id = effective_draft_id
            continue
        return {
            'prompt_used': current_prompt,
            'provider_response': model_response,
            'draft_payload': draft_payload,
            'previewed': previewed,
            'count_intent_mismatch': final_mismatch,
            'count_intent_retry_used': count_retry_used,
            'prompt_coverage_mismatch': final_coverage_mismatch,
            'prompt_coverage_retry_used': coverage_retry_count > 0,
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

    def normalize_service_for_retry(item: dict[str, Any]) -> str:
        for key in ('selected', 'service', 'name', 'type', 'kind'):
            normalized = app_backend._normalize_service_item_selection(item.get(key))
            if normalized:
                return normalized
        message_lower = message.lower()
        if 'https' in message_lower or 'http' in message_lower or 'web' in message_lower:
            return 'HTTP'
        if 'dhcp' in message_lower:
            return 'DHCPClient'
        if 'ssh' in message_lower:
            return 'SSH'
        return 'HTTP'

    service_selection_error = any(fragment in message.lower() for fragment in (
        'selected or service must be one of:',
        'services selected must be one of:',
        'service must be one of:',
        'selected must be one of: ssh, http, dhcpclient, or random',
    ))
    service_replace_error = tool_name.endswith('scenario.replace_section') and str((tool_args or {}).get('section_name') or '').strip().lower() == 'services' and service_selection_error
    service_add_error = tool_name.endswith('scenario.add_service_item') and service_selection_error
    if service_replace_error or service_add_error:
        enabled = [str(name or '').strip() for name in (enabled_tool_names or []) if str(name or '').strip()]
        add_service_available = any(name.endswith('scenario.add_service_item') for name in enabled)
        replace_section_available = any(name.endswith('scenario.replace_section') for name in enabled)

        item = None
        if service_add_error:
            item = tool_args if isinstance(tool_args, dict) else {}
        else:
            payload = tool_args.get('section_payload') if isinstance(tool_args, dict) else None
            items = payload.get('items') if isinstance(payload, dict) and isinstance(payload.get('items'), list) else []
            item = items[0] if items and isinstance(items[0], dict) else {}
        item = item if isinstance(item, dict) else {}

        retry_service = normalize_service_for_retry(item)
        count_raw = item.get('v_count') if item.get('v_count') not in (None, '') else item.get('count')
        try:
            count = max(1, int(count_raw)) if count_raw not in (None, '') else 1
        except Exception:
            count = 1

        guidance = (
            'Services rows must use one exact canonical label: SSH, HTTP, or DHCPClient. '
            'Normalize aliases such as https/web to HTTP and dhcp to DHCPClient. '
            f'Retry with selected="{retry_service}" and count={count}. '
            'Do not use free-text service labels or generic placeholders inside the Services section.'
        )

        if add_service_available or not enabled:
            return json.dumps({
                'error': message,
                'recoverable': True,
                'guidance': guidance,
                'retry_hint': {
                    'tool': 'scenario.add_service_item',
                    'selected': retry_service,
                    'count': count,
                },
            })
        if replace_section_available:
            return json.dumps({
                'error': message,
                'recoverable': True,
                'guidance': guidance,
                'retry_hint': {
                    'tool': 'scenario.replace_section',
                    'section_name': 'Services',
                    'section_payload': {
                        'items': [{
                            'selected': retry_service,
                            'v_metric': 'Count',
                            'v_count': count,
                            'factor': 1.0,
                        }],
                    },
                },
            })
        return None

    vulnerability_catalog_error = 'specific vulnerability must match an enabled catalog entry by v_path or v_name' in message.lower()
    if tool_name.endswith('scenario.add_vulnerability_item') and vulnerability_catalog_error:
        enabled = [str(name or '').strip() for name in (enabled_tool_names or []) if str(name or '').strip()]
        search_available = any(name.endswith('scenario.search_vulnerability_catalog') for name in enabled)
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
        try:
            count = max(1, int((tool_args or {}).get('v_count') or 1))
        except Exception:
            count = 1

        guidance = (
            'Do not invent a Specific vulnerability name/path for broad category requests. '
            'Search the vulnerability catalog using the user\'s wording and, when available, README-backed catalog context. '
            'Then add only concrete Specific vulnerability rows with explicit v_name and v_path from the chosen catalog matches.'
        )

        if search_available:
            return json.dumps({
                'error': message,
                'recoverable': True,
                'guidance': guidance,
                'retry_hint': {
                    'tool': 'scenario.search_vulnerability_catalog',
                    'query': raw_query or 'vulnerability',
                    'limit': max(5, count * 3),
                },
            })

        return json.dumps({
            'error': message,
            'recoverable': True,
            'guidance': guidance,
        })

    traffic_pattern_error = 'pattern must be one of: continuous, periodic, burst, poisson, or ramp' in message.lower()
    traffic_content_type_error = 'content_type must be one of: text, photo, audio, video, or gibberish' in message.lower()
    traffic_replace_error = tool_name.endswith('scenario.replace_section') and str((tool_args or {}).get('section_name') or '').strip().lower() == 'traffic' and ('traffic pattern must be one of:' in message.lower() or traffic_content_type_error)
    traffic_add_error = tool_name.endswith('scenario.add_traffic_item') and (traffic_pattern_error or traffic_content_type_error)
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
        retry_content_type = app_backend._normalize_traffic_content_type_value(item.get('content_type') or item.get('content')) or 'text'
        count_raw = item.get('v_count') if item.get('v_count') not in (None, '') else item.get('count')
        try:
            count = max(1, int(count_raw)) if count_raw not in (None, '') else 1
        except Exception:
            count = 1

        guidance_parts = []
        if traffic_pattern_error:
            guidance_parts.append(
                'Traffic rows must use exact pattern values: continuous, periodic, burst, poisson, or ramp. '
                'For varied traffic profiles, create multiple Traffic rows and give each row one exact pattern value rather than vague free text such as "various" or non-canonical labels.'
            )
        if traffic_content_type_error:
            guidance_parts.append(
                'Traffic rows must set content_type to one of: text, photo, audio, video, or gibberish. '
                'If the user did not request a specific content type, use content_type="text".'
            )
        guidance = ' '.join(guidance_parts).strip()
        if not guidance:
            guidance = 'Traffic rows must satisfy the schema-backed Traffic item contract.'
        guidance += f' Retry with pattern="{retry_pattern}" and content_type="{retry_content_type}" for this row.'

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
                    'content_type': retry_content_type,
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
                            'content_type': retry_content_type,
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
    if bridge_mode in _SUPPORTED_AI_BRIDGE_MODE_ALIASES:
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
    supports_mcp_bridge: bool = False

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
            'supports_mcp_bridge': self.supports_mcp_bridge,
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


def _build_request_headers(*, extra_headers: dict[str, str] | None = None) -> dict[str, str]:
    headers = {'Accept': 'application/json'}
    if isinstance(extra_headers, dict):
        for key, value in extra_headers.items():
            key_text = str(key or '').strip()
            value_text = str(value or '').strip()
            if key_text and value_text:
                headers[key_text] = value_text
    return headers


def _fetch_json(url: str, *, timeout: float, headers: dict[str, str] | None = None) -> dict[str, Any]:
    request_obj = Request(url, headers=_build_request_headers(extra_headers=headers))
    payload = _run_with_wall_clock_timeout(
        lambda: _read_response_text(request_obj, timeout=timeout),
        timeout_seconds=timeout,
    )
    data = json.loads(payload)
    if not isinstance(data, dict):
        raise ValueError('Provider returned a non-object JSON payload.')
    return data


def _post_json(url: str, payload: dict[str, Any], *, timeout: float, headers: dict[str, str] | None = None) -> dict[str, Any]:
    body = json.dumps(payload).encode('utf-8')
    request_obj = Request(
        url,
        data=body,
        headers={**_build_request_headers(extra_headers=headers), 'Content-Type': 'application/json'},
        method='POST',
    )
    raw = _run_with_wall_clock_timeout(
        lambda: _read_response_text(request_obj, timeout=timeout),
        timeout_seconds=timeout,
    )
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError('Provider returned a non-object JSON payload.')
    return data


def _read_response_text(request_obj: Request, *, timeout: float) -> str:
    with urlopen(request_obj, timeout=timeout) as response:
        return response.read().decode('utf-8')


def _run_with_wall_clock_timeout(func: Callable[[], Any], *, timeout_seconds: float) -> Any:
    result_queue: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=1)

    def _worker() -> None:
        try:
            result_queue.put(('result', func()))
        except BaseException as exc:  # pragma: no cover - propagated to caller
            result_queue.put(('error', exc))

    worker = threading.Thread(target=_worker, daemon=True)
    worker.start()
    worker.join(timeout_seconds)
    if worker.is_alive():
        raise URLError(TimeoutError(f'timed out after {timeout_seconds:.0f}s (wall clock)'))

    try:
        outcome, value = result_queue.get_nowait()
    except queue.Empty:
        raise URLError(TimeoutError(f'timed out after {timeout_seconds:.0f}s (wall clock)'))

    if outcome == 'error':
        raise value
    return value


def _stream_json_lines(
    url: str,
    payload: dict[str, Any],
    *,
    timeout: float,
    headers: dict[str, str] | None = None,
    cancellation_check: Callable[[], bool] | None = None,
    on_open: Callable[[Any], None] | None = None,
):
    body = json.dumps(payload).encode('utf-8')
    request_obj = Request(
        url,
        data=body,
        headers={**_build_request_headers(extra_headers=headers), 'Content-Type': 'application/json'},
        method='POST',
    )
    event_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
    stop_event = threading.Event()

    def _worker() -> None:
        try:
            with urlopen(request_obj, timeout=timeout) as response:
                if callable(on_open):
                    on_open(response)
                event_queue.put(('opened', None))
                for raw_line in response:
                    if stop_event.is_set():
                        break
                    event_queue.put(('line', raw_line))
        except BaseException as exc:  # pragma: no cover - surfaced to caller
            event_queue.put(('error', exc))
        finally:
            event_queue.put(('done', None))

    worker = threading.Thread(target=_worker, daemon=True)
    worker.start()
    deadline = time.monotonic() + timeout

    while True:
        if cancellation_check and cancellation_check():
            stop_event.set()
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            stop_event.set()
            raise URLError(TimeoutError(f'timed out after {timeout:.0f}s (wall clock)'))
        try:
            event_type, event_value = event_queue.get(timeout=min(0.25, remaining))
        except queue.Empty:
            continue
        if event_type == 'opened':
            continue
        if event_type == 'line':
            line = event_value.decode('utf-8').strip()
            if not line:
                continue
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                yield parsed
            continue
        if event_type == 'error':
            raise event_value
        if event_type == 'done':
            break


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


def _is_ollama_direct_json_generation_failure(exc: ProviderAdapterError | None) -> bool:
    if exc is None:
        return False
    message = str(getattr(exc, 'message', '') or '').strip().lower()
    return 'ollama did not return valid json for scenario generation' in message


def _build_bridge_fallback_payload(payload: dict[str, Any]) -> dict[str, Any]:
    next_payload = dict(payload or {})
    next_payload['bridge_mode'] = _CANONICAL_AI_BRIDGE_MODE
    next_payload.pop('skip_bridge', None)
    return next_payload


def _should_use_mcp_bridge_for_request(adapter: ProviderAdapter, payload: dict[str, Any], *, skip_bridge: bool) -> bool:
    if skip_bridge or not adapter.capability.supports_mcp_bridge:
        return False
    provider = str(payload.get('provider') or getattr(adapter.capability, 'provider', '') or '').strip().lower()
    if provider == 'ollama':
        has_bridge_config = any([
            str(payload.get('mcp_server_path') or '').strip(),
            str(payload.get('mcp_server_url') or '').strip(),
            str(payload.get('servers_json_path') or '').strip(),
            bool(payload.get('auto_discovery')),
        ])
        return has_bridge_config or _is_mcp_python_sdk_bridge_mode(payload.get('bridge_mode'))
    return _is_mcp_python_sdk_bridge_mode(payload.get('bridge_mode'))


def _payload_bool(raw_value: Any, *, default: bool) -> bool:
    if raw_value is None:
        return default
    if isinstance(raw_value, bool):
        return raw_value
    text = str(raw_value or '').strip().lower()
    if text in {'1', 'true', 'yes', 'on'}:
        return True
    if text in {'0', 'false', 'no', 'off'}:
        return False
    return default


def _normalize_litellm_base_url(raw_value: Any, *, enforce_ssl: bool) -> str:
    base_url = _normalize_base_url(raw_value)
    parsed = urlparse(base_url)
    if enforce_ssl and (parsed.scheme or '').lower() != 'https':
        raise ValueError('Base URL must use https when Enforce SSL is enabled.')
    return base_url


def _litellm_request_headers(api_key: Any) -> dict[str, str] | None:
    key_text = str(api_key or '').strip()
    if not key_text:
        return None
    return {'Authorization': f'Bearer {key_text}'}


def _litellm_models_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    path = (parsed.path or '').rstrip('/')
    if path.endswith('/v1'):
        return f'{base_url}/models'
    return f'{base_url}/v1/models'


def _litellm_chat_completions_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    path = (parsed.path or '').rstrip('/')
    if path.endswith('/v1'):
        return f'{base_url}/chat/completions'
    return f'{base_url}/v1/chat/completions'


def _extract_litellm_message_text(raw_payload: dict[str, Any]) -> str:
    choices = raw_payload.get('choices') if isinstance(raw_payload.get('choices'), list) else []
    if not choices:
        return ''
    message = choices[0].get('message') if isinstance(choices[0], dict) else {}
    content = message.get('content') if isinstance(message, dict) else ''
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                if item.strip():
                    parts.append(item.strip())
                continue
            if not isinstance(item, dict):
                continue
            item_type = str(item.get('type') or '').strip().lower()
            if item_type in {'text', 'output_text'}:
                text = str(item.get('text') or '').strip()
                if text:
                    parts.append(text)
        return '\n'.join(parts).strip()
    return str(content or '').strip()


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


def _build_ai_seed_scenario_for_prompt(current_scenario: dict[str, Any], user_prompt: str | None = None) -> dict[str, Any]:
    seed_scenario = _build_ai_seed_scenario(current_scenario)
    if not str(user_prompt or '').strip():
        return seed_scenario
    compiled = _compile_ai_intent(user_prompt)
    return apply_compiled_sections_to_scenario(seed_scenario, compiled)


def _overlay_compiled_intent_sections(scenario_payload: dict[str, Any], user_prompt: str | None = None) -> dict[str, Any]:
    if not str(user_prompt or '').strip():
        return scenario_payload
    compiled = _compile_ai_intent(user_prompt)
    result = apply_compiled_sections_to_scenario(scenario_payload, compiled)
    if 'Routing' not in compiled.locked_sections:
        return result

    sections = result.get('sections') if isinstance(result.get('sections'), dict) else {}
    node_information = sections.get('Node Information') if isinstance(sections.get('Node Information'), dict) else None
    if not isinstance(node_information, dict):
        return result

    items = node_information.get('items') if isinstance(node_information.get('items'), list) else []
    filtered_items = []
    for item in items:
        if not isinstance(item, dict):
            continue
        selection = app_backend._normalize_routing_item_selection(item.get('selected'))
        if selection:
            continue
        filtered_items.append(item)

    if len(filtered_items) == len(items):
        return result

    next_sections = deepcopy(sections)
    next_node_information = deepcopy(node_information)
    next_node_information['items'] = filtered_items
    next_sections['Node Information'] = next_node_information
    result['sections'] = next_sections
    return result


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


def _canonicalize_generated_routing_modes(scenario_payload: dict[str, Any]) -> dict[str, Any]:
    sections = scenario_payload.get('sections') if isinstance(scenario_payload.get('sections'), dict) else {}
    routing_section = sections.get('Routing') if isinstance(sections.get('Routing'), dict) else None
    if not routing_section:
        return scenario_payload
    items = routing_section.get('items') if isinstance(routing_section.get('items'), list) else None
    if items is None:
        return scenario_payload

    canonical_modes = {
        'min': 'Min',
        'uniform': 'Uniform',
        'exact': 'Exact',
        'nonuniform': 'NonUniform',
    }
    next_items: list[Any] = []
    changed = False
    for raw_item in items:
        if not isinstance(raw_item, dict):
            next_items.append(raw_item)
            continue
        item = deepcopy(raw_item)
        for mode_key in ('r2r_mode', 'r2s_mode'):
            raw_mode = str(item.get(mode_key) or '').strip()
            canonical = canonical_modes.get(raw_mode.lower())
            if canonical and canonical != raw_mode:
                item[mode_key] = canonical
                changed = True
        next_items.append(item)
    if not changed:
        return scenario_payload

    next_payload = deepcopy(scenario_payload)
    next_sections = next_payload.get('sections') if isinstance(next_payload.get('sections'), dict) else {}
    next_routing = next_sections.get('Routing') if isinstance(next_sections.get('Routing'), dict) else {}
    next_routing['items'] = next_items
    next_sections['Routing'] = next_routing
    next_payload['sections'] = next_sections
    return next_payload


def _build_intent_compiler_guidance(compiled: Any, *, strict_json: bool = False) -> list[str]:
    locked_sections = tuple(
        str(section_name or '').strip()
        for section_name in (getattr(compiled, 'locked_sections', ()) or ())
        if str(section_name or '').strip()
    )
    if not locked_sections:
        return []

    section_list = ', '.join(locked_sections)
    guidance = [
        f'Treat compiler-seeded sections in the template as authoritative for explicit structured requests: {section_list}.',
    ]
    if strict_json:
        guidance.append('Do not remove or rewrite those seeded rows unless the user request clearly requires different values.')
    else:
        guidance.append('Preserve those seeded rows unless the user request clearly requires different values.')
    guidance.append('Prefer filling missing optional details around the seeded template instead of re-authoring compiler-managed rows from scratch.')

    locked_set = set(locked_sections)
    if 'Routing' in locked_set:
        guidance.extend([
            'If routers are requested, Routing v_count is router quantity, while r2r_* and r2s_* fields are connectivity hints.',
            'There is no r2h field. Map router-to-host wording to Routing r2s_* fields.',
        ])
    if 'Traffic' in locked_set:
        guidance.append('If you add or adjust traffic rows beyond the seed, use selected="TCP" or "UDP" and backend-supported pattern labels only.')
    if 'Vulnerabilities' in locked_set:
        guidance.append('If you add or adjust vulnerabilities beyond the seed, use concrete Specific rows with explicit v_name and v_path from catalog matches.')
    return guidance


def _build_ollama_prompt(current_scenario: dict[str, Any], user_prompt: str) -> str:
    template = _build_ai_seed_scenario_for_prompt(current_scenario, user_prompt)
    compiled = _compile_ai_intent(user_prompt)
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
            'Do not leave prior scenario rows in place unless they are explicitly requested in the prompt.',
            'Do not include markdown, commentary, or code fences.',
            *_build_intent_compiler_guidance(compiled),
            *_build_count_intent_guidance(user_prompt),
        ],
        'section_expectations': {
            'Node Information': 'items contain selected, factor, and optional v_metric/v_count. Use selected="Docker" for docker hosts. Use v_metric="Count" with v_count for explicit host counts.',
            'Routing': 'items contain selected, factor, optional v_metric/v_count for router counts, and optional r2r_mode/r2r_edges/r2s_mode/r2s_edges/r2s_hosts_min/r2s_hosts_max. v_count is the number of routers. r2r_edges is router-to-router link density. r2s_edges and r2s_hosts_* describe router-to-segment attachment density.',
            'Services': 'items contain selected and factor.',
            'Traffic': 'items contain selected, factor, pattern, rate_kbps, period_s, jitter_pct, content_type. Use selected="TCP" or "UDP" plus either v_metric="Count" with v_count or a positive factor so traffic flows materialize.',
            'Vulnerabilities': 'items contain selected plus vulnerability fields such as v_metric, v_count, v_name, and v_path. Prefer concrete Specific rows chosen from the vulnerability catalog.',
            'Segmentation': 'items contain selected and factor.',
        },
        'user_request': user_prompt,
        'template': template,
    }
    if compiled.applied_actions:
        rules['intent_compiler_seed'] = compiled.applied_actions
    return json.dumps(rules, indent=2)


def _build_ollama_repair_prompt(current_scenario: dict[str, Any], user_prompt: str, raw_generation: str) -> str:
    template = _build_ai_seed_scenario_for_prompt(current_scenario, user_prompt)
    compiled = _compile_ai_intent(user_prompt)
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
            *_build_intent_compiler_guidance(compiled),
            *_build_count_intent_guidance(user_prompt),
        ],
        'user_request': user_prompt,
        'template': template,
        'previous_invalid_response': raw_generation[:4000],
    }
    if compiled.applied_actions:
        rules['intent_compiler_seed'] = compiled.applied_actions
    return json.dumps(rules, indent=2)


def _build_ollama_strict_json_repair_prompt(current_scenario: dict[str, Any], user_prompt: str, raw_generation: str) -> str:
    template = _build_ai_seed_scenario_for_prompt(current_scenario, user_prompt)
    compiled = _compile_ai_intent(user_prompt)
    template.pop('hitl', None)
    template.pop('flow_state', None)
    template.pop('plan_preview', None)
    template.pop('ai_generator', None)
    template.pop('_sid', None)
    rules = {
        'instructions': [
            'Return exactly one valid JSON object and nothing else.',
            'Do not output commentary, explanations, markdown, code fences, or schema notes.',
            'Do not repeat phrases like "Return JSON only" or "Top-level object must be" in the output.',
            'The output must start with { and end with }.',
            'The only allowed top-level key is "scenario".',
            'Use the clean template and fill only backend-compatible values.',
            'If some details are missing, keep the template structure valid and leave optional arrays empty rather than adding prose.',
            'For explicit host counts, use Node Information items with v_metric="Count" and v_count.',
            'For explicit router counts, use Routing items with v_metric="Count" and v_count.',
            *_build_intent_compiler_guidance(compiled, strict_json=True),
            *_build_count_intent_guidance(user_prompt),
        ],
        'required_output_shape': {
            'scenario': template,
        },
        'user_request': user_prompt,
        'previous_invalid_response': raw_generation[:4000],
    }
    if compiled.applied_actions:
        rules['intent_compiler_seed'] = compiled.applied_actions
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
    return _normalize_local_path(raw_value)


def _build_bridge_stage_details(*, stage: str, started_at: float, draft_id: str = '') -> dict[str, Any]:
    details: dict[str, Any] = {
        'bridge_stage': stage,
        'bridge_elapsed_seconds': round(max(0.0, time.monotonic() - started_at), 2),
    }
    if draft_id:
        details['draft_id'] = draft_id
    return details


def _build_bridge_query_state_details(client: Any) -> dict[str, Any]:
    state = getattr(client, 'query_debug_state', None)
    if not isinstance(state, dict) or not state:
        return {}
    details: dict[str, Any] = {}
    phase = str(state.get('phase') or '').strip()
    if phase:
        details['bridge_query_phase'] = phase
    phase_started_at = state.get('phase_started_at')
    if isinstance(phase_started_at, (int, float)):
        details['bridge_query_phase_elapsed_seconds'] = round(max(0.0, time.monotonic() - float(phase_started_at)), 2)
    iteration = state.get('iteration')
    if isinstance(iteration, int):
        details['bridge_query_iteration'] = iteration
    message_count = state.get('message_count')
    if isinstance(message_count, int):
        details['bridge_query_message_count'] = message_count
    last_tool_name = str(state.get('last_tool_name') or '').strip()
    if last_tool_name:
        details['bridge_last_tool_name'] = last_tool_name
    last_tool_stage = str(state.get('last_tool_stage') or '').strip()
    if last_tool_stage:
        details['bridge_last_tool_stage'] = last_tool_stage
    last_tool_args = state.get('last_tool_args')
    if isinstance(last_tool_args, dict) and last_tool_args:
        details['bridge_last_tool_args'] = {
            str(key): last_tool_args[key]
            for key in list(last_tool_args.keys())[:8]
        }
    llm_mode = str(state.get('llm_mode') or '').strip()
    if llm_mode:
        details['bridge_llm_mode'] = llm_mode
    current_draft_id = str(state.get('current_draft_id') or '').strip()
    if current_draft_id:
        details['bridge_current_draft_id'] = current_draft_id
    return details


def _append_provider_attempt(
    provider_attempts: list[dict[str, Any]],
    *,
    attempt: str,
    format_mode: str = '',
    started_at: float,
    status: str,
    response: str = '',
    error: str = '',
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        'attempt': attempt,
        'status': status,
        'elapsed_seconds': round(max(0.0, time.monotonic() - started_at), 2),
    }
    if format_mode:
        entry['format_mode'] = format_mode
    if response or status == 'completed':
        entry['response'] = response
    if error:
        entry['error'] = error[:4000]
    provider_attempts.append(entry)
    return entry


def _build_provider_generation_error_details(
    *,
    provider: str,
    stage: str,
    started_at: float,
    base_url: str = '',
    model: str = '',
    timeout_seconds: float | None = None,
    attempt: str = '',
    provider_attempts: list[dict[str, Any]] | None = None,
    error_category: str = '',
) -> dict[str, Any]:
    details: dict[str, Any] = {
        'provider_generation_stage': stage,
        'provider_generation_elapsed_seconds': round(max(0.0, time.monotonic() - started_at), 2),
        'provider': provider,
    }
    if base_url:
        details['base_url'] = base_url
    if model:
        details['model'] = model
    if isinstance(timeout_seconds, (int, float)):
        details['timeout_seconds'] = float(timeout_seconds)
    if attempt:
        details['provider_current_attempt'] = attempt
    if provider_attempts:
        details['provider_attempts'] = provider_attempts
    if error_category:
        details['provider_error_category'] = error_category
    return details


def _augment_provider_error_for_bridge_stage(
    exc: BaseException,
    *,
    stage: str,
    started_at: float,
    fallback: str,
    draft_id: str = '',
    client: Any | None = None,
) -> ProviderAdapterError:
    details = _build_bridge_stage_details(stage=stage, started_at=started_at, draft_id=draft_id)
    details.update(_build_bridge_query_state_details(client))
    if isinstance(exc, ProviderAdapterError):
        merged_details = dict(getattr(exc, 'details', {}) or {})
        merged_details.setdefault('bridge_stage', details['bridge_stage'])
        merged_details.setdefault('bridge_elapsed_seconds', details['bridge_elapsed_seconds'])
        if draft_id:
            merged_details.setdefault('draft_id', draft_id)
        for key, value in details.items():
            merged_details.setdefault(key, value)
        return ProviderAdapterError(exc.message, status_code=exc.status_code, details=merged_details)
    return ProviderAdapterError(
        _describe_mcp_bridge_base_exception(exc, fallback=fallback),
        status_code=502,
        details=details,
    )


def _normalize_mcp_bridge_payload(payload: dict[str, Any]) -> dict[str, Any]:
    bridge_mode = _normalize_ai_bridge_mode(payload.get('bridge_mode'))

    mcp_server_path = _normalize_local_path(payload.get('mcp_server_path'))
    mcp_server_url = str(payload.get('mcp_server_url') or '').strip()
    servers_json_path = _normalize_mcp_servers_json_path(payload.get('servers_json_path'))
    auto_discovery = bool(payload.get('auto_discovery'))
    if not any([mcp_server_path, mcp_server_url, servers_json_path, auto_discovery]):
        mcp_server_path = _DEFAULT_MCP_SERVER_PATH

    if mcp_server_path and not os.path.exists(mcp_server_path):
        raise ProviderAdapterError(f'MCP server script not found: {mcp_server_path}', status_code=400)
    if servers_json_path and not os.path.exists(servers_json_path):
        raise ProviderAdapterError(f'servers_json_path not found: {servers_json_path}', status_code=400)

    enabled_tools_specified = 'enabled_tools' in payload
    enabled_tools = _normalize_tool_selection(payload.get('enabled_tools'))
    hil_enabled_raw = payload.get('hil_enabled')
    if hil_enabled_raw is None:
        hil_enabled = _env_flag('CORETG_MCP_PYTHON_SDK_HIL_ENABLED', False)
    else:
        hil_enabled = bool(hil_enabled_raw)
    return {
        'bridge_mode': bridge_mode,
        'mcp_server_path': mcp_server_path,
        'mcp_server_url': mcp_server_url,
        'servers_json_path': servers_json_path,
        'auto_discovery': auto_discovery,
        'enabled_tools': enabled_tools,
        'enabled_tools_specified': enabled_tools_specified,
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


_LLM_TOOL_PROPERTY_ALLOWLISTS: dict[str, set[str]] = {
    'scenario.add_node_role_item': {'selected', 'count', 'factor'},
    'scenario.add_service_item': {'selected', 'count', 'factor', 'density'},
    'scenario.add_routing_item': {
        'selected', 'protocol', 'count', 'factor', 'density',
        'r2r_mode', 'r2r_edges', 'r2s_mode', 'r2s_edges', 'r2s_hosts_min', 'r2s_hosts_max',
    },
    'scenario.add_traffic_item': {
        'selected', 'protocol', 'count', 'factor', 'density',
        'pattern', 'rate_kbps', 'period_s', 'jitter_pct', 'content_type',
    },
    'scenario.add_segmentation_item': {'selected', 'count', 'factor', 'density'},
    'scenario.add_vulnerability_item': {'v_name', 'v_path', 'v_type', 'v_vector', 'v_count'},
}


def _is_draft_scoped_mcp_bridge_tool(qualified_tool_name: Any) -> bool:
    name = str(qualified_tool_name or '').strip()
    if not name or '.scenario.' not in name:
        return False
    return not name.endswith('scenario.create_draft') and not name.endswith('scenario.search_vulnerability_catalog')


def _build_llm_chat_tool_schema(qualified_tool_name: str, input_schema: dict[str, Any]) -> dict[str, Any]:
    schema = deepcopy(input_schema) if isinstance(input_schema, dict) else {'type': 'object'}
    properties = schema.get('properties') if isinstance(schema.get('properties'), dict) else {}
    required = [str(item or '').strip() for item in (schema.get('required') or []) if str(item or '').strip()]
    tool_suffix = qualified_tool_name.split('.', 1)[1] if '.' in qualified_tool_name else qualified_tool_name
    allowlist = _LLM_TOOL_PROPERTY_ALLOWLISTS.get(tool_suffix)

    next_properties: dict[str, Any] = {}
    for key, value in properties.items():
        normalized_key = str(key or '').strip()
        if not normalized_key:
            continue
        if normalized_key == 'draft_id' and _is_draft_scoped_mcp_bridge_tool(qualified_tool_name):
            continue
        if allowlist is not None and normalized_key not in allowlist:
            continue
        next_properties[normalized_key] = value

    next_required = [key for key in required if key != 'draft_id' and key in next_properties]
    schema['properties'] = next_properties
    schema['required'] = next_required
    return schema


def _sanitize_mcp_bridge_tool_arguments(
    qualified_tool_name: str,
    tool_args: dict[str, Any],
    *,
    input_schema: dict[str, Any] | None = None,
    current_draft_id: str = '',
) -> dict[str, Any]:
    args = dict(tool_args or {}) if isinstance(tool_args, dict) else {}
    allowed_properties = set()
    if isinstance(input_schema, dict):
        allowed_properties = {
            str(key or '').strip()
            for key in ((input_schema.get('properties') or {}).keys() if isinstance(input_schema.get('properties'), dict) else [])
            if str(key or '').strip()
        }

    def _is_placeholder_value(value: Any) -> bool:
        if not isinstance(value, str):
            return False
        text = value.strip()
        if not text:
            return False
        if text in {'?', '??', '???', '...', '\u2026'}:
            return True
        return bool(re.fullmatch(r'[?.\s]+', text))

    sanitized: dict[str, Any] = {}
    for key, value in args.items():
        normalized_key = str(key or '').strip()
        if not normalized_key:
            continue
        if allowed_properties and normalized_key not in allowed_properties:
            continue
        if normalized_key == 'draft_id' and not str(value or '').strip():
            continue
        if _is_placeholder_value(value):
            continue
        sanitized[normalized_key] = value

    if qualified_tool_name.endswith('scenario.create_draft'):
        sanitized.pop('draft_id', None)
    elif _is_draft_scoped_mcp_bridge_tool(qualified_tool_name) and current_draft_id:
        sanitized['draft_id'] = current_draft_id

    return sanitized


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
            'id': str(entry.get('id') or '').strip(),
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


def _normalize_openai_chat_tool_calls(raw_tool_calls: Any) -> list[dict[str, Any]]:
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
            'id': str(entry.get('id') or '').strip(),
            'function': {
                'name': tool_name,
                'arguments': tool_args,
            },
        })
    return tool_calls


def _extract_openai_chat_message(raw_payload: dict[str, Any]) -> dict[str, Any]:
    choices = raw_payload.get('choices') if isinstance(raw_payload.get('choices'), list) else []
    first_choice = choices[0] if choices and isinstance(choices[0], dict) else {}
    message = first_choice.get('message') if isinstance(first_choice.get('message'), dict) else {}
    role = str(message.get('role') or 'assistant').strip() or 'assistant'
    content = message.get('content')
    if isinstance(content, list):
        text_parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                item_type = str(item.get('type') or '').strip().lower()
                if item_type in {'text', 'output_text'}:
                    text = str(item.get('text') or '').strip()
                    if text:
                        text_parts.append(text)
            elif isinstance(item, str) and item.strip():
                text_parts.append(item.strip())
        content_text = '\n'.join(text_parts).strip()
    else:
        content_text = str(content or '')
    tool_calls = _normalize_openai_chat_tool_calls(message.get('tool_calls'))
    result = {
        'role': role,
        'content': content_text,
    }
    if tool_calls:
        result['tool_calls'] = tool_calls
    return result


class _RepoMcpBridgeClient:
    def __init__(self, *, model: str, host: str, provider: str = 'ollama', api_key: str = ''):
        self.model = model
        self.host = host
        self.provider = str(provider or 'ollama').strip().lower() or 'ollama'
        self.api_key = str(api_key or '').strip()
        self.sessions: dict[str, dict[str, Any]] = {}
        self.connection_errors: dict[str, str] = {}
        self.tool_manager = _BridgeToolManager()
        self.hil_manager = _BridgeHilManager()
        self.abort_current_query = False
        self.loop_limit = 8
        self.timeout_seconds = 120.0
        self.query_debug_state: dict[str, Any] = {}
        self._exit_stack: AsyncExitStack | None = None

    def _set_query_debug_state(self, **kwargs: Any) -> None:
        state = dict(self.query_debug_state)
        state.update(kwargs)
        state['phase_started_at'] = time.monotonic()
        self.query_debug_state = state

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
                    'parameters': _build_llm_chat_tool_schema(tool.name, tool.inputSchema if isinstance(tool.inputSchema, dict) else {}),
                },
            })
        return payload

    def _uses_openai_chat_completions(self) -> bool:
        return self.provider in {'litellm', 'openai'}

    def _chat_request_headers(self) -> dict[str, str] | None:
        if self._uses_openai_chat_completions() and self.api_key:
            return {'Authorization': f'Bearer {self.api_key}'}
        return None

    def _provider_label(self) -> str:
        if self.provider == 'litellm':
            return 'LiteLLM'
        if self.provider == 'openai':
            return 'OpenAI-compatible provider'
        return 'Ollama'

    def _prepare_messages_for_provider(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        prepared: list[dict[str, Any]] = []
        for message in messages:
            if not isinstance(message, dict):
                continue
            role = str(message.get('role') or '').strip().lower()
            if role not in {'user', 'assistant', 'tool', 'system'}:
                continue
            if self._uses_openai_chat_completions():
                out: dict[str, Any] = {'role': role, 'content': str(message.get('content') or '')}
                if role == 'assistant' and isinstance(message.get('tool_calls'), list):
                    out['tool_calls'] = [
                        {
                            'id': str(tool_call.get('id') or f'call_{idx + 1}').strip(),
                            'type': 'function',
                            'function': {
                                'name': str(((tool_call.get('function') or {}).get('name')) or '').strip(),
                                'arguments': json.dumps(((tool_call.get('function') or {}).get('arguments')) or {}, ensure_ascii=False),
                            },
                        }
                        for idx, tool_call in enumerate(message.get('tool_calls') or [])
                        if isinstance(tool_call, dict) and str(((tool_call.get('function') or {}).get('name')) or '').strip()
                    ]
                if role == 'tool':
                    out['tool_call_id'] = str(message.get('tool_call_id') or '').strip() or str(message.get('tool_name') or '').strip() or 'tool_call'
                prepared.append(out)
                continue
            out = {'role': role, 'content': str(message.get('content') or '')}
            if role == 'assistant' and isinstance(message.get('tool_calls'), list):
                out['tool_calls'] = message.get('tool_calls')
            if role == 'tool':
                out['tool_name'] = str(message.get('tool_name') or '').strip()
            prepared.append(out)
        return prepared

    def _openai_tool_choice(self, tools_payload: list[dict[str, Any]]) -> str | None:
        if not tools_payload:
            return None
        return 'required'

    def _has_enabled_chat_tools(self) -> bool:
        try:
            return bool(self._build_chat_tools_payload())
        except Exception:
            return False

    def _post_chat(self, *, messages: list[dict[str, Any]]) -> dict[str, Any]:
        self._set_query_debug_state(
            phase='awaiting_llm_response',
            llm_mode='nonstream',
            message_count=len(messages),
        )
        try:
            if self._uses_openai_chat_completions():
                tools_payload = self._build_chat_tools_payload()
                payload = {
                    'model': self.model,
                    'messages': self._prepare_messages_for_provider(messages),
                    'stream': False,
                    'temperature': 0.1,
                }
                if tools_payload:
                    payload['tools'] = tools_payload
                    tool_choice = self._openai_tool_choice(tools_payload)
                    if tool_choice:
                        payload['tool_choice'] = tool_choice
                return _post_json(
                    _litellm_chat_completions_url(self.host),
                    payload,
                    timeout=self.timeout_seconds,
                    headers=self._chat_request_headers(),
                )
            return _post_json(
                f'{self.host}/api/chat',
                {
                    'model': self.model,
                    'messages': self._prepare_messages_for_provider(messages),
                    'tools': self._build_chat_tools_payload(),
                    'stream': False,
                    'options': {'temperature': 0.1},
                },
                timeout=self.timeout_seconds,
                headers=self._chat_request_headers(),
            )
        except HTTPError as exc:
            detail = ''
            try:
                detail = exc.read().decode('utf-8').strip()
            except Exception:
                detail = ''
            message = f'{self._provider_label()} returned HTTP {exc.code}.'
            if detail:
                message = f'{message} {detail[:240]}'
            raise ProviderAdapterError(message, status_code=502) from exc
        except URLError as exc:
            reason = getattr(exc, 'reason', exc)
            raise ProviderAdapterError(f'Could not reach {self._provider_label()} at {self.host}: {reason}', status_code=502) from exc
        except (TimeoutError, socket.timeout) as exc:
            raise ProviderAdapterError(
                f'{self._provider_label()} chat request timed out after {self.timeout_seconds:.0f}s.',
                status_code=502,
            ) from exc

    def _stream_chat(
        self,
        *,
        messages: list[dict[str, Any]],
        emit: Callable[..., None],
        cancel_check: Callable[[], bool] | None = None,
        on_response_open: Callable[[Any], None] | None = None,
    ) -> dict[str, Any]:
        accumulated_text = ''
        tool_calls: list[dict[str, Any]] = []
        if self._uses_openai_chat_completions():
            response = self._post_chat(messages=messages)
            assistant_message = _extract_openai_chat_message(response)
            content_delta = str(assistant_message.get('content') or '')
            if content_delta:
                accumulated_text = content_delta
                emit('llm_delta', text=content_delta)
            for tool_call in assistant_message.get('tool_calls') if isinstance(assistant_message.get('tool_calls'), list) else []:
                tool_calls.append(tool_call)
                emit('tool_call', tool_name=str(((tool_call.get('function') or {}).get('name')) or ''))
            assistant_message['content'] = accumulated_text
            if tool_calls:
                assistant_message['tool_calls'] = tool_calls
            return assistant_message
        accumulated_thinking = ''
        self._set_query_debug_state(
            phase='awaiting_llm_response',
            llm_mode='stream',
            message_count=len(messages),
        )
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
        except (TimeoutError, socket.timeout) as exc:
            raise ProviderAdapterError(
                f'Ollama chat request timed out after {self.timeout_seconds:.0f}s.',
                status_code=502,
            ) from exc
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
        initial_draft_id: str = '',
        emit: Callable[..., None] | None = None,
        cancel_check: Callable[[], bool] | None = None,
        on_response_open: Callable[[Any], None] | None = None,
    ) -> str:
        messages: list[dict[str, Any]] = [{'role': 'user', 'content': prompt}]
        final_text = ''
        current_draft_id = str(initial_draft_id or '').strip()
        self.query_debug_state = {
            'phase': 'starting_query',
            'phase_started_at': time.monotonic(),
            'iteration': 0,
            'message_count': len(messages),
            'current_draft_id': current_draft_id,
        }

        for iteration in range(max(1, int(self.loop_limit or 8))):
            if self._is_cancelled(cancel_check):
                return final_text
            self._set_query_debug_state(
                phase='starting_iteration',
                iteration=iteration + 1,
                message_count=len(messages),
                current_draft_id=current_draft_id,
            )
            if emit is not None:
                assistant_message = self._stream_chat(
                    messages=messages,
                    emit=emit,
                    cancel_check=cancel_check,
                    on_response_open=on_response_open,
                )
            else:
                raw_response = self._post_chat(messages=messages)
                assistant_message = (
                    _extract_openai_chat_message(raw_response)
                    if self._uses_openai_chat_completions()
                    else _extract_ollama_chat_message(raw_response)
                )

            content = str(assistant_message.get('content') or '')
            if content:
                final_text = content
            messages.append({
                'role': 'assistant',
                'content': content,
                **({'tool_calls': assistant_message.get('tool_calls')} if assistant_message.get('tool_calls') else {}),
            })

            tool_calls = assistant_message.get('tool_calls') if isinstance(assistant_message.get('tool_calls'), list) else []
            self._set_query_debug_state(
                phase='assistant_response_received',
                iteration=iteration + 1,
                message_count=len(messages),
                current_draft_id=current_draft_id,
            )
            if self._uses_openai_chat_completions() and self._has_enabled_chat_tools() and not tool_calls:
                provider_response = content.strip()
                raise ProviderAdapterError(
                    'Provider returned plain text instead of MCP tool calls. Verify that MCP tools are enabled and that the selected model supports tool calling.',
                    status_code=502,
                    details={'provider_response': provider_response[:4000]},
                )
            if not tool_calls:
                self._set_query_debug_state(
                    phase='completed_without_tool_calls',
                    iteration=iteration + 1,
                    message_count=len(messages),
                    current_draft_id=current_draft_id,
                )
                break

            for tool_call in tool_calls:
                if self._is_cancelled(cancel_check):
                    return final_text
                function = tool_call.get('function') if isinstance(tool_call.get('function'), dict) else {}
                qualified_tool_name = _normalize_mcp_bridge_tool_name(function.get('name'), known_server_names=list(self.sessions.keys()))
                tool_args = function.get('arguments') if isinstance(function.get('arguments'), dict) else {}
                tool_definition = next((tool for tool in self.tool_manager.get_available_tools() if tool.name == qualified_tool_name), None)
                tool_args = _sanitize_mcp_bridge_tool_arguments(
                    qualified_tool_name,
                    tool_args,
                    input_schema=getattr(tool_definition, 'inputSchema', None),
                    current_draft_id=current_draft_id,
                )
                self._set_query_debug_state(
                    phase='calling_tool',
                    iteration=iteration + 1,
                    message_count=len(messages),
                    current_draft_id=current_draft_id,
                    last_tool_name=qualified_tool_name,
                    last_tool_stage='start',
                    last_tool_args=tool_args,
                )
                if emit is not None:
                    emit('tool', stage='start', tool_name=qualified_tool_name, message=f'Running {qualified_tool_name}')
                try:
                    tool_result = await _mcp_bridge_call_tool(self, qualified_tool_name, tool_args)
                    tool_response = _structured_text_payload(qualified_tool_name, tool_result)
                    if qualified_tool_name.endswith('scenario.create_draft'):
                        current_draft_id = str(((tool_result.get('draft') or {}).get('draft_id') or '')).strip() or current_draft_id
                    elif _is_draft_scoped_mcp_bridge_tool(qualified_tool_name):
                        current_draft_id = str(tool_args.get('draft_id') or current_draft_id).strip()
                    self._set_query_debug_state(
                        phase='tool_result_received',
                        iteration=iteration + 1,
                        message_count=len(messages),
                        current_draft_id=current_draft_id,
                        last_tool_name=qualified_tool_name,
                        last_tool_stage='result',
                        last_tool_args=tool_args,
                    )
                except ProviderAdapterError as exc:
                    self._set_query_debug_state(
                        phase='tool_error',
                        iteration=iteration + 1,
                        message_count=len(messages),
                        current_draft_id=current_draft_id,
                        last_tool_name=qualified_tool_name,
                        last_tool_stage='error',
                        last_tool_args=tool_args,
                    )
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
                    'tool_call_id': str(tool_call.get('id') or '').strip(),
                    'content': tool_response,
                })

        self._set_query_debug_state(
            phase='query_complete',
            message_count=len(messages),
            current_draft_id=current_draft_id,
        )
        return final_text

    async def process_query(self, prompt: str, *, initial_draft_id: str = '') -> str:
        return await self._run_query(prompt, initial_draft_id=initial_draft_id)

    async def process_query_with_events(
        self,
        prompt: str,
        *,
        initial_draft_id: str = '',
        emit: Callable[..., None],
        cancel_check: Callable[[], bool] | None = None,
        on_response_open: Callable[[Any], None] | None = None,
    ) -> str:
        return await self._run_query(
            prompt,
            initial_draft_id=initial_draft_id,
            emit=emit,
            cancel_check=cancel_check,
            on_response_open=on_response_open,
        )

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
    user_prompt: str | None = None,
    initial_draft_id: str = '',
    emit: Callable[..., None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
    on_response_open: Callable[[Any], None] | None = None,
) -> str:
    process_query = None
    sanitized_initial_draft_id = str(initial_draft_id or '').strip()

    async def _invoke_process_query(callable_obj: Callable[..., Any], current_prompt: str, **kwargs: Any) -> str:
        if sanitized_initial_draft_id:
            try:
                return await callable_obj(current_prompt, initial_draft_id=sanitized_initial_draft_id, **kwargs)
            except TypeError as exc:
                if 'initial_draft_id' not in str(exc):
                    raise
        return await callable_obj(current_prompt, **kwargs)

    if emit is not None:
        process_with_events = getattr(client, 'process_query_with_events', None)
        if callable(process_with_events):
            process_query = lambda current_prompt: _invoke_process_query(
                process_with_events,
                current_prompt,
                emit=emit,
                cancel_check=cancel_check,
                on_response_open=on_response_open,
            )
    if process_query is None:
        process_query = lambda current_prompt: _invoke_process_query(client.process_query, current_prompt)

    try:
        return await process_query(prompt)
    except ProviderAdapterError as exc:
        repair = _build_prompt_repair_decision(prompt=prompt, user_prompt=user_prompt, exc=exc)
        if not repair.retryable:
            raise
        if emit is not None and repair.status_message:
            emit('status', message=repair.status_message)
        return await process_query(repair.retry_prompt or prompt)


def _compact_draft_payload_for_llm(draft: dict[str, Any]) -> dict[str, Any]:
    return {
        'draft_id': str(draft.get('draft_id') or '').strip(),
        'updated_at': draft.get('updated_at'),
        'preview_summary': draft.get('preview_summary'),
        'last_saved_xml_path': draft.get('last_saved_xml_path'),
    }


def _compact_preview_payload_for_llm(preview: dict[str, Any]) -> dict[str, Any]:
    return {
        'seed': preview.get('seed'),
        'routers': len(preview.get('routers') or []),
        'hosts': len(preview.get('hosts') or []),
        'switches': len(preview.get('switches') or []),
        'links': len(preview.get('links') or []),
    }


def _compact_tool_result_for_llm(qualified_tool_name: str, data: dict[str, Any]) -> dict[str, Any]:
    compact = deepcopy(data)
    draft = compact.get('draft')
    if isinstance(draft, dict):
        compact['draft'] = _compact_draft_payload_for_llm(draft)

    preview = compact.get('preview')
    if isinstance(preview, dict):
        compact['preview'] = _compact_preview_payload_for_llm(preview)

    if qualified_tool_name.endswith('search_vulnerability_catalog'):
        results = compact.get('results')
        if isinstance(results, list):
            compact['results'] = [
                {
                    'name': result.get('name'),
                    'path': result.get('path'),
                    'type': result.get('type'),
                    'vector': result.get('vector'),
                    'cve': result.get('cve'),
                    'score': result.get('score'),
                }
                for result in results[:5]
                if isinstance(result, dict)
            ]
    return compact


def _structured_text_payload(qualified_tool_name: str, data: dict[str, Any]) -> str:
    return json.dumps(_compact_tool_result_for_llm(qualified_tool_name, data), indent=2, sort_keys=True)


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
    try:
        client = McpBridgeClient(
            model=model,
            host=host,
            provider=str(payload.get('provider') or 'ollama').strip().lower() or 'ollama',
            api_key=str(payload.get('api_key') or '').strip(),
        )
    except TypeError:
        client = McpBridgeClient(model=model, host=host)
        try:
            setattr(client, 'provider', str(payload.get('provider') or 'ollama').strip().lower() or 'ollama')
            setattr(client, 'api_key', str(payload.get('api_key') or '').strip())
        except Exception:
            pass
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


def _apply_mcp_bridge_tool_selection(client: Any, enabled_tools: list[str], *, selection_provided: bool) -> dict[str, bool]:
    enabled_map = client.tool_manager.get_enabled_tools().copy()
    selected = {tool_name for tool_name in enabled_tools if _is_user_exposed_mcp_bridge_tool(tool_name)}
    dedicated_mutation_suffixes = (
        'scenario.add_node_role_item',
        'scenario.add_service_item',
        'scenario.add_routing_item',
        'scenario.add_traffic_item',
        'scenario.add_segmentation_item',
        'scenario.add_vulnerability_item',
    )
    has_dedicated_mutation_tools = any(
        tool_name.endswith(dedicated_mutation_suffixes)
        for tool_name in (selected or enabled_map.keys())
    )
    for tool_name in list(enabled_map.keys()):
        if not _is_user_exposed_mcp_bridge_tool(tool_name):
            new_state = False
        elif selection_provided and has_dedicated_mutation_tools and tool_name.endswith('scenario.replace_section'):
            new_state = False
        elif not selection_provided and not selected:
            new_state = True
        else:
            new_state = tool_name in selected
        client.tool_manager.set_tool_status(tool_name, new_state)
        enabled_map[tool_name] = new_state
    return enabled_map


async def _mcp_bridge_discover(payload: dict[str, Any], *, model: str, host: str) -> dict[str, Any]:
    client, bridge_cfg = await _mcp_bridge_connect(payload, model=model, host=host)
    try:
        enabled_map = _apply_mcp_bridge_tool_selection(
            client,
            bridge_cfg['enabled_tools'],
            selection_provided=bool(bridge_cfg.get('enabled_tools_specified')),
        )
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


def _find_optional_mcp_bridge_tool(available_tools: list[str], suffix: str) -> str:
    for tool_name in available_tools:
        if tool_name.endswith(suffix):
            return tool_name
    return ''


def _build_seeded_traffic_rows(user_prompt: str) -> list[dict[str, Any]]:
    return _compiler_build_seeded_traffic_rows(user_prompt)


async def _apply_deterministic_mcp_bridge_seed(
    client: Any,
    *,
    available_tools: list[str],
    draft_id: str,
    user_prompt: str,
) -> list[str]:
    applied: list[str] = []

    routing_tool = _find_optional_mcp_bridge_tool(available_tools, 'scenario.add_routing_item')
    node_tool = _find_optional_mcp_bridge_tool(available_tools, 'scenario.add_node_role_item')
    service_tool = _find_optional_mcp_bridge_tool(available_tools, 'scenario.add_service_item')
    traffic_tool = _find_optional_mcp_bridge_tool(available_tools, 'scenario.add_traffic_item')
    segmentation_tool = _find_optional_mcp_bridge_tool(available_tools, 'scenario.add_segmentation_item')
    vuln_tool = _find_optional_mcp_bridge_tool(available_tools, 'scenario.add_vulnerability_item')

    compiled = _compile_ai_intent(user_prompt)
    has_seeded_vulnerability_ops = any(op.get('kind') == 'vulnerability' for op in compiled.tool_seed_ops)
    for op in compiled.tool_seed_ops:
        if op.get('kind') == 'routing' and routing_tool:
            routing_args: dict[str, Any] = {
                'draft_id': draft_id,
                'protocol': op.get('protocol') or 'OSPFv2',
                'count': int(op.get('count') or 1),
            }
            if op.get('r2r_mode'):
                routing_args['r2r_mode'] = op.get('r2r_mode')
            await _mcp_bridge_call_tool(client, routing_tool, routing_args)
        elif op.get('kind') == 'node' and node_tool:
            await _mcp_bridge_call_tool(client, node_tool, {
                'draft_id': draft_id,
                'role': op.get('role'),
                'count': int(op.get('count') or 1),
            })
        elif op.get('kind') == 'service' and service_tool:
            await _mcp_bridge_call_tool(client, service_tool, {
                'draft_id': draft_id,
                'service': op.get('service'),
                'count': int(op.get('count') or 1),
            })
        elif op.get('kind') == 'traffic' and traffic_tool:
            await _mcp_bridge_call_tool(client, traffic_tool, {
                'draft_id': draft_id,
                'protocol': op.get('protocol'),
                'count': int(op.get('count') or 1),
                'pattern': op.get('pattern') or 'continuous',
                'content_type': op.get('content_type') or 'text',
            })
        elif op.get('kind') == 'segmentation' and segmentation_tool:
            await _mcp_bridge_call_tool(client, segmentation_tool, {
                'draft_id': draft_id,
                'kind': op.get('selected'),
                'count': int(op.get('count') or 1),
            })
    applied.extend(compiled.applied_actions)

    vulnerability_target_count = _extract_vulnerability_target_count(user_prompt)

    if segmentation_tool:
        for control, count in _extract_segmentation_control_count_intent(user_prompt).items():
            if count <= 0:
                continue
            await _mcp_bridge_call_tool(client, segmentation_tool, {
                'draft_id': draft_id,
                'kind': control,
                'count': count,
            })
            applied.append(f'Segmentation {control}={count}')

    if vuln_tool and vulnerability_target_count > 0 and not has_seeded_vulnerability_ops:
        query_hint = _extract_vulnerability_query_hint(user_prompt)
        candidates = _search_vulnerability_catalog_for_prompt(query_hint, limit=vulnerability_target_count)
        for candidate in candidates[:max(0, vulnerability_target_count)]:
            candidate_name = str(candidate.get('name') or '').strip()
            candidate_path = str(candidate.get('path') or '').strip()
            if not candidate_name or not candidate_path:
                continue
            await _mcp_bridge_call_tool(client, vuln_tool, {
                'draft_id': draft_id,
                'v_name': candidate_name,
                'v_path': candidate_path,
                'v_count': 1,
            })
            applied.append(f'Vulnerability {candidate_name}')

    return applied


def _build_mcp_bridge_goal_prompt(
    *,
    draft_id: str,
    enabled_tools: list[str],
    scenario_name: str,
    user_prompt: str,
    seeded_actions: list[str] | None = None,
) -> str:
    normalized_seeded_actions = [str(action or '').strip() for action in (seeded_actions or []) if str(action or '').strip()]
    compiled = _compile_ai_intent(user_prompt)
    opening_line = 'Use MCP tools to rebuild the current scenario draft from scratch. Do not create a second draft.'
    seed_lines: list[str] = []
    if normalized_seeded_actions:
        opening_line = 'The current draft already contains deterministic seed rows for obvious count-based requirements. Treat those seeded rows as provisionally correct and do not duplicate them. Only adjust or replace a seeded row when the current draft or preview shows a concrete mismatch with the user request.'
        seed_lines.append('Deterministic seed already added: ' + '; '.join(normalized_seeded_actions) + '.')
        seed_lines.append('Do not call scenario.get_authoring_schema merely to reinterpret already-seeded Routing, Services, or Traffic rows. Only call it when you need allowed values for an unseeded section or for a concrete field you still cannot author safely.')
    if compiled.locked_sections:
        seed_lines.append('Compiler-managed sections for phase 1: ' + ', '.join(compiled.locked_sections) + '. Preserve those seeded Node Information/Routing rows unless preview proves they mismatch the user request.')
    return '\n'.join([
        opening_line,
        f'Target draft_id: {draft_id}',
        'The bridge injects the current draft_id automatically for draft-scoped tools. Do not include draft_id in tool arguments unless a tool explicitly requires it.',
        f'Scenario name: {scenario_name}',
        f'Enabled tools: {", ".join(enabled_tools) if enabled_tools else "(none)"}',
        'You must work only through enabled tools.',
        *seed_lines,
        'Keep all section payloads backend-compatible.',
        'Treat the existing draft as the working draft for this request. Do not re-audit or re-author seeded rows by default; focus first on any remaining unseeded requirements, then preview. If seeded rows already satisfy the request, preview immediately.',
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
        *_build_mcp_bridge_execution_guidance(user_prompt),
        'If the user asks for routers without naming a protocol, use scenario.add_routing_item with protocol="OSPFv2" and the requested count when that tool is enabled; otherwise replace only the Routing section with a Count row selected="OSPFv2".',
        'When dedicated tools are available, prefer scenario.add_node_role_item for host or Docker counts, scenario.add_routing_item for explicit router/protocol rows and routing edge hints, scenario.add_service_item for Services rows, scenario.add_traffic_item for TCP or UDP traffic, and scenario.add_segmentation_item for Segmentation rows.',
        'For vulnerabilities, prefer scenario.search_vulnerability_catalog first, then call scenario.add_vulnerability_item with explicit v_name and v_path from the chosen result. Do not pass factor. If the user asks for multiple different vulnerabilities, make separate add_vulnerability_item calls with v_count=1 for each chosen vulnerability.',
        'For broad vulnerability categories such as web-related, database, auth, or ssh-related vulnerabilities, do not invent a synthetic category row. Search the vulnerability catalog using the user\'s wording and available README-backed context, and do not pass v_type or v_vector filters unless the user explicitly requested those exact filters. Then choose concrete catalog results.',
        *_build_vulnerability_grounding_guidance(user_prompt),
        'For services and segmentation, prefer schema-discovered values and the dedicated mutation tools; otherwise use replace_section with backend-compatible items.',
        'For traffic requests, ensure each Traffic row uses selected="TCP" or "UDP", a concrete content_type, and one exact pattern from: continuous, periodic, burst, poisson, or ramp. For varied traffic profiles, create multiple Traffic rows rather than vague free-text profile labels. Each Traffic row must also use either v_metric="Count" with v_count or a positive factor so preview flows materialize.',
        'Only use free-text fields where the schema explicitly expects them, such as notes or vulnerability identifiers like v_name/v_path.',
        'Preview the draft before you finish if preview_draft is enabled.',
        'Do not save XML unless save_xml is explicitly enabled and necessary.',
        f'User goal: {user_prompt}',
        'Respond with a short plain summary of what you changed after using tools.',
    ])


async def _mcp_bridge_generate(payload: dict[str, Any], *, current_scenario: dict[str, Any], user_prompt: str, model: str, host: str) -> dict[str, Any]:
    connect_started_at = time.monotonic()
    try:
        client, bridge_cfg = await _mcp_bridge_connect(payload, model=model, host=host)
    except BaseException as exc:
        raise _augment_provider_error_for_bridge_stage(
            exc,
            stage='connect_mcp_bridge',
            started_at=connect_started_at,
            fallback='MCP bridge generation failed while connecting to MCP servers.',
        ) from exc
    try:
        seed_scenario = _build_ai_seed_scenario_for_prompt(current_scenario, user_prompt)
        enabled_map = _apply_mcp_bridge_tool_selection(
            client,
            bridge_cfg['enabled_tools'],
            selection_provided=bool(bridge_cfg.get('enabled_tools_specified')),
        )
        available_tools = [str(getattr(tool, 'name', '') or '').strip() for tool in client.tool_manager.get_available_tools()]
        enabled_tools = [name for name in available_tools if enabled_map.get(name, True) and _is_user_exposed_mcp_bridge_tool(name)]
        if str(payload.get('provider') or 'ollama').strip().lower() in {'litellm', 'openai'} and not enabled_tools:
            raise ProviderAdapterError(
                'No enabled MCP tools are available for AI generation. Refresh Connection and enable at least one tool before generating.',
                status_code=400,
            )

        create_tool = _find_required_mcp_bridge_tool(available_tools, 'scenario.create_draft')
        get_tool = _find_required_mcp_bridge_tool(available_tools, 'scenario.get_draft')
        preview_tool = _find_required_mcp_bridge_tool(available_tools, 'scenario.preview_draft')

        draft_id = ''
        execution_result: dict[str, Any] | None = None
        for attempt in range(2):
            create_started_at = time.monotonic()
            try:
                created = await _mcp_bridge_call_tool(client, create_tool, {
                    'name': current_scenario.get('name'),
                    'scenario': seed_scenario,
                    'core': payload.get('core') if isinstance(payload.get('core'), dict) else {},
                })
            except BaseException as exc:
                raise _augment_provider_error_for_bridge_stage(
                    exc,
                    stage='create_draft',
                    started_at=create_started_at,
                    fallback='MCP bridge generation failed while creating the scenario draft.',
                    client=client,
                ) from exc
            draft = created.get('draft') if isinstance(created.get('draft'), dict) else {}
            draft_id = str(draft.get('draft_id') or '').strip()
            if not draft_id:
                raise ProviderAdapterError('MCP draft creation did not return a draft_id.', status_code=500)

            seed_started_at = time.monotonic()
            try:
                seeded_actions = await _apply_deterministic_mcp_bridge_seed(
                    client,
                    available_tools=enabled_tools,
                    draft_id=draft_id,
                    user_prompt=user_prompt,
                )
            except BaseException as exc:
                raise _augment_provider_error_for_bridge_stage(
                    exc,
                    stage='seed_draft_from_prompt',
                    started_at=seed_started_at,
                    draft_id=draft_id,
                    fallback='MCP bridge generation failed while seeding deterministic draft rows.',
                    client=client,
                ) from exc

            prompt = _build_mcp_bridge_goal_prompt(
                draft_id=draft_id,
                enabled_tools=enabled_tools,
                scenario_name=str(current_scenario.get('name') or '').strip() or 'Scenario',
                user_prompt=user_prompt,
                seeded_actions=seeded_actions,
            )
            try:
                execute_started_at = time.monotonic()
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
                raise _augment_provider_error_for_bridge_stage(
                    exc,
                    stage='execute_prompt_and_preview',
                    started_at=execute_started_at,
                    draft_id=draft_id,
                    fallback='MCP bridge generation failed while executing the authoring prompt.',
                    client=client,
                ) from exc
            except BaseException as exc:
                raise _augment_provider_error_for_bridge_stage(
                    exc,
                    stage='execute_prompt_and_preview',
                    started_at=execute_started_at,
                    draft_id=draft_id,
                    fallback='MCP bridge generation failed while executing model-requested tool calls.',
                    client=client,
                ) from exc
        if not isinstance(execution_result, dict):
            raise ProviderAdapterError('MCP bridge generation failed to produce a preview result.', status_code=502)
        draft_payload = execution_result.get('draft_payload') if isinstance(execution_result.get('draft_payload'), dict) else {}
        scenario_payload = draft_payload.get('scenario') if isinstance(draft_payload.get('scenario'), dict) else deepcopy(current_scenario)
        scenario_payload = _restore_preserved_scenario_metadata(current_scenario, scenario_payload)
        scenario_payload = _overlay_compiled_intent_sections(scenario_payload, user_prompt)
        canonicalize_started_at = time.monotonic()
        try:
            scenario_payload = _canonicalize_generated_vulnerabilities_or_raise(scenario_payload)
            _ensure_explicit_vulnerability_query_matches_or_raise(user_prompt, scenario_payload)
            scenario_payload = _canonicalize_generated_routing_modes(scenario_payload)
            scenario_payload = app_backend._concretize_preview_placeholders(scenario_payload, seed=payload.get('seed'))
        except BaseException as exc:
            raise _augment_provider_error_for_bridge_stage(
                exc,
                stage='canonicalize_generated_vulnerabilities',
                started_at=canonicalize_started_at,
                draft_id=draft_id,
                fallback='MCP bridge generation failed while canonicalizing vulnerabilities.',
                client=client,
            ) from exc
        refreshed_preview, refreshed_plan, refreshed_flow_meta = _refresh_preview_for_final_bridge_scenario(
            payload,
            scenario_payload=scenario_payload,
        )
        return {
            'provider': str(payload.get('provider') or 'ollama').strip().lower() or 'ollama',
            'bridge_mode': bridge_cfg['bridge_mode'],
            'base_url': host,
            'model': model,
            'prompt_used': execution_result.get('prompt_used') or prompt,
            'provider_response': execution_result.get('provider_response') or '',
            'generated_scenario': scenario_payload,
            'preview': refreshed_preview,
            'plan': refreshed_plan,
            'flow_meta': refreshed_flow_meta,
            'breakdowns': None,
            'count_intent_mismatch': execution_result.get('count_intent_mismatch'),
            'count_intent_retry_used': bool(execution_result.get('count_intent_retry_used')),
            'prompt_coverage_mismatch': execution_result.get('prompt_coverage_mismatch'),
            'prompt_coverage_retry_used': bool(execution_result.get('prompt_coverage_retry_used')),
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
    connect_started_at = time.monotonic()
    try:
        client, bridge_cfg = await _mcp_bridge_connect(payload, model=model, host=host)
    except BaseException as exc:
        raise _augment_provider_error_for_bridge_stage(
            exc,
            stage='connect_mcp_bridge',
            started_at=connect_started_at,
            fallback='MCP bridge generation failed while connecting to MCP servers.',
        ) from exc
    seed_scenario = _build_ai_seed_scenario(current_scenario)
    if callable(on_client_ready):
        on_client_ready(client)

    try:
        enabled_map = _apply_mcp_bridge_tool_selection(
            client,
            bridge_cfg['enabled_tools'],
            selection_provided=bool(bridge_cfg.get('enabled_tools_specified')),
        )
        available_tools = [str(getattr(tool, 'name', '') or '').strip() for tool in client.tool_manager.get_available_tools()]
        enabled_tools = [name for name in available_tools if enabled_map.get(name, True) and _is_user_exposed_mcp_bridge_tool(name)]
        if str(payload.get('provider') or 'ollama').strip().lower() in {'litellm', 'openai'} and not enabled_tools:
            raise ProviderAdapterError(
                'No enabled MCP tools are available for AI generation. Refresh Connection and enable at least one tool before generating.',
                status_code=400,
            )

        create_tool = _find_required_mcp_bridge_tool(available_tools, 'scenario.create_draft')
        get_tool = _find_required_mcp_bridge_tool(available_tools, 'scenario.get_draft')
        preview_tool = _find_required_mcp_bridge_tool(available_tools, 'scenario.preview_draft')

        draft_id = ''
        execution_result: dict[str, Any] | None = None
        for attempt in range(2):
            emit('status', message='Creating scenario draft...')
            if cancel_check and cancel_check():
                raise ProviderAdapterError('Generation cancelled by user.', status_code=499)
            create_started_at = time.monotonic()
            try:
                created = await _mcp_bridge_call_tool(client, create_tool, {
                    'name': current_scenario.get('name'),
                    'scenario': seed_scenario,
                    'core': payload.get('core') if isinstance(payload.get('core'), dict) else {},
                })
            except BaseException as exc:
                raise _augment_provider_error_for_bridge_stage(
                    exc,
                    stage='create_draft',
                    started_at=create_started_at,
                    fallback='MCP bridge generation failed while creating the scenario draft.',
                    client=client,
                ) from exc
            draft = created.get('draft') if isinstance(created.get('draft'), dict) else {}
            draft_id = str(draft.get('draft_id') or '').strip()
            if not draft_id:
                raise ProviderAdapterError('MCP draft creation did not return a draft_id.', status_code=500)

            seed_started_at = time.monotonic()
            try:
                seeded_actions = await _apply_deterministic_mcp_bridge_seed(
                    client,
                    available_tools=enabled_tools,
                    draft_id=draft_id,
                    user_prompt=user_prompt,
                )
            except BaseException as exc:
                raise _augment_provider_error_for_bridge_stage(
                    exc,
                    stage='seed_draft_from_prompt',
                    started_at=seed_started_at,
                    draft_id=draft_id,
                    fallback='MCP bridge generation failed while seeding deterministic draft rows.',
                    client=client,
                ) from exc

            prompt = _build_mcp_bridge_goal_prompt(
                draft_id=draft_id,
                enabled_tools=enabled_tools,
                scenario_name=str(current_scenario.get('name') or '').strip() or 'Scenario',
                user_prompt=user_prompt,
                seeded_actions=seeded_actions,
            )
            emit('status', message='Sending prompt to Ollama...')
            if cancel_check and cancel_check():
                raise ProviderAdapterError('Generation cancelled by user.', status_code=499)
            try:
                execute_started_at = time.monotonic()
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
                raise _augment_provider_error_for_bridge_stage(
                    exc,
                    stage='execute_prompt_and_preview',
                    started_at=execute_started_at,
                    draft_id=draft_id,
                    fallback='MCP bridge generation failed while executing the authoring prompt.',
                    client=client,
                ) from exc
            except BaseException as exc:
                raise _augment_provider_error_for_bridge_stage(
                    exc,
                    stage='execute_prompt_and_preview',
                    started_at=execute_started_at,
                    draft_id=draft_id,
                    fallback='MCP bridge generation failed while executing model-requested tool calls.',
                    client=client,
                ) from exc
        if not isinstance(execution_result, dict):
            raise ProviderAdapterError('MCP bridge generation failed to produce a preview result.', status_code=502)
        if cancel_check and cancel_check():
            raise ProviderAdapterError('Generation cancelled by user.', status_code=499)

        emit('status', message='Refreshing draft after tool calls...')
        draft_payload = execution_result.get('draft_payload') if isinstance(execution_result.get('draft_payload'), dict) else {}
        previewed = execution_result.get('previewed') if isinstance(execution_result.get('previewed'), dict) else {}
        scenario_payload = draft_payload.get('scenario') if isinstance(draft_payload.get('scenario'), dict) else deepcopy(current_scenario)
        canonicalize_started_at = time.monotonic()
        try:
            scenario_payload = _canonicalize_generated_vulnerabilities_or_raise(scenario_payload)
            scenario_payload = _restore_preserved_scenario_metadata(current_scenario, scenario_payload)
            scenario_payload = _overlay_compiled_intent_sections(scenario_payload, user_prompt)
            _ensure_explicit_vulnerability_query_matches_or_raise(user_prompt, scenario_payload)
            scenario_payload = _canonicalize_generated_routing_modes(scenario_payload)
            scenario_payload = app_backend._concretize_preview_placeholders(scenario_payload, seed=payload.get('seed'))
        except BaseException as exc:
            raise _augment_provider_error_for_bridge_stage(
                exc,
                stage='canonicalize_generated_vulnerabilities',
                started_at=canonicalize_started_at,
                draft_id=draft_id,
                fallback='MCP bridge generation failed while canonicalizing vulnerabilities.',
                client=client,
            ) from exc
        refreshed_preview, refreshed_plan, refreshed_flow_meta = _refresh_preview_for_final_bridge_scenario(
            payload,
            scenario_payload=scenario_payload,
        )
        return {
            'provider': str(payload.get('provider') or 'ollama').strip().lower() or 'ollama',
            'bridge_mode': bridge_cfg['bridge_mode'],
            'base_url': host,
            'model': model,
            'prompt_used': execution_result.get('prompt_used') or prompt,
            'provider_response': execution_result.get('provider_response') or '',
            'generated_scenario': scenario_payload,
            'preview': refreshed_preview,
            'plan': refreshed_plan,
            'flow_meta': refreshed_flow_meta,
            'breakdowns': None,
            'count_intent_mismatch': execution_result.get('count_intent_mismatch'),
            'count_intent_retry_used': bool(execution_result.get('count_intent_retry_used')),
            'prompt_coverage_mismatch': execution_result.get('prompt_coverage_mismatch'),
            'prompt_coverage_retry_used': bool(execution_result.get('prompt_coverage_retry_used')),
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
    user_prompt: str,
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
            'prompt_coverage_mismatch': generation_result.get('prompt_coverage_mismatch'),
            'prompt_coverage_retry_used': bool(generation_result.get('prompt_coverage_retry_used')),
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
    seed_scenario = _build_ai_seed_scenario_for_prompt(current_scenario, user_prompt)
    merged_scenario = _normalize_generated_scenario(seed_scenario, generation_result.get('parsed_generation') or {})
    merged_scenario = _restore_preserved_scenario_metadata(current_scenario, merged_scenario)
    merged_scenario = _overlay_compiled_intent_sections(merged_scenario, user_prompt)
    merged_scenario = _canonicalize_generated_vulnerabilities_or_raise(merged_scenario)
    _ensure_explicit_vulnerability_query_matches_or_raise(user_prompt, merged_scenario)
    merged_scenario = _canonicalize_generated_routing_modes(merged_scenario)
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

    preview_resp, preview_json = _dispatch_preview_full(preview_body)

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


def _dispatch_preview_full(preview_body: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    current_app = _app if _app is not None else getattr(app_backend, 'app', None)
    if current_app is None:
        raise ProviderAdapterError('Preview route is unavailable.', status_code=500)
    with current_app.test_request_context('/api/plan/preview_full', method='POST', json=preview_body):
        preview_resp = current_app.make_response(current_app.dispatch_request())
        preview_json = preview_resp.get_json(silent=True) or {}
    return preview_resp, preview_json


def _refresh_preview_for_final_bridge_scenario(
    payload: dict[str, Any],
    *,
    scenario_payload: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    preview_body = {
        'scenarios': [scenario_payload],
        'core': payload.get('core') if isinstance(payload.get('core'), dict) else None,
        'scenario': scenario_payload.get('name') or None,
    }
    if payload.get('seed') is not None:
        preview_body['seed'] = payload.get('seed')

    preview_resp, preview_json = _dispatch_preview_full(preview_body)
    if not preview_resp.status_code or preview_resp.status_code >= 400 or preview_json.get('ok') is False:
        raise ProviderAdapterError(
            preview_json.get('error') or f'Preview failed (HTTP {preview_resp.status_code}).',
            status_code=400,
            details={'generated_scenario': scenario_payload},
        )

    return (
        preview_json.get('full_preview') if isinstance(preview_json.get('full_preview'), dict) else {},
        preview_json.get('plan') if isinstance(preview_json.get('plan'), dict) else {},
        preview_json.get('flow_meta') if isinstance(preview_json.get('flow_meta'), dict) else {},
    )


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
            if cancellation_check and cancellation_check():
                raise ProviderAdapterError('Generation cancelled by user.', status_code=499)
            return ''.join(raw_parts).strip()

        try:
            raw_generation = _request_stream(format_mode)
        except URLError as exc:
            reason = getattr(exc, 'reason', exc)
            raise ProviderAdapterError(
                f'Could not reach Ollama at {base_url}: {reason}',
                status_code=502,
            ) from exc
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

    try:
        prompt = _build_ollama_prompt(current_scenario, user_prompt)
        provider_attempts: list[dict[str, Any]] = []
        emit('status', message='Sending prompt to Ollama…')
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
            if cancellation_check and cancellation_check():
                raise ProviderAdapterError('Generation cancelled by user.', status_code=499)
            emit('status', message='Repair draft was still invalid JSON. Requesting a strict JSON rewrite…')
            strict_prompt = _build_ollama_strict_json_repair_prompt(current_scenario, user_prompt, raw_generation)
            raw_generation, parsed_generation, format_mode = _generate_once_streaming(prompt=strict_prompt)
            provider_attempts.append({'attempt': 'strict-rewrite', 'format_mode': format_mode, 'response': raw_generation})
            prompt = strict_prompt
        if not isinstance(parsed_generation, dict) or not parsed_generation:
            raise ProviderAdapterError(
                'Ollama did not return valid JSON for scenario generation.',
                status_code=502,
                details={
                    'provider_response': str((provider_attempts[-1].get('response') if provider_attempts else '') or '')[:4000],
                    'provider_attempts': provider_attempts,
                },
            )
        return {
            'provider': 'ollama',
            'base_url': base_url,
            'model': model,
            'prompt_used': prompt,
            'provider_response': str((provider_attempts[-1].get('response') if provider_attempts else '') or ''),
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
        supports_mcp_bridge=True,
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
        generation_started_at = time.monotonic()

        def _run_attempt(*, attempt_name: str, prompt_text: str) -> tuple[str, dict[str, Any], str]:
            attempt_started_at = time.monotonic()
            try:
                raw_generation, parsed_generation, format_mode = _run_with_wall_clock_timeout(
                    lambda: self._generate_once(
                        base_url=base_url,
                        model=model,
                        prompt=prompt_text,
                        timeout_seconds=timeout_seconds,
                    ),
                    timeout_seconds=timeout_seconds,
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
                _append_provider_attempt(
                    provider_attempts,
                    attempt=attempt_name,
                    started_at=attempt_started_at,
                    status='failed',
                    error=message,
                )
                raise ProviderAdapterError(
                    message,
                    status_code=502,
                    details=_build_provider_generation_error_details(
                        provider='ollama',
                        stage='direct_generate',
                        started_at=generation_started_at,
                        base_url=base_url,
                        model=model,
                        timeout_seconds=timeout_seconds,
                        attempt=attempt_name,
                        provider_attempts=provider_attempts,
                        error_category='http_error',
                    ),
                ) from exc
            except URLError as exc:
                reason = getattr(exc, 'reason', exc)
                reason_text = str(reason)
                _append_provider_attempt(
                    provider_attempts,
                    attempt=attempt_name,
                    started_at=attempt_started_at,
                    status='failed',
                    error=reason_text,
                )
                error_category = 'timeout' if 'timed out' in reason_text.lower() else 'connection_error'
                raise ProviderAdapterError(
                    f'Could not reach Ollama at {base_url}: {reason}',
                    status_code=502,
                    details=_build_provider_generation_error_details(
                        provider='ollama',
                        stage='direct_generate',
                        started_at=generation_started_at,
                        base_url=base_url,
                        model=model,
                        timeout_seconds=timeout_seconds,
                        attempt=attempt_name,
                        provider_attempts=provider_attempts,
                        error_category=error_category,
                    ),
                ) from exc
            _append_provider_attempt(
                provider_attempts,
                attempt=attempt_name,
                format_mode=format_mode,
                started_at=attempt_started_at,
                status='completed',
                response=raw_generation,
            )
            return raw_generation, parsed_generation, format_mode

        try:
            raw_generation, parsed_generation, format_mode = _run_attempt(
                attempt_name='initial',
                prompt_text=prompt,
            )
            if not isinstance(parsed_generation, dict) or not parsed_generation:
                repair_prompt = _build_ollama_repair_prompt(current_scenario, user_prompt, raw_generation)
                raw_generation, parsed_generation, format_mode = _run_attempt(
                    attempt_name='repair',
                    prompt_text=repair_prompt,
                )
                prompt = repair_prompt
            if not isinstance(parsed_generation, dict) or not parsed_generation:
                strict_prompt = _build_ollama_strict_json_repair_prompt(current_scenario, user_prompt, raw_generation)
                raw_generation, parsed_generation, format_mode = _run_attempt(
                    attempt_name='strict-rewrite',
                    prompt_text=strict_prompt,
                )
                prompt = strict_prompt
            if not isinstance(parsed_generation, dict) or not parsed_generation:
                raise ProviderAdapterError(
                    'Ollama did not return valid JSON for scenario generation.',
                    status_code=502,
                    details={
                        'provider_response': str((provider_attempts[-1].get('response') if provider_attempts else '') or '')[:4000],
                        'provider_attempts': provider_attempts,
                    },
                )
            return {
                'provider': 'ollama',
                'base_url': base_url,
                'model': model,
                'prompt_used': prompt,
                'provider_response': str((provider_attempts[-1].get('response') if provider_attempts else '') or ''),
                'provider_attempts': provider_attempts,
                'parsed_generation': parsed_generation,
            }
        except ProviderAdapterError:
            raise
        except Exception as exc:  # pragma: no cover
            try:
                if log is not None:
                    log.exception('[ai-provider] generation failed: %s', exc)
            except Exception:
                pass
            raise ProviderAdapterError(
                'Unexpected generation failure while contacting Ollama.',
                status_code=500,
                details=_build_provider_generation_error_details(
                    provider='ollama',
                    stage='direct_generate',
                    started_at=generation_started_at,
                    base_url=base_url,
                    model=model,
                    timeout_seconds=timeout_seconds,
                    provider_attempts=provider_attempts,
                    error_category='unexpected_error',
                ),
            ) from exc


class LiteLlmProviderAdapter(ProviderAdapter):
    capability = ProviderCapability(
        provider='litellm',
        label='LiteLLM',
        enabled=True,
        mode='remote',
        description='OpenAI-compatible LiteLLM proxy for hosted or routed model access.',
        default_base_url='https://localhost:4000/v1',
        requires_model=True,
        requires_api_key=False,
        supports_mcp_bridge=True,
    )

    def validate(self, payload: dict[str, Any], *, log: Any = None) -> dict[str, Any]:
        model = str(payload.get('model') or '').strip()
        timeout_raw = payload.get('timeout_seconds')
        try:
            timeout_seconds = float(timeout_raw) if timeout_raw is not None else 8.0
        except (TypeError, ValueError):
            timeout_seconds = 8.0
        timeout_seconds = min(max(timeout_seconds, 1.0), 20.0)
        enforce_ssl = _payload_bool(payload.get('enforce_ssl'), default=True)

        try:
            base_url = _normalize_litellm_base_url(payload.get('base_url'), enforce_ssl=enforce_ssl)
        except ValueError as exc:
            raise ProviderAdapterError(str(exc), details={'checked_at': _utc_timestamp()}) from exc

        headers = _litellm_request_headers(payload.get('api_key'))
        models_url = _litellm_models_url(base_url)
        try:
            data = _fetch_json(models_url, timeout=timeout_seconds, headers=headers)
            raw_models = data.get('data') if isinstance(data, dict) else []
            models: list[str] = []
            if isinstance(raw_models, list):
                for entry in raw_models:
                    if isinstance(entry, dict):
                        name = str(entry.get('id') or entry.get('name') or '').strip()
                    else:
                        name = str(entry or '').strip()
                    if name:
                        models.append(name)
            model_found = (not model) or (model in models)
            message = f'Reached LiteLLM at {base_url}.'
            if model and not model_found:
                message = f'Reached LiteLLM at {base_url}, but model {model!r} was not found.'
            return {
                'success': True,
                'provider': 'litellm',
                'base_url': base_url,
                'models': models,
                'model': model,
                'model_found': model_found,
                'message': message,
                'checked_at': _utc_timestamp(),
                'enforce_ssl': enforce_ssl,
            }
        except HTTPError as exc:
            detail = ''
            try:
                detail = exc.read().decode('utf-8').strip()
            except Exception:
                detail = ''
            message = f'LiteLLM returned HTTP {exc.code}.'
            if detail:
                message = f'{message} {detail[:240]}'
            raise ProviderAdapterError(message, status_code=502, details={'checked_at': _utc_timestamp()}) from exc
        except URLError as exc:
            reason = getattr(exc, 'reason', exc)
            raise ProviderAdapterError(
                f'Could not reach LiteLLM at {base_url}: {reason}',
                status_code=502,
                details={'checked_at': _utc_timestamp()},
            ) from exc
        except Exception as exc:  # pragma: no cover
            try:
                if log is not None:
                    log.exception('[ai-provider] litellm validation failed: %s', exc)
            except Exception:
                pass
            raise ProviderAdapterError(
                'Unexpected validation failure while contacting LiteLLM.',
                status_code=500,
                details={'checked_at': _utc_timestamp()},
            ) from exc

    def _build_generate_payload(self, *, model: str, prompt: str, response_format: dict[str, Any]) -> dict[str, Any]:
        return {
            'model': model,
            'messages': [
                {
                    'role': 'user',
                    'content': prompt,
                },
            ],
            'temperature': 0.1,
            'response_format': response_format,
            'stream': False,
        }

    def _generate_once(self, *, base_url: str, api_key: str, model: str, prompt: str, timeout_seconds: float) -> tuple[str, dict[str, Any], str]:
        response_format = {'type': 'json_object'}
        response = _post_json(
            _litellm_chat_completions_url(base_url),
            self._build_generate_payload(model=model, prompt=prompt, response_format=response_format),
            timeout=timeout_seconds,
            headers=_litellm_request_headers(api_key),
        )
        raw_generation = _extract_litellm_message_text(response)
        parsed_generation = _extract_json_candidate(raw_generation)
        return raw_generation, parsed_generation or {}, 'json_object'

    def generate(self, payload: dict[str, Any], *, current_scenario: dict[str, Any], user_prompt: str, log: Any = None) -> dict[str, Any]:
        model = str(payload.get('model') or '').strip()
        if not model:
            raise ProviderAdapterError('model is required.')

        enforce_ssl = _payload_bool(payload.get('enforce_ssl'), default=True)
        try:
            base_url = _normalize_litellm_base_url(payload.get('base_url'), enforce_ssl=enforce_ssl)
        except ValueError as exc:
            raise ProviderAdapterError(str(exc)) from exc

        timeout_raw = payload.get('timeout_seconds')
        try:
            timeout_seconds = float(timeout_raw) if timeout_raw is not None else 90.0
        except (TypeError, ValueError):
            timeout_seconds = 90.0
        timeout_seconds = min(max(timeout_seconds, 5.0), 240.0)

        api_key = str(payload.get('api_key') or '').strip()
        prompt = _build_ollama_prompt(current_scenario, user_prompt)
        provider_attempts: list[dict[str, Any]] = []
        try:
            raw_generation, parsed_generation, format_mode = self._generate_once(
                base_url=base_url,
                api_key=api_key,
                model=model,
                prompt=prompt,
                timeout_seconds=timeout_seconds,
            )
            provider_attempts.append({'attempt': 'initial', 'format_mode': format_mode, 'response': raw_generation})
            if not isinstance(parsed_generation, dict) or not parsed_generation:
                repair_prompt = _build_ollama_repair_prompt(current_scenario, user_prompt, raw_generation)
                raw_generation, parsed_generation, format_mode = self._generate_once(
                    base_url=base_url,
                    api_key=api_key,
                    model=model,
                    prompt=repair_prompt,
                    timeout_seconds=timeout_seconds,
                )
                provider_attempts.append({'attempt': 'repair', 'format_mode': format_mode, 'response': raw_generation})
                prompt = repair_prompt
            if not isinstance(parsed_generation, dict) or not parsed_generation:
                raise ProviderAdapterError(
                    'LiteLLM did not return valid JSON for scenario generation.',
                    status_code=502,
                    details={
                        'provider_response': str((provider_attempts[-1].get('response') if provider_attempts else '') or '')[:4000],
                        'provider_attempts': provider_attempts,
                    },
                )
            return {
                'provider': 'litellm',
                'base_url': base_url,
                'model': model,
                'prompt_used': prompt,
                'provider_response': str((provider_attempts[-1].get('response') if provider_attempts else '') or ''),
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
            message = f'LiteLLM returned HTTP {exc.code}.'
            if detail:
                message = f'{message} {detail[:240]}'
            raise ProviderAdapterError(message, status_code=502) from exc
        except URLError as exc:
            reason = getattr(exc, 'reason', exc)
            raise ProviderAdapterError(f'Could not reach LiteLLM at {base_url}: {reason}', status_code=502) from exc
        except Exception as exc:  # pragma: no cover
            try:
                if log is not None:
                    log.exception('[ai-provider] litellm generation failed: %s', exc)
            except Exception:
                pass
            raise ProviderAdapterError(
                'Unexpected generation failure while contacting LiteLLM.',
                status_code=500,
            ) from exc


_PROVIDER_REGISTRY: dict[str, ProviderAdapter] = {
    'ollama': OllamaProviderAdapter(),
    'litellm': LiteLlmProviderAdapter(),
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
    if not begin_route_registration(app, 'ai_provider_routes'):
        return

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
            if _should_use_mcp_bridge_for_request(adapter, payload, skip_bridge=skip_bridge):
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

        skip_bridge = bool(payload.get('skip_bridge'))
        if _should_use_mcp_bridge_for_request(adapter, payload, skip_bridge=skip_bridge):
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
                'prompt_coverage_mismatch': generation_result.get('prompt_coverage_mismatch'),
                'prompt_coverage_retry_used': bool(generation_result.get('prompt_coverage_retry_used')),
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
            if isinstance(adapter, OllamaProviderAdapter) and _is_ollama_direct_json_generation_failure(exc):
                model = str(payload.get('model') or '').strip()
                if not model:
                    return jsonify({'success': False, 'error': exc.message, **exc.details}), exc.status_code
                try:
                    base_url = _normalize_base_url(payload.get('base_url'))
                    generation_result = asyncio.run(_mcp_bridge_generate(
                        _build_bridge_fallback_payload(payload),
                        current_scenario=current_scenario,
                        user_prompt=user_prompt,
                        model=model,
                        host=base_url,
                    ))
                except ProviderAdapterError as bridge_exc:
                    details = dict(bridge_exc.details or {})
                    details.setdefault('direct_generation_error', exc.message)
                    return jsonify({'success': False, 'error': bridge_exc.message, **details}), bridge_exc.status_code
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
                    'prompt_coverage_mismatch': generation_result.get('prompt_coverage_mismatch'),
                    'prompt_coverage_retry_used': bool(generation_result.get('prompt_coverage_retry_used')),
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
                    'direct_generation_error': exc.message,
                })
            else:
                return jsonify({'success': False, 'error': exc.message, **exc.details}), exc.status_code

        try:
            provider = generation_result.get('provider') or str(payload.get('provider') or 'ollama').strip().lower()
            base_url = generation_result.get('base_url') or ''
            model = generation_result.get('model') or str(payload.get('model') or '').strip()
            prompt = generation_result.get('prompt_used') or ''
            raw_generation = str(generation_result.get('provider_response') or '').strip()
            seed_scenario = _build_ai_seed_scenario_for_prompt(current_scenario, user_prompt)
            merged_scenario = _normalize_generated_scenario(seed_scenario, generation_result.get('parsed_generation') or {})
            merged_scenario = _restore_preserved_scenario_metadata(current_scenario, merged_scenario)
            merged_scenario = _overlay_compiled_intent_sections(merged_scenario, user_prompt)
            merged_scenario = _canonicalize_generated_vulnerabilities_or_raise(merged_scenario)
            _ensure_explicit_vulnerability_query_matches_or_raise(user_prompt, merged_scenario)
            merged_scenario = _canonicalize_generated_routing_modes(merged_scenario)
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

            preview_resp, preview_json = _dispatch_preview_full(preview_body)

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
        skip_bridge = bool(payload.get('skip_bridge'))
        request_id = str(payload.get('request_id') or '').strip() or _create_stream_request_id()
        stream_entry = _register_ai_stream(request_id)

        @stream_with_context
        def _stream_events():
            try:
                adapter = _get_provider_adapter(payload.get('provider'))
                if _should_use_mcp_bridge_for_request(adapter, payload, skip_bridge=skip_bridge):
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
                                user_prompt=user_prompt,
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
                        if isinstance(adapter, OllamaProviderAdapter):
                            try:
                                generation_result = _generate_ollama_streaming_result(
                                    payload,
                                    current_scenario=current_scenario,
                                    user_prompt=user_prompt,
                                    emit=emit,
                                    cancellation_check=is_cancelled,
                                    on_response_open=on_response_open,
                                )
                            except ProviderAdapterError as exc:
                                if not _is_ollama_direct_json_generation_failure(exc):
                                    raise
                                model = str(payload.get('model') or '').strip()
                                if not model:
                                    raise
                                emit('status', message='Direct Ollama JSON generation failed. Falling back to MCP bridge…')
                                base_url = _normalize_base_url(payload.get('base_url'))
                                generation_result = asyncio.run(_mcp_bridge_generate_with_events(
                                    _build_bridge_fallback_payload(payload),
                                    current_scenario=current_scenario,
                                    user_prompt=user_prompt,
                                    model=model,
                                    host=base_url,
                                    emit=emit,
                                    cancel_check=is_cancelled,
                                    on_client_ready=lambda client: stream_entry.__setitem__('client', client),
                                    on_response_open=on_response_open,
                                ))
                        else:
                            emit('status', message='Contacting provider...')
                            generation_result = adapter.generate(
                                payload,
                                current_scenario=current_scenario,
                                user_prompt=user_prompt,
                                log=log,
                            )
                            raw_generation = str(generation_result.get('provider_response') or '').strip()
                            if raw_generation:
                                emit('llm_delta', text=raw_generation)
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
                            user_prompt=user_prompt,
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
                        provider_label = getattr(adapter.capability, 'label', 'provider')
                        emit('error', error=f'Unexpected generation failure while contacting {provider_label}.')
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

    mark_routes_registered(app, 'ai_provider_routes')


try:
    _app = getattr(app_backend, 'app', None)
    if _app is not None:
        register(_app, logger=getattr(_app, 'logger', None))
except Exception:
    pass