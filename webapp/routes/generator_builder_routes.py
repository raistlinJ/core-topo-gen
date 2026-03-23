from __future__ import annotations

import json
import os
import queue
import re
import shutil
import tempfile
import threading
import time
import uuid
from typing import Any, Callable
from urllib.error import HTTPError, URLError

from flask import Response, jsonify, render_template, request, send_file, stream_with_context
from werkzeug.utils import secure_filename

from webapp.routes._registration import begin_route_registration, mark_routes_registered


_GROUNDING_CACHE: dict[str, str] = {}
_BUILD_GENERATOR_SCAFFOLD: Callable[[dict[str, Any]], tuple[dict[str, str], str, str]] | None = None


def _derive_plugin_id(name_hint: str, *, fallback: str = 'generated_generator') -> str:
    text = re.sub(r'[^a-zA-Z0-9_.\-]+', '_', str(name_hint or '').strip())
    text = re.sub(r'_+', '_', text).strip('_')
    return text or fallback


def _coerce_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        items = value
    elif value is None:
        items = []
    else:
        items = str(value).splitlines()
    result: list[str] = []
    for item in items:
        text = str(item or '').strip()
        if text:
            result.append(text)
    return result


def _coerce_requires(value: Any, optional_value: Any = None) -> tuple[list[dict[str, Any]], list[str]]:
    normalized: list[dict[str, Any]] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                artifact = str(item.get('artifact') or '').strip()
                if not artifact:
                    continue
                normalized.append({'artifact': artifact, 'optional': bool(item.get('optional'))})
            else:
                artifact = str(item or '').strip()
                if artifact:
                    normalized.append({'artifact': artifact, 'optional': False})
    elif value is not None:
        for artifact in _coerce_string_list(value):
            normalized.append({'artifact': artifact, 'optional': False})

    optional_list = _coerce_string_list(optional_value)
    optional_set = {artifact for artifact in optional_list if artifact}
    next_normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in normalized:
        artifact = str(item.get('artifact') or '').strip()
        if not artifact or artifact in seen:
            continue
        seen.add(artifact)
        next_normalized.append({'artifact': artifact, 'optional': bool(item.get('optional')) or artifact in optional_set})
    for artifact in optional_list:
        if artifact and artifact not in seen:
            next_normalized.append({'artifact': artifact, 'optional': True})
            seen.add(artifact)
    return next_normalized, optional_list


def _coerce_runtime_inputs(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            continue
        name = str(item.get('name') or '').strip()
        if not name or name in seen:
            continue
        seen.add(name)
        record: dict[str, Any] = {
            'name': name,
            'type': str(item.get('type') or 'string').strip() or 'string',
            'required': bool(item.get('required', True)),
        }
        if item.get('sensitive') is True:
            record['sensitive'] = True
        normalized.append(record)
    return normalized


def _extract_json_object(text: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    candidates = [str(text or '').strip()]
    fenced = re.findall(r'```(?:json)?\s*(.*?)```', str(text or ''), flags=re.IGNORECASE | re.DOTALL)
    candidates.extend(fragment.strip() for fragment in fenced if fragment and fragment.strip())
    for candidate in candidates:
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
        start = candidate.find('{')
        if start < 0:
            continue
        try:
            parsed, _offset = decoder.raw_decode(candidate[start:])
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            continue
    raise ValueError('AI response did not contain a valid JSON object.')


def _build_direct_generation_prompt(messages: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for message in messages:
        role = str(message.get('role') or '').strip().lower()
        content = str(message.get('content') or '').strip()
        if not content:
            continue
        if role == 'system':
            parts.append(content)
        elif role == 'user':
            parts.append(f'User request:\n{content}')
        else:
            parts.append(f'{role.title()}:\n{content}')
    return '\n\n'.join(parts).strip()


def _generate_builder_ollama_response(
    ai_provider_routes: Any,
    *,
    messages: list[dict[str, Any]],
    model: str,
    base_url: str,
    verify_ssl: bool,
    timeout_seconds: float,
) -> str:
    prompt = _build_direct_generation_prompt(messages)
    try:
        raw_response = ai_provider_routes._post_json(
            f'{base_url}/api/generate',
            {
                'model': model,
                'prompt': prompt,
                'stream': False,
                'format': 'json',
                'options': {'temperature': 0.1},
            },
            timeout=timeout_seconds,
            verify_ssl=verify_ssl,
        )
    except HTTPError as exc:
        raise ai_provider_routes.ProviderAdapterError(
            f'Ollama request failed with HTTP {exc.code}.',
            status_code=502,
        ) from exc
    except URLError as exc:
        reason = getattr(exc, 'reason', exc)
        raise ai_provider_routes.ProviderAdapterError(
            f'Could not reach Ollama at {base_url}: {reason}',
            status_code=502,
        ) from exc
    assistant_text = str(raw_response.get('response') or '').strip()
    if not assistant_text:
        assistant_text = str(raw_response.get('thinking') or '').strip()
    if not assistant_text:
        raise ai_provider_routes.ProviderAdapterError('Ollama returned an empty response.', status_code=502)
    return assistant_text


def _generate_builder_ollama_streaming_response(
    ai_provider_routes: Any,
    *,
    messages: list[dict[str, Any]],
    model: str,
    base_url: str,
    verify_ssl: bool,
    timeout_seconds: float,
    emit: Callable[..., None],
    cancellation_check: Callable[[], bool] | None = None,
    on_response_open: Callable[[Any], None] | None = None,
) -> str:
    prompt = _build_direct_generation_prompt(messages)
    emit('llm_prompt', text=prompt)
    raw_parts: list[str] = []
    thinking_parts: list[str] = []
    try:
        for chunk in ai_provider_routes._stream_json_lines(
            f'{base_url}/api/generate',
            {
                'model': model,
                'prompt': prompt,
                'stream': True,
                'format': 'json',
                'options': {'temperature': 0.1},
            },
            timeout=timeout_seconds,
            verify_ssl=verify_ssl,
            cancellation_check=cancellation_check,
            on_open=on_response_open,
        ):
            if cancellation_check and cancellation_check():
                raise ai_provider_routes.ProviderAdapterError('Generation cancelled by user.', status_code=499)
            delta = str(chunk.get('response') or '')
            if delta:
                raw_parts.append(delta)
                emit('llm_delta', text=delta)
            thinking = str(chunk.get('thinking') or '')
            if thinking:
                thinking_parts.append(thinking)
                emit('llm_thinking', text=thinking)
    except HTTPError as exc:
        raise ai_provider_routes.ProviderAdapterError(
            f'Ollama request failed with HTTP {exc.code}.',
            status_code=502,
        ) from exc
    except URLError as exc:
        reason = getattr(exc, 'reason', exc)
        raise ai_provider_routes.ProviderAdapterError(
            f'Could not reach Ollama at {base_url}: {reason}',
            status_code=502,
        ) from exc
    assistant_text = ''.join(raw_parts).strip()
    if not assistant_text:
        assistant_text = ''.join(thinking_parts).strip()
    if not assistant_text:
        raise ai_provider_routes.ProviderAdapterError('Ollama returned an empty response.', status_code=502)
    return assistant_text


def _build_builder_ai_scaffold_result(
    payload: dict[str, Any],
    *,
    ai_provider_routes: Any,
    emit: Callable[..., None] | None = None,
    cancellation_check: Callable[[], bool] | None = None,
    on_response_open: Callable[[Any], None] | None = None,
) -> dict[str, Any]:
    if _BUILD_GENERATOR_SCAFFOLD is None:
        raise RuntimeError('build_generator_scaffold is not configured')
    messages = _build_generator_builder_ai_messages(payload)
    provider = str(payload.get('provider') or 'ollama').strip().lower() or 'ollama'
    adapter = ai_provider_routes._get_provider_adapter(provider)
    model = str(payload.get('model') or '').strip()
    if not model:
        raise ValueError('model is required')
    base_url = str(payload.get('base_url') or '').strip() or str(adapter.capability.default_base_url or '').strip()
    if not base_url:
        raise ValueError('base_url is required')
    enforce_ssl = ai_provider_routes._payload_bool(payload.get('enforce_ssl'), default=True)
    if provider in {'litellm', 'openai'}:
        base_url = ai_provider_routes._normalize_openai_compatible_base_url(base_url, enforce_ssl=enforce_ssl)
    else:
        base_url = ai_provider_routes._normalize_base_url(base_url)
    timeout_seconds = ai_provider_routes._normalize_bridge_timeout_seconds(
        payload.get('timeout_seconds'),
        default=240.0,
        low=5.0,
        high=240.0,
    )

    direct_prompt = _build_direct_generation_prompt(messages)
    if emit is not None:
        emit('status', message='Preparing Builder prompt...')
        if provider != 'ollama':
            emit('llm_prompt', text=direct_prompt)
        emit('status', message=f'Contacting {provider}...')

    if provider == 'ollama' and emit is not None:
        assistant_text = _generate_builder_ollama_streaming_response(
            ai_provider_routes,
            messages=messages,
            model=model,
            base_url=base_url,
            verify_ssl=enforce_ssl,
            timeout_seconds=timeout_seconds,
            emit=emit,
            cancellation_check=cancellation_check,
            on_response_open=on_response_open,
        )
    elif provider == 'ollama':
        assistant_text = _generate_builder_ollama_response(
            ai_provider_routes,
            messages=messages,
            model=model,
            base_url=base_url,
            verify_ssl=enforce_ssl,
            timeout_seconds=timeout_seconds,
        )
    else:
        client = ai_provider_routes._RepoMcpBridgeClient(
            model=model,
            host=base_url,
            provider=provider,
            api_key=str(payload.get('api_key') or '').strip(),
            verify_ssl=enforce_ssl,
        )
        client.timeout_seconds = timeout_seconds
        raw_response = client._post_chat(messages=messages)
        if client._uses_openai_chat_completions():
            assistant_message = ai_provider_routes._extract_openai_chat_message(raw_response)
        else:
            assistant_message = ai_provider_routes._extract_ollama_chat_message(raw_response)
        assistant_text = str(assistant_message.get('content') or '').strip()
        if emit is not None and assistant_text:
            emit('llm_delta', text=assistant_text)

    if cancellation_check and cancellation_check():
        raise ai_provider_routes.ProviderAdapterError('Generation cancelled by user.', status_code=499)
    if emit is not None:
        emit('status', message='Normalizing scaffold...')
    ai_payload = _extract_json_object(assistant_text)
    scaffold_payload = _normalize_ai_scaffold_payload(ai_payload, payload)
    scaffold_files, manifest_yaml, folder_path = _BUILD_GENERATOR_SCAFFOLD(scaffold_payload)
    return {
        'ok': True,
        'provider': provider,
        'base_url': base_url,
        'model': model,
        'assistant_json': ai_payload,
        'assistant_text': assistant_text,
        'scaffold_request': scaffold_payload,
        'folder_path': folder_path,
        'manifest_yaml': manifest_yaml,
        'scaffold_paths': sorted(scaffold_files.keys()),
        'files': scaffold_files,
    }


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _read_grounding_file(rel_path: str) -> str:
    cached = _GROUNDING_CACHE.get(rel_path)
    if cached is not None:
        return cached
    abs_path = os.path.join(_repo_root(), rel_path)
    try:
        with open(abs_path, 'r', encoding='utf-8') as handle:
            text = handle.read().strip()
    except Exception:
        text = ''
    _GROUNDING_CACHE[rel_path] = text
    return text


def _render_grounding_section(title: str, rel_path: str) -> list[str]:
    text = _read_grounding_file(rel_path)
    if not text:
        return []
    return [
        f'{title} ({rel_path}):',
        '```text',
        text,
        '```',
        '',
    ]


def _extract_markdown_section(rel_path: str, heading: str) -> str:
    text = _read_grounding_file(rel_path)
    if not text:
        return ''
    lines = text.splitlines()
    start_index = -1
    for index, line in enumerate(lines):
        if line.strip() == heading.strip():
            start_index = index
            break
    if start_index < 0:
        return ''
    collected: list[str] = []
    for index in range(start_index, len(lines)):
        line = lines[index]
        if index > start_index and line.startswith('## '):
            break
        collected.append(line)
    return '\n'.join(collected).strip()


def _render_grounding_excerpt(title: str, rel_path: str, heading: str) -> list[str]:
    text = _extract_markdown_section(rel_path, heading)
    if not text:
        return []
    return [
        f'{title} ({rel_path} :: {heading}):',
        '```text',
        text,
        '```',
        '',
    ]


def _build_generator_grounding_lines(plugin_type: str) -> list[str]:
    if plugin_type == 'flag-node-generator':
        template_base = 'generator_templates/flag-node-generator-python-compose'
        sample_base = 'flag_node_generators/py_sample_nfs_sensitive_file'
    else:
        template_base = 'generator_templates/flag-generator-python-compose'
        sample_base = 'flag_generators/py_sample_textfile_username_password'

    lines = [
        'Repo authoring guidance:',
        '- Start from the provided template scaffold for this generator family.',
        '- Keep manifest artifacts and outputs.json keys aligned exactly.',
        '- Preserve test-vs-execute parity; do not rely on incidental environment state.',
        '- Keep the implementation deterministic for the same inputs.',
        '',
    ]
    lines.extend(_render_grounding_excerpt(
        'Reference docs excerpt: AI scaffolding quickstart',
        'docs/GENERATOR_AUTHORING.md',
        '## 0) AI scaffolding quickstart',
    ))
    lines.extend(_render_grounding_section('Reference template: generator.py', f'{template_base}/generator.py'))
    lines.extend(_render_grounding_section('Reference template: docker-compose.yml', f'{template_base}/docker-compose.yml'))
    lines.extend(_render_grounding_section('Reference sample: manifest.yaml', f'{sample_base}/manifest.yaml'))
    lines.extend(_render_grounding_section('Reference sample: generator.py', f'{sample_base}/generator.py'))
    return lines


def _extract_builder_failure_text(last_test_result: dict[str, Any] | None) -> str:
    if not isinstance(last_test_result, dict):
        return ''
    parts = [
        str(last_test_result.get('failure_summary') or '').strip(),
        str(last_test_result.get('stderr') or '').strip(),
        str(last_test_result.get('stdout') or '').strip(),
        str(last_test_result.get('log_tail') or '').strip(),
    ]
    return '\n'.join(part for part in parts if part).strip()


def _build_targeted_failure_guidance(last_test_result: dict[str, Any] | None) -> list[str]:
    text = _extract_builder_failure_text(last_test_result)
    lowered = text.lower()
    if not text:
        return []
    lines: list[str] = []
    if 'inject_files validation failed' in lowered or 'inject_files staging failed' in lowered:
        lines.extend([
            'Observed failure to fix first: inject_files referenced file paths that were never created.',
            '- inject_files entries are validated as real files under /outputs or /outputs/artifacts before success exit.',
            '- If you keep inject_files: ["File(path)"], then outputs.json.outputs["File(path)"] must point to a file that the generator actually writes, for example artifacts/challenge.bin.',
            '- Do not list inject_files unless the corresponding file artifact is produced every successful run.',
            '- If no injected file is needed, remove inject_files and remove File(path) from produces.',
            '',
        ])
    if 'failed to generate base image' in lowered:
        lines.extend([
            'Observed failure to fix first: the generator attempted to build or synthesize a base image and failed at runtime.',
            '- Ensure all required dependencies are installed explicitly in the runtime image.',
            '- Do not hide the concrete exception behind a generic failure message.',
            '- Create required parent directories before writing generated assets.',
            '',
        ])
    return lines


def _split_outside_parens(value: str, *, delimiters: str = ',') -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    for ch in str(value or ''):
        if ch in delimiters and depth == 0:
            part = ''.join(buf).strip()
            if part:
                parts.append(part)
            buf = []
            continue
        if ch == '(':
            depth += 1
        elif ch == ')' and depth > 0:
            depth -= 1
        buf.append(ch)
    tail = ''.join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _parse_runtime_input_spec(text: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    normalized = str(text or '').replace('\n', ',')
    for raw_part in _split_outside_parens(normalized, delimiters=','):
        part = str(raw_part or '').strip().rstrip('.')
        if not part:
            continue
        match = re.match(r'(?P<name>[A-Za-z0-9_]+)\s*(?:\((?P<meta>[^)]*)\))?$', part)
        if not match:
            continue
        name = str(match.group('name') or '').strip()
        meta = str(match.group('meta') or '').strip().lower()
        if not name:
            continue
        record: dict[str, Any] = {'name': name, 'type': 'string', 'required': True}
        if 'optional' in meta:
            record['required'] = False
        if 'sensitive' in meta:
            record['sensitive'] = True
        result.append(record)
    return _coerce_runtime_inputs(result)


def _parse_artifact_requirements_spec(text: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    normalized = str(text or '').replace('\n', ', ')
    required_match = re.search(r'require\s+(.+?)(?:\.|$)', normalized, flags=re.IGNORECASE)
    if required_match:
        for artifact in _split_outside_parens(required_match.group(1), delimiters=','):
            art = str(artifact or '').strip().rstrip('.')
            if art:
                results.append({'artifact': art, 'optional': False})
    optional_match = re.search(r'(?:optionally\s+accept|optional(?:ly)?\s+accepts?)\s+(.+?)(?:\.|$)', normalized, flags=re.IGNORECASE)
    if optional_match:
        for artifact in _split_outside_parens(optional_match.group(1), delimiters=','):
            art = str(artifact or '').strip().rstrip('.')
            if art:
                results.append({'artifact': art, 'optional': True})
    normalized, _ = _coerce_requires(results)
    return normalized


def _parse_artifact_override_requirements_spec(text: str) -> list[dict[str, Any]]:
    normalized_text = str(text or '').strip()
    if not normalized_text:
        return []
    if re.search(r'\brequire\b|\baccept\b', normalized_text, flags=re.IGNORECASE):
        return _parse_artifact_requirements_spec(normalized_text)
    results: list[dict[str, Any]] = []
    normalized = normalized_text.replace('\n', ', ')
    for artifact in _split_outside_parens(normalized, delimiters=','):
        part = str(artifact or '').strip().rstrip('.')
        if not part:
            continue
        optional = False
        optional_match = re.match(r'(.+?)\s*\((optional|required)\)$', part, flags=re.IGNORECASE)
        if optional_match:
            part = str(optional_match.group(1) or '').strip()
            optional = str(optional_match.group(2) or '').strip().lower() == 'optional'
        if part:
            results.append({'artifact': part, 'optional': optional})
    normalized_results, _ = _coerce_requires(results)
    return normalized_results


def _parse_artifact_outputs_spec(text: str) -> list[str]:
    normalized = str(text or '').strip().replace('\n', ',')
    parts = [part.strip().rstrip('.') for part in _split_outside_parens(normalized, delimiters=',')]
    outputs = [str(part or '').strip().rstrip('.') for part in parts]
    return [item for item in outputs if item]


def _parse_hint_templates_spec(text: str) -> list[str]:
    raw = str(text or '').strip()
    if not raw:
        return []
    if '\n' in raw:
        return [part.strip() for part in raw.splitlines() if part.strip()]
    if ';' in raw:
        parts = [part.strip() for part in raw.split(';') if part.strip()]
        return parts
    return [raw]


def _parse_readme_mentions_spec(text: str) -> list[str]:
    raw = str(text or '').strip()
    if not raw:
        return []
    normalized = raw.replace('\n', ', ')
    return [part.strip() for part in re.split(r'\s+and\s+|,\s*', normalized) if part.strip()]


def _format_runtime_input_spec(inputs: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for item in _coerce_runtime_inputs(inputs):
        name = str(item.get('name') or '').strip()
        if not name:
            continue
        flags = ['required' if item.get('required') is not False else 'optional']
        if item.get('sensitive') is True:
            flags.append('sensitive')
        lines.append(f"{name} ({', '.join(flags)})")
    return '\n'.join(lines)


def _format_requires_spec(requires: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for item in _coerce_requires(requires)[0]:
        artifact = str(item.get('artifact') or '').strip()
        if not artifact:
            continue
        lines.append(f"{artifact}{' (optional)' if item.get('optional') else ''}")
    return '\n'.join(lines)


def _format_string_list_spec(items: list[str]) -> str:
    return '\n'.join(_coerce_string_list(items))


def _apply_inject_destination(inject_files: list[str], destination: str) -> list[str]:
    dest = str(destination or '').strip()
    if not dest:
        return _coerce_string_list(inject_files)
    out: list[str] = []
    for item in _coerce_string_list(inject_files):
        if '->' in item:
            out.append(item)
        else:
            out.append(f'{item} -> {dest}')
    return out


def _compile_prompt_intent(prompt: str, plugin_type: str) -> dict[str, Any]:
    text = str(prompt or '').strip()
    lowered = text.lower()
    explicit: dict[str, Any] = {}
    inferred: dict[str, Any] = {}
    notes: dict[str, Any] = {
        'write_file_under_outputs_artifacts': False,
        'needs_hint_template': False,
        'readme_mentions': [],
        'inject_destination': '',
    }

    runtime_match = re.search(r'Runtime inputs:\s*(.+)', text, flags=re.IGNORECASE)
    if runtime_match:
        runtime_inputs = _parse_runtime_input_spec(runtime_match.group(1))
        if runtime_inputs:
            explicit['runtime_inputs'] = runtime_inputs

    req_match = re.search(r'Artifact requirements:\s*(.+)', text, flags=re.IGNORECASE)
    if req_match:
        requires = _parse_artifact_requirements_spec(req_match.group(1))
        if requires:
            explicit['requires'] = requires

    produces_match = re.search(r'Artifact outputs:\s*(.+)', text, flags=re.IGNORECASE)
    if produces_match:
        produces = _parse_artifact_outputs_spec(produces_match.group(1))
        if produces:
            explicit['produces'] = produces

    inject_match = re.search(r'Include\s+inject_files\s+with\s+(.+?)(?:\.|$)', text, flags=re.IGNORECASE)
    if inject_match:
        inject_items = _parse_artifact_outputs_spec(inject_match.group(1))
        if inject_items:
            explicit['inject_files'] = inject_items

    hint_match = re.search(r'Hint templates?:\s*(.+)', text, flags=re.IGNORECASE)
    if hint_match:
        hint_templates = _parse_hint_templates_spec(hint_match.group(1))
        if hint_templates:
            explicit['hint_templates'] = hint_templates

    inject_dest_match = re.search(r'Inject destination:\s*(.+?)(?:\.|$)', text, flags=re.IGNORECASE)
    if inject_dest_match:
        notes['inject_destination'] = str(inject_dest_match.group(1) or '').strip()

    if re.search(r'hint template', text, flags=re.IGNORECASE):
        notes['needs_hint_template'] = True

    readme_match = re.search(r'README should mention\s+(.+?)(?:\.|$)', text, flags=re.IGNORECASE)
    if readme_match:
        notes['readme_mentions'] = [part.strip() for part in re.split(r'\s+and\s+|,\s*', readme_match.group(1)) if part.strip()]

    if re.search(r'write\s+a\s+\w*\s*file\s+under\s+/outputs/artifacts/', lowered):
        notes['write_file_under_outputs_artifacts'] = True

    mentions_ssh_credentials = 'ssh' in lowered and any(token in lowered for token in ('credential', 'credentials', 'creds', 'password', 'username'))
    mentions_hint = 'hint' in lowered or 'next step' in lowered
    mentions_deterministic = 'determin' in lowered or 'same inputs' in lowered or 'same seed' in lowered
    mentions_web_creds = any(token in lowered for token in ('http basic', 'basic auth', 'web login', 'web creds', 'token gate', 'token auth'))
    mentions_ssh_key = 'ssh key' in lowered or 'authorized_keys' in lowered or 'private key' in lowered
    mentions_stego = any(token in lowered for token in ('stego', 'stegan', 'carrier image', 'png', 'jpeg', 'image flag'))

    if mentions_ssh_credentials and plugin_type == 'flag-generator':
        inferred['runtime_inputs'] = [
            {'name': 'seed', 'type': 'string', 'required': True},
            {'name': 'secret', 'type': 'string', 'required': True, 'sensitive': True},
            {'name': 'flag_prefix', 'type': 'string', 'required': False},
        ]
        inferred['requires'] = [
            {'artifact': 'Knowledge(ip)', 'optional': False},
            {'artifact': 'Knowledge(hostname)', 'optional': True},
        ]
        inferred['produces'] = ['Flag(flag_id)', 'Credential(user)', 'Credential(user,password)', 'File(path)']
        inferred['inject_files'] = ['File(path)']
        inferred['hint_templates'] = ['Next: SSH to {{NEXT_NODE_NAME}} using {{OUTPUT.Credential(user)}} / {{OUTPUT.Credential(user,password)}}']
        notes['write_file_under_outputs_artifacts'] = True
        notes['readme_mentions'] = list(dict.fromkeys(notes['readme_mentions'] + ['determinism', 'local runner testing']))

    if mentions_web_creds and plugin_type == 'flag-generator':
        inferred.setdefault('runtime_inputs', [
            {'name': 'seed', 'type': 'string', 'required': True},
            {'name': 'secret', 'type': 'string', 'required': True, 'sensitive': True},
            {'name': 'flag_prefix', 'type': 'string', 'required': False},
        ])
        inferred.setdefault('produces', ['Flag(flag_id)', 'Credential(user)', 'Credential(user,password)', 'File(path)'])
        inferred.setdefault('hint_templates', ['Next: browse to the service and authenticate with {{OUTPUT.Credential(user)}} / {{OUTPUT.Credential(user,password)}}'])
        notes['write_file_under_outputs_artifacts'] = True

    if mentions_ssh_key and plugin_type == 'flag-generator':
        inferred.setdefault('runtime_inputs', [
            {'name': 'seed', 'type': 'string', 'required': True},
            {'name': 'secret', 'type': 'string', 'required': True, 'sensitive': True},
            {'name': 'flag_prefix', 'type': 'string', 'required': False},
        ])
        inferred.setdefault('produces', ['Flag(flag_id)', 'Credential(user)', 'File(path)'])
        inferred.setdefault('inject_files', ['File(path)'])
        notes['write_file_under_outputs_artifacts'] = True

    if mentions_stego and plugin_type == 'flag-generator':
        inferred.setdefault('runtime_inputs', [
            {'name': 'seed', 'type': 'string', 'required': True},
            {'name': 'flag_prefix', 'type': 'string', 'required': False},
        ])
        inferred.setdefault('produces', ['Flag(flag_id)', 'File(path)'])
        inferred.setdefault('inject_files', ['File(path)'])
        notes['write_file_under_outputs_artifacts'] = True

    if mentions_hint:
        notes['needs_hint_template'] = True
    if mentions_deterministic:
        notes['readme_mentions'] = list(dict.fromkeys(notes['readme_mentions'] + ['determinism', 'local runner testing']))

    return {
        'explicit': explicit,
        'inferred': inferred,
        'notes': notes,
    }


def _parse_prompt_intent_overrides(overrides_payload: Any) -> dict[str, Any]:
    if not isinstance(overrides_payload, dict):
        return {'manual': {}, 'notes': {}, 'raw': {}}

    manual: dict[str, Any] = {}
    notes: dict[str, Any] = {}
    raw: dict[str, str] = {}

    runtime_text = str(overrides_payload.get('runtime_inputs') or '').strip()
    if runtime_text:
        raw['runtime_inputs'] = runtime_text
        runtime_inputs = _parse_runtime_input_spec(runtime_text)
        if runtime_inputs:
            manual['runtime_inputs'] = runtime_inputs

    requires_text = str(overrides_payload.get('requires') or '').strip()
    if requires_text:
        raw['requires'] = requires_text
        requires = _parse_artifact_override_requirements_spec(requires_text)
        if requires:
            manual['requires'] = requires

    produces_text = str(overrides_payload.get('produces') or '').strip()
    if produces_text:
        raw['produces'] = produces_text
        produces = _parse_artifact_outputs_spec(produces_text)
        if produces:
            manual['produces'] = produces

    inject_text = str(overrides_payload.get('inject_files') or '').strip()
    if inject_text:
        raw['inject_files'] = inject_text
        inject_files = _parse_artifact_outputs_spec(inject_text)
        if inject_files:
            manual['inject_files'] = inject_files

    inject_destination = str(overrides_payload.get('inject_destination') or '').strip()
    if inject_destination:
        raw['inject_destination'] = inject_destination
        notes['inject_destination'] = inject_destination

    if manual.get('inject_files'):
        manual['inject_files'] = _apply_inject_destination(manual.get('inject_files') or [], inject_destination)

    hint_text = str(overrides_payload.get('hint_templates') or '').strip()
    if hint_text:
        raw['hint_templates'] = hint_text
        hint_templates = _parse_hint_templates_spec(hint_text)
        if hint_templates:
            manual['hint_templates'] = hint_templates

    readme_text = str(overrides_payload.get('readme_mentions') or '').strip()
    if readme_text:
        raw['readme_mentions'] = readme_text
        notes['readme_mentions'] = _parse_readme_mentions_spec(readme_text)

    if 'write_file_under_outputs_artifacts' in overrides_payload:
        notes['write_file_under_outputs_artifacts'] = bool(overrides_payload.get('write_file_under_outputs_artifacts'))
    if 'needs_hint_template' in overrides_payload:
        notes['needs_hint_template'] = bool(overrides_payload.get('needs_hint_template'))

    return {'manual': manual, 'notes': notes, 'raw': raw}


def _resolve_prompt_intent(prompt: str, plugin_type: str, overrides_payload: Any = None) -> dict[str, Any]:
    compiled = _compile_prompt_intent(prompt, plugin_type)
    explicit = compiled.get('explicit') if isinstance(compiled.get('explicit'), dict) else {}
    inferred = compiled.get('inferred') if isinstance(compiled.get('inferred'), dict) else {}
    base_notes = dict(compiled.get('notes') or {}) if isinstance(compiled.get('notes'), dict) else {}
    override_bundle = _parse_prompt_intent_overrides(overrides_payload)
    manual = override_bundle.get('manual') if isinstance(override_bundle.get('manual'), dict) else {}
    manual_notes = override_bundle.get('notes') if isinstance(override_bundle.get('notes'), dict) else {}
    notes = {**base_notes, **manual_notes}

    merged: dict[str, Any] = {}
    for key in ('runtime_inputs', 'requires', 'produces', 'inject_files', 'hint_templates'):
        if manual.get(key):
            merged[key] = manual.get(key)
            continue
        if explicit.get(key):
            merged[key] = explicit.get(key)
            continue
        if inferred.get(key):
            merged[key] = inferred.get(key)

    inject_destination = str(notes.get('inject_destination') or '').strip()
    if merged.get('inject_files'):
        merged['inject_files'] = _apply_inject_destination(merged.get('inject_files') or [], inject_destination)

    editable = {
        'runtime_inputs': _format_runtime_input_spec(merged.get('runtime_inputs') or []),
        'requires': _format_requires_spec(merged.get('requires') or []),
        'produces': _format_string_list_spec(merged.get('produces') or []),
        'inject_files': _format_string_list_spec(merged.get('inject_files') or []),
        'inject_destination': inject_destination,
        'hint_templates': _format_string_list_spec(merged.get('hint_templates') or []),
        'readme_mentions': ', '.join(str(item).strip() for item in (notes.get('readme_mentions') or []) if str(item).strip()),
    }

    return {
        'manual': manual,
        'manual_notes': manual_notes,
        'manual_raw': override_bundle.get('raw') if isinstance(override_bundle.get('raw'), dict) else {},
        'explicit': explicit,
        'inferred': inferred,
        'merged': merged,
        'notes': notes,
        'editable': editable,
    }


def _merged_prompt_intent_defaults(prompt: str, plugin_type: str) -> dict[str, Any]:
    resolved = _resolve_prompt_intent(prompt, plugin_type)
    merged = dict(resolved.get('merged') or {}) if isinstance(resolved.get('merged'), dict) else {}
    merged['notes'] = resolved.get('notes') if isinstance(resolved.get('notes'), dict) else {}
    merged['explicit'] = resolved.get('explicit') if isinstance(resolved.get('explicit'), dict) else {}
    merged['inferred'] = resolved.get('inferred') if isinstance(resolved.get('inferred'), dict) else {}
    return merged


def _build_prompt_intent_preview(payload: dict[str, Any]) -> dict[str, Any]:
    plugin_type = str(payload.get('plugin_type') or 'flag-generator').strip() or 'flag-generator'
    prompt = str(payload.get('prompt') or '').strip()
    resolved = _resolve_prompt_intent(prompt, plugin_type, payload.get('intent_overrides'))
    manual = resolved.get('manual') if isinstance(resolved.get('manual'), dict) else {}
    explicit = resolved.get('explicit') if isinstance(resolved.get('explicit'), dict) else {}
    inferred = resolved.get('inferred') if isinstance(resolved.get('inferred'), dict) else {}
    notes = resolved.get('notes') if isinstance(resolved.get('notes'), dict) else {}
    merged = resolved.get('merged') if isinstance(resolved.get('merged'), dict) else {}
    manual_notes = resolved.get('manual_notes') if isinstance(resolved.get('manual_notes'), dict) else {}

    sections: list[dict[str, Any]] = []
    if manual:
        items: list[str] = []
        if manual.get('runtime_inputs'):
            items.append('Runtime inputs: ' + ', '.join(str(item.get('name')) for item in manual.get('runtime_inputs') if isinstance(item, dict)))
        if manual.get('requires'):
            items.append('Artifact requirements: ' + ', '.join(str(item.get('artifact')) + (' (optional)' if item.get('optional') else '') for item in manual.get('requires') if isinstance(item, dict)))
        if manual.get('produces'):
            items.append('Artifact outputs: ' + ', '.join(str(item) for item in manual.get('produces') or []))
        if manual.get('inject_files'):
            items.append('Inject files: ' + ', '.join(str(item) for item in manual.get('inject_files') or []))
        if manual.get('hint_templates'):
            items.append('Hint templates: ' + '; '.join(str(item) for item in manual.get('hint_templates') or []))
        manual_readme_mentions = [str(item).strip() for item in (manual_notes.get('readme_mentions') or []) if str(item).strip()]
        if manual_readme_mentions:
            items.append('README notes: ' + ', '.join(manual_readme_mentions))
        sections.append({'title': 'Manual Overrides', 'tone': 'warning', 'items': items})

    if explicit:
        items = []
        if explicit.get('runtime_inputs'):
            items.append('Runtime inputs: ' + ', '.join(str(item.get('name')) for item in explicit.get('runtime_inputs') if isinstance(item, dict)))
        if explicit.get('requires'):
            items.append('Artifact requirements: ' + ', '.join(str(item.get('artifact')) for item in explicit.get('requires') if isinstance(item, dict)))
        if explicit.get('produces'):
            items.append('Artifact outputs: ' + ', '.join(str(item) for item in explicit.get('produces') or []))
        if explicit.get('inject_files'):
            items.append('Inject files: ' + ', '.join(str(item) for item in explicit.get('inject_files') or []))
        if explicit.get('hint_templates'):
            items.append('Hint templates: ' + '; '.join(str(item) for item in explicit.get('hint_templates') or []))
        sections.append({'title': 'User-Specified', 'tone': 'primary', 'items': items})

    inferred_items: list[str] = []
    if not manual.get('runtime_inputs') and not explicit.get('runtime_inputs') and merged.get('runtime_inputs'):
        inferred_items.append('Runtime inputs: ' + ', '.join(str(item.get('name')) for item in merged.get('runtime_inputs') if isinstance(item, dict)))
    if not manual.get('requires') and not explicit.get('requires') and merged.get('requires'):
        inferred_items.append('Artifact requirements: ' + ', '.join(str(item.get('artifact')) for item in merged.get('requires') if isinstance(item, dict)))
    if not manual.get('produces') and not explicit.get('produces') and merged.get('produces'):
        inferred_items.append('Artifact outputs: ' + ', '.join(str(item) for item in merged.get('produces') or []))
    if not manual.get('inject_files') and not explicit.get('inject_files') and merged.get('inject_files'):
        inferred_items.append('Inject files: ' + ', '.join(str(item) for item in merged.get('inject_files') or []))
    if not manual.get('hint_templates') and not explicit.get('hint_templates') and merged.get('hint_templates'):
        inferred_items.append('Hint templates: ' + '; '.join(str(item) for item in merged.get('hint_templates') or []))
    if inferred_items:
        sections.append({'title': 'Inferred Defaults', 'tone': 'secondary', 'items': inferred_items})

    note_items: list[str] = []
    if notes.get('write_file_under_outputs_artifacts'):
        note_items.append('Write generated file artifacts under /outputs/artifacts/ when File(path) is used.')
    if notes.get('needs_hint_template'):
        note_items.append('Include a hint template only if referenced outputs are actually produced.')
    if notes.get('inject_destination'):
        note_items.append(f'Inject destination: {notes.get("inject_destination")}')
    readme_mentions = [str(item).strip() for item in (notes.get('readme_mentions') or []) if str(item).strip()]
    if readme_mentions:
        note_items.append('README notes: ' + ', '.join(readme_mentions))
    if note_items:
        sections.append({'title': 'Notes', 'tone': 'info', 'items': note_items})

    return {
        'ok': True,
        'plugin_type': plugin_type,
        'manual': manual,
        'explicit': explicit,
        'inferred': inferred,
        'merged': {k: v for k, v in merged.items() if k in {'runtime_inputs', 'requires', 'produces', 'inject_files', 'hint_templates'}},
        'notes': notes,
        'sections': sections,
        'editable': resolved.get('editable') if isinstance(resolved.get('editable'), dict) else {},
    }


def _merged_prompt_intent_defaults(prompt: str, plugin_type: str) -> dict[str, Any]:
    resolved = _resolve_prompt_intent(prompt, plugin_type)
    merged = dict(resolved.get('merged') or {}) if isinstance(resolved.get('merged'), dict) else {}
    merged['notes'] = resolved.get('notes') if isinstance(resolved.get('notes'), dict) else {}
    merged['explicit'] = resolved.get('explicit') if isinstance(resolved.get('explicit'), dict) else {}
    merged['inferred'] = resolved.get('inferred') if isinstance(resolved.get('inferred'), dict) else {}
    return merged


def _build_prompt_intent_preview(payload: dict[str, Any]) -> dict[str, Any]:
    plugin_type = str(payload.get('plugin_type') or 'flag-generator').strip() or 'flag-generator'
    prompt = str(payload.get('prompt') or '').strip()
    resolved = _resolve_prompt_intent(prompt, plugin_type, payload.get('intent_overrides'))
    manual = resolved.get('manual') if isinstance(resolved.get('manual'), dict) else {}
    explicit = resolved.get('explicit') if isinstance(resolved.get('explicit'), dict) else {}
    inferred = resolved.get('inferred') if isinstance(resolved.get('inferred'), dict) else {}
    notes = resolved.get('notes') if isinstance(resolved.get('notes'), dict) else {}
    merged = resolved.get('merged') if isinstance(resolved.get('merged'), dict) else {}

    sections: list[dict[str, Any]] = []
    if manual:
        items: list[str] = []
        if manual.get('runtime_inputs'):
            items.append('Runtime inputs: ' + ', '.join(str(item.get('name')) for item in manual.get('runtime_inputs') if isinstance(item, dict)))
        if manual.get('requires'):
            items.append('Artifact requirements: ' + ', '.join(str(item.get('artifact')) + (' (optional)' if item.get('optional') else '') for item in manual.get('requires') if isinstance(item, dict)))
        if manual.get('produces'):
            items.append('Artifact outputs: ' + ', '.join(str(item) for item in manual.get('produces') or []))
        if manual.get('inject_files'):
            items.append('Inject files: ' + ', '.join(str(item) for item in manual.get('inject_files') or []))
        if manual.get('hint_templates'):
            items.append('Hint templates: ' + '; '.join(str(item) for item in manual.get('hint_templates') or []))
        manual_readme_mentions = [str(item).strip() for item in (resolved.get('manual_notes') or {}).get('readme_mentions', []) if str(item).strip()]
        if manual_readme_mentions:
            items.append('README notes: ' + ', '.join(manual_readme_mentions))
        sections.append({'title': 'Manual Overrides', 'tone': 'warning', 'items': items})

    if explicit:
        items: list[str] = []
        if explicit.get('runtime_inputs'):
            items.append('Runtime inputs: ' + ', '.join(str(item.get('name')) for item in explicit.get('runtime_inputs') if isinstance(item, dict)))
        if explicit.get('requires'):
            items.append('Artifact requirements: ' + ', '.join(str(item.get('artifact')) for item in explicit.get('requires') if isinstance(item, dict)))
        if explicit.get('produces'):
            items.append('Artifact outputs: ' + ', '.join(str(item) for item in explicit.get('produces') or []))
        if explicit.get('inject_files'):
            items.append('Inject files: ' + ', '.join(str(item) for item in explicit.get('inject_files') or []))
        if explicit.get('hint_templates'):
            items.append('Hint templates: ' + '; '.join(str(item) for item in explicit.get('hint_templates') or []))
        sections.append({'title': 'User-Specified', 'tone': 'primary', 'items': items})

    inferred_items: list[str] = []
    if not explicit.get('runtime_inputs') and merged.get('runtime_inputs'):
        inferred_items.append('Runtime inputs: ' + ', '.join(str(item.get('name')) for item in merged.get('runtime_inputs') if isinstance(item, dict)))
    if not explicit.get('requires') and merged.get('requires'):
        inferred_items.append('Artifact requirements: ' + ', '.join(str(item.get('artifact')) for item in merged.get('requires') if isinstance(item, dict)))
    if not explicit.get('produces') and merged.get('produces'):
        inferred_items.append('Artifact outputs: ' + ', '.join(str(item) for item in merged.get('produces') or []))
    if not explicit.get('inject_files') and merged.get('inject_files'):
        inferred_items.append('Inject files: ' + ', '.join(str(item) for item in merged.get('inject_files') or []))
    if not explicit.get('hint_templates') and merged.get('hint_templates'):
        inferred_items.append('Hint templates: ' + '; '.join(str(item) for item in merged.get('hint_templates') or []))
    if inferred_items:
        sections.append({'title': 'Inferred Defaults', 'tone': 'secondary', 'items': inferred_items})

    note_items: list[str] = []
    if notes.get('write_file_under_outputs_artifacts'):
        note_items.append('Write generated file artifacts under /outputs/artifacts/ when File(path) is used.')
    if notes.get('needs_hint_template'):
        note_items.append('Include a hint template only if referenced outputs are actually produced.')
    if notes.get('inject_destination'):
        note_items.append(f'Inject destination: {notes.get("inject_destination")}')
    readme_mentions = [str(item).strip() for item in (notes.get('readme_mentions') or []) if str(item).strip()]
    if readme_mentions:
        note_items.append('README notes: ' + ', '.join(readme_mentions))
    if note_items:
        sections.append({'title': 'Notes', 'tone': 'info', 'items': note_items})

    return {
        'ok': True,
        'plugin_type': plugin_type,
        'manual': manual,
        'explicit': explicit,
        'inferred': inferred,
        'merged': {k: v for k, v in merged.items() if k in {'runtime_inputs', 'requires', 'produces', 'inject_files', 'hint_templates'}},
        'notes': notes,
        'sections': sections,
        'editable': resolved.get('editable') if isinstance(resolved.get('editable'), dict) else {},
    }


def _build_prompt_intent_guidance(prompt: str, plugin_type: str, overrides_payload: Any = None) -> list[str]:
    resolved = _resolve_prompt_intent(prompt, plugin_type, overrides_payload)
    manual = resolved.get('manual') if isinstance(resolved.get('manual'), dict) else {}
    explicit = resolved.get('explicit') if isinstance(resolved.get('explicit'), dict) else {}
    inferred = resolved.get('inferred') if isinstance(resolved.get('inferred'), dict) else {}
    notes = resolved.get('notes') if isinstance(resolved.get('notes'), dict) else {}
    manual_notes = resolved.get('manual_notes') if isinstance(resolved.get('manual_notes'), dict) else {}
    if not (manual or explicit or inferred or notes):
        return []

    lines: list[str] = []
    if manual:
        lines.append('Builder preview overrides are set. These take precedence over both prompt-derived explicit requirements and heuristics:')
        if manual.get('runtime_inputs'):
            labels = []
            for item in manual.get('runtime_inputs') or []:
                if not isinstance(item, dict):
                    continue
                parts = ['required' if item.get('required') is not False else 'optional']
                if item.get('sensitive') is True:
                    parts.append('sensitive')
                labels.append(f"{item.get('name')} ({', '.join(parts)})")
            if labels:
                lines.append(f"- Respect these Builder override runtime inputs: {', '.join(labels)}.")
        if manual.get('requires'):
            req_labels = []
            for item in manual.get('requires') or []:
                if not isinstance(item, dict):
                    continue
                req_labels.append(f"{item.get('artifact')}{' (optional)' if item.get('optional') else ''}")
            if req_labels:
                lines.append(f"- Respect these Builder override artifact requirements: {', '.join(req_labels)}.")
        if manual.get('produces'):
            lines.append(f"- Respect these Builder override artifact outputs: {', '.join(str(x) for x in (manual.get('produces') or []))}.")
        if manual.get('inject_files'):
            lines.append(f"- Respect these Builder override inject_files entries: {', '.join(str(x) for x in (manual.get('inject_files') or []))}. Every one must resolve to a created output file.")
        if manual.get('hint_templates'):
            lines.append(f"- Respect these Builder override hint templates: {'; '.join(str(x) for x in (manual.get('hint_templates') or []))}.")
        manual_readme_mentions = [str(item).strip() for item in (manual_notes.get('readme_mentions') or []) if str(item).strip()]
        if manual_readme_mentions:
            lines.append(f"- Respect these Builder override README notes: {', '.join(manual_readme_mentions)}.")
        lines.append('')

    if explicit:
        lines.append('User-specified scaffold requirements detected in the prompt. These override heuristic defaults when there is any conflict:')
        if explicit.get('runtime_inputs'):
            labels = []
            for item in explicit.get('runtime_inputs') or []:
                if not isinstance(item, dict):
                    continue
                parts = []
                if item.get('required') is False:
                    parts.append('optional')
                else:
                    parts.append('required')
                if item.get('sensitive') is True:
                    parts.append('sensitive')
                labels.append(f"{item.get('name')} ({', '.join(parts)})")
            if labels:
                lines.append(f"- Respect these user-specified runtime inputs: {', '.join(labels)}.")
        if explicit.get('requires'):
            req_labels = []
            for item in explicit.get('requires') or []:
                if not isinstance(item, dict):
                    continue
                req_labels.append(f"{item.get('artifact')}{' (optional)' if item.get('optional') else ''}")
            if req_labels:
                lines.append(f"- Respect these user-specified artifact requirements: {', '.join(req_labels)}.")
        if explicit.get('produces'):
            lines.append(f"- Respect these user-specified artifact outputs: {', '.join(str(x) for x in (explicit.get('produces') or []))}.")
        if explicit.get('inject_files'):
            lines.append(f"- Respect these user-specified inject_files entries: {', '.join(str(x) for x in (explicit.get('inject_files') or []))}. Every one must resolve to a created output file.")
        lines.append('')

    if inferred:
        lines.append('Prompt-derived defaults to apply only when the prompt did not already specify a conflicting requirement:')
        if inferred.get('runtime_inputs'):
            labels = []
            for item in inferred.get('runtime_inputs') or []:
                if not isinstance(item, dict):
                    continue
                parts = []
                if item.get('required') is False:
                    parts.append('optional')
                else:
                    parts.append('required')
                if item.get('sensitive') is True:
                    parts.append('sensitive')
                labels.append(f"{item.get('name')} ({', '.join(parts)})")
            if labels:
                lines.append(f"- Suggested runtime inputs: {', '.join(labels)}.")
        if inferred.get('requires'):
            req_labels = []
            for item in inferred.get('requires') or []:
                if not isinstance(item, dict):
                    continue
                req_labels.append(f"{item.get('artifact')}{' (optional)' if item.get('optional') else ''}")
            if req_labels:
                lines.append(f"- Suggested artifact requirements: {', '.join(req_labels)}.")
        if inferred.get('produces'):
            lines.append(f"- Suggested artifact outputs: {', '.join(str(x) for x in (inferred.get('produces') or []))}.")
        if inferred.get('inject_files'):
            lines.append(f"- Suggested inject_files entries: {', '.join(str(x) for x in (inferred.get('inject_files') or []))}. Only keep them if the file artifacts are actually produced.")
        if inferred.get('hint_templates'):
            lines.append(f"- Suggested hint template shape: {str((inferred.get('hint_templates') or [''])[0])}.")
        lines.append('')

    if notes.get('write_file_under_outputs_artifacts'):
        lines.append('- Prompt-derived authoring hint: if the prompt asks for a generated file artifact, write it under /outputs/artifacts/ and expose it through outputs.json.')
    if notes.get('needs_hint_template'):
        lines.append('- Prompt-derived authoring hint: include a hint template only if the resulting outputs referenced by the template are actually produced.')
    readme_mentions = [str(item).strip() for item in (notes.get('readme_mentions') or []) if str(item).strip()]
    if readme_mentions:
        lines.append(f"- Prompt-derived authoring hint: README should mention {', '.join(readme_mentions)}.")
    if lines and lines[-1] != '':
        lines.append('')
    return lines


def _build_generator_builder_ai_messages(payload: dict[str, Any]) -> list[dict[str, str]]:
    plugin_type = str(payload.get('plugin_type') or 'flag-generator').strip() or 'flag-generator'
    source_id_hint = str(payload.get('source_id_hint') or '').strip()
    name_hint = str(payload.get('name_hint') or '').strip()
    prompt = str(payload.get('prompt') or '').strip()
    if not prompt:
        raise ValueError('prompt is required')

    kind_requirements = [
        '- For all generators: read /inputs/config.json and write /outputs/outputs.json.',
        '- outputs.json must include generator_id and Flag(flag_id).',
        '- Keep outputs deterministic for the same inputs.',
        '- Use Python standard library only unless the prompt explicitly requires otherwise.',
        '- Return JSON only. Do not wrap in markdown fences.',
        '- outputs.json.outputs keys must exactly match produces and must reference artifacts that actually exist by the time the generator exits successfully.',
        '- If you declare inject_files, every inject entry must resolve to a real generated file path, not just an ontology key name.',
    ]
    if plugin_type == 'flag-node-generator':
        kind_requirements.extend([
            '- Also write /outputs/docker-compose.yml.',
            '- Include File(path): docker-compose.yml in outputs.',
            '- Do not emit ${...} placeholders in docker-compose.yml.',
            '- Prefer explicit working_dir or absolute script paths in compose startup commands.',
        ])
    else:
        kind_requirements.extend([
            '- Do not write hint.txt unless explicitly required by the prompt.',
            '- If you emit files, write them under /outputs/artifacts/... and reference them from outputs.',
            '- If produces includes File(path), write the file under /outputs or /outputs/artifacts and set outputs.json.outputs["File(path)"] to that created path.',
            '- If inject_files includes File(path), the File(path) output must exist on disk before exit or the test will fail validation.',
        ])

    schema_lines = [
        '{',
        '  "plugin_id": "source_identifier",',
        '  "folder_name": "py_source_identifier",',
        '  "name": "Human-readable name",',
        '  "description": "One sentence summary",',
        '  "requires": [{"artifact": "Knowledge(ip)", "optional": false}],',
        '  "optional_requires": ["Knowledge(hostname)"],',
        '  "produces": ["Flag(flag_id)", "Credential(user,password)"],',
        '  "runtime_inputs": [{"name": "seed", "type": "string", "required": true}],',
        '  "hint_templates": ["Next: use {{OUTPUT.Credential(user,password)}}"],',
        '  "inject_files": ["File(path)"],',
        '  "env": {"EXAMPLE": "value"},',
        '  "compose_text": "full docker-compose.yml text",',
        '  "readme_text": "full README.md text",',
        '  "generator_py_text": "full generator.py text"',
        '}',
    ]

    current_scaffold = payload.get('current_scaffold_request') if isinstance(payload.get('current_scaffold_request'), dict) else None
    current_files = payload.get('current_files') if isinstance(payload.get('current_files'), dict) else None
    last_test_result = payload.get('last_test_result') if isinstance(payload.get('last_test_result'), dict) else None
    mode = 'refine' if current_scaffold else 'create'

    context_lines = [
        f'Mode: {mode}',
        f'Target kind: {plugin_type}',
        f'Source id hint: {source_id_hint or "(derive one)"}',
        f'Name hint: {name_hint or "(derive one)"}',
        '',
        'Compatibility requirements:',
        *kind_requirements,
        '',
        'Response contract:',
        '- Reply with exactly one JSON object.',
        '- Use requires as a list of {artifact, optional}.',
        '- Use runtime_inputs as a list of {name, type, required, sensitive?}.',
        '- Include full generator_py_text.',
        '- Include compose_text when the default scaffold would be insufficient.',
        '- Keep manifest-facing artifact keys and outputs.json keys aligned.',
        '- Treat inject_files as runtime file paths that must be created, not as abstract artifact declarations.',
        '- If inject_files references File(path), then produces must include File(path) and outputs.json.outputs["File(path)"] must point to a created file.',
        '',
        'JSON schema shape:',
        *schema_lines,
        '',
    ]
    context_lines.extend(_build_prompt_intent_guidance(prompt, plugin_type, payload.get('intent_overrides')))
    context_lines.extend(_build_generator_grounding_lines(plugin_type))
    if current_scaffold:
        context_lines.extend([
            'Current scaffold request (treat this as the existing generator state and preserve compatible parts unless the user asked to change them):',
            json.dumps(current_scaffold, indent=2, ensure_ascii=False),
            '',
        ])
    if current_files:
        selected_files: dict[str, str] = {}
        for key in sorted(current_files.keys()):
            text = str(current_files.get(key) or '')
            if key.endswith('/manifest.yaml') or key.endswith('/generator.py') or key.endswith('/README.md') or key.endswith('/docker-compose.yml'):
                selected_files[key] = text
        if selected_files:
            context_lines.extend([
                'Current scaffold files:',
                json.dumps(selected_files, indent=2, ensure_ascii=False),
                '',
            ])
    if last_test_result:
        test_summary = {
            'ok': bool(last_test_result.get('ok')),
            'returncode': last_test_result.get('returncode'),
            'stdout': str(last_test_result.get('stdout') or '')[-4000:],
            'stderr': str(last_test_result.get('stderr') or '')[-4000:],
            'failure_summary': str(last_test_result.get('failure_summary') or '')[-2000:],
            'files': last_test_result.get('files') if isinstance(last_test_result.get('files'), list) else [],
        }
        context_lines.extend([
            'Latest local test result:',
            json.dumps(test_summary, indent=2, ensure_ascii=False),
            '',
            'When refining, fix concrete test failures first before adding unrelated behavior.',
            '',
        ])
        context_lines.extend(_build_targeted_failure_guidance(last_test_result))
    context_lines.extend([
        'User request:',
        prompt,
    ])
    return [
        {
            'role': 'system',
            'content': 'You author CORE TopoGen generator scaffolds. Produce strict JSON only and optimize for runtime compatibility.',
        },
        {
            'role': 'user',
            'content': '\n'.join(context_lines),
        },
    ]


def _normalize_ai_scaffold_payload(ai_payload: dict[str, Any], request_payload: dict[str, Any]) -> dict[str, Any]:
    plugin_type = str(request_payload.get('plugin_type') or ai_payload.get('plugin_type') or 'flag-generator').strip() or 'flag-generator'
    resolved_prompt_intent = _resolve_prompt_intent(
        str(request_payload.get('prompt') or ''),
        plugin_type,
        request_payload.get('intent_overrides'),
    )
    plugin_id = str(ai_payload.get('plugin_id') or request_payload.get('source_id_hint') or '').strip()
    if not plugin_id:
        plugin_id = _derive_plugin_id(ai_payload.get('name') or request_payload.get('name_hint') or '')
    folder_name = str(ai_payload.get('folder_name') or '').strip() or f'py_{plugin_id}'
    requires, _optional_requires = _coerce_requires(ai_payload.get('requires'), ai_payload.get('optional_requires'))
    runtime_inputs = _coerce_runtime_inputs(ai_payload.get('runtime_inputs') or ai_payload.get('inputs'))
    hint_templates = _coerce_string_list(ai_payload.get('hint_templates'))
    inject_files = _coerce_string_list(ai_payload.get('inject_files'))
    produces = _coerce_string_list(ai_payload.get('produces'))

    manual = resolved_prompt_intent.get('manual') if isinstance(resolved_prompt_intent.get('manual'), dict) else {}
    explicit = resolved_prompt_intent.get('explicit') if isinstance(resolved_prompt_intent.get('explicit'), dict) else {}
    notes = resolved_prompt_intent.get('notes') if isinstance(resolved_prompt_intent.get('notes'), dict) else {}
    merged_defaults = dict(resolved_prompt_intent.get('merged') or {}) if isinstance(resolved_prompt_intent.get('merged'), dict) else {}
    inject_destination = str(notes.get('inject_destination') or '').strip()

    if manual.get('requires'):
        requires = _coerce_requires(manual.get('requires'))[0]
    elif explicit.get('requires'):
        requires = _coerce_requires(explicit.get('requires'))[0]
    elif not requires and merged_defaults.get('requires'):
        requires = _coerce_requires(merged_defaults.get('requires'))[0]

    if manual.get('runtime_inputs'):
        runtime_inputs = _coerce_runtime_inputs(manual.get('runtime_inputs'))
    elif explicit.get('runtime_inputs'):
        runtime_inputs = _coerce_runtime_inputs(explicit.get('runtime_inputs'))
    elif not runtime_inputs and merged_defaults.get('runtime_inputs'):
        runtime_inputs = _coerce_runtime_inputs(merged_defaults.get('runtime_inputs'))

    if manual.get('produces'):
        produces = _coerce_string_list(manual.get('produces'))
    elif explicit.get('produces'):
        produces = _coerce_string_list(explicit.get('produces'))
    elif not produces and merged_defaults.get('produces'):
        produces = _coerce_string_list(merged_defaults.get('produces'))

    if manual.get('inject_files'):
        inject_files = _coerce_string_list(manual.get('inject_files'))
    elif explicit.get('inject_files'):
        inject_files = _coerce_string_list(explicit.get('inject_files'))
    elif not inject_files and merged_defaults.get('inject_files'):
        inject_files = _coerce_string_list(merged_defaults.get('inject_files'))

    inject_files = _apply_inject_destination(inject_files, inject_destination)

    if manual.get('hint_templates'):
        hint_templates = _coerce_string_list(manual.get('hint_templates'))
    elif explicit.get('hint_templates'):
        hint_templates = _coerce_string_list(explicit.get('hint_templates'))
    elif not hint_templates and merged_defaults.get('hint_templates'):
        hint_templates = _coerce_string_list(merged_defaults.get('hint_templates'))

    compose_text = str(ai_payload.get('compose_text') or '').strip('\n')
    readme_text = str(ai_payload.get('readme_text') or '').strip('\n')
    generator_py_text = str(ai_payload.get('generator_py_text') or ai_payload.get('generator_text') or '').strip('\n')
    env_value = ai_payload.get('env') if isinstance(ai_payload.get('env'), dict) else {}
    env = {str(key): str(value) for key, value in env_value.items() if str(key or '').strip()}

    if notes.get('write_file_under_outputs_artifacts') and 'File(path)' in produces and not any(str(item).startswith('File(path)') for item in inject_files):
        if explicit.get('inject_files') or merged_defaults.get('inject_files'):
            inject_files = _apply_inject_destination(_coerce_string_list(explicit.get('inject_files') or merged_defaults.get('inject_files')), inject_destination)

    return {
        'plugin_type': plugin_type,
        'plugin_id': plugin_id,
        'folder_name': folder_name,
        'name': str(ai_payload.get('name') or request_payload.get('name_hint') or plugin_id).strip() or plugin_id,
        'description': str(ai_payload.get('description') or request_payload.get('prompt') or f'Generator {plugin_id}').strip(),
        'requires': requires,
        'produces': produces,
        'runtime_inputs': runtime_inputs,
        'hint_templates': hint_templates,
        'inject_files': inject_files,
        'env': env,
        'compose_text': compose_text,
        'readme_text': readme_text,
        'generator_py_text': generator_py_text,
    }


def _default_test_value(input_name: str, input_type: str) -> Any:
    normalized_name = str(input_name or '').strip().lower()
    normalized_type = str(input_type or 'string').strip().lower()
    if normalized_name == 'seed':
        return 'demo-seed'
    if normalized_name == 'secret':
        return 'demo-secret'
    if normalized_name == 'node_name':
        return 'node1'
    if normalized_name == 'flag_prefix':
        return 'FLAG'
    if normalized_type in {'int', 'number'}:
        return 1
    if normalized_type == 'float':
        return 1.0
    if normalized_type == 'boolean':
        return True
    if normalized_type == 'json':
        return {'demo': True}
    if normalized_type in {'string_list', 'file_list'}:
        return []
    return f'demo-{normalized_name or "value"}'


def _build_default_test_config(scaffold_payload: dict[str, Any]) -> dict[str, Any]:
    runtime_inputs = scaffold_payload.get('runtime_inputs') if isinstance(scaffold_payload.get('runtime_inputs'), list) else []
    config: dict[str, Any] = {}
    for item in runtime_inputs:
        if not isinstance(item, dict):
            continue
        name = str(item.get('name') or '').strip()
        if not name:
            continue
        config[name] = _default_test_value(name, str(item.get('type') or 'string'))
    return config


def _collect_run_output_files(run_dir: str) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    if not os.path.isdir(run_dir):
        return files
    for root, _dirs, filenames in os.walk(run_dir):
        for filename in filenames:
            abs_path = os.path.join(root, filename)
            rel_path = os.path.relpath(abs_path, run_dir).replace('\\', '/')
            try:
                size = os.path.getsize(abs_path)
            except Exception:
                size = None
            text_content = None
            if size is not None and size <= 65536:
                try:
                    with open(abs_path, 'r', encoding='utf-8') as handle:
                        text_content = handle.read()
                except Exception:
                    text_content = None
            files.append({
                'path': rel_path,
                'name': filename,
                'size': size,
                'text': text_content,
            })
    files.sort(key=lambda entry: str(entry.get('path') or ''))
    return files


def _builder_test_workspace_root() -> str:
    return _repo_root()


def _builder_test_runs_dir(outputs_dir_getter: Callable[[], str]) -> str:
    return os.path.join(os.path.abspath(outputs_dir_getter()), 'generator_builder_runs')


def _builder_test_run_dir_for_id(outputs_dir_getter: Callable[[], str], run_id: str) -> str:
    return os.path.join(_builder_test_runs_dir(outputs_dir_getter), str(run_id or '').strip())


def _is_file_input_type(input_type: Any) -> bool:
    normalized = str(input_type or '').strip().lower()
    return normalized in {'file', 'path', 'artifact', 'binary'}


def _build_scaffold_zip_bytes(scaffold_files: dict[str, str], *, zipfile_module: Any, io_module: Any) -> bytes:
    mem = io_module.BytesIO()
    with zipfile_module.ZipFile(mem, 'w', zipfile_module.ZIP_DEFLATED) as zf:
        for path, content in scaffold_files.items():
            zf.writestr(path, content)
    mem.seek(0)
    return mem.getvalue()


def _persist_scaffold_files(run_dir: str, scaffold_files: dict[str, str], scaffold_payload: dict[str, Any]) -> None:
    scaffold_root = os.path.join(run_dir, 'scaffold')
    os.makedirs(scaffold_root, exist_ok=True)
    for rel_path, content in (scaffold_files or {}).items():
        safe_rel = str(rel_path or '').lstrip('/').replace('\\', '/')
        if not safe_rel:
            continue
        abs_path = os.path.abspath(os.path.join(scaffold_root, safe_rel))
        if not (abs_path == scaffold_root or abs_path.startswith(scaffold_root + os.sep)):
            continue
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, 'w', encoding='utf-8') as handle:
            handle.write(str(content or ''))
    request_path = os.path.join(scaffold_root, '_scaffold_request.json')
    with open(request_path, 'w', encoding='utf-8') as handle:
        json.dump(scaffold_payload or {}, handle, indent=2, ensure_ascii=False)
        handle.write('\n')


def _tail_text_file(path: str, limit_chars: int = 12000) -> str:
    if not path or not os.path.isfile(path):
        return ''
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as handle:
            text = handle.read()
    except Exception:
        return ''
    if limit_chars > 0 and len(text) > limit_chars:
        return text[-limit_chars:]
    return text


def _summarize_run_log(log_tail: str) -> str:
    text = str(log_tail or '').replace('\r', '\n')
    lines = [line.strip() for line in text.splitlines() if line and line.strip()]
    if not lines:
        return ''
    ignored_prefixes = ('__SSE_EVENT__', '[remote] synced outputs:')
    interesting: list[str] = []
    for line in lines:
        if any(line.startswith(prefix) for prefix in ignored_prefixes):
            continue
        interesting.append(line)
    candidates = interesting or lines
    selected: list[str] = []
    for line in reversed(candidates):
        selected.append(line)
        lowered = line.lower()
        if 'traceback' in lowered or 'calledprocesserror' in lowered or 'failed' in lowered or 'error' in lowered:
            if len(selected) >= 6:
                break
        if len(selected) >= 12:
            break
    selected.reverse()
    return '\n'.join(selected[-12:]).strip()


def register(
    app,
    *,
    require_builder_or_admin: Callable[[], None],
    runs: dict[str, dict[str, Any]],
    outputs_dir: Callable[[], str],
    flag_generators_from_enabled_sources: Callable[[], tuple[list[dict], list[dict]]],
    flag_node_generators_from_enabled_sources: Callable[[], tuple[list[dict], list[dict]]],
    reserved_artifacts: dict[str, dict[str, Any]],
    load_custom_artifacts: Callable[[], dict[str, dict[str, Any]]],
    upsert_custom_artifact: Callable[..., dict[str, Any]],
    build_generator_scaffold: Callable[[dict[str, Any]], tuple[dict[str, str], str, str]],
    install_generator_pack_or_bundle: Callable[..., tuple[bool, str]],
    run_remote_builder_test: Callable[..., dict[str, Any]],
    start_remote_builder_test_process: Callable[..., dict[str, Any]],
    sync_remote_flag_test_outputs: Callable[[dict[str, Any]], None],
    purge_remote_flag_test_dir: Callable[[dict[str, Any]], None],
    parse_flag_test_core_cfg_from_form: Callable[[Any], dict[str, Any] | None],
    ensure_core_vm_idle_for_test: Callable[[dict[str, Any]], None],
    cleanup_remote_test_runtime: Callable[[dict[str, Any]], None],
    write_sse_marker: Callable[[Any, str, Any], None],
    local_timestamp_safe: Callable[[], str],
    sanitize_id: Callable[[Any], str],
    io_module: Any,
    zipfile_module: Any,
) -> None:
    global _BUILD_GENERATOR_SCAFFOLD
    _BUILD_GENERATOR_SCAFFOLD = build_generator_scaffold
    if not begin_route_registration(app, 'generator_builder_routes'):
        return

    @app.route('/generator_builder')
    def generator_builder_page():
        require_builder_or_admin()
        return render_template('generator_builder.html', active_page='generator_builder')

    @app.route('/api/generators/artifacts_index')
    def api_generators_artifacts_index():
        require_builder_or_admin()
        try:
            flag_gens, _errs1 = flag_generators_from_enabled_sources()
            node_gens, _errs2 = flag_node_generators_from_enabled_sources()

            idx: dict[str, dict[str, Any]] = {}

            def _add_from(gens: list[dict], plugin_type: str) -> None:
                for g in gens:
                    if not isinstance(g, dict):
                        continue
                    gid = str(g.get('id') or '').strip()
                    gname = str(g.get('name') or '').strip() or gid
                    outs = g.get('outputs') if isinstance(g.get('outputs'), list) else []
                    for o in outs:
                        if not isinstance(o, dict):
                            continue
                        art = str(o.get('name') or '').strip()
                        if not art:
                            continue
                        tp = str(o.get('type') or '').strip()
                        desc = str(o.get('description') or '').strip()
                        sensitive = o.get('sensitive') is True
                        entry = idx.get(art)
                        if not entry:
                            entry = {'artifact': art, 'type': tp, 'description': desc, 'sensitive': sensitive, 'producers': []}
                            idx[art] = entry
                        if not entry.get('type') and tp:
                            entry['type'] = tp
                        if not str(entry.get('description') or '').strip() and desc:
                            entry['description'] = desc
                        if entry.get('sensitive') is not True and sensitive is True:
                            entry['sensitive'] = True
                        producers = entry.get('producers') if isinstance(entry.get('producers'), list) else []
                        if not any((p.get('plugin_id') == gid and p.get('plugin_type') == plugin_type) for p in producers if isinstance(p, dict)):
                            producers.append({'plugin_id': gid, 'plugin_type': plugin_type, 'name': gname})
                        entry['producers'] = producers

            _add_from(flag_gens, 'flag-generator')
            _add_from(node_gens, 'flag-node-generator')

            try:
                for art, meta in reserved_artifacts.items():
                    if art not in idx:
                        idx[art] = {
                            'artifact': art,
                            'type': str(meta.get('type') or '').strip(),
                            'description': str(meta.get('description') or '').strip(),
                            'sensitive': meta.get('sensitive') is True,
                            'producers': [{'plugin_id': '(reserved)', 'plugin_type': 'reserved', 'name': 'Reserved'}],
                        }
                    else:
                        if not str(idx[art].get('type') or '').strip() and str(meta.get('type') or '').strip():
                            idx[art]['type'] = str(meta.get('type') or '').strip()
                        if not str(idx[art].get('description') or '').strip() and str(meta.get('description') or '').strip():
                            idx[art]['description'] = str(meta.get('description') or '').strip()
                        if idx[art].get('sensitive') is not True and meta.get('sensitive') is True:
                            idx[art]['sensitive'] = True
            except Exception:
                pass

            try:
                custom = load_custom_artifacts()
                for art, meta in custom.items():
                    if art not in idx:
                        idx[art] = {'artifact': art, 'type': str(meta.get('type') or '').strip(), 'producers': []}
                    else:
                        if not str(idx[art].get('type') or '').strip() and str(meta.get('type') or '').strip():
                            idx[art]['type'] = str(meta.get('type') or '').strip()
            except Exception:
                pass

            artifacts = sorted(idx.values(), key=lambda x: str(x.get('artifact') or ''))
            return jsonify({'ok': True, 'artifacts': artifacts})
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 500

    @app.route('/api/generators/artifacts_index/custom', methods=['POST'])
    def api_generators_artifacts_index_custom_add():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        try:
            artifact = str(payload.get('artifact') or '').strip()
            type_value = str(payload.get('type') or '').strip() or None
            item = upsert_custom_artifact(artifact, type_value=type_value)
            return jsonify({'ok': True, 'artifact': item})
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 400

    @app.route('/api/generators/scaffold_meta', methods=['POST'])
    def api_generators_scaffold_meta():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        try:
            scaffold_files, manifest_yaml, _folder_path = build_generator_scaffold(payload)
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 400
        return jsonify({
            'ok': True,
            'manifest_yaml': manifest_yaml,
            'scaffold_paths': sorted(scaffold_files.keys()),
        })

    @app.route('/api/generators/prompt_intent_preview', methods=['POST'])
    def api_generators_prompt_intent_preview():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        try:
            return jsonify(_build_prompt_intent_preview(payload))
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 400

    @app.route('/api/generators/ai_scaffold', methods=['POST'])
    def api_generators_ai_scaffold():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        from webapp.routes import ai_provider as ai_provider_routes

        try:
            result = _build_builder_ai_scaffold_result(payload, ai_provider_routes=ai_provider_routes)
        except ai_provider_routes.ProviderAdapterError as exc:
            return jsonify({'ok': False, 'error': exc.message, **(exc.details or {})}), exc.status_code
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 400

        return jsonify(result)

    @app.route('/api/generators/ai_scaffold_stream', methods=['POST'])
    def api_generators_ai_scaffold_stream():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        from webapp.routes import ai_provider as ai_provider_routes

        request_id = str(payload.get('request_id') or '').strip() or ai_provider_routes._create_stream_request_id()
        payload['request_id'] = request_id
        try:
            ai_provider_routes._get_provider_adapter(payload.get('provider'))
        except ai_provider_routes.ProviderAdapterError as exc:
            return jsonify({'ok': False, 'error': exc.message, **(exc.details or {})}), exc.status_code

        stream_entry = ai_provider_routes._register_ai_stream(request_id)

        @stream_with_context
        def _stream_events():
            event_queue: queue.Queue[str | None] = queue.Queue()

            def emit(event_type: str, **event_payload: Any) -> None:
                event_queue.put(ai_provider_routes._ndjson_event(event_type, request_id=request_id, **event_payload))

            def is_cancelled() -> bool:
                return bool(stream_entry['cancelled'].is_set())

            def on_response_open(response_obj: Any) -> None:
                stream_entry['response'] = response_obj

            def worker() -> None:
                try:
                    result = _build_builder_ai_scaffold_result(
                        payload,
                        ai_provider_routes=ai_provider_routes,
                        emit=emit,
                        cancellation_check=is_cancelled,
                        on_response_open=on_response_open,
                    )
                    if is_cancelled():
                        emit('error', error='Generation cancelled by user.', status_code=499)
                        return
                    emit('result', data=result)
                except ai_provider_routes.ProviderAdapterError as exc:
                    emit('error', error=exc.message, status_code=exc.status_code, details=exc.details or {})
                except Exception as exc:  # pragma: no cover
                    emit('error', error=str(exc))
                finally:
                    stream_entry['response'] = None
                    event_queue.put(None)

            threading.Thread(target=worker, daemon=True).start()
            try:
                while True:
                    next_event = event_queue.get()
                    if next_event is None:
                        break
                    yield next_event
            finally:
                ai_provider_routes._unregister_ai_stream(request_id)

        return Response(
            _stream_events(),
            mimetype='application/x-ndjson',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no',
            },
        )

    @app.route('/api/generators/ai_scaffold_stream/cancel', methods=['POST'])
    def api_generators_ai_scaffold_stream_cancel():
        require_builder_or_admin()
        from webapp.routes import ai_provider as ai_provider_routes

        payload = request.get_json(silent=True) or {}
        request_id = str(payload.get('request_id') or '').strip()
        if not request_id:
            return jsonify({'ok': False, 'error': 'request_id is required.'}), 400
        cancelled = ai_provider_routes._cancel_ai_stream(request_id)
        if not cancelled:
            return jsonify({'ok': False, 'error': 'request_id was not active.'}), 404
        return jsonify({'ok': True, 'request_id': request_id})

    @app.route('/api/generators/builder_test', methods=['POST'])
    def api_generators_builder_test():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        scaffold_payload = payload.get('scaffold_request') if isinstance(payload.get('scaffold_request'), dict) else {}
        if not scaffold_payload:
            return jsonify({'ok': False, 'error': 'scaffold_request is required.'}), 400
        try:
            scaffold_files, manifest_yaml, folder_path = build_generator_scaffold(scaffold_payload)
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 400

        plugin_kind = str(scaffold_payload.get('plugin_type') or 'flag-generator').strip() or 'flag-generator'
        plugin_id = sanitize_id(scaffold_payload.get('plugin_id')) or 'generator'
        config = _build_default_test_config(scaffold_payload)

        try:
            result = run_remote_builder_test(
                scaffold_files=scaffold_files,
                plugin_kind=plugin_kind,
                plugin_id=plugin_id,
                config=config,
            )
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Failed running builder test: {exc}'}), 500

        return jsonify({
            'ok': bool(result.get('ok')),
            'plugin_id': plugin_id,
            'plugin_type': plugin_kind,
            'folder_path': folder_path,
            'manifest_yaml': manifest_yaml,
            'returncode': result.get('returncode'),
            'stdout': str(result.get('stdout') or ''),
            'stderr': str(result.get('stderr') or ''),
            'files': result.get('files') if isinstance(result.get('files'), list) else [],
            'test_mode': 'remote_core_vm',
        }), (200 if result.get('ok') else 400)

    @app.route('/api/generators/builder_test/run', methods=['POST'])
    def api_generators_builder_test_run():
        require_builder_or_admin()
        scaffold_raw = (request.form.get('scaffold_request') or '').strip()
        if not scaffold_raw:
            return jsonify({'ok': False, 'error': 'scaffold_request is required.'}), 400
        try:
            scaffold_payload = json.loads(scaffold_raw)
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Invalid scaffold_request JSON: {exc}'}), 400
        if not isinstance(scaffold_payload, dict):
            return jsonify({'ok': False, 'error': 'scaffold_request must be an object.'}), 400

        try:
            scaffold_files, _manifest_yaml, _folder_path = build_generator_scaffold(scaffold_payload)
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 400

        plugin_kind = str(scaffold_payload.get('plugin_type') or 'flag-generator').strip() or 'flag-generator'
        plugin_id = sanitize_id(scaffold_payload.get('plugin_id')) or 'generator'
        run_id = local_timestamp_safe() + '-' + uuid.uuid4().hex[:10]
        run_dir = _builder_test_run_dir_for_id(outputs_dir, run_id)
        inputs_dir = os.path.join(run_dir, 'inputs')
        os.makedirs(inputs_dir, exist_ok=True)
        log_path = os.path.join(run_dir, 'run.log')

        try:
            _persist_scaffold_files(run_dir, scaffold_files, scaffold_payload)
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Failed preparing scaffold snapshot: {exc}'}), 500

        cfg = _build_default_test_config(scaffold_payload)
        saved_uploads: dict[str, dict[str, Any]] = {}
        runtime_inputs = scaffold_payload.get('runtime_inputs') if isinstance(scaffold_payload.get('runtime_inputs'), list) else []

        for item in runtime_inputs:
            if not isinstance(item, dict):
                continue
            name = str(item.get('name') or '').strip()
            if not name:
                continue
            raw_val = request.form.get(name)
            if raw_val is not None:
                cfg[name] = raw_val

        def _unique_dest_filename(dir_path: str, filename: str) -> str:
            base = secure_filename(filename) or 'upload'
            candidate = base
            root, ext = os.path.splitext(base)
            idx = 1
            while os.path.exists(os.path.join(dir_path, candidate)):
                candidate = f'{root}_{idx}{ext}'
                idx += 1
                if idx > 5000:
                    break
            return candidate

        for item in runtime_inputs:
            if not isinstance(item, dict):
                continue
            name = str(item.get('name') or '').strip()
            if not name or not _is_file_input_type(item.get('type')):
                continue
            uploaded = request.files.get(name)
            if not (uploaded and getattr(uploaded, 'filename', '')):
                continue
            original_filename = str(getattr(uploaded, 'filename', '') or '')
            stored = _unique_dest_filename(inputs_dir, f'{name}__{original_filename}')
            dest = os.path.join(inputs_dir, stored)
            try:
                uploaded.save(dest)
            except Exception:
                return jsonify({'ok': False, 'error': f'Failed saving file input: {name}'}), 400
            cfg[name] = f'/inputs/{stored}'
            saved_uploads[name] = {
                'original_filename': original_filename,
                'stored_filename': stored,
                'stored_path': f'inputs/{stored}',
                'container_path': f'/inputs/{stored}',
            }

        missing: list[str] = []
        for item in runtime_inputs:
            if not isinstance(item, dict):
                continue
            if item.get('required') is False:
                continue
            name = str(item.get('name') or '').strip()
            if not name:
                continue
            val = cfg.get(name)
            if val is None or (isinstance(val, str) and not val.strip()):
                missing.append(name)
        if missing:
            return jsonify({'ok': False, 'error': f"Missing required input(s): {', '.join(missing)}"}), 400

        try:
            core_cfg = parse_flag_test_core_cfg_from_form(request.form)
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'CORE VM SSH config required: {exc}'}), 400
        if not isinstance(core_cfg, dict):
            return jsonify({'ok': False, 'error': 'CORE VM SSH config required for builder tests.'}), 400

        try:
            ensure_core_vm_idle_for_test(core_cfg)
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 409

        try:
            with open(log_path, 'a', encoding='utf-8') as log_f:
                log_f.write(f'[builder-test] starting {plugin_id} (remote CORE VM)\n')
                write_sse_marker(log_f, 'phase', {
                    'phase': 'starting',
                    'generator_id': plugin_id,
                    'run_id': run_id,
                    'remote': True,
                })
        except Exception:
            pass

        try:
            log_handle = open(log_path, 'a', encoding='utf-8')
            remote_meta = start_remote_builder_test_process(
                run_id=run_id,
                run_dir=run_dir,
                log_handle=log_handle,
                scaffold_files=scaffold_files,
                plugin_kind=plugin_kind,
                plugin_id=plugin_id,
                cfg=cfg,
                core_cfg=core_cfg,
            )
        except Exception as exc:
            try:
                with open(log_path, 'a', encoding='utf-8') as log_f:
                    log_f.write(f'[builder-test] failed to start remote run: {exc}\n')
                    write_sse_marker(log_f, 'phase', {'phase': 'error', 'error': str(exc)})
            except Exception:
                pass
            return jsonify({'ok': False, 'error': f'Failed launching remote builder test: {exc}'}), 500

        runs[run_id] = {
            'proc': None,
            'log_path': log_path,
            'done': False,
            'returncode': None,
            'status': 'generator_running',
            'run_dir': run_dir,
            'kind': 'generator_builder_test',
            'generator_id': plugin_id,
            'generator_name': str(scaffold_payload.get('name') or plugin_id),
            'plugin_type': plugin_kind,
            'remote': True,
            'core_cfg': core_cfg,
            'remote_run_dir': remote_meta.get('remote_run_dir'),
            'remote_repo_dir': remote_meta.get('remote_repo_dir'),
            'remote_env_path': remote_meta.get('remote_env_path'),
            'ssh_client': remote_meta.get('ssh_client'),
            'ssh_channel': remote_meta.get('ssh_channel'),
            'ssh_log_thread': remote_meta.get('ssh_log_thread'),
            'ssh_log_handle': log_handle,
            'cleanup_requested': False,
        }

        def _finalize_builder_run(run_id_local: str) -> None:
            meta = runs.get(run_id_local)
            if not isinstance(meta, dict):
                return
            rc = -1
            try:
                channel = meta.get('ssh_channel')
                if channel is not None:
                    while True:
                        try:
                            if channel.exit_status_ready():
                                rc = int(channel.recv_exit_status())
                                break
                        except Exception:
                            break
                        time.sleep(0.5)
            finally:
                try:
                    with open(str(meta.get('log_path') or ''), 'a', encoding='utf-8') as log_f:
                        write_sse_marker(log_f, 'phase', {'phase': 'generator_done', 'returncode': rc})
                except Exception:
                    pass
                try:
                    if not meta.get('cleanup_requested'):
                        sync_remote_flag_test_outputs(meta)
                except Exception:
                    pass
                try:
                    purge_remote_flag_test_dir(meta)
                except Exception:
                    pass
                try:
                    thread_obj = meta.get('ssh_log_thread')
                    if thread_obj and hasattr(thread_obj, 'join'):
                        thread_obj.join(timeout=3)
                except Exception:
                    pass
                try:
                    client_obj = meta.get('ssh_client')
                    if client_obj:
                        client_obj.close()
                except Exception:
                    pass
                try:
                    handle = meta.get('ssh_log_handle')
                    if handle:
                        handle.flush()
                        handle.close()
                except Exception:
                    pass
                meta['done'] = True
                meta['returncode'] = rc
                meta['status'] = 'completed' if rc == 0 else 'failed'
                try:
                    with open(str(meta.get('log_path') or ''), 'a', encoding='utf-8') as log_f:
                        write_sse_marker(log_f, 'phase', {'phase': 'done', 'returncode': rc})
                except Exception:
                    pass

        threading.Thread(
            target=_finalize_builder_run,
            args=(run_id,),
            name=f'builder-test-{run_id[:8]}',
            daemon=True,
        ).start()

        return jsonify({
            'ok': True,
            'run_id': run_id,
            'saved_uploads': saved_uploads,
        })

    @app.route('/api/generators/builder_test/outputs/<run_id>', methods=['GET'])
    def api_generators_builder_test_outputs(run_id: str):
        require_builder_or_admin()
        meta = runs.get(run_id)
        if meta and meta.get('kind') != 'generator_builder_test':
            return jsonify({'ok': False, 'error': 'not found'}), 404

        run_dir = meta.get('run_dir') if isinstance(meta, dict) else None
        if not isinstance(run_dir, str) or not run_dir:
            run_dir = _builder_test_run_dir_for_id(outputs_dir, run_id)
        abs_run_dir = os.path.abspath(run_dir)
        outputs_root = os.path.abspath(outputs_dir())
        if not (abs_run_dir == outputs_root or abs_run_dir.startswith(outputs_root + os.sep)):
            return jsonify({'ok': False, 'error': 'refusing'}), 400
        if not os.path.isdir(abs_run_dir):
            done = bool(meta.get('done')) if isinstance(meta, dict) else False
            returncode = meta.get('returncode') if isinstance(meta, dict) else None
            return jsonify({'ok': True, 'files': [], 'done': done, 'returncode': returncode}), 200

        input_files: list[dict[str, Any]] = []
        output_files: list[dict[str, Any]] = []
        scaffold_files: list[dict[str, Any]] = []
        misc_files: list[dict[str, Any]] = []
        for root, _dirs, filenames in os.walk(abs_run_dir):
            rel_root = os.path.relpath(root, abs_run_dir).replace('\\', '/')
            for filename in filenames:
                abs_path = os.path.join(root, filename)
                try:
                    st = os.stat(abs_path)
                    rel = os.path.relpath(abs_path, abs_run_dir).replace('\\', '/')
                    entry = {'path': rel, 'name': filename, 'size': st.st_size}
                except Exception:
                    continue
                if rel_root == 'inputs' or rel_root.startswith('inputs/'):
                    input_files.append(entry)
                elif rel_root == 'scaffold' or rel_root.startswith('scaffold/'):
                    scaffold_files.append(entry)
                elif rel == 'run.log':
                    misc_files.append(entry)
                else:
                    output_files.append(entry)
        input_files.sort(key=lambda item: str(item.get('path') or ''))
        output_files.sort(key=lambda item: str(item.get('path') or ''))
        scaffold_files.sort(key=lambda item: str(item.get('path') or ''))
        misc_files.sort(key=lambda item: str(item.get('path') or ''))
        done = bool(meta.get('done')) if isinstance(meta, dict) else True
        returncode = meta.get('returncode') if isinstance(meta, dict) else None
        log_path = meta.get('log_path') if isinstance(meta, dict) else os.path.join(abs_run_dir, 'run.log')
        log_tail = _tail_text_file(str(log_path or ''))
        failure_summary = _summarize_run_log(log_tail)
        return jsonify({
            'ok': True,
            'inputs': input_files,
            'outputs': output_files,
            'scaffold': scaffold_files,
            'misc': misc_files,
            'done': done,
            'returncode': returncode,
            'log_tail': log_tail,
            'failure_summary': failure_summary,
        }), 200

    @app.route('/api/generators/builder_test/download/<run_id>', methods=['GET'])
    def api_generators_builder_test_download(run_id: str):
        require_builder_or_admin()
        meta = runs.get(run_id)
        if meta and meta.get('kind') != 'generator_builder_test':
            return jsonify({'ok': False, 'error': 'not found'}), 404
        run_dir = meta.get('run_dir') if isinstance(meta, dict) else None
        if not isinstance(run_dir, str) or not run_dir:
            run_dir = _builder_test_run_dir_for_id(outputs_dir, run_id)
        rel = (request.args.get('p') or '').strip().lstrip('/').replace('\\', '/')
        if not rel:
            return jsonify({'ok': False, 'error': 'invalid path'}), 400
        abs_run_dir = os.path.abspath(run_dir)
        outputs_root = os.path.abspath(outputs_dir())
        if not (abs_run_dir == outputs_root or abs_run_dir.startswith(outputs_root + os.sep)):
            return jsonify({'ok': False, 'error': 'refusing'}), 400
        abs_path = os.path.abspath(os.path.join(abs_run_dir, rel))
        if not (abs_path == abs_run_dir or abs_path.startswith(abs_run_dir + os.sep)):
            return jsonify({'ok': False, 'error': 'refusing'}), 400
        if not os.path.exists(abs_path) or not os.path.isfile(abs_path):
            return jsonify({'ok': False, 'error': 'missing file'}), 404
        return send_file(abs_path, as_attachment=True, download_name=os.path.basename(abs_path))

    @app.route('/api/generators/builder_test/cleanup/<run_id>', methods=['POST'])
    def api_generators_builder_test_cleanup(run_id: str):
        require_builder_or_admin()
        meta = runs.get(run_id)
        if meta and meta.get('kind') != 'generator_builder_test':
            return jsonify({'ok': False, 'error': 'not found'}), 404
        run_dir = meta.get('run_dir') if isinstance(meta, dict) else None
        if not isinstance(run_dir, str) or not run_dir:
            run_dir = _builder_test_run_dir_for_id(outputs_dir, run_id)
        abs_run_dir = os.path.abspath(run_dir)
        outputs_root = os.path.abspath(outputs_dir())
        if not (abs_run_dir == outputs_root or abs_run_dir.startswith(outputs_root + os.sep)):
            return jsonify({'ok': False, 'error': 'refusing'}), 400

        try:
            if isinstance(meta, dict):
                meta['cleanup_requested'] = True
                try:
                    cleanup_remote_test_runtime(meta)
                except Exception:
                    pass
                try:
                    channel = meta.get('ssh_channel')
                    if channel is not None and hasattr(channel, 'close'):
                        channel.close()
                except Exception:
                    pass
                try:
                    client_obj = meta.get('ssh_client')
                    if client_obj is not None:
                        client_obj.close()
                except Exception:
                    pass
                try:
                    purge_remote_flag_test_dir(meta)
                except Exception:
                    pass
        except Exception:
            pass

        try:
            lp = meta.get('log_path') if isinstance(meta, dict) else os.path.join(abs_run_dir, 'run.log')
            if isinstance(lp, str) and lp:
                with open(lp, 'a', encoding='utf-8') as log_f:
                    write_sse_marker(log_f, 'phase', {'phase': 'cleanup_start', 'run_id': run_id})
        except Exception:
            pass

        removed = False
        try:
            if os.path.isdir(abs_run_dir):
                shutil.rmtree(abs_run_dir, ignore_errors=True)
            removed = True
        except Exception:
            removed = False

        try:
            if isinstance(meta, dict):
                meta['done'] = True
        except Exception:
            pass
        try:
            if isinstance(meta, dict):
                lp = meta.get('log_path')
            else:
                lp = os.path.join(abs_run_dir, 'run.log')
            if isinstance(lp, str) and lp and os.path.exists(lp):
                with open(lp, 'a', encoding='utf-8') as log_f2:
                    write_sse_marker(log_f2, 'phase', {'phase': 'cleanup_done', 'run_id': run_id, 'removed': removed})
        except Exception:
            pass
        try:
            runs.pop(run_id, None)
        except Exception:
            pass
        return jsonify({'ok': True, 'removed': removed}), 200

    @app.route('/api/generators/install_generated', methods=['POST'])
    def api_generators_install_generated():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        scaffold_payload = payload.get('scaffold_request') if isinstance(payload.get('scaffold_request'), dict) else {}
        if not scaffold_payload:
            return jsonify({'ok': False, 'error': 'scaffold_request is required.'}), 400
        try:
            scaffold_files, _manifest_yaml, _folder_path = build_generator_scaffold(scaffold_payload)
            zip_bytes = _build_scaffold_zip_bytes(scaffold_files, zipfile_module=zipfile_module, io_module=io_module)
            pack_label = str(payload.get('pack_label') or scaffold_payload.get('name') or scaffold_payload.get('plugin_id') or 'generated-builder-pack').strip()
            fd, tmp_path = tempfile.mkstemp(prefix='coretg_builder_pack_', suffix='.zip')
            os.close(fd)
            try:
                with open(tmp_path, 'wb') as handle:
                    handle.write(zip_bytes)
                ok, note = install_generator_pack_or_bundle(zip_path=tmp_path, pack_label=pack_label, pack_origin='generator_builder')
            finally:
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 400
        if not ok:
            return jsonify({'ok': False, 'error': note}), 400
        return jsonify({'ok': True, 'message': note, 'pack_label': pack_label})

    @app.route('/api/generators/scaffold_zip', methods=['POST'])
    def api_generators_scaffold_zip():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        try:
            scaffold_files, _manifest_yaml, _folder_path = build_generator_scaffold(payload)
            plugin_id = sanitize_id(payload.get('plugin_id')) or 'generator'
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 400

        mem = io_module.BytesIO()
        with zipfile_module.ZipFile(mem, 'w', zipfile_module.ZIP_DEFLATED) as zf:
            for path, content in scaffold_files.items():
                zf.writestr(path, content)
        mem.seek(0)
        return send_file(
            mem,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'generator_scaffold_{plugin_id}.zip',
        )

    mark_routes_registered(app, 'generator_builder_routes')