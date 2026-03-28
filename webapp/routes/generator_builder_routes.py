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
_VALIDATE_BUILDER_SCAFFOLD: Callable[[dict[str, str]], list[str]] | None = None
_BUILDER_PROVIDER_HEARTBEAT_SECONDS = 5.0


class BuilderScaffoldValidationError(ValueError):
    def __init__(self, validation_errors: list[str], *, auto_heal: dict[str, Any] | None = None):
        errors = [str(item).strip() for item in (validation_errors or []) if str(item).strip()]
        super().__init__(errors[0] if errors else 'Generated scaffold failed validation.')
        self.validation_errors = errors
        self.auto_heal = dict(auto_heal or {}) if isinstance(auto_heal, dict) else {}


class BuilderScaffoldGenerationError(ValueError):
    def __init__(self, scaffold_errors: list[str], *, auto_heal: dict[str, Any] | None = None):
        errors = [str(item).strip() for item in (scaffold_errors or []) if str(item).strip()]
        super().__init__(errors[0] if errors else 'Generated scaffold could not be normalized or built.')
        self.scaffold_errors = errors
        self.auto_heal = dict(auto_heal or {}) if isinstance(auto_heal, dict) else {}


def _normalize_builder_file_text(text: Any) -> str:
    return str(text or '').replace('\r\n', '\n').replace('\r', '\n')


def _first_builder_failure_line(last_test_result: dict[str, Any] | None) -> str:
    text = _extract_builder_failure_text(last_test_result)
    for raw_line in text.splitlines():
        line = str(raw_line or '').strip()
        if line:
            return line
    return ''


def _detect_builder_refinement_noop(
    scaffold_payload: dict[str, Any],
    scaffold_files: dict[str, str],
    request_payload: dict[str, Any],
) -> list[str]:
    current_scaffold = request_payload.get('current_scaffold_request')
    current_files = request_payload.get('current_files')
    if not isinstance(current_scaffold, dict) or not isinstance(current_files, dict):
        return []

    normalized_current_files = {str(path): _normalize_builder_file_text(text) for path, text in current_files.items()}
    normalized_next_files = {str(path): _normalize_builder_file_text(text) for path, text in scaffold_files.items()}
    if normalized_current_files != normalized_next_files:
        return []

    plugin_id = str(scaffold_payload.get('plugin_id') or current_scaffold.get('plugin_id') or '').strip()
    detail = f' for {plugin_id}' if plugin_id else ''
    prior_failure = _first_builder_failure_line(
        request_payload.get('last_test_result') if isinstance(request_payload.get('last_test_result'), dict) else None
    )
    prior_failure_detail = f' Latest failure to address: {prior_failure}' if prior_failure else ''
    return [
        'Refinement returned the same scaffold files'
        f'{detail} without any file changes. '
        'When refining or auto-healing, modify the relevant scaffold files to address the latest request or failure instead of returning the existing scaffold unchanged.'
        f'{prior_failure_detail}'
    ]


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


def _generate_builder_openai_compatible_response(
    ai_provider_routes: Any,
    *,
    prompt: str,
    model: str,
    base_url: str,
    api_key: str,
    verify_ssl: bool,
    timeout_seconds: float,
    emit: Callable[..., None] | None = None,
    cancellation_check: Callable[[], bool] | None = None,
) -> str:
    if cancellation_check and cancellation_check():
        raise ai_provider_routes.ProviderAdapterError('Generation cancelled by user.', status_code=499)

    prompt_chars = len(prompt)
    prompt_lines = len(prompt.splitlines())
    request_started_at = time.monotonic()
    response_opened_at: float | None = None

    heartbeat_done = threading.Event()
    heartbeat_thread: threading.Thread | None = None
    if emit is not None:
        emit('status', message=f'Builder diagnostics: prompt_chars={prompt_chars}, prompt_lines={prompt_lines}, timeout={timeout_seconds:.0f}s.')
        emit('status', message='Contacting OpenAI-compatible endpoint (initial)...')

        def _heartbeat() -> None:
            interval = max(float(_BUILDER_PROVIDER_HEARTBEAT_SECONDS), 0.01)
            while not heartbeat_done.wait(interval):
                if cancellation_check and cancellation_check():
                    return
                elapsed = time.monotonic() - request_started_at
                emit('status', message=f'Still waiting on OpenAI-compatible endpoint (initial)... elapsed={elapsed:.1f}s')

        heartbeat_thread = threading.Thread(target=_heartbeat, daemon=True)
        heartbeat_thread.start()

    def _on_response_open(_response_obj: Any) -> None:
        nonlocal response_opened_at
        response_opened_at = time.monotonic()
        if emit is not None:
            emit('status', message=f'OpenAI-compatible endpoint accepted the request after {response_opened_at - request_started_at:.1f}s; reading body...')

    try:
        raw_response = ai_provider_routes._run_with_wall_clock_timeout(
            lambda: ai_provider_routes._post_json(
                ai_provider_routes._openai_compatible_chat_completions_url(base_url),
                {
                    'model': model,
                    'messages': [
                        {
                            'role': 'user',
                            'content': prompt,
                        },
                    ],
                    'temperature': 0.1,
                    'response_format': {'type': 'json_object'},
                    'stream': False,
                },
                timeout=timeout_seconds,
                headers=ai_provider_routes._openai_compatible_request_headers(api_key),
                verify_ssl=verify_ssl,
                on_open=_on_response_open,
            ),
            timeout_seconds=timeout_seconds,
        )
    except HTTPError as exc:
        detail = ''
        try:
            detail = exc.read().decode('utf-8').strip()
        except Exception:
            detail = ''
        message = f'OpenAI-compatible endpoint returned HTTP {exc.code}.'
        if detail:
            message = f'{message} {detail[:240]}'
        raise ai_provider_routes.ProviderAdapterError(
            message,
            status_code=502,
            details={
                'stage': 'builder_openai_initial',
                'prompt_chars': prompt_chars,
                'prompt_lines': prompt_lines,
                'timeout_seconds': float(timeout_seconds),
                'elapsed_seconds': round(time.monotonic() - request_started_at, 3),
                'response_opened': response_opened_at is not None,
            },
        ) from exc
    except URLError as exc:
        reason = getattr(exc, 'reason', exc)
        raise ai_provider_routes.ProviderAdapterError(
            f'Could not reach OpenAI-compatible endpoint at {base_url}: {reason}',
            status_code=502,
            details={
                'stage': 'builder_openai_initial',
                'prompt_chars': prompt_chars,
                'prompt_lines': prompt_lines,
                'timeout_seconds': float(timeout_seconds),
                'elapsed_seconds': round(time.monotonic() - request_started_at, 3),
                'response_opened': response_opened_at is not None,
            },
        ) from exc
    finally:
        heartbeat_done.set()
        if heartbeat_thread is not None:
            heartbeat_thread.join(timeout=0.2)

    if emit is not None:
        emit('status', message=f'OpenAI-compatible endpoint responded (initial) in {time.monotonic() - request_started_at:.1f}s.')

    assistant_text = str(ai_provider_routes._extract_openai_compatible_message_text(raw_response) or '').strip()
    if not assistant_text:
        raise ai_provider_routes.ProviderAdapterError(
            'OpenAI-compatible endpoint returned an empty response.',
            status_code=502,
            details={
                'stage': 'builder_openai_initial',
                'prompt_chars': prompt_chars,
                'prompt_lines': prompt_lines,
                'timeout_seconds': float(timeout_seconds),
                'elapsed_seconds': round(time.monotonic() - request_started_at, 3),
                'response_opened': response_opened_at is not None,
            },
        )
    if emit is not None:
        emit('llm_delta', text=assistant_text)
    return assistant_text


def _validate_builder_scaffold_files(scaffold_files: dict[str, str]) -> list[str]:
    if _VALIDATE_BUILDER_SCAFFOLD is None:
        return []
    try:
        errors = _VALIDATE_BUILDER_SCAFFOLD(scaffold_files)
    except Exception:
        return []
    if not isinstance(errors, list):
        return []
    return [str(item).strip() for item in errors if str(item).strip()]


def _build_builder_auto_heal_prompt(original_prompt: str, validation_errors: list[str]) -> str:
    bullets = '\n'.join(f'- {str(item).strip()}' for item in (validation_errors or []) if str(item).strip())
    lines = [
        'Repair the current generator scaffold without changing its intended behavior more than necessary.',
        'Fix these scaffold validation errors first:',
        bullets or '- Generated scaffold failed validation.',
        'Requirements for the repaired scaffold:',
        '- Do not return the prior scaffold unchanged; make concrete edits to the relevant scaffold files.',
        '- Any runtime input that generator.py treats as required in /inputs/config.json must be declared in runtime_inputs so manifest inputs stay in sync.',
        '- If a required runtime input is sensitive, mark it sensitive in runtime_inputs.',
        '- Keep outputs.json, produces, inject_files, and actual created files aligned.',
        '',
        'Original user request:',
        str(original_prompt or '').strip() or 'Repair the current scaffold.',
    ]
    return '\n'.join(lines).strip()


def _build_builder_scaffold_repair_prompt(original_prompt: str, scaffold_errors: list[str]) -> str:
    bullets = '\n'.join(f'- {str(item).strip()}' for item in (scaffold_errors or []) if str(item).strip())
    lines = [
        'Repair the current generator scaffold response so it can be normalized and built into a valid scaffold.',
        'Fix these scaffold construction errors first:',
        bullets or '- Generated scaffold could not be normalized or built.',
        'Requirements for the repaired scaffold:',
        '- Do not return the prior scaffold unchanged; make concrete edits that resolve the reported issue.',
        '- Reply with exactly one JSON object matching the Builder scaffold schema.',
        '- Include complete generator_py_text and keep manifest-facing fields internally consistent.',
        '- Ensure the response can be normalized into a scaffold and persisted without manual edits.',
        '',
        'Original user request:',
        str(original_prompt or '').strip() or 'Repair the current scaffold.',
    ]
    return '\n'.join(lines).strip()


def _materialize_builder_scaffold(assistant_text: str, request_payload: dict[str, Any]) -> dict[str, Any]:
    ai_payload = _extract_json_object(assistant_text)
    scaffold_payload = _normalize_ai_scaffold_payload(ai_payload, request_payload)
    if _BUILD_GENERATOR_SCAFFOLD is None:
        raise RuntimeError('build_generator_scaffold is not configured')
    scaffold_files, manifest_yaml, folder_path = _BUILD_GENERATOR_SCAFFOLD(scaffold_payload)
    validation_errors = _validate_builder_scaffold_files(scaffold_files)
    validation_errors.extend(_detect_builder_refinement_noop(scaffold_payload, scaffold_files, request_payload))
    return {
        'ai_payload': ai_payload,
        'scaffold_payload': scaffold_payload,
        'scaffold_files': scaffold_files,
        'manifest_yaml': manifest_yaml,
        'folder_path': folder_path,
        'validation_errors': validation_errors,
    }


def _generate_builder_ai_assistant_text(
    payload: dict[str, Any],
    *,
    ai_provider_routes: Any,
    emit: Callable[..., None] | None = None,
    cancellation_check: Callable[[], bool] | None = None,
    on_response_open: Callable[[Any], None] | None = None,
) -> dict[str, Any]:
    provider = str(payload.get('provider') or 'ollama').strip().lower() or 'ollama'
    prompt_payload = dict(payload)
    prompt_payload['compact_grounding'] = provider in {'litellm', 'openai'}
    prompt_payload['ultra_compact_prompt'] = bool(
        provider in {'litellm', 'openai'}
        and not isinstance(payload.get('current_scaffold_request'), dict)
        and not isinstance(payload.get('current_files'), dict)
        and not isinstance(payload.get('last_test_result'), dict)
    )
    messages = _build_generator_builder_ai_messages(prompt_payload)
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
        default=480.0,
        low=5.0,
        high=480.0,
    )

    direct_prompt = _build_direct_generation_prompt(messages)
    if emit is not None:
        emit('status', message='Preparing Builder prompt...')
        if prompt_payload.get('ultra_compact_prompt'):
            emit('status', message='Using ultra-compact Builder prompt for OpenAI-compatible create request.')
        if prompt_payload.get('compact_grounding'):
            emit('status', message='Using compact Builder grounding for OpenAI-compatible request.')
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
        assistant_text = _generate_builder_openai_compatible_response(
            ai_provider_routes,
            prompt=direct_prompt,
            model=model,
            base_url=base_url,
            api_key=str(payload.get('api_key') or '').strip(),
            verify_ssl=enforce_ssl,
            timeout_seconds=timeout_seconds,
            emit=emit,
            cancellation_check=cancellation_check,
        )

    if cancellation_check and cancellation_check():
        raise ai_provider_routes.ProviderAdapterError('Generation cancelled by user.', status_code=499)

    return {
        'assistant_text': assistant_text,
        'provider': provider,
        'base_url': base_url,
        'model': model,
    }


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

    def _coerce_scaffold_errors(exc: Exception) -> list[str]:
        message = str(exc).strip() or exc.__class__.__name__
        return [message]

    attempt = _generate_builder_ai_assistant_text(
        payload,
        ai_provider_routes=ai_provider_routes,
        emit=emit,
        cancellation_check=cancellation_check,
        on_response_open=on_response_open,
    )
    auto_heal: dict[str, Any] = {
        'attempted': False,
        'healed': False,
        'initial_scaffold_errors': [],
        'final_scaffold_errors': [],
        'initial_validation_errors': [],
        'final_validation_errors': [],
        'attempt_count': 1,
    }
    if emit is not None:
        emit('status', message='Normalizing scaffold...')
    assistant_text = str(attempt.get('assistant_text') or '')
    try:
        materialized = _materialize_builder_scaffold(assistant_text, payload)
    except Exception as exc:
        scaffold_errors = _coerce_scaffold_errors(exc)
        auto_heal['attempted'] = True
        auto_heal['attempt_count'] = 2
        auto_heal['initial_scaffold_errors'] = list(scaffold_errors)
        auto_heal['final_scaffold_errors'] = list(scaffold_errors)
        if emit is not None:
            emit('status', message='Generated scaffold could not be normalized or built; attempting AI auto-heal...')
            emit('llm_output_reset', reason='Auto-heal retry started after scaffold construction failed.')
        repair_payload = dict(payload)
        repair_payload['prompt'] = _build_builder_scaffold_repair_prompt(str(payload.get('prompt') or ''), scaffold_errors)
        repair_payload['last_test_result'] = {
            'ok': False,
            'returncode': 1,
            'failure_summary': '\n'.join(scaffold_errors),
            'stderr': '\n'.join(scaffold_errors),
            'stdout': '',
            'log_tail': '',
            'files': [],
        }
        repair_attempt = _generate_builder_ai_assistant_text(
            repair_payload,
            ai_provider_routes=ai_provider_routes,
            emit=emit,
            cancellation_check=cancellation_check,
            on_response_open=on_response_open,
        )
        if emit is not None:
            emit('status', message='Normalizing auto-healed scaffold...')
        assistant_text = str(repair_attempt.get('assistant_text') or '')
        try:
            materialized = _materialize_builder_scaffold(assistant_text, repair_payload)
        except Exception as retry_exc:
            retry_scaffold_errors = _coerce_scaffold_errors(retry_exc)
            auto_heal['final_scaffold_errors'] = list(retry_scaffold_errors)
            raise BuilderScaffoldGenerationError(retry_scaffold_errors, auto_heal=auto_heal)

    ai_payload = materialized['ai_payload']
    scaffold_payload = materialized['scaffold_payload']
    scaffold_files = materialized['scaffold_files']
    manifest_yaml = materialized['manifest_yaml']
    folder_path = materialized['folder_path']
    validation_errors = list(materialized['validation_errors'])
    auto_heal['initial_validation_errors'] = list(validation_errors)
    auto_heal['final_validation_errors'] = list(validation_errors)

    if validation_errors:
        auto_heal['attempted'] = True
        auto_heal['attempt_count'] = 2
        if emit is not None:
            emit('status', message='Generated scaffold failed validation; attempting AI auto-heal...')
            emit('llm_output_reset', reason='Auto-heal retry started after scaffold validation failed.')
        repair_payload = dict(payload)
        repair_payload['prompt'] = _build_builder_auto_heal_prompt(str(payload.get('prompt') or ''), validation_errors)
        repair_payload['current_scaffold_request'] = scaffold_payload
        repair_payload['current_files'] = scaffold_files
        repair_payload['last_test_result'] = {
            'ok': False,
            'returncode': 1,
            'failure_summary': '\n'.join(validation_errors),
            'stderr': '\n'.join(validation_errors),
            'stdout': '',
            'log_tail': '',
            'files': [],
        }
        repair_attempt = _generate_builder_ai_assistant_text(
            repair_payload,
            ai_provider_routes=ai_provider_routes,
            emit=emit,
            cancellation_check=cancellation_check,
            on_response_open=on_response_open,
        )
        if emit is not None:
            emit('status', message='Normalizing auto-healed scaffold...')
        assistant_text = str(repair_attempt.get('assistant_text') or '')
        try:
            materialized = _materialize_builder_scaffold(assistant_text, repair_payload)
        except Exception as exc:
            retry_scaffold_errors = _coerce_scaffold_errors(exc)
            auto_heal['final_scaffold_errors'] = list(retry_scaffold_errors)
            raise BuilderScaffoldGenerationError(retry_scaffold_errors, auto_heal=auto_heal)
        ai_payload = materialized['ai_payload']
        scaffold_payload = materialized['scaffold_payload']
        scaffold_files = materialized['scaffold_files']
        manifest_yaml = materialized['manifest_yaml']
        folder_path = materialized['folder_path']
        validation_errors = list(materialized['validation_errors'])
        auto_heal['final_validation_errors'] = list(validation_errors)
        auto_heal['healed'] = not validation_errors
        if validation_errors:
            raise BuilderScaffoldValidationError(validation_errors, auto_heal=auto_heal)
    else:
        auto_heal['healed'] = True

    return {
        'ok': True,
        'provider': str(attempt.get('provider') or ''),
        'base_url': str(attempt.get('base_url') or ''),
        'model': str(attempt.get('model') or ''),
        'assistant_json': ai_payload,
        'assistant_text': assistant_text,
        'scaffold_request': scaffold_payload,
        'folder_path': folder_path,
        'manifest_yaml': manifest_yaml,
        'scaffold_paths': sorted(scaffold_files.keys()),
        'files': scaffold_files,
        'scaffold_errors': [],
        'validation_errors': validation_errors,
        'auto_heal': auto_heal,
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


def _render_grounding_excerpt_head(title: str, rel_path: str, heading: str, *, max_lines: int = 40, max_chars: int = 1800) -> list[str]:
    text = _extract_markdown_section(rel_path, heading)
    if not text:
        return []
    lines = text.splitlines()
    excerpt = '\n'.join(lines[:max_lines]).strip()
    if max_chars > 0 and len(excerpt) > max_chars:
        excerpt = excerpt[:max_chars].rstrip()
    if len(lines) > max_lines or len(text) > len(excerpt):
        excerpt = f'{excerpt}\n... [truncated]'.strip()
    return [
        f'{title} ({rel_path} :: {heading}):',
        '```text',
        excerpt,
        '```',
        '',
    ]


def _render_grounding_head(title: str, rel_path: str, *, max_lines: int = 80, max_chars: int = 4000) -> list[str]:
    text = _read_grounding_file(rel_path)
    if not text:
        return []
    lines = text.splitlines()
    excerpt = '\n'.join(lines[:max_lines]).strip()
    if max_chars > 0 and len(excerpt) > max_chars:
        excerpt = excerpt[:max_chars].rstrip()
    if len(lines) > max_lines or len(text) > len(excerpt):
        excerpt = f'{excerpt}\n... [truncated]'.strip()
    return [
        f'{title} ({rel_path}):',
        '```text',
        excerpt,
        '```',
        '',
    ]


def _build_generator_grounding_lines(plugin_type: str, *, compact: bool = False, ultra_compact: bool = False) -> list[str]:
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
    if ultra_compact:
        lines.extend([
            'Ultra-compact grounding mode is active for this request: return only the requested JSON object and keep the scaffold minimal, deterministic, and valid.',
            '',
        ])
        return lines
    if compact:
        lines.extend(_render_grounding_excerpt_head(
            'Reference docs excerpt: AI scaffolding quickstart',
            'docs/GENERATOR_AUTHORING.md',
            '## 0) AI scaffolding quickstart',
            max_lines=24,
            max_chars=1400,
        ))
        lines.extend(_render_grounding_head('Reference sample excerpt: manifest.yaml', f'{sample_base}/manifest.yaml', max_lines=40, max_chars=1500))
        if plugin_type == 'flag-node-generator':
            lines.extend(_render_grounding_head('Reference template excerpt: docker-compose.yml', f'{template_base}/docker-compose.yml', max_lines=20, max_chars=900))
        lines.extend([
            'Compact grounding mode is active for this request: use the excerpts above as shape guidance and avoid depending on omitted sample details.',
            '',
        ])
        return lines
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
    missing_module = re.search(r"modulenotfounderror:\s+no module named ['\"]([^'\"]+)['\"]", text, re.IGNORECASE)
    if missing_module:
        module_name = missing_module.group(1).strip()
        module_label = module_name or 'the missing dependency'
        lines.extend([
            f'Observed failure to fix first: the runtime image is missing the Python dependency {module_label}.',
            f'- Update compose_text or the Docker image build so {module_label} is installed before generator.py runs.',
            '- If the missing package is optional, remove the import and implementation path that depends on it instead of leaving a guaranteed runtime crash.',
            '- Keep generator.py imports aligned with the packages installed inside the container.',
            '',
        ])
    if 'does not declare them under inputs' in lowered or ('generated scaffold is inconsistent' in lowered and '/inputs/config.json' in lowered):
        lines.extend([
            'Observed failure to fix first: generator.py requires runtime config keys that manifest inputs do not declare.',
            '- Every key that generator.py treats as required from /inputs/config.json must appear in runtime_inputs so manifest.yaml inputs stay aligned.',
            '- If the required key is sensitive, mark it sensitive in runtime_inputs.',
            '- If the extra key is not truly required, remove the hard failure path from generator.py instead of leaving manifest/code drift.',
            '',
        ])
    return lines


def _builder_file_block_language(path: str) -> str:
    lowered = str(path or '').lower()
    if lowered.endswith('.py'):
        return 'python'
    if lowered.endswith('.md'):
        return 'markdown'
    if lowered.endswith('.yaml') or lowered.endswith('.yml'):
        return 'yaml'
    if lowered.endswith('.json'):
        return 'json'
    return ''


def _format_builder_current_files(current_files: dict[str, Any] | None) -> list[str]:
    if not isinstance(current_files, dict):
        return []
    lines: list[str] = []
    for key in sorted(current_files.keys()):
        text = str(current_files.get(key) or '')
        if not (
            key.endswith('/manifest.yaml')
            or key.endswith('/generator.py')
            or key.endswith('/README.md')
            or key.endswith('/docker-compose.yml')
        ):
            continue
        language = _builder_file_block_language(key)
        lines.append(f'File: {key}')
        lines.append(f'```{language}' if language else '```')
        lines.append(text.rstrip('\n'))
        lines.append('```')
        lines.append('')
    return lines


def _extract_builder_original_create_prompt(iteration_history: list[dict[str, Any]] | None) -> str:
    if not isinstance(iteration_history, list):
        return ''
    for entry in iteration_history:
        if not isinstance(entry, dict):
            continue
        mode = str(entry.get('mode') or '').strip().lower()
        prompt = str(entry.get('prompt') or '').strip()
        if mode == 'create' and prompt:
            return prompt
    return ''


def _format_builder_iteration_history(iteration_history: list[dict[str, Any]] | None) -> list[str]:
    if not isinstance(iteration_history, list):
        return []
    lines: list[str] = []
    for entry in iteration_history[-8:]:
        if not isinstance(entry, dict):
            continue
        mode = str(entry.get('mode') or '').strip().lower()
        if mode not in {'create', 'refine'}:
            continue
        prompt = str(entry.get('prompt') or '').strip()
        if not prompt:
            continue
        status = str(entry.get('status') or '').strip()
        plugin_id = str(entry.get('plugin_id') or '').strip()
        detail_parts = []
        if status:
            detail_parts.append(f'status={status}')
        if plugin_id:
            detail_parts.append(f'plugin_id={plugin_id}')
        detail = f" ({', '.join(detail_parts)})" if detail_parts else ''
        lines.append(f'- {mode}{detail}: {prompt}')
    return lines


def _format_builder_scaffold_validation(scaffold_validation: dict[str, Any] | None) -> list[str]:
    if not isinstance(scaffold_validation, dict):
        return []
    if scaffold_validation.get('pending') is True:
        return ['- Validation is still pending.']
    lines: list[str] = []
    errors = scaffold_validation.get('errors') if isinstance(scaffold_validation.get('errors'), list) else []
    for error in errors[:8]:
        text = str(error or '').strip()
        if text:
            lines.append(f'- {text}')
    message = str(scaffold_validation.get('message') or '').strip()
    if message and all(message != line[2:] for line in lines if line.startswith('- ')):
        lines.append(f'- {message}')
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
    compact_grounding = bool(payload.get('compact_grounding'))
    ultra_compact_prompt = bool(payload.get('ultra_compact_prompt'))
    source_id_hint = str(payload.get('source_id_hint') or '').strip()
    name_hint = str(payload.get('name_hint') or '').strip()
    prompt = str(payload.get('prompt') or '').strip()
    if not prompt:
        raise ValueError('prompt is required')
    prompt_lower = prompt.lower()
    prompt_mentions_image = any(token in prompt_lower for token in ('stego', 'stegan', 'carrier image', 'png', 'jpeg', 'jpg', 'image flag', 'image artifact'))

    kind_requirements = [
        '- For all generators: read /inputs/config.json and write /outputs/outputs.json.',
        '- outputs.json must include generator_id and Flag(flag_id).',
        '- Keep outputs deterministic for the same inputs.',
        '- Use Python standard library only unless the prompt explicitly requires otherwise.',
        '- Return JSON only. Do not wrap in markdown fences.',
        '- Any /inputs/config.json key that generator.py requires must be declared in runtime_inputs so manifest inputs match the code.',
        '- If a required runtime input is secret-like (for example secret, token, api_key, password), mark it sensitive in runtime_inputs.',
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
        if prompt_mentions_image:
            kind_requirements.extend([
                '- For image or steganography outputs, generate a valid, viewable carrier image file rather than random bytes renamed to .png or .jpg.',
                '- Prefer Pillow/PIL with an explicit install step in compose_text when you need to create or modify images; do not hand-roll PNG or JPEG bytes unless you fully implement a standards-compliant encoder.',
                '- Do not append arbitrary payload bytes after image end markers or mutate container bytes outside real pixel data.',
                '- If you embed a flag in an image, preserve normal renderability of the carrier image and write the artifact under /outputs/artifacts/.',
            ])

    if ultra_compact_prompt:
        kind_requirements = [
            '- Read /inputs/config.json and write /outputs/outputs.json.',
            '- outputs.json must include generator_id and Flag(flag_id).',
            '- Keep outputs deterministic and ensure all declared outputs exist.',
        ]
        if plugin_type == 'flag-node-generator':
            kind_requirements.extend([
                '- Also write /outputs/docker-compose.yml and expose File(path): docker-compose.yml.',
                '- Do not emit ${...} placeholders in docker-compose.yml.',
            ])
        else:
            kind_requirements.extend([
                '- Write file outputs under /outputs or /outputs/artifacts and reference them from outputs.json.',
                '- If inject_files includes File(path), that file must be created before exit.',
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
    if ultra_compact_prompt:
        schema_lines = [
            '{"plugin_id":"source_identifier","folder_name":"py_source_identifier","name":"Human-readable name","description":"One sentence summary","requires":[{"artifact":"Knowledge(ip)","optional":false}],"optional_requires":[],"produces":["Flag(flag_id)"],"runtime_inputs":[],"hint_templates":[],"inject_files":[],"env":{},"readme_text":"full README.md text","generator_py_text":"full generator.py text","compose_text":"full docker-compose.yml text if needed"}',
        ]
    elif compact_grounding:
        schema_lines = [
            '{"plugin_id":"source_identifier","folder_name":"py_source_identifier","name":"Human-readable name","description":"One sentence summary","requires":[{"artifact":"Knowledge(ip)","optional":false}],"optional_requires":["Knowledge(hostname)"],"produces":["Flag(flag_id)"],"runtime_inputs":[{"name":"seed","type":"string","required":true}],"hint_templates":["Next: use {{OUTPUT.Flag(flag_id)}}"],"inject_files":["File(path)"],"env":{"EXAMPLE":"value"},"readme_text":"full README.md text","generator_py_text":"full generator.py text","compose_text":"full docker-compose.yml text"}',
        ]

    current_scaffold = payload.get('current_scaffold_request') if isinstance(payload.get('current_scaffold_request'), dict) else None
    current_files = payload.get('current_files') if isinstance(payload.get('current_files'), dict) else None
    last_test_result = payload.get('last_test_result') if isinstance(payload.get('last_test_result'), dict) else None
    iteration_history = payload.get('iteration_history') if isinstance(payload.get('iteration_history'), list) else None
    scaffold_validation = payload.get('scaffold_validation') if isinstance(payload.get('scaffold_validation'), dict) else None
    mode = 'refine' if current_scaffold else 'create'

    context_lines = [
        f'Mode: {mode}',
        f'Target kind: {plugin_type}',
        f'Grounding mode: {"ultra-compact" if ultra_compact_prompt else ("compact" if compact_grounding else "full")}',
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
    if ultra_compact_prompt:
        minimal_requirements = [
            '- Reply with exactly one JSON object and no prose.',
            '- Include plugin_id, name, description, readme_text, and generator_py_text.',
            '- Keep produces aligned with outputs.json and include Flag(flag_id).',
            '- Include compose_text only if it is actually required.',
        ]
        if plugin_type == 'flag-node-generator':
            minimal_requirements.append('- For node generators, include a working docker-compose.yml in compose_text.')
        else:
            minimal_requirements.append('- For file outputs, write them under /outputs or /outputs/artifacts and reference them from outputs.json.')
        context_lines = [
            f'Mode: {mode}',
            f'Target kind: {plugin_type}',
            'Grounding mode: ultra-compact',
            '',
            'Requirements:',
            *minimal_requirements,
            '',
            'JSON schema shape:',
            *schema_lines,
            '',
            'User request:',
            prompt or 'Build a deterministic generator scaffold.',
            '',
        ]
    else:
        context_lines.extend(_build_prompt_intent_guidance(prompt, plugin_type, payload.get('intent_overrides')))
    if current_scaffold:
        context_lines.extend([
            'Refinement priority:',
            '- Treat the current scaffold below as the source material to edit, not as a loose example.',
            '- Preserve plugin_id, folder_name, and working behavior unless the user request or concrete failure requires a change.',
            '- Fix the latest concrete failure first, then make only the minimum additional edits needed to satisfy the user request.',
            '- Do not return the current scaffold unchanged; update the relevant files that implement the requested fix.',
            '',
            'Current scaffold request (treat this as the existing generator state and preserve compatible parts unless the user asked to change them):',
            json.dumps(current_scaffold, indent=2, ensure_ascii=False),
            '',
        ])
    original_create_prompt = _extract_builder_original_create_prompt(iteration_history)
    if original_create_prompt:
        context_lines.extend([
            'Original create request:',
            original_create_prompt,
            '',
        ])
    formatted_iteration_history = _format_builder_iteration_history(iteration_history)
    if formatted_iteration_history:
        context_lines.extend([
            'Recent create/refine history (oldest to newest):',
            *formatted_iteration_history,
            '- Preserve earlier intent unless the newest user request or a concrete test/validation failure requires changing it.',
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
    formatted_scaffold_validation = _format_builder_scaffold_validation(scaffold_validation)
    if formatted_scaffold_validation:
        context_lines.extend([
            'Current scaffold validation warnings:',
            *formatted_scaffold_validation,
            '- Fix these warnings if they are still relevant after applying the latest request.',
            '',
        ])
    formatted_current_files = _format_builder_current_files(current_files)
    if formatted_current_files:
        context_lines.extend([
            'Current scaffold files:',
            *formatted_current_files,
        ])
    context_lines.extend(_build_generator_grounding_lines(plugin_type, compact=compact_grounding, ultra_compact=ultra_compact_prompt))
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
    installed_generators_root: Callable[[], str],
    flag_generators_from_enabled_sources: Callable[[], tuple[list[dict], list[dict]]],
    flag_node_generators_from_enabled_sources: Callable[[], tuple[list[dict], list[dict]]],
    reserved_artifacts: dict[str, dict[str, Any]],
    load_custom_artifacts: Callable[[], dict[str, dict[str, Any]]],
    upsert_custom_artifact: Callable[..., dict[str, Any]],
    build_generator_scaffold: Callable[[dict[str, Any]], tuple[dict[str, str], str, str]],
    validate_builder_scaffold: Callable[[dict[str, str]], list[str]],
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
    global _BUILD_GENERATOR_SCAFFOLD, _VALIDATE_BUILDER_SCAFFOLD
    _BUILD_GENERATOR_SCAFFOLD = build_generator_scaffold
    _VALIDATE_BUILDER_SCAFFOLD = validate_builder_scaffold
    if not begin_route_registration(app, 'generator_builder_routes'):
        return

    def _builder_existing_generator_views(plugin_type: str) -> list[dict[str, Any]]:
        loader = flag_node_generators_from_enabled_sources if str(plugin_type or '').strip() == 'flag-node-generator' else flag_generators_from_enabled_sources
        try:
            generators, _errors = loader()
        except Exception:
            return []
        return [generator for generator in (generators or []) if isinstance(generator, dict)]

    def _builder_existing_generator_ids(plugin_type: str) -> set[str]:
        existing: set[str] = set()
        kind_dir = 'flag_node_generators' if str(plugin_type or '').strip() == 'flag-node-generator' else 'flag_generators'
        try:
            installed_root = os.path.join(installed_generators_root(), kind_dir)
            for dirpath, _dirnames, filenames in os.walk(installed_root):
                if '.coretg_pack.json' not in filenames:
                    continue
                marker_path = os.path.join(dirpath, '.coretg_pack.json')
                try:
                    with open(marker_path, 'r', encoding='utf-8') as handle:
                        marker = json.load(handle)
                    if isinstance(marker, dict):
                        source_id = str(marker.get('source_generator_id') or '').strip()
                        normalized_id = sanitize_id(source_id) or _derive_plugin_id(source_id, fallback='')
                        if source_id:
                            existing.add(source_id)
                        if normalized_id:
                            existing.add(normalized_id)
                except Exception:
                    continue
        except Exception:
            pass
        for generator in _builder_existing_generator_views(plugin_type):
            raw_id = str(generator.get('id') or '').strip()
            normalized_id = sanitize_id(raw_id) or _derive_plugin_id(raw_id, fallback='')
            if raw_id:
                existing.add(raw_id)
            if normalized_id:
                existing.add(normalized_id)
        return existing

    def _builder_existing_generator_names(plugin_type: str) -> set[str]:
        existing: set[str] = set()
        for generator in _builder_existing_generator_views(plugin_type):
            name = str(generator.get('name') or '').strip().lower()
            if name:
                existing.add(name)
        return existing

    def _next_unique_builder_id(requested_id: str, *, plugin_type: str) -> tuple[str, bool]:
        candidate = sanitize_id(requested_id) or _derive_plugin_id(requested_id, fallback='generated_generator')
        existing = _builder_existing_generator_ids(plugin_type)
        if candidate not in existing:
            return candidate, False
        match = re.match(r'^(.*?)(?:[_-](\d+))?$', candidate)
        root = (match.group(1) if match and match.group(1) else candidate).strip('_-') or candidate
        suffix = int(match.group(2)) + 1 if match and match.group(2) else 2
        while candidate in existing:
            candidate = f'{root}_{suffix}'
            suffix += 1
        return candidate, True

    def _next_unique_builder_name(requested_name: str, *, plugin_type: str) -> str:
        base_name = str(requested_name or '').strip()
        if not base_name:
            return base_name
        existing = _builder_existing_generator_names(plugin_type)
        if base_name.lower() not in existing:
            return base_name
        match = re.match(r'^(.*?)(?:\s+(\d+))?$', base_name)
        root = (match.group(1) if match and match.group(1) else base_name).strip() or base_name
        suffix = int(match.group(2)) + 1 if match and match.group(2) else 2
        candidate = base_name
        while candidate.lower() in existing:
            candidate = f'{root} {suffix}'
            suffix += 1
        return candidate

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
        response = {
            'ok': True,
            'manifest_yaml': manifest_yaml,
            'scaffold_paths': sorted(scaffold_files.keys()),
        }
        validation_errors = validate_builder_scaffold(scaffold_files)
        if validation_errors:
            response['validation_errors'] = validation_errors
            response['validation_ok'] = False
        return jsonify(response)

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
        from webapp.routes import ai_provider as ai_provider_routes
        payload = ai_provider_routes._resolve_payload_with_stored_api_key(request.get_json(silent=True) or {})

        try:
            result = _build_builder_ai_scaffold_result(payload, ai_provider_routes=ai_provider_routes)
        except ai_provider_routes.ProviderAdapterError as exc:
            return jsonify({'ok': False, 'error': exc.message, **(exc.details or {})}), exc.status_code
        except BuilderScaffoldGenerationError as exc:
            return jsonify({
                'ok': False,
                'error': str(exc),
                'scaffold_errors': exc.scaffold_errors,
                'auto_heal': exc.auto_heal,
            }), 422
        except BuilderScaffoldValidationError as exc:
            return jsonify({
                'ok': False,
                'error': str(exc),
                'validation_errors': exc.validation_errors,
                'auto_heal': exc.auto_heal,
            }), 422
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 400

        return jsonify(result)

    @app.route('/api/generators/ai_scaffold_stream', methods=['POST'])
    def api_generators_ai_scaffold_stream():
        require_builder_or_admin()
        from webapp.routes import ai_provider as ai_provider_routes
        payload = ai_provider_routes._resolve_payload_with_stored_api_key(request.get_json(silent=True) or {})

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
                except BuilderScaffoldGenerationError as exc:
                    emit('error', error=str(exc), status_code=422, scaffold_errors=exc.scaffold_errors, auto_heal=exc.auto_heal)
                except BuilderScaffoldValidationError as exc:
                    emit('error', error=str(exc), status_code=422, validation_errors=exc.validation_errors, auto_heal=exc.auto_heal)
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
        validation_errors = validate_builder_scaffold(scaffold_files)
        if validation_errors:
            return jsonify({
                'ok': False,
                'error': validation_errors[0],
                'validation_errors': validation_errors,
            }), 400

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
        validation_errors = validate_builder_scaffold(scaffold_files)
        if validation_errors:
            return jsonify({
                'ok': False,
                'error': validation_errors[0],
                'validation_errors': validation_errors,
            }), 400

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
            normalized_payload = dict(scaffold_payload)
            plugin_type = str(normalized_payload.get('plugin_type') or 'flag-generator').strip() or 'flag-generator'
            requested_plugin_id = sanitize_id(normalized_payload.get('plugin_id')) or _derive_plugin_id(normalized_payload.get('plugin_id') or normalized_payload.get('name') or '')
            requested_name = str(normalized_payload.get('name') or requested_plugin_id).strip() or requested_plugin_id
            final_plugin_id, renamed = _next_unique_builder_id(requested_plugin_id, plugin_type=plugin_type)
            final_name = requested_name
            if renamed:
                final_name = _next_unique_builder_name(requested_name, plugin_type=plugin_type) or final_plugin_id
                normalized_payload['folder_name'] = secure_filename(f'py_{final_plugin_id}') or f'py_{final_plugin_id}'
            else:
                normalized_payload['folder_name'] = str(normalized_payload.get('folder_name') or '').strip() or (secure_filename(f'py_{final_plugin_id}') or f'py_{final_plugin_id}')
            normalized_payload['plugin_id'] = final_plugin_id
            normalized_payload['name'] = final_name
            scaffold_files, _manifest_yaml, _folder_path = build_generator_scaffold(normalized_payload)
            validation_errors = validate_builder_scaffold(scaffold_files)
            if validation_errors:
                return jsonify({'ok': False, 'error': validation_errors[0], 'validation_errors': validation_errors}), 400
            zip_bytes = _build_scaffold_zip_bytes(scaffold_files, zipfile_module=zipfile_module, io_module=io_module)
            requested_pack_label = str(payload.get('pack_label') or scaffold_payload.get('name') or scaffold_payload.get('plugin_id') or 'generated-builder-pack').strip()
            pack_label = requested_pack_label or final_name or final_plugin_id or 'generated-builder-pack'
            if renamed and pack_label in {requested_name, requested_plugin_id}:
                pack_label = final_name or final_plugin_id or pack_label
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
        rename_note = ''
        if renamed:
            rename_note = f'Duplicate generator id "{requested_plugin_id}" detected. Installed as "{final_plugin_id}".'
        return jsonify({
            'ok': True,
            'message': note,
            'pack_label': pack_label,
            'renamed': renamed,
            'rename_note': rename_note,
            'installed_as': {
                'plugin_type': plugin_type,
                'plugin_id': final_plugin_id,
                'name': final_name,
                'folder_name': str(normalized_payload.get('folder_name') or ''),
            },
        })

    @app.route('/api/generators/scaffold_zip', methods=['POST'])
    def api_generators_scaffold_zip():
        require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        try:
            scaffold_files, _manifest_yaml, _folder_path = build_generator_scaffold(payload)
            plugin_id = sanitize_id(payload.get('plugin_id')) or 'generator'
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 400
        validation_errors = validate_builder_scaffold(scaffold_files)
        if validation_errors:
            return jsonify({'ok': False, 'error': validation_errors[0], 'validation_errors': validation_errors}), 400

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