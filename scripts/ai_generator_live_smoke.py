import argparse
import http.cookiejar
import json
import sys
import urllib.parse
import urllib.request


DEFAULT_BASE_URL = 'http://127.0.0.1:9090'
DEFAULT_USERNAME = 'coreadmin'
DEFAULT_PASSWORD = 'coreadmin'


def _build_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def _http_post(opener: urllib.request.OpenerDirector, url: str, form_data: dict[str, str]) -> str:
    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(form_data).encode('utf-8'),
        method='POST',
    )
    with opener.open(request, timeout=20) as response:
        return response.read().decode('utf-8', errors='replace')


def _http_get(opener: urllib.request.OpenerDirector, url: str) -> str:
    with opener.open(url, timeout=20) as response:
        return response.read().decode('utf-8', errors='replace')


def _require(text: str, needle: str, *, source: str) -> None:
    if needle not in text:
        raise AssertionError(f'Missing expected marker in {source}: {needle}')


def main() -> int:
    parser = argparse.ArgumentParser(description='Smoke-test the live AI Generator UI and provider catalog.')
    parser.add_argument('--base-url', default=DEFAULT_BASE_URL)
    parser.add_argument('--username', default=DEFAULT_USERNAME)
    parser.add_argument('--password', default=DEFAULT_PASSWORD)
    args = parser.parse_args()

    base_url = str(args.base_url or DEFAULT_BASE_URL).rstrip('/')
    opener = _build_opener()

    _http_post(
        opener,
        f'{base_url}/login',
        {'username': str(args.username), 'password': str(args.password)},
    )

    index_html = _http_get(opener, f'{base_url}/')
    providers_text = _http_get(opener, f'{base_url}/api/ai/providers')
    panel_js = _http_get(opener, f'{base_url}/static/ai_generator_panel.js')
    workflow_js = _http_get(opener, f'{base_url}/static/ai_generator_workflow.js')

    _require(index_html, '/static/ai_generator_panel.js', source='index')
    _require(index_html, '/static/ai_generator_workflow.js', source='index')
    _require(index_html, 'aiGeneratorStreamAutoFollowInput', source='index')

    providers_payload = json.loads(providers_text)
    if not providers_payload.get('success'):
        raise AssertionError('Provider catalog did not return success=true')

    providers = providers_payload.get('providers') or []
    labels = {str(item.get('label') or '').strip() for item in providers if isinstance(item, dict)}
    provider_keys = {str(item.get('provider') or '').strip() for item in providers if isinstance(item, dict)}
    if labels != {'Ollama', 'OpenAI-Compatible'}:
        raise AssertionError(f'Unexpected provider labels: {sorted(labels)}')
    if provider_keys != {'ollama', 'litellm'}:
        raise AssertionError(f'Unexpected provider keys: {sorted(provider_keys)}')

    for needle in (
        'OpenAI-Compatible',
        'aiGeneratorSaveApiKeyBtn',
        'aiGeneratorClearApiKeyBtn',
        'aiGeneratorApiKeyStatus',
        'Stored securely on the server for your account.',
        'type="url" class="form-control" id="aiGeneratorBaseUrlInput"',
    ):
        _require(panel_js, needle, source='ai_generator_panel.js')

    for needle in (
        'best_effort_used',
        'best_effort_reason',
        'auto_heal_prompt',
        'auto_heal_leniency',
    ):
        _require(workflow_js, needle, source='ai_generator_workflow.js')

    print('SMOKE_AI_GENERATOR_OK=1')
    print(f'base_url={base_url}')
    print(f'providers={sorted(labels)}')
    print(f'default_provider={providers_payload.get("default_provider")!r}')
    return 0


if __name__ == '__main__':
    sys.exit(main())