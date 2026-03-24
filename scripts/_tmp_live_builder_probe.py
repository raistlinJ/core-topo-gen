import argparse
import http.cookiejar
import json
import ssl
import sys
import time
from urllib.error import HTTPError
import urllib.parse
import urllib.request


def _open_json(opener, url, payload, *, accept='application/json', timeout=30):
    body = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            'Content-Type': 'application/json',
            'Accept': accept,
        },
        method='POST',
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.read().decode('utf-8'), getattr(resp, 'status', None) or resp.getcode()
    except HTTPError as exc:
        detail = ''
        try:
            detail = exc.read().decode('utf-8', errors='replace')
        except Exception:
            detail = ''
        return detail, exc.code


def _open_direct(url, *, headers=None, timeout=30, insecure=False):
    req = urllib.request.Request(url, headers=headers or {}, method='GET')
    try:
        context = ssl._create_unverified_context() if insecure else None
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            return resp.read().decode('utf-8', errors='replace'), getattr(resp, 'status', None) or resp.getcode()
    except HTTPError as exc:
        detail = ''
        try:
            detail = exc.read().decode('utf-8', errors='replace')
        except Exception:
            detail = ''
        return detail, exc.code


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--web-base', default='http://127.0.0.1:9090')
    parser.add_argument('--provider-base', required=True)
    parser.add_argument('--api-key', required=True)
    parser.add_argument('--model', required=True)
    parser.add_argument('--prompt', default='Build a deterministic demo generator.')
    parser.add_argument('--stream-timeout', type=float, default=180.0)
    parser.add_argument('--insecure', action='store_true')
    args = parser.parse_args()

    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    login_body = urllib.parse.urlencode({'username': 'coreadmin', 'password': 'coreadmin'}).encode('utf-8')
    login_req = urllib.request.Request(f'{args.web_base}/login', data=login_body, method='POST')
    with opener.open(login_req, timeout=20) as resp:
        login_status = getattr(resp, 'status', None) or resp.getcode()
        print(f'LOGIN_STATUS={login_status}')

    validate_payload = {
        'provider': 'litellm',
        'base_url': args.provider_base,
        'api_key': args.api_key,
        'model': args.model,
        'enforce_ssl': not args.insecure,
    }
    validate_text, validate_status = _open_json(
        opener,
        f'{args.web_base}/api/ai/provider/validate',
        validate_payload,
        timeout=60,
    )
    print(f'VALIDATE_HTTP={validate_status}')
    print(f'VALIDATE_BODY={validate_text}')

    direct_models_url = args.provider_base.rstrip('/')
    if not direct_models_url.endswith('/v1'):
        direct_models_url = f'{direct_models_url}/v1'
    direct_models_url = f'{direct_models_url}/models'
    direct_headers = {
        'Authorization': f'Bearer {args.api_key}',
        'Accept': 'application/json',
        'Connection': 'close',
    }
    direct_models_text, direct_models_status = _open_direct(
        direct_models_url,
        headers=direct_headers,
        timeout=60,
        insecure=args.insecure,
    )
    print(f'DIRECT_MODELS_HTTP={direct_models_status}')
    print(f'DIRECT_MODELS_BODY={direct_models_text}')

    request_id = f'live-builder-{int(time.time())}'
    scaffold_payload = {
        'request_id': request_id,
        'plugin_type': 'flag-generator',
        'provider': 'litellm',
        'base_url': args.provider_base,
        'api_key': args.api_key,
        'model': args.model,
        'prompt': args.prompt,
        'enforce_ssl': not args.insecure,
    }
    body = json.dumps(scaffold_payload).encode('utf-8')
    req = urllib.request.Request(
        f'{args.web_base}/api/generators/ai_scaffold_stream',
        data=body,
        headers={
            'Content-Type': 'application/json',
            'Accept': 'application/x-ndjson',
        },
        method='POST',
    )

    start = time.time()
    last_lines: list[str] = []
    try:
        with opener.open(req, timeout=args.stream_timeout) as resp:
            stream_status = getattr(resp, 'status', None) or resp.getcode()
            print(f'STREAM_HTTP={stream_status}')
            while True:
                raw = resp.readline()
                if not raw:
                    break
                line = raw.decode('utf-8', errors='replace').strip()
                if not line:
                    continue
                last_lines.append(line)
                last_lines = last_lines[-40:]
                print(line)
                sys.stdout.flush()
    except Exception as exc:
        print(f'STREAM_EXCEPTION={type(exc).__name__}: {exc}')
    finally:
        elapsed = time.time() - start
        print(f'ELAPSED_SECONDS={elapsed:.1f}')
        if last_lines:
            print('LAST_LINES_START')
            for line in last_lines:
                print(line)
            print('LAST_LINES_END')

    return 0


if __name__ == '__main__':
    raise SystemExit(main())