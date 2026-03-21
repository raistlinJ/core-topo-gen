import pytest

from scripts import ai_generator_live_smoke


def test_require_raises_for_missing_marker() -> None:
    with pytest.raises(AssertionError, match='Missing expected marker in panel.js: needle'):
        ai_generator_live_smoke._require('alpha beta', 'needle', source='panel.js')


def test_main_validates_live_ai_generator_assets(monkeypatch, capsys) -> None:
    calls: list[tuple[str, str]] = []

    def fake_build_opener():
        return object()

    def fake_http_post(opener, url, form_data):
        calls.append(('POST', url))
        assert opener is not None
        assert form_data == {'username': 'coreadmin', 'password': 'coreadmin'}
        return 'ok'

    def fake_http_get(opener, url):
        calls.append(('GET', url))
        if url.endswith('/api/ai/providers'):
            return (
                '{"success": true, "default_provider": "ollama", "providers": ['
                '{"label": "OpenAI-Compatible", "provider": "litellm"},'
                '{"label": "Ollama", "provider": "ollama"}'
                ']}'
            )
        if url.endswith('/static/ai_generator_panel.js'):
            return '\n'.join([
                'Auto-heal Prompt',
                'aiGeneratorAutoHealPromptInput',
                'aiGeneratorAutoHealLeniencyInput',
                'High: more retries, best-effort fallback',
                'OpenAI-Compatible',
            ])
        if url.endswith('/static/ai_generator_workflow.js'):
            return '\n'.join([
                'best_effort_used',
                'best_effort_reason',
                'auto_heal_prompt',
                'auto_heal_leniency',
            ])
        return '<script src="/static/ai_generator_panel.js"></script><script src="/static/ai_generator_workflow.js"></script>'

    monkeypatch.setattr(ai_generator_live_smoke, '_build_opener', fake_build_opener)
    monkeypatch.setattr(ai_generator_live_smoke, '_http_post', fake_http_post)
    monkeypatch.setattr(ai_generator_live_smoke, '_http_get', fake_http_get)
    monkeypatch.setattr('sys.argv', ['ai_generator_live_smoke.py'])

    exit_code = ai_generator_live_smoke.main()

    assert exit_code == 0
    assert calls[0] == ('POST', 'http://127.0.0.1:9090/login')
    out = capsys.readouterr().out
    assert 'SMOKE_AI_GENERATOR_OK=1' in out
    assert "providers=['Ollama', 'OpenAI-Compatible']" in out


def test_main_rejects_unexpected_provider_catalog(monkeypatch) -> None:
    def fake_build_opener():
        return object()

    def fake_http_post(opener, url, form_data):
        return 'ok'

    def fake_http_get(opener, url):
        if url.endswith('/api/ai/providers'):
            return '{"success": true, "default_provider": "ollama", "providers": [{"label": "Anthropic", "provider": "anthropic"}]}'
        if url.endswith('/static/ai_generator_panel.js'):
            return 'Auto-heal Prompt\naiGeneratorAutoHealPromptInput\naiGeneratorAutoHealLeniencyInput\nHigh: more retries, best-effort fallback\nOpenAI-Compatible'
        if url.endswith('/static/ai_generator_workflow.js'):
            return 'best_effort_used\nbest_effort_reason\nauto_heal_prompt\nauto_heal_leniency'
        return '<script src="/static/ai_generator_panel.js"></script><script src="/static/ai_generator_workflow.js"></script>'

    monkeypatch.setattr(ai_generator_live_smoke, '_build_opener', fake_build_opener)
    monkeypatch.setattr(ai_generator_live_smoke, '_http_post', fake_http_post)
    monkeypatch.setattr(ai_generator_live_smoke, '_http_get', fake_http_get)
    monkeypatch.setattr('sys.argv', ['ai_generator_live_smoke.py'])

    with pytest.raises(AssertionError, match='Unexpected provider labels'):
        ai_generator_live_smoke.main()