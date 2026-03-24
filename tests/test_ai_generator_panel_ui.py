from pathlib import Path


AI_PANEL_PATH = Path(__file__).resolve().parent.parent / "webapp" / "static" / "ai_generator_panel.js"
INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"
AI_STREAM_PATH = Path(__file__).resolve().parent.parent / "webapp" / "static" / "ai_generator_stream.js"


def test_ai_generator_panel_uses_provider_catalog_instead_of_hardcoded_dropdown() -> None:
    text = AI_PANEL_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function getProviderCatalog() {",
        "deps.getAiProviderCatalog()",
        "deps.refreshAiProviderCatalog()",
        "const providerEntries = getProviderEntries();",
        "const providerOptions = providerEntries.map((entry) => {",
        "supports_mcp_bridge",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing AI Generator provider catalog wiring snippets: " + "; ".join(missing)



def test_ai_generator_panel_renders_openai_compatible_controls_from_catalog_backed_ui() -> None:
    text = AI_PANEL_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "provider === 'litellm'",
        'id="aiGeneratorApiKeyInput"',
        'id="aiGeneratorSaveApiKeyBtn"',
        'id="aiGeneratorClearApiKeyBtn"',
        'id="aiGeneratorApiKeyStatus"',
        'id="aiGeneratorEnforceSslInput"',
        "supportsBridge: true",
        'reachable and MCP tools ready',
        'When on, the OpenAI-compatible base URL must use <strong>https</strong>',
        'Stored securely on the server for your account.',
        'Connect fetches models from',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing OpenAI-compatible UI control snippets in AI Generator panel: " + "; ".join(missing)


def test_ai_generator_panel_no_longer_shows_bridge_field_copy() -> None:
    text = AI_PANEL_PATH.read_text(encoding="utf-8", errors="ignore")

    removed_snippets = [
        '<label class="form-label">Bridge</label>',
        'id="aiGeneratorBridgeModeInput"',
        'official MCP Python SDK',
    ]

    present = [snippet for snippet in removed_snippets if snippet in text]
    assert not present, "Bridge field copy should be removed from AI Generator panel: " + "; ".join(present)


def test_ai_generator_panel_keeps_mcp_tooling_available_for_openai_compatible_provider() -> None:
    text = AI_PANEL_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "provider: 'litellm'",
        'supports_mcp_bridge: true',
        'Validate the bridge to discover MCP tools exposed through the MCP Python SDK bridge.',
        'data-ai-generator-tool="${escapeHtml(name)}"',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing OpenAI-compatible MCP tool UI snippets in AI Generator panel: " + "; ".join(missing)


def test_ai_generator_panel_exposes_bridge_bypass_toggle() -> None:
    text = AI_PANEL_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'id="aiGeneratorUseBridgeInput"',
        'Use MCP Bridge',
        'bypass the MCP bridge and test direct',
        "skip_bridge: !useBridgeInput.checked",
        'const useBridge = supportsBridge && aiState.skip_bridge !== true;',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing AI Generator bridge bypass toggle snippets: " + "; ".join(missing)


def test_ai_generator_panel_shows_fetch_models_button_and_hook() -> None:
    text = AI_PANEL_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'id="aiGeneratorFetchModelsBtn"',
        'Fetch Models',
        "const fetchModelsBtn = document.getElementById('aiGeneratorFetchModelsBtn');",
        "deps.fetchAiGeneratorModels()",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing Fetch-models button wiring in AI Generator Provider Config: " + "; ".join(missing)


def test_ai_generator_workflow_blocks_bridge_generation_without_enabled_tools() -> None:
    text = (Path(__file__).resolve().parent.parent / "webapp" / "static" / "ai_generator_workflow.js").read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const hasDiscoveredTools = Array.isArray(nextAvailableTools) && nextAvailableTools.length > 0;",
        "bridge_ok: providerMeta.supportsBridge ? hasDiscoveredTools : false",
        "No MCP tools are enabled. Refresh Connection and enable at least one tool before generating.",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing AI Generator workflow safeguards for zero enabled MCP tools: " + "; ".join(missing)


def test_ai_generator_workflow_uses_stored_key_unless_replacement_is_dirty() -> None:
    text = (Path(__file__).resolve().parent.parent / "webapp" / "static" / "ai_generator_workflow.js").read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function resolveAiGeneratorApiKey(aiState) {",
        "return aiState.api_key_dirty === true ? raw : '';",
        "api_key: resolveAiGeneratorApiKey(aiState),",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing AI Generator workflow stored-key resolution snippets: " + "; ".join(missing)


def test_ai_generator_workflow_classifies_validated_vulnerability_shortages_as_warnings() -> None:
    text = (Path(__file__).resolve().parent.parent / "webapp" / "static" / "ai_generator_workflow.js").read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function classifyGenerationWarning(message) {",
        "last_generation_error: warningMessage ? '' : message",
        "last_generation_warning: warningMessage",
        "validated\\/tested\\s+vulnerabilit(?:y|ies)",
        "validate more vulnerabilities|reduce the requested vulnerability count",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing AI Generator validated-vulnerability shortage warning snippets: " + "; ".join(missing)


def test_ai_generator_panel_renders_validated_vulnerability_warning_block() -> None:
    text = AI_PANEL_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const generationWarning = (aiState.last_generation_warning || '').toString().trim();",
        'id="aiGeneratorGenerationWarningWrap"',
        'id="aiGeneratorGenerationWarning"',
        'alert alert-warning mb-0 small',
        'Not enough validated/tested vulnerabilities are currently eligible for this request.',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing AI Generator validated-vulnerability warning UI snippets: " + "; ".join(missing)


def test_ai_generator_panel_uses_url_field_for_provider_base_url_and_disables_password_manager_hints() -> None:
    text = AI_PANEL_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'type="url" class="form-control" id="aiGeneratorBaseUrlInput"',
        'autocomplete="url"',
        'autocapitalize="off"',
        'spellcheck="false"',
        'autocomplete="new-password"',
        'data-lpignore="true"',
        'data-1p-ignore="true"',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing AI Generator URL/API-key field hardening snippets: " + "; ".join(missing)


def test_ai_generator_panel_ignores_stale_api_key_overrides_when_stored_key_exists() -> None:
    text = AI_PANEL_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function resolveAiGeneratorApiKey(aiState) {",
        "return aiState.api_key_dirty === true ? raw : '';",
        "api_key: status.has_api_key && aiState.api_key_dirty !== true ? '' : resolveAiGeneratorApiKey(aiState)",
        "api_key_dirty: true,",
        "api_key_dirty: false,",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing AI Generator stored-key protection snippets: " + "; ".join(missing)


def test_index_ai_generator_state_strips_api_key_from_persisted_storage() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const AI_PROVIDER_SECRET_CACHE = window.CORETG_AI_PROVIDER_SECRET_CACHE || {};",
        "sanitized.api_key = '';",
        "sanitized.api_key_dirty = false;",
        "has_stored_api_key: false,",
        "api_key_status_loaded: false,",
        "localMap[key] = sanitizedState;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing AI Generator secure API-key persistence snippets in index template: " + "; ".join(missing)


def test_index_bootstrap_tracks_ai_generator_warning_state() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "skip_bridge: false,",
        "api_key_dirty: false,",
        "merged.skip_bridge = merged.skip_bridge === true;",
        "merged.api_key_dirty = merged.api_key_dirty === true;",
        "next.skip_bridge = next.skip_bridge === true;",
        "next.api_key_dirty = next.api_key_dirty === true;",
        "last_generation_error: '',",
        "last_generation_warning: '',",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing AI Generator warning bootstrap state snippets in index template: " + "; ".join(missing)


def test_index_stream_modal_exposes_activity_auto_follow_toggle() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'aiGeneratorStreamAutoFollowInput',
        'Auto-follow',
        'ai-generator-stream-panel-toggle',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing AI Generator activity auto-follow toggle snippets in index template: " + "; ".join(missing)


def test_ai_generator_stream_defaults_activity_auto_follow_on() -> None:
    text = AI_STREAM_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'autoFollowEvents: true,',
        'function syncAutoFollowToggle() {',
        'function scheduleActivityAutoFollow() {',
        'function scrollActivityToBottom() {',
        "modalEl.addEventListener('shown.bs.modal', () => {",
        "const autoFollowInput = document.getElementById('aiGeneratorStreamAutoFollowInput');",
        'if (streamState.autoFollowEvents) {',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing AI Generator activity auto-follow stream snippets: " + "; ".join(missing)


def test_ai_generator_stream_prompts_for_cancel_during_long_waits() -> None:
    text = AI_STREAM_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'const AI_GENERATOR_CANCEL_PROMPT_CHECKPOINTS_MS = [90000, 180000, 240000, 360000];',
        'function scheduleNextLongWaitPrompt() {',
        'async function promptForLongWaitCancel(checkpointMs) {',
        "cancelLabel: 'Keep Waiting'",
        "Cancellation requested after waiting ${seconds}s.",
        'function startLongWaitPrompts() {',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing AI Generator long-wait cancel prompt snippets: " + "; ".join(missing)


def test_ai_generator_workflow_requests_extended_timeout_and_starts_long_wait_prompts() -> None:
    text = (Path(__file__).resolve().parent.parent / "webapp" / "static" / "ai_generator_workflow.js").read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'timeout_seconds: 480,',
        "if (typeof streamApi.startLongWaitPrompts === 'function') {",
        'streamApi.startLongWaitPrompts();',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing AI Generator workflow long-wait prompt snippets: " + "; ".join(missing)



def test_index_bootstrap_caches_ai_provider_catalog_for_panel() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function getDefaultAiProviderCatalog() {",
        "let aiProviderCatalogState = getDefaultAiProviderCatalog();",
        "async function refreshAiProviderCatalog(options = {}) {",
        "const resp = await fetch('/api/ai/providers'",
        "getAiProviderCatalog,",
        "refreshAiProviderCatalog,",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing AI provider catalog bootstrap snippets in index template: " + "; ".join(missing)


def test_index_bridge_payload_only_sends_enabled_tools_after_discovery() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const hasDiscoveredTools = Array.isArray(aiState && aiState.available_tools) && aiState.available_tools.length > 0;",
        "if (hasDiscoveredTools) {",
        "payload.enabled_tools = Array.isArray(aiState.enabled_tools) ? aiState.enabled_tools : [];",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing bridge payload gating snippets in index template: " + "; ".join(missing)


def test_ai_generator_client_normalizes_legacy_ollmcp_bridge_mode() -> None:
    index_text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    workflow_text = (Path(__file__).resolve().parent.parent / "webapp" / "static" / "ai_generator_workflow.js").read_text(encoding="utf-8", errors="ignore")

    index_expected = [
        "function normalizeAiBridgeMode(rawValue) {",
        "text === 'ollmcp'",
        "merged.bridge_mode = normalizeAiBridgeMode(merged.bridge_mode || defaults.bridge_mode);",
        "bridge_mode: normalizeAiBridgeMode(aiState.bridge_mode || 'mcp-python-sdk')",
    ]
    workflow_expected = [
        "function normalizeBridgeMode(value) {",
        "text === 'ollmcp'",
        "bridge_mode: normalizeBridgeMode(aiState.bridge_mode || 'mcp-python-sdk')",
    ]

    index_missing = [snippet for snippet in index_expected if snippet not in index_text]
    workflow_missing = [snippet for snippet in workflow_expected if snippet not in workflow_text]
    assert not index_missing, "Missing legacy bridge_mode normalization snippets in index template: " + "; ".join(index_missing)
    assert not workflow_missing, "Missing legacy bridge_mode normalization snippets in AI Generator workflow: " + "; ".join(workflow_missing)


def test_ai_generator_workflow_sends_skip_bridge_when_bridge_bypass_enabled() -> None:
    workflow_text = (Path(__file__).resolve().parent.parent / "webapp" / "static" / "ai_generator_workflow.js").read_text(encoding="utf-8", errors="ignore")
    assert "skip_bridge: aiState.skip_bridge === true," in workflow_text
