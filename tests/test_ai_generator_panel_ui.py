from pathlib import Path


AI_PANEL_PATH = Path(__file__).resolve().parent.parent / "webapp" / "static" / "ai_generator_panel.js"
INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


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
        'id="aiGeneratorEnforceSslInput"',
        "supportsBridge: true",
        'reachable and MCP tools ready',
        'When on, the OpenAI-compatible base URL must use <strong>https</strong>',
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


def test_ai_generator_workflow_blocks_bridge_generation_without_enabled_tools() -> None:
    text = (Path(__file__).resolve().parent.parent / "webapp" / "static" / "ai_generator_workflow.js").read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const hasDiscoveredTools = Array.isArray(nextAvailableTools) && nextAvailableTools.length > 0;",
        "bridge_ok: providerMeta.supportsBridge ? hasDiscoveredTools : false",
        "No MCP tools are enabled. Refresh Connection and enable at least one tool before generating.",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing AI Generator workflow safeguards for zero enabled MCP tools: " + "; ".join(missing)


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


def test_index_bootstrap_tracks_ai_generator_warning_state() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "last_generation_error: '',",
        "last_generation_warning: '',",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing AI Generator warning bootstrap state snippets in index template: " + "; ".join(missing)



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
