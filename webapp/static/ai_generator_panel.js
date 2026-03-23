(function (window) {
    function createCoretgAiGeneratorPanel(deps) {
        const PROVIDER_META_FALLBACK = {
            ollama: {
                label: 'Ollama',
                baseUrlLabel: 'Ollama Host URL',
                baseUrlPlaceholder: 'http://127.0.0.1:11434',
                defaultBaseUrl: 'http://127.0.0.1:11434',
                supportsBridge: true,
                connectionSuccessLabel: 'MCP Connected',
                reachabilityLabel: 'Provider Reachable',
            },
            litellm: {
                label: 'OpenAI-Compatible',
                baseUrlLabel: 'OpenAI-Compatible Base URL',
                baseUrlPlaceholder: 'https://localhost:4000/v1',
                defaultBaseUrl: 'https://localhost:4000/v1',
                supportsBridge: true,
                connectionSuccessLabel: 'Connected',
                reachabilityLabel: 'Provider Reachable',
            },
        };

        function escapeHtml(value) {
            return (value ?? '').toString()
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        function getProviderCatalog() {
            if (deps && typeof deps.getAiProviderCatalog === 'function') {
                return deps.getAiProviderCatalog();
            }
            return { providers: [] };
        }

        function getProviderEntries() {
            const catalog = getProviderCatalog();
            const providers = Array.isArray(catalog && catalog.providers) ? catalog.providers : [];
            if (providers.length) return providers;
            return [
                {
                    provider: 'ollama',
                    label: 'Ollama',
                    enabled: true,
                    default_base_url: 'http://127.0.0.1:11434',
                    supports_mcp_bridge: true,
                    requires_api_key: false,
                },
                {
                    provider: 'litellm',
                    label: 'OpenAI-Compatible',
                    enabled: true,
                    default_base_url: 'https://localhost:4000/v1',
                    supports_mcp_bridge: true,
                    requires_api_key: false,
                },
            ];
        }

        function resolveProviderMeta(provider, providerEntries) {
            const key = String(provider || 'ollama').trim().toLowerCase();
            const fallback = PROVIDER_META_FALLBACK[key] || {
                label: key || 'Provider',
                baseUrlLabel: 'Provider Base URL',
                baseUrlPlaceholder: '',
                defaultBaseUrl: '',
                supportsBridge: false,
                connectionSuccessLabel: 'Connected',
                reachabilityLabel: 'Provider Reachable',
            };
            const catalogEntry = Array.isArray(providerEntries)
                ? providerEntries.find((entry) => String(entry && entry.provider || '').trim().toLowerCase() === key)
                : null;
            return {
                ...fallback,
                label: String(catalogEntry && catalogEntry.label || fallback.label),
                defaultBaseUrl: String(catalogEntry && catalogEntry.default_base_url || fallback.defaultBaseUrl),
                supportsBridge: catalogEntry && Object.prototype.hasOwnProperty.call(catalogEntry, 'supports_mcp_bridge')
                    ? !!catalogEntry.supports_mcp_bridge
                    : fallback.supportsBridge,
                requiresApiKey: catalogEntry && Object.prototype.hasOwnProperty.call(catalogEntry, 'requires_api_key')
                    ? !!catalogEntry.requires_api_key
                    : false,
                enabled: catalogEntry && Object.prototype.hasOwnProperty.call(catalogEntry, 'enabled')
                    ? !!catalogEntry.enabled
                    : true,
            };
        }

        function formatGenerationSummary(summary) {
            if (!summary || typeof summary !== 'object') return '';
            const parts = [
                `Preview ready: routers=${Number(summary.routers) || 0}`,
                `hosts=${Number(summary.hosts) || 0}`,
                `switches=${Number(summary.switches) || 0}`,
            ];
            const sectionCounts = (summary.section_item_counts && typeof summary.section_item_counts === 'object')
                ? summary.section_item_counts
                : null;
            if (sectionCounts) {
                const sectionParts = [
                    ['node info', sectionCounts.node_information],
                    ['routing', sectionCounts.routing],
                    ['services', sectionCounts.services],
                    ['traffic', sectionCounts.traffic],
                    ['vulnerabilities', sectionCounts.vulnerabilities],
                    ['segmentation', sectionCounts.segmentation],
                ].map(([label, value]) => `${label}=${Number(value) || 0}`);
                parts.push(`sections: ${sectionParts.join(', ')}`);
            }
            if (summary.seed) {
                parts.push(`seed=${summary.seed}`);
            }
            return parts.join(', ');
        }

        async function fetchStoredApiKeyStatus(provider) {
            const resp = await fetch('/api/ai/provider/credential/status', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({ provider }),
            });
            let data = null;
            try { data = await resp.json(); } catch (err) { data = null; }
            if (!resp.ok || !data || data.success === false) {
                throw new Error((data && (data.error || data.message)) || `Credential status failed (HTTP ${resp.status})`);
            }
            return data;
        }

        async function saveStoredApiKey(provider, apiKey) {
            const resp = await fetch('/api/ai/provider/credential/save', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({ provider, api_key: apiKey }),
            });
            let data = null;
            try { data = await resp.json(); } catch (err) { data = null; }
            if (!resp.ok || !data || data.success === false) {
                throw new Error((data && (data.error || data.message)) || `Secure API key save failed (HTTP ${resp.status})`);
            }
            return data;
        }

        async function clearStoredApiKey(provider) {
            const resp = await fetch('/api/ai/provider/credential/clear', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({ provider }),
            });
            let data = null;
            try { data = await resp.json(); } catch (err) { data = null; }
            if (!resp.ok || !data || data.success === false) {
                throw new Error((data && (data.error || data.message)) || `Secure API key clear failed (HTTP ${resp.status})`);
            }
            return data;
        }

        function renderAiGeneratorPanel() {
            const root = document.getElementById('aiGeneratorRoot');
            if (!root) return;
            if ((deps.getScenariosActiveTab && deps.getScenariosActiveTab()) !== 'ai-generator') {
                root.innerHTML = '';
                root.classList.add('d-none');
                return;
            }
            root.classList.remove('d-none');
            const providerCatalog = getProviderCatalog();
            if (
                (!providerCatalog || (providerCatalog.loaded !== true && providerCatalog.loading !== true && providerCatalog.attempted !== true))
                && deps && typeof deps.refreshAiProviderCatalog === 'function'
            ) {
                deps.refreshAiProviderCatalog().then(() => {
                    try {
                        if ((deps.getScenariosActiveTab && deps.getScenariosActiveTab()) === 'ai-generator') {
                            renderAiGeneratorPanel();
                        }
                    } catch (err) { }
                }).catch(() => { });
            }
            const { idx, scenario } = deps.getActiveScenarioContext();
            if (idx === null || !scenario) {
                root.innerHTML = '<div class="ai-generator-shell"><div class="card border-0 shadow-sm"><div class="card-body"><div class="fw-semibold mb-1">AI Generator</div><div class="text-muted small">Create or import a scenario before configuring an AI provider.</div></div></div></div>';
                return;
            }

            const aiState = deps.ensureAiGeneratorStateForScenario(scenario, idx);
            const providerEntries = getProviderEntries();
            const validation = aiState.validation || {};
            const models = Array.isArray(validation.models) ? validation.models : [];
            const availableTools = Array.isArray(aiState.available_tools) ? aiState.available_tools : [];
            const enabledTools = new Set(Array.isArray(aiState.enabled_tools) ? aiState.enabled_tools : []);
            const hilEnabled = !!aiState.hil_enabled;
            const isCheckingValidation = !!validation.in_progress;
            const isValidated = !!validation.ok;
            const hasOllamaConnection = !!validation.ollama_ok;
            const hasBridgeConnection = !!validation.bridge_ok;
            const modelFound = validation.model_found !== false;
            const generationSummary = (aiState.last_generation_summary && typeof aiState.last_generation_summary === 'object') ? aiState.last_generation_summary : null;
            const generationError = (aiState.last_generation_error || '').toString().trim();
            const generationWarning = (aiState.last_generation_warning || '').toString().trim();
            const promptCoverageMismatch = (aiState.prompt_coverage_mismatch && typeof aiState.prompt_coverage_mismatch === 'object') ? aiState.prompt_coverage_mismatch : null;
            const promptCoverageReasons = promptCoverageMismatch && Array.isArray(promptCoverageMismatch.reasons)
                ? promptCoverageMismatch.reasons.filter(Boolean).map((item) => String(item))
                : [];
            const promptCoverageRetryUsed = !!aiState.prompt_coverage_retry_used;
            const checkedAt = validation.checked_at ? (() => {
                try { return new Date(validation.checked_at).toLocaleString(); } catch (err) { return validation.checked_at; }
            })() : '';
            const provider = (aiState.provider || 'ollama').toString();
            const providerMeta = resolveProviderMeta(provider, providerEntries);
            const supportsBridge = !!providerMeta.supportsBridge;
            const useBridge = supportsBridge && aiState.skip_bridge !== true;
            const providerLabel = providerMeta.label;
            const usesSecureApiKeyStorage = provider === 'litellm';
            const hasStoredApiKey = !!aiState.has_stored_api_key;
            const apiKeyStoredAt = (aiState.api_key_stored_at || '').toString().trim();
            const apiKeyStatusLoaded = aiState.api_key_status_loaded === true && aiState.api_key_status_provider === provider;
            const apiKeyStatusLoading = usesSecureApiKeyStorage && aiState.api_key_status_loading === true && aiState.api_key_status_provider === provider;
            if (usesSecureApiKeyStorage && !apiKeyStatusLoaded && !apiKeyStatusLoading) {
                deps.persistAiGeneratorStateForScenario(scenario, idx, {
                    api_key_status_loading: true,
                    api_key_status_loaded: false,
                    api_key_status_provider: provider,
                });
                fetchStoredApiKeyStatus(provider).then((status) => {
                    deps.persistAiGeneratorStateForScenario(scenario, idx, {
                        has_stored_api_key: !!status.has_api_key,
                        api_key_secret_id: status.identifier || null,
                        api_key_stored_at: status.stored_at || null,
                        api_key_status_loaded: true,
                        api_key_status_loading: false,
                        api_key_status_provider: provider,
                    });
                    renderAiGeneratorPanel();
                }).catch((err) => {
                    deps.persistAiGeneratorStateForScenario(scenario, idx, {
                        has_stored_api_key: false,
                        api_key_secret_id: null,
                        api_key_stored_at: null,
                        api_key_status_loaded: true,
                        api_key_status_loading: false,
                        api_key_status_provider: provider,
                        validation: {
                            ...validation,
                            message: err && err.message ? String(err.message) : 'Failed to load secure API key status.',
                        },
                    });
                    renderAiGeneratorPanel();
                });
            }
            const connectionActionLabel = isCheckingValidation ? 'Connecting...' : (isValidated ? 'Refresh Connection' : 'Connect');
            const connectionStatus = (() => {
                if (isCheckingValidation) {
                    return {
                        badgeClass: 'text-bg-info',
                        badgeLabel: 'Checking',
                        summary: 'Connection check in progress',
                    };
                }
                if (isValidated || hasBridgeConnection) {
                    return {
                        badgeClass: 'text-bg-success',
                        badgeLabel: useBridge ? providerMeta.connectionSuccessLabel : 'Connected',
                        summary: useBridge
                            ? `${providerLabel} reachable and MCP tools ready`
                            : `${providerLabel} reachable and ready for direct generation`,
                    };
                }
                if (hasOllamaConnection && !modelFound) {
                    return {
                        badgeClass: 'text-bg-warning',
                        badgeLabel: 'Model Missing',
                        summary: `${providerLabel} reachable, but the selected model was not found`,
                    };
                }
                if (hasOllamaConnection) {
                    return {
                        badgeClass: 'text-bg-primary',
                        badgeLabel: providerMeta.reachabilityLabel,
                        summary: useBridge
                            ? `${providerLabel} reachable, MCP tools not validated yet`
                            : `${providerLabel} reachable`,
                    };
                }
                if (validation.message) {
                    return {
                        badgeClass: 'text-bg-danger',
                        badgeLabel: 'Failed',
                        summary: 'Last connection check failed',
                    };
                }
                return {
                    badgeClass: 'text-bg-secondary',
                    badgeLabel: 'Not Connected',
                    summary: 'Connection not validated yet',
                };
            })();
            const validationMessageClass = (() => {
                if (isCheckingValidation) return 'text-info';
                if (isValidated) return 'text-success';
                if (hasOllamaConnection && !modelFound) return 'text-warning';
                if (hasOllamaConnection) return 'text-primary';
                if (validation.message) return 'text-danger';
                return 'text-muted';
            })();
            const modelOptions = (() => {
                const names = [];
                models.forEach(name => {
                    const text = (name || '').toString().trim();
                    if (text && !names.includes(text)) names.push(text);
                });
                const currentModel = (aiState.model || '').toString().trim();
                if (currentModel && !names.includes(currentModel)) names.unshift(currentModel);
                if (!names.length) names.push('');
                return names.map(name => {
                    const selected = name === currentModel ? 'selected' : '';
                    const label = name || 'Select a model after validation';
                    const disabled = name ? '' : 'disabled';
                    return `<option value="${escapeHtml(name)}" ${selected} ${disabled}>${escapeHtml(label)}</option>`;
                }).join('');
            })();
            const toolMarkup = availableTools.length
                ? availableTools.map(tool => {
                    const name = (tool && tool.name) ? String(tool.name) : '';
                    const description = (tool && tool.description) ? String(tool.description) : '';
                    const serverName = (tool && tool.server_name) ? String(tool.server_name) : 'server';
                    const toolName = (tool && tool.tool_name) ? String(tool.tool_name) : name;
                    const checked = enabledTools.has(name) ? 'checked' : '';
                    return `<label class="ai-generator-tool-option" title="${escapeHtml(name)}">
                    <input class="form-check-input" type="checkbox" data-ai-generator-tool="${escapeHtml(name)}" ${checked} ${isValidated ? '' : 'disabled'}>
                    <span class="ai-generator-tool-meta">
                        <span class="ai-generator-tool-header">
                            <span class="ai-generator-tool-name">${escapeHtml(toolName)}</span>
                            <span class="ai-generator-tool-server">${escapeHtml(serverName)}</span>
                        </span>
                        <span class="ai-generator-tool-description">${escapeHtml(description || 'No description available.')}</span>
                        <span class="ai-generator-tool-identity">${escapeHtml(name)}</span>
                    </span>
                </label>`;
                }).join('')
                : `<div class="text-muted small">${useBridge ? 'Validate the bridge to discover MCP tools exposed through the MCP Python SDK bridge.' : 'Bridge tooling is currently bypassed for direct generation diagnostics.'}</div>`;

            const bestEffortUsed = !!aiState.last_best_effort_used;
            const bestEffortReason = String(aiState.last_best_effort_reason || '').trim();

            const providerOptions = providerEntries.map((entry) => {
                const key = String(entry && entry.provider || '').trim().toLowerCase();
                if (!key) return '';
                const label = String(entry && entry.label || key);
                const enabled = !!(entry && entry.enabled);
                const selected = provider === key ? 'selected' : '';
                const disabled = enabled ? '' : 'disabled';
                const suffix = enabled ? '' : ' (coming soon)';
                return `<option value="${escapeHtml(key)}" ${selected} ${disabled}>${escapeHtml(label + suffix)}</option>`;
            }).join('');

            const bridgeMarkup = supportsBridge
                ? `
                                <div class="form-check form-switch mb-3">
                                    <input class="form-check-input" type="checkbox" role="switch" id="aiGeneratorUseBridgeInput" ${useBridge ? 'checked' : ''}>
                                    <label class="form-check-label" for="aiGeneratorUseBridgeInput">Use MCP Bridge</label>
                                    <div class="form-text">Leave this on for normal tool-assisted generation. Turn it off to bypass the MCP bridge and test direct ${escapeHtml(providerLabel)} generation.</div>
                                </div>
                                <details class="mb-3">
                                    <summary class="fw-semibold mb-2">Advanced MCP Bridge</summary>
                                    <div class="pt-3">
                                        <div class="mb-3">
                                            <label class="form-label">MCP Server Script</label>
                                            <input type="text" class="form-control" id="aiGeneratorMcpServerPathInput" value="${escapeHtml(aiState.mcp_server_path || 'MCP/server.py')}" placeholder="MCP/server.py">
                                            <div class="form-text">Repo-local default for stdio MCP mode. When this is set, it is used ahead of the URL and servers.json values.</div>
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">MCP Server URL</label>
                                            <input type="text" class="form-control" id="aiGeneratorMcpServerUrlInput" value="${escapeHtml(aiState.mcp_server_url || '')}" placeholder="http://localhost:8000/mcp">
                                            <div class="form-text">Auto-filled as a streamable HTTP template. The repo currently uses the local script by default.</div>
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">servers.json Path</label>
                                            <input type="text" class="form-control" id="aiGeneratorServersJsonInput" value="${escapeHtml(aiState.servers_json_path || 'MCP/mcp-bridge-servers.json')}" placeholder="/path/to/servers.json">
                                            <div class="form-text">Auto-filled with a repo-local MCP server config file you can use if you prefer config-file based server wiring.</div>
                                        </div>
                                        <div class="form-check form-switch mb-3">
                                            <input class="form-check-input" type="checkbox" role="switch" id="aiGeneratorAutoDiscoveryInput" ${aiState.auto_discovery ? 'checked' : ''}>
                                            <label class="form-check-label" for="aiGeneratorAutoDiscoveryInput">Enable MCP server auto-discovery</label>
                                        </div>
                                        <div class="form-check form-switch mb-0">
                                            <input class="form-check-input" type="checkbox" role="switch" id="aiGeneratorHilEnabledInput" ${hilEnabled ? 'checked' : ''}>
                                            <label class="form-check-label" for="aiGeneratorHilEnabledInput">Require tool confirmation (supervised mode)</label>
                                            <div class="form-text">Off by default for web requests. Turn this on only when an operator can confirm tool calls in the backend process terminal.</div>
                                        </div>
                                    </div>
                                </details>`
                : `
                                <div class="alert alert-light border small mb-3">
                                    This provider does not currently expose MCP bridge controls in this page.
                                </div>`;

            const directProviderFields = provider === 'litellm'
                ? `
                                <div class="mb-3">
                                    <label class="form-label">API Key <span class="text-muted">(optional)</span></label>
                                    <input type="password" class="form-control" id="aiGeneratorApiKeyInput" value="${escapeHtml(aiState.api_key || '')}" placeholder="${hasStoredApiKey ? 'Stored securely. Enter a new key to replace it.' : 'sk-...'}" autocomplete="new-password" data-lpignore="true" data-1p-ignore="true" spellcheck="false">
                                    <div class="d-flex align-items-center gap-2 mt-2 flex-wrap">
                                        <button type="button" class="btn btn-outline-secondary btn-sm" id="aiGeneratorSaveApiKeyBtn">${hasStoredApiKey ? 'Update Key' : 'Save Key'}</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm ${hasStoredApiKey ? '' : 'd-none'}" id="aiGeneratorClearApiKeyBtn">Clear Stored Key</button>
                                        <span class="small ${hasStoredApiKey ? 'text-success' : 'text-muted'}" id="aiGeneratorApiKeyStatus">${apiKeyStatusLoading ? 'Checking secure key status...' : (hasStoredApiKey ? `API key stored securely${apiKeyStoredAt ? ` • ${escapeHtml(apiKeyStoredAt)}` : ''}` : 'No API key stored securely yet.')}</span>
                                    </div>
                                    <div class="form-text">Stored securely on the server for your account. Leave the field blank to keep the current saved key. The base URL is not stored securely.</div>
                                </div>
                                <div class="form-check form-switch mb-3">
                                    <input class="form-check-input" type="checkbox" role="switch" id="aiGeneratorEnforceSslInput" ${aiState.enforce_ssl === false ? '' : 'checked'}>
                                    <label class="form-check-label" for="aiGeneratorEnforceSslInput">Enforce SSL</label>
                                    <div class="form-text">Enabled by default. When on, the OpenAI-compatible base URL must use <strong>https</strong> and certificates are verified. Turn it off to allow self-signed certificates or plain <strong>http</strong> endpoints.</div>
                                </div>`
                : '';

            root.innerHTML = `
            <div class="ai-generator-shell">
                <div class="d-flex justify-content-between align-items-start flex-wrap gap-3 mb-3">
                    <div>
                        <div class="text-uppercase small text-muted">AI Scenario Authoring</div>
                        <h4 class="mb-1">AI Generator for ${escapeHtml(scenario.name || `Scenario ${idx + 1}`)}</h4>
                        <div class="text-muted small">${useBridge ? `Connect ${escapeHtml(providerLabel)} to the repo MCP server through the MCP Python SDK bridge, choose the allowed tools, then let the model operate the draft through backend-safe tool calls.` : `Connect ${escapeHtml(providerLabel)}, validate the model endpoint, then generate a scenario draft directly through the provider.`}</div>
                    </div>
                    <div class="d-inline-flex align-items-center gap-2 small text-muted">
                        <span class="badge ${connectionStatus.badgeClass}">${escapeHtml(connectionStatus.badgeLabel)}</span>
                        <span>${escapeHtml(connectionStatus.summary)}</span>
                    </div>
                </div>
                <div class="row g-3">
                    <div class="col-12 col-xl-5">
                        <div class="card border-0 shadow-sm h-100">
                            <div class="card-header bg-white border-0 pb-0 d-flex justify-content-between align-items-center gap-2 flex-wrap"><strong>Provider Config</strong><span class="badge ${connectionStatus.badgeClass}">${escapeHtml(connectionStatus.badgeLabel)}</span></div>
                            <div class="card-body">
                                <div class="mb-3">
                                    <label class="form-label">Provider</label>
                                    <select class="form-select" id="aiGeneratorProviderSelect">${providerOptions}</select>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">${escapeHtml(providerMeta.baseUrlLabel)}</label>
                                    <input type="url" class="form-control" id="aiGeneratorBaseUrlInput" value="${escapeHtml(aiState.base_url || '')}" placeholder="${escapeHtml(providerMeta.baseUrlPlaceholder)}" autocomplete="url" autocapitalize="off" autocorrect="off" spellcheck="false" inputmode="url">
                                </div>
                                ${directProviderFields}
                                <div class="mb-3">
                                    <label class="form-label">LLM Model</label>
                                    <div class="d-flex align-items-center gap-2 flex-wrap mb-2">
                                        <button type="button" class="btn btn-outline-secondary btn-sm" id="aiGeneratorFetchModelsBtn" ${isCheckingValidation ? 'disabled' : ''}>Fetch Models</button>
                                        <div class="small text-muted">${useBridge ? `Connect fetches models from ${escapeHtml(providerLabel)} and then validates MCP bridge discovery. Use Fetch Models when you only want the available LLM list first.` : `Connect fetches models from ${escapeHtml(providerLabel)} using the configured base URL and optional API key. Use Fetch Models when you only want the available LLM list first.`}</div>
                                    </div>
                                    <select class="form-select" id="aiGeneratorModelSelect">${modelOptions}</select>
                                </div>
                                ${useBridge ? bridgeMarkup : ''}
                                <div class="d-flex gap-2 align-items-center">
                                    <button type="button" class="btn btn-primary" id="aiGeneratorValidateBtn" ${isCheckingValidation ? 'disabled' : ''}>${escapeHtml(connectionActionLabel)}</button>
                                    <div class="small text-muted">${useBridge ? `Connect validates ${escapeHtml(providerLabel)} reachability, available LLMs, and MCP tool discovery through the MCP Python SDK bridge.` : `Connect validates ${escapeHtml(providerLabel)} reachability, available LLMs, and the current SSL/API-key settings.`}</div>
                                </div>
                                <div class="mt-3 small ${validationMessageClass}" id="aiGeneratorValidationMessage">${escapeHtml(validation.message || 'No validation has been run yet.')}${checkedAt ? ` • ${escapeHtml(checkedAt)}` : ''}</div>
                            </div>
                        </div>
                    </div>
                    <div class="col-12 col-xl-7">
                        <div class="d-flex flex-column gap-3 h-100">
                            <div class="card border-0 shadow-sm ${isValidated ? '' : 'border border-warning-subtle'} ${useBridge ? '' : 'd-none'}">
                                <div class="card-header bg-white border-0 pb-0 d-flex justify-content-between align-items-center">
                                    <strong>Enabled MCP Tools</strong>
                                    <span class="badge text-bg-light border">${availableTools.length} discovered</span>
                                </div>
                                <div class="card-body">
                                    <div class="mb-3 text-muted small">Choose which MCP tools the model can use. The backend will run the MCP Python SDK bridge against the selected ${escapeHtml(providerLabel)} model and only the enabled tools.</div>
                                    <div class="ai-generator-tools-scroll">
                                        <div id="aiGeneratorToolsWrap" class="ai-generator-tools-grid">${toolMarkup}</div>
                                    </div>
                                </div>
                            </div>
                            <div class="card border-0 shadow-sm flex-fill ${isValidated ? '' : 'border border-warning-subtle'}">
                                <div class="card-header bg-white border-0 pb-0 d-flex justify-content-between align-items-center">
                                    <strong>Prompt + Generate</strong>
                                    <span class="badge ${isValidated ? 'text-bg-success' : 'text-bg-secondary'}">${isValidated ? 'Unlocked' : 'Locked until validation'}</span>
                                </div>
                                <div class="card-body">
                                    <div class="mb-3">
                                        <label class="form-label">Prompt / Command Intent</label>
                                        <textarea class="form-control" id="aiGeneratorPromptInput" rows="6" placeholder="Describe the topology, services, vulnerabilities, and flag-sequencing goals you want generated." ${isValidated ? '' : 'disabled'}>${escapeHtml(aiState.draft_prompt || '')}</textarea>
                                    </div>
                                    <div class="d-flex gap-2 flex-wrap align-items-center mb-3">
                                        <button type="button" class="btn btn-success" id="aiGeneratorGenerateBtn" ${isValidated ? '' : 'disabled'}>Construct Scenario Elements</button>
                                        <button type="button" class="btn btn-outline-secondary" id="aiGeneratorBuildPacketBtn" ${isValidated ? '' : 'disabled'}>Refresh Prompt / Command</button>
                                        <div class="small text-muted">${useBridge ? 'Runs the MCP Python SDK bridge with the selected LLM and enabled tools, then returns the updated draft and preview.' : `Runs direct ${escapeHtml(providerLabel)} generation, then previews the resulting draft through the existing backend planner.`}</div>
                                    </div>
                                    <div class="mb-3 ${generationError ? '' : 'd-none'}" id="aiGeneratorGenerationErrorWrap">
                                        <div class="alert alert-danger mb-0 small" id="aiGeneratorGenerationError">${escapeHtml(generationError)}</div>
                                    </div>
                                    <div class="mb-3 ${generationWarning ? '' : 'd-none'}" id="aiGeneratorGenerationWarningWrap">
                                        <div class="alert alert-warning mb-0 small" id="aiGeneratorGenerationWarning">
                                            <div class="fw-semibold mb-1">Not enough validated/tested vulnerabilities are currently eligible for this request.</div>
                                            <div>${escapeHtml(generationWarning)}</div>
                                        </div>
                                    </div>
                                    <div class="mb-3 ${generationSummary ? '' : 'd-none'}" id="aiGeneratorGenerationSummaryWrap">
                                        <div class="alert alert-success mb-0 small" id="aiGeneratorGenerationSummary">${generationSummary ? escapeHtml(formatGenerationSummary(generationSummary)) : ''}</div>
                                    </div>
                                    <div class="mb-3 ${(promptCoverageMismatch || promptCoverageRetryUsed) ? '' : 'd-none'}" id="aiGeneratorCoverageWrap">
                                        <div class="alert ${promptCoverageMismatch ? 'alert-warning' : 'alert-info'} mb-0 small" id="aiGeneratorCoverageMessage">
                                            ${promptCoverageMismatch
                                                ? `<div class="fw-semibold mb-1">Some prompt requirements were still ignored.</div><ul class="mb-0">${promptCoverageReasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join('')}</ul>`
                                                : `${promptCoverageRetryUsed ? 'The backend auto-retried once because the first draft missed requested prompt items or values.' : ''}`}
                                        </div>
                                    </div>
                                    <div class="mb-3 ${bestEffortUsed ? '' : 'd-none'}" id="aiGeneratorBestEffortWrap">
                                        <div class="alert alert-info mb-0 small" id="aiGeneratorBestEffortMessage">${escapeHtml(bestEffortReason || 'A best-effort draft preview was returned after repeated tool-call formatting failures.')}</div>
                                    </div>
                                    <details class="mb-0">
                                        <summary class="small text-muted fw-semibold">Prompt packet preview</summary>
                                        <pre class="bg-light border rounded p-3 ai-generator-packet mt-2 mb-0" id="aiGeneratorPacketOutput">${escapeHtml(aiState.prompt_packet || 'Validate the provider to unlock prompt-packet generation.')}</pre>
                                    </details>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>`;

            const providerSelect = document.getElementById('aiGeneratorProviderSelect');
            const baseUrlInput = document.getElementById('aiGeneratorBaseUrlInput');
            const modelSelect = document.getElementById('aiGeneratorModelSelect');
            const useBridgeInput = document.getElementById('aiGeneratorUseBridgeInput');
            const mcpServerPathInput = document.getElementById('aiGeneratorMcpServerPathInput');
            const mcpServerUrlInput = document.getElementById('aiGeneratorMcpServerUrlInput');
            const serversJsonInput = document.getElementById('aiGeneratorServersJsonInput');
            const apiKeyInput = document.getElementById('aiGeneratorApiKeyInput');
            const saveApiKeyBtn = document.getElementById('aiGeneratorSaveApiKeyBtn');
            const clearApiKeyBtn = document.getElementById('aiGeneratorClearApiKeyBtn');
            const enforceSslInput = document.getElementById('aiGeneratorEnforceSslInput');
            const autoDiscoveryInput = document.getElementById('aiGeneratorAutoDiscoveryInput');
            const hilEnabledInput = document.getElementById('aiGeneratorHilEnabledInput');
            const autoHealPromptInput = document.getElementById('aiGeneratorAutoHealPromptInput');
            const autoHealLeniencyInput = document.getElementById('aiGeneratorAutoHealLeniencyInput');
            const promptInput = document.getElementById('aiGeneratorPromptInput');
            const validateBtn = document.getElementById('aiGeneratorValidateBtn');
            const fetchModelsBtn = document.getElementById('aiGeneratorFetchModelsBtn');
            const buildPacketBtn = document.getElementById('aiGeneratorBuildPacketBtn');
            const resetValidation = () => ({ ok: false, in_progress: false, ollama_ok: false, bridge_ok: false, checked_at: null, message: '', models: [], model_found: false, provider: providerSelect ? providerSelect.value : provider });

            if (providerSelect) {
                providerSelect.addEventListener('change', () => {
                    const nextProvider = providerSelect.value;
                    const nextMeta = resolveProviderMeta(nextProvider, providerEntries);
                    const currentMeta = resolveProviderMeta(provider, providerEntries);
                    const currentBaseUrl = String(aiState.base_url || '').trim();
                    const shouldResetBaseUrl = !currentBaseUrl || currentBaseUrl === currentMeta.defaultBaseUrl;
                    deps.persistAiGeneratorStateForScenario(scenario, idx, {
                        provider: nextProvider,
                        base_url: shouldResetBaseUrl ? nextMeta.defaultBaseUrl : currentBaseUrl,
                        enforce_ssl: nextProvider === 'litellm' ? true : aiState.enforce_ssl,
                        api_key_status_loaded: false,
                        api_key_status_loading: false,
                        api_key_status_provider: nextProvider,
                        validation: resetValidation(),
                    });
                    renderAiGeneratorPanel();
                });
            }
            if (baseUrlInput) {
                baseUrlInput.addEventListener('input', () => {
                    deps.persistAiGeneratorStateForScenario(scenario, idx, { base_url: baseUrlInput.value, validation: resetValidation() });
                });
                baseUrlInput.addEventListener('change', () => {
                    renderAiGeneratorPanel();
                });
            }
            if (apiKeyInput) {
                apiKeyInput.addEventListener('input', () => {
                    deps.persistAiGeneratorStateForScenario(scenario, idx, { api_key: apiKeyInput.value, validation: resetValidation() });
                });
                apiKeyInput.addEventListener('change', async () => {
                    const nextValue = String(apiKeyInput.value || '').trim();
                    if (!nextValue) return;
                    try {
                        const stored = await saveStoredApiKey(provider, nextValue);
                        deps.persistAiGeneratorStateForScenario(scenario, idx, {
                            api_key: '',
                            has_stored_api_key: true,
                            api_key_secret_id: stored.identifier || null,
                            api_key_stored_at: stored.stored_at || null,
                            api_key_status_loaded: true,
                            api_key_status_loading: false,
                            api_key_status_provider: provider,
                        });
                        if (typeof window.showToast === 'function') {
                            window.showToast('API key stored securely.', { force: true, title: 'AI Generator', autohide: true, delay: 2500 });
                        }
                        renderAiGeneratorPanel();
                    } catch (err) {
                        deps.persistAiGeneratorStateForScenario(scenario, idx, {
                            validation: {
                                ...validation,
                                message: err && err.message ? String(err.message) : 'Failed to store API key securely.',
                            },
                        });
                        renderAiGeneratorPanel();
                    }
                });
            }
            if (saveApiKeyBtn && apiKeyInput) {
                saveApiKeyBtn.addEventListener('click', async () => {
                    const nextValue = String(apiKeyInput.value || '').trim();
                    if (!nextValue) return;
                    saveApiKeyBtn.disabled = true;
                    try {
                        const stored = await saveStoredApiKey(provider, nextValue);
                        deps.persistAiGeneratorStateForScenario(scenario, idx, {
                            api_key: '',
                            has_stored_api_key: true,
                            api_key_secret_id: stored.identifier || null,
                            api_key_stored_at: stored.stored_at || null,
                            api_key_status_loaded: true,
                            api_key_status_loading: false,
                            api_key_status_provider: provider,
                        });
                        if (typeof window.showToast === 'function') {
                            window.showToast('API key stored securely.', { force: true, title: 'AI Generator', autohide: true, delay: 2500 });
                        }
                        renderAiGeneratorPanel();
                    } catch (err) {
                        deps.persistAiGeneratorStateForScenario(scenario, idx, {
                            validation: {
                                ...validation,
                                message: err && err.message ? String(err.message) : 'Failed to store API key securely.',
                            },
                        });
                        renderAiGeneratorPanel();
                    }
                });
            }
            if (clearApiKeyBtn) {
                clearApiKeyBtn.addEventListener('click', async () => {
                    clearApiKeyBtn.disabled = true;
                    try {
                        await clearStoredApiKey(provider);
                        deps.persistAiGeneratorStateForScenario(scenario, idx, {
                            api_key: '',
                            has_stored_api_key: false,
                            api_key_secret_id: null,
                            api_key_stored_at: null,
                            api_key_status_loaded: true,
                            api_key_status_loading: false,
                            api_key_status_provider: provider,
                        });
                        if (typeof window.showToast === 'function') {
                            window.showToast('Stored API key cleared.', { force: true, title: 'AI Generator', autohide: true, delay: 2500 });
                        }
                        renderAiGeneratorPanel();
                    } catch (err) {
                        deps.persistAiGeneratorStateForScenario(scenario, idx, {
                            validation: {
                                ...validation,
                                message: err && err.message ? String(err.message) : 'Failed to clear stored API key.',
                            },
                        });
                        renderAiGeneratorPanel();
                    }
                });
            }
            if (enforceSslInput) {
                enforceSslInput.addEventListener('change', () => {
                    deps.persistAiGeneratorStateForScenario(scenario, idx, { enforce_ssl: !!enforceSslInput.checked, validation: resetValidation() });
                    renderAiGeneratorPanel();
                });
            }
            if (modelSelect) {
                modelSelect.addEventListener('change', () => {
                    deps.persistAiGeneratorStateForScenario(scenario, idx, { model: modelSelect.value, validation: resetValidation() });
                    renderAiGeneratorPanel();
                });
            }
            if (useBridgeInput) {
                useBridgeInput.addEventListener('change', () => {
                    deps.persistAiGeneratorStateForScenario(scenario, idx, {
                        skip_bridge: !useBridgeInput.checked,
                        validation: resetValidation(),
                    });
                    renderAiGeneratorPanel();
                });
            }
            if (mcpServerPathInput) {
                mcpServerPathInput.addEventListener('input', () => {
                    deps.persistAiGeneratorStateForScenario(scenario, idx, { mcp_server_path: mcpServerPathInput.value, validation: resetValidation() });
                });
                mcpServerPathInput.addEventListener('change', () => {
                    renderAiGeneratorPanel();
                });
            }
            if (mcpServerUrlInput) {
                mcpServerUrlInput.addEventListener('input', () => {
                    deps.persistAiGeneratorStateForScenario(scenario, idx, { mcp_server_url: mcpServerUrlInput.value, validation: resetValidation() });
                });
                mcpServerUrlInput.addEventListener('change', () => {
                    renderAiGeneratorPanel();
                });
            }
            if (serversJsonInput) {
                serversJsonInput.addEventListener('input', () => {
                    deps.persistAiGeneratorStateForScenario(scenario, idx, { servers_json_path: serversJsonInput.value, validation: resetValidation() });
                });
                serversJsonInput.addEventListener('change', () => {
                    renderAiGeneratorPanel();
                });
            }
            if (autoDiscoveryInput) {
                autoDiscoveryInput.addEventListener('change', () => {
                    deps.persistAiGeneratorStateForScenario(scenario, idx, { auto_discovery: !!autoDiscoveryInput.checked, validation: resetValidation() });
                    renderAiGeneratorPanel();
                });
            }
            if (hilEnabledInput) {
                hilEnabledInput.addEventListener('change', () => {
                    deps.persistAiGeneratorStateForScenario(scenario, idx, { hil_enabled: !!hilEnabledInput.checked, validation: resetValidation() });
                    renderAiGeneratorPanel();
                });
            }
            if (autoHealPromptInput) {
                autoHealPromptInput.addEventListener('change', () => {
                    deps.persistAiGeneratorStateForScenario(scenario, idx, {
                        auto_heal_prompt: !!autoHealPromptInput.checked,
                        auto_heal_leniency: autoHealLeniency,
                    });
                    renderAiGeneratorPanel();
                });
            }
            if (autoHealLeniencyInput) {
                autoHealLeniencyInput.addEventListener('change', () => {
                    deps.persistAiGeneratorStateForScenario(scenario, idx, {
                        auto_heal_leniency: autoHealLeniencyInput.value,
                    });
                    renderAiGeneratorPanel();
                });
            }
            document.querySelectorAll('[data-ai-generator-tool]').forEach((checkbox) => {
                checkbox.addEventListener('change', () => {
                    const selected = Array.from(document.querySelectorAll('[data-ai-generator-tool]'))
                        .filter((entry) => entry.checked)
                        .map((entry) => entry.getAttribute('data-ai-generator-tool') || '')
                        .filter(Boolean);
                    deps.persistAiGeneratorStateForScenario(scenario, idx, { enabled_tools: selected });
                });
            });
            if (promptInput) {
                promptInput.addEventListener('input', () => {
                    deps.persistAiGeneratorStateForScenario(scenario, idx, { draft_prompt: promptInput.value });
                });
            }
            if (validateBtn) {
                validateBtn.addEventListener('click', () => {
                    deps.validateAiGeneratorConfig();
                });
            }
            if (fetchModelsBtn) {
                fetchModelsBtn.addEventListener('click', () => {
                    if (deps && typeof deps.fetchAiGeneratorModels === 'function') {
                        deps.fetchAiGeneratorModels();
                    }
                });
            }
            if (buildPacketBtn) {
                buildPacketBtn.addEventListener('click', () => {
                    const promptValue = promptInput ? promptInput.value : (aiState.draft_prompt || '');
                    const nextState = deps.persistAiGeneratorStateForScenario(scenario, idx, {
                        draft_prompt: promptValue,
                        prompt_packet: deps.buildAiGeneratorPromptPacket({ ...scenario, ai_generator: { ...aiState, draft_prompt: promptValue } }, idx),
                        last_packet_at: new Date().toISOString(),
                    });
                    const output = document.getElementById('aiGeneratorPacketOutput');
                    if (output) output.textContent = nextState.prompt_packet || '';
                });
            }
            const generateBtn = document.getElementById('aiGeneratorGenerateBtn');
            if (generateBtn) {
                generateBtn.addEventListener('click', () => {
                    deps.generateAiScenarioPreview();
                });
            }
        }

        return renderAiGeneratorPanel;
    }

    window.createCoretgAiGeneratorPanel = createCoretgAiGeneratorPanel;
})(window);