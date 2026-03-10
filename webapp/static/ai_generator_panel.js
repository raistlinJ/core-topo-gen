(function (window) {
    function createCoretgAiGeneratorPanel(deps) {
        function escapeHtml(value) {
            return (value ?? '').toString()
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
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
            const { idx, scenario } = deps.getActiveScenarioContext();
            if (idx === null || !scenario) {
                root.innerHTML = '<div class="ai-generator-shell"><div class="card border-0 shadow-sm"><div class="card-body"><div class="fw-semibold mb-1">AI Generator</div><div class="text-muted small">Create or import a scenario before configuring an AI provider.</div></div></div></div>';
                return;
            }

            const aiState = deps.ensureAiGeneratorStateForScenario(scenario, idx);
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
            const checkedAt = validation.checked_at ? (() => {
                try { return new Date(validation.checked_at).toLocaleString(); } catch (err) { return validation.checked_at; }
            })() : '';
            const provider = (aiState.provider || 'ollama').toString();
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
                        badgeLabel: 'MCP Connected',
                        summary: `${provider} reachable and ${aiState.bridge_mode || 'mcp-python-sdk'} validated`,
                    };
                }
                if (hasOllamaConnection && !modelFound) {
                    return {
                        badgeClass: 'text-bg-warning',
                        badgeLabel: 'Model Missing',
                        summary: `${provider} reachable, but the selected model was not found`,
                    };
                }
                if (hasOllamaConnection) {
                    return {
                        badgeClass: 'text-bg-primary',
                        badgeLabel: 'Ollama Reachable',
                        summary: `${provider} reachable, MCP bridge not validated`,
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
                : '<div class="text-muted small">Validate the bridge to discover MCP tools exposed through the MCP Python SDK bridge.</div>';

            root.innerHTML = `
            <div class="ai-generator-shell">
                <div class="d-flex justify-content-between align-items-start flex-wrap gap-3 mb-3">
                    <div>
                        <div class="text-uppercase small text-muted">AI Scenario Authoring</div>
                        <h4 class="mb-1">AI Generator for ${escapeHtml(scenario.name || `Scenario ${idx + 1}`)}</h4>
                        <div class="text-muted small">Connect Ollama to the repo MCP server through the MCP Python SDK bridge, choose the allowed tools, then let the model operate the draft through backend-safe tool calls.</div>
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
                                    <select class="form-select" id="aiGeneratorProviderSelect">
                                        <option value="ollama" ${provider === 'ollama' ? 'selected' : ''}>Ollama</option>
                                        <option value="openai" disabled>OpenAI (coming soon)</option>
                                        <option value="anthropic" disabled>Claude / Anthropic (coming soon)</option>
                                    </select>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Bridge</label>
                                    <input type="text" class="form-control" id="aiGeneratorBridgeModeInput" value="${escapeHtml(aiState.bridge_mode || 'mcp-python-sdk')}" disabled>
                                    <div class="form-text">This client bridge uses the <strong>official MCP Python SDK</strong> to connect Ollama to MCP tools.</div>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Ollama Host URL</label>
                                    <input type="text" class="form-control" id="aiGeneratorBaseUrlInput" value="${escapeHtml(aiState.base_url || '')}" placeholder="http://127.0.0.1:11434">
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">LLM Model</label>
                                    <div class="d-flex gap-2 align-items-center mb-2">
                                        <button type="button" class="btn btn-outline-secondary btn-sm" id="aiGeneratorFetchModelsBtn">Fetch Models</button>
                                        <div class="small text-muted">Refreshes models from Ollama only. Use Connect to validate MCP bridge discovery.</div>
                                    </div>
                                    <select class="form-select" id="aiGeneratorModelSelect">${modelOptions}</select>
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
                                </details>
                                <div class="d-flex gap-2 align-items-center">
                                    <button type="button" class="btn btn-primary" id="aiGeneratorValidateBtn" ${isCheckingValidation ? 'disabled' : ''}>${escapeHtml(connectionActionLabel)}</button>
                                    <div class="small text-muted">Connect validates Ollama reachability, available LLMs, and MCP tool discovery through the MCP Python SDK bridge.</div>
                                </div>
                                <div class="mt-3 small ${validationMessageClass}" id="aiGeneratorValidationMessage">${escapeHtml(validation.message || 'No validation has been run yet.')}${checkedAt ? ` • ${escapeHtml(checkedAt)}` : ''}</div>
                            </div>
                        </div>
                    </div>
                    <div class="col-12 col-xl-7">
                        <div class="d-flex flex-column gap-3 h-100">
                            <div class="card border-0 shadow-sm ${isValidated ? '' : 'border border-warning-subtle'}">
                                <div class="card-header bg-white border-0 pb-0 d-flex justify-content-between align-items-center">
                                    <strong>Enabled MCP Tools</strong>
                                    <span class="badge text-bg-light border">${availableTools.length} discovered</span>
                                </div>
                                <div class="card-body">
                                    <div class="mb-3 text-muted small">Choose which MCP tools the model can use. The backend will run the MCP Python SDK bridge against the selected Ollama model and only the enabled tools.</div>
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
                                        <div class="small text-muted">Runs the MCP Python SDK bridge with the selected LLM and enabled tools, then returns the updated draft and preview.</div>
                                    </div>
                                    <div class="mb-3 ${generationError ? '' : 'd-none'}" id="aiGeneratorGenerationErrorWrap">
                                        <div class="alert alert-danger mb-0 small" id="aiGeneratorGenerationError">${escapeHtml(generationError)}</div>
                                    </div>
                                    <div class="mb-3 ${generationSummary ? '' : 'd-none'}" id="aiGeneratorGenerationSummaryWrap">
                                        <div class="alert alert-success mb-0 small" id="aiGeneratorGenerationSummary">${generationSummary ? escapeHtml(`Preview ready: routers=${generationSummary.routers}, hosts=${generationSummary.hosts}, switches=${generationSummary.switches}${generationSummary.seed ? `, seed=${generationSummary.seed}` : ''}`) : ''}</div>
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
            const mcpServerPathInput = document.getElementById('aiGeneratorMcpServerPathInput');
            const mcpServerUrlInput = document.getElementById('aiGeneratorMcpServerUrlInput');
            const serversJsonInput = document.getElementById('aiGeneratorServersJsonInput');
            const autoDiscoveryInput = document.getElementById('aiGeneratorAutoDiscoveryInput');
            const hilEnabledInput = document.getElementById('aiGeneratorHilEnabledInput');
            const fetchModelsBtn = document.getElementById('aiGeneratorFetchModelsBtn');
            const promptInput = document.getElementById('aiGeneratorPromptInput');
            const validateBtn = document.getElementById('aiGeneratorValidateBtn');
            const buildPacketBtn = document.getElementById('aiGeneratorBuildPacketBtn');
            const resetValidation = () => ({ ok: false, in_progress: false, ollama_ok: false, bridge_ok: false, checked_at: null, message: '', models: [], model_found: false, provider: providerSelect ? providerSelect.value : provider });

            if (providerSelect) {
                providerSelect.addEventListener('change', () => {
                    deps.persistAiGeneratorStateForScenario(scenario, idx, { provider: providerSelect.value, validation: resetValidation() });
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
            if (modelSelect) {
                modelSelect.addEventListener('change', () => {
                    deps.persistAiGeneratorStateForScenario(scenario, idx, { model: modelSelect.value, validation: resetValidation() });
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
                    deps.fetchAiGeneratorModels();
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