(function (window) {
    function createCoretgAiGeneratorWorkflow(deps) {
        const streamApi = (deps && deps.streamApi) || {};

        function getProviderMeta(provider) {
            const key = String(provider || 'ollama').trim().toLowerCase();
            if (key === 'litellm') {
                return {
                    label: 'OpenAI-Compatible',
                    supportsBridge: true,
                };
            }
            return {
                label: 'Ollama',
                supportsBridge: true,
            };
        }

        function normalizeBridgeMode(value) {
            const text = String(value || '').trim().toLowerCase();
            if (!text || text === 'ollmcp' || text === 'mcp_python_sdk' || text === 'python-sdk' || text === 'mcp-sdk') {
                return 'mcp-python-sdk';
            }
            return text;
        }

        function extractCountIntent(promptValue) {
            const text = String(promptValue || '').toLowerCase();
            const totalNodesMatch = text.match(/\b(?:topology|scenario)\s+with\s+(\d+)\s+nodes?\b|\b(\d+)\s+total\s+nodes?\b|\b(\d+)\s+nodes?\b/);
            const routerMatch = text.match(/\b(\d+)\s+routers?\b/);
            const totalNodes = totalNodesMatch ? parseInt(totalNodesMatch[1] || totalNodesMatch[2] || totalNodesMatch[3] || '0', 10) : null;
            const routerCount = routerMatch ? parseInt(routerMatch[1] || '0', 10) : null;
            return {
                totalNodes: Number.isFinite(totalNodes) ? totalNodes : null,
                routerCount: Number.isFinite(routerCount) ? routerCount : null,
            };
        }

        function buildFinalOutputFallback(data, message = '', success = true, promptValue = '') {
            const providerResponse = (data && data.provider_response ? String(data.provider_response) : '').trim();
            if (providerResponse) return providerResponse;

            const preview = (data && data.preview && typeof data.preview === 'object') ? data.preview : {};
            const routers = Array.isArray(preview.routers) ? preview.routers.length : 0;
            const hosts = Array.isArray(preview.hosts) ? preview.hosts.length : 0;
            const switches = Array.isArray(preview.switches) ? preview.switches.length : 0;
            const countIntent = extractCountIntent(promptValue);
            const retryUsed = !!(data && data.count_intent_retry_used);
            const mismatch = (data && data.count_intent_mismatch && typeof data.count_intent_mismatch === 'object')
                ? data.count_intent_mismatch
                : null;
            const coverageRetryUsed = !!(data && data.prompt_coverage_retry_used);
            const coverageMismatch = (data && data.prompt_coverage_mismatch && typeof data.prompt_coverage_mismatch === 'object')
                ? data.prompt_coverage_mismatch
                : null;
            const bestEffortUsed = !!(data && data.best_effort_used);
            const bestEffortReason = (data && data.best_effort_reason ? String(data.best_effort_reason) : '').trim();
            const parts = [];
            if (success) {
                parts.push('No textual model summary was returned. The request completed through tool calls.');
                parts.push(`Preview summary: routers=${routers}, hosts=${hosts}, switches=${switches}.`);
                if (bestEffortUsed) {
                    parts.push(bestEffortReason || 'A best-effort draft preview was returned after repeated tool-call formatting failures.');
                }
                if (retryUsed) {
                    parts.push('An automatic retry was attempted because the first preview did not match the requested counts.');
                }
                if (coverageRetryUsed) {
                    parts.push('An automatic retry was attempted because the first draft omitted requested prompt items or values.');
                }
                if (countIntent.totalNodes !== null || countIntent.routerCount !== null) {
                    const requestedBits = [];
                    if (countIntent.totalNodes !== null) requestedBits.push(`requested total nodes=${countIntent.totalNodes}`);
                    if (countIntent.routerCount !== null) requestedBits.push(`requested routers=${countIntent.routerCount}`);
                    parts.push(`Requested counts: ${requestedBits.join(', ')}.`);
                }
                if (mismatch && Array.isArray(mismatch.reasons) && mismatch.reasons.length) {
                    parts.push(`Count mismatch remains: ${mismatch.reasons.join('; ')}.`);
                }
                if (coverageMismatch && Array.isArray(coverageMismatch.reasons) && coverageMismatch.reasons.length) {
                    parts.push(`Prompt coverage mismatch remains: ${coverageMismatch.reasons.join('; ')}.`);
                }
            } else {
                parts.push('No textual model output was returned before the request ended.');
            }
            if (message) {
                parts.push('');
                parts.push(message);
            }
            return parts.join('\n');
        }

        function ensureModalOutput(data, message = '', success = true, promptValue = '') {
            if (!streamApi || typeof streamApi.appendOutput !== 'function') return;
            const existingOutput = (typeof streamApi.getOutputText === 'function')
                ? streamApi.getOutputText()
                : String((streamApi.state && streamApi.state.outputText) || '');
            if (existingOutput.trim()) return;
            const fallbackText = buildFinalOutputFallback(data, message, success, promptValue);
            if (fallbackText.trim()) {
                streamApi.appendOutput(fallbackText);
            }
        }

        function renderPanel() {
            if (deps && typeof deps.renderAiGeneratorPanel === 'function') {
                deps.renderAiGeneratorPanel();
            }
        }

        function getState() {
            return deps && typeof deps.getState === 'function' ? deps.getState() : null;
        }

        function getPreviewState() {
            return deps && typeof deps.getPreviewState === 'function' ? deps.getPreviewState() : null;
        }

        function getScenarioSectionItemCounts(scenario) {
            const sections = (scenario && typeof scenario === 'object' && scenario.sections && typeof scenario.sections === 'object')
                ? scenario.sections
                : {};
            const readCount = (sectionName) => {
                const section = sections[sectionName];
                return Array.isArray(section && section.items) ? section.items.length : 0;
            };
            return {
                node_information: readCount('Node Information'),
                routing: readCount('Routing'),
                services: readCount('Services'),
                traffic: readCount('Traffic'),
                vulnerabilities: readCount('Vulnerabilities'),
                segmentation: readCount('Segmentation'),
            };
        }

        async function applyPreviewSuccess({ idx, scenario, aiState, promptValue, data }) {
            const state = getState();
            const previewState = getPreviewState();
            if (!state || !previewState) return;

            const generatedScenario = data.generated_scenario && typeof data.generated_scenario === 'object'
                ? data.generated_scenario
                : scenario;
            if (scenario && generatedScenario && typeof generatedScenario === 'object') {
                generatedScenario.name = scenario.name;
            }
            state.scenarios[idx] = generatedScenario;
            window.state = state;

            previewState.fullPreview = (data.preview && typeof data.preview === 'object') ? data.preview : null;
            previewState.dirty = true;
            try {
                state.scenarios[idx].plan_preview = {
                    full_preview: data.preview || null,
                    plan: data.plan || null,
                    breakdowns: data.breakdowns || null,
                    flow_meta: data.flow_meta || null,
                    saved_at: new Date().toISOString(),
                };
            } catch (e) { }

            const preview = data.preview && typeof data.preview === 'object' ? data.preview : {};
            const generationSummary = {
                routers: Array.isArray(preview.routers) ? preview.routers.length : 0,
                hosts: Array.isArray(preview.hosts) ? preview.hosts.length : 0,
                switches: Array.isArray(preview.switches) ? preview.switches.length : 0,
                section_item_counts: getScenarioSectionItemCounts(generatedScenario),
                seed: preview.seed || null,
                generated_at: data.checked_at || new Date().toISOString(),
            };
            deps.persistAiGeneratorStateForScenario(state.scenarios[idx], idx, {
                draft_prompt: promptValue,
                prompt_packet: data.prompt_used || aiState.prompt_packet,
                last_packet_at: new Date().toISOString(),
                draft_id: data.draft_id || aiState.draft_id || '',
                available_tools: Array.isArray(data.bridge_tools) ? data.bridge_tools : aiState.available_tools,
                enabled_tools: Array.isArray(data.enabled_tools) ? data.enabled_tools : aiState.enabled_tools,
                last_generation_summary: generationSummary,
                last_generation_error: '',
                last_generation_warning: '',
                prompt_coverage_mismatch: (data.prompt_coverage_mismatch && typeof data.prompt_coverage_mismatch === 'object') ? data.prompt_coverage_mismatch : null,
                prompt_coverage_retry_used: !!data.prompt_coverage_retry_used,
                last_best_effort_used: !!data.best_effort_used,
                last_best_effort_reason: String(data.best_effort_reason || ''),
            });

            try { deps.persistEditorState(); } catch (e) { }
            try {
                if (deps && typeof deps.persistEditorSnapshotToServerNow === 'function') {
                    await deps.persistEditorSnapshotToServerNow();
                }
            } catch (e) { }
            try { deps.updatePlanButtons(); } catch (e) { }
            deps.render();
        }

        function classifyGenerationWarning(message) {
            const text = String(message || '').trim();
            if (!text) return '';
            if (
                /validated\/tested\s+vulnerabilit(?:y|ies)/i.test(text)
                && /(required|eligible|validate more vulnerabilities|reduce the requested vulnerability count)/i.test(text)
            ) {
                return text;
            }
            return '';
        }

        function handlePreviewFailure({ idx, scenario, promptValue, message }) {
            const warningMessage = classifyGenerationWarning(message);
            deps.persistAiGeneratorStateForScenario(scenario, idx, {
                draft_prompt: promptValue,
                last_generation_error: warningMessage ? '' : message,
                last_generation_warning: warningMessage,
                prompt_coverage_mismatch: null,
                prompt_coverage_retry_used: false,
                last_best_effort_used: false,
                last_best_effort_reason: '',
            });
            renderPanel();
        }

        function buildPromptPacket(scenario, idx) {
            const aiState = deps.ensureAiGeneratorStateForScenario(scenario, idx);
            const providerMeta = getProviderMeta(aiState.provider);
            const scenarioName = (scenario && scenario.name) ? String(scenario.name).trim() : `Scenario ${idx + 1}`;
            const objective = (aiState.draft_prompt || '').toString().trim() || 'Describe the desired topology, services, vulnerabilities, and flag-sequencing goals.';
            return JSON.stringify({
                provider: aiState.provider,
                ...(providerMeta.supportsBridge ? { bridge_mode: normalizeBridgeMode(aiState.bridge_mode || 'mcp-python-sdk') } : {}),
                base_url: aiState.base_url,
                enforce_ssl: aiState.enforce_ssl === false ? false : true,
                model: aiState.model,
                ...(providerMeta.supportsBridge ? {
                    mcp_server_path: aiState.mcp_server_path || 'MCP/server.py',
                    mcp_server_url: aiState.mcp_server_url || '',
                    servers_json_path: aiState.servers_json_path || '',
                    auto_discovery: !!aiState.auto_discovery,
                    hil_enabled: !!aiState.hil_enabled,
                    auto_heal_prompt: aiState.auto_heal_prompt === false ? false : true,
                    auto_heal_leniency: ['low', 'medium', 'high'].includes(String(aiState.auto_heal_leniency || '').toLowerCase()) ? String(aiState.auto_heal_leniency || '').toLowerCase() : 'medium',
                    enabled_tools: Array.isArray(aiState.enabled_tools) ? aiState.enabled_tools : [],
                } : {}),
                scenario_name: scenarioName,
                goal: objective,
                expected_backend_flow: providerMeta.supportsBridge
                    ? [
                        'Connect Ollama to the repo MCP server through the MCP Python SDK bridge',
                        'Use enabled scenario authoring tools to mutate a draft',
                        'Preview the draft through the existing planner flow',
                        'POST /save_xml_api to persist XML once accepted',
                    ]
                    : [
                        `Validate direct ${providerMeta.label} access`,
                        'Generate backend-compatible scenario JSON',
                        'Preview the draft through the existing planner flow',
                        'POST /save_xml_api to persist XML once accepted',
                    ],
                prompt: providerMeta.supportsBridge
                    ? [
                        `You are authoring a valid CORE TopoGen scenario draft for "${scenarioName}" through MCP tools.`,
                        'Prefer tool calls over raw JSON generation.',
                        'Keep all section payloads backend-compatible and preview before finishing.',
                        `User objective: ${objective}`,
                    ].join('\n')
                    : [
                        `You are authoring a valid CORE TopoGen scenario draft for "${scenarioName}".`,
                        'Return backend-compatible JSON for the scenario structure.',
                        'Keep all section payloads backend-compatible and preview-safe.',
                        `User objective: ${objective}`,
                    ].join('\n'),
            }, null, 2);
        }

        async function validateConfig() {
            const { idx, scenario } = deps.getActiveScenarioContext();
            if (idx === null || !scenario) return;
            const aiState = deps.ensureAiGeneratorStateForScenario(scenario, idx);
            const providerMeta = getProviderMeta(aiState.provider);
            const validateBtn = document.getElementById('aiGeneratorValidateBtn');
            if (validateBtn) {
                validateBtn.disabled = true;
            }
            deps.persistAiGeneratorStateForScenario(scenario, idx, {
                validation: {
                    ok: false,
                    in_progress: true,
                    ollama_ok: false,
                    bridge_ok: false,
                    checked_at: new Date().toISOString(),
                    message: aiState.validation && aiState.validation.ok ? 'Refreshing connection...' : 'Connecting...',
                    provider: aiState.provider,
                },
            });
            renderPanel();
            try {
                const resp = await fetch('/api/ai/provider/validate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({
                        provider: aiState.provider,
                        base_url: aiState.base_url,
                        api_key: aiState.api_key || '',
                        enforce_ssl: aiState.enforce_ssl === false ? false : true,
                        model: aiState.model,
                        ...deps.buildAiGeneratorBridgePayload(aiState),
                    }),
                });
                let data = null;
                try { data = await resp.json(); } catch (err) { data = null; }
                if (!resp.ok || !data || data.success === false) {
                    const message = (data && (data.error || data.message)) ? (data.error || data.message) : `Validation failed (HTTP ${resp.status})`;
                    const nextAvailableTools = data && Array.isArray(data.tools)
                        ? data.tools
                        : (Array.isArray(aiState.available_tools) ? aiState.available_tools : []);
                    const nextEnabledTools = data && Array.isArray(data.enabled_tools)
                        ? data.enabled_tools
                        : (Array.isArray(aiState.enabled_tools) ? aiState.enabled_tools : []);
                    deps.persistAiGeneratorStateForScenario(scenario, idx, {
                        available_tools: nextAvailableTools,
                        enabled_tools: nextEnabledTools,
                        validation: {
                            ok: false,
                            in_progress: false,
                            ollama_ok: false,
                            bridge_ok: false,
                            checked_at: new Date().toISOString(),
                            message,
                            models: data && Array.isArray(data.models) ? data.models : [],
                            model_found: !!(data && data.model_found),
                            provider: aiState.provider,
                        },
                    });
                    renderPanel();
                    return;
                }
                const models = Array.isArray(data.models) ? data.models : [];
                const bridge = (data.bridge && typeof data.bridge === 'object') ? data.bridge : {};
                const nextAvailableTools = Array.isArray(data.tools)
                    ? data.tools
                    : (Array.isArray(bridge.tools)
                        ? bridge.tools
                        : (Array.isArray(aiState.available_tools) ? aiState.available_tools : []));
                const nextEnabledTools = Array.isArray(data.enabled_tools)
                    ? data.enabled_tools
                    : (Array.isArray(bridge.enabled_tools)
                        ? bridge.enabled_tools
                        : (Array.isArray(aiState.enabled_tools) ? aiState.enabled_tools : []));
                const hasDiscoveredTools = Array.isArray(nextAvailableTools) && nextAvailableTools.length > 0;
                deps.persistAiGeneratorStateForScenario(scenario, idx, {
                    model: aiState.model || data.model || (models[0] || ''),
                    mcp_server_path: bridge.mcp_server_path || aiState.mcp_server_path,
                    mcp_server_url: bridge.mcp_server_url || aiState.mcp_server_url,
                    servers_json_path: bridge.servers_json_path || aiState.servers_json_path,
                    auto_discovery: bridge.auto_discovery !== undefined ? !!bridge.auto_discovery : !!aiState.auto_discovery,
                    hil_enabled: bridge.hil_enabled !== undefined ? !!bridge.hil_enabled : !!aiState.hil_enabled,
                    enforce_ssl: data && Object.prototype.hasOwnProperty.call(data, 'enforce_ssl') ? !!data.enforce_ssl : (aiState.enforce_ssl === false ? false : true),
                    available_tools: nextAvailableTools,
                    enabled_tools: nextEnabledTools,
                    validation: {
                        ok: !!data.success,
                        in_progress: false,
                        ollama_ok: true,
                        bridge_ok: providerMeta.supportsBridge ? hasDiscoveredTools : false,
                        checked_at: data.checked_at || new Date().toISOString(),
                        message: providerMeta.supportsBridge && !hasDiscoveredTools
                            ? (data.message || 'Connected, but no MCP tools were discovered. Refresh Connection and verify bridge settings.')
                            : (data.message || 'Connection validated.'),
                        models,
                        model_found: data.model_found !== false,
                        provider: aiState.provider,
                    },
                });
                renderPanel();
            } catch (err) {
                const message = (err && err.message) ? err.message : 'Validation request failed.';
                deps.persistAiGeneratorStateForScenario(scenario, idx, {
                    available_tools: Array.isArray(aiState.available_tools) ? aiState.available_tools : [],
                    enabled_tools: Array.isArray(aiState.enabled_tools) ? aiState.enabled_tools : [],
                    validation: {
                        ok: false,
                        in_progress: false,
                        ollama_ok: false,
                        bridge_ok: false,
                        checked_at: new Date().toISOString(),
                        message,
                        models: [],
                        model_found: false,
                        provider: aiState.provider,
                    },
                });
                renderPanel();
            } finally {
                if (validateBtn) {
                    validateBtn.disabled = false;
                }
            }
        }

        async function fetchModels() {
            const { idx, scenario } = deps.getActiveScenarioContext();
            if (idx === null || !scenario) return;
            const aiState = deps.ensureAiGeneratorStateForScenario(scenario, idx);
            const providerMeta = getProviderMeta(aiState.provider);
            const fetchModelsBtn = document.getElementById('aiGeneratorFetchModelsBtn');
            if (fetchModelsBtn) {
                fetchModelsBtn.disabled = true;
                fetchModelsBtn.textContent = 'Fetching...';
            }
            deps.persistAiGeneratorStateForScenario(scenario, idx, {
                validation: {
                    ...aiState.validation,
                    in_progress: true,
                    checked_at: new Date().toISOString(),
                    message: `Refreshing models from ${providerMeta.label}...`,
                    provider: aiState.provider,
                },
            });
            renderPanel();
            try {
                const resp = await fetch('/api/ai/provider/validate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({
                        provider: aiState.provider,
                        base_url: aiState.base_url,
                        api_key: aiState.api_key || '',
                        enforce_ssl: aiState.enforce_ssl === false ? false : true,
                        model: '',
                        bridge_mode: normalizeBridgeMode(aiState.bridge_mode || 'mcp-python-sdk'),
                        skip_bridge: true,
                    }),
                });
                let data = null;
                try { data = await resp.json(); } catch (err) { data = null; }
                if (!resp.ok || !data || data.success === false) {
                    const message = (data && (data.error || data.message)) ? (data.error || data.message) : `Model refresh failed (HTTP ${resp.status})`;
                    deps.persistAiGeneratorStateForScenario(scenario, idx, {
                        validation: {
                            ...aiState.validation,
                            ok: false,
                            in_progress: false,
                            ollama_ok: false,
                            bridge_ok: false,
                            checked_at: new Date().toISOString(),
                            message,
                            models: data && Array.isArray(data.models) ? data.models : [],
                            model_found: !!(data && data.model_found),
                            provider: aiState.provider,
                        },
                    });
                    renderPanel();
                    return;
                }
                const models = Array.isArray(data.models) ? data.models : [];
                const nextModel = (() => {
                    const currentModel = String(aiState.model || '').trim();
                    if (currentModel && models.includes(currentModel)) return currentModel;
                    if (!currentModel && data.model && models.includes(data.model)) return data.model;
                    return models[0] || currentModel;
                })();
                const refreshMessage = models.length
                    ? `Fetched ${models.length} model${models.length === 1 ? '' : 's'} from ${providerMeta.label}.`
                    : `Reached ${providerMeta.label}, but no models were returned.`;
                deps.persistAiGeneratorStateForScenario(scenario, idx, {
                    model: nextModel,
                    validation: {
                        ...aiState.validation,
                        ok: !!(aiState.validation && aiState.validation.ok),
                        in_progress: false,
                        ollama_ok: true,
                        bridge_ok: !!(aiState.validation && aiState.validation.bridge_ok),
                        checked_at: data.checked_at || new Date().toISOString(),
                        message: refreshMessage,
                        models,
                        model_found: !!nextModel,
                        provider: aiState.provider,
                    },
                });
                renderPanel();
            } catch (err) {
                const message = (err && err.message) ? err.message : 'Model refresh request failed.';
                deps.persistAiGeneratorStateForScenario(scenario, idx, {
                    validation: {
                        ...aiState.validation,
                        ok: false,
                        in_progress: false,
                        ollama_ok: false,
                        bridge_ok: false,
                        checked_at: new Date().toISOString(),
                        message,
                        provider: aiState.provider,
                    },
                });
                renderPanel();
            } finally {
                const currentFetchModelsBtn = document.getElementById('aiGeneratorFetchModelsBtn');
                if (currentFetchModelsBtn) {
                    currentFetchModelsBtn.disabled = false;
                    currentFetchModelsBtn.textContent = 'Fetch Models';
                }
            }
        }

        async function generatePreview(options = {}) {
            const { idx, scenario } = deps.getActiveScenarioContext();
            if (idx === null || !scenario) return;
            const state = getState();
            const aiState = deps.ensureAiGeneratorStateForScenario(scenario, idx);
            const providerMeta = getProviderMeta(aiState.provider);
            const generateBtn = document.getElementById('aiGeneratorGenerateBtn');
            const originalLabel = generateBtn ? generateBtn.textContent : '';
            const promptInput = document.getElementById('aiGeneratorPromptInput');
            const promptValue = (promptInput ? promptInput.value : (aiState.draft_prompt || '')).toString().trim();
            const skipConfirmation = !!(options && options.skipConfirmation);
            if (!promptValue) {
                deps.persistAiGeneratorStateForScenario(scenario, idx, {
                    last_generation_error: 'Prompt / command intent is required.',
                    last_generation_warning: '',
                });
                renderPanel();
                return;
            }
            if (providerMeta.supportsBridge) {
                const enabledTools = Array.isArray(aiState.enabled_tools) ? aiState.enabled_tools.filter(Boolean) : [];
                if (!enabledTools.length) {
                    deps.persistAiGeneratorStateForScenario(scenario, idx, {
                        last_generation_error: 'No MCP tools are enabled. Refresh Connection and enable at least one tool before generating.',
                        last_generation_warning: '',
                    });
                    renderPanel();
                    return;
                }
            }
            if (!skipConfirmation) {
                try {
                    const confirmTitle = 'Reconstruct Scenario Elements';
                    const confirmMessage = `
                <p class="mb-3">This will remove the current topology/editor scenario data and recreate it from the prompt.</p>
                <div class="row g-3 text-start">
                    <div class="col-md-6">
                        <div class="border rounded p-3 h-100 bg-light">
                            <div class="fw-semibold text-danger mb-2">Rebuilt From Prompt</div>
                            <ul class="mb-0 small">
                                <li>Node Information</li>
                                <li>Routing</li>
                                <li>Services</li>
                                <li>Traffic</li>
                                <li>Vulnerabilities</li>
                                <li>Segmentation</li>
                                <li>Notes and generated counts</li>
                            </ul>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="border rounded p-3 h-100 bg-light">
                            <div class="fw-semibold text-success mb-2">Preserved</div>
                            <ul class="mb-0 small">
                                <li>Scenario name</li>
                                <li>Base CORE Scenario</li>
                                <li>Topology Seed</li>
                                <li>VM / Access settings</li>
                                <li>AI Generator connection settings</li>
                            </ul>
                        </div>
                    </div>
                </div>
                <p class="mt-3 mb-0">Proceed?</p>
            `;
                    let confirmed = false;
                    if (typeof window.confirmWithModal === 'function') {
                        confirmed = await window.confirmWithModal(confirmTitle, confirmMessage, 'Reconstruct Elements', 'primary', { allowHtml: true });
                    } else {
                        confirmed = window.confirm('This will rebuild topology/editor scenario data from the prompt while preserving Base CORE Scenario, Topology Seed, VM / Access settings, and AI Generator connection settings. Proceed?');
                    }
                    if (!confirmed) {
                        return;
                    }
                } catch (e) {
                    return;
                }
            }
            if (generateBtn) {
                generateBtn.disabled = true;
                generateBtn.textContent = 'Generating...';
            }
            try {
                if (typeof streamApi.setRetryAction === 'function') {
                    streamApi.setRetryAction(() => generatePreview({ skipConfirmation: true }));
                } else if (streamApi.state) {
                    streamApi.state.retryAction = () => generatePreview({ skipConfirmation: true });
                }
                let scenarioSeed = null;
                try {
                    const seedCandidate = (typeof window.coretgEnsureSeedForScenario === 'function')
                        ? window.coretgEnsureSeedForScenario(scenario.name || '')
                        : null;
                    const parsedSeed = parseInt(String(seedCandidate ?? ''), 10);
                    scenarioSeed = Number.isFinite(parsedSeed) && parsedSeed > 0 ? parsedSeed : null;
                } catch (e) { }
                const requestBody = {
                    request_id: streamApi.createRequestId(),
                    provider: aiState.provider,
                    base_url: aiState.base_url,
                    api_key: aiState.api_key || '',
                    enforce_ssl: aiState.enforce_ssl === false ? false : true,
                    model: aiState.model,
                    skip_bridge: aiState.skip_bridge === true,
                    ...deps.buildAiGeneratorBridgePayload(aiState),
                    prompt: promptValue,
                    scenarios: state.scenarios,
                    core: deps.getCoreConfig(true),
                    scenario_index: idx,
                    seed: scenarioSeed,
                };
                streamApi.showModal({
                    scenarioName: scenario.name || `Scenario ${idx + 1}`,
                    provider: aiState.provider || 'ollama',
                    model: aiState.model || '',
                });
                const streamController = typeof AbortController !== 'undefined' ? new AbortController() : null;
                streamApi.state.controller = streamController;
                streamApi.state.running = true;
                streamApi.state.requestId = requestBody.request_id;
                streamApi.updateButtons();
                const resp = await fetch('/api/ai/generate_scenario_preview_stream', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify(requestBody),
                    signal: streamController ? streamController.signal : undefined,
                });
                if (!resp.ok) {
                    let data = null;
                    try { data = await resp.json(); } catch (err) { data = null; }
                    const message = (data && (data.error || data.message)) ? (data.error || data.message) : `Generation failed (HTTP ${resp.status})`;
                    streamApi.finishModal(false, message);
                    handlePreviewFailure({ idx, scenario, promptValue, message });
                    return;
                }

                let finalData = null;
                let streamError = '';
                await streamApi.consumeNdjsonStream(resp, (event) => {
                    const type = (event && event.type) ? String(event.type) : '';
                    if (type === 'status') {
                        const message = (event.message || 'Working...').toString();
                        streamApi.setStatus(message, 'Waiting for the next update.', 'primary');
                        streamApi.appendEvent('Status', message);
                        return;
                    }
                    if (type === 'llm_delta') {
                        streamApi.setStatus('Receiving model output...', 'Streaming response from the LLM.', 'primary');
                        streamApi.appendOutput((event.text || '').toString());
                        return;
                    }
                    if (type === 'llm_thinking') {
                        streamApi.setStatus('Model is thinking...', 'Waiting for the next streamed reasoning update.', 'primary');
                        streamApi.appendEvent('Thinking', (event.text || '').toString(), 'default', {
                            mergeKey: 'llm-thinking',
                            appendBody: true,
                            tailMode: 'thinking',
                            maxChars: 24000,
                            maxLines: 400,
                        });
                        return;
                    }
                    if (type === 'tool_call') {
                        const toolName = (event.tool_name || 'tool').toString();
                        streamApi.setStatus('Calling tool...', `${toolName} was requested by the model.`, 'primary');
                        streamApi.appendEvent('Tool requested', toolName);
                        return;
                    }
                    if (type === 'tool') {
                        const toolName = (event.tool_name || 'tool').toString();
                        const stage = (event.stage || 'update').toString();
                        const message = (event.message || '').toString();
                        streamApi.setStatus(
                            stage === 'start' ? 'Running tool...' : 'Tool update received',
                            toolName,
                            'primary'
                        );
                        streamApi.appendEvent(stage === 'start' ? 'Tool running' : 'Tool result', `${toolName}\n${message}`);
                        return;
                    }
                    if (type === 'error') {
                        streamError = (event.error || 'Generation failed.').toString();
                        streamApi.appendEvent('Error', streamError, 'danger');
                        return;
                    }
                    if (type === 'result') {
                        finalData = (event.data && typeof event.data === 'object') ? event.data : null;
                        ensureModalOutput(finalData, '', true, promptValue);
                    }
                });

                if (streamError) {
                    ensureModalOutput(finalData, streamError, false, promptValue);
                    streamApi.finishModal(false, streamError);
                    handlePreviewFailure({ idx, scenario, promptValue, message: streamError });
                    return;
                }
                if (!finalData || finalData.success === false) {
                    const message = finalData && (finalData.error || finalData.message)
                        ? (finalData.error || finalData.message)
                        : 'Generation stream ended before a final result was returned.';
                    ensureModalOutput(finalData, message, false, promptValue);
                    streamApi.finishModal(false, message);
                    handlePreviewFailure({ idx, scenario, promptValue, message });
                    return;
                }

                await applyPreviewSuccess({ idx, scenario, aiState, promptValue, data: finalData });
                ensureModalOutput(finalData, 'Scenario draft and preview are ready.', true, promptValue);
                streamApi.finishModal(true, 'Scenario draft and preview are ready.');
            } catch (err) {
                const message = (err && (err.name === 'AbortError' || err.code === 20))
                    ? 'Generation cancelled by user.'
                    : ((err && err.message) ? err.message : 'Unexpected generation failure.');
                ensureModalOutput(null, message, false, promptValue);
                streamApi.finishModal(false, message);
                handlePreviewFailure({ idx, scenario, promptValue, message });
            } finally {
                if (generateBtn) {
                    generateBtn.disabled = false;
                    generateBtn.textContent = originalLabel || 'Construct Scenario Elements';
                }
            }
        }

        return {
            applyAiScenarioPreviewSuccess: applyPreviewSuccess,
            handleAiScenarioPreviewFailure: handlePreviewFailure,
            buildAiGeneratorPromptPacket: buildPromptPacket,
            validateAiGeneratorConfig: validateConfig,
            fetchAiGeneratorModels: fetchModels,
            generateAiScenarioPreview: generatePreview,
        };
    }

    window.createCoretgAiGeneratorWorkflow = createCoretgAiGeneratorWorkflow;
})(window);