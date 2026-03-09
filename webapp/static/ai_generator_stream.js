(function (window, document) {
    const streamState = {
        modal: null,
        outputStarted: false,
        controller: null,
        running: false,
        requestId: '',
        meta: '',
        status: '',
        detail: '',
        outputText: '',
        events: [],
    };
    const EVENT_COLLAPSE_THRESHOLD = 900;

    function createRequestId() {
        try {
            if (window.crypto && typeof window.crypto.randomUUID === 'function') {
                return window.crypto.randomUUID();
            }
        } catch (e) { }
        return `ai-stream-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    }

    function updateButtons() {
        const cancelBtn = document.getElementById('aiGeneratorStreamCancelBtn');
        const copyBtn = document.getElementById('aiGeneratorStreamCopyBtn');
        const downloadBtn = document.getElementById('aiGeneratorStreamDownloadBtn');
        const closeBtn = document.getElementById('aiGeneratorStreamCloseBtn');
        const headerCloseBtn = document.getElementById('aiGeneratorStreamHeaderCloseBtn');
        if (cancelBtn) cancelBtn.disabled = !streamState.running;
        if (copyBtn) copyBtn.disabled = !streamState.outputText && !streamState.events.length;
        if (downloadBtn) downloadBtn.disabled = !streamState.outputText && !streamState.events.length;
        if (closeBtn) closeBtn.disabled = !!streamState.running;
        if (headerCloseBtn) headerCloseBtn.disabled = !!streamState.running;
    }

    function renderEventBody(bodyEl, fullBody) {
        if (!bodyEl) return;
        const text = (fullBody || '').toString();
        bodyEl.textContent = '';
        if (!text) return;
        if (text.length <= EVENT_COLLAPSE_THRESHOLD) {
            bodyEl.textContent = text;
            return;
        }
        const preview = document.createElement('div');
        preview.className = 'ai-generator-stream-event-preview';
        preview.textContent = `${text.slice(0, EVENT_COLLAPSE_THRESHOLD)}\n\n[truncated in-place; expand below for full payload]`;
        bodyEl.appendChild(preview);

        const details = document.createElement('details');
        details.className = 'ai-generator-stream-event-toggle';
        const summary = document.createElement('summary');
        summary.textContent = 'Show full payload';
        const full = document.createElement('div');
        full.className = 'ai-generator-stream-event-toggle-body';
        full.textContent = text;
        details.appendChild(summary);
        details.appendChild(full);
        bodyEl.appendChild(details);
    }

    function ensureModalGuards() {
        const modalEl = document.getElementById('aiGeneratorStreamModal');
        if (!modalEl || modalEl.dataset.aiGeneratorGuarded === '1') return;
        modalEl.addEventListener('hide.bs.modal', (event) => {
            if (streamState.running) {
                event.preventDefault();
                event.stopPropagation();
            }
        });
        modalEl.dataset.aiGeneratorGuarded = '1';
    }

    function getModalInstance() {
        const modalEl = document.getElementById('aiGeneratorStreamModal');
        if (!modalEl || !window.bootstrap || !bootstrap.Modal) return null;
        ensureModalGuards();
        return bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl, { backdrop: true, keyboard: true });
    }

    function setStatus(statusText, detailText = '', tone = 'primary') {
        const statusEl = document.getElementById('aiGeneratorStreamStatus');
        const detailEl = document.getElementById('aiGeneratorStreamDetail');
        const badgeEl = document.getElementById('aiGeneratorStreamStateBadge');
        streamState.status = statusText || 'Running...';
        streamState.detail = detailText || '';
        if (statusEl) statusEl.textContent = statusText || 'Running...';
        if (detailEl) detailEl.textContent = detailText || '';
        if (badgeEl) {
            badgeEl.className = `badge text-bg-${tone || 'primary'}`;
            badgeEl.textContent = tone === 'success' ? 'Done' : (tone === 'danger' ? 'Error' : 'Running');
        }
    }

    function appendOutput(text, prefix = '') {
        const outputEl = document.getElementById('aiGeneratorStreamOutput');
        if (!outputEl || !text) return;
        if (!streamState.outputStarted && prefix) {
            outputEl.textContent += `${prefix}`;
            streamState.outputText += `${prefix}`;
            streamState.outputStarted = true;
        }
        outputEl.textContent += text;
        streamState.outputText += text;
        outputEl.scrollTop = outputEl.scrollHeight;
        updateButtons();
    }

    function appendEvent(title, body = '', tone = 'default', options = {}) {
        const eventsEl = document.getElementById('aiGeneratorStreamEvents');
        if (!eventsEl) return;
        const mergeKey = (options && options.mergeKey) ? String(options.mergeKey) : '';
        const appendBody = !!(options && options.appendBody);
        if (mergeKey) {
            const existingEl = eventsEl.querySelector(`[data-merge-key="${mergeKey.replace(/"/g, '&quot;')}"]`);
            const existingIndex = streamState.events.findIndex((event) => event && event.mergeKey === mergeKey);
            if (existingEl && existingIndex >= 0) {
                const bodyEl = existingEl.querySelector('.ai-generator-stream-event-body');
                const currentBody = (streamState.events[existingIndex].body || '').toString();
                const nextChunk = (body || '').toString();
                const nextBody = appendBody ? `${currentBody}${nextChunk}` : nextChunk;
                renderEventBody(bodyEl, nextBody);
                streamState.events[existingIndex] = {
                    ...streamState.events[existingIndex],
                    title: title || 'Update',
                    body: nextBody,
                    tone: tone || 'default',
                    mergeKey,
                };
                eventsEl.scrollTop = eventsEl.scrollHeight;
                updateButtons();
                return;
            }
        }
        const item = document.createElement('div');
        item.className = 'ai-generator-stream-event';
        if (mergeKey) item.dataset.mergeKey = mergeKey;
        if (tone === 'danger') item.classList.add('is-error');
        if (tone === 'success') item.classList.add('is-success');
        const titleEl = document.createElement('div');
        titleEl.className = 'ai-generator-stream-event-title';
        titleEl.textContent = title || 'Update';
        const bodyEl = document.createElement('div');
        bodyEl.className = 'ai-generator-stream-event-body';
        renderEventBody(bodyEl, body || '');
        item.appendChild(titleEl);
        item.appendChild(bodyEl);
        eventsEl.appendChild(item);
        streamState.events.push({ title: title || 'Update', body: body || '', tone: tone || 'default', mergeKey });
        eventsEl.scrollTop = eventsEl.scrollHeight;
        updateButtons();
    }

    function buildTranscript() {
        const parts = [];
        if (streamState.meta) parts.push(streamState.meta);
        if (streamState.status || streamState.detail) {
            parts.push(`Status: ${streamState.status || ''}`.trim());
            if (streamState.detail) parts.push(`Detail: ${streamState.detail}`);
        }
        if (streamState.events.length) {
            parts.push('');
            parts.push('Activity:');
            streamState.events.forEach((event) => {
                const title = (event && event.title) ? String(event.title) : 'Update';
                const body = (event && event.body) ? String(event.body) : '';
                parts.push(`- ${title}${body ? `: ${body}` : ''}`);
            });
        }
        if (streamState.outputText) {
            parts.push('');
            parts.push('LLM Output:');
            parts.push(streamState.outputText);
        }
        return parts.join('\n');
    }

    async function copyTranscript() {
        const text = buildTranscript();
        if (!text.trim()) return;
        try {
            if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
                await navigator.clipboard.writeText(text);
            } else {
                const textarea = document.createElement('textarea');
                textarea.value = text;
                textarea.setAttribute('readonly', 'readonly');
                textarea.style.position = 'fixed';
                textarea.style.left = '-9999px';
                document.body.appendChild(textarea);
                textarea.select();
                document.execCommand('copy');
                document.body.removeChild(textarea);
            }
            appendEvent('Transcript copied', 'Copied the current output and activity to the clipboard.', 'success');
        } catch (err) {
            appendEvent('Copy failed', (err && err.message) ? err.message : 'Clipboard write failed.', 'danger');
        }
    }

    function downloadTranscript() {
        const text = buildTranscript();
        if (!text.trim()) return;
        try {
            const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            const safeName = (streamState.meta || 'ai-generator-transcript')
                .toString()
                .toLowerCase()
                .replace(/[^a-z0-9]+/g, '-')
                .replace(/^-+|-+$/g, '') || 'ai-generator-transcript';
            link.href = url;
            link.download = `${safeName}.txt`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
            appendEvent('Transcript downloaded', 'Downloaded the full output and activity transcript.', 'success');
        } catch (err) {
            appendEvent('Download failed', (err && err.message) ? err.message : 'Transcript download failed.', 'danger');
        }
    }

    async function cancelStream() {
        if (!streamState.running || !streamState.controller) return;
        appendEvent('Cancel requested', 'Aborting the active browser request.');
        setStatus('Cancelling generation...', 'Waiting for the request to stop.', 'danger');
        const requestId = streamState.requestId;
        if (requestId) {
            try {
                await fetch('/api/ai/generate_scenario_preview_stream/cancel', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ request_id: requestId }),
                });
            } catch (e) { }
        }
        try { streamState.controller.abort(); } catch (e) { }
        streamState.controller = null;
        streamState.running = false;
        updateButtons();
    }

    function showModal({ scenarioName = '', provider = '', model = '' } = {}) {
        streamState.modal = getModalInstance();
        streamState.outputStarted = false;
        streamState.controller = null;
        streamState.running = false;
        streamState.requestId = '';
        streamState.outputText = '';
        streamState.events = [];
        const metaEl = document.getElementById('aiGeneratorStreamMeta');
        const outputEl = document.getElementById('aiGeneratorStreamOutput');
        const eventsEl = document.getElementById('aiGeneratorStreamEvents');
        if (metaEl) {
            const bits = [scenarioName, provider, model].map(v => (v || '').toString().trim()).filter(Boolean);
            streamState.meta = bits.length ? bits.join(' • ') : 'AI generation in progress';
            metaEl.textContent = streamState.meta;
        }
        if (outputEl) outputEl.textContent = '';
        if (eventsEl) eventsEl.innerHTML = '';
        setStatus('Preparing request...', 'Connecting to the backend stream.', 'primary');
        appendEvent('Starting', 'Opening generation stream.');
        updateButtons();
        try { streamState.modal?.show(); } catch (e) { }
    }

    function finishModal(success, detailText = '') {
        streamState.running = false;
        streamState.controller = null;
        streamState.requestId = '';
        setStatus(
            success ? 'Generation finished' : 'Generation failed',
            detailText || (success ? 'Scenario draft and preview are ready.' : 'The request stopped before a valid result was returned.'),
            success ? 'success' : 'danger'
        );
        appendEvent(success ? 'Complete' : 'Error', detailText || '', success ? 'success' : 'danger');
        updateButtons();
    }

    async function consumeNdjsonStream(response, onEvent) {
        if (!response.body || typeof response.body.getReader !== 'function') {
            throw new Error('Streaming response body is unavailable in this browser.');
        }
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            let newlineIndex = buffer.indexOf('\n');
            while (newlineIndex >= 0) {
                const line = buffer.slice(0, newlineIndex).trim();
                buffer = buffer.slice(newlineIndex + 1);
                if (line) {
                    let parsed = null;
                    try { parsed = JSON.parse(line); } catch (e) { parsed = null; }
                    if (parsed && typeof parsed === 'object') onEvent(parsed);
                }
                newlineIndex = buffer.indexOf('\n');
            }
        }
        buffer += decoder.decode();
        const lastLine = buffer.trim();
        if (lastLine) {
            let parsed = null;
            try { parsed = JSON.parse(lastLine); } catch (e) { parsed = null; }
            if (parsed && typeof parsed === 'object') onEvent(parsed);
        }
    }

    window.CORETG_AI_GENERATOR_STREAM = {
        state: streamState,
        createRequestId,
        updateButtons,
        renderEventBody,
        ensureModalGuards,
        getModalInstance,
        setStatus,
        appendOutput,
        appendEvent,
        buildTranscript,
        copyTranscript,
        downloadTranscript,
        cancelStream,
        showModal,
        finishModal,
        consumeNdjsonStream,
    };
})(window, document);