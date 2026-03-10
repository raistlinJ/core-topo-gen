(function (window, document) {
    const streamState = {
        modal: null,
        outputStarted: false,
        controller: null,
        running: false,
        canRetry: false,
        retryAction: null,
        requestId: '',
        meta: '',
        status: '',
        detail: '',
        outputText: '',
        events: [],
    };
    const EVENT_COLLAPSE_THRESHOLD = 900;
    const STREAMING_TAIL_MAX_CHARS = 24000;
    const STREAMING_TAIL_MAX_LINES = 400;
    const OUTPUT_TAIL_MAX_CHARS = 180000;
    const OUTPUT_TAIL_MAX_LINES = 3000;
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
        const retryBtn = document.getElementById('aiGeneratorStreamRetryBtn');
        const closeBtn = document.getElementById('aiGeneratorStreamCloseBtn');
        const headerCloseBtn = document.getElementById('aiGeneratorStreamHeaderCloseBtn');
        if (cancelBtn) cancelBtn.disabled = !streamState.running;
        if (copyBtn) copyBtn.disabled = !streamState.outputText && !streamState.events.length;
        if (downloadBtn) downloadBtn.disabled = !streamState.outputText && !streamState.events.length;
        if (retryBtn) retryBtn.disabled = !!streamState.running || !streamState.canRetry || typeof streamState.retryAction !== 'function';
        if (closeBtn) closeBtn.disabled = !!streamState.running;
        if (headerCloseBtn) headerCloseBtn.disabled = !!streamState.running;
    }

    function setRetryAction(retryAction) {
        streamState.retryAction = typeof retryAction === 'function' ? retryAction : null;
        updateButtons();
    }

    async function retryStream() {
        if (streamState.running || !streamState.canRetry || typeof streamState.retryAction !== 'function') return;
        try {
            await streamState.retryAction();
        } catch (err) {
            appendEvent('Retry failed', (err && err.message) ? err.message : 'Retry request failed.', 'danger');
        }
    }

    function shouldUseRollingTail(options = {}) {
        const modeKey = (options && options.tailMode) ? String(options.tailMode) : '';
        if (modeKey === 'thinking') {
            return true;
        }
        return !!(options && options.rollingTail);
    }

    function buildRollingTailText(text, maxChars = STREAMING_TAIL_MAX_CHARS, maxLines = STREAMING_TAIL_MAX_LINES) {
        let visible = (text || '').toString();
        let trimmedByChars = false;
        let trimmedByLines = false;
        if (visible.length > maxChars) {
            visible = visible.slice(visible.length - maxChars);
            trimmedByChars = true;
        }
        const lines = visible.split('\n');
        if (lines.length > maxLines) {
            visible = lines.slice(lines.length - maxLines).join('\n');
            trimmedByLines = true;
        }
        return {
            text: visible,
            trimmed: trimmedByChars || trimmedByLines,
        };
    }

    function renderScrollingTextBlock(parentEl, text, className) {
        const block = document.createElement('div');
        block.className = className;
        block.textContent = text;
        parentEl.appendChild(block);
        block.scrollTop = block.scrollHeight;
        return block;
    }

    function bindPayloadToggle(detailsEl, summaryEl) {
        if (!detailsEl || !summaryEl) return;
        const syncLabel = () => {
            summaryEl.textContent = detailsEl.open ? 'Collapse payload' : 'Expand payload';
        };
        detailsEl.addEventListener('toggle', syncLabel);
        syncLabel();
    }

    function renderOutput() {
        const outputEl = document.getElementById('aiGeneratorStreamOutput');
        const outputHintEl = document.getElementById('aiGeneratorStreamOutputHint');
        if (!outputEl) return;
        const fullText = (streamState.outputText || '').toString();
        const tail = buildRollingTailText(fullText, OUTPUT_TAIL_MAX_CHARS, OUTPUT_TAIL_MAX_LINES);
        outputEl.textContent = tail.text;
        outputEl.scrollTop = outputEl.scrollHeight;
        if (outputHintEl) {
            outputHintEl.textContent = tail.trimmed
                ? 'Showing newest model output lines. Older output remains available via Copy Transcript or Download Transcript.'
                : '';
        }
    }

    function renderEventBody(bodyEl, fullBody, options = {}) {
        if (!bodyEl) return;
        const text = (fullBody || '').toString();
        bodyEl.textContent = '';
        if (!text) return;
        const renderedText = shouldUseRollingTail(options)
            ? buildRollingTailText(
                text,
                options.maxChars || STREAMING_TAIL_MAX_CHARS,
                options.maxLines || STREAMING_TAIL_MAX_LINES,
            ).text
            : text;
        const shouldCollapse = renderedText.length > EVENT_COLLAPSE_THRESHOLD || renderedText.includes('\n');
        if (!shouldCollapse) {
            bodyEl.textContent = renderedText;
            return;
        }
        const details = document.createElement('details');
        details.className = 'ai-generator-stream-event-toggle';
        details.open = !!options.initialOpen;
        const summary = document.createElement('summary');
        const full = document.createElement('div');
        full.className = shouldUseRollingTail(options)
            ? 'ai-generator-stream-event-live-tail ai-generator-stream-event-toggle-body'
            : 'ai-generator-stream-event-toggle-body';
        full.textContent = renderedText;
        details.appendChild(summary);
        details.appendChild(full);
        bindPayloadToggle(details, summary);
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
        if (!text) return;
        if (!streamState.outputStarted && prefix) {
            streamState.outputText += `${prefix}`;
            streamState.outputStarted = true;
        }
        streamState.outputText += text;
        renderOutput();
        updateButtons();
    }

    function getOutputText() {
        return (streamState.outputText || '').toString();
    }

    function rerenderEventByMergeKey(mergeKey) {
        const eventsEl = document.getElementById('aiGeneratorStreamEvents');
        if (!eventsEl || !mergeKey) return;
        const existingEl = eventsEl.querySelector(`[data-merge-key="${String(mergeKey).replace(/"/g, '&quot;')}"]`);
        const existingEvent = streamState.events.find((event) => event && event.mergeKey === mergeKey);
        if (!existingEl || !existingEvent) return;
        const bodyEl = existingEl.querySelector('.ai-generator-stream-event-body');
        const detailsEl = bodyEl ? bodyEl.querySelector('.ai-generator-stream-event-toggle') : null;
        renderEventBody(bodyEl, existingEvent.body || '', {
            ...(existingEvent.renderOptions || {}),
            initialOpen: !!(detailsEl && detailsEl.open),
        });
        eventsEl.scrollTop = eventsEl.scrollHeight;
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
                const detailsEl = bodyEl ? bodyEl.querySelector('.ai-generator-stream-event-toggle') : null;
                const currentBody = (streamState.events[existingIndex].body || '').toString();
                const nextChunk = (body || '').toString();
                const nextBody = appendBody ? `${currentBody}${nextChunk}` : nextChunk;
                renderEventBody(bodyEl, nextBody, {
                    ...(options || {}),
                    initialOpen: !!(detailsEl && detailsEl.open),
                });
                streamState.events[existingIndex] = {
                    ...streamState.events[existingIndex],
                    title: title || 'Update',
                    body: nextBody,
                    tone: tone || 'default',
                    mergeKey,
                    renderOptions: options || {},
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
        renderEventBody(bodyEl, body || '', options);
        item.appendChild(titleEl);
        item.appendChild(bodyEl);
        eventsEl.appendChild(item);
        streamState.events.push({ title: title || 'Update', body: body || '', tone: tone || 'default', mergeKey, renderOptions: options || {} });
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

    function ensureDownloadFrame() {
        let frame = document.getElementById('aiGeneratorTranscriptDownloadFrame');
        if (frame) return frame;
        frame = document.createElement('iframe');
        frame.id = 'aiGeneratorTranscriptDownloadFrame';
        frame.name = 'aiGeneratorTranscriptDownloadFrame';
        frame.style.display = 'none';
        document.body.appendChild(frame);
        return frame;
    }

    function downloadTranscript() {
        const text = buildTranscript();
        if (!text.trim()) return;
        try {
            const safeName = (streamState.meta || 'ai-generator-transcript')
                .toString()
                .toLowerCase()
                .replace(/[^a-z0-9]+/g, '-')
                .replace(/^-+|-+$/g, '') || 'ai-generator-transcript';
            const frame = ensureDownloadFrame();
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = '/api/ai/download_transcript';
            form.target = frame.name;
            form.style.display = 'none';

            const transcriptField = document.createElement('textarea');
            transcriptField.name = 'transcript';
            transcriptField.value = text;
            form.appendChild(transcriptField);

            const filenameField = document.createElement('input');
            filenameField.type = 'hidden';
            filenameField.name = 'filename';
            filenameField.value = safeName;
            form.appendChild(filenameField);

            document.body.appendChild(form);
            form.submit();
            window.setTimeout(() => {
                try { document.body.removeChild(form); } catch (e) { }
            }, 1000);
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
        streamState.canRetry = false;
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
        renderOutput();
        setStatus('Preparing request...', 'Connecting to the backend stream.', 'primary');
        appendEvent('Starting', 'Opening generation stream.');
        updateButtons();
        try { streamState.modal?.show(); } catch (e) { }
    }

    function finishModal(success, detailText = '') {
        streamState.running = false;
        streamState.controller = null;
        streamState.requestId = '';
        streamState.canRetry = true;
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
        getOutputText,
        appendEvent,
        buildTranscript,
        copyTranscript,
        downloadTranscript,
        cancelStream,
        retryStream,
        setRetryAction,
        showModal,
        finishModal,
        consumeNdjsonStream,
    };
})(window, document);