from pathlib import Path


FLOW_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "flow.html"


def test_flow_assignment_persists_resolved_paths() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "'resolved_paths',",
        "const resolvedPaths = (curA && typeof curA.resolved_paths === 'object'",
        "if (resolvedPaths !== undefined) out.resolved_paths = resolvedPaths;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing resolved_paths persistence snippets in flow template: " + "; ".join(missing)


def test_flow_chain_editor_hides_resolved_paths_row() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    removed_snippets = [
        "const resolved = (fa && typeof fa.resolved_paths === 'object'",
        "addPathEntry('artifacts_dir'",
        "inject_source ${srcIdx + 1}",
        "addRow('Resolved Paths', wrapLive",
    ]

    present = [snippet for snippet in removed_snippets if snippet in text]
    assert not present, "Resolved paths row snippets should be removed from flow chain editor: " + "; ".join(present)


def test_flow_injects_table_shows_resolved_path_column() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "headLabel.textContent = 'Resolved path';",
        "viewToggle.title = 'Toggle path view (CORE VM or Container)';",
        "const resolvedInjectSources = (fa && fa.resolved_paths && Array.isArray(fa.resolved_paths.inject_sources))",
        "function resolvedPathsForCandidate(srcValue, resolvedValue)",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing resolved path column wiring in injects table: " + "; ".join(missing)


def test_flow_inject_override_editor_shows_resolved_column() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const h2Label = document.createElement('span');",
        "h2Label.textContent = 'Resolved path';",
        "pathViewToggleBtn.title = 'Toggle path view (CORE VM or Container)';",
        "h3.textContent = 'Destination dir';",
        "function refreshPathHints()",
        "const resolvedInjectSources = (fa && fa.resolved_paths && Array.isArray(fa.resolved_paths.inject_sources))",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing resolved-path column wiring in inject override editor: " + "; ".join(missing)


def test_flow_page_does_not_auto_generate_on_load() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    forbidden_snippet = "await generate(false, { autoLoad: true, resolveOnGenerate: false });"
    assert forbidden_snippet not in text, "Flow page should not auto-generate on load; Generate button must be explicit"


def test_flow_inject_path_view_roundtrips_via_flow_state() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "out.inject_path_view = injectPathView;",
        "curA.inject_path_view = String(savedA.inject_path_view).trim().toLowerCase();",
        "fa.inject_path_view = pathView;",
        "persistFlowStateAndXmlBestEffort();",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing inject path view XML/state round-trip snippets: " + "; ".join(missing)


def test_flow_restore_prefers_xml_authoritative_state() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const xmlAuthoritative = hasAuthoritativeXmlPathForScenario(scenarioName);",
        "if (xmlAuthoritative) {",
        "if (serverUsable) return fromServer;",
        "return null;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing XML-authoritative flow restore snippets: " + "; ".join(missing)


def test_flow_restore_refreshes_xml_before_state_selection() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "if (hasAuthoritativeXmlPathForScenario(scenarioName) && typeof window.coretgRefreshScenarioStateFromXml === 'function') {",
        "const latest = await window.coretgRefreshScenarioStateFromXml(scenarioName, { updateHidden: true, xml_path: xmlPath });",
        "if (key) flowStateByScenario[key] = fs;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Flow restore should refresh XML-backed scenario state first: " + "; ".join(missing)


def test_flow_restore_emits_debug_logs_for_roundtrip_diagnostics() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "console.debug('[flow.restore] start'",
        "console.debug('[flow.restore] xml refresh'",
        "console.debug('[flow.restore] selected state'",
        "console.debug('[flow.restore] attackflow_preview response'",
        "console.error('[flow.restore] failed'",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing flow restore debug logging snippets: " + "; ".join(missing)


def test_flow_save_to_xml_clears_chain_when_disabled() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const chain_ids = (!flowEnabled)",
        "flag_assignments: (!flowEnabled) ? [] : buildPersistAssignments(chain_ids),",
        "flow_enabled: !!flowEnabled,",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Disabled flow saves should clear chain/assignments in XML payload: " + "; ".join(missing)


def test_flow_state_with_topology_dirty_field_is_usable_on_restore() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippet = "if (Object.prototype.hasOwnProperty.call(state, 'topology_dirty')) return true;"
    assert expected_snippet in text, "Flow restore should treat topology_dirty-bearing flow_state as usable"


def test_flow_restore_requires_resolved_values_for_saved_chain() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const hasResolvedValues = (flowState) => {",
        "const assignments = Array.isArray(flowState.flag_assignments) ? flowState.flag_assignments : [];",
        "return hasResolvedValues(normalized);",
        "setStatus('Chain does not exist. Click Generate to start.', false);",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Flow restore should hide partial chain states without resolved values: " + "; ".join(missing)


def test_flow_refresh_does_not_mark_dirty_from_preview_plan_fetch_errors() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    forbidden_snippet = "setTopologyDirtyState(true, 'topology_or_ip_changed');"
    assert forbidden_snippet not in text, "Transient preview-plan fetch errors should not force topology_dirty on refresh"


def test_flow_preview_tab_persists_flow_state_before_redirect() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "link.addEventListener('click', async (ev) => {",
        "await saveFlowStateToXml(xmlPath);",
        "window.location.href = url;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Preview-tab navigation should persist flow state before redirect: " + "; ".join(missing)


def test_flow_empty_state_uses_placeholder_message_instead_of_mermaid_error() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        '<div id="flowDiagram">Please generate a chain. It will appear here.</div>',
        "const fallbackText = 'Please generate a chain. It will appear here.';",
        "if (!diagramText || !String(diagramText).trim()) {",
        "if (renderedText.includes('syntax error in text')) {",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing flow empty-state placeholder snippets: " + "; ".join(missing)


def test_flow_generate_max_retries_defaults_to_ten() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'max="50" value="10" style="width: 90px;">',
        "parseInt(generateMaxRetriesEl.value || '10', 10) || 10",
        "} catch (e) { retriesRemaining = 10; }",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing flow max-retries default snippets: " + "; ".join(missing)
