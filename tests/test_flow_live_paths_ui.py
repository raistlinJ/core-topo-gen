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
        "<th style=\"width: 1%; white-space: nowrap;\">Variable</th><th>Resolved path</th>",
        "const resolvedInjectSources = (fa && fa.resolved_paths && Array.isArray(fa.resolved_paths.inject_sources))",
        "function resolvedPathsForCandidate(srcValue, resolvedValue)",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing resolved path column wiring in injects table: " + "; ".join(missing)


def test_flow_inject_override_editor_shows_resolved_column() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "h2.textContent = 'Resolved path';",
        "h3.textContent = 'Destination dir';",
        "function refreshPathHints()",
        "const resolvedInjectSources = (fa && fa.resolved_paths && Array.isArray(fa.resolved_paths.inject_sources))",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing resolved-path column wiring in inject override editor: " + "; ".join(missing)
