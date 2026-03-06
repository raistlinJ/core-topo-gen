from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def test_local_mode_locks_core_connection_endpoint_fields() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const WEBUI_LOCAL_MODE =",
        "const WEBUI_LOCAL_CORE_HOST =",
        "const WEBUI_LOCAL_CORE_PORT =",
        "const WEBUI_LOCAL_SSH_PORT =",
        "if (WEBUI_LOCAL_MODE) {",
        "coreState.grpc_host = WEBUI_LOCAL_CORE_HOST;",
        "coreState.ssh_host = WEBUI_LOCAL_CORE_HOST;",
        "coreModalInputs.grpc_host.disabled = WEBUI_LOCAL_MODE || inputsDisabled;",
        "coreModalInputs.grpc_port.disabled = WEBUI_LOCAL_MODE || inputsDisabled;",
        "coreModalInputs.ssh_host.disabled = WEBUI_LOCAL_MODE || inputsDisabled;",
        "coreModalInputs.ssh_port.disabled = WEBUI_LOCAL_MODE || inputsDisabled;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing local-mode UI read-only guard snippets: " + "; ".join(missing)
