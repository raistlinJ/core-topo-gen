from pathlib import Path


BACKEND_PATH = Path(__file__).resolve().parent.parent / "webapp" / "app_backend.py"


def test_local_mode_backend_coerces_core_endpoint_fields_to_localhost() -> None:
    text = BACKEND_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "def _webui_local_mode() -> bool:",
        "mode = str(os.getenv('CORETG_RUN_MODE') or '').strip().lower()",
        "if _webui_local_mode():",
        "cfg['host'] = local_host",
        "cfg['grpc_host'] = local_host",
        "cfg['port'] = local_port",
        "cfg['grpc_port'] = local_port",
        "cfg['ssh_host'] = local_host",
        "cfg['ssh_port'] = local_ssh_port",
        "'webui_local_mode': _webui_local_mode(),",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing local-mode backend guard snippets: " + "; ".join(missing)
