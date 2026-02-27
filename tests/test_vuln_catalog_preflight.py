from webapp import app_backend as backend


def test_core_like_compose_template_preflight_raw_fails(tmp_path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        """
services:
  app:
    image: apache/airflow:2.9.0
    environment:
      - AIRFLOW_UID=${AIRFLOW_UID:-50000}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    ok, err, meta = backend._core_like_compose_template_preflight(str(compose))

    assert ok is False
    assert "unescaped `${...}`" in str(err)
    assert int(meta.get("raw_template_expr_count") or 0) >= 1


def test_core_like_compose_template_preflight_wrapped_passes(tmp_path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        """
services:
  app:
    image: apache/airflow:2.9.0
    environment:
      - AIRFLOW_UID=${"${AIRFLOW_UID:-50000}"}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    ok, err, meta = backend._core_like_compose_template_preflight(str(compose))

    assert ok is True
    assert err is None
    assert str(meta.get("template_engine") or "") in ("mako", "ast-fallback")


def test_core_vm_compose_template_preflight_reports_remote_failure(monkeypatch):
    def _fake_exec(_client, _cmd, timeout=30.0, cancel_check=None, check=False):
        out = '{"ok": false, "error": "Compose template contains unescaped `${...}` expression(s): line 16: ${AIRFLOW_UID:-50000}", "meta": {"raw_template_expr_count": 1}}'
        return 0, out, ""

    monkeypatch.setattr(backend, "_exec_ssh_command", _fake_exec)

    ok, err, meta = backend._core_vm_compose_template_preflight(object(), "/tmp/tests/test-abc/docker-compose.yml")

    assert ok is False
    assert "unescaped `${...}`" in str(err)
    assert int(meta.get("raw_template_expr_count") or 0) == 1


def test_core_vm_compose_template_preflight_reports_remote_success(monkeypatch):
    def _fake_exec(_client, _cmd, timeout=30.0, cancel_check=None, check=False):
        out = '{"ok": true, "meta": {"template_engine": "mako"}}'
        return 0, out, ""

    monkeypatch.setattr(backend, "_exec_ssh_command", _fake_exec)

    ok, err, meta = backend._core_vm_compose_template_preflight(object(), "/tmp/tests/test-abc/docker-compose.yml")

    assert ok is True
    assert err is None
    assert meta.get("template_engine") == "mako"


def test_redact_sensitive_text_masks_password_token():
    raw = "core123!@#\nline2 core123!@#\n"
    out = backend._redact_sensitive_text(raw, redact_tokens=["core123!@#"])
    assert "core123!@#" not in out
    assert out.count("[REDACTED]") >= 2


def test_redact_sensitive_text_ignores_short_or_empty_tokens():
    raw = "abc xyz"
    out = backend._redact_sensitive_text(raw, redact_tokens=["", "ab", None])
    assert out == raw


def test_core_vm_render_compose_template_success(monkeypatch):
    def _fake_exec(_client, _cmd, timeout=30.0, cancel_check=None, check=False):
        out = '{"ok": true, "path": "/tmp/tests/test-abc/docker-compose.runtime.yml", "meta": {"engine": "mako"}}'
        return 0, out, ""

    monkeypatch.setattr(backend, "_exec_ssh_command", _fake_exec)

    ok, rendered_path, err, meta = backend._core_vm_render_compose_template(object(), "/tmp/tests/test-abc/docker-compose.yml")

    assert ok is True
    assert err is None
    assert rendered_path == "/tmp/tests/test-abc/docker-compose.runtime.yml"
    assert meta.get("engine") == "mako"


def test_core_vm_render_compose_template_failure(monkeypatch):
    def _fake_exec(_client, _cmd, timeout=30.0, cancel_check=None, check=False):
        out = '{"ok": false, "error": "mako render failed: invalid syntax"}'
        return 0, out, ""

    monkeypatch.setattr(backend, "_exec_ssh_command", _fake_exec)

    ok, rendered_path, err, meta = backend._core_vm_render_compose_template(object(), "/tmp/tests/test-abc/docker-compose.yml")

    assert ok is False
    assert rendered_path is None
    assert "mako render failed" in str(err)
    assert isinstance(meta, dict)
