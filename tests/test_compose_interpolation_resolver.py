import os


def test_resolve_compose_interpolations_unwraps_and_resolves_airflow_user(monkeypatch):
    from core_topo_gen.builders.topology import _resolve_compose_interpolations

    # Ensure defaults are used (unset env) so output is deterministic.
    monkeypatch.delenv("AIRFLOW_UID", raising=False)
    monkeypatch.delenv("AIRFLOW_GID", raising=False)

    src = 'user: ${"${AIRFLOW_UID:-50000}"}:${"${AIRFLOW_GID:-50000}"}\n'
    out = _resolve_compose_interpolations(src)

    assert "${" not in out
    assert out.strip() == "user: 50000:50000"


def test_resolve_compose_interpolations_handles_escaped_quote_wrapper(monkeypatch):
    from core_topo_gen.builders.topology import _resolve_compose_interpolations

    monkeypatch.setenv("HOSTNAME", "corehost")
    # This form can appear when wrapper text is inside a quoted YAML scalar.
    src = 'name: ${\\"${HOSTNAME}\\"}\n'
    out = _resolve_compose_interpolations(src)

    assert "${" not in out
    assert out.strip() == "name: corehost"
