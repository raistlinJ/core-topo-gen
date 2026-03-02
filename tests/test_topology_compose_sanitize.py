from __future__ import annotations

import textwrap

from core_topo_gen.builders.topology import _sanitize_compose_incompatible_workdirs


def test_sanitize_compose_incompatible_workdirs_removes_root_for_ofbiz(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore  # noqa: F401
    except Exception:
        return

    compose_path = tmp_path / "docker-compose.yml"
    compose_path.write_text(
        textwrap.dedent(
            """
            services:
              app:
                image: vulhub/ofbiz:18.12.10
                working_dir: /
              db:
                image: postgres:15
                working_dir: /
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR_STRICT", raising=False)

    changed = _sanitize_compose_incompatible_workdirs(str(compose_path))
    assert changed is True

    out = compose_path.read_text(encoding="utf-8")
    assert "image: vulhub/ofbiz:18.12.10" in out
    assert "image: postgres:15" in out
    # OFBiz root working_dir should be removed.
    assert "image: vulhub/ofbiz:18.12.10\n    working_dir: /" not in out
    # Other services remain unchanged.
    assert "image: postgres:15\n    working_dir: /" in out


def test_sanitize_compose_incompatible_workdirs_respects_strict_env(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore  # noqa: F401
    except Exception:
        return

    compose_path = tmp_path / "docker-compose.yml"
    compose_path.write_text(
        textwrap.dedent(
            """
            services:
              app:
                image: vulhub/ofbiz:18.12.10
                working_dir: /
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR_STRICT", "1")

    changed = _sanitize_compose_incompatible_workdirs(str(compose_path))
    assert changed is False

    out = compose_path.read_text(encoding="utf-8")
    assert "working_dir: /" in out
