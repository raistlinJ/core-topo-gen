import io
import os
import zipfile

from webapp.app_backend import app
import webapp.app_backend as app_backend
from werkzeug.utils import secure_filename


def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for path, content in files.items():
            z.writestr(path, content)
    buf.seek(0)
    return buf.read()


def test_generator_pack_zip_upload_installs_and_is_discoverable(tmp_path, monkeypatch):
    # Install into a temp directory so tests don't mutate the repo.
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))

    gen_id = "pack_test_binary_embed_text"

    manifest = """manifest_version: 1
id: pack_test_binary_embed_text
kind: flag-generator
name: \"Pack Test: Binary Embed\"
description: \"Test pack generator\"
runtime:
  type: docker-compose
  compose_file: docker-compose.yml
  service: generator
inputs: []
artifacts:
  requires: []
  produces:
    - filesystem.file
injects: []
"""

    compose = """version: '3.8'
services:
  generator:
    image: python:3.11-slim
    command: [\"python\", \"-c\", \"print('ok')\"]
"""

    generator_py = """def main():
    return 0
"""

    zip_bytes = _make_zip(
        {
            f"flag_generators/{gen_id}/manifest.yaml": manifest,
            f"flag_generators/{gen_id}/docker-compose.yml": compose,
            f"flag_generators/{gen_id}/generator.py": generator_py,
        }
    )

    client = app.test_client()
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (200, 302)

    resp = client.post(
        "/generator_packs/upload",
        data={"zip_file": (io.BytesIO(zip_bytes), "pack.zip")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)

    # Should now appear in manifest-backed endpoint.
    data_resp = client.get("/flag_generators_data")
    assert data_resp.status_code == 200
    data = data_resp.get_json() or {}
    ids = {g.get("id") for g in (data.get("generators") or []) if isinstance(g, dict)}
    assert gen_id in ids

    # Ensure files were installed into the configured install root.
    assert (install_root / "flag_generators").exists()


def test_generator_pack_uninstall_removes_generators(tmp_path, monkeypatch):
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))

    gen_id = "pack_test_uninstall"

    manifest = f"""manifest_version: 1
id: {gen_id}
kind: flag-generator
name: \"Pack Test: Uninstall\"
runtime:
  type: docker-compose
  compose_file: docker-compose.yml
  service: generator
inputs: []
artifacts:
  requires: []
  produces:
    - filesystem.file
injects: []
"""

    compose = """version: '3.8'
services:
  generator:
    image: python:3.11-slim
    command: [\"python\", \"-c\", \"print('ok')\"]
"""

    zip_bytes = _make_zip(
        {
            f"flag_generators/{gen_id}/manifest.yaml": manifest,
            f"flag_generators/{gen_id}/docker-compose.yml": compose,
            f"flag_generators/{gen_id}/generator.py": "print('hi')\n",
        }
    )

    client = app.test_client()
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (200, 302)

    resp = client.post(
        "/generator_packs/upload",
        data={"zip_file": (io.BytesIO(zip_bytes), "pack.zip")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)

    packs_state = app_backend._load_installed_generator_packs_state()
    packs = packs_state.get("packs") or []
    assert isinstance(packs, list) and packs
    pack_id = packs[-1].get("id")
    assert pack_id

    installed = packs[-1].get("installed") or []
    assert installed and isinstance(installed, list)
    installed_path = installed[0].get("path")
    assert installed_path and os.path.exists(installed_path)

    del_resp = client.post(f"/generator_packs/delete/{pack_id}", follow_redirects=False)
    assert del_resp.status_code in (302, 303)
    assert not os.path.exists(installed_path)

    data_resp = client.get("/flag_generators_data")
    assert data_resp.status_code == 200
    data = data_resp.get_json() or {}
    ids = {g.get("id") for g in (data.get("generators") or []) if isinstance(g, dict)}
    assert gen_id not in ids


def test_generator_pack_download_zip_contains_manifest(tmp_path, monkeypatch):
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))

    gen_id = "pack_test_download"
    manifest = f"""manifest_version: 1
id: {gen_id}
kind: flag-generator
name: \"Pack Test: Download\"
runtime:
  type: docker-compose
  compose_file: docker-compose.yml
  service: generator
inputs: []
artifacts:
  requires: []
  produces:
    - filesystem.file
injects: []
"""
    compose = """version: '3.8'
services:
  generator:
    image: python:3.11-slim
    command: [\"python\", \"-c\", \"print('ok')\"]
"""

    zip_bytes = _make_zip(
        {
            f"flag_generators/{gen_id}/manifest.yaml": manifest,
            f"flag_generators/{gen_id}/docker-compose.yml": compose,
            f"flag_generators/{gen_id}/generator.py": "print('hi')\n",
        }
    )

    client = app.test_client()
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (200, 302)

    resp = client.post(
        "/generator_packs/upload",
        data={"zip_file": (io.BytesIO(zip_bytes), "pack.zip")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)

    packs_state = app_backend._load_installed_generator_packs_state()
    packs = packs_state.get("packs") or []
    assert packs and isinstance(packs, list)
    pack_id = packs[-1].get("id")
    assert pack_id

    dl = client.get(f"/generator_packs/download/{pack_id}")
    assert dl.status_code == 200
    assert dl.data[:2] == b"PK"

    z = zipfile.ZipFile(io.BytesIO(dl.data), "r")
    names = set(z.namelist())
    # Archive structure is normalized to flag_generators/<installed_dir>/manifest.yaml
    assert any(n.endswith("/manifest.yaml") and n.startswith("flag_generators/") for n in names)


def test_generator_pack_zip_upload_rejects_missing_manifest(tmp_path, monkeypatch):
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))

    zip_bytes = _make_zip(
        {
            "flag_generators/bad_one/docker-compose.yml": "version: '3.8'\nservices: {generator: {image: busybox}}\n",
            "flag_generators/bad_one/generator.py": "print('hi')\n",
        }
    )

    client = app.test_client()
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (200, 302)

    resp = client.post(
        "/generator_packs/upload",
        data={"zip_file": (io.BytesIO(zip_bytes), "badpack.zip")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)

    # No installed generators directory should be created beyond the root.
    # (The root is created, but no kind subdir should exist.)
    assert not (install_root / "flag_generators").exists()


def test_generator_pack_export_all_is_zip_of_zips(tmp_path, monkeypatch):
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))

    gen_id = "pack_test_export_all"
    manifest = f"""manifest_version: 1
id: {gen_id}
kind: flag-generator
name: \"Pack Test: Export All\"
runtime:
  type: docker-compose
  compose_file: docker-compose.yml
  service: generator
inputs: []
artifacts:
  requires: []
  produces:
    - filesystem.file
injects: []
"""
    compose = """version: '3.8'
services:
  generator:
    image: python:3.11-slim
    command: [\"python\", \"-c\", \"print('ok')\"]
"""

    zip_bytes = _make_zip(
        {
            f"flag_generators/{gen_id}/manifest.yaml": manifest,
            f"flag_generators/{gen_id}/docker-compose.yml": compose,
            f"flag_generators/{gen_id}/generator.py": "print('hi')\n",
        }
    )

    client = app.test_client()
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (200, 302)

    resp = client.post(
        "/generator_packs/upload",
        data={"zip_file": (io.BytesIO(zip_bytes), "pack.zip")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)

    packs_state = app_backend._load_installed_generator_packs_state()
    packs = packs_state.get("packs") or []
    assert packs and isinstance(packs, list)
    pack = packs[-1]
    pack_id = pack.get("id")
    assert pack_id
    label = secure_filename(str(pack.get("label") or "")).strip() or "pack"
    expected_inner = f"packs/{pack_id}-{label}.zip"

    all_dl = client.get("/generator_packs/export_all")
    assert all_dl.status_code == 200
    assert all_dl.data[:2] == b"PK"

    outer = zipfile.ZipFile(io.BytesIO(all_dl.data), "r")
    outer_names = set(outer.namelist())
    assert expected_inner in outer_names

    inner_bytes = outer.read(expected_inner)
    assert inner_bytes[:2] == b"PK"
    inner = zipfile.ZipFile(io.BytesIO(inner_bytes), "r")
    inner_names = set(inner.namelist())
    assert "pack.json" in inner_names
    assert any(n.endswith("/manifest.yaml") and n.startswith("flag_generators/") for n in inner_names)


def test_generator_pack_can_roundtrip_export_all_zip(tmp_path, monkeypatch):
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))

    gen_id = "pack_test_roundtrip"
    manifest = f"""manifest_version: 1
id: {gen_id}
kind: flag-generator
name: \"Pack Test: Roundtrip\"
runtime:
  type: docker-compose
  compose_file: docker-compose.yml
  service: generator
inputs: []
artifacts:
  requires: []
  produces:
    - filesystem.file
injects: []
"""
    compose = """version: '3.8'
services:
  generator:
    image: python:3.11-slim
    command: [\"python\", \"-c\", \"print('ok')\"]
"""

    pack_zip = _make_zip(
        {
            f"flag_generators/{gen_id}/manifest.yaml": manifest,
            f"flag_generators/{gen_id}/docker-compose.yml": compose,
            f"flag_generators/{gen_id}/generator.py": "print('hi')\n",
        }
    )

    client = app.test_client()
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (200, 302)

    up = client.post(
        "/generator_packs/upload",
        data={"zip_file": (io.BytesIO(pack_zip), "pack.zip")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert up.status_code in (302, 303)

    # Export bundle
    bundle = client.get("/generator_packs/export_all")
    assert bundle.status_code == 200
    assert bundle.data[:2] == b"PK"

    # Uninstall all currently installed packs (just one for this test)
    state = app_backend._load_installed_generator_packs_state()
    packs = state.get("packs") or []
    assert packs and isinstance(packs, list)
    for p in list(packs):
        pid = p.get("id")
        assert pid
        d = client.post(f"/generator_packs/delete/{pid}", follow_redirects=False)
        assert d.status_code in (302, 303)

    # Ensure generator no longer discoverable
    data_resp = client.get("/flag_generators_data")
    assert data_resp.status_code == 200
    data = data_resp.get_json() or {}
    ids = {g.get("id") for g in (data.get("generators") or []) if isinstance(g, dict)}
    assert gen_id not in ids

    # Re-import from the export-all zip bundle
    restore = client.post(
        "/generator_packs/upload",
        data={"zip_file": (io.BytesIO(bundle.data), "generator_packs.zip")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert restore.status_code in (302, 303)

    # Generator should be back
    data_resp2 = client.get("/flag_generators_data")
    assert data_resp2.status_code == 200
    data2 = data_resp2.get_json() or {}
    ids2 = {g.get("id") for g in (data2.get("generators") or []) if isinstance(g, dict)}
    assert gen_id in ids2
