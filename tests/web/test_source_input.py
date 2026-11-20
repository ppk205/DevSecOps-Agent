"""FR-01/71: legacy web input accepts local folders and optional commit pins."""

from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from vulnscan.web import app as web


def test_fr01_web_form_accepts_a_plain_folder_without_a_commit(tmp_path, monkeypatch):
    folder = tmp_path / "plain folder"
    folder.mkdir()
    (folder / "Example.java").touch()
    calls = []

    class Recorder:
        def __init__(self, db_path):
            pass

        def run(self, checkout, config, **kwargs):
            calls.append((checkout, kwargs))
            return {"id": 1}

    monkeypatch.setattr(web, "ScanService", Recorder)
    engine = create_engine(f"sqlite:///{tmp_path / 'web.db'}")
    with TestClient(web.create_app(engine, tmp_path / "exports")) as client:
        token = client.get("/api/csrf").json()["csrf_token"]
        response = client.post(
            "/scans",
            data={"target_repository_url": str(folder)},
            headers={"X-CSRF-Token": token},
            follow_redirects=False,
        )
    assert response.status_code == 303, response.text
    assert calls == [(str(folder), {"repo": str(folder), "expected_commit": "no-revision"})]


def test_fr01_web_form_does_not_require_a_url_or_commit(tmp_path, monkeypatch):
    module_path = Path(web.__file__).resolve()
    bundle_dirs = {
        module_path.with_name("static") / "app",
        module_path.parents[3] / "web-ui" / "dist",
    }
    is_dir = Path.is_dir
    monkeypatch.setattr(Path, "is_dir", lambda path: path not in bundle_dirs and is_dir(path))
    engine = create_engine(f"sqlite:///{tmp_path / 'form.db'}")
    with TestClient(web.create_app(engine, tmp_path / "exports")) as client:
        response = client.get("/")
    assert response.status_code == 200
    assert response.headers["X-Pitwall-Legacy"] == "true"
    assert 'name="target_repository_url" type="text"' in response.text
    assert 'name="target_commit_sha" minlength="7" required' not in response.text
