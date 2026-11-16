"""FR-66: the current web application is the default landing page."""

from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from vulnscan.storage.database import migrate
from vulnscan.web.app import create_app


def test_root_redirects_to_current_app(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    migrate(engine)
    with TestClient(create_app(engine=engine, export_dir=tmp_path / "exports")) as client:
        response = client.get("/", follow_redirects=False)
    assert response.status_code in (302, 303, 307, 308)
    assert response.headers["location"] == "/app/"
    assert "X-Pitwall-Legacy" not in response.headers
