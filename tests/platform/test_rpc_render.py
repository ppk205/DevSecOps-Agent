"""FR-66/67, QR-21: shared native templates need no ASGI request object."""

import threading

import pytest
from starlette.requests import Request

from vulnscan.core.rpc import ServiceRPC
from vulnscan.core.scan_service import ScanService


@pytest.mark.parametrize(
    ("page_path", "run", "active_link"),
    [
        ("/", None, '<a href="/" class="active">Targets</a>'),
        ("/runs/7", {"id": 7}, '<a href="/runs/7" class="active">Run 7</a>'),
        ("/runs/7/findings", {"id": 7}, '<a href="/" class="">Targets</a>'),
    ],
)
def test_native_render_navigation_without_asgi_request(tmp_path, page_path, run, active_link):
    rpc = ServiceRPC(ScanService(str(tmp_path / "render.db")))
    context = {"csrf_token": "synthetic<&", "runs": [], "page_path": page_path}
    if run is not None:
        context["run"] = run
    html = rpc.dispatch(
        "render_page", {"template": "targets.html", "context": context}, "render", threading.Event()
    )
    assert "Target registration" in html
    assert active_link in html
    assert 'value="synthetic&lt;&amp;"' in html


def test_asgi_request_navigation_keeps_precedence(tmp_path):
    rpc = ServiceRPC(ScanService(str(tmp_path / "render.db")))
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/runs/7",
            "scheme": "http",
            "server": ("127.0.0.1", 80),
            "root_path": "",
            "query_string": b"",
            "headers": [],
        }
    )
    html = rpc.dispatch(
        "render_page",
        {"template": "targets.html", "context": {"request": request, "page_path": "/", "run": {"id": 7}}},
        "render",
        threading.Event(),
    )
    assert '<a href="/runs/7" class="active">Run 7</a>' in html


@pytest.mark.parametrize("template", ["base.html", "../targets.html", "../../.env"])
def test_render_template_allowlist_remains_confined(tmp_path, template):
    rpc = ServiceRPC(ScanService(str(tmp_path / "render.db")))
    with pytest.raises(ValueError, match="unknown dashboard template"):
        rpc.dispatch(
            "render_page", {"template": template, "context": {}}, "render", threading.Event()
        )
