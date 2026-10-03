"""FR-66/67: native HTTP routes, CSRF, escaping and projection consistency."""

import os
import socket
import subprocess
import sys
import time

import httpx
import pytest

from tests.platform.test_native import BINARY
from tests.platform.test_scan_service import checkout, service, settings

__all__ = ["checkout", "service"]
pytestmark = pytest.mark.skipif(
    not BINARY.is_file(), reason="build Go before native dashboard tests"
)


def test_native_dashboard_routes_csrf_and_exports(service, checkout, tmp_path):
    result = service.run(str(checkout), settings(tmp_path))
    finding = service.detail(result["id"])["findings"][0]
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    env = {
        **os.environ,
        "DEVSECOPS_PYTHON": sys.executable,
        "DEVSECOPS_RPC_MODULE": "tests.platform.rpc_fixture",
    }
    process = subprocess.Popen(
        [
            str(BINARY),
            "serve",
            "--db-path",
            service.db_path,
            "--port",
            str(port),
            "--out",
            str(tmp_path / "web-reports"),
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        with httpx.Client(
            base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=5
        ) as client:
            for _ in range(100):
                try:
                    home = client.get("/")
                    break
                except httpx.ConnectError:
                    time.sleep(0.05)
            else:
                pytest.fail("Native dashboard did not start")
            assert home.status_code == 200, home.text
            assert "Target registration" in home.text
            assert client.get(f"/runs/{result['id']}").status_code == 200
            assert client.get(f"/runs/{result['id']}/findings").status_code == 200
            route = f"/findings/{finding['finding_id']}/status"
            assert client.post(route, data={"status": "rejected"}).status_code == 403
            token = client.cookies["vulnscan_csrf"]
            assert (
                client.post(route, data={"status": "rejected", "_csrf": token}).status_code == 303
            )
            assert service.finding_page(result["id"], "status:rejected")["total"] == 1
            counts = client.get(f"/api/runs/{result['id']}").json()["counts"]
            assert counts["rejected"] == 1
            for fmt in ("json", "sarif", "html", "markdown"):
                export = client.get(f"/runs/{result['id']}/export/{fmt}")
                assert export.status_code == 200, export.text
                assert "attachment" in export.headers["Content-Disposition"]
    finally:
        process.terminate()
        process.wait(timeout=10)
        if process.stderr:
            process.stderr.close()
