"""Authenticated remote relay, replay, typed confirms and safe SPA fallback."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from tests.harness.test_host_clients import make_host
from vulnscan.harness.remote import RemoteServer, create_remote_app, issue_token, remote_url


def login(client, token):
    bootstrap = client.get("/api/remote/state")
    csrf = bootstrap.json()["csrf_token"]
    response = client.post(
        "/api/remote/login", json={"token": token}, headers={"X-CSRF-Token": csrf}
    )
    return response, csrf


def test_login_token_is_single_use_and_expires(tmp_path):
    host, _, _ = make_host(tmp_path)
    token = issue_token()
    app = create_remote_app(host, token, None)
    with TestClient(app) as client:
        response, csrf = login(client, token)
        assert response.status_code == 200
        assert "HttpOnly" in response.headers["set-cookie"]
        assert client.cookies.get("devsec_remote")
        assert (
            client.post(
                "/api/remote/login", json={"token": token}, headers={"X-CSRF-Token": csrf}
            ).status_code
            == 401
        )
    expired = create_remote_app(host, issue_token(), None)
    expired.state.clock = lambda: expired.state.issued_at + 601
    with TestClient(expired) as client:
        assert login(client, expired.state.login_token)[0].status_code == 401
    assert remote_url(1234, "test") == "http://127.0.0.1:1234/app/remote#t=test"
    host.close()


def test_post_without_csrf_is_403(tmp_path):
    host, _, _ = make_host(tmp_path)
    token = issue_token()
    with TestClient(create_remote_app(host, token, None)) as client:
        assert login(client, token)[0].status_code == 200
        assert client.post("/api/remote/messages", json={"type": "interrupt"}).status_code == 403
        csrf = client.cookies["csrf_token"]
        assert (
            client.post(
                "/api/remote/messages",
                json={"type": "interrupt"},
                headers={"X-CSRF-Token": csrf, "Origin": "https://evil.example"},
            ).status_code
            == 403
        )
    host.close()


def test_state_contains_pending_request_and_redacts(tmp_path):
    host, _, arrived = make_host(tmp_path)
    host.attach("tui", "tui")
    host.start()
    assert arrived.wait(5)
    secret = "sk-ant-" + "x" * 24
    host.publish({"type": "text_delta", "text": secret})
    token = issue_token()
    with TestClient(create_remote_app(host, token, None)) as client:
        assert login(client, token)[0].status_code == 200
        state = client.get("/api/remote/state").json()
        assert state["pending"]["gate"] == "G0"
        assert state["ready"]["session_log"]
        host.close()
        response = client.get("/api/remote/events?after=1")
        data = [
            json.loads(line[6:]) for line in response.text.splitlines() if line.startswith("data: ")
        ]
        assert [e["seq"] for e in data] == list(range(2, data[-1]["seq"] + 1))
        assert secret not in response.text and "[REDACTED]" in response.text


def test_spa_served_when_built(tmp_path):
    host, _, _ = make_host(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<main>remote</main>")
    (dist / "asset.js").write_text("console.log('asset')")
    with TestClient(create_remote_app(host, issue_token(), dist)) as client:
        assert client.get("/app/remote").text == "<main>remote</main>"
        assert client.get("/app/asset.js").text == "console.log('asset')"
        assert client.get("/app/%2e%2e/s.jsonl").status_code == 404
    host.close()


def test_non_loopback_server_requires_flag(tmp_path):
    host, _, _ = make_host(tmp_path)
    with pytest.raises(ValueError, match="remote-allow-lan"):
        RemoteServer(host, bind="0.0.0.0")
    host.close()


def test_headless_sse_disconnect_interrupts_pending_gate(tmp_path):
    host, _, arrived = make_host(tmp_path, "auto")
    server = RemoteServer(host)
    try:
        server.start()
        assert server.url.startswith("http://127.0.0.1:")
        assert host.start()
        assert arrived.wait(5)
        assert not host.started
        with httpx.Client(base_url=f"http://127.0.0.1:{server.port}", timeout=5) as client:
            csrf = client.get("/api/remote/state").json()["csrf_token"]
            assert (
                client.post(
                    "/api/remote/login",
                    json={"token": server.token},
                    headers={"X-CSRF-Token": csrf},
                ).status_code
                == 200
            )
            with client.stream("GET", "/api/remote/events?after=0") as stream:
                for line in stream.iter_lines():
                    if (
                        line.startswith("data: ")
                        and json.loads(line[6:])["type"] == "permission_request"
                    ):
                        break
            assert host.wait_idle(5)
            assert not host.started
            assert any(
                e["type"] == "gate" and e["choice"] == "undecided"
                for e in host.session.ctx.log.events()
            )
    finally:
        server.close()
        server.wait(5)
        host.close()


def test_run_headless_waits_for_consent_and_closes(tmp_path, monkeypatch, capsys):
    from vulnscan.harness.remote import run_headless

    host, _, arrived = make_host(tmp_path, "auto")
    monkeypatch.setattr("vulnscan.harness.rpc.build_host", lambda options, emit: host)
    closed = []

    class Server:
        def __init__(self, session_host, **kwargs):
            assert session_host is host
            self.url = "http://127.0.0.1:1234/app/remote#t=fixture"

        def start(self):
            assert not host.busy

        def wait(self):
            assert arrived.wait(5)
            assert not host.started
            raise KeyboardInterrupt

        def close(self):
            closed.append(True)

    monkeypatch.setattr("vulnscan.harness.remote.RemoteServer", Server)
    assert run_headless(target=host.session.ctx.ws.target, model="test", mode="auto") == 0
    assert "#t=fixture" in capsys.readouterr().out
    assert closed and host.closed


def test_run_headless_refuses_lan_without_flag(tmp_path, capsys):
    from vulnscan.harness.remote import run_headless

    assert run_headless(target=tmp_path, model="test", remote_host="0.0.0.0") == 2
    assert "remote-allow-lan" in capsys.readouterr().out
