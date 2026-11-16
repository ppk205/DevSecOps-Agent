"""FR-75: outbound webhooks validate and pin their destination."""

import hashlib
import hmac
import socket

import pytest

from vulnscan.notifications.webhook import send_webhook


def test_signature_and_validated_socket_address(monkeypatch):
    from vulnscan.notifications import webhook

    monkeypatch.setenv("TEST_HOOK_URL", "https://hooks.example.com/private?token=synthetic")
    monkeypatch.setenv("TEST_HOOK_KEY", "k" * 32)
    monkeypatch.setattr(webhook.time, "time", lambda: 1700000000)
    lookups = []
    monkeypatch.setattr(
        webhook.socket,
        "getaddrinfo",
        lambda *args, **kwargs: (
            lookups.append(args) or [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
        ),
    )
    sent = {}

    class FakeConnection:
        def __init__(self, host, port, timeout, address):
            sent.update(host=host, port=port, timeout=timeout, address=address)

        def request(self, method, path, body, headers):
            sent.update(method=method, path=path, body=body, headers=headers)

        def getresponse(self):
            class Response:
                status = 204

                def read(self, limit):
                    return b""

            return Response()

        def close(self):
            pass

    monkeypatch.setattr(webhook, "_PinnedHTTPSConnection", FakeConnection)
    body = b'{"ok":true}'
    result = send_webhook(
        body,
        delivery_id="id-1",
        url_env="TEST_HOOK_URL",
        signing_key_env="TEST_HOOK_KEY",
        allowed_hosts=["hooks.example.com"],
    )
    assert result.status == "sent"
    assert len(lookups) == 1
    assert sent["host"] == "hooks.example.com"
    assert sent["address"][4] == ("8.8.8.8", 443)
    assert (
        sent["headers"]["X-DevSecOps-Signature"]
        == "sha256=" + hmac.new(b"k" * 32, b"1700000000." + body, hashlib.sha256).hexdigest()
    )


def test_connection_uses_validated_ip_and_original_tls_name(monkeypatch):
    from vulnscan.notifications import webhook

    calls = {}

    class FakeSocket:
        def settimeout(self, timeout):
            calls["timeout"] = timeout

        def connect(self, address):
            calls["address"] = address

        def close(self):
            pass

    class FakeContext:
        verify_mode = 2
        check_hostname = True

        def wrap_socket(self, sock, server_hostname):
            calls["server_hostname"] = server_hostname
            return sock

    monkeypatch.setattr(webhook.socket, "socket", lambda *a: FakeSocket())
    monkeypatch.setattr(webhook.ssl, "create_default_context", FakeContext)
    connection = webhook._PinnedHTTPSConnection(
        "hooks.example.com", 443, 5.0, (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))
    )
    connection.connect()
    assert calls == {
        "timeout": 5.0,
        "address": ("8.8.8.8", 443),
        "server_hostname": "hooks.example.com",
    }


@pytest.mark.parametrize(
    "ip", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1"]
)
def test_private_dns_answers_prevent_connection(monkeypatch, ip):
    from vulnscan.notifications import webhook

    monkeypatch.setenv("TEST_HOOK_URL", "https://hooks.example.com/private")
    monkeypatch.setenv("TEST_HOOK_KEY", "k" * 32)
    monkeypatch.setattr(
        webhook.socket,
        "getaddrinfo",
        lambda *a, **k: [
            (socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))
        ],
    )
    monkeypatch.setattr(webhook, "_PinnedHTTPSConnection", lambda *a, **k: pytest.fail("connected"))
    result = send_webhook(
        b"{}",
        delivery_id="id",
        url_env="TEST_HOOK_URL",
        signing_key_env="TEST_HOOK_KEY",
        allowed_hosts=["hooks.example.com"],
    )
    assert result.status == "unconfigured"


def test_short_signing_key_never_resolves(monkeypatch):
    from vulnscan.notifications import webhook

    monkeypatch.setenv("TEST_HOOK_URL", "https://hooks.example.com/private")
    monkeypatch.setenv("TEST_HOOK_KEY", "k" * 31)
    monkeypatch.setattr(webhook.socket, "getaddrinfo", lambda *a, **k: pytest.fail("resolved"))
    assert (
        send_webhook(
            b"{}",
            delivery_id="id",
            url_env="TEST_HOOK_URL",
            signing_key_env="TEST_HOOK_KEY",
            allowed_hosts=["hooks.example.com"],
        ).status
        == "unconfigured"
    )


def test_changed_destination_after_claim_is_rejected_before_dns(monkeypatch):
    from vulnscan.notifications import webhook

    monkeypatch.setenv("TEST_HOOK_URL", "https://hooks.example.com/first")
    monkeypatch.setenv("TEST_HOOK_KEY", "k" * 32)
    fingerprint = webhook.destination_fingerprint(
        "https://hooks.example.com/first", "TEST_HOOK_URL", "TEST_HOOK_KEY", ["hooks.example.com"]
    )
    monkeypatch.setenv("TEST_HOOK_URL", "https://hooks.example.com/second")
    monkeypatch.setattr(webhook.socket, "getaddrinfo", lambda *a, **k: pytest.fail("resolved"))
    result = send_webhook(
        b"{}",
        delivery_id="id",
        url_env="TEST_HOOK_URL",
        signing_key_env="TEST_HOOK_KEY",
        allowed_hosts=["hooks.example.com"],
        expected_fingerprint=fingerprint,
    )
    assert result.status == "unconfigured"


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.example.com/path",
        "https://hooks.example.com:444/path",
        "https://user@hooks.example.com/path",
        "https://hooks.example.com/path#fragment",
        "https://hooks.example.com/path#",
        "https://8.8.8.8/path",
        "https://other.example.com/path",
        "https://hooks.example.com/invalid\npath",
    ],
)
def test_bad_destination_is_rejected_before_dns(monkeypatch, url):
    from vulnscan.notifications import webhook

    monkeypatch.setenv("TEST_HOOK_URL", url)
    monkeypatch.setenv("TEST_HOOK_KEY", "k" * 32)
    monkeypatch.setattr(webhook.socket, "getaddrinfo", lambda *a, **k: pytest.fail("resolved"))
    assert (
        send_webhook(
            b"{}",
            delivery_id="id",
            url_env="TEST_HOOK_URL",
            signing_key_env="TEST_HOOK_KEY",
            allowed_hosts=["hooks.example.com"],
        ).status
        == "unconfigured"
    )


def test_mixed_dns_answers_are_rejected(monkeypatch):
    from vulnscan.notifications import webhook

    monkeypatch.setenv("TEST_HOOK_URL", "https://hooks.example.com/path")
    monkeypatch.setenv("TEST_HOOK_KEY", "k" * 32)
    monkeypatch.setattr(
        webhook.socket,
        "getaddrinfo",
        lambda *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))
            for ip in ("8.8.8.8", "127.0.0.1")
        ],
    )
    monkeypatch.setattr(webhook, "_PinnedHTTPSConnection", lambda *a, **k: pytest.fail("connected"))
    assert (
        send_webhook(
            b"{}",
            delivery_id="id",
            url_env="TEST_HOOK_URL",
            signing_key_env="TEST_HOOK_KEY",
            allowed_hosts=["hooks.example.com"],
        ).status
        == "unconfigured"
    )


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (200, "sent"),
        (202, "sent"),
        (204, "sent"),
        (301, "failed"),
        (307, "failed"),
        (400, "failed"),
        (429, "failed"),
        (500, "failed"),
    ],
)
def test_http_response_is_not_retried(monkeypatch, status, expected):
    from vulnscan.notifications import webhook

    monkeypatch.setenv("TEST_HOOK_URL", "https://hooks.example.com/secret")
    monkeypatch.setenv("TEST_HOOK_KEY", "k" * 32)
    monkeypatch.setattr(
        webhook.socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))],
    )
    requests = []

    class FakeConnection:
        def __init__(self, *args):
            pass

        def request(self, *args, **kwargs):
            requests.append(1)

        def getresponse(self):
            class Response:
                def read(self, limit):
                    return b"private response"

            response = Response()
            response.status = status
            return response

        def close(self):
            pass

    monkeypatch.setattr(webhook, "_PinnedHTTPSConnection", FakeConnection)
    result = send_webhook(
        b"{}",
        delivery_id="id",
        url_env="TEST_HOOK_URL",
        signing_key_env="TEST_HOOK_KEY",
        allowed_hosts=["hooks.example.com"],
    )
    assert result.status == expected
    assert requests == [1]
    assert "secret" not in result.detail and "private" not in result.detail


@pytest.mark.parametrize("failure", ["timeout", "oversize"])
def test_unacknowledged_delivery_is_unknown_and_not_retried(monkeypatch, failure):
    from vulnscan.notifications import webhook

    monkeypatch.setenv("TEST_HOOK_URL", "https://hooks.example.com/private")
    monkeypatch.setenv("TEST_HOOK_KEY", "k" * 32)
    monkeypatch.setattr(
        webhook.socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))],
    )
    requests = []

    class FakeConnection:
        def __init__(self, *args):
            pass

        def request(self, *args, **kwargs):
            requests.append(1)
            if failure == "timeout":
                raise TimeoutError("synthetic private URL")

        def getresponse(self):
            class Response:
                status = 200

                def read(self, limit):
                    return b"x" * limit

            return Response()

        def close(self):
            pass

    monkeypatch.setattr(webhook, "_PinnedHTTPSConnection", FakeConnection)
    result = send_webhook(
        b"{}",
        delivery_id="id",
        url_env="TEST_HOOK_URL",
        signing_key_env="TEST_HOOK_KEY",
        allowed_hosts=["hooks.example.com"],
    )
    assert result.status == "unknown"
    assert requests == [1]
    assert "private" not in result.detail
