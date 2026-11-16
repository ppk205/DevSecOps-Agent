"""Signed summary delivery with a DNS-validated, pinned HTTPS connection."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import socket
import ssl
import time
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlsplit

from .settings import WebhookSettings
from .transports import DeliveryResult


def destination_fingerprint(
    url: str, url_env: str, signing_key_env: str, hosts: Sequence[str]
) -> str:
    material = json.dumps(
        [url, url_env, signing_key_env, list(hosts)], ensure_ascii=False, separators=(",", ":")
    )
    return hashlib.sha256(material.encode()).hexdigest()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, timeout: float, address: tuple[Any, ...]) -> None:
        self._tls_context = ssl.create_default_context()
        super().__init__(host, port=port, timeout=timeout, context=self._tls_context)
        self._address = address

    def connect(self) -> None:
        family, socktype, protocol, _, sockaddr = self._address
        sock = socket.socket(family, socktype, protocol)
        try:
            sock.settimeout(self.timeout)
            sock.connect(sockaddr)
            self.sock = self._tls_context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def send_webhook(
    body: bytes,
    *,
    delivery_id: str,
    url_env: str = "DEVSEC_WEBHOOK_URL",
    signing_key_env: str = "DEVSEC_WEBHOOK_SIGNING_SECRET",
    allowed_hosts: Sequence[str],
    timeout: float = 5.0,
    expected_fingerprint: str | None = None,
) -> DeliveryResult:
    url = os.environ.get(url_env, "")
    secret = os.environ.get(signing_key_env, "").encode("utf-8")
    invalid = DeliveryResult("unconfigured", "Webhook destination or signing key is invalid")
    if (
        expected_fingerprint is not None
        and destination_fingerprint(url, url_env, signing_key_env, allowed_hosts)
        != expected_fingerprint
    ):
        return invalid
    if (
        len(secret) < 32
        or len(body) > 16384
        or not delivery_id
        or any(ord(c) < 33 or ord(c) > 126 for c in delivery_id)
    ):
        return invalid
    try:
        if "#" in url or any(ord(c) <= 32 or ord(c) == 127 for c in url):
            return invalid
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.port not in (None, 443)
            or not parsed.hostname
        ):
            return invalid
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        normalized = WebhookSettings(allowed_hosts=list(allowed_hosts)).allowed_hosts
        if host not in normalized:
            return invalid
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        if not addresses:
            return invalid
        for item in addresses:
            ip = ipaddress.ip_address(item[4][0])
            if not ip.is_global or (
                isinstance(ip, ipaddress.IPv6Address)
                and ip.ipv4_mapped is not None
                and not ip.ipv4_mapped.is_global
            ):
                return invalid
    except (ValueError, UnicodeError, OSError):
        return invalid

    timestamp = str(int(time.time()))
    signature = hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    connection = None
    try:
        connection = _PinnedHTTPSConnection(host, 443, timeout, addresses[0])
        connection.request(
            "POST",
            path,
            body=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "DevSecOps-Agent",
                "X-DevSecOps-Delivery": delivery_id,
                "X-DevSecOps-Timestamp": timestamp,
                "X-DevSecOps-Signature": "sha256=" + signature,
            },
        )
        response = connection.getresponse()
        data = response.read(65537)
        if len(data) > 65536:
            return DeliveryResult("unknown", "Webhook acknowledgement exceeded the response limit")
        if 200 <= response.status < 300:
            return DeliveryResult("sent", "Webhook HTTP request acknowledged", response.status)
        return DeliveryResult("failed", "Webhook HTTP request was rejected", response.status)
    except (OSError, http.client.HTTPException, ValueError):
        return DeliveryResult(
            "unknown", "Delivery was not acknowledged; remote acceptance is unknown"
        )
    finally:
        if connection is not None:
            connection.close()
