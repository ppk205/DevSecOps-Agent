"""Tests for vulnscan.verification.probe (mocked httpx, no network)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from vulnscan.contracts.enums import CWECategory
from vulnscan.contracts.finding import Finding
from vulnscan.verification.probe import (
    MAX_REQUESTS_PER_FINDING,
    AllowlistError,
    ProbeKind,
    RequestBudgetExceeded,
    UnsupportedProbeKindError,
    VerificationProbe,
    _RequestBudget,
    probe_target,
)

HOST = "example.com"
BASE = f"http://{HOST}/app"


def _mock_client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _finding_dict(**overrides: Any) -> dict[str, Any]:
    finding = {"path": "/search", "parameter": "q", "method": "GET"}
    finding.update(overrides)
    return finding


def test_xss_canary_reflected() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        echoed = request.url.params.get("q", "")
        return httpx.Response(200, text=f"<p>results for {echoed}</p>")

    result = probe_target(
        BASE,
        _finding_dict(kind="reflected-xss"),
        allowed_hosts=[HOST],
        client=_mock_client(handler),
    )
    assert isinstance(result, VerificationProbe)
    assert result.kind is ProbeKind.REFLECTED_XSS
    assert result.reflected is True
    assert result.error_based is None
    assert len(result.requests_made) == 1
    assert result.requests_made[0].method == "GET"
    assert result.requests_made[0].status_code == 200
    assert "q=" in seen[0]


def test_xss_canary_unique_per_probe() -> None:
    captured: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("q", "")
        captured.append(value)
        return httpx.Response(200, text=f"echo {value}")

    kwargs: dict[str, Any] = {"allowed_hosts": [HOST]}
    first = probe_target(BASE, _finding_dict(kind="xss"), client=_mock_client(handler), **kwargs)
    second = probe_target(BASE, _finding_dict(kind="xss"), client=_mock_client(handler), **kwargs)
    assert first.reflected and second.reflected
    assert len(captured) == 2
    assert captured[0] != captured[1]
    assert captured[0].startswith("vscn") and captured[1].startswith("vscn")


def test_xss_not_reflected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<p>no results page</p>")

    result = probe_target(
        BASE,
        _finding_dict(kind="reflected-xss"),
        allowed_hosts=[HOST],
        client=_mock_client(handler),
    )
    assert result.reflected is False
    assert len(result.requests_made) == 1


def test_xss_kind_derived_from_finding_cwe() -> None:
    finding = Finding(
        finding_id="f1",
        run_id="r1",
        fingerprint="fp1",
        title="possible xss",
        cwe_category=CWECategory.XSS,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        metadata={"path": "/search", "parameter": "q"},
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=f"echo {request.url.params.get('q', '')}")

    result = probe_target(BASE, finding, allowed_hosts=[HOST], client=_mock_client(handler))
    assert result.kind is ProbeKind.REFLECTED_XSS
    assert result.reflected is True


@pytest.mark.parametrize(
    ("body", "dbms"),
    [
        ("You have an error in your SQL syntax near ''", "mysql"),
        ("Warning: mysql_fetch_array() expects parameter", "mysql"),
        ("unterminated quoted string at character 12", "postgresql"),
        ("invalid input syntax for type integer", "postgresql"),
        ("Unclosed quotation mark after the character string ''", "mssql"),
        ("Microsoft OLE DB Provider for SQL Server error", "mssql"),
        ("ORA-01756: quoted string not properly terminated", "oracle"),
        ('sqlite3.OperationalError: near "\'": syntax error', "sqlite"),
    ],
)
def test_sql_error_signatures_per_dbms(body: str, dbms: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text=body)

    result = probe_target(
        BASE,
        _finding_dict(kind="sql-error", path="/item", parameter="id"),
        allowed_hosts=[HOST],
        client=_mock_client(handler),
    )
    assert result.kind is ProbeKind.SQL_ERROR
    assert result.error_based is True
    assert result.dbms == dbms
    assert result.reflected is None
    assert len(result.requests_made) <= MAX_REQUESTS_PER_FINDING


def test_sql_error_no_match() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<p>normal item page</p>")

    result = probe_target(
        BASE,
        _finding_dict(kind="sqli", path="/item", parameter="id", method="GET"),
        allowed_hosts=[HOST],
        client=_mock_client(handler),
    )
    assert result.error_based is False
    assert result.dbms is None
    assert len(result.requests_made) == 1  # explicit GET: no POST follow-up


def test_sql_error_get_then_post_fallback() -> None:
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, str(request.url)))
        if request.method == "GET":
            return httpx.Response(200, text="<p>normal item page</p>")
        return httpx.Response(500, text="You have an error in your SQL syntax")

    result = probe_target(
        BASE,
        _finding_dict(kind="sql-error", path="/item", parameter="id", method="AUTO"),
        allowed_hosts=[HOST],
        client=_mock_client(handler),
    )
    assert result.error_based is True
    assert result.dbms == "mysql"
    assert [method for method, _ in calls] == ["GET", "POST"]
    assert len(result.requests_made) == 2
    assert len(result.requests_made) <= MAX_REQUESTS_PER_FINDING


def test_evidence_excerpt_is_redacted() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="echo password=supersecret123 done")

    result = probe_target(
        "http://example.com/",
        {"kind": "reflected-xss", "path": "/", "parameter": "name"},
        allowed_hosts=["example.com"],
        client=_mock_client(handler),
    )
    assert "supersecret123" not in result.evidence_excerpt
    assert "password=***" in result.evidence_excerpt


def test_allowlist_rejection_makes_no_request() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, text="should never happen")

    with pytest.raises(AllowlistError):
        probe_target(
            "http://evil.test/",
            _finding_dict(kind="reflected-xss"),
            allowed_hosts=[HOST],
            client=_mock_client(handler),
        )
    assert calls == []


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:8000/",
        "http://127.0.0.1:8000/",
        "http://[::1]:8000/",
        "http://example.com.evil.test/",
        "http://evil.test/?x=example.com",
    ],
)
def test_allowlist_no_localhost_bypass_tricks(base_url: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="should never happen")

    with pytest.raises(AllowlistError):
        probe_target(
            base_url,
            _finding_dict(kind="reflected-xss"),
            allowed_hosts=[HOST],
            client=_mock_client(handler),
        )


def test_allowlist_userinfo_trick_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="should never happen")

    with pytest.raises(AllowlistError):
        probe_target(
            f"http://{HOST}@evil.test/",
            _finding_dict(kind="reflected-xss"),
            allowed_hosts=[HOST],
            client=_mock_client(handler),
        )


def test_allowlist_is_case_insensitive_but_exact() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="plain page")

    result = probe_target(
        "http://EXAMPLE.com/",
        _finding_dict(kind="reflected-xss"),
        allowed_hosts=["example.com"],
        client=_mock_client(handler),
    )
    assert result.reflected is False
    with pytest.raises(AllowlistError):
        probe_target(
            "http://sub.example.com/",
            _finding_dict(kind="reflected-xss"),
            allowed_hosts=["example.com"],
            client=_mock_client(handler),
        )


def test_request_budget_never_exceeded() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="plain page")

    result = probe_target(
        BASE,
        _finding_dict(kind="sql-error", path="/item", parameter="id"),
        allowed_hosts=[HOST],
        client=_mock_client(handler),
    )
    assert len(result.requests_made) <= MAX_REQUESTS_PER_FINDING
    assert MAX_REQUESTS_PER_FINDING == 3


def test_request_budget_guard_raises() -> None:
    budget = _RequestBudget(limit=1)
    budget.consume()
    with pytest.raises(RequestBudgetExceeded):
        budget.consume()


def test_timeout_clamped_to_10s(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    real_client = httpx.Client

    def factory(*args: Any, **kwargs: Any) -> httpx.Client:
        captured.update(kwargs)
        return real_client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="ok")))

    monkeypatch.setattr(httpx, "Client", factory)
    probe_target(BASE, _finding_dict(kind="reflected-xss"), timeout=60, allowed_hosts=[HOST])
    assert float(captured["timeout"]) <= 10.0


def test_unsupported_kind_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    with pytest.raises(UnsupportedProbeKindError):
        probe_target(
            BASE,
            {"path": "/x", "kind": "port-scan"},
            allowed_hosts=[HOST],
            client=_mock_client(handler),
        )
    with pytest.raises(UnsupportedProbeKindError):
        probe_target(
            BASE,
            {"path": "/x"},
            allowed_hosts=[HOST],
            client=_mock_client(handler),
        )


def test_probe_result_is_not_a_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="plain page")

    result = probe_target(
        BASE,
        _finding_dict(kind="reflected-xss"),
        allowed_hosts=[HOST],
        client=_mock_client(handler),
    )
    assert isinstance(result, VerificationProbe)
    assert not isinstance(result, Finding)
    assert not hasattr(result, "finding_id")
