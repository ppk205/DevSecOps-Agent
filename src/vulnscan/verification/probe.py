"""Targeted HTTP verification probes (assisted DAST, opt-in).

Only two probe kinds exist, and both are strictly read-only checks against a
target the operator explicitly allowlists:

- ``reflected-xss``: GET the vulnerable path with a unique random canary
  token in the flagged parameter; report whether the token is reflected.
- ``sql-error``: GET (then POST if needed) with a single quote appended to
  the flagged parameter; match the response against known DB error
  signatures (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) and report the
  DBMS guess.

Safety rules enforced here (not by convention elsewhere):

- The target host must appear in the explicit ``allowed_hosts`` argument,
  matched exactly after lowercasing (so ``localhost`` never implies
  ``127.0.0.1``/``[::1]`` and vice versa). Anything else raises
  :class:`AllowlistError` before any request is made.
- Only ``http``/``https`` URLs are probed.
- The per-probe timeout is clamped to :data:`MAX_TIMEOUT_SECONDS` (10s).
- At most :data:`MAX_REQUESTS_PER_FINDING` (3) requests are made per
  finding; every request is logged and returned in ``requests_made``.
- Redirects are not followed, so a probe can never be bounced to an
  off-allowlist host.

This module never creates findings. It returns a :class:`VerificationProbe`
value object; promoting or rejecting a finding from that result is the
validator's job, not this module's.
"""

from __future__ import annotations

import logging
import re
import secrets
from collections.abc import Mapping
from enum import Enum
from typing import TYPE_CHECKING, Any

import httpx
from pydantic import Field

from vulnscan.contracts._base import VersionedModel

if TYPE_CHECKING:  # pragma: no cover - typing only, never constructed here
    from vulnscan.contracts.finding import Finding

logger = logging.getLogger(__name__)

#: Hard ceiling for any single probe request (seconds). Larger ``timeout``
#: arguments are clamped down to this value.
MAX_TIMEOUT_SECONDS = 10.0

#: Hard ceiling on HTTP requests per finding, across both probe kinds.
MAX_REQUESTS_PER_FINDING = 3

#: Maximum characters kept in ``evidence_excerpt`` after redaction.
EVIDENCE_EXCERPT_LIMIT = 500

_CANARY_BYTES = 8
_CANARY_PREFIX = "vscn"

__all__ = [
    "EVIDENCE_EXCERPT_LIMIT",
    "MAX_REQUESTS_PER_FINDING",
    "MAX_TIMEOUT_SECONDS",
    "AllowlistError",
    "ProbeKind",
    "ProbedRequest",
    "RequestBudgetExceeded",
    "UnsupportedProbeKindError",
    "VerificationProbe",
    "probe_target",
]


class ProbeKind(str, Enum):
    """The only two probe kinds this module supports."""

    REFLECTED_XSS = "reflected-xss"
    SQL_ERROR = "sql-error"


class AllowlistError(ValueError):
    """Raised when a probe target host is not explicitly allowlisted.

    Raised before any network request is made.
    """


class UnsupportedProbeKindError(ValueError):
    """Raised when the probe kind cannot be resolved to a supported kind."""


class RequestBudgetExceeded(RuntimeError):
    """Raised if a probe would exceed ``MAX_REQUESTS_PER_FINDING``."""


class ProbedRequest(VersionedModel):
    """One HTTP request made by a probe, kept for auditability."""

    method: str = Field(..., description="HTTP method used, e.g. 'GET'.")
    url: str = Field(..., description="Full URL requested (without secrets).")
    status_code: int | None = Field(
        default=None,
        description="Response status, or None if no response was received.",
    )


class VerificationProbe(VersionedModel):
    """Outcome of probing one finding. Never a finding itself."""

    kind: ProbeKind = Field(..., description="Which of the two probe kinds ran.")
    reflected: bool | None = Field(
        default=None,
        description="Reflected-XSS probes only: canary echoed in the response.",
    )
    error_based: bool | None = Field(
        default=None,
        description="SQL-error probes only: a known DB error signature matched.",
    )
    dbms: str | None = Field(
        default=None,
        description="SQL-error probes only: DBMS guess (mysql, postgresql, ...).",
    )
    evidence_excerpt: str = Field(
        default="",
        description="Redacted, truncated response excerpt backing the verdict.",
    )
    requests_made: list[ProbedRequest] = Field(
        default_factory=list,
        description="Every request the probe made, in order.",
    )


#: Case-insensitive DB error signatures keyed by DBMS guess. Each entry is
#: deliberately DBMS-specific so a match names exactly one engine.
_DB_ERROR_SIGNATURES: dict[str, tuple[str, ...]] = {
    "mysql": (
        "you have an error in your sql syntax",
        "warning: mysql",
        "mysqli",
        "mysql_fetch",
        "mysql_num_rows",
        "valid mysql result",
    ),
    "postgresql": (
        "unterminated quoted string",
        "syntax error at or near",
        "invalid input syntax for",
        "pg_query()",
        "postgresql",
        "psql:",
        "npgsql",
    ),
    "mssql": (
        "unclosed quotation mark after the character string",
        "microsoft ole db provider for sql server",
        "odbc sql server driver",
        "[sql server]",
        "system.data.sqlclient",
    ),
    "oracle": (
        "quoted string not properly terminated",
        "oracle error",
        "ora-",
        "oci_",
    ),
    "sqlite": (
        "sqlite3::",
        "sqlite_error",
        "sqlite exception",
        "sqlite3.operationalerror",
    ),
}

_XSS_ALIASES = {"xss", "reflected-xss", "reflectedxss", "reflected_xss"}
_SQL_ALIASES = {"sqli", "sql-error", "sqlerror", "sql_error", "sql-injection", "sqlinjection"}

# ``key=value`` / ``key: value`` secrets are masked before being stored.
_REDACT_PATTERN = re.compile(
    r"(?i)((?:passw(?:or)?d|passwd|pwd|secret|api[_-]?key|token|sessionid|auth)\s*[:=]\s*)([^\s&;\"']+)"
)


def _redact(text: str) -> str:
    """Mask credential-looking values so excerpts are safe to persist."""
    return _REDACT_PATTERN.sub(r"\1***", text or "")


def _excerpt(body: str, needle: str = "", *, case_sensitive: bool = True) -> str:
    """Return a redacted excerpt, preferring a window around ``needle``."""
    text = _redact(body or "")
    if needle:
        haystack = text if case_sensitive else text.lower()
        key = needle if case_sensitive else needle.lower()
        pos = haystack.find(key)
        if pos >= 0:
            start = max(0, pos - 200)
            return text[start : start + EVIDENCE_EXCERPT_LIMIT]
    return text[:EVIDENCE_EXCERPT_LIMIT]


def _normalize_host(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


def _checked_url(base_url: str, path: str, allowed_hosts: Any) -> str:
    """Join ``path`` onto ``base_url`` and enforce the host allowlist.

    Both the base URL and the final joined URL must carry an allowlisted
    host, so a finding path that is itself an absolute off-allowlist URL
    cannot smuggle a probe elsewhere.
    """
    allowed = {_normalize_host(h) for h in (allowed_hosts or ()) if str(h).strip()}
    try:
        base = httpx.URL(base_url)
    except Exception as exc:
        raise AllowlistError(f"refusing to probe unparseable URL {base_url!r}") from exc
    if base.scheme not in ("http", "https") or not base.host:
        raise AllowlistError(f"refusing to probe non-http(s) or hostless URL {base_url!r}")
    if _normalize_host(base.host) not in allowed:
        logger.warning("probe target host %r is not allowlisted; refusing", base.host)
        raise AllowlistError(f"probe target host {base.host!r} is not in the allowlist")
    from urllib.parse import urljoin as _urljoin

    final = httpx.URL(_urljoin(str(base), path or "/"))
    if _normalize_host(final.host or "") not in allowed:
        logger.warning("probe path escapes allowlisted host %r; refusing", final.host)
        raise AllowlistError(f"probe path target host {final.host!r} is not in the allowlist")
    return str(final)


def _effective_timeout(timeout: float) -> float:
    try:
        value = float(timeout)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"timeout must be a number, got {timeout!r}") from exc
    if value <= 0:
        raise ValueError(f"timeout must be positive, got {timeout!r}")
    if value > MAX_TIMEOUT_SECONDS:
        logger.info("clamping probe timeout %s to %ss", value, MAX_TIMEOUT_SECONDS)
    return min(value, MAX_TIMEOUT_SECONDS)


class _RequestBudget:
    """Counts probe requests; refuses to exceed ``MAX_REQUESTS_PER_FINDING``."""

    def __init__(self, limit: int = MAX_REQUESTS_PER_FINDING) -> None:
        self._remaining = limit

    def consume(self) -> None:
        if self._remaining <= 0:
            raise RequestBudgetExceeded(
                f"probe would exceed {MAX_REQUESTS_PER_FINDING} requests per finding"
            )
        self._remaining -= 1


def _hints_of(finding: Finding | Mapping[str, Any]) -> dict[str, Any]:
    """Read probe hints (path/parameter/method/kind) off any finding shape."""
    if isinstance(finding, Mapping):
        return dict(finding)
    hints: dict[str, Any] = {}
    metadata = getattr(finding, "metadata", None)
    if isinstance(metadata, dict):
        hints.update(metadata)
    for attr in ("path", "parameter", "param", "method", "kind", "probe_kind"):
        value = getattr(finding, attr, None)
        if value is not None:
            hints.setdefault(attr, value)
    cwe = getattr(finding, "cwe_category", None)
    if cwe is not None:
        hints.setdefault("cwe_category", getattr(cwe, "value", cwe))
    return hints


def _kind_from_cwe(cwe: Any) -> str:
    text = str(cwe or "")
    if "79" in text:
        return "reflected-xss"
    if "89" in text:
        return "sql-error"
    raise UnsupportedProbeKindError(
        f"cannot derive probe kind from {cwe!r}; pass kind='reflected-xss' or kind='sql-error'"
    )


def _normalize_kind(raw: Any) -> ProbeKind:
    key = str(raw or "").strip().lower().replace("_", "-")
    if key in _XSS_ALIASES:
        return ProbeKind.REFLECTED_XSS
    if key in _SQL_ALIASES:
        return ProbeKind.SQL_ERROR
    raise UnsupportedProbeKindError(
        f"unsupported probe kind {raw!r}; only 'reflected-xss' and 'sql-error' are supported"
    )


def _match_dbms(body: str) -> tuple[str | None, str | None]:
    """Return (dbms, matched_signature) for the first known error signature."""
    lowered = (body or "").lower()
    for dbms, signatures in _DB_ERROR_SIGNATURES.items():
        for signature in signatures:
            if signature in lowered:
                return dbms, signature
    return None, None


def _do_request(
    client: httpx.Client,
    budget: _RequestBudget,
    records: list[ProbedRequest],
    method: str,
    url: str,
    params: dict[str, str] | None = None,
    data: dict[str, str] | None = None,
) -> httpx.Response | None:
    """Make one budgeted, logged request; return None on transport failure."""
    budget.consume()
    label = f"{method} {url}"
    logger.info("probe request: %s params=%s", label, bool(params or data))
    record = ProbedRequest(method=method, url=url, status_code=None)
    records.append(record)
    try:
        if method == "POST":
            response = client.post(url, data=data or {})
        else:
            response = client.get(url, params=params or {})
    except httpx.HTTPError as exc:
        logger.warning("probe request failed: %s (%s)", label, exc)
        return None
    record.status_code = response.status_code
    logger.info("probe response: %s -> %s", label, response.status_code)
    return response


def _probe_xss(
    client: httpx.Client,
    budget: _RequestBudget,
    records: list[ProbedRequest],
    url: str,
    parameter: str,
) -> VerificationProbe:
    canary = f"{_CANARY_PREFIX}{secrets.token_hex(_CANARY_BYTES)}"
    response = _do_request(client, budget, records, "GET", url, params={parameter: canary})
    body = response.text if response is not None else ""
    reflected = canary in body
    logger.info("xss probe: reflected=%s requests=%d", reflected, len(records))
    return VerificationProbe(
        kind=ProbeKind.REFLECTED_XSS,
        reflected=reflected,
        evidence_excerpt=_excerpt(body, canary) if reflected else _excerpt(body),
        requests_made=list(records),
    )


def _probe_sql_error(
    client: httpx.Client,
    budget: _RequestBudget,
    records: list[ProbedRequest],
    url: str,
    parameter: str,
    method_hint: str,
) -> VerificationProbe:
    payload = "'"
    response = _do_request(client, budget, records, "GET", url, params={parameter: payload})
    body = response.text if response is not None else ""
    dbms, signature = _match_dbms(body)
    if dbms is None and method_hint != "GET":
        post_response = _do_request(client, budget, records, "POST", url, data={parameter: payload})
        post_body = post_response.text if post_response is not None else ""
        if post_body:
            body = post_body
        dbms, signature = _match_dbms(body)
    error_based = dbms is not None
    logger.info(
        "sql-error probe: error_based=%s dbms=%s requests=%d", error_based, dbms, len(records)
    )
    excerpt = (
        _excerpt(body, signature or "", case_sensitive=False) if error_based else _excerpt(body)
    )
    return VerificationProbe(
        kind=ProbeKind.SQL_ERROR,
        error_based=error_based,
        dbms=dbms,
        evidence_excerpt=excerpt,
        requests_made=list(records),
    )


def probe_target(
    base_url: str,
    finding: Finding | Mapping[str, Any],
    timeout: float = MAX_TIMEOUT_SECONDS,
    allowed_hosts: Any = (),
    *,
    kind: str | ProbeKind | None = None,
    client: httpx.Client | None = None,
) -> VerificationProbe:
    """Probe one finding against ``base_url`` and return a verdict object.

    ``finding`` may be a :class:`~vulnscan.contracts.finding.Finding` or a
    plain mapping carrying any of ``path``, ``parameter`` (alias ``param``),
    ``method``, ``kind``/``probe_kind`` (or a ``cwe_category`` of CWE-79 /
    CWE-89 to derive the kind). ``kind`` overrides whatever the finding says.

    ``client`` is an escape hatch for tests (a pre-configured
    ``httpx.Client``); when omitted, a client with the clamped timeout is
    created and closed automatically.
    """
    effective_timeout = _effective_timeout(timeout)
    hints = _hints_of(finding)
    raw_kind = kind if kind is not None else hints.get("probe_kind", hints.get("kind"))
    if raw_kind is None:
        raw_kind = _kind_from_cwe(hints.get("cwe_category"))
    probe_kind = _normalize_kind(raw_kind.value if isinstance(raw_kind, Enum) else raw_kind)

    path = str(hints.get("path", "/") or "/")
    parameter = str(
        hints.get("parameter", hints.get("param"))
        or ("q" if probe_kind is ProbeKind.REFLECTED_XSS else "id")
    )
    method_hint = str(hints.get("method", "AUTO") or "AUTO").upper()

    url = _checked_url(base_url, path, allowed_hosts)
    logger.info("probing %s kind=%s parameter=%s", url, probe_kind.value, parameter)

    budget = _RequestBudget()
    records: list[ProbedRequest] = []
    own_client = client is None
    active = client if client is not None else httpx.Client(timeout=effective_timeout)
    try:
        if probe_kind is ProbeKind.REFLECTED_XSS:
            return _probe_xss(active, budget, records, url, parameter)
        return _probe_sql_error(active, budget, records, url, parameter, method_hint)
    finally:
        if own_client:
            active.close()
