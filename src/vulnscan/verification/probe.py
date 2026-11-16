"""Các probe xác minh HTTP có định hướng (assisted DAST, tùy chọn tham gia).

Chỉ có hai loại probe tồn tại, và cả hai đều là các kiểm tra chỉ đọc nghiêm ngặt đối với
mục tiêu mà người vận hành đưa vào allowlist một cách rõ ràng:

- ``reflected-xss``: GET đường dẫn dễ bị tấn công với một canary token ngẫu nhiên
  duy nhất trong tham số bị gắn cờ; báo cáo liệu token có bị phản chiếu hay không.
- ``sql-error``: GET (sau đó POST nếu cần) với dấu nháy đơn nối thêm vào
  tham số bị gắn cờ; so khớp response với các chữ ký lỗi DB đã biết
  (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) và báo cáo phỏng đoán DBMS.

Các quy tắc an toàn được thực thi tại đây (không phải theo quy ước ở nơi khác):

- Host mục tiêu phải xuất hiện trong đối số ``allowed_hosts`` rõ ràng,
  so khớp chính xác sau khi chuyển về chữ thường (do đó ``localhost`` không bao giờ ngầm định
  ``127.0.0.1``/``[::1]`` và ngược lại). Mọi trường hợp khác sẽ ném
  :class:`AllowlistError` trước khi bất kỳ request nào được thực hiện.
- Chỉ các URL ``http``/``https`` mới được probe.
- Timeout cho mỗi probe bị giới hạn ở :data:`MAX_TIMEOUT_SECONDS` (10s).
- Tối đa :data:`MAX_REQUESTS_PER_FINDING` (3) request được thực hiện cho mỗi
  finding; mọi request đều được ghi log và trả về trong ``requests_made``.
- Không theo dõi chuyển hướng (redirect), do đó probe không bao giờ bị chuyển tiếp sang
  một host nằm ngoài allowlist.

Module này không bao giờ tạo finding. Nó trả về một value object :class:`VerificationProbe`;
việc nâng cấp hoặc từ chối một finding từ kết quả đó là nhiệm vụ của validator,
không phải của module này.
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

#: Trần giới hạn cứng cho bất kỳ request probe đơn lẻ nào (giây). Các đối số ``timeout``
#: lớn hơn sẽ được ép xuống giá trị này.
MAX_TIMEOUT_SECONDS = 10.0

#: Trần giới hạn cứng về số request HTTP cho mỗi finding, trên cả hai loại probe.
MAX_REQUESTS_PER_FINDING = 3

#: Số ký tự tối đa được giữ trong ``evidence_excerpt`` sau khi che giấu dữ liệu nhạy cảm.
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
    """Hai loại probe duy nhất mà module này hỗ trợ."""

    REFLECTED_XSS = "reflected-xss"
    SQL_ERROR = "sql-error"


class AllowlistError(ValueError):
    """Được ném ra khi host mục tiêu của probe không nằm trong allowlist rõ ràng.

    Được ném ra trước khi bất kỳ request mạng nào được thực hiện.
    """


class UnsupportedProbeKindError(ValueError):
    """Được ném ra khi loại probe không thể phân giải thành một loại được hỗ trợ."""


class RequestBudgetExceeded(RuntimeError):
    """Được ném ra nếu một probe vượt quá ``MAX_REQUESTS_PER_FINDING``."""


class ProbedRequest(VersionedModel):
    """Một request HTTP được thực hiện bởi probe, được giữ lại nhằm phục vụ kiểm toán."""

    method: str = Field(..., description="HTTP method used, e.g. 'GET'.")
    url: str = Field(..., description="Full URL requested (without secrets).")
    status_code: int | None = Field(
        default=None,
        description="Response status, or None if no response was received.",
    )


class VerificationProbe(VersionedModel):
    """Kết quả probe một finding. Bản thân nó không bao giờ là một finding."""

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


#: Chữ ký lỗi DB không phân biệt hoa thường được định danh theo phỏng đoán DBMS. Mỗi mục
#: được thiết kế đặc thù cho từng DBMS để khi khớp sẽ chỉ định danh chính xác một engine.
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

# Các secret dạng ``key=value`` / ``key: value`` được che đi trước khi lưu trữ.
_REDACT_PATTERN = re.compile(
    r"(?i)((?:passw(?:or)?d|passwd|pwd|secret|api[_-]?key|token|sessionid|auth)\s*[:=]\s*)([^\s&;\"']+)"
)


def _redact(text: str) -> str:
    """Che các giá trị trông giống thông tin xác thực để đoạn trích an toàn khi lưu trữ."""
    return _REDACT_PATTERN.sub(r"\1***", text or "")


def _excerpt(body: str, needle: str = "", *, case_sensitive: bool = True) -> str:
    """Trả về một đoạn trích đã che dữ liệu nhạy cảm, ưu tiên vùng xung quanh ``needle``."""
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
    """Nối ``path`` vào ``base_url`` và thực thi allowlist cho host.

    Cả URL cơ sở và URL kết quả sau khi nối đều phải chứa một host
    trong allowlist, để đường dẫn finding vốn là một URL tuyệt đối ngoài allowlist
    không thể lén đưa probe tới nơi khác.
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
    """Đếm số request probe; từ chối vượt quá ``MAX_REQUESTS_PER_FINDING``."""

    def __init__(self, limit: int = MAX_REQUESTS_PER_FINDING) -> None:
        self._remaining = limit

    def consume(self) -> None:
        if self._remaining <= 0:
            raise RequestBudgetExceeded(
                f"probe would exceed {MAX_REQUESTS_PER_FINDING} requests per finding"
            )
        self._remaining -= 1


def _hints_of(finding: Finding | Mapping[str, Any]) -> dict[str, Any]:
    """Đọc các gợi ý probe (path/parameter/method/kind) từ bất kỳ cấu trúc finding nào."""
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
    """Trả về (dbms, matched_signature) cho chữ ký lỗi đã biết đầu tiên."""
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
    """Thực hiện một request trong ngân sách định mức có ghi log; trả về None khi lỗi truyền tải."""
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
    """Probe một finding đối với ``base_url`` và trả về một đối tượng phán quyết (verdict).

    ``finding`` có thể là một :class:`~vulnscan.contracts.finding.Finding` hoặc một
    mapping thông thường chứa bất kỳ trường nào như ``path``, ``parameter`` (bí danh ``param``),
    ``method``, ``kind``/``probe_kind`` (hoặc ``cwe_category`` của CWE-79 /
    CWE-89 để suy ra kind). ``kind`` sẽ ghi đè lên bất kỳ giá trị nào finding khai báo.

    ``client`` là lối thoát dự phòng cho các bài test (một ``httpx.Client`` được cấu hình trước);
    khi bỏ qua, một client với timeout đã được ép giới hạn sẽ được tạo và đóng tự động.
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
