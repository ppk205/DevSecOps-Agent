"""Mô hình rule và bộ nạp cho native taint-hunt engine.

Chấp nhận hai định dạng gói quy tắc (đều nằm trong ``rules/<family>.json``):

* Định dạng Taint — danh sách JSON gồm các đối tượng có ``sources``, ``sinks`` và
  ``sanitizers`` (``[{"id": ..., "cwe": ..., "attack": ..., "severity":
  ..., "sources": [<regex>], "sinks": [<regex>], "sanitizers":
  [{"pattern": <regex>, "prevent": [<attack>, ...]}]}]``). Engine
  theo dõi ``sources`` thông qua các phép gán đi vào ``sinks``.
* Định dạng Port — ``{"language": ..., "rules": [...]}`` trong đó mỗi rule
  mang các ``patterns`` của sink (các bản port từ bộ quy tắc Semgrep YAML). Chúng nhận
  tập hợp source/sanitizer mặc định của family ở bên dưới để tham gia
  vào luồng taint; rule không có mô hình source vẫn báo cáo các kết quả khớp sink
  dưới dạng finding ``Weak``.

``attack`` đặt tên cho khả năng tấn công mà một finding báo cáo; một sanitizer chỉ
làm sạch các dòng đối với các cuộc tấn công được liệt kê trong tập ``prevent`` của nó, do đó một hàm escape XSS
sẽ không bao giờ làm vô hiệu hóa một rule SQL-injection.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

RULES_DIR = Path(__file__).resolve().parent / "rules"

#: Regex source mặc định áp dụng cho các rule được port (chỉ có sink) theo từng family.
_FAMILY_SOURCES: dict[str, list[str]] = {
    "python": [r"request\.(args|form|values|json|data|GET|POST)", r"\binput\s*\("],
    "javascript": [
        r"req\.(query|body|params)",
        r"location\.(search|hash)",
        r"document\.URL",
        r"event\.data",
        r"window\.name",
    ],
    "java": [
        r"request\.getParameter",
        r"getParameter\s*\(",
        r"request\.getHeader",
        r"getHeader\s*\(",
        r"request\.getCookies",
        r"getCookies\s*\(\s*\)",
        r"request\.getQueryString",
        r"getQueryString\s*\(\s*\)",
        r"\.get\s*\(\s*\"kid\"",
        r"header\.get\s*\(",
        r"claims\.get\s*\(",
        r"getUsername\s*\(",
        r"\.getName\s*\(",
        r"getPrincipal\s*\(",
    ],
    "php": [r"\$_(GET|POST|REQUEST|COOKIE)"],
    "go": [
        r"r\.URL\.Query\s*\(",
        r"r\.FormValue\s*\(",
        r"r\.PostFormValue\s*\(",
        r"r\.URL\.Path\b",
        r"r\.Header\.Get\s*\(",
        r"r\.Body\b",
        r"mux\.Vars\s*\(",
        r"c\.Query\s*\(",
        r"c\.Param\s*\(",
        r"c\.PostForm\s*\(",
        r"c\.GetHeader\s*\(",
        r"os\.Args\b",
    ],
    "ruby": [
        r"\bparams\b",
        r"request\.(body|query_string|headers|cookies|path|url)\b",
        r"cookies\s*\[",
        r"ENV\s*\[",
        r"(?<![\w.])gets\b",
        r"\bSTDIN\b",
    ],
    "csharp": [
        r"Request\.(Query|Form|Params|Cookies|Headers|Body|QueryString|InputStream)\b",
        r"Console\.ReadLine\s*\(",
        r"Environment\.GetEnvironmentVariable\s*\(",
        r"\bargs\s*\[",
    ],
    "generic": [r"\brequest\b", r"\binput\s*\(", r"\bargv\b"],
}

#: Các sanitizer mặc định (pattern, prevented attacks) cho những rule được port.
_FAMILY_SANITIZERS: dict[tuple[str, str], list[tuple[str, list[str]]]] = {
    ("python", "xss"): [(r"escape\s*\(", ["xss"])],
    ("python", "command_injection"): [(r"shlex\.quote\s*\(", ["command_injection"])],
    ("javascript", "xss"): [(r"encodeURIComponent\s*\(|DOMPurify\.sanitize\s*\(", ["xss"])],
    ("java", "xss"): [(r"escapeHtml|StringEscapeUtils", ["xss"])],
    ("php", "xss"): [(r"htmlspecialchars\s*\(", ["xss"])],
    ("php", "command_injection"): [(r"escapeshellarg\s*\(", ["command_injection"])],
    ("go", "xss"): [(r"template\.HTMLEscapeString\s*\(|html\.EscapeString\s*\(", ["xss"])],
    ("ruby", "xss"): [(r"ERB::Util\.html_escape\s*\(|html_escape\s*\(|(?<![\w:])h\s*\(", ["xss"])],
    ("ruby", "command_injection"): [(r"Shellwords\.(escape|join)\s*\(", ["command_injection"])],
    ("csharp", "xss"): [
        (
            (
                r"HtmlEncoder\.Default\.Encode\s*\(|HttpUtility\.HtmlEncode\s*\(|"
                r"WebUtility\.HtmlEncode\s*\(|AntiXssEncoder\.HtmlEncode\s*\("
            ),
            ["xss"],
        )
    ],
}


@dataclass
class Sanitizer:
    """Một pattern làm sạch; chỉ triệt tiêu luồng cho các cuộc tấn công được liệt kê."""

    pattern: str
    prevent: list[str] = field(default_factory=list)


@dataclass
class Rule:
    """Một taint rule với các regex được biên dịch trước (biên dịch trong post-init)."""

    id: str
    cwe: str = ""
    attack: str = ""
    severity: str = "medium"
    sources: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    taint_sinks: list[str] = field(default_factory=list)
    sanitizers: list[Sanitizer] = field(default_factory=list)
    message: str = ""
    source_ref: str = ""
    # Kiểm tra rò rỉ tài nguyên (nhóm OBL): rule không mang pattern nào; engine
    # đánh dấu các phép gán `new <ResourceType>(...)` / getConnection mà
    # biến của nó không bao giờ được gọi `.close()` phía sau trong file (các phép gán
    # try-with-resources được loại trừ — chúng đóng ngầm định).
    resource_check: bool = False
    # taint: sink chỉ kích hoạt với dữ liệu bị taint; search: chỉ riêng pattern là
    # bằng chứng Weak. Được port từ chế độ riêng của rule Semgrep; các rule
    # tự xây dựng mặc định theo cấu trúc (có sources = taint).
    mode: str = ""
    # True khi sources được điền từ giá trị mặc định của family (các rule
    # chỉ có pattern được port): các khớp sink kích hoạt Weak khi thiếu bằng chứng taint.
    pattern_only: bool = False
    source_res: list[re.Pattern[str]] = field(init=False, repr=False, compare=False)
    sink_res: list[re.Pattern[str]] = field(init=False, repr=False, compare=False)
    taint_sink_res: list[re.Pattern[str]] = field(init=False, repr=False, compare=False)
    sanitizer_res: list[tuple[re.Pattern[str], list[str]]] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if self.mode not in ("taint", "search"):
            self.mode = "taint" if self.sources else "search"
        self.source_res = [_compile(p, self.id) for p in self.sources]
        self.sink_res = [_compile(p, self.id) for p in self.sinks]
        self.taint_sink_res = [_compile(p, self.id) for p in self.taint_sinks]
        self.sanitizer_res = [
            (_compile(s.pattern, self.id), list(s.prevent)) for s in self.sanitizers
        ]


def _compile(pattern: str, rule_id: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"native_hunt: rule {rule_id!r}: bad regex {pattern!r}: {exc}") from exc


def _str_list(value: Any, what: str, path: Path) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"native_hunt: {path} rule {what} must be a list of strings")
    return list(value)


def _opt_str(value: Any, what: str, path: Path) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return str(value)
    raise ValueError(
        f"native_hunt: {path} rule field {what} must be a string, got {type(value).__name__}"
    )


def _parse_rule(item: Any, path: Path, family: str, ported: bool) -> Rule:
    if not isinstance(item, dict):
        raise TypeError(
            f"native_hunt: rule entry in {path} must be an object, got {type(item).__name__}"
        )
    rule_id = item.get("id")
    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError(f"native_hunt: rule entry in {path} is missing a string 'id'")
    sinks = _str_list(item.get("sinks"), f"{rule_id!r} 'sinks'", path)
    if not sinks:
        sinks = _str_list(item.get("patterns"), f"{rule_id!r} 'patterns'", path)
    if not sinks:
        raise ValueError(f"native_hunt: {path} rule {rule_id!r} has no 'sinks' (or 'patterns')")
    if "sources" in item:
        sources = _str_list(item.get("sources"), f"{rule_id!r} 'sources'", path)
        pattern_only = False
    elif ported:
        sources = list(_FAMILY_SOURCES.get(family, _FAMILY_SOURCES["generic"]))
        pattern_only = True
    else:
        sources = []
        pattern_only = False
    attack = _opt_str(item.get("attack", ""), f"{rule_id!r} 'attack'", path)
    raw_mode = _opt_str(item.get("mode", ""), f"{rule_id!r} 'mode'", path).lower()
    if raw_mode not in ("", "taint", "search"):
        raise ValueError(f"native_hunt: {path} rule {rule_id!r} has unknown mode {raw_mode!r}")
    if not raw_mode:
        raw_mode = "taint" if (sources and not pattern_only) else "search"
    if "sanitizers" in item:
        raw_sans = item.get("sanitizers")
        if not isinstance(raw_sans, list):
            raise ValueError(f"native_hunt: {path} rule {rule_id!r} 'sanitizers' must be a list")
        sanitizers = []
        for entry in raw_sans:
            if not isinstance(entry, dict) or not isinstance(entry.get("pattern"), str):
                raise TypeError(
                    f"native_hunt: {path} rule {rule_id!r} sanitizer needs a string 'pattern'"
                )
            prevent = _str_list(entry.get("prevent", []), f"{rule_id!r} sanitizer 'prevent'", path)
            sanitizers.append(Sanitizer(pattern=entry["pattern"], prevent=prevent))
    elif ported:
        sanitizers = [
            Sanitizer(pattern=pat, prevent=list(prev))
            for pat, prev in _FAMILY_SANITIZERS.get((family, attack), [])
        ]
    else:
        sanitizers = []
    return Rule(
        id=rule_id,
        cwe=_opt_str(item.get("cwe", ""), f"{rule_id!r} 'cwe'", path),
        attack=attack,
        severity=_opt_str(item.get("severity", "medium"), f"{rule_id!r} 'severity'", path),
        sources=sources,
        sinks=sinks,
        taint_sinks=_str_list(item.get("taint_sinks"), f"{rule_id!r} 'taint_sinks'", path),
        pattern_only=pattern_only,
        mode=raw_mode,
        resource_check=bool(item.get("resource_check", False)),
        sanitizers=sanitizers,
        message=_opt_str(item.get("message", ""), f"{rule_id!r} 'message'", path),
        source_ref=_opt_str(item.get("source", ""), f"{rule_id!r} 'source'", path),
    )


def load_rules(family: str) -> list[Rule]:
    """Tải bộ rule cho *family* (ví dụ: ``"python"``).

    Chấp nhận định dạng taint (danh sách JSON) và định dạng ported
    (``{"language": ..., "rules": [...]}`` với sink ``patterns``).
    Trả về danh sách rỗng khi không có bộ rule nào; ném :class:`ValueError`
    khi file bộ rule tồn tại nhưng sai định dạng. Không phân biệt chữ hoa chữ thường.
    """
    name = family.strip().lower()
    path = RULES_DIR / f"{name}.json"
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"native_hunt: invalid rule JSON in {path}: {exc}") from exc
    if isinstance(raw, list):
        return [_parse_rule(item, path, name, ported=False) for item in raw]
    if isinstance(raw, dict) and isinstance(raw.get("rules"), list):
        return [_parse_rule(item, path, name, ported=True) for item in raw["rules"]]
    raise ValueError(f"native_hunt: rule pack {path} must hold a JSON list or a 'rules' object")
