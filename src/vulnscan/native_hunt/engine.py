"""Engine taint dựa trên regex qua ba lần lặp trên một file hoặc cây snapshot.

Ngữ nghĩa (chủ ý tinh gọn và có tài liệu rõ ràng):

* Sources làm nhiễm độc (taint) các phép gán đơn giản ``name = <expr>`` khi dòng khớp với
  regex source của một rule. Chỉ theo dõi các tên biến đơn thuần (không theo dõi thuộc tính,
  tuple, hoặc phép gán mở rộng) — bất cứ thứ gì phức tạp hơn đều nằm ngoài phạm vi của
  một engine hướng dòng.
* Taint lan truyền khi vế phải của phép gán tham chiếu đến một biến
  bị taint, tối đa :data:`MAX_ITERATIONS` lượt điểm bất động để các chuỗi
  như ``a -> b -> c -> sink`` được phân giải bất kể thứ tự dòng.
  Gán lại một biến với dữ liệu không bị taint sẽ triệt tiêu taint của nó.
* Một dòng khớp với một sanitizer có danh sách ``prevent`` chứa kiểu
  attack của rule sẽ triệt tiêu taint của biến được gán, và sink trên dòng đó
  sẽ không bao giờ kích hoạt. Các sanitizer cho những attack khác sẽ bị bỏ qua.
* Confidence: ``High`` khi chính dòng sink chứa source (hoặc
  dùng biến được gán trực tiếp từ source, 0 bước nhảy), ``Medium``
  cho một bước nhảy, ``Weak`` cho hai bước nhảy trở lên, hoặc cho các kết quả khớp sink của rule
  không có mô hình source (các bản port chỉ có sink sẽ không mang provenance).
* File bị thiếu, không đọc được, hoặc quá kích thước sẽ không tạo ra finding nào thay vì
  báo lỗi; :func:`scan_snapshot` ghi nhận các file quá kích thước/không đọc được vào
  ``SnapshotResult.skipped``.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Literal

from .taint import RULES_DIR, Rule, load_rules

#: Các file lớn hơn kích thước này sẽ bị bỏ qua (giới hạn thời gian chạy trên các bundle được sinh tự động).
MAX_FILE_BYTES = 256 * 1024

#: Các file có độ dài dòng trung bình vượt quá mức này là các bundle rút gọn (minified)/vendored
#: nơi mọi pattern cùng xuất hiện trên một dòng khổng lồ (toàn bộ là FP).
#: Bị bỏ qua kèm theo lý do được ghi lại, tương tự như các file vượt quá kích thước.
MAX_AVG_LINE_LEN = 2000

#: Các hậu tố không bao giờ được quét có ý nghĩa (các bundle rút gọn vendored).
MINIFIED_SUFFIXES = (".min.js",)

#: Các lượt lặp fixpoint để lan truyền vết bẩn (taint propagation).
MAX_ITERATIONS = 3

#: Bảng ánh xạ hậu tố được dùng bởi scan_snapshot; các pack cho các họ khác áp dụng cho mọi file.
FAMILY_EXTENSIONS: dict[str, frozenset[str]] = {
    "python": frozenset({".py"}),
    "javascript": frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue"}),
    "java": frozenset({".java", ".jsp", ".jspx"}),
    "php": frozenset({".php", ".phtml"}),
    "go": frozenset({".go"}),
    "ruby": frozenset({".rb", ".erb"}),
    "csharp": frozenset({".cs", ".cshtml", ".razor"}),
}

Confidence = Literal["High", "Medium", "Weak"]

_ASSIGN_RE = re.compile(
    r"^\s*(?:(?:final\s+)?[A-Za-z_][\w<>\[\].,\s]*?\s+)?"
    r"(?P<var>[A-Za-z_]\w*)\s*(?<![=!<>]):?=\s*(?![=>])(?P<rhs>.+)$"
)

#: Định nghĩa phương thức/hàm được ghi nhận cho lan truyền vết bẩn gọi hàm→tham số cùng file:
#: ``name`` + danh sách tham số thô. Hỗ trợ Java method, Python def,
#: JS function/method, Go func, Ruby def, C# method
#: (chỉ signature trên một dòng, nỗ lực tối đa).
_DEF_RE = re.compile(
    r"(?:def\s+|function\s+)?(?P<name>[A-Za-z_]\w*)\s*\((?P<params>.*)\)\s*(?:\{|:|throws\b)?\s*$"
)

#: Một dòng định nghĩa chứa một trong các dấu hiệu này đánh dấu dữ liệu đầu vào do người dùng kiểm soát
#: (annotation của framework, đối tượng servlet, các accessor nhận input
#: từ người dùng rõ ràng). Chỉ những trường hợp này mới làm vấy bẩn (taint) tất cả tham số — một từ đơn thuần như
#: ``request`` đứng một mình là KHÔNG đủ (mọi handler của framework đều nhận một request).
_ENTRY_MARK_RE = re.compile(
    r"@RequestParam|@RequestBody|@PathVariable|@RequestHeader|@CookieValue|"
    r"HttpServletRequest|HttpServletResponse|MultipartFile|"
    r"FromQuery|FromRoute|FromForm|FromBody|HttpRequest|"
    r"request\.(?:args|form|values|json|data|GET|POST|query|body|params)\b|"
    r"req\.(query|body|params)\b"
)

_CALL_RE = re.compile(r"(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^();]*)\)")

#: Gán nối tiếp (``.=``/``+=``): giữ vết bẩn hiện có, thêm vết bẩn từ vế phải.
_APPEND_ASSIGN_RE = re.compile(
    r"(?<![\w=!<>])(?P<var>[A-Za-z_]\w*|\$\w+)\s*(?P<op>[+.]?=)\s*(?P<rhs>.+)$"
)

#: Bắt đầu Heredoc: ``$var .= <<<TAG`` hoặc ``$var = <<<TAG``. Các dòng nội dung cho đến
#: ký tự kết thúc ``TAG;`` đứng riêng lẻ sẽ nội suy ``{$var}``/``$var``.
_HEREDOC_RE = re.compile(
    r"(?P<var>\$\w+)\s*(?P<op>\.?=)\s*<<<\s*(?P<tag>[A-Za-z_]\w*)"
)

#: Dự phòng cho các phép gán nằm sâu bên trong điều kiện/lời gọi hàm
#: (``while ((line = in.readLine()) != null)``). Chỉ dùng khi phép gán
#: ở đầu dòng bị trượt; giữ nguyên các cơ chế bảo vệ tránh nhầm với ==/!=/=>.
_COND_ASSIGN_RE = re.compile(r"(?<![\w=!<>])(?P<var>[A-Za-z_]\w*)\s*=\s*(?![=>])(?P<rhs>[^;]+)")


def _split_params(raw: str) -> list[str]:
    """Token cuối cùng của mỗi phần phân tách bằng dấu phẩy, đã loại bỏ các chú thích."""
    out: list[str] = []
    for part in raw.split(","):
        part = re.sub(r"@\w+(?:\([^()]*\))?\s*", "", part).strip()
        tokens = re.findall(r"[A-Za-z_]\w*", part)
        if tokens:
            out.append(tokens[-1])
    return out


def _collect_defs(lines: list[str]) -> dict[str, list[str]]:
    """Tên phương thức -> danh sách tên tham số, định nghĩa đầu tiên được ưu tiên."""
    defs: dict[str, list[str]] = {}
    for raw in lines:
        stripped = raw.strip()
        # Lời gọi hàm, luồng điều khiển và return không phải là định nghĩa hàm.
        if stripped.startswith(("return", "if", "for", "while", "switch", "catch")):
            continue
        if not re.search(r"[{:]\s*$|throws\b", stripped):
            continue
        match = _DEF_RE.search(stripped)
        if match is None:
            continue
        name = match.group("name")
        if name in defs or name in {"if", "for", "while", "switch", "catch", "return"}:
            continue
        params = _split_params(match.group("params"))
        if params:
            defs[name] = params
    return defs


@dataclass
class Finding:
    """Một observation ghi nhận dữ liệu bị taint lan tới sink."""

    rule_id: str
    cwe: str
    attack: str
    severity: str
    file: str
    line: int
    snippet: str
    confidence: Confidence
    source_line: int | None = None
    message: str = ""
    source_ref: str = ""


@dataclass
class SnapshotResult:
    """Kết quả quét một cây snapshot."""

    findings: list[Finding] = field(default_factory=list)
    scanned: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


@lru_cache(maxsize=4096)
def _word_rx(name: str) -> re.Pattern[str]:
    # Biến kiểu PHP ``$vars`` không có ranh giới từ ở đầu (``{`` → ``$`` đều là
    # các ký tự không phải chữ), do đó neo theo điều kiện "không đứng sau một ký tự chữ".
    if name.startswith("$"):
        return re.compile(r"(?<!\w)" + re.escape(name) + r"\b")
    return re.compile(r"\b" + re.escape(name) + r"\b")


def _line_sanitized(line: str, rule: Rule) -> bool:
    return any(
        rx.search(line) is not None for rx, prevent in rule.sanitizer_res if rule.attack in prevent
    )


def _scan_rule(
    name: str, lines: list[str], rule: Rule, defs: dict[str, list[str]] | None = None
) -> list[Finding]:
    tainted: dict[str, tuple[int, int]] = {}  # var -> (origin_line, hops)
    method_defs = defs if defs is not None else {}
    # Điểm vào: tham số phương thức trên các dòng định nghĩa mang dấu hiệu source
    # (Spring annotation, đối tượng servlet request) bắt đầu ở trạng thái tainted.
    for lineno, raw in enumerate(lines, start=1):
        if _ENTRY_MARK_RE.search(raw) is None:
            continue
        match = _DEF_RE.search(raw.strip())
        if match is None:
            continue
        for param in _split_params(match.group("params")):
            if tainted.get(param) != (lineno, 0):
                tainted[param] = (lineno, 0)
    heredoc: tuple[str, str, bool] | None = None  # (var, tag, is_append), trên mỗi lượt pass
    for _ in range(MAX_ITERATIONS):
        changed = False
        heredoc = None
        for lineno, raw in enumerate(lines, start=1):
            # Phần thân Heredoc nội suy các biến tainted vào biến heredoc.
            if heredoc is not None:
                hvar, htag, _ = heredoc
                if raw.strip().rstrip(";") == htag:
                    heredoc = None
                    continue
                for tvar, (origin, hops) in list(tainted.items()):
                    if _word_rx(tvar).search(raw) is None:
                        continue
                    if hvar not in tainted or hops + 1 < tainted[hvar][1]:
                        tainted[hvar] = (origin, hops + 1)
                        changed = True
                    break
                continue
            hstart = _HEREDOC_RE.search(raw)
            if hstart is not None:
                hvar = hstart.group("var")
                if hstart.group("op") == "=" and hvar in tainted:
                    # Phép gán heredoc mới sẽ đặt lại vết bẩn trước đó; các
                    # dòng nội dung bên dưới sẽ làm bẩn lại nếu chúng nội suy
                    # dữ liệu tainted. Thay vào đó ``.=`` sẽ tiếp tục tích lũy.
                    del tainted[hvar]
                    changed = True
                heredoc = (hvar, hstart.group("tag"), hstart.group("op") == ".=")
            # Lan truyền gọi hàm→tham số trong cùng file chạy trên mọi dòng (lời gọi hàm
            # hiếm khi giống phép gán): foo(taintedArg) sẽ làm bẩn tham số
            # của foo ở vị trí đó; vòng lặp fixpoint sẽ tiếp tục lan truyền nó.
            for call in _CALL_RE.finditer(raw):
                callee = call.group("name")
                if callee not in method_defs:
                    continue
                for arg, param in zip(
                    call.group("args").split(","), method_defs[callee]
                ):
                    for tvar, (origin, hops) in list(tainted.items()):
                        if _word_rx(tvar).search(arg) is None:
                            continue
                        if param not in tainted or hops + 1 < tainted[param][1]:
                            tainted[param] = (origin, hops + 1)
                            changed = True
                        break
            match = _ASSIGN_RE.match(raw)
            if match is None:
                match = _COND_ASSIGN_RE.search(raw)
            if match is None:
                # Gán nối tiếp (``.=``/``+=``) không bao giờ triệt tiêu: nó giữ
                # vết bẩn hiện có và thêm vết bẩn từ vế phải.
                appended = _APPEND_ASSIGN_RE.search(raw)
                if appended is not None:
                    var = appended.group("var")
                    rhs = appended.group("rhs")
                    if _line_sanitized(raw, rule):
                        if var in tainted:
                            del tainted[var]
                            changed = True
                        continue
                    for tvar, (origin, hops) in list(tainted.items()):
                        if _word_rx(tvar).search(rhs) is None:
                            continue
                        if var not in tainted or hops + 1 < tainted[var][1]:
                            tainted[var] = (origin, hops + 1)
                            changed = True
                        break
                continue
            var, rhs = match.group("var"), match.group("rhs")
            if _line_sanitized(raw, rule):
                if var in tainted:
                    del tainted[var]
                    changed = True
                continue
            if any(rx.search(raw) is not None for rx in rule.source_res):
                if tainted.get(var) != (lineno, 0):
                    tainted[var] = (lineno, 0)
                    changed = True
                continue
            best: tuple[int, int] | None = None
            for tvar, (origin, hops) in tainted.items():
                if tvar == var or _word_rx(tvar).search(rhs) is None:
                    continue
                if best is None or hops < best[1]:
                    best = (origin, hops)
            if best is not None:
                if var not in tainted or best[1] + 1 < tainted[var][1]:
                    tainted[var] = (best[0], best[1] + 1)
                    changed = True
            elif var in tainted:
                del tainted[var]  # được gán lại thành dữ liệu không vấy bẩn
                changed = True
        if not changed:
            break

    findings: list[Finding] = []
    joined = [""] * len(lines)
    for i, raw in enumerate(lines):
        # Cửa sổ dòng lệnh liên tục: các lời gọi nhiều dòng giữ sink trên
        # một dòng và tham số tainted ở dòng tiếp theo (chuỗi kiểu builder).
        window = "\n".join(lines[i : i + 3])
        joined[i] = window
    for lineno, raw in enumerate(lines, start=1):
        window = joined[lineno - 1]
        sink_hit = any(rx.search(raw) is not None for rx in rule.sink_res)
        # Bản thân pattern taint_sink phải nằm trên dòng được báo cáo; cửa sổ
        # 3 dòng chỉ giúp tìm tham số tainted (ngăn sink của dòng
        # lân cận nhận dòng này làm của riêng nó).
        taint_hit = any(rx.search(raw) is not None for rx in rule.taint_sink_res)
        if not sink_hit and not taint_hit:
            continue
        if _line_sanitized(raw, rule):
            continue
        if sink_hit and any(rx.search(raw) is not None for rx in rule.source_res):
            confidence: Confidence = "High"
            source_line: int | None = lineno
        else:
            best_ref: tuple[int, int] | None = None
            for tvar, (origin, hops) in tainted.items():
                if _word_rx(tvar).search(window) is None:
                    continue
                if best_ref is None or hops < best_ref[1]:
                    best_ref = (origin, hops)
            if best_ref is None:
                # Các rule ở search-mode kích hoạt Weak chỉ dựa trên pattern; taint-mode
                # rules (và taint_sinks) không bao giờ kích hoạt nếu thiếu dữ liệu bị taint.
                if taint_hit and not sink_hit:
                    continue
                if not sink_hit or rule.mode == "taint":
                    continue
                confidence = "Weak"
                source_line = None
            else:
                source_line = best_ref[0]
                confidence = "High" if best_ref[1] == 0 else "Medium" if best_ref[1] == 1 else "Weak"
        findings.append(
            Finding(
                rule_id=rule.id,
                cwe=rule.cwe,
                attack=rule.attack,
                severity=rule.severity,
                file=name,
                line=lineno,
                snippet=raw.strip()[:200],
                confidence=confidence,
                source_line=source_line,
                message=rule.message,
                source_ref=rule.source_ref,
            )
        )
    return findings


_RESOURCE_CTOR_RE = re.compile(
    r"=\s*new\s+(FileInputStream|FileOutputStream|BufferedReader|BufferedWriter|"
    r"InputStreamReader|OutputStreamWriter|PrintWriter|PrintStream|Scanner|"
    r"Formatter|RandomAccessFile|FileChannel|Socket|ZipFile)\s*\("
)
_RESOURCE_CALL_RE = re.compile(
    r"=\s*(?:\w+\.)?(?:getConnection|createStatement|prepareStatement|openConnection)\s*\("
)
_RESOURCE_CLOSE_RE = re.compile(r"\.(?:close|disconnect|release)\s*\(")


def _scan_resources(name: str, lines: list[str], rule: Rule) -> list[Finding]:
    """Đánh dấu các phép gán tài nguyên không bao giờ được gọi `.close()` trong file.

    Xấp xỉ OBL theo phương thức best-effort: các phép gán try-with-resources
    (``try (Type var = ...)``) được đóng ngầm định và sẽ được bỏ qua. Các finding
    có mức Weak — việc đóng tài nguyên giữa các phương thức không thể thấy được trong quét cục bộ một file.
    """
    out: list[Finding] = []
    for lineno, raw in enumerate(lines, start=1):
        if "try (" in raw or "try(" in raw:
            continue
        opened = _RESOURCE_CTOR_RE.search(raw) or _RESOURCE_CALL_RE.search(raw)
        if opened is None:
            continue
        match = _ASSIGN_RE.match(raw) or _COND_ASSIGN_RE.search(raw)
        if match is None:
            continue
        var = match.group("var")
        if var in {"in", "out", "err"}:
            continue
        closed = any(
            _word_rx(var).search(later) is not None and _RESOURCE_CLOSE_RE.search(later) is not None
            for later in lines[lineno:]
        )
        if closed:
            continue
        out.append(
            Finding(
                rule_id=rule.id,
                cwe=rule.cwe,
                attack=rule.attack,
                severity=rule.severity,
                file=name,
                line=lineno,
                snippet=raw.strip()[:200],
                confidence="Weak",
                source_line=None,
                message=rule.message,
                source_ref=rule.source_ref,
            )
        )
    return out


def _scan_text(name: str, text: str, rules: Sequence[Rule]) -> list[Finding]:
    lines = text.splitlines()
    out: list[Finding] = []
    defs = _collect_defs(lines)
    for rule in rules:
        if rule.resource_check:
            out.extend(_scan_resources(name, lines, rule))
        else:
            out.extend(_scan_rule(name, lines, rule, defs))
    out.sort(key=lambda f: (f.file, f.line, f.rule_id))
    return out


def _skip_reason(path: Path, text: str | None) -> str | None:
    """Lý do một file không được quét theo mẫu (pattern), hoặc None để tiếp tục quét."""
    if path.name.lower().endswith(MINIFIED_SUFFIXES):
        return "minified bundle: pattern scan skipped"
    if text is not None:
        lines = text.splitlines() or [""]
        if sum(len(line) for line in lines) / len(lines) > MAX_AVG_LINE_LEN:
            return "oversized lines (minified/vendored): pattern scan skipped"
    return None


def scan_file(path: str | Path, rules: Sequence[Rule]) -> list[Finding]:
    """Quét một file; các file thiếu/không đọc được/quá kích thước sẽ không tạo finding."""
    target = Path(path)
    try:
        if not target.is_file() or target.stat().st_size > MAX_FILE_BYTES:
            return []
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if _skip_reason(target, text) is not None:
        return []
    return _scan_text(str(target), text, rules)


def _family_for_suffix(suffix: str) -> str | None:
    for family, exts in FAMILY_EXTENSIONS.items():
        if suffix in exts:
            return family
    return None


def scan_snapshot(root: str | Path, families: Sequence[str] | None = None) -> SnapshotResult:
    """Quét mọi file dưới *root* khớp với *families* (mặc định là tất cả bộ quy tắc).

    Các file có phần mở rộng không khớp với family đã yêu cầu sẽ bị bỏ qua;
    các file quá kích thước hoặc không đọc được sẽ được ghi vào ``skipped``. Chỉ
    metadata ``.git`` và symlink bị bỏ qua; các thư mục ẩn khác
    (ví dụ: wrapper ``.mvn``) là các mã nguồn hợp lệ. Nếu thiếu *root*
    sẽ trả về kết quả rỗng.
    """
    result = SnapshotResult()
    root_path = Path(root)
    if not root_path.is_dir():
        return result
    wanted = [f.strip().lower() for f in (families if families is not None else [])]
    if not wanted:
        wanted = sorted(p.stem for p in RULES_DIR.glob("*.json"))
    packs = [(fam, load_rules(fam)) for fam in wanted]
    packs = [(fam, rules) for fam, rules in packs if rules]
    if not packs:
        return result
    for child in sorted(root_path.rglob("*")):
        if child.is_symlink() or not child.is_file():
            continue
        try:
            rel = child.relative_to(root_path).as_posix()
        except ValueError:
            continue
        if any(part == ".git" for part in Path(rel).parts):
            continue
        suffix_family = _family_for_suffix(child.suffix.lower())
        applicable: list[Rule] = []
        for pack_family, rules in packs:
            if pack_family in FAMILY_EXTENSIONS and suffix_family != pack_family:
                continue
            applicable.extend(rules)
        if not applicable:
            continue
        try:
            if child.stat().st_size > MAX_FILE_BYTES:
                result.skipped.append(rel)
                continue
            text = child.read_text(encoding="utf-8", errors="replace")
        except OSError:
            result.skipped.append(rel)
            continue
        reason = _skip_reason(child, text)
        if reason is not None:
            result.skipped.append(f"{rel} ({reason})")
            continue
        result.scanned.append(rel)
        result.findings.extend(_scan_text(rel, text, applicable))
    result.findings.sort(key=lambda f: (f.file, f.line, f.rule_id))
    return result
