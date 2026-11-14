"""Đề xuất sửa đổi do AI tạo cho các finding.

Mô hình chỉ viết một unified diff — nó không bao giờ chạm vào mã nguồn. Áp dụng một
đề xuất sẽ sao chép các tệp bị ảnh hưởng vào thư mục overlay dưới artifacts,
vá bản sao, và quét lại bản sao bằng rule của finding để chứng minh
finding đã biến mất. Thư mục làm việc (checkout) của người dùng không bao giờ bị sửa đổi.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulnscan.providers.client import ChatMessage, ProviderClient
from vulnscan.providers.profile_store import load_profile

FIX_SYSTEM = (
    "You are a secure-code repair assistant. Given one vulnerability finding "
    "with its source snippet, output ONLY a unified diff that fixes it. "
    "Rules: keep the diff minimal; do not change behavior beyond the fix; "
    "do not include explanations, only the diff in a ```diff block. "
    "Use `a/<path>` / `b/<path>` headers with the repo-relative file path."
)

FIX_USER_TEMPLATE = """\
CWE: {cwe}
Title: {title}
Rule: {rule}
File: {file_path} (line {line})
Severity: {severity}

Vulnerable code:
```
{snippet}
```
{context_section}
Write the minimal unified diff fixing this {cwe} issue."""


@dataclass
class FixProposal:
    finding_id: str
    file_path: str
    diff_text: str
    model: str


def build_fix_prompt(finding: dict[str, Any], code_context: str = "") -> str:
    """Kết xuất prompt người dùng cho một dict finding (bản kết xuất Finding).

    ``code_context`` là mã nguồn bao quanh rộng hơn từ checkout cục bộ.
    Nếu không có nó, mô hình sẽ tái tạo các dòng ngữ cảnh nghe có vẻ hợp lý nhưng sai,
    và bộ áp dụng bản vá nghiêm ngặt sẽ từ chối patch một cách chính xác.
    """
    section = ""
    if code_context.strip():
        section = (
            "Full surrounding code for exact context lines "
            "(each line is prefixed `NN|` with its real number — "
            "strip the prefixes, never renumber, copy context verbatim):\n```\n"
            + code_context[:4000]
            + "\n```\n"
        )
    obs = (finding.get("observations") or [{}])[0]
    loc = obs.get("location", {})
    return FIX_USER_TEMPLATE.format(
        cwe=finding.get("cwe_category") or "unknown",
        title=finding.get("title", ""),
        rule=obs.get("rule_id", ""),
        file_path=loc.get("file_path", ""),
        line=loc.get("line_start", "?"),
        severity=finding.get("severity", ""),
        snippet=(loc.get("snippet") or "")[:2000],
        context_section=section,
    )


def extract_diff(reply: str) -> str:
    """Trích xuất khối ```diff từ phản hồi của mô hình; chuỗi rỗng nếu không có."""
    match = re.search(r"```diff\s*(.*?)```", reply, re.DOTALL)
    if match:
        return match.group(1).strip() + "\n"
    # Phương án dự phòng: diff thô bắt đầu tại tiêu đề --- a/ đầu tiên.
    start = reply.find("--- a/")
    if start >= 0:
        return reply[start:].strip() + "\n"
    return ""


def propose_fix(
    finding: dict[str, Any],
    profile_id: str,
    model: str | None = None,
    max_tokens: int = 2000,
    code_context: str = "",
) -> FixProposal:
    """Yêu cầu mô hình cung cấp unified diff để khắc phục một finding."""
    profile = load_profile(profile_id)
    client = ProviderClient(profile)
    response = client.chat(
        [
            ChatMessage(role="system", content=FIX_SYSTEM),
            ChatMessage(role="user", content=build_fix_prompt(finding, code_context)),
        ],
        model=model or profile.default_model,
        temperature=0.0,
        max_tokens=max_tokens,
    )
    diff = extract_diff(response.content or "")
    if not diff:
        raise ValueError("Model reply contained no unified diff")
    obs = (finding.get("observations") or [{}])[0]
    return FixProposal(
        finding_id=str(finding.get("finding_id", "")),
        file_path=str(obs.get("location", {}).get("file_path", "")),
        diff_text=diff,
        model=str(model or profile.default_model or profile.id),
    )


def apply_unified_diff(repo_root: Path, diff_text: str) -> list[str]:
    """Áp dụng unified diff cho các tệp dưới repo_root (thuần Python).

    Chỉ hỗ trợ các hunk tệp đơn `--- a/x` / `+++ b/x` có kèm ngữ cảnh,
    đúng như những gì prompt sửa lỗi yêu cầu. Ném ra ValueError với bất kỳ điều gì
    bất thường thay vì đoán mò.
    """
    lines = diff_text.splitlines()
    target: str | None = None
    hunks: list[tuple[int, int, list[str]]] = []
    current: list[str] | None = None
    old_start = new_start = 0
    for line in lines:
        if line.startswith("--- a/"):
            continue
        if line.startswith("+++ b/"):
            target = line[len("+++ b/") :].strip()
            continue
        match = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if match:
            if current is not None:
                hunks.append((old_start, new_start, current))
            old_start, new_start = int(match.group(1)), int(match.group(2))
            current = []
            continue
        if current is not None and line[:1] in (" ", "-", "+", "\\"):
            if line.startswith("\\"):
                continue
            current.append(line)
    if current is not None:
        hunks.append((old_start, new_start, current))
    if not target or not hunks:
        raise ValueError("Diff has no target file or hunks")
    if ".." in Path(target).parts or Path(target).is_absolute():
        raise ValueError("Diff target escapes the overlay")
    path = repo_root / target
    original = path.read_text(encoding="utf-8").splitlines()
    patched: list[str] = []
    cursor = 0
    for start, _new_start, hunk in hunks:
        base = start - 1
        if base < cursor:
            raise ValueError("Overlapping hunks")
        patched.extend(original[cursor:base])
        cursor = base
        for hline in hunk:
            kind, text = hline[0], hline[1:]
            if kind == " ":
                if cursor >= len(original) or original[cursor] != text:
                    raise ValueError(f"Context mismatch at line {cursor + 1}")
                patched.append(original[cursor])
                cursor += 1
            elif kind == "-":
                if cursor >= len(original) or original[cursor] != text:
                    raise ValueError(f"Removal mismatch at line {cursor + 1}")
                cursor += 1
            elif kind == "+":
                patched.append(text)
            else:
                raise ValueError(f"Unknown hunk prefix {kind!r}")
    patched.extend(original[cursor:])
    path.write_text("\n".join(patched) + "\n", encoding="utf-8")
    return [target]


def verify_fixed(
    overlay: Path,
    file_path: str,
    rule_id: str,
    line: int | None,
    semgrep_bin: str = "semgrep",  # giữ tham số để tương thích chữ ký cũ
) -> dict[str, Any]:
    """Quét lại tệp đã vá bằng ``native-hunt``; finding phải biến mất.

    Trả về {fixed: bool, detail: str}. Việc cùng một rule kích hoạt lại tại cùng
    vị trí đồng nghĩa với việc bản vá chưa khắc phục được nó.
    """
    from vulnscan.native_hunt import scan_snapshot

    del semgrep_bin
    norm_file = Path(file_path).as_posix()
    short_rule = str(rule_id).split(".")[-1]
    result = scan_snapshot(str(overlay), ["java", "javascript", "python", "php"])
    file_findings = [
        f for f in result.findings if Path(f.file).as_posix() == norm_file
    ]
    if short_rule and short_rule != "model-hunt":
        refires = [
            f
            for f in file_findings
            if f.rule_id.endswith(short_rule) and (line is None or f.line == line)
        ]
    else:
        refires = [f for f in file_findings if line is None or f.line == line]
    if refires:
        return {
            "fixed": False,
            "detail": f"native-hunt refired: {[(f.rule_id, f.line) for f in refires]}",
        }
    return {"fixed": True, "detail": "native-hunt found no matching issue on the patched file"}


def prepare_overlay(checkout: str, file_path: str, overlay_root: Path) -> Path:
    """Sao chép tệp bị ảnh hưởng vào thư mục overlay (không bao giờ chạm vào checkout)."""
    src = Path(checkout) / file_path
    if ".." in Path(file_path).parts or not src.is_file():
        raise ValueError("Finding file is not inside the checkout")
    overlay_root.mkdir(parents=True, exist_ok=True)
    dest = overlay_root / file_path
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dest)
    return overlay_root
