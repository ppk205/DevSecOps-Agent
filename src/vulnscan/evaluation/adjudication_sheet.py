"""Hiển thị 29 finding đã định tuyến khuyến nghị dưới dạng bảng phán quyết có thể xem xét.

Mỗi dòng chứa chính xác dòng mã nguồn mà Laya đã thấy, nhờ đó con người có thể gắn nhãn
``expected_route`` bằng cách đọc code thay vì phỏng đoán từ tên rule.
Công cụ này chỉ hiển thị; nó không bao giờ gắn nhãn. Chỉ con người mới có quyền phán quyết.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

CONTEXT_LINES = 6


def _repo_path(file_path: str, repo_root: Path) -> Path | None:
    """Phân giải đường dẫn quét tuyệt đối trở lại thư mục checkout, nếu nó tồn tại ở đó.

    Một lượt quét sẽ ghi lại đường dẫn tuyệt đối từ bất kỳ máy nào đã chạy scanner, do đó
    phần tiền tố checkout phải được loại bỏ trước khi đường dẫn có thể được phân giải lại.
    """
    if not file_path:
        return None
    raw = Path(file_path)
    windows = PureWindowsPath(file_path)
    portable = windows if windows.is_absolute() else PurePosixPath(file_path.replace("\\", "/"))
    candidates: list[Path] = []
    if portable.is_absolute():
        parts = portable.parts
        if "src" in parts:
            idx = len(parts) - 1 - parts[::-1].index("src")
            candidates.append(repo_root.joinpath(*parts[idx:]))
        candidates.append(raw)
    else:
        candidates.append(repo_root.joinpath(*portable.parts))
        candidates.append(raw)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _source_excerpt(
    file_path: str, line_start: int | None, repo_root: Path, context: int = CONTEXT_LINES
) -> str | None:
    """Dòng đã quét kèm một chút ngữ cảnh, hoặc None nếu không thể truy cập."""
    path = _repo_path(file_path, repo_root)
    if path is None or not line_start:
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    start = max(0, line_start - 1 - context)
    end = min(len(lines), line_start + context)
    out: list[str] = []
    for i in range(start, end):
        marker = ">>" if i == line_start - 1 else "  "
        out.append(f"{marker} {i + 1:>5} | {lines[i]}")
    return "\n".join(out)


def build_sheet(
    scan: dict[str, Any],
    repo_root: Path,
    confidence_key: str = "recommended_action",
) -> list[dict[str, Any]]:
    """Một mục có thể xem xét cho mỗi finding, được sắp xếp theo route rồi đến CWE."""
    payloads = scan.get("advisory_routing", {}).get("payloads", [])
    findings = {f["finding_id"]: f for f in scan.get("findings", [])}

    rows: list[dict[str, Any]] = []
    for payload in payloads:
        finding_id = str(payload.get("finding_id", ""))
        finding = findings.get(finding_id, {})
        obs = (finding.get("observations") or [{}])[0]
        location = obs.get("location") or {}
        answer = (payload.get("answers") or {}).get(confidence_key) or {}

        file_path = str(location.get("file_path") or "")
        rows.append(
            {
                "finding_id": finding_id,
                "cwe": finding.get("cwe_category"),
                "severity": finding.get("severity"),
                "laya_route": payload.get("route"),
                "laya_confidence": answer.get("confidence"),
                "laya_probs": answer.get("probabilities"),
                "needs_human_review": (
                    (payload.get("answers") or {}).get("needs_human_review") or {}
                ).get("noul"),
                "evidence_sufficiency": (
                    (payload.get("answers") or {}).get("evidence_sufficiency") or {}
                ).get("score"),
                "rule_id": obs.get("rule_id"),
                "file": file_path,
                "line": location.get("line_start"),
                "message": (obs.get("message") or "")[:160],
                "expected_route": None,
                "source": _source_excerpt(file_path, location.get("line_start"), repo_root),
            }
        )

    rows.sort(key=lambda r: (str(r["laya_route"]), str(r["cwe"]), str(r["finding_id"])))
    return rows


def render_text(rows: Sequence[dict[str, Any]], limit: int | None = None) -> str:
    """Bảng phán quyết cho con người đọc."""
    out: list[str] = []
    shown = rows if limit is None else rows[:limit]

    for i, row in enumerate(shown, start=1):
        out.append("=" * 78)
        out.append(f"[{i}] {row['finding_id']}  {row['cwe']} / {row['severity']}")
        out.append(f"  file      {row['file']}:{row['line']}")
        out.append(f"  rule      {row['rule_id']}")
        out.append(
            f"  Laya      route={row['laya_route']} "
            f"conf={row['laya_confidence']} "
            f"needs_human={row['needs_human_review']} "
            f"suff={row['evidence_sufficiency']}"
        )
        if row["laya_probs"]:
            top = max(row["laya_probs"].items(), key=lambda kv: kv[1])
            out.append(f"            top choice={top[0]} p={top[1]}")
        out.append(f"  message   {row['message']}")
        if row["source"]:
            out.append("  ---")
            for line in row["source"].splitlines():
                out.append(f"  {line}")
        else:
            out.append("  (source not reachable from checkout)")
        out.append(f"  -> LABEL expected_route: {row['expected_route']}")
        out.append("")

    if limit is not None and len(rows) > limit:
        out.append(f"... {len(rows) - limit} more in the JSON sheet")
    return "\n".join(out)
