"""Quảng bá các ứng viên săn tìm đã xác minh chỉ thuộc về mô hình thành Finding tương đương cấp độ scanner.

Chế độ Hunt phân nhóm các ứng viên của mô hình với các finding của scanner
(:func:`vulnscan.ai.compare.compare_hunt_vs_scanners`): các ứng viên đồng thuận
đã có một scanner Finding, nhưng các ứng viên chỉ thuộc về mô hình sẽ
bị biến mất trong âm thầm. Việc quảng bá sẽ đọc lại vị trí của từng ứng viên thông qua
cùng bộ đọc trích đoạn bị cô lập mà các luồng hunt và review sử dụng, và tổng hợp
một Finding ``UNPROCESSED`` cho mỗi ứng viên vẫn còn bằng chứng mã nguồn thực sự phía sau nó.

Quy tắc loại bỏ: các mục không phải dict, tệp bị thiếu hoặc không phải chuỗi, tệp thoát ra
ngoài snapshot, trích đoạn không đọc được hoặc rỗng, và dòng không hợp lệ (không phải số nguyên hoặc
< 1) sẽ bị bỏ qua. Việc quảng bá không bao giờ ném ngoại lệ: một ứng viên hỏng không bao giờ
làm hỏng cả đợt. Severity fallback về ``MEDIUM`` khi giá trị của ứng viên
không phải là thành viên :class:`Severity`; CWE không thể ánh xạ sẽ trở thành
``UNCLASSIFIED`` trên finding (``None`` trên observation).
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vulnscan.ai.compare import norm_path
from vulnscan.ai.excerpts import code_excerpt
from vulnscan.contracts.enums import (
    CWECategory,
    EvidenceStrength,
    FindingProvenance,
    FindingStatus,
    Severity,
    ToolName,
    language_from_extension,
)
from vulnscan.contracts.finding import Finding, Observation, SourceCoordinate
from vulnscan.scanners.mapping import confidence_value
from vulnscan.scanners.mapping import cwe_category as map_cwe_category

#: Sentinel được trả về bởi :func:`code_excerpt` khi không có mã nguồn nào đọc được.
_NO_EXCERPT = "(no source excerpt available)"

logger = logging.getLogger(__name__)

_MODEL_RULE_ID = "model-hunt"

# Enum contracts chưa có thành viên model; metadata rule_id + origin
# sẽ mang thông tin nguồn gốc model cho đến khi có thành viên này.
_candidate_tool: object = getattr(ToolName, "MODEL_HUNT", None)
_MODEL_TOOL: ToolName = (
    _candidate_tool if isinstance(_candidate_tool, ToolName) else ToolName.NATIVE_HUNT
)


def _candidate_line(candidate: dict[str, Any]) -> int | None:
    """Dòng mã nguồn bắt đầu từ 1, hoặc None khi dòng của ứng viên không hợp lệ."""
    try:
        line = int(candidate.get("line", 0))
    except (TypeError, ValueError):
        return None
    return line if line >= 1 else None


def _inside_snapshot(snapshot_root: str, file_path: str) -> bool:
    """True khi *file_path* được phân giải bên trong *snapshot_root*."""
    try:
        root = Path(snapshot_root).resolve()
        target = (root / file_path).resolve()
        target.relative_to(root)
    except (OSError, ValueError, RuntimeError):
        return False
    return True


def _severity_of(candidate: dict[str, Any]) -> Severity:
    """Mức độ nghiêm trọng của ứng viên, hoặc MEDIUM khi nó không phải thành viên Severity."""
    try:
        return Severity(str(candidate.get("severity", "medium")).strip().lower())
    except ValueError:
        return Severity.MEDIUM


def _promote_one(candidate: Any, *, snapshot_root: str, run_id: str) -> Finding | None:
    """Tạo một Finding có nguồn gốc từ model, hoặc None khi ứng viên bị loại bỏ."""
    if not isinstance(candidate, dict):
        return None
    raw_file = candidate.get("file")
    if not isinstance(raw_file, str) or not raw_file.strip():
        return None
    line = _candidate_line(candidate)
    if line is None or not _inside_snapshot(snapshot_root, raw_file):
        return None
    excerpt = code_excerpt(snapshot_root, raw_file, line)
    if not excerpt or excerpt == _NO_EXCERPT:
        return None

    norm_file = norm_path(raw_file)
    cwe_label = str(candidate.get("cwe") or "")
    mapped = map_cwe_category(cwe_label or None)
    severity = _severity_of(candidate)
    title = str(candidate.get("title") or "").strip()
    rationale = str(candidate.get("rationale") or "")
    evidence = str(candidate.get("evidence") or "")
    cwe_display = mapped.value if mapped is not None else (cwe_label.strip() or "CWE-unknown")
    if not title:
        title = f"{cwe_display} at {norm_file}:{line}"
    now = datetime.now(UTC)
    digest = hashlib.sha256(
        f"{norm_file}|{line}|{cwe_display}|{_MODEL_RULE_ID}".encode()
    ).hexdigest()
    finding_id = f"model-{digest[:16]}"
    observation_id = f"{finding_id}-obs"
    observation = Observation(
        observation_id=observation_id,
        run_id=run_id,
        tool=_MODEL_TOOL,
        tool_version=_MODEL_RULE_ID,
        rule_id=_MODEL_RULE_ID,
        cwe_category=mapped,
        severity=severity,
        message=(rationale.strip() or title)[:2000],
        confidence=confidence_value(candidate.get("laya_confidence"), default=1.0),
        location=SourceCoordinate(
            file_path=norm_file,
            language=language_from_extension(norm_file),
            line_start=line,
            snippet=excerpt[:2000],
        ),
        detected_at=now,
        metadata={"model_tool": _MODEL_RULE_ID},
    )
    return Finding(
        finding_id=finding_id,
        run_id=run_id,
        fingerprint=digest,
        title=title[:500],
        description=rationale[:2000],
        cwe_category=mapped if mapped is not None else CWECategory.UNCLASSIFIED,
        severity=severity,
        status=FindingStatus.UNPROCESSED,
        provenance=FindingProvenance.MODEL,
        observations=[observation],
        evidence_strength=EvidenceStrength.NONE,
        evidence_refs=[observation_id],
        created_at=now,
        updated_at=now,
        metadata={
            "title": title[:500],
            "rationale": rationale[:2000],
            "evidence": evidence[:2000],
        },
    )


def promote_model_only(
    model_only: list[dict[str, Any]],
    *,
    snapshot_root: str,
    run_id: str,
) -> list[Finding]:
    """Quảng bá các ứng viên chỉ thuộc về mô hình có bằng chứng mã nguồn đọc được.

    Mỗi Finding trả về đều mang ``provenance == MODEL`` ở cấp cao nhất.
    Không bao giờ ném ngoại lệ: các mục lỗi sẽ bị bỏ qua.
    """
    promoted: list[Finding] = []
    for candidate in model_only or []:
        try:
            finding = _promote_one(candidate, snapshot_root=snapshot_root, run_id=run_id)
        except Exception as exc:  # noqa: BLE001 - one bad candidate never kills promotion
            logger.debug("skipping unpromotable candidate: %s", exc)
            continue
        if finding is not None:
            promoted.append(finding)
    return promoted
