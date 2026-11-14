"""Xác minh Laya đối với các ứng viên do mô hình săn tìm.

Mỗi ứng viên săn tìm trở thành một ``DecisionRequest`` (metadata ứng viên +
trích đoạn mã nguồn 30 dòng bị cô lập) dùng chung bộ câu hỏi triage đóng băng, và
mẻ dữ liệu đi qua ``LayaDecisionBackend.predict_many``. Kết quả được đính kèm
ngược lại vào các bản sao của ứng viên dưới dạng các trường chỉ mang tính cố vấn::

    {laya_route, laya_confidence, laya_status}

Laya ở đây chỉ đóng vai trò cố vấn, tương tự như trong giai đoạn shadow triage: nó ghi nhận
một tuyến, không bao giờ quyết định trạng thái finding (trạng thái chỉ thay đổi qua IndependentValidator).
Khi Laya không khả dụng, mọi mục sẽ nhận ``{"laya_status": "skipped"}``.
Hàm này không bao giờ ném ngoại lệ.
"""

from __future__ import annotations

import logging
from typing import Any

from vulnscan.ai.excerpts import code_excerpt
from vulnscan.contracts.decision import DecisionRequest
from vulnscan.decisions.laya import LayaDecisionBackend
from vulnscan.decisions.protocol import QUESTION_SET_VERSION
from vulnscan.decisions.router import DecisionRouter
from vulnscan.decisions.triage import build_triage_questions

logger = logging.getLogger(__name__)

_SKIPPED = "skipped"


def _candidate_line(candidate: dict[str, Any]) -> int:
    try:
        return int(candidate.get("line", 0) or 0)
    except (TypeError, ValueError):
        return 0


def laya_verify_candidates(
    candidates: list[dict[str, Any]],
    *,
    snapshot_root: str,
    laya_config: LayaDecisionBackend | Any | None = None,
) -> list[dict[str, Any]]:
    """Xác minh các ứng viên săn tìm với Laya; đính kèm route/confidence/status.

    Args:
        candidates: các mục đầu ra săn tìm (title, file, line, cwe, severity,
            rationale, evidence).
        snapshot_root: snapshot quét bất biến cho các trích đoạn bị cô lập.
        laya_config: một ``LayaDecisionBackend`` để tái sử dụng, hoặc None để xây dựng
            backend mặc định. Bất kỳ giá trị nào khác đều bị bỏ qua (sử dụng mặc định).

    Returns:
        Các dict mới (không thay đổi đầu vào) được đính kèm ``laya_route``,
        ``laya_confidence`` và ``laya_status``. Sự cố Laya
        (hoặc sự cố khởi tạo) sẽ đánh dấu mọi mục là ``skipped``.
    """
    if not candidates:
        return []
    questions = build_triage_questions()
    requests: list[DecisionRequest] = []
    for candidate in candidates:
        excerpt = code_excerpt(
            snapshot_root, str(candidate.get("file", "")), _candidate_line(candidate)
        )
        state: dict[str, Any] = {
            "title": str(candidate.get("title", "")),
            "file_path": str(candidate.get("file", "")),
            "line_start": _candidate_line(candidate),
            "cwe": str(candidate.get("cwe", "")),
            "severity": str(candidate.get("severity", "")),
            "rationale": str(candidate.get("rationale", "")),
            "evidence": str(candidate.get("evidence", "")),
            "code_excerpt": excerpt,
            "is_this_exploitable": (
                f"Is this finding exploitable? {candidate.get('title', '')} "
                f"at {candidate.get('file', '')}:{_candidate_line(candidate)} "
                f"({candidate.get('cwe', 'unknown CWE')}). "
                f"Rationale: {candidate.get('rationale', '')}"
            ),
        }
        requests.append(
            DecisionRequest(
                state=state,
                questions=questions,
                question_set_version=QUESTION_SET_VERSION,
            )
        )

    backend: LayaDecisionBackend
    if isinstance(laya_config, LayaDecisionBackend):
        backend = laya_config
    else:
        try:
            backend = LayaDecisionBackend()
        except Exception as exc:  # noqa: BLE001 - verify stage must never raise
            logger.warning("laya backend unavailable, skipping verification: %s", exc)
            return [{**c, "laya_status": _SKIPPED} for c in candidates]

    try:
        results = backend.predict_many(requests)
    except Exception as exc:  # noqa: BLE001 - verify stage must never raise
        logger.warning("laya verification failed, marking skipped: %s", exc)
        return [{**c, "laya_status": _SKIPPED} for c in candidates]

    router = DecisionRouter()
    enriched: list[dict[str, Any]] = []
    for candidate, request, result in zip(candidates, requests, results, strict=True):
        try:
            route = router.route(request=request, result=result, final_status=None)
            enriched.append(
                {
                    **candidate,
                    "laya_route": route.route,
                    "laya_confidence": route.confidence,
                    "laya_status": result.status.value,
                }
            )
        except Exception as exc:  # noqa: BLE001 - one bad row must not fail the batch
            logger.warning("laya route mapping failed for a candidate: %s", exc)
            enriched.append({**candidate, "laya_status": _SKIPPED})
    return enriched
