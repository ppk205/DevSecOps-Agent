"""Các chỉ số hiệu chuẩn và chất lượng định tuyến cho các quyết định khuyến nghị.

Đây là các con số T09 phải báo cáo. Không có gì ở đây đọc finding status: tầng
khuyến nghị được chấm điểm so với ground truth do bên gọi cung cấp, nhờ đó câu trả lời
của model có thể được chấm điểm mà không bao giờ cần tin tưởng nó để đặt trạng thái.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

CONFIDENCE_BINS = 10


@dataclass(frozen=True)
class Calibration:
    """Expected Calibration Error và điểm Brier cho một chuỗi độ tin cậy."""

    n: int
    ece: float
    brier: float
    mean_confidence: float
    accuracy: float

    def to_dict(self) -> dict[str, Any]:
        # Mọi điểm số là None khi không có gì được chấm điểm. Giá trị 0 ở đây sẽ bị hiểu
        # như một kết quả đo lường được, điều duy nhất mà T09 không được phép tự tạo ra.
        if self.n == 0:
            return {
                "n": 0,
                "ece": None,
                "brier": None,
                "mean_confidence": None,
                "accuracy": None,
            }
        return {
            "n": self.n,
            "ece": round(self.ece, 6),
            "brier": round(self.brier, 6),
            "mean_confidence": round(self.mean_confidence, 6),
            "accuracy": round(self.accuracy, 6),
        }


@dataclass(frozen=True)
class ReliabilityBin:
    """Một bin biểu đồ độ tin cậy: độ chính xác dự đoán so với quan sát được."""

    lo: float
    hi: float
    count: int
    mean_confidence: float
    accuracy: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "lo": round(self.lo, 4),
            "hi": round(self.hi, 4),
            "count": self.count,
            "mean_confidence": round(self.mean_confidence, 6),
            "accuracy": round(self.accuracy, 6),
        }


def compute_calibration(
    confidences: list[float],
    correct: list[bool],
    bins: int = CONFIDENCE_BINS,
) -> Calibration:
    """ECE và điểm Brier trên các bin độ tin cậy có độ rộng bằng nhau.

    ``correct`` ghi lại liệu kết quả mà model dự đoán cho một mục
    có thực sự xảy ra hay không; nó do evaluator cung cấp, không bao giờ được suy diễn từ
    câu trả lời của model.
    """
    if len(confidences) != len(correct):
        raise ValueError("confidences and correct must be the same length")
    if not confidences:
        return Calibration(n=0, ece=0.0, brier=0.0, mean_confidence=0.0, accuracy=0.0)

    total = len(confidences)
    accuracy = sum(correct) / total
    brier = (
        sum(
            (conf - (1.0 if ok else 0.0)) ** 2
            for conf, ok in zip(confidences, correct, strict=True)
        )
        / total
    )

    ece = 0.0
    for lo in range(bins):
        low, high = lo / bins, (lo + 1) / bins
        last = lo == bins - 1
        bucket = [
            (c, k)
            for c, k in zip(confidences, correct, strict=True)
            if (low <= c < high) or (last and c == 1.0)
        ]
        if not bucket:
            continue
        share = len(bucket) / total
        bucket_conf = sum(c for c, _ in bucket) / len(bucket)
        bucket_acc = sum(1 for _, k in bucket if k) / len(bucket)
        ece += share * abs(bucket_acc - bucket_conf)

    return Calibration(
        n=total,
        ece=ece,
        brier=brier,
        mean_confidence=sum(confidences) / total,
        accuracy=accuracy,
    )


def reliability_diagram(
    confidences: list[float],
    correct: list[bool],
    bins: int = CONFIDENCE_BINS,
) -> list[dict[str, Any]]:
    """Độ chính xác dự đoán so với quan sát theo từng bin cho biểu đồ độ tin cậy."""
    if len(confidences) != len(correct):
        raise ValueError("confidences and correct must be the same length")

    diagram: list[dict[str, Any]] = []
    for lo in range(bins):
        low, high = lo / bins, (lo + 1) / bins
        last = lo == bins - 1
        bucket = [
            (c, k)
            for c, k in zip(confidences, correct, strict=True)
            if (low <= c < high) or (last and c == 1.0)
        ]
        if not bucket:
            continue
        diagram.append(
            ReliabilityBin(
                lo=low,
                hi=high,
                count=len(bucket),
                mean_confidence=sum(c for c, _ in bucket) / len(bucket),
                accuracy=sum(1 for _, k in bucket if k) / len(bucket),
            ).to_dict()
        )
    return diagram


@dataclass
class RoutingReport:
    """Phân phối route, chất lượng chuyển cấp và phân tích chi tiết theo từng slice."""

    total: int
    route_counts: dict[str, int] = field(default_factory=dict)
    unavailable: int = 0
    false_escalations: int = 0
    missed_escalations: int = 0
    dangerous_downgrades: int = 0
    correct_routes: int = 0
    scored_routes: int = 0
    by_cwe: dict[str, dict[str, Any]] = field(default_factory=dict)
    by_language: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def route_accuracy(self) -> float | None:
        """``None`` khi không có gì được chấm điểm — không có mục chấm điểm không phải là độ chính xác 0%."""
        return self.correct_routes / self.scored_routes if self.scored_routes else None

    @property
    def false_escalation_rate(self) -> float | None:
        return self.false_escalations / self.scored_routes if self.scored_routes else None

    @staticmethod
    def _rate(value: float | None) -> float | None:
        return None if value is None else round(value, 6)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "route_counts": dict(sorted(self.route_counts.items(), key=lambda kv: -kv[1])),
            "unavailable": self.unavailable,
            "route_accuracy": self._rate(self.route_accuracy),
            "false_escalations": self.false_escalations,
            "missed_escalations": self.missed_escalations,
            "dangerous_downgrades": self.dangerous_downgrades,
            "false_escalation_rate": self._rate(self.false_escalation_rate),
            "scored_routes": self.scored_routes,
            "by_cwe": self.by_cwe,
            "by_language": self.by_language,
        }


def _slice_stats(entries: list[tuple[bool, bool]]) -> dict[str, Any]:
    """Số lượng đúng và giá trị trung bình cho một slice, chấp nhận slice rỗng."""
    if not entries:
        return {"n": 0, "correct": 0, "accuracy": 0.0}
    correct = sum(1 for ok, _ in entries if ok)
    return {
        "n": len(entries),
        "correct": correct,
        "accuracy": round(correct / len(entries), 6),
    }


def build_routing_report(
    rows: list[dict[str, Any]],
    expected_route_key: str = "expected_route",
) -> RoutingReport:
    """Chấm điểm các route khuyến nghị so với kỳ vọng do bên gọi cung cấp.

    Mỗi hàng cần ``route``, ``cwe`` và ``language``; các hàng chứa
    ``expected_route`` sẽ được chấm điểm, phần còn lại chỉ được đếm. ``True`` trong
    ``expected_route`` nghĩa là finding đáng để con người xem xét, vì vậy bất kỳ sự chuyển cấp nào
    lên ``human_review`` đều được tính là đúng; các trường hợp bỏ sót hoặc chuyển cấp không cần thiết
    được đếm riêng biệt.
    """
    report = RoutingReport(total=len(rows))

    cwe_buckets: dict[str, list[tuple[bool, bool]]] = defaultdict(list)
    lang_buckets: dict[str, list[tuple[bool, bool]]] = defaultdict(list)

    for row in rows:
        route = str(row.get("route", "unknown"))
        report.route_counts[route] = report.route_counts.get(route, 0) + 1

        if row.get("decision_status") != "completed":
            report.unavailable += 1

        expected = row.get(expected_route_key)
        if expected is None:
            continue

        if isinstance(expected, bool):
            # Kỳ vọng dạng boolean: finding này có đáng để con người xem xét không? Khi đó
            # điều duy nhất cần chấm điểm là liệu nó có được chuyển cấp hay không.
            should_escalate = expected
            escalated = route == "human_review"
            correct = escalated == should_escalate
            if should_escalate and not escalated:
                report.missed_escalations += 1
            elif escalated and not should_escalate:
                report.false_escalations += 1
        else:
            # Một lane có tên cụ thể được chấm điểm theo khớp chính xác, vì vậy một
            # cross_file_analysis được định tuyến đúng không được tính là bỏ sót do không chuyển cấp.
            should_escalate = route == str(expected)
            correct = route == str(expected)
            if expected != "human_review" and route == "human_review":
                report.false_escalations += 1
            if expected == "human_review" and route != "human_review":
                report.missed_escalations += 1
        if expected not in {False, "low_priority"} and route == "low_priority":
            report.dangerous_downgrades += 1

        report.scored_routes += 1
        report.correct_routes += int(correct)

        cwe_buckets[str(row.get("cwe", "unknown"))].append((correct, should_escalate))
        lang_buckets[str(row.get("language", "unknown"))].append((correct, should_escalate))

    report.by_cwe = {k: _slice_stats(v) for k, v in sorted(cwe_buckets.items())}
    report.by_language = {k: _slice_stats(v) for k, v in sorted(lang_buckets.items())}
    return report
