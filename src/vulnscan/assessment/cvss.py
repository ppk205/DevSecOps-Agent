"""Bộ tính điểm xác định cho CVSS v4.0.

Triển khai công thức tính điểm cơ sở CVSS v4.0 từ đặc tả của FIRST:
https://www.first.org/cvss/v4.0/specification-document

Không yêu cầu thư viện tính điểm bên ngoài — công thức hoàn toàn độc lập.
Phân tích và xác thực chuỗi vector, tính base score, suy ra
mức độ nghiêm trọng định tính, và kiểm tra tính đầy đủ của tất cả các metric bắt buộc.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum

# Trọng số giá trị metric CVSS 4.0 (Mục 18)
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_AT = {"N": 0.85, "P": 0.62}
_PR: dict[str, float | dict[str, float]] = {
    "N": 0.85,
    "L": {"U": 0.62, "H": 0.68},
    "H": {"U": 0.27, "H": 0.50},
}
_UI = {"N": 0.85, "P": 0.62}
_IMPACT = {"N": 0.00, "L": 0.15, "H": 0.56}
_IMPACT_SI_SA = {"N": 0.00, "L": 0.15, "H": 0.56}


class Severity(str, Enum):
    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass(frozen=True)
class CVSSResult:
    """Vector CVSS v4.0 đã được phân tích cú pháp và tính điểm."""

    vector: str
    base_score: float
    qualitative: Severity
    metrics: dict[str, str]
    missing: list[str]


def _severity_from_score(score: float) -> Severity:
    if score == 0.0:
        return Severity.NONE
    elif score <= 3.9:
        return Severity.LOW
    elif score <= 6.9:
        return Severity.MEDIUM
    elif score <= 8.9:
        return Severity.HIGH
    else:
        return Severity.CRITICAL


def parse_vector(vector: str) -> dict[str, str]:
    """Phân tích một chuỗi vector CVSS v4.0 thành dict metric.

    Ném ra ValueError nếu vector bị sai định dạng.
    """
    if not vector.startswith("CVSS:4.0/"):
        raise ValueError(
            f"Invalid CVSS v4.0 vector: must start with 'CVSS:4.0/', got '{vector[:20]}'"
        )
    parts = vector[len("CVSS:4.0/") :].split("/")
    metrics = {}
    for part in parts:
        if ":" not in part:
            raise ValueError(f"Invalid metric in vector: '{part}'")
        key, val = part.split(":", 1)
        if key in metrics:
            raise ValueError(f"Duplicate metric: '{key}'")
        metrics[key] = val
    return metrics


REQUIRED_BASE = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA"]


def score(vector: str) -> CVSSResult:
    """Phân tích, xác thực và tính điểm cho chuỗi vector CVSS v4.0.

    Trả về một :class:`CVSSResult` với điểm số đã tính, mức độ nghiêm trọng
    định tính, các metric đã phân tích cú pháp và danh sách các metric bắt buộc bị thiếu.
    """
    metrics = parse_vector(vector)

    # Kiểm tra các metric bắt buộc
    missing = [m for m in REQUIRED_BASE if m not in metrics]

    # Nếu thiếu các metric quan trọng, điểm số là 0
    critical_missing = [m for m in ["AV", "AC", "AT", "PR", "UI"] if m not in metrics]
    if critical_missing:
        return CVSSResult(
            vector=vector,
            base_score=0.0,
            qualitative=Severity.NONE,
            metrics=metrics,
            missing=missing,
        )

    # Lấy giá trị metric với các giá trị mặc định cho metric tùy chọn
    scope = metrics.get("S", "U")
    av = _AV.get(metrics["AV"], 0.0)
    ac = _AC.get(metrics["AC"], 0.0)
    at = _AT.get(metrics["AT"], 0.0)

    # PR phụ thuộc vào scope
    pr_val = metrics["PR"]
    if pr_val in _PR:
        entry = _PR[pr_val]
        if isinstance(entry, dict):
            pr = entry.get(scope, 0.0)
        else:
            pr = entry
    else:
        pr = 0.0

    ui = _UI.get(metrics["UI"], 0.0)

    # Các metric tác động lên hệ thống con chứa lỗ hổng (Mục 18.3)
    vc = _IMPACT.get(metrics.get("VC", "N"), 0.0)
    vi = _IMPACT.get(metrics.get("VI", "N"), 0.0)
    va = _IMPACT.get(metrics.get("VA", "N"), 0.0)

    # Các metric tác động lên hệ thống kế tiếp (Mục 18.4)
    sc = _IMPACT_SI_SA.get(metrics.get("SC", "N"), 0.0)
    si = _IMPACT_SI_SA.get(metrics.get("SI", "N"), 0.0)
    sa = _IMPACT_SI_SA.get(metrics.get("SA", "N"), 0.0)

    # Bước 1: Hệ thống con chứa lỗ hổng (Mục 18.3)
    iss_v = 1.0 - ((1.0 - vc) * (1.0 - vi) * (1.0 - va))
    if iss_v <= 0.0:
        impact_v = 0.0
    else:
        impact_v = 7.52 * (iss_v - 0.029) - 3.25 * (iss_v * 0.9731 - 0.02) ** 13
        impact_v = max(impact_v, 0.0)

    # Bước 2: Hệ thống kế tiếp (Mục 18.4)
    iss_s = 1.0 - ((1.0 - sc) * (1.0 - si) * (1.0 - sa))
    if iss_s <= 0.0:
        impact_s = 0.0
    else:
        impact_s = 7.52 * (iss_s - 0.029) - 3.25 * (iss_s * 0.9731 - 0.02) ** 13
        impact_s = max(impact_s, 0.0)

    # Bước 3: Khả năng khai thác (Section 18.5)
    exploitability = 8.22 * av * ac * at * pr * ui

    # Bước 4: Base score (Mục 18.6)
    if scope == "U":
        # Không đổi (Unchanged): chỉ có tác động lên hệ thống con chứa lỗ hổng
        if impact_v <= 0:
            score_val = 0.0
        else:
            score_val = min(impact_v + exploitability, 10.0)
    else:
        # Thay đổi (Changed): kết hợp cả hai hệ thống con với hệ số nhân 1.08
        if impact_v <= 0 and impact_s <= 0:
            score_val = 0.0
        else:
            score_val = min(1.08 * (impact_v + impact_s + exploitability), 10.0)

    # Làm tròn lên đến một chữ số thập phân theo đặc tả
    score_val = math.ceil(score_val * 10.0) / 10.0

    return CVSSResult(
        vector=vector,
        base_score=score_val,
        qualitative=_severity_from_score(score_val),
        metrics=metrics,
        missing=missing,
    )


def validate(vector: str) -> list[str]:
    """Xác thực một vector CVSS v4.0. Trả về danh sách chuỗi lỗi (rỗng = hợp lệ)."""
    errors = []
    if not vector.startswith("CVSS:4.0/"):
        errors.append(f"Must start with 'CVSS:4.0/', got '{vector[:20]}'")
        return errors

    try:
        metrics = parse_vector(vector)
    except ValueError as e:
        errors.append(str(e))
        return errors

    for m in REQUIRED_BASE:
        if m not in metrics:
            errors.append(f"Missing required metric: {m}")

    # Xác thực các giá trị metric
    valid_av = {"N", "A", "L", "P"}
    valid_ac = {"L", "H"}
    valid_at = {"N", "P"}
    valid_pr = {"N", "L", "H"}
    valid_ui = {"N", "P"}
    valid_impact = {"N", "L", "H"}
    valid_s = {"U", "H"}

    checks = [
        ("AV", valid_av),
        ("AC", valid_ac),
        ("AT", valid_at),
        ("PR", valid_pr),
        ("UI", valid_ui),
        ("S", valid_s),
        ("VC", valid_impact),
        ("VI", valid_impact),
        ("VA", valid_impact),
        ("SC", valid_impact),
        ("SI", valid_impact),
        ("SA", valid_impact),
    ]

    for key, valid_vals in checks:
        if key in metrics and metrics[key] not in valid_vals:
            errors.append(f"Invalid value for {key}: '{metrics[key]}' (valid: {valid_vals})")

    return errors
