"""Xây dựng lại các câu hỏi được định kiểu từ dạng dict được sử dụng trên đường truyền.

Bộ xử lý theo lô truyền các câu hỏi dưới dạng dict thuần túy, vì vậy module này
là nơi duy nhất chuyển đổi chúng trở lại thành hợp đồng định kiểu.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from vulnscan.contracts.decision import DecisionQuestion, DecisionType


def _criteria_from_native(qtype: DecisionType, criteria: Any) -> dict[str, str] | list[str]:
    """Khôi phục cấu trúc tiêu chí (criteria shape) ban đầu.

    Một thang điểm (score rubric) là một *danh sách thứ tự* các nhãn cấp độ, trong khi
    một bảng lựa chọn (choice rubric) là một dict gồm ``value -> description``. Dạng dict
    gây mơ hồ trên đường truyền, vì vậy một dict có khóa thứ tự được đọc ngược lại thành danh sách
    ban đầu; nếu không, một chu trình khứ hồi sẽ âm thầm thay đổi câu hỏi mà mô hình nhìn thấy.
    """
    if isinstance(criteria, list):
        return [str(item) for item in criteria]
    if not isinstance(criteria, Mapping):
        return {}
    ordinal = sorted(criteria) == [str(i) for i in range(len(criteria))]
    if qtype is DecisionType.SCORE and ordinal:
        return [str(criteria[key]) for key in sorted(criteria, key=int)]
    return {str(key): str(value) for key, value in criteria.items()}


def to_decision_questions(native: dict[str, dict[str, Any]]) -> dict[str, DecisionQuestion]:
    """Xây dựng lại các câu hỏi được định kiểu từ dạng dict mà batcher truyền qua lại."""
    questions: dict[str, DecisionQuestion] = {}
    for name, raw in native.items():
        qtype = DecisionType(raw["type"])
        questions[name] = DecisionQuestion(
            name=name,
            type=qtype,
            instructions=str(raw.get("instructions", "")),
            criteria=_criteria_from_native(qtype, raw.get("criteria", {})),
        )
    return questions
