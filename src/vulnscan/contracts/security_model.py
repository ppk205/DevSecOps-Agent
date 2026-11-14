"""SecurityModelRef — mô hình bảo mật theo ứng dụng được đánh phiên bản cho một nhóm CWE (ACC-02, ACC-05).

Mỗi mô hình bao gồm đầu vào request, các thao tác nguy hiểm, helper, hàm làm sạch (sanitizer),
kiểm tra xác thực và khả năng áp dụng của chúng cho một nhóm CWE nhất định.
Các tham chiếu fixture hồi quy gắn chặt mô hình với các ví dụ có thể kiểm thử được.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from ._base import VersionedModel
from .enums import CWECategory, ModelApplicability


class RegressionFixtureRef(VersionedModel):
    """Con trỏ tới một fixture hồi quy đơn lẻ được sử dụng bởi hoặc để xác thực một mô hình."""

    fixture_id: str = Field(
        ...,
        description="Stable fixture identifier within the regression suite.",
    )
    fixture_path: str = Field(
        ...,
        description="Relative path to the fixture file.",
    )
    expected_detection: bool = Field(
        ...,
        description="True if this fixture is expected to produce a finding.",
    )
    description: str = Field(
        default="",
        description="Human-readable description of what the fixture tests.",
    )


class SecurityModelRef(VersionedModel):
    """Tham chiếu đến một mô hình bảo mật được tạo phiên bản cho một danh mục CWE.

    Các mô hình được đóng băng cho mỗi lần chạy đánh giá; các thay đổi yêu cầu một ``model_version`` mới.
    """

    model_id: str = Field(
        ...,
        description="Stable model identifier, e.g. 'sqli-servlet-refs'.",
        pattern=r"^[a-z][a-z0-9-]{2,63}$",
    )
    model_version: str = Field(
        ...,
        description="Version of this model's schema/content.",
    )
    cwe_category: CWECategory = Field(
        ...,
        description="CWE group this model covers.",
    )
    applicability: ModelApplicability = Field(
        ...,
        description="Whether this model is applicable to the current target.",
    )
    provenance: str = Field(
        ...,
        description=(
            "How the model was created (e.g. 'manual', 'ai-assisted', "
            "'generated-from-fixtures').  Both students reviewed models."
        ),
    )
    description: str = Field(
        default="",
        description="Free-text summary of the model's scope and assumptions.",
    )
    inputs_covered: list[str] = Field(
        default_factory=list,
        description="List of request input types or helpers this model tracks.",
    )
    operations_covered: list[str] = Field(
        default_factory=list,
        description="Dangerous operations or sinks this model tracks.",
    )
    sanitizers_covered: list[str] = Field(
        default_factory=list,
        description="Sanitizer or validation helpers this model recognizes.",
    )
    auth_checks_covered: list[str] = Field(
        default_factory=list,
        description="Authentication/authorization checks this model tracks.",
    )
    assumptions: list[str] = Field(
        default_factory=list,
        description=(
            "Assumptions made during model construction (e.g. 'no ORM "
            "abstraction layer', 'JPA queries use string concatenation')."
        ),
    )
    regression_fixtures: list[RegressionFixtureRef] = Field(
        default_factory=list,
        description="Regression fixtures used to validate and test this model.",
    )
    limitations: list[str] = Field(
        default_factory=list,
        description="Known limitations or gaps in model coverage.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form metadata.",
    )


__all__ = ["RegressionFixtureRef", "SecurityModelRef"]
