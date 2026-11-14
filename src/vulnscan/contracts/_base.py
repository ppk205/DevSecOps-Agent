"""Các lớp cơ sở value-object phổ biến được dùng chung bởi mọi model contract.

Được giữ ở mức ít phụ thuộc (chỉ dùng stdlib) để việc import tầng contract không bao giờ
kéo theo các SDK của scanner hay client của provider. Tất cả các Pydantic model trong package này
kế thừa từ :class:`VulnscanBaseModel`, nơi ghim chính sách tuần tự hóa trên toàn bộ dự án tại một chỗ duy nhất.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class VulnscanBaseModel(BaseModel):
    """Lớp cơ sở cho mọi model contract.

    - ``extra="forbid"`` từ chối các khóa lạ để payload sai định dạng từ
      scanner hoặc provider sẽ báo lỗi ngay lập tức thay vì âm thầm loại bỏ dữ liệu.
    - ``populate_by_name`` cho phép các nơi sử dụng khởi tạo bằng tên trường
      hoặc alias của nó (rất hữu ích khi nạp JSON của các công cụ native).
    - ``use_enum_values`` cố tình KHÔNG được bật: bên sử dụng dựa vào các thành viên
      enum, và đầu ra sau khi tuần tự hóa vẫn là chuỗi thuần túy vì mọi enum đều kế thừa từ ``str``.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        validate_assignment=True,
        frozen=False,
        use_enum_values=False,
        str_strip_whitespace=True,
    )

    def snapshot(self) -> dict[str, Any]:
        """Trả về một bản sao thuần túy, có thể tuần tự hóa sang JSON của bản ghi này."""
        return self.model_dump(mode="json")


class VersionedModel(VulnscanBaseModel):
    """Marker mixin cho các bản ghi có mang phiên bản schema tường minh.

    Các contract có sự phát triển; mỗi bản ghi được lưu trữ và xuất khẩu đều giữ
    ``version`` của nó để bên sử dụng có thể migrate thay vì đoán mò. Khi một model
    đại diện cho một artifact thay vì hình dạng schema, ``version`` sẽ chứa
    phiên bản artifact (ví dụ: rule pack, policy, procedure).
    """

    version: str = Field(
        default="0.1.0",
        description="Version of this record's schema or artifact, e.g. '0.1.0'.",
    )


__all__ = ["Field", "VersionedModel", "VulnscanBaseModel"]
