"""Các data contract dùng chung cho pipeline DevSecOps-Agent.

Import các model từ thư mục gốc của package này thay vì từ từng tệp riêng lẻ:

    from vulnscan.contracts import Finding, RunStatus, ScanSpecification

Các thay đổi contract do coordinator quản lý: sau T00, các cập nhật phải thông qua
coordinator, người sẽ cập nhật đồng thời cả các nơi sử dụng lẫn các fixture.
"""

from __future__ import annotations

from .__all__ import *
from .__all__ import __all__

# Liên kết lại danh sách đã export dưới tên riêng của package này.
__all__ = list(__all__)
