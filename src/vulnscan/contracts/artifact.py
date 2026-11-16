"""ArtifactReference — con trỏ nhẹ trỏ tới một artifact nhị phân hoặc văn bản đã được lưu trữ lâu dài.

Mọi tệp do pipeline tạo ra hoặc sử dụng (đầu ra thô của scanner, báo cáo JUnit,
ảnh chụp màn hình bằng chứng, SARIF được xuất) đều nhận một trong các con trỏ này. Checksum
đảm bảo khả năng tái tạo; MIME type đảm bảo các trình phân tích cú pháp hoạt động chính xác.
"""

from __future__ import annotations

from pydantic import Field

from ._base import VersionedModel
from .enums import LanguageKind


class ArtifactReference(VersionedModel):
    """Tham chiếu bất biến tới một tệp trên đĩa hoặc vị trí trong object-store."""

    path: str = Field(
        ...,
        description="Workspace-relative path (e.g. 'artifacts/semgrep/scan.json').",
    )
    checksum_sha256: str = Field(
        ...,
        description="Lower-case hex-encoded SHA-256 digest of the file contents.",
        min_length=64,
        max_length=64,
    )
    mime_type: str = Field(
        ...,
        description="IANA MIME type, e.g. 'application/json', 'text/html'.",
        pattern=r"^[a-z][a-z0-9.+-]+/[a-z][a-z0-9.+-]+$",
    )
    size_bytes: int | None = Field(
        default=None,
        description="File size in bytes.  None if unknown.",
        ge=0,
    )
    language_hint: LanguageKind | None = Field(
        default=None,
        description="Source language if the artifact is source code.",
    )
    encoding: str = Field(
        default="utf-8",
        description="Text encoding, default utf-8.",
    )

    def fingerprint(self) -> str:
        """Định danh ngắn gọn, dễ đọc cho con người trong nhật ký và báo cáo."""
        return f"{self.path}@{self.checksum_sha256[:12]}"


__all__ = ["ArtifactReference"]
