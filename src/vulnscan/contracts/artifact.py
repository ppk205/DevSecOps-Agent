"""ArtifactReference — lightweight pointer to a persisted binary or text artifact.

Every file produced or consumed by the pipeline (scanner raw output, JUnit
report, evidence screenshot, exported SARIF) gets one of these.  Checksums
ensure reproducibility; MIME type keeps parsers honest.
"""

from __future__ import annotations

from pydantic import Field

from ._base import VersionedModel
from .enums import LanguageKind


class ArtifactReference(VersionedModel):
    """Immutable reference to a file on disk or object-store location."""

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
        """Short, human-readable identifier for logs and reports."""
        return f"{self.path}@{self.checksum_sha256[:12]}"


__all__ = ["ArtifactReference"]
