"""Common value-object base classes shared by every contract model.

Kept dependency-light (stdlib only) so that importing the contract layer never
pulls scanner SDKs or provider clients. All Pydantic models in this package
inherit from :class:`VulnscanBaseModel`, which pins the project-wide serialization
policy in one place.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class VulnscanBaseModel(BaseModel):
    """Base for every contract model.

    - ``extra="forbid"`` rejects unknown keys so a malformed payload from a
      scanner or provider fails loudly instead of silently dropping data.
    - ``populate_by_name`` lets consumers construct with either the field name
      or its alias (useful when ingesting native tool JSON).
    - ``use_enum_values`` is intentionally NOT enabled: consumers rely on the
      enum members, and serialized output is still a plain string because every
      enum subclasses ``str``.
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
        """Return a plain, JSON-serializable copy of this record."""
        return self.model_dump(mode="json")


class VersionedModel(VulnscanBaseModel):
    """Marker mixin for records that carry an explicit schema version.

    Contracts evolve; every persisted and exported record keeps its
    ``version`` so consumers can migrate instead of guessing. Where a model
    represents an artifact rather than a schema shape, ``version`` holds the
    artifact version (e.g. rule pack, policy, procedure).
    """

    version: str = Field(
        default="0.1.0",
        description="Version of this record's schema or artifact, e.g. '0.1.0'.",
    )


__all__ = ["Field", "VersionedModel", "VulnscanBaseModel"]
