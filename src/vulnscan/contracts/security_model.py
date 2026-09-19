"""SecurityModelRef — versioned application-specific security model for a CWE group (ACC-02, ACC-05).

Each model covers request inputs, dangerous operations, helpers, sanitizers,
authentication checks, and their applicability for a given CWE group.
Regression fixture references anchor the model to testable examples.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from ._base import VersionedModel
from .enums import CWECategory, ModelApplicability


class RegressionFixtureRef(VersionedModel):
    """Pointer to a single regression fixture used by or validating a model."""

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
    """References a versioned security model for a CWE category.

    Models are frozen per evaluation run; changes require a new ``model_version``.
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
