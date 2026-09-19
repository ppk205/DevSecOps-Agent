"""AuthorizationPolicyRef — declared authorization policy for target roles (ACC-03).

Both students independently review intended permissions; observed implementation
cannot define its own correctness.  Missing or disputed policy leaves affected
findings unresolved.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from ._base import VersionedModel
from .enums import (
    OperationKind,
    PolicyAssumptionStatus,
    RoleKind,
)


class MappedRoute(VersionedModel):
    """A route or enforcement point mapped to an authorization-policy entry."""

    http_method: str = Field(
        ...,
        description="HTTP method, e.g. 'GET', 'POST'.",
    )
    path_pattern: str = Field(
        ...,
        description="URL path pattern, e.g. '/order/{id}'.",
    )
    controller_class: str | None = Field(
        default=None,
        description="Fully qualified controller/servlet class name.",
    )
    action_method: str | None = Field(
        default=None,
        description="Method inside the controller that handles this route.",
    )


class AuthorizationPolicyRef(VersionedModel):
    """One entry in the declared authorization policy.

    Each entry states what a given role is allowed (or assumed) to do on a
    specific resource type, optionally scoped by an ownership condition.
    """

    policy_id: str = Field(
        ...,
        description="Stable identifier for this policy entry.",
        pattern=r"^[a-z][a-z0-9-]{2,63}$",
    )
    policy_version: str = Field(
        ...,
        description="Version of the overall authorization policy document.",
    )
    role: RoleKind = Field(
        ...,
        description="Role this policy entry applies to.",
    )
    resource: str = Field(
        ...,
        description="Resource type or identifier, e.g. 'order', 'user_profile'.",
    )
    operation: OperationKind = Field(
        ...,
        description="Operation type (read, create, update, delete, execute, manage).",
    )
    allowed: bool = Field(
        ...,
        description="True if the role is permitted; False if explicitly denied.",
    )
    ownership_condition: str | None = Field(
        default=None,
        description=(
            "Scope condition, e.g. 'owner_or_admin', 'same_seller'.  "
            "None means no ownership restriction."
        ),
    )
    assumption_status: PolicyAssumptionStatus = Field(
        default=PolicyAssumptionStatus.UNREVIEWED,
        description="Review state of this policy entry.",
    )
    reviewed_by: list[str] = Field(
        default_factory=list,
        description="Usernames or agent IDs that reviewed this entry.",
    )
    mapped_routes: list[MappedRoute] = Field(
        default_factory=list,
        description="Routes or enforcement points this policy entry covers.",
    )
    notes: str = Field(
        default="",
        description="Free-text notes about this policy entry.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form metadata.",
    )


__all__ = ["AuthorizationPolicyRef", "MappedRoute"]
