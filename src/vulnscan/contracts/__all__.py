"""Complete public export list for the vulnscan contracts package.

Single source of truth: ``__init__.py`` imports from here, and downstream
modules import from ``vulnscan.contracts`` rather than reaching into individual
files.  Evaluator-only models are exported but must never be exposed through
inference contracts or scanner/agent input mounts.
"""

from __future__ import annotations

# Base classes and Field helper
from ._base import Field, VersionedModel, VulnscanBaseModel
from .artifact import ArtifactReference
from .assessment import Assessment, CVSSAssessment
from .authorization import AuthorizationPolicyRef, MappedRoute
from .context_evidence import (
    AmbiguousResolution,
    ContextEvidence,
    DataflowPath,
    JSPContext,
)

# Accuracy contracts (ACC-01 .. ACC-07)
from .coverage import CoverageRecord
from .decision import (
    DecisionAnswer,
    DecisionQuestion,
    DecisionRequest,
    DecisionResult,
    DecisionRoute,
    DecisionStatus,
    DecisionType,
)

# ruff: noqa: RUF022  (semantic grouping intentionally overrides alphabetical __all__)
# Enums (shared vocabulary across every module)
from .enums import (
    WEB_SOURCE_EXTENSIONS,
    CoverageUnitStatus,
    CWECategory,
    EvidenceKind,
    EvidenceStrength,
    ExportFormat,
    ExtractionMode,
    FindingStatus,
    LanguageKind,
    MissReason,
    ModelApplicability,
    OperationKind,
    PolicyAssumptionStatus,
    ProviderProtocol,
    RoleKind,
    RunStatus,
    Severity,
    SplitMembership,
    StageStatus,
    ToolName,
    VariantRelationship,
    VerificationOutcome,
    language_from_extension,
)

# Evaluator-only records (ACC-05..07) — never exposed to scanners or agents
from .evaluation import EvaluationCase, MatchingCriteria, ReviewJudgment
from .finding import Finding, FindingGroup, Observation, SourceCoordinate

# Providers, artifacts, and reporting
from .provider import ProviderProfile, ProviderUsage
from .report import (
    FindingCounts,
    ReportExport,
    SarifLocation,
    SarifReport,
    SarifResult,
)
from .run_manifest import (
    ModelSettings,
    RunManifest,
    StageTiming,
    ToolVersionRecord,
)

# Core pipeline models
from .scan_spec import ScanSpecification, ToolConfig
from .scanner_result import ScannerResult
from .security_model import RegressionFixtureRef, SecurityModelRef
from .validation import EvidenceRecord, ValidationDecision
from .verification import VerificationObservation

__all__ = [
    # Base
    "Field",
    "VersionedModel",
    "VulnscanBaseModel",
    # Enums
    "CoverageUnitStatus",
    "CWECategory",
    "EvidenceKind",
    "EvidenceStrength",
    "ExtractionMode",
    "ExportFormat",
    "FindingStatus",
    "LanguageKind",
    "WEB_SOURCE_EXTENSIONS",
    "language_from_extension",
    "MissReason",
    "ModelApplicability",
    "OperationKind",
    "PolicyAssumptionStatus",
    "ProviderProtocol",
    "RoleKind",
    "RunStatus",
    "Severity",
    "SplitMembership",
    "StageStatus",
    "ToolName",
    "VariantRelationship",
    "VerificationOutcome",
    # Core pipeline
    "ScanSpecification",
    "ToolConfig",
    "ScannerResult",
    "SourceCoordinate",
    "Observation",
    "FindingGroup",
    "Finding",
    "Assessment",
    "CVSSAssessment",
    "EvidenceRecord",
    "ValidationDecision",
    "ToolVersionRecord",
    "StageTiming",
    "ModelSettings",
    "RunManifest",
    # Accuracy contracts
    "CoverageRecord",
    "RegressionFixtureRef",
    "SecurityModelRef",
    "MappedRoute",
    "AuthorizationPolicyRef",
    "DataflowPath",
    "AmbiguousResolution",
    "JSPContext",
    "ContextEvidence",
    "DecisionType",
    "DecisionStatus",
    "DecisionQuestion",
    "DecisionRequest",
    "DecisionAnswer",
    "DecisionResult",
    "DecisionRoute",
    "VerificationObservation",
    # Evaluator-only
    "MatchingCriteria",
    "ReviewJudgment",
    "EvaluationCase",
    # Providers, artifacts, reporting
    "ProviderProfile",
    "ProviderUsage",
    "ArtifactReference",
    "FindingCounts",
    "ReportExport",
    "SarifLocation",
    "SarifResult",
    "SarifReport",
]
