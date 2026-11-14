"""Danh sách export công khai hoàn chỉnh cho package vulnscan contracts.

Nguồn chân lý duy nhất: ``__init__.py`` import từ đây, và các module
hạ nguồn import từ ``vulnscan.contracts`` thay vì truy cập trực tiếp vào từng tệp riêng lẻ.
Các model chỉ dành cho evaluator được export nhưng tuyệt đối không bao giờ được lộ ra qua
các contract suy luận hoặc các điểm gắn kết đầu vào của scanner/agent.
"""

from __future__ import annotations

# Các lớp cơ sở và hàm trợ giúp Field
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

# Các contract về độ chính xác (ACC-01 .. ACC-07)
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
# Các Enum (từ vựng dùng chung giữa mọi module)
from .enums import (
    WEB_SOURCE_EXTENSIONS,
    CoverageUnitStatus,
    CWECategory,
    EvidenceKind,
    EvidenceStrength,
    ExportFormat,
    ExtractionMode,
    FindingProvenance,
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

# Các bản ghi chỉ dành cho evaluator (ACC-05..07) — không bao giờ để lộ cho scanner hoặc agent
from .evaluation import EvaluationCase, MatchingCriteria, ReviewJudgment
from .finding import Finding, FindingGroup, Observation, SourceCoordinate

# Các provider, artifact và báo cáo
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

# Các model cốt lõi của pipeline
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
    # Các Enum
    "CoverageUnitStatus",
    "CWECategory",
    "EvidenceKind",
    "EvidenceStrength",
    "ExtractionMode",
    "ExportFormat",
    "FindingStatus",
    "FindingProvenance",
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
    # Pipeline cốt lõi
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
    # Các contract về độ chính xác
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
    # Chỉ dành cho evaluator
    "MatchingCriteria",
    "ReviewJudgment",
    "EvaluationCase",
    # Các provider, artifact, báo cáo
    "ProviderProfile",
    "ProviderUsage",
    "ArtifactReference",
    "FindingCounts",
    "ReportExport",
    "SarifLocation",
    "SarifResult",
    "SarifReport",
]
