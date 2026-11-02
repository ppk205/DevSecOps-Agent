"""Shared enumerations for the DevSecOps-Agent contract layer.

These enums are used across modules (scanners, normalization, assessment,
validation, reporting) so that status values and categories are never spelled
differently between components. Every value is a stable string so that
serialized JSON records remain readable across versions.
"""

from __future__ import annotations

from enum import Enum


class RunStatus(str, Enum):
    """Lifecycle of a whole scan run as persisted in storage."""

    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    SKIPPED = "skipped"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"
    INTERRUPTED = "interrupted"
    CANCELLED = "cancelled"
    RETRYING = "retrying"


class StageStatus(str, Enum):
    """Lifecycle of a single stage (intake, scan, normalize, assess, ...)."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
    INTERRUPTED = "interrupted"
    RETRYING = "retrying"
    BLOCKED = "blocked"


class Severity(str, Enum):
    """Reference severity categories.

    Native scanner severities are mapped onto these categories; numeric CVSS
    equivalents are never invented for them.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNDETERMINED = "undetermined"


class CWECategory(str, Enum):
    """The twelve planned source-code vulnerability groups, plus dependency and
    unclassified tracks.

    Values use the canonical CWE identifier so records stay comparable across
    tools. The dependency track is evaluated separately from source-code groups.
    """

    # Injection family
    SQL_INJECTION = "CWE-89"
    COMMAND_INJECTION = "CWE-78"
    CODE_INJECTION = "CWE-94"
    LDAP_INJECTION = "CWE-90"
    XPATH_INJECTION = "CWE-643"
    # Cross-site scripting family
    XSS = "CWE-79"
    # Authentication and session management
    AUTH_FAILURE = "CWE-287"
    SESSION_FIXATION = "CWE-384"
    # Access control
    BROKEN_ACCESS_CONTROL = "CWE-862"
    IDOR = "CWE-639"
    # Sensitive data exposure
    SENSITIVE_DATA_EXPOSURE = "CWE-200"
    HARD_CODED_SECRET = "CWE-798"
    INSECURE_RANDOMNESS = "CWE-330"
    INSECURE_DESERIALIZATION = "CWE-502"
    # Security misconfiguration
    SECURITY_MISCONFIGURATION = "CWE-16"
    # Cryptographic failures
    CRYPTOGRAPHIC_FAILURE = "CWE-327"
    # Logging and monitoring
    INSUFFICIENT_LOGGING = "CWE-778"
    # Dependency track (evaluated separately)
    DEPENDENCY_VULNERABILITY = "CWE-1104"
    UNCLASSIFIED = "CWE-UNCLASSIFIED"


class FindingStatus(str, Enum):
    """Workflow status of a grouped finding.

    An AI assessment may never move a finding directly to CONFIRMED or
    REJECTED; only independent validation can.
    """

    UNPROCESSED = "unprocessed"
    TRIAGED = "triaged"
    ASSESSED = "assessed"
    PENDING_VALIDATION = "pending_validation"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    UNRESOLVED = "unresolved"


class VerificationOutcome(str, Enum):
    """Outcome of independent verification. Kept distinct from evidence strength."""

    DEMONSTRATED = "demonstrated"
    BLOCKED = "blocked"
    HARNESSED_FAILED = "harness_failed"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"
    NOT_VERIFIED = "not_verified"


class EvidenceStrength(str, Enum):
    """Qualitative strength of the evidence backing a conclusion.

    Static support is not proof of successful exploitation; a failed test is
    not proof that a vulnerability is absent.
    """

    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    STRUCTURAL_ONLY = "structural_only"
    NONE = "none"


class ExportFormat(str, Enum):
    """Supported report export formats."""

    SARIF = "sarif"
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"
    TXT = "txt"
    DOCX = "docx"


class ToolName(str, Enum):
    """Deterministic scanners supported by the pipeline."""

    SEMGREP = "semgrep"
    SPOTBUGS = "spotbugs"
    FIND_SEC_BUGS = "findsecbugs"
    OWASP_DEPENDENCY_CHECK = "owasp-dependency-check"
    GITLEAKS = "gitleaks"
    CODEQL = "codeql"


class ExtractionMode(str, Enum):
    """How a scanner derived its view of a unit of analysis (ACC-01, ACC-07)."""

    FULL_AST = "full_ast"
    PARTIAL_AST = "partial_ast"
    DATAFLOW = "dataflow"
    PATTERN = "pattern"
    BYTECODE = "bytecode"
    DEPENDENCY_GRAPH = "dependency_graph"
    TEXT = "text"
    JSP_PRECOMPILED = "jsp_precompiled"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"


class CoverageUnitStatus(str, Enum):
    """Per-unit analysis status used by coverage records (ACC-07).

    Skipped units cannot appear successfully analyzed; partial and failed are
    reported separately from analyzed.
    """

    ANALYZED = "analyzed"
    PARTIAL = "partial"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"
    SKIPPED = "skipped"
    NOT_ELIGIBLE = "not_eligible"
    NOT_PROCESSED = "not_processed"


class LanguageKind(str, Enum):
    """Source language of an analysis unit; Java and JSP reconcile separately."""

    JAVA = "java"
    JSP = "jsp"
    OTHER = "other"


class EvidenceKind(str, Enum):
    """Kind of evidence attached to an observation or assessment."""

    STATIC = "static"
    DATAFLOW = "dataflow"
    RUNTIME = "runtime"
    STRUCTURAL = "structural"
    POLICY = "policy"
    MODEL = "model"
    DOCUMENTATION = "documentation"


class ProviderProtocol(str, Enum):
    """Wire protocol used to talk to a BYOK model provider."""

    OPENAI_CHAT_COMPLETIONS = "openai_chat_completions"
    OPENAI_RESPONSES = "openai_responses"
    ANTHROPIC_MESSAGES = "anthropic_messages"
    OPENAI_COMPATIBLE = "openai_compatible"


class RoleKind(str, Enum):
    """Roles in the declared authorization policy (ACC-03)."""

    CUSTOMER = "customer"
    SELLER = "seller"
    ADMINISTRATOR = "administrator"
    SHIPPER = "shipper"
    ANONYMOUS = "anonymous"


class PolicyAssumptionStatus(str, Enum):
    """Review state of an authorization-policy entry (ACC-03)."""

    INTENDED = "intended"
    IMPLEMENTED_OBSERVED = "implemented_observed"
    DISPUTED = "disputed"
    MISSING = "missing"
    UNREVIEWED = "unreviewed"


class SplitMembership(str, Enum):
    """Dataset split of an evaluation case (evaluator only)."""

    DEVELOPMENT = "development"
    HELD_OUT = "held_out"
    EVALUATION = "evaluation"
    EXCLUDED = "excluded"


class VariantRelationship(str, Enum):
    """Relationship of a variant inside its case family (evaluator only)."""

    VULNERABLE = "vulnerable"
    FIXED = "fixed"
    NEGATIVE = "negative"
    REGRESSION = "regression"


class MissReason(str, Enum):
    """Classification of a missed finding by stage (ACC-07).

    Multiple contributing reasons are permitted, plus an explicit undetermined
    reason pending review; unsupported causal explanations are never forced.
    """

    MISSING_RULE = "missing_rule"
    BROKEN_EXTRACTION = "broken_extraction"
    MISSING_MODEL = "missing_model"
    UNSUPPORTED_FLOW = "unsupported_flow"
    INCORRECT_GROUPING = "incorrect_grouping"
    AI_REJECTION = "ai_rejection"
    VERIFICATION_LIMITATION = "verification_limitation"
    UNDETERMINED = "undetermined"


class ModelApplicability(str, Enum):
    """Applicability of a versioned security model (ACC-02, ACC-05)."""

    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    PARTIAL = "partial"
    UNVERIFIED = "unverified"
    SUPERSEDED = "superseded"


class OperationKind(str, Enum):
    """Coarse operation vocabulary for authorization-policy references."""

    READ = "read"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    MANAGE = "manage"


__all__ = [
    "CWECategory",
    "CoverageUnitStatus",
    "EvidenceKind",
    "EvidenceStrength",
    "ExportFormat",
    "ExtractionMode",
    "FindingStatus",
    "LanguageKind",
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
]
