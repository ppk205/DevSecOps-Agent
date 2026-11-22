"""Các enum dùng chung cho tầng hợp đồng (contract layer) của DevSecOps-Agent.

Các enum này được sử dụng trên các module (scanner, normalization, assessment,
validation, reporting) để các giá trị trạng thái và danh mục không bao giờ bị viết
khác nhau giữa các thành phần. Mỗi giá trị là một chuỗi ổn định để các bản ghi
JSON được tuần tự hóa vẫn có thể đọc được qua các phiên bản.
"""

from __future__ import annotations

from enum import Enum


class RunStatus(str, Enum):
    """Vòng đời của toàn bộ một lần quét (scan run) được lưu trữ bền vững."""

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
    """Vòng đời của một giai đoạn đơn lẻ (intake, scan, normalize, assess, ...)."""

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
    """Các danh mục mức độ nghiêm trọng tham chiếu.

    Mức độ nghiêm trọng gốc của scanner được ánh xạ vào các danh mục này; không bao
    giờ tự tạo ra các giá trị số tương đương CVSS cho chúng.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNDETERMINED = "undetermined"


class CWECategory(str, Enum):
    """Mười hai nhóm lỗ hổng mã nguồn theo kế hoạch, cùng với các nhánh dependency
    và unclassified.

    Các giá trị sử dụng định danh CWE chuẩn để các bản ghi có thể so sánh được
    giữa các công cụ. Nhánh dependency được đánh giá riêng biệt với các nhóm mã nguồn.
    """

    # Nhóm lỗ hổng Injection
    SQL_INJECTION = "CWE-89"
    COMMAND_INJECTION = "CWE-78"
    CODE_INJECTION = "CWE-94"
    EVAL_INJECTION = "CWE-95"
    LDAP_INJECTION = "CWE-90"
    XPATH_INJECTION = "CWE-643"
    XXE = "CWE-611"
    SSRF = "CWE-918"
    NOSQL_INJECTION = "CWE-943"
    TEMPLATE_INJECTION = "CWE-1336"
    LOG_INJECTION = "CWE-117"
    HEADER_INJECTION = "CWE-113"
    OPEN_REDIRECT = "CWE-601"
    PATH_TRAVERSAL = "CWE-22"
    PHP_FILE_INCLUSION = "CWE-98"
    PROTOTYPE_POLLUTION = "CWE-1321"
    DYNAMIC_OBJECT_ATTRS = "CWE-915"
    # Nhóm lỗ hổng Cross-site scripting
    XSS = "CWE-79"
    # Quản lý xác thực và phiên làm việc
    AUTH_FAILURE = "CWE-287"
    SESSION_FIXATION = "CWE-384"
    # Kiểm soát truy cập (Access control)
    BROKEN_ACCESS_CONTROL = "CWE-862"
    IDOR = "CWE-639"
    # Lộ lọt dữ liệu nhạy cảm (Sensitive data exposure)
    SENSITIVE_DATA_EXPOSURE = "CWE-200"
    HARD_CODED_SECRET = "CWE-798"
    INSECURE_RANDOMNESS = "CWE-330"
    TIMING_ATTACK = "CWE-208"
    INSECURE_DESERIALIZATION = "CWE-502"
    WEAK_HASH = "CWE-328"
    TLS_CERT_VALIDATION_DISABLED = "CWE-295"
    # Cấu hình sai bảo mật (Security misconfiguration)
    SECURITY_MISCONFIGURATION = "CWE-16"
    DEBUG_LEFTOVER = "CWE-489"
    DEBUG_INFO_EXPOSURE = "CWE-215"
    STACK_TRACE_EXPOSURE = "CWE-209"
    INSECURE_COOKIE = "CWE-614"
    CORS_WILDCARD = "CWE-942"
    UNVERIFIED_COMM_CHANNEL = "CWE-940"
    INSUFFICIENT_COMPARISON = "CWE-697"
    IMPROPER_INPUT_VALIDATION = "CWE-20"
    UNSAFE_REFLECTION = "CWE-470"
    REDOS = "CWE-1333"
    # Lỗi mã hóa (Cryptographic failures)
    CRYPTOGRAPHIC_FAILURE = "CWE-327"
    # Ghi log và giám sát (Logging and monitoring)
    INSUFFICIENT_LOGGING = "CWE-778"
    # Điểm yếu chất lượng mã nguồn do các bộ phân tích bytecode (SpotBugs) báo cáo.
    # Được giữ tách biệt với UNCLASSIFIED để độ bao phủ của quy tắc có thể mở rộng mà không
    # giả định rằng mọi lỗi linting đều có thể khai thác được.
    UNCHECKED_RETURN_VALUE = "CWE-252"
    UNUSED_ASSIGNMENT = "CWE-563"
    IMPROPER_RESOURCE_SHUTDOWN = "CWE-404"
    GENERIC_EXCEPTION_CAUGHT = "CWE-396"
    UNICODE_ENCODING_ERROR = "CWE-176"
    IMPROPER_EXCEPTION_CHECK = "CWE-754"
    EXTERNALLY_CONTROLLED_FORMAT_STRING = "CWE-134"
    # Nhánh phụ thuộc (được đánh giá riêng biệt)
    DEPENDENCY_VULNERABILITY = "CWE-1104"
    UNCLASSIFIED = "CWE-UNCLASSIFIED"


class FindingStatus(str, Enum):
    """Trạng thái luồng công việc (workflow status) của một finding đã nhóm.

    Một đánh giá AI không bao giờ được chuyển trực tiếp một finding sang CONFIRMED
    hoặc REJECTED; chỉ validation độc lập mới có thể làm điều này.
    """

    UNPROCESSED = "unprocessed"
    TRIAGED = "triaged"
    ASSESSED = "assessed"
    PENDING_VALIDATION = "pending_validation"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    UNRESOLVED = "unresolved"


class FindingProvenance(str, Enum):
    """Lane nào đã tạo ra một finding: model hunt, scanner, hoặc cả hai.

    Tùy chọn trên hợp đồng Finding; nếu vắng mặt (None) nghĩa là scanner.
    """

    MODEL = "model"
    SCANNER = "scanner"
    BOTH = "both"


class VerificationOutcome(str, Enum):
    """Kết quả của việc xác minh độc lập. Được giữ tách biệt với độ mạnh của bằng chứng."""

    DEMONSTRATED = "demonstrated"
    BLOCKED = "blocked"
    HARNESSED_FAILED = "harness_failed"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"
    NOT_VERIFIED = "not_verified"


class EvidenceStrength(str, Enum):
    """Độ mạnh định tính của bằng chứng hỗ trợ cho một kết luận.

    Bằng chứng tĩnh không phải là bằng chứng của việc khai thác thành công; một bài kiểm
    tra thất bại không phải là bằng chứng cho thấy lỗ hổng không tồn tại.
    """

    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    STRUCTURAL_ONLY = "structural_only"
    NONE = "none"


class ExportFormat(str, Enum):
    """Các định dạng xuất báo cáo được hỗ trợ."""

    SARIF = "sarif"
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"
    TXT = "txt"
    DOCX = "docx"


class ToolName(str, Enum):
    """Các scanner tất định được hỗ trợ bởi pipeline."""

    SEMGREP = "semgrep"
    NATIVE_HUNT = "native-hunt"
    SPOTBUGS = "spotbugs"
    FIND_SEC_BUGS = "findsecbugs"
    OWASP_DEPENDENCY_CHECK = "owasp-dependency-check"
    GITLEAKS = "gitleaks"
    CODEQL = "codeql"
    TRIVY = "trivy"


class ExtractionMode(str, Enum):
    """Cách một scanner thu được góc nhìn về một đơn vị phân tích (ACC-01, ACC-07)."""

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
    """Trạng thái phân tích theo từng đơn vị được sử dụng bởi các bản ghi độ bao phủ (ACC-07).

    Các đơn vị bị bỏ qua không thể hiển thị là đã phân tích thành công; các trạng
    thái partial và failed được báo cáo tách biệt với analyzed.
    """

    ANALYZED = "analyzed"
    PARTIAL = "partial"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"
    SKIPPED = "skipped"
    NOT_ELIGIBLE = "not_eligible"
    NOT_PROCESSED = "not_processed"


class LanguageKind(str, Enum):
    """Source language of an analysis unit; each language family reconciles separately."""

    JAVA = "java"
    KOTLIN = "kotlin"
    JSP = "jsp"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    PYTHON = "python"
    PHP = "php"
    GO = "go"
    RUBY = "ruby"
    CPP = "cpp"
    CSHARP = "csharp"
    OTHER = "other"


#: File extensions scanned as source across the supported language families.
WEB_SOURCE_EXTENSIONS = frozenset(
    {
        ".java",
        ".kt",
        ".kts",
        ".jsp",
        ".jspx",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".vue",
        ".py",
        ".php",
        ".phtml",
        ".go",
        ".rb",
        ".erb",
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
        ".hh",
        ".hpp",
        ".hxx",
        ".cs",
        ".cshtml",
        ".razor",
    }
)

_EXTENSION_LANGUAGE: dict[str, LanguageKind] = {
    ".java": LanguageKind.JAVA,
    ".kt": LanguageKind.KOTLIN,
    ".kts": LanguageKind.KOTLIN,
    ".jsp": LanguageKind.JSP,
    ".jspx": LanguageKind.JSP,
    ".js": LanguageKind.JAVASCRIPT,
    ".jsx": LanguageKind.JAVASCRIPT,
    ".mjs": LanguageKind.JAVASCRIPT,
    ".cjs": LanguageKind.JAVASCRIPT,
    ".vue": LanguageKind.JAVASCRIPT,
    ".ts": LanguageKind.TYPESCRIPT,
    ".tsx": LanguageKind.TYPESCRIPT,
    ".py": LanguageKind.PYTHON,
    ".php": LanguageKind.PHP,
    ".phtml": LanguageKind.PHP,
    ".go": LanguageKind.GO,
    ".rb": LanguageKind.RUBY,
    ".erb": LanguageKind.RUBY,
    ".c": LanguageKind.CPP,
    ".cc": LanguageKind.CPP,
    ".cpp": LanguageKind.CPP,
    ".cxx": LanguageKind.CPP,
    ".h": LanguageKind.CPP,
    ".hh": LanguageKind.CPP,
    ".hpp": LanguageKind.CPP,
    ".hxx": LanguageKind.CPP,
    ".cs": LanguageKind.CSHARP,
    ".cshtml": LanguageKind.CSHARP,
    ".razor": LanguageKind.CSHARP,
}


def language_from_extension(path: str) -> LanguageKind:
    """Map a file path to its language kind; unknown extensions are OTHER."""
    from pathlib import Path

    return _EXTENSION_LANGUAGE.get(Path(path).suffix.lower(), LanguageKind.OTHER)


class EvidenceKind(str, Enum):
    """Loại bằng chứng được đính kèm vào một observation hoặc assessment."""

    STATIC = "static"
    DATAFLOW = "dataflow"
    RUNTIME = "runtime"
    STRUCTURAL = "structural"
    POLICY = "policy"
    MODEL = "model"
    DOCUMENTATION = "documentation"


class ProviderProtocol(str, Enum):
    """Giao thức truyền thông (wire protocol) được sử dụng để giao tiếp với model provider BYOK."""

    OPENAI_CHAT_COMPLETIONS = "openai_chat_completions"
    OPENAI_RESPONSES = "openai_responses"
    ANTHROPIC_MESSAGES = "anthropic_messages"
    OPENAI_COMPATIBLE = "openai_compatible"
    V0_PLATFORM_API = "v0_platform_api"


class RoleKind(str, Enum):
    """Các role trong chính sách phân quyền được khai báo (ACC-03)."""

    CUSTOMER = "customer"
    SELLER = "seller"
    ADMINISTRATOR = "administrator"
    SHIPPER = "shipper"
    ANONYMOUS = "anonymous"


class PolicyAssumptionStatus(str, Enum):
    """Trạng thái rà soát của một mục chính sách phân quyền (ACC-03)."""

    INTENDED = "intended"
    IMPLEMENTED_OBSERVED = "implemented_observed"
    DISPUTED = "disputed"
    MISSING = "missing"
    UNREVIEWED = "unreviewed"


class SplitMembership(str, Enum):
    """Phân chia tập dữ liệu (dataset split) của một ca đánh giá (chỉ dành cho evaluator)."""

    DEVELOPMENT = "development"
    HELD_OUT = "held_out"
    EVALUATION = "evaluation"
    EXCLUDED = "excluded"


class VariantRelationship(str, Enum):
    """Mối quan hệ của một biến thể bên trong nhóm ca (case family) của nó (chỉ dành cho evaluator)."""

    VULNERABLE = "vulnerable"
    FIXED = "fixed"
    NEGATIVE = "negative"
    REGRESSION = "regression"


class MissReason(str, Enum):
    """Phân loại finding bị bỏ sót theo từng giai đoạn (ACC-07).

    Cho phép nhiều lý do đóng góp, cộng với một lý do undetermined tường minh
    chờ rà soát; không bao giờ áp đặt các giải thích nguyên nhân không có căn cứ.
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
    """Khả năng áp dụng của một mô hình bảo mật được tạo phiên bản (ACC-02, ACC-05)."""

    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    PARTIAL = "partial"
    UNVERIFIED = "unverified"
    SUPERSEDED = "superseded"


class OperationKind(str, Enum):
    """Từ vựng thao tác tổng quát cho các tham chiếu chính sách phân quyền."""

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
    "FindingProvenance",
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
