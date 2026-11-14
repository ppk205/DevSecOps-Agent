"""Giao thức định tuyến quyết định cố định (frozen).

Mọi thứ trong file này là một cam kết ổn định. Việc thay đổi bất kỳ giá trị nào ở đây là
một breaking change đối với hợp đồng quyết định và phải nâng phiên bản tương ứng.
"""

from __future__ import annotations

from typing import Final

# --- Phiên bản hợp đồng -----------------------------------------------------

CONTRACT_VERSION: Final[str] = "decision-contract-2"
INPUT_FORMAT_VERSION: Final[str] = "laya-state-2"
ROUTING_POLICY_VERSION: Final[str] = "laya-policy-2"
QUESTION_SET_VERSION: Final[str] = "laya-questions-1"

# --- Ghim phiên bản model ----------------------------------------------------

MODEL_ID: Final[str] = "convaiinnovations/laya"
MODEL_REVISION: Final[str] = "aa8c91ca088ec597df95a0d1c76b3063cb2ae5e8"
MODEL_LICENSE: Final[str] = "Apache-2.0"

# --- Ghim phiên bản phụ thuộc ------------------------------------------------

# Các phiên bản đã được xác minh trên máy tham chiếu RTX 3050 4 GB (Windows 11,
# Python 3.11.15). ``torch`` được ghim vào bản build CUDA 12.4; wheel CPU
# là phương án dự phòng được chấp nhận và phải được báo cáo khi hoạt động.
VERIFIED_DEPENDENCIES: Final[dict[str, str]] = {
    "laya": "0.3.20",
    "torch": "2.6.0+cu124",
    "transformers": "5.17.0",
    "python": "3.11.15",
}

# --- Giới hạn runtime --------------------------------------------------------

MAX_INPUT_TOKENS: Final[int] = 512
MAX_INPUT_CHARS: Final[int] = 1_500
DEFAULT_TIMEOUT_SECONDS: Final[int] = 30
DEFAULT_BATCH_SIZE: Final[int] = 4

# --- Ngữ nghĩa ngưỡng --------------------------------------------------------
#
# Đây là các ngưỡng định tuyến khuyến nghị, không phải ngưỡng mức độ nghiêm trọng hay trạng thái.
# Chúng quyết định lane nào một finding được *gợi ý*; chúng không bao giờ cấp hoặc từ chối
# một trạng thái, và không ngưỡng nào được dùng để từ chối bằng chứng.

#: Đạt hoặc vượt quá độ tin cậy câu trả lời này, route đã chọn được giữ nguyên.
HIGH_CONFIDENCE_THRESHOLD: Final[float] = 0.85

#: Đạt hoặc vượt quá điểm ``needs_human_review`` này, finding sẽ được định tuyến tới
#: con người bất kể hai câu trả lời còn lại.
REVIEW_THRESHOLD: Final[float] = 0.60

#: Độ tin cậy thấp hơn mức này sẽ chuyển finding tới ``human_review``
#: thay vì để phỏng đoán độ tin cậy thấp chọn một lane rẻ hơn.
ESCALATION_FLOOR: Final[float] = 0.50

# --- Che giấu dữ liệu nhạy cảm ----------------------------------------------
#
# Model tuyệt đối không được thấy thông tin đăng nhập, secret hoặc nhãn do con người gán. Các khóa này
# bị loại bỏ khỏi state envelope trước khi nó đến backend.

REDACTED_KEYS: Final[frozenset[str]] = frozenset(
    {
        "api_key",
        "apikey",
        "auth_token",
        "authorization",
        "aws_secret_access_key",
        "credential",
        "credentials",
        "label",
        "labels",
        "owner_password",
        "password",
        "passwd",
        "private_key",
        "refresh_token",
        "secret",
        "secrets",
        "session_token",
        "token",
    }
)

REDACTION_PLACEHOLDER: Final[str] = "[REDACTED]"

# --- Tập câu hỏi ------------------------------------------------------------
#
# Ba câu hỏi có kiểu mà mọi quyết định định tuyến phải trả lời. Thứ tự là một phần của
# giao thức truyền tải (wire contract).

ROUTING_QUESTION_NAMES: Final[tuple[str, ...]] = (
    "recommended_action",
    "evidence_sufficiency",
    "needs_human_review",
)

# --- Hành vi dự phòng --------------------------------------------------------
#
# Mọi trường hợp lỗi bên dưới đều phải chuyển hướng về pipeline cơ sở. Pipeline cơ sở
# không bao giờ phụ thuộc vào việc model có hiện diện hay chạy chính xác hay không.

FALLBACK_ROUTE: Final[str] = "baseline_fallback"
FALLBACK_DECISION_STATUS: Final[str] = "incomplete"

#: ``error_code`` -> ý nghĩa cho con người đọc, được lưu trong artifact để người xem báo cáo
#: có thể phân biệt giữa việc model thực sự từ chối và lỗi truyền tải.
ERROR_CODES: Final[dict[str, str]] = {
    "dependency_unavailable": "Laya or its runtime dependency is missing; install the optional environment.",
    "backend_unavailable": "Model loading or inference failed; check checkpoint identity and device.",
    "package_missing": "The laya package is not installed; routing skipped.",
    "model_unavailable": "The model could not be loaded; routing skipped.",
    "timeout": "Inference exceeded the configured timeout; routing skipped.",
    "out_of_memory": "Inference ran out of GPU memory; routing skipped.",
    "malformed_output": "The model response could not be parsed; routing skipped.",
    "unknown": "Unclassified failure; routing skipped.",
}

# --- Thẩm quyền trạng thái ---------------------------------------------------
#
# Bất biến duy nhất của hệ thống con này. Câu trả lời của model có thể được ghi lại như
# metadata khuyến nghị, nhưng giá trị của ``Finding.status`` chỉ có thể được ghi tại đây.

STATUS_OWNER: Final[str] = "IndependentValidator"
ADVISORY_AFFECTS_FINDING_STATUS: Final[bool] = False
