"""Frozen decision-routing protocol.

Everything in this file is a stability promise. Changing any value here is a
breaking change to the decision contract and must bump the relevant version.
"""

from __future__ import annotations

from typing import Final

# --- Contract versioning -----------------------------------------------------

CONTRACT_VERSION: Final[str] = "decision-contract-2"
INPUT_FORMAT_VERSION: Final[str] = "laya-state-2"
ROUTING_POLICY_VERSION: Final[str] = "laya-policy-2"
QUESTION_SET_VERSION: Final[str] = "laya-questions-1"

# --- Model pin ---------------------------------------------------------------

MODEL_ID: Final[str] = "convaiinnovations/laya"
MODEL_REVISION: Final[str] = "aa8c91ca088ec597df95a0d1c76b3063cb2ae5e8"
MODEL_LICENSE: Final[str] = "Apache-2.0"

# --- Dependency pin ----------------------------------------------------------

# Versions verified on the RTX 3050 4 GB reference machine (Windows 11,
# Python 3.11.15). ``torch`` is pinned to the CUDA 12.4 build; the CPU wheel
# is an acceptable fallback and must be reported when active.
VERIFIED_DEPENDENCIES: Final[dict[str, str]] = {
    "laya": "0.3.20",
    "torch": "2.6.0+cu124",
    "transformers": "5.17.0",
    "python": "3.11.15",
}

# --- Runtime limits ----------------------------------------------------------

MAX_INPUT_TOKENS: Final[int] = 512
MAX_INPUT_CHARS: Final[int] = 1_500
DEFAULT_TIMEOUT_SECONDS: Final[int] = 30
DEFAULT_BATCH_SIZE: Final[int] = 4

# --- Threshold semantics -----------------------------------------------------
#
# These are advisory routing thresholds, not severity or status thresholds.
# They decide which lane a finding is *suggested* for; they never grant or deny
# a status, and no threshold may be used to reject evidence.

#: At or above this answer confidence, the chosen route is taken as-is.
HIGH_CONFIDENCE_THRESHOLD: Final[float] = 0.85

#: At or above this ``needs_human_review`` score, the finding is routed to a
#: human regardless of the other two answers.
REVIEW_THRESHOLD: Final[float] = 0.60

#: A confidence strictly below this sends the finding to ``human_review``
#: rather than letting a low-confidence guess pick a cheaper lane.
ESCALATION_FLOOR: Final[float] = 0.50

# --- Redaction ---------------------------------------------------------------
#
# The model must never see credentials, secrets, or human labels. These keys are
# dropped from the state envelope before it reaches the backend.

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

# --- Question set ------------------------------------------------------------
#
# The three typed questions every routing decision must answer. Order is part of
# the wire contract.

ROUTING_QUESTION_NAMES: Final[tuple[str, ...]] = (
    "recommended_action",
    "evidence_sufficiency",
    "needs_human_review",
)

# --- Fallback behaviour ------------------------------------------------------
#
# Every failure mode below must degrade to the baseline pipeline. The baseline
# never depends on the model being present or correct.

FALLBACK_ROUTE: Final[str] = "baseline_fallback"
FALLBACK_DECISION_STATUS: Final[str] = "incomplete"

#: ``error_code`` -> human meaning, persisted in artifacts so a report reader
#: can tell a genuine model refusal from a transport failure.
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

# --- Status authority --------------------------------------------------------
#
# The single invariant of this subsystem. A model answer may be recorded as
# advisory metadata, but the value of ``Finding.status`` is writable only here.

STATUS_OWNER: Final[str] = "IndependentValidator"
ADVISORY_AFFECTS_FINDING_STATUS: Final[bool] = False
