"""CVSS v4.0 deterministic scorer.

Implements the CVSS v4.0 base scoring formula from the FIRST specification:
https://www.first.org/cvss/v4.0/specification-document

No external scoring library required — the formula is self-contained.
Parses and validates vector strings, computes base score, derives
qualitative severity, and checks that all required metrics are present.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import Enum

# CVSS 4.0 metric value weights (Section 18)
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_AT = {"N": 0.85, "P": 0.62}
_PR = {
    "N": 0.85,
    "L": {"U": 0.62, "H": 0.68},
    "H": {"U": 0.27, "H": 0.50},
}
_UI = {"N": 0.85, "P": 0.62}
_IMPACT = {"N": 0.00, "L": 0.15, "H": 0.56}
_IMPACT_SI_SA = {"N": 0.00, "L": 0.15, "H": 0.56}


class Severity(str, Enum):
    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass(frozen=True)
class CVSSResult:
    """Parsed and scored CVSS v4.0 vector."""
    vector: str
    base_score: float
    qualitative: Severity
    metrics: dict[str, str]
    missing: list[str]


def _severity_from_score(score: float) -> Severity:
    if score == 0.0:
        return Severity.NONE
    elif score <= 3.9:
        return Severity.LOW
    elif score <= 6.9:
        return Severity.MEDIUM
    elif score <= 8.9:
        return Severity.HIGH
    else:
        return Severity.CRITICAL


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS v4.0 vector string into a metric dict.

    Raises ValueError if the vector is malformed.
    """
    if not vector.startswith("CVSS:4.0/"):
        raise ValueError(
            f"Invalid CVSS v4.0 vector: must start with 'CVSS:4.0/', got '{vector[:20]}'"
        )
    parts = vector[len("CVSS:4.0/"):].split("/")
    metrics = {}
    for part in parts:
        if ":" not in part:
            raise ValueError(f"Invalid metric in vector: '{part}'")
        key, val = part.split(":", 1)
        if key in metrics:
            raise ValueError(f"Duplicate metric: '{key}'")
        metrics[key] = val
    return metrics


REQUIRED_BASE = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA"]


def score(vector: str) -> CVSSResult:
    """Parse, validate, and score a CVSS v4.0 vector string.

    Returns a :class:`CVSSResult` with the computed score, qualitative
    severity, parsed metrics, and list of missing required metrics.
    """
    metrics = parse_vector(vector)

    # Check required metrics
    missing = [m for m in REQUIRED_BASE if m not in metrics]

    # If critical metrics are missing, score is 0
    critical_missing = [m for m in ["AV", "AC", "AT", "PR", "UI"] if m not in metrics]
    if critical_missing:
        return CVSSResult(
            vector=vector,
            base_score=0.0,
            qualitative=Severity.NONE,
            metrics=metrics,
            missing=missing,
        )

    # Get metric values with defaults for optional ones
    scope = metrics.get("S", "U")
    av = _AV.get(metrics["AV"], 0.0)
    ac = _AC.get(metrics["AC"], 0.0)
    at = _AT.get(metrics["AT"], 0.0)

    # PR is scope-dependent
    pr_val = metrics["PR"]
    if pr_val in _PR:
        if isinstance(_PR[pr_val], dict):
            pr = _PR[pr_val].get(scope, 0.0)
        else:
            pr = _PR[pr_val]
    else:
        pr = 0.0

    ui = _UI.get(metrics["UI"], 0.0)

    # Vulnerability subsystem impact metrics (Section 18.3)
    vc = _IMPACT.get(metrics.get("VC", "N"), 0.0)
    vi = _IMPACT.get(metrics.get("VI", "N"), 0.0)
    va = _IMPACT.get(metrics.get("VA", "N"), 0.0)

    # Subsequent system impact metrics (Section 18.4)
    sc = _IMPACT_SI_SA.get(metrics.get("SC", "N"), 0.0)
    si = _IMPACT_SI_SA.get(metrics.get("SI", "N"), 0.0)
    sa = _IMPACT_SI_SA.get(metrics.get("SA", "N"), 0.0)

    # Step 1: Vulnerability subsystem (Section 18.3)
    iss_v = 1.0 - ((1.0 - vc) * (1.0 - vi) * (1.0 - va))
    if iss_v <= 0.0:
        impact_v = 0.0
    else:
        impact_v = 7.52 * (iss_v - 0.029) - 3.25 * (iss_v * 0.9731 - 0.02) ** 13
        impact_v = max(impact_v, 0.0)

    # Step 2: Subsequent system (Section 18.4)
    iss_s = 1.0 - ((1.0 - sc) * (1.0 - si) * (1.0 - sa))
    if iss_s <= 0.0:
        impact_s = 0.0
    else:
        impact_s = 7.52 * (iss_s - 0.029) - 3.25 * (iss_s * 0.9731 - 0.02) ** 13
        impact_s = max(impact_s, 0.0)

    # Step 3: Exploitability (Section 18.5)
    exploitability = 8.22 * av * ac * at * pr * ui

    # Step 4: Base score (Section 18.6)
    if scope == "U":
        # Unchanged: only vulnerability subsystem impact
        if impact_v <= 0:
            score_val = 0.0
        else:
            score_val = min(impact_v + exploitability, 10.0)
    else:
        # Changed: combine both subsystems with 1.08 multiplier
        if impact_v <= 0 and impact_s <= 0:
            score_val = 0.0
        else:
            score_val = min(1.08 * (impact_v + impact_s + exploitability), 10.0)

    # Round up to one decimal place per spec
    score_val = math.ceil(score_val * 10.0) / 10.0

    return CVSSResult(
        vector=vector,
        base_score=score_val,
        qualitative=_severity_from_score(score_val),
        metrics=metrics,
        missing=missing,
    )


def validate(vector: str) -> list[str]:
    """Validate a CVSS v4.0 vector. Returns list of error strings (empty = valid)."""
    errors = []
    if not vector.startswith("CVSS:4.0/"):
        errors.append(f"Must start with 'CVSS:4.0/', got '{vector[:20]}'")
        return errors

    try:
        metrics = parse_vector(vector)
    except ValueError as e:
        errors.append(str(e))
        return errors

    for m in REQUIRED_BASE:
        if m not in metrics:
            errors.append(f"Missing required metric: {m}")

    # Validate metric values
    valid_av = {"N", "A", "L", "P"}
    valid_ac = {"L", "H"}
    valid_at = {"N", "P"}
    valid_pr = {"N", "L", "H"}
    valid_ui = {"N", "P"}
    valid_impact = {"N", "L", "H"}
    valid_scope = {"U", "H"}
    valid_s = {"U", "H"}

    checks = [
        ("AV", valid_av), ("AC", valid_ac), ("AT", valid_at),
        ("PR", valid_pr), ("UI", valid_ui), ("S", valid_s),
        ("VC", valid_impact), ("VI", valid_impact), ("VA", valid_impact),
        ("SC", valid_impact), ("SI", valid_impact), ("SA", valid_impact),
    ]

    for key, valid_vals in checks:
        if key in metrics and metrics[key] not in valid_vals:
            errors.append(f"Invalid value for {key}: '{metrics[key]}' (valid: {valid_vals})")

    return errors
