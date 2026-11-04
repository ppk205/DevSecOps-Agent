"""CVSS v4.0 MacroVector scoring, adapted from FIRST's BSD-2-Clause reference.

Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors.
SPDX-License-Identifier: BSD-2-Clause. See CVSS4-LICENSE.txt.
Reference commit: c5b0d409ae9f57c44264c6ce5f27d89298e1d32a.
Incomplete Base vectors remain unscored. Scores do not verify metric assumptions.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from itertools import product

from ._cvss4_data import LOOKUP, MAX_COMPOSED, MAX_SEVERITY, METRICS

REQUIRED_BASE = list(METRICS)[:11]
_ENVIRONMENTAL = list(METRICS)[12:26]
_ORDER = {key: index for index, key in enumerate(METRICS)}
_LEVELS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}
_GROUPS = [
    ("AV", "PR", "UI"),
    ("AC", "AT"),
    ("VC", "VI", "VA", "CR", "IR", "AR"),
    ("SC", "SI", "SA"),
]


class Severity(str, Enum):
    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass(frozen=True)
class CVSSResult:
    vector: str
    base_score: float | None
    qualitative: Severity | None
    metrics: dict[str, str]
    missing: list[str]
    overall_score: float | None = None
    overall_qualitative: Severity | None = None
    nomenclature: str = "CVSS-B"


def _severity_from_score(value: float | None) -> Severity | None:
    if value is None:
        return None
    if value == 0:
        return Severity.NONE
    if value < 4:
        return Severity.LOW
    if value < 7:
        return Severity.MEDIUM
    if value < 9:
        return Severity.HIGH
    return Severity.CRITICAL


def parse_vector(vector: str) -> dict[str, str]:
    """Parse valid v4 tokens in specification order, permitting incomplete Base."""
    if not isinstance(vector, str) or not vector.startswith("CVSS:4.0/"):
        raise ValueError("Vector must start with CVSS:4.0/")
    metrics: dict[str, str] = {}
    last = -1
    for part in vector[len("CVSS:4.0/") :].split("/"):
        if part.count(":") != 1:
            raise ValueError("Malformed CVSS metric")
        key, value = part.split(":")
        if key not in METRICS:
            raise ValueError("Unknown CVSS v4.0 metric")
        if key in metrics:
            raise ValueError("Duplicate CVSS metric")
        if _ORDER[key] < last:
            raise ValueError("Invalid CVSS v4.0 metric order")
        if value not in METRICS[key]:
            raise ValueError("Invalid value for CVSS metric " + key)
        metrics[key] = value
        last = _ORDER[key]
    return metrics


def validate(vector: str) -> list[str]:
    try:
        metrics = parse_vector(vector)
    except ValueError as exc:
        return [str(exc)]
    return ["Missing required metric: " + key for key in REQUIRED_BASE if key not in metrics]


def _effective(metrics: dict[str, str]) -> dict[str, str]:
    values = {key: metrics.get(key, "X") for key in METRICS}
    for key in REQUIRED_BASE:
        if values["M" + key] != "X":
            values[key] = values["M" + key]
    for key in ("CR", "IR", "AR"):
        if values[key] == "X":
            values[key] = "H"
    if values["E"] == "X":
        values["E"] = "A"
    return values


def _macro(values: dict[str, str]) -> str:
    first = [values["AV"] == "N", values["PR"] == "N", values["UI"] == "N"]
    eq1 = 0 if all(first) else 1 if any(first) and values["AV"] != "P" else 2
    eq2 = 0 if values["AC"] == "L" and values["AT"] == "N" else 1
    eq3 = (
        0
        if values["VC"] == values["VI"] == "H"
        else 1
        if any(values[key] == "H" for key in ("VC", "VI", "VA"))
        else 2
    )
    eq4 = (
        0
        if "S" in (values["MSI"], values["MSA"])
        else 1
        if any(values[key] == "H" for key in ("SC", "SI", "SA"))
        else 2
    )
    eq5 = {"A": 0, "P": 1, "U": 2}[values["E"]]
    eq6 = (
        0
        if any(
            values[requirement] == "H" and values[impact] == "H"
            for requirement, impact in [("CR", "VC"), ("IR", "VI"), ("AR", "VA")]
        )
        else 1
    )
    return "".join(str(value) for value in (eq1, eq2, eq3, eq4, eq5, eq6))


@lru_cache(maxsize=270)
def _highest_vectors(code: str) -> tuple[dict[str, str], ...]:
    groups = [
        MAX_COMPOSED["eq1"][code[0]],
        MAX_COMPOSED["eq2"][code[1]],
        MAX_COMPOSED["eq3"][code[2]][code[5]],
        MAX_COMPOSED["eq4"][code[3]],
        MAX_COMPOSED["eq5"][code[4]],
    ]
    return tuple(
        dict(part.split(":") for part in "".join(parts).strip("/").split("/"))
        for parts in product(*groups)
    )


def _calculate(metrics: dict[str, str]) -> float:
    values = _effective(metrics)
    if all(values[key] == "N" for key in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0
    code = _macro(values)
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(value) for value in code)
    macro_score = LOOKUP[code]

    def lookup(parts: tuple[int, ...]) -> float | None:
        return LOOKUP.get("".join(str(value) for value in parts))

    lower = [lookup((eq1 + 1, eq2, eq3, eq4, eq5, eq6)), lookup((eq1, eq2 + 1, eq3, eq4, eq5, eq6))]
    if eq3 == 0 and eq6 == 0:
        a = lookup((eq1, eq2, eq3, eq4, eq5, eq6 + 1))
        b = lookup((eq1, eq2, eq3 + 1, eq4, eq5, eq6))
        next_combined = max(a, b) if a is not None and b is not None else b
    elif (eq3, eq6) in {(1, 1), (0, 1)}:
        next_combined = lookup((eq1, eq2, eq3 + 1, eq4, eq5, eq6))
    elif (eq3, eq6) == (1, 0):
        next_combined = lookup((eq1, eq2, eq3, eq4, eq5, eq6 + 1))
    else:
        next_combined = lookup((eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1))
    lower.extend(
        [
            next_combined,
            lookup((eq1, eq2, eq3, eq4 + 1, eq5, eq6)),
            lookup((eq1, eq2, eq3, eq4, eq5 + 1, eq6)),
        ]
    )
    distances: dict[str, float] = {}
    for highest in _highest_vectors(code):
        distances = {
            key: levels[values[key]] - levels[highest[key]] for key, levels in _LEVELS.items()
        }
        if all(value >= 0 for value in distances.values()):
            break
    else:
        raise ValueError("CVSS MacroVector maximum could not be resolved")
    current = [sum(distances[key] for key in group) for group in _GROUPS] + [0.0]
    depths = [
        float(MAX_SEVERITY["eq1"][code[0]]) * 0.1,
        float(MAX_SEVERITY["eq2"][code[1]]) * 0.1,
        float(MAX_SEVERITY["eq3eq6"][code[2]][code[5]]) * 0.1,
        float(MAX_SEVERITY["eq4"][code[3]]) * 0.1,
        1.0,
    ]
    normalized = [
        (macro_score - next_score) * (distance / depth)
        for next_score, distance, depth in zip(lower, current, depths, strict=True)
        if next_score is not None
    ]
    mean = sum(normalized) / len(normalized) if normalized else 0.0
    value = min(10.0, max(0.0, macro_score - mean))
    return math.floor(value * 10.0 + 0.5) / 10.0


def score(vector: str) -> CVSSResult:
    """Return true Base score and separate contextual score; never score missing Base."""
    metrics = parse_vector(vector)
    missing = [key for key in REQUIRED_BASE if key not in metrics]
    threat = metrics.get("E", "X") != "X"
    environmental = any(metrics.get(key, "X") != "X" for key in _ENVIRONMENTAL)
    name = "CVSS-B" + ("T" if threat else "") + ("E" if environmental else "")
    if missing:
        return CVSSResult(vector, None, None, metrics, missing, nomenclature=name)
    base = _calculate({key: metrics[key] for key in REQUIRED_BASE})
    overall = _calculate(metrics) if threat or environmental else base
    return CVSSResult(
        vector,
        base,
        _severity_from_score(base),
        metrics,
        [],
        overall,
        _severity_from_score(overall),
        name,
    )
