"""Normalizer: ScannerResult -> list[Observation].

Validates each observation against contracts (invalid CWE, missing location).
Never invents coordinates. Pure: operates on already-fetched data.
"""

from __future__ import annotations

from vulnscan.contracts import CWECategory, Observation, ScannerResult


def normalize_result(result: ScannerResult) -> list[Observation]:
    """Extract and validate observations from a scanner result.

    Invalid observations (bad CWE, missing coordinates) are dropped — they
    never reach the grouping stage.
    """
    valid: list[Observation] = []
    for obs in result.observations:
        if not _is_valid_cwe(obs):
            continue
        if not _has_location(obs):
            continue
        valid.append(obs)
    return valid


def _is_valid_cwe(obs: Observation) -> bool:
    """A CWE must be a member of the CWECategory enum (or absent)."""
    if obs.cwe_category is None:
        return True  # dependency findings may lack an explicit CWE
    return isinstance(obs.cwe_category, CWECategory)


def _has_location(obs: Observation) -> bool:
    """Every observation must carry a source coordinate with a file path."""
    return obs.location is not None and bool(obs.location.file_path)
