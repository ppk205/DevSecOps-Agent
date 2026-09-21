"""Conservative grouping of observations into findings.

Grouping key: (file_path, line_start, cwe_category). Same-CWE findings at
*different* sites stay distinct. All contributing observations are preserved
on the resulting Finding. Grouping never invents coordinates or CWEs.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime, timezone

from vulnscan.contracts import (
    EvidenceStrength,
    Finding,
    FindingGroup,
    FindingStatus,
    Observation,
    Severity,
)


def _group_key(obs: Observation) -> tuple[str, int, str]:
    """(file_path, line_start, cwe) — the minimal stable grouping key."""
    loc = obs.location
    file_path = loc.file_path if loc else ""
    line_start = loc.line_start if loc else 0
    cwe = obs.cwe_category.value if obs.cwe_category else ""
    return (file_path, line_start, cwe)


def _highest_severity(observations: list[Observation]) -> Severity:
    """The most severe observation in the group (undetermined if empty)."""
    order = {
        Severity.UNDETERMINED: 0,
        Severity.INFO: 1,
        Severity.LOW: 2,
        Severity.MEDIUM: 3,
        Severity.HIGH: 4,
        Severity.CRITICAL: 5,
    }
    if not observations:
        return Severity.UNDETERMINED
    return max(observations, key=lambda o: order.get(o.severity, 0)).severity


def _fingerprint(key: tuple[str, int, str], observations: list[Observation]) -> str:
    """Stable SHA-256 fingerprint: location + cwe + sorted rule ids."""
    h = hashlib.sha256()
    h.update("|".join(str(x) for x in key).encode("utf-8"))
    for rule_id in sorted(o.rule_id for o in observations):
        h.update(rule_id.encode("utf-8"))
    return h.hexdigest()


def _title_for(key: tuple[str, int, str], observations: list[Observation]) -> str:
    cwe = key[2] or "CWE-unknown"
    rep = observations[0]
    symbol = rep.location.symbol if rep.location and rep.location.symbol else ""
    where = f"{key[0]}:{key[1]}"
    if symbol:
        return f"{cwe} in {symbol} ({where})"
    return f"{cwe} at {where}"


def group_findings(
    observations: list[Observation],
    run_id: str = "",
) -> list[Finding]:
    """Group observations by (file, line, cwe) into Finding objects.

    Observations that share a key are merged into one Finding. Provenance is
    preserved: every contributing observation is kept, and a FindingGroup
    records which tool + observations produced it.
    """
    groups: dict[tuple[str, int, str], list[Observation]] = defaultdict(list)
    for obs in observations:
        groups[_group_key(obs)].append(obs)

    findings: list[Finding] = []
    for key, obs_list in groups.items():
        fp = _fingerprint(key, obs_list)
        rep_loc = obs_list[0].location
        tools = sorted({o.tool for o in obs_list}, key=lambda t: t.value)

        now = datetime.now(timezone.utc)
        finding = Finding(
            finding_id=fp[:16],
            run_id=run_id,
            fingerprint=fp,
            title=_title_for(key, obs_list),
            description=obs_list[0].message,
            cwe_category=obs_list[0].cwe_category
            if obs_list[0].cwe_category is not None
            else next((o.cwe_category for o in obs_list if o.cwe_category), None),
            severity=_highest_severity(obs_list),
            status=FindingStatus.UNPROCESSED,
            observations=list(obs_list),
            evidence_strength=EvidenceStrength.MODERATE,
            evidence_refs=[o.observation_id for o in obs_list],
            metadata={"grouping_key": list(key)},
            created_at=now,
            updated_at=now,
        )
        finding.groups = [
            FindingGroup(
                group_id=f"{finding.finding_id}-g0",
                finding_id=finding.finding_id,
                tool_names=tools,
                observation_ids=[o.observation_id for o in obs_list],
                representative_observation_id=obs_list[0].observation_id,
                grouping_rationale=(
                    "same file, line, and CWE; merged conservatively — "
                    "same-CWE findings at different sites stay distinct"
                ),
                grouping_method="location-cwe",
                grouped_at=now,
            )
        ]
        findings.append(finding)

    # A finding confirmed by more than one distinct tool has stronger evidence.
    tool_sets = {
        f.finding_id: {t.value for t in f.groups[0].tool_names} for f in findings
    }
    for f in findings:
        if len(tool_sets[f.finding_id]) > 1:
            f.evidence_strength = EvidenceStrength.STRONG

    return findings
