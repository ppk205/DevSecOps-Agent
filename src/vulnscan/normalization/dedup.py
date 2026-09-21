"""Conservative deduplication of findings.

Dedup key: the finding fingerprint (location + cwe + sorted rule ids).
Never merge solely because CWE labels match — location and rule evidence
must agree. All contributing observations from every duplicate are folded
into the surviving finding so nothing is lost.
"""

from __future__ import annotations

from vulnscan.contracts import Finding


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove exact duplicates by fingerprint, folding observations in.

    Two findings with the same CWE but different fingerprints (different
    locations or rule evidence) are kept separate.
    """
    seen: dict[str, Finding] = {}
    order: list[str] = []

    for f in findings:
        fp = f.fingerprint
        if fp in seen:
            # Preserve provenance: fold the duplicate's observations in.
            keeper = seen[fp]
            ids = {o.observation_id for o in keeper.observations}
            for obs in f.observations:
                if obs.observation_id not in ids:
                    keeper.observations.append(obs)
                    keeper.evidence_refs.append(obs.observation_id)
            for g in f.groups:
                if g.group_id not in {kg.group_id for kg in keeper.groups}:
                    keeper.groups.append(g)
            continue
        seen[fp] = f
        order.append(fp)

    return [seen[fp] for fp in order]
