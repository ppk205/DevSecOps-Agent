"""Small persisted projections for responsive finding lists (FR-71, QR-21)."""

from __future__ import annotations

import json
from typing import Any


def project_finding(item: dict[str, Any]) -> tuple[dict[str, Any], str]:
    tools = sorted({str(o.get("tool", "")) for o in item.get("observations", [])})
    summary = {
        "finding_id": str(item.get("finding_id", "")),
        "severity": str(item.get("severity", "undetermined")),
        "cwe_category": str(item.get("cwe_category", "CWE-UNCLASSIFIED")),
        "status": str(item.get("status", "unprocessed")),
        "scanner": ", ".join(tools),
        "title": str(item.get("title", "")),
    }
    return summary, json.dumps(item, ensure_ascii=False, sort_keys=True).lower()


def matches(summary: dict[str, Any], search_text: str, query: str) -> bool:
    fields = {
        "severity": str(summary["severity"]).lower(),
        "cwe": str(summary["cwe_category"]).lower(),
        "status": str(summary["status"]).lower(),
        "scanner": str(summary["scanner"]).lower(),
    }
    for term in query.lower().split():
        if ":" in term:
            name, value = term.split(":", 1)
            if value not in fields.get(name, ""):
                return False
        elif term not in search_text:
            return False
    return True
