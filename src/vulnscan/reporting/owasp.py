"""FR-61: offline OWASP Top 10:2025 classification of normalized finding CWEs.

Mapped IDs are copied from OWASP category pages, not inferred from CWE parents.
Reference: https://top10.owasp.org/2025/ (CC BY 3.0), retrieved 2026-11-04.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from vulnscan.contracts import Finding, FindingStatus
from vulnscan.core.security import sanitize

EDITION = "2025"
SNAPSHOT_DATE = "2026-11-04"
SOURCE_URL = "https://top10.owasp.org/2025/"
SECTION_TITLE = "OWASP Top 10:2025 and CWE mapping"
NOTE = (
    "This is a CWE classification of reported findings, not a coverage or compliance assessment. "
    "An empty category means No mapped findings reported; it does not mean tested, safe or passed. "
    "Counts retain finding status; pending includes unprocessed, triaged, assessed and pending validation."
    " A finding with multiple labels may appear in several rows/categories; do not add those row counts."
)


@dataclass(frozen=True)
class Category:
    id: str
    name: str
    source_url: str
    source_sha256: str
    cwes: frozenset[str]


CATEGORIES: tuple[Category, ...] = (
    Category(
        id="A01:2025",
        name="Broken Access Control",
        source_url="https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/",
        source_sha256="e51ca05866f4213489e82484f1f48ed4d779e1809e87f70449806b496a0320cd",
        cwes=frozenset(
            f"CWE-{n}"
            for n in [
                "22",
                "23",
                "36",
                "59",
                "61",
                "65",
                "200",
                "201",
                "219",
                "276",
                "281",
                "282",
                "283",
                "284",
                "285",
                "352",
                "359",
                "377",
                "379",
                "402",
                "424",
                "425",
                "441",
                "497",
                "538",
                "540",
                "548",
                "552",
                "566",
                "601",
                "615",
                "639",
                "668",
                "732",
                "749",
                "862",
                "863",
                "918",
                "922",
                "1275",
            ]
        ),
    ),
    Category(
        id="A02:2025",
        name="Security Misconfiguration",
        source_url="https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/",
        source_sha256="532fbbd67f3db734b7ed5d47e0263dd3800fce80e22da327123a88f2947017c9",
        cwes=frozenset(
            f"CWE-{n}"
            for n in [
                "5",
                "11",
                "13",
                "15",
                "16",
                "260",
                "315",
                "489",
                "526",
                "547",
                "611",
                "614",
                "776",
                "942",
                "1004",
                "1174",
            ]
        ),
    ),
    Category(
        id="A03:2025",
        name="Software Supply Chain Failures",
        source_url="https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/",
        source_sha256="66090225ad8f54a836e5b9e94456243baa7d38b70176f4d720668ef36f3a793d",
        cwes=frozenset(f"CWE-{n}" for n in ["447", "1035", "1104", "1329", "1357", "1395"]),
    ),
    Category(
        id="A04:2025",
        name="Cryptographic Failures",
        source_url="https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/",
        source_sha256="5b140b4cadf334becc35334278494f98396dc9b5720df6c904688352b51dc834",
        cwes=frozenset(
            f"CWE-{n}"
            for n in [
                "261",
                "296",
                "319",
                "320",
                "321",
                "322",
                "323",
                "324",
                "325",
                "326",
                "327",
                "328",
                "329",
                "330",
                "331",
                "332",
                "334",
                "335",
                "336",
                "337",
                "338",
                "340",
                "342",
                "347",
                "523",
                "757",
                "759",
                "760",
                "780",
                "916",
                "1240",
                "1241",
            ]
        ),
    ),
    Category(
        id="A05:2025",
        name="Injection",
        source_url="https://top10.owasp.org/2025/A05_2025-Injection/",
        source_sha256="69d7ec591944699c49b89c544a52cb32adccbfad56c41784ca34fde837822de6",
        cwes=frozenset(
            f"CWE-{n}"
            for n in [
                "20",
                "74",
                "76",
                "77",
                "78",
                "79",
                "80",
                "83",
                "86",
                "88",
                "89",
                "90",
                "91",
                "93",
                "94",
                "95",
                "96",
                "97",
                "98",
                "99",
                "103",
                "104",
                "112",
                "113",
                "114",
                "115",
                "116",
                "129",
                "159",
                "470",
                "493",
                "500",
                "564",
                "610",
                "643",
                "644",
                "917",
            ]
        ),
    ),
    Category(
        id="A06:2025",
        name="Insecure Design",
        source_url="https://top10.owasp.org/2025/A06_2025-Insecure_Design/",
        source_sha256="cf67ac90b3c088ca4566807fbc4bbd2090bccc81d61f15c0e25190032618195f",
        cwes=frozenset(
            f"CWE-{n}"
            for n in [
                "73",
                "183",
                "256",
                "266",
                "269",
                "286",
                "311",
                "312",
                "313",
                "316",
                "362",
                "382",
                "419",
                "434",
                "436",
                "444",
                "451",
                "454",
                "472",
                "501",
                "522",
                "525",
                "539",
                "598",
                "602",
                "628",
                "642",
                "646",
                "653",
                "656",
                "657",
                "676",
                "693",
                "799",
                "807",
                "841",
                "1021",
                "1022",
                "1125",
            ]
        ),
    ),
    Category(
        id="A07:2025",
        name="Authentication Failures",
        source_url="https://top10.owasp.org/2025/A07_2025-Authentication_Failures/",
        source_sha256="9decccf146242740ba34b1c14df7b729ef159274a3533182c6bcefc9f52c8816",
        cwes=frozenset(
            f"CWE-{n}"
            for n in [
                "258",
                "259",
                "287",
                "288",
                "289",
                "290",
                "291",
                "293",
                "294",
                "295",
                "297",
                "298",
                "299",
                "300",
                "302",
                "303",
                "304",
                "305",
                "306",
                "307",
                "308",
                "309",
                "346",
                "350",
                "384",
                "521",
                "613",
                "620",
                "640",
                "798",
                "940",
                "941",
                "1390",
                "1391",
                "1392",
                "1393",
            ]
        ),
    ),
    Category(
        id="A08:2025",
        name="Software or Data Integrity Failures",
        source_url="https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/",
        source_sha256="03082e5a3ce031d6d2425927653aca0ad47d474dafb4208862e86b4363d66d85",
        cwes=frozenset(
            f"CWE-{n}"
            for n in [
                "345",
                "353",
                "426",
                "427",
                "494",
                "502",
                "506",
                "509",
                "565",
                "784",
                "829",
                "830",
                "915",
                "926",
            ]
        ),
    ),
    Category(
        id="A09:2025",
        name="Security Logging & Alerting Failures",
        source_url="https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/",
        source_sha256="e8f875d2db062bfd3eb00db65486b30dd64c417357f9346a395cf434b5055f31",
        cwes=frozenset(f"CWE-{n}" for n in ["117", "221", "223", "532", "778"]),
    ),
    Category(
        id="A10:2025",
        name="Mishandling of Exceptional Conditions",
        source_url="https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/",
        source_sha256="492a7444a58c06ec76af06ed4f89e656804cde6b71f61ba2ed5703a9aa343864",
        cwes=frozenset(
            f"CWE-{n}"
            for n in [
                "209",
                "215",
                "234",
                "235",
                "248",
                "252",
                "274",
                "280",
                "369",
                "390",
                "391",
                "394",
                "396",
                "397",
                "460",
                "476",
                "478",
                "484",
                "550",
                "636",
                "703",
                "754",
                "755",
                "756",
            ]
        ),
    ),
)


def _bucket(findings: Sequence[Finding]) -> dict[str, Any]:
    counts = {status.value: 0 for status in FindingStatus}
    for finding in findings:
        counts[finding.status.value] += 1
    return {
        "total": len(findings),
        "status_counts": counts,
        "finding_ids": sorted(str(sanitize(f.finding_id)) for f in findings),
    }


def build_owasp_summary(findings: Sequence[Finding]) -> dict[str, Any]:
    """Use exact normalized CWE labels; never infer status or test coverage."""
    grouped: dict[str, list[Finding]] = {}

    def labels(finding: Finding) -> set[str]:
        return {c.value for c in [finding.cwe_category, *finding.additional_cwe_labels]}

    for finding in findings:
        for cwe in labels(finding):
            grouped.setdefault(cwe, []).append(finding)
    categories = []
    listed = frozenset(cwe for category in CATEGORIES for cwe in category.cwes)
    for category in CATEGORIES:
        matched = [f for f in findings if category.cwes.intersection(labels(f))]
        categories.append(
            {
                "id": category.id,
                "name": category.name,
                "source_url": category.source_url,
                "source_sha256": category.source_sha256,
                **_bucket(matched),
                "cwes": [
                    {"cwe": cwe, **_bucket(grouped[cwe])}
                    for cwe in sorted(category.cwes.intersection(grouped), key=lambda c: int(c[4:]))
                ],
            }
        )
    unmapped = []
    for cwe, values in sorted(grouped.items()):
        if cwe not in listed:
            reason = "unclassified_cwe" if cwe == "CWE-UNCLASSIFIED" else "not_listed_in_owasp_2025"
            unmapped.append({"cwe": cwe or None, "reason": reason, **_bucket(values)})
    return {
        "edition": EDITION,
        "source_url": SOURCE_URL,
        "snapshot_date": SNAPSHOT_DATE,
        "classification_only": True,
        "mapping_basis": "Exact normalized primary/secondary CWEs in OWASP category-specific mapped-CWE lists",
        "note": NOTE,
        "total_findings": len(findings),
        "categories": categories,
        "unmapped": unmapped,
    }


TABLE_HEADERS = ("OWASP category", "Reported CWE", "Finding IDs", "Finding status counts")


def status_text(counts: dict[str, int]) -> str:
    pending = sum(
        value
        for status, value in counts.items()
        if status not in {"confirmed", "rejected", "unresolved"}
    )
    return f"Confirmed: {counts['confirmed']}; Rejected: {counts['rejected']}; Unresolved: {counts['unresolved']}; Pending: {pending}"


def table_rows(summary: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    rows: list[tuple[str, str, str, str]] = []
    for category in summary["categories"]:
        label = f"{category['id']} {category['name']}"
        if category["cwes"]:
            rows.extend(
                (
                    label,
                    row["cwe"],
                    ", ".join(row["finding_ids"]),
                    status_text(row["status_counts"]),
                )
                for row in category["cwes"]
            )
        else:
            rows.append((label, "—", "—", status_text(category["status_counts"])))
    for row in summary["unmapped"]:
        rows.append(
            (
                f"Unmapped ({row['reason']})",
                row["cwe"] or "Missing CWE",
                ", ".join(row["finding_ids"]),
                status_text(row["status_counts"]),
            )
        )
    return rows


def markdown_section(findings: Sequence[Finding]) -> str:
    import html

    def cell(value: str) -> str:
        return (
            html.escape(value)
            .replace("|", "&#124;")
            .replace("`", "&#96;")
            .replace("\n", " ")
            .replace("\r", " ")
        )

    summary = build_owasp_summary(findings)
    lines = [
        f"## {SECTION_TITLE}",
        "",
        NOTE,
        "",
        "| " + " | ".join(TABLE_HEADERS) + " |",
        "|---|---|---|---|",
    ]
    lines.extend(
        "| " + " | ".join(cell(value) for value in row) + " |" for row in table_rows(summary)
    )
    lines.extend(
        [
            "",
            f"Mapping source: [OWASP Top 10:2025]({SOURCE_URL}); offline snapshot {SNAPSHOT_DATE}.",
        ]
    )
    return "\n".join(lines)


def append_to_narrative(narrative: str, findings: Sequence[Finding]) -> str:
    """Replace model-authored OWASP headings with the deterministic section."""
    kept: list[str] = []
    skip_level = 0
    fence: str | None = None
    for line in str(sanitize(narrative)).splitlines():
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if marker:
            value = marker.group(1)
            if fence is None:
                fence = value
            elif value[0] == fence[0] and len(value) >= len(fence):
                fence = None
            if not skip_level:
                kept.append(line)
            continue
        if fence:
            if not skip_level:
                kept.append(line)
            continue
        heading = re.match(r"^ {0,3}(#{1,6})[ \t]+(.+)", line)
        if heading:
            level, title = len(heading.group(1)), heading.group(2)
            if re.search(r"OWASP.*Top\s*(?:10|Ten)|Top\s*(?:10|Ten).*OWASP", title, re.IGNORECASE):
                skip_level = level
                continue
            if skip_level and level <= skip_level:
                skip_level = 0
        if not skip_level:
            kept.append(line)
    if fence and not skip_level:
        kept.append(fence)
    body = "\n".join(kept).rstrip()
    return (body + "\n\n" if body else "") + markdown_section(findings) + "\n"
