"""Apply agent-derived labels to the T09 adjudication sheet.

Labels come from reading the source at each finding's exact line, and every
label records the evidence that produced it. They are NOT independent
adjudication: the agent that built the pipeline graded it. The sheet is
marked accordingly so no reader mistakes these for external ground truth.

Keyed by ``file:line`` rather than finding_id so a label can never be attached
to a finding the reviewer did not actually read.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

DEFAULT_SHEET = Path("evidence/t09/adjudication_sheet.json")

# "file:line" -> (needs_review, verdict, reason)
# verdict: "false_positive" | "true_positive"
#
# ``needs_review`` answers "is this worth an analyst's time". It does NOT
# answer "which lane is best", which is what Laya actually emits (8 lanes)
# and what the evaluator scores. The lane is derived below.
LABELS: dict[str, tuple[bool, str, str]] = {
    # --- CWE-79 XSS: 13 findings ------------------------------------------
    "src/main/java/web/AuthServlet.java:129": (
        False, "false_positive",
        "System.out.println to stdout, not a response sink",
    ),
    "src/main/java/web/seller/ShopRegistrationServlet.java:95": (
        False, "false_positive",
        "Debug println of request params to stdout",
    ),
    "src/main/java/web/seller/ShopRegistrationServlet.java:130": (
        False, "false_positive",
        "session.setAttribute with literal 'seller', not user input",
    ),
    "src/main/java/web/TestEmailServlet.java:30": (
        False, "false_positive",
        "Debug println of request param to stdout",
    ),
    "src/main/java/web/TestEmailServlet.java:36": (
        False, "false_positive",
        (
            "Reflects 'email' into an application/json response; JSON is not "
            "rendered as HTML, so no script executes"
        ),
    ),
    "src/main/java/web/AuthServlet.java:152": (
        False, "false_positive",
        "token is JwtUtil.generateToken(subject), server-generated",
    ),
    "src/main/java/web/AuthServlet.java:253": (
        False, "false_positive",
        "Cooldown value is a long from the DB, not a string sink",
    ),
    # AdminUsers: every dynamic value is escaped by escapeJson() first
    "src/main/java/web/admin/AdminUsersServlet.java:501": (
        False, "false_positive",
        "role routed through escapeJson() before JSON embedding",
    ),
    "src/main/java/web/admin/AdminUsersServlet.java:510": (
        False, "false_positive",
        "status routed through escapeJson() before JSON embedding",
    ),
    "src/main/java/web/admin/AdminUsersServlet.java:541": (
        False, "false_positive",
        "role/status routed through escapeJson() before JSON embedding",
    ),
    "src/main/java/web/admin/AdminUsersServlet.java:573": (
        False, "false_positive",
        "role routed through escapeJson() before JSON embedding",
    ),
    "src/main/java/web/admin/AdminUsersServlet.java:582": (
        False, "false_positive",
        "status routed through escapeJson() before JSON embedding",
    ),
    "src/main/java/web/admin/AdminUsersServlet.java:611": (
        False, "false_positive",
        "role/status routed through escapeJson() before JSON embedding",
    ),
    # --- CWE-89 SQLi: 12 findings -----------------------------------------
    "src/main/java/web/seller/SellerProductsServlet.java:173": (
        False, "false_positive",
        "whereClause appends literals only; values bound via ? placeholders",
    ),
    "src/main/java/web/seller/SellerProductsServlet.java:208": (
        False, "false_positive",
        "countProducts uses the same literal-only whereClause",
    ),
    "src/main/java/dao/CartDAO.java:582": (
        False, "false_positive",
        "ensureColumn receives a DDL literal; migration-only",
    ),
    "src/main/java/dao/CartDAO.java:599": (
        False, "false_positive",
        "columnExists uses PreparedStatement with ? placeholders",
    ),
    "src/main/java/utils/DBUtil.java:837": (
        False, "false_positive",
        "countRows: sole caller passes literal 'book_metrics'",
    ),
    "src/main/java/utils/DBUtil.java:884": (
        False, "false_positive",
        "coerceColumnToVarchar typeSql: all 6 callers pass literals",
    ),
    "src/main/java/utils/DBUtil.java:893": (
        False, "false_positive",
        "coerceColumnToVarchar defaultSql: all callers pass literals",
    ),
    "src/main/java/utils/DBUtil.java:908": (
        False, "false_positive",
        "addCheckConstraint: all 5 callers pass literals",
    ),
    "src/main/java/utils/DBUtil.java:915": (
        False, "false_positive",
        "dropConstraintIfExists: sole caller passes a literal",
    ),
    "src/main/java/utils/DBUtil.java:987": (
        False, "false_positive",
        "Same DDL migration path; no user-controlled value reaches the sink",
    ),
    "src/main/java/web/ProfileServlet.java:396": (
        False, "false_positive",
        "ensureUserColumnExists called with literals 'birth_date', 'address'",
    ),
    # --- unclassified: 5 findings -----------------------------------------
    "src/main/java/web/seller/ShopRegistrationServlet.java:127": (
        False, "false_positive",
        "session attributes set from literals, not from request data",
    ),
    "src/main/webapp/admin-users.html:9": (
        True, "true_positive",
        (
            "Loads jsdelivr CSS and Google Fonts with no integrity attribute; no "
            "file in src/main/webapp uses SRI"
        ),
    ),
    "src/main/webapp/admin-orders.html:8": (
        True, "true_positive",
        "bootstrap 5.3.3 loaded from jsdelivr without integrity=",
    ),
    "src/main/webapp/admin-orders.html:9": (
        True, "true_positive",
        "Font Awesome 6.5.2 loaded from cdnjs without integrity=",
    ),
    "src/main/webapp/test-email.html:9": (
        True, "true_positive",
        "bootstrap 5.3.0 loaded from jsdelivr without integrity=",
    ),
}


PROVENANCE = {
    "labelled_by": "devsecops-agent",
    "independently_adjudicated": False,
    "label_method": "source read: sink reachability and escaping checked at the reported line",
}


def _key(row: dict[str, Any]) -> str:
    rel = row["file"].split("JVA-bookstore")[-1].replace("\\", "/").lstrip("/")
    return f"{rel}:{row['line']}"


# The 4 true positives are all missing subresource-integrity on a third-party
# CDN, so the cheapest useful lane is checking the dependency surface. Every
# other finding is a scanner artefact with no better lane than "ignore it".
# Keeping this explicit stops a bool from being passed off as a lane.
LANE_OVERRIDES: dict[str, str] = {
    "src/main/webapp/admin-users.html:9": "dependency_analysis",
    "src/main/webapp/admin-orders.html:8": "dependency_analysis",
    "src/main/webapp/admin-orders.html:9": "dependency_analysis",
    "src/main/webapp/test-email.html:9": "dependency_analysis",
}


def expected_lane(key: str, needs_review: bool) -> str:
    if key in LANE_OVERRIDES:
        return LANE_OVERRIDES[key]
    if needs_review:
        raise SystemExit(
            f"{key} needs review but has no lane; add a LANE_OVERRIDES entry"
        )
    return "low_priority"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Apply source-derived labels to an adjudication sheet."
    )
    parser.add_argument("--sheet", type=Path, default=DEFAULT_SHEET)
    args = parser.parse_args()
    sheet: Path = args.sheet

    rows: list[dict[str, Any]] = json.loads(sheet.read_text(encoding="utf-8"))

    unlabelled = [_key(r) for r in rows if _key(r) not in LABELS]
    if unlabelled:
        raise SystemExit(f"no label for: {unlabelled}")
    extra = set(LABELS) - {_key(r) for r in rows}
    if extra:
        raise SystemExit(f"labels for unknown findings: {sorted(extra)}")

    for row in rows:
        key = _key(row)
        needs_review, verdict, reason = LABELS[key]
        lane = expected_lane(key, needs_review)
        row["needs_review"] = needs_review
        row["expected_route"] = lane
        row["verdict"] = verdict
        row["label_reason"] = reason
        row.update(PROVENANCE)

    rows.sort(key=lambda r: (str(r["cwe"]), str(r["file"]), str(r["line"])))
    sheet.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    tp = sum(1 for r in rows if r["verdict"] == "true_positive")
    lanes: dict[str, int] = {}
    for r in rows:
        lanes[r["expected_route"]] = lanes.get(r["expected_route"], 0) + 1
    print(f"labelled {len(rows)} · true_positive {tp} · false_positive {len(rows) - tp}")
    print(f"expected lanes: {json.dumps(lanes, sort_keys=True)}")
    print("independently_adjudicated: false (labels derived by the pipeline's own agent)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
