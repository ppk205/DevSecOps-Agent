"""CWE extraction must survive the real Semgrep output schemas.

Regression guard: the legacy ``--json`` schema stores CWE labels under
``extra.metadata.cwe``, not under a ``tags`` key. Reading only ``tags``
classified every finding as UNCLASSIFIED while still reporting success, so
nothing downstream noticed.
"""

from __future__ import annotations

import json

from vulnscan.contracts.enums import CWECategory
from vulnscan.scanners.semgrep_adapter import parse_json, parse_sarif

# Verbatim shapes taken from semgrep 1.178.0 output on JVA-bookstore.
LEGACY_SQLI = {
    "check_id": "java.lang.security.audit.sqli.jdbc-sqli.jdbc-sqli",
    "path": "src/main/java/dao/CartDAO.java",
    "start": {"line": 582, "col": 5, "offset": 12000},
    "end": {"line": 582, "col": 40, "offset": 12035},
    "extra": {
        "message": "Detected a formatted string in a SQL statement.",
        "metadata": {
            "cwe": [
                (
                    "CWE-89: Improper Neutralization of Special Elements used in an "
                    "SQL Command ('SQL Injection')"
                )
            ],
            "category": "security",
            "owasp": ["A03:2021 - Injection"],
        },
        "severity": "WARNING",
    },
}

SARIF_DOC = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "semgrep",
                    "semanticVersion": "1.178.0",
                    "rules": [
                        {
                            "id": "java.lang.security.audit.sqli.jdbc-sqli.jdbc-sqli",
                            "properties": {
                                "tags": [
                                    (
                                        "CWE-89: Improper Neutralization of Special Elements "
                                        "used in an SQL Command ('SQL Injection')"
                                    ),
                                    "security",
                                ]
                            },
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "java.lang.security.audit.sqli.jdbc-sqli.jdbc-sqli",
                    "level": "warning",
                    "message": {"text": "Detected a formatted string in a SQL statement."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/main/java/dao/CartDAO.java"},
                                "region": {"startLine": 582, "endLine": 582},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


def _legacy(payloads: list[dict]) -> str:
    return json.dumps({"results": payloads})


def test_legacy_json_extracts_cwe_from_metadata_cwe_list() -> None:
    obs, _ = parse_json(
        _legacy([LEGACY_SQLI]), run_id="r", tool_version="1.178.0", source_snapshot="s"
    )

    assert len(obs) == 1
    assert obs[0].cwe_category == CWECategory.SQL_INJECTION


def test_legacy_json_without_cwe_metadata_stays_unset() -> None:
    payload = json.loads(json.dumps(LEGACY_SQLI))
    payload["extra"]["metadata"] = {"category": "security"}

    obs, _ = parse_json(
        _legacy([payload]), run_id="r", tool_version="1.178.0", source_snapshot="s"
    )

    assert obs[0].cwe_category is None


def test_legacy_json_ignores_non_cwe_metadata() -> None:
    payload = json.loads(json.dumps(LEGACY_SQLI))
    payload["extra"]["metadata"] = {"owasp": ["A03:2021 - Injection"], "technology": ["jdbc"]}

    obs, _ = parse_json(
        _legacy([payload]), run_id="r", tool_version="1.178.0", source_snapshot="s"
    )

    assert obs[0].cwe_category is None


def test_legacy_json_falls_back_to_tags_when_present() -> None:
    payload = json.loads(json.dumps(LEGACY_SQLI))
    payload["extra"]["metadata"] = {"tags": ["CWE-89: Improper Neutralization"]}

    obs, _ = parse_json(
        _legacy([payload]), run_id="r", tool_version="1.178.0", source_snapshot="s"
    )

    assert obs[0].cwe_category == CWECategory.SQL_INJECTION


def test_sarif_extracts_cwe_from_described_tag() -> None:
    obs, _ = parse_sarif(json.dumps(SARIF_DOC), run_id="r", tool_version="1.178.0", source_snapshot="s")

    assert len(obs) == 1
    assert obs[0].cwe_category == CWECategory.SQL_INJECTION


def test_both_schemas_agree_on_the_same_finding() -> None:
    legacy, _ = parse_json(
        _legacy([LEGACY_SQLI]), run_id="r", tool_version="1.178.0", source_snapshot="s"
    )
    sarif, _ = parse_sarif(json.dumps(SARIF_DOC), run_id="r", tool_version="1.178.0", source_snapshot="s")

    assert legacy[0].cwe_category == sarif[0].cwe_category
    assert legacy[0].location.file_path == sarif[0].location.file_path
