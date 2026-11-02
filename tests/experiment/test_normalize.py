"""Normalisers keep every row and never raise on odd tool output."""

from __future__ import annotations

import json
from pathlib import Path

from vulnscan.experiment.normalize import (
    from_b6,
    from_harness,
    from_sarif,
    from_scan_run,
)


def test_from_scan_run_selects_only_its_baseline(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "scanner-gitleaks.json").write_text(
        json.dumps(
            {
                "observations": [
                    {
                        "observation_id": "o1",
                        "rule_id": "aws-key",
                        "cwe_category": "CWE-798",
                        "severity": "high",
                        "location": {"file_path": "src/A.java", "line_start": 12},
                    },
                    {
                        "observation_id": "o2",
                        "rule_id": "x",
                        "location": {"file_path": "src/B.java", "line_start": 3},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "hunt.json").write_text(
        json.dumps(
            {
                "candidates": [
                    {"title": "sqli", "file": "src/C.java", "line": 7, "cwe": "CWE-89"},
                    {"title": "no line", "file": "src/D.java"},
                ]
            }
        ),
        encoding="utf-8",
    )
    rows = from_scan_run(run_dir, "B5")
    assert [(r.file, r.line, r.cwe) for r in rows] == [
        ("src/A.java", 12, "CWE-798"),
        ("src/B.java", 3, "CWE-unknown"),
    ]
    assert {r.stage for r in rows} == {"baseline"}
    assert [(r.file, r.line) for r in from_scan_run(run_dir, "B7")] == [("src/C.java", 7)]


def test_from_sarif_reads_rule_tags(tmp_path: Path) -> None:
    sarif = tmp_path / "codeql.sarif"
    sarif.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "rules": [
                                    {
                                        "id": "java/sql-injection",
                                        "properties": {
                                            "tags": ["security", "external/cwe/cwe-089"]
                                        },
                                    }
                                ]
                            }
                        },
                        "results": [
                            {
                                "ruleId": "java/sql-injection",
                                "level": "error",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/A.java"},
                                            "region": {"startLine": 42},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    rows = from_sarif(sarif, "B3")
    assert [(r.file, r.line, r.cwe, r.stage) for r in rows] == [
        ("src/A.java", 42, "CWE-89", "baseline")
    ]


def test_from_harness_splits_proposed_and_confirmed(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "f1",
                        "cwe": "CWE-89",
                        "cvss_vector": "CVSS:4.0/AV:N",
                        "path": [{"file": "src/A.java", "line": 9}],
                    },
                    {"id": "f2", "cwe": "CWE-79", "path": []},
                ]
            }
        ),
        encoding="utf-8",
    )
    log = tmp_path / "s.jsonl"
    log.write_text(
        json.dumps(
            {"type": "gate", "gate": "G5", "choice": "confirm", "payload": {"finding_id": "f1"}}
        )
        + "\n",
        encoding="utf-8",
    )
    rows = from_harness(report, log, "S2", run=2)
    assert [(r.stage, r.source_id, r.run) for r in rows] == [
        ("proposed", "f1", 2),
        ("after_g5", "f1", 2),
    ]


def test_from_b6_skips_replies_without_a_location(tmp_path: Path) -> None:
    path = tmp_path / "b6.jsonl"
    path.write_text(
        "\n".join(
            [
                json.dumps({"file": "src/A.java", "line": 4, "cwe": "CWE-79"}),
                json.dumps({"error": "invalid json"}),
                "not json",
                json.dumps({"file": "src/B.java", "line": 0}),
            ]
        ),
        encoding="utf-8",
    )
    rows = from_b6(path, "B6", run=1)
    assert [(r.file, r.line) for r in rows] == [("src/A.java", 4)]


def test_unknown_cwe_kept(tmp_path: Path) -> None:
    sarif = tmp_path / "s.sarif"
    sarif.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "odd",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/C.java"},
                                            "region": {"startLine": 2},
                                        }
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    rows = from_sarif(sarif, "B3")
    assert rows[0].cwe == "CWE-unknown"


def test_broken_artifact_yields_no_rows(tmp_path: Path) -> None:
    (tmp_path / "scanner-semgrep.json").write_text("{not json", encoding="utf-8")
    assert from_scan_run(tmp_path, "B1") == []


def test_harness_uses_sink_and_latest_g5_not_first_hop(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "f",
                        "cwe": "CWE-89",
                        "path": [
                            {"file": "Source.java", "line": 1},
                            {"file": "Sink.java", "line": 90},
                        ],
                    }
                ]
            }
        )
    )
    log = tmp_path / "session.jsonl"
    log.write_text(
        "\n".join(
            json.dumps(
                {"type": "gate", "gate": "G5", "choice": choice, "payload": {"finding_id": "f"}}
            )
            for choice in ["confirm", "reject"]
        )
    )
    rows = from_harness(report, log, "S2", 1)
    assert [(r.file, r.line, r.stage) for r in rows] == [("Sink.java", 90, "proposed")]


def test_bare_cwe_number_kept(tmp_path: Path) -> None:
    path = tmp_path / "b6.jsonl"
    path.write_text(json.dumps({"file": "A.java", "line": 1, "cwe": 89}))
    assert from_b6(path, "B6", 1)[0].cwe == "CWE-89"


def test_sarif_rule_index_and_escaped_uri_with_malformed_neighbor(tmp_path: Path) -> None:
    path = tmp_path / "codeql.sarif"
    path.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "rules": [
                                    {
                                        "id": "java/test",
                                        "properties": {"tags": ["external/cwe/cwe-089"]},
                                    }
                                ]
                            }
                        },
                        "results": [
                            {
                                "ruleIndex": 0,
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/My%20File.java"},
                                            "region": {"startLine": 2},
                                        }
                                    }
                                ],
                            },
                            {"ruleId": "bad", "locations": ["not an object"]},
                        ],
                    }
                ]
            }
        )
    )
    rows = from_sarif(path, "B3")
    assert [(r.file, r.cwe) for r in rows] == [("src/My File.java", "CWE-89")]
