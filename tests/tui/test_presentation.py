"""QR-01/05: terminal summaries preserve recorded evidence and validation state."""

from vulnscan.tui.presentation import finding_summary


def test_qr01_missing_excerpt_and_recorded_workflow_state_are_explicit():
    text = finding_summary(
        {
            "title": "Suspected issue",
            "status": "unprocessed",
            "observations": [{"location": {"file_path": "Example.java", "line_start": 7}}],
        }
    )
    assert "Example.java:7" in text
    assert "No source excerpt was retained" in text
    assert "Verification / review: unprocessed" in text
    assert "No evidence record references" in text


def test_qr05_confirmed_finding_retains_source_and_evidence_references():
    text = finding_summary(
        {
            "title": "Verified issue",
            "status": "confirmed",
            "evidence_refs": ["record-a"],
            "observations": [
                {
                    "tool": "semgrep",
                    "rule_id": "sql-injection",
                    "location": {
                        "file_path": "Example.java",
                        "line_start": 7,
                        "snippet": "String query = input;",
                    },
                }
            ],
        }
    )
    assert "Verification / review: confirmed" in text
    assert "String query = input;" in text and "record-a" in text
    assert "No evidence record" not in text
