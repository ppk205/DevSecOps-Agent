"""FR-61: final narratives always retain the application-owned OWASP section."""

from types import SimpleNamespace

import pytest

from tests.reporting.test_reporter import _finding
from vulnscan.contracts import FindingStatus
from vulnscan.reporting import final_report


def test_fr61_deterministic_narrative_adds_owasp_section_and_valid_cwe_ids():
    text = final_report.deterministic_narrative([_finding("sql", FindingStatus.UNRESOLVED)], [], {})
    assert text.count("## OWASP Top 10:2025") == 1
    assert "A05:2025" in text and "CWE-89" in text
    assert "CWE-CWE-" not in text


def test_fr61_finding_title_containing_owasp_remains_in_fallback():
    finding = _finding(
        "title-ref", FindingStatus.UNRESOLVED, title="OWASP Top 10 issue in checkout"
    )
    text = final_report.deterministic_narrative([finding], [], {})
    assert "## OWASP Top 10 issue in checkout [unresolved]" in text
    assert "src/LoginServlet.java:42" in text


def test_fr61_unclosed_model_code_block_does_not_hide_new_section():
    from vulnscan.reporting.owasp import append_to_narrative

    text = append_to_narrative("# Model report\n```text\nexcerpt", [])
    assert "excerpt\n```\n\n## OWASP Top 10:2025" in text


@pytest.mark.parametrize("outcome", ["content", "empty", "error"])
def test_fr61_model_report_and_fallback_have_exact_application_mapping(monkeypatch, outcome):
    prompts = []
    monkeypatch.setattr(
        final_report, "load_profile", lambda _: SimpleNamespace(id="fake", default_model="fixture")
    )

    class FakeClient:
        def __init__(self, *args):
            pass

        def chat(self, messages, **kwargs):
            prompts.append(messages[0].content)
            if outcome == "error":
                raise ValueError("synthetic failure")
            content = (
                "# Report body\n\n## OWASP Top 10:2021\nFAKE OWASP COUNTS\n\n## Next steps\nReview evidence.\n"
                if outcome == "content"
                else ""
            )
            return SimpleNamespace(content=content, model="fixture", usage={"total_tokens": 10})

    monkeypatch.setattr(final_report, "ProviderClient", FakeClient)
    result = final_report.run_final_report(
        [_finding("sql", FindingStatus.REJECTED)], [], {}, profile_id="fake"
    )
    text = result["markdown"]
    assert text.count("## OWASP Top 10:2025") == 1
    assert "A05:2025" in text and "CWE-89" in text and "Rejected: 1" in text
    assert "FAKE OWASP COUNTS" not in text
    if outcome == "content":
        assert "# Report body" in text and "## Next steps" in text
    assert result["ai_written"] is (outcome == "content")
    assert (
        result["status"] == {"content": "completed", "empty": "partial", "error": "failed"}[outcome]
    )
    assert len(prompts) == 1
