"""FR-75: opt-in selection and summary-only outbound events."""

import json

import pytest

from tests.ai.test_review_wiring import _finding
from vulnscan.notifications.events import events_for_scan
from vulnscan.notifications.settings import NotificationSettings, load_settings, save_settings


def test_destinations_and_events_default_to_disabled(tmp_path):
    settings = load_settings(base=tmp_path)
    assert not settings.telegram.enabled and not settings.discord.enabled
    assert settings.telegram.events == [] and settings.discord.events == []


def test_settings_store_references_and_preserve_selected_events(tmp_path):
    settings = NotificationSettings.model_validate(
        {
            "mode": "manual",
            "telegram": {"enabled": True, "events": ["scan_failed", "gate_failed"]},
            "discord": {"enabled": True, "events": ["report_ready"]},
        }
    )
    save_settings(settings, base=tmp_path)
    loaded = load_settings(base=tmp_path)
    assert loaded == settings
    data = json.loads((tmp_path / ".devsec-notifications.json").read_text())
    assert data["telegram"]["token_env"] == "DEVSEC_TELEGRAM_BOT_TOKEN"
    assert "token" not in data["telegram"] and "webhook_url" not in data["discord"]


def test_raw_urls_are_not_accepted_as_environment_references(tmp_path):
    with pytest.raises(ValueError, match="Invalid notification settings") as error:
        save_settings(
            {"discord": {"webhook_env": "https://discord.com/api/webhooks/1/private-value"}},
            base=tmp_path,
        )
    assert "private-value" not in str(error.value)


def test_events_include_only_summary_fields_and_actual_outcomes():
    summary = {
        "run_id": "run-a",
        "status": "completed",
        "gate": "failed",
        "configuration": {"mode": "hunt", "provider_profile": "test-profile"},
        "ai_usage": {"completed_requests": 0, "failed_requests": 2},
        "reports": {"json": "/private/report.json"},
        "errors": ["private source code"],
        "assessments": [{"rationale": "private model response"}],
    }
    events = events_for_scan(summary, [_finding()])
    assert {e["kind"] for e in events} == {
        "scan_completed",
        "gate_failed",
        "high_critical_findings",
        "ai_failed",
        "report_ready",
    }
    text = json.dumps(events)
    assert "private source code" not in text and "private model response" not in text
    assert "/private/report.json" not in text
    assert "confirmed vulnerability" not in text.lower()


def test_disabled_ai_and_rejected_findings_do_not_create_problem_alerts():
    from vulnscan.contracts import FindingStatus

    events = events_for_scan(
        {
            "run_id": "run-a",
            "status": "completed",
            "gate": "passed",
            "configuration": {"mode": "deterministic"},
        },
        [_finding(status=FindingStatus.REJECTED)],
    )
    assert [e["kind"] for e in events] == ["scan_completed"]


def test_requested_provider_unavailable_is_alerted_even_with_saved_profile():
    summary = {
        "run_id": "run-a",
        "status": "completed",
        "configuration": {
            "mode": "deterministic",
            "ai_review": True,
            "provider_profile": "missing-key-profile",
        },
        "stages": [
            {
                "stage": "targeted_deep_analysis",
                "status": "skipped",
                "message": "provider unavailable: CredentialError",
            }
        ],
    }
    assert "ai_failed" in {event["kind"] for event in events_for_scan(summary, [])}
