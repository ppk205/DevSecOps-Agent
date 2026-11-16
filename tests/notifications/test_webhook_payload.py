"""FR-75 / P-WEB-01/02: retained summaries have a bounded canonical wire schema."""

import json
import os
import socket

import pytest

from vulnscan.infra.envfile import EnvFile
from vulnscan.notifications import events as notification_events
from vulnscan.providers import credentials


@pytest.fixture(autouse=True)
def synthetic_environment(monkeypatch):
    # Redaction runs against synthetic values, never the operator's credentials.
    monkeypatch.setattr(os, "environ", {"SYNTHETIC_SECRET": "private-synthetic-marker"})


def test_envelope_has_only_selected_summary_fields():
    offered = [
        {
            "kind": "gate_failed",
            "message": "Scan run-a: security gate failed.",
            "label": "Untrusted label",
            "source": "private source",
            "path": "/private/repository",
            "diff": "private diff",
            "transcript": "private model transcript",
            "match": "private scanner match",
        }
    ]
    body = notification_events.build_webhook_body("run-a", "completed", offered, "delivery-a")
    assert json.loads(body) == {
        "schema_version": 1,
        "delivery_id": "delivery-a",
        "run_id": "run-a",
        "scan_status": "completed",
        "events": [{"kind": "gate_failed", "message": "Scan run-a: security gate failed."}],
    }
    assert len(body) <= 16384
    assert offered[0]["source"] == "private source"  # The retained record is not rewritten.


def test_unicode_bytes_are_sorted_compact_and_deterministic():
    first = [{"message": "Đã xong ✓", "kind": "scan_completed"}]
    second = [{"kind": "scan_completed", "message": "Đã xong ✓", "label": "ignored"}]
    expected = (
        '{"delivery_id":"delivery-a","events":[{"kind":"scan_completed",'
        '"message":"Đã xong ✓"}],"run_id":"run-a","scan_status":"completed",'
        '"schema_version":1}'
    ).encode()
    assert (
        notification_events.build_webhook_body("run-a", "completed", first, "delivery-a")
        == expected
    )
    assert (
        notification_events.build_webhook_body("run-a", "completed", second, "delivery-a")
        == expected
    )


def test_hostile_summary_is_sanitized_before_encoding_and_bounding():
    message = (
        '\x1b[31m<script>alert("x")</script>\x1b[0m\x00\x7f\x85 '
        "token=synthetic-token private-synthetic-marker sk-synthetic123456"
    )
    body = notification_events.build_webhook_body(
        "run-private-synthetic-marker",
        "completed",
        [{"kind": "scan_completed", "message": message}],
        "delivery-a",
    )
    payload = json.loads(body)
    assert payload["run_id"] == "run-[REDACTED]"
    assert payload["events"][0]["message"] == (
        '<script>alert("x")</script> token=[REDACTED] [REDACTED] [REDACTED]'
    )
    assert b"private-synthetic-marker" not in body
    assert b"synthetic-token" not in body and b"sk-synthetic123456" not in body


def test_identity_and_messages_keep_existing_character_bounds():
    body = notification_events.build_webhook_body(
        "r" * 101,
        "completed",
        [{"kind": "scan_completed", "message": "✓" * 1801}],
        "delivery-a",
    )
    payload = json.loads(body)
    assert payload["run_id"] == "r" * 100
    assert payload["events"][0]["message"] == "✓" * 1800


@pytest.mark.parametrize("kind", list(notification_events.EVENT_LABELS))
def test_each_existing_kind_can_be_retained(kind):
    body = notification_events.build_webhook_body(
        "run-a", "completed", [{"kind": kind, "message": "Retained summary."}], "delivery-a"
    )
    assert json.loads(body)["events"] == [{"kind": kind, "message": "Retained summary."}]


@pytest.mark.parametrize(
    "record",
    [
        {"kind": "pr_created", "message": "synthetic-private-message"},
        {"kind": "scan_completed"},
        {"message": "synthetic-private-message"},
        {"kind": "scan_completed", "message": {"source": "synthetic-private-source"}},
        {"kind": ["scan_completed"], "message": "synthetic-private-message"},
    ],
)
def test_unknown_or_malformed_events_are_rejected_generically(record):
    with pytest.raises(ValueError) as error:
        notification_events.build_webhook_body("run-a", "completed", [record], "delivery-a")
    assert "synthetic-private" not in str(error.value)


def test_raw_scan_dictionary_is_not_an_event_sequence():
    with pytest.raises(ValueError):
        notification_events.build_webhook_body(
            "run-a",
            "completed",
            {"status": "completed", "source": "synthetic-private-source"},
            "delivery-a",
        )


def test_empty_selection_does_not_invent_events():
    body = notification_events.build_webhook_body("run-a", "failed", [], "delivery-a")
    assert json.loads(body)["events"] == []
    assert json.loads(body)["scan_status"] == "failed"


def test_exact_16kib_boundary_is_accepted_and_next_utf8_byte_rejected():
    # Hand-counted compact envelope: 89 bytes, three 38-byte event objects and
    # two commas. Messages add 5,400 + 5,400 + 5,379 UTF-8 bytes = 16,384 total.
    records = [{"kind": "scan_completed", "message": "✓" * 1800} for _ in range(2)]
    records.append({"kind": "scan_completed", "message": "✓" * 1793})
    body = notification_events.build_webhook_body("r", "completed", records, "d")
    assert len(body) == 16384
    assert json.loads(body)["events"][-1]["message"] == "✓" * 1793
    records[-1]["message"] += "x"
    with pytest.raises(ValueError, match="16 KiB"):
        notification_events.build_webhook_body("r", "completed", records, "d")


def test_builder_does_not_load_credentials_resolve_or_send(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("The envelope builder must be offline")

    monkeypatch.setattr(EnvFile, "load_into_environ", forbidden)
    monkeypatch.setattr(credentials, "load_api_key", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    body = notification_events.build_webhook_body(
        "run-a",
        "completed",
        [{"kind": "scan_completed", "message": "Scan completed."}],
        "delivery-a",
    )
    assert json.loads(body)["events"] == [{"kind": "scan_completed", "message": "Scan completed."}]
