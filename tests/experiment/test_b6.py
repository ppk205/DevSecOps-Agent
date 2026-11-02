"""Synthetic transport replies; these are not experiment measurements."""

import json
from pathlib import Path

import pytest

from vulnscan.experiment import b6
from vulnscan.harness.messages import Message, ProviderError, Reply, Usage
from vulnscan.harness.providers import BUILTIN_PROFILES


class Fake:
    def __init__(self, contents: list[str | Exception], cloud: bool = False):
        self.profile = BUILTIN_PROFILES["deepseek" if cloud else "ollama"]
        self.model = "synthetic-model"
        self.contents = contents
        self.calls = []

    def complete(self, system, messages, tools):
        self.calls.append((system, messages, tools))
        content = self.contents.pop(0)
        if isinstance(content, Exception):
            raise content
        return Reply(Message("assistant", content), Usage(10, 5), self.model)


def target(tmp_path: Path) -> Path:
    root = tmp_path / "target"
    root.mkdir()
    (root / "A.java").write_text("class A {}\n")
    (root / "B.jsp").write_text("<p>synthetic</p>\n")
    return root


def events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_rows_written_per_file(tmp_path):
    fake = Fake(
        [
            json.dumps(
                [
                    {
                        "file": "A.java",
                        "line": 1,
                        "cwe": "CWE-89",
                        "cvss_vector": None,
                        "explanation": "synthetic",
                        "fix": None,
                    }
                ]
            ),
            "[]",
        ]
    )
    out = tmp_path / "b6.jsonl"
    summary = b6.run(target(tmp_path), fake, out)
    assert summary["status"] == "completed" and summary["completed_files"] == 2
    assert len(fake.calls) == 2
    assert all(
        system == b6.B6_PROMPT and len(messages) == 1 and tools == []
        for system, messages, tools in fake.calls
    )
    assert '<untrusted_code path="A.java">' in fake.calls[0][1][0].content
    assert [e["file"] for e in events(out) if e["type"] == "finding"] == ["A.java"]
    assert summary["cost_usd"] is None


def test_cloud_without_consent_exits_2(tmp_path, monkeypatch):
    fake = Fake([], cloud=True)
    monkeypatch.setattr(b6, "resolve_model", lambda spec: (fake.profile, fake.model))
    monkeypatch.setattr(b6, "make_transport", lambda *args: pytest.fail("transport before consent"))
    assert (
        b6.main(
            ["--target", str(tmp_path), "--model", "synthetic", "--out", str(tmp_path / "b.jsonl")]
        )
        == 2
    )
    assert not (tmp_path / "b.jsonl").exists()


def test_budget_exhaustion_marks_partial(tmp_path):
    fake = Fake(["[]", "[]"])
    result = b6.run(target(tmp_path), fake, tmp_path / "b6.jsonl", budget=1, rates=(100000, 0))
    assert result["status"] == "partial" and result["completed_files"] == 1
    assert "budget" in result["reason"] and len(fake.calls) == 1


def test_unknown_price_cannot_enforce_usd_budget(tmp_path):
    fake = Fake([])
    result = b6.run(target(tmp_path), fake, tmp_path / "b6.jsonl", budget=1)
    assert result["status"] == "partial" and not fake.calls
    assert result["cost_usd"] is None and "price" in result["reason"]


@pytest.mark.parametrize("reply", ["not JSON", '{"file":"A.java"}', '[{"file":"../x","line":1}]'])
def test_invalid_json_reply_recorded_not_dropped(tmp_path, reply):
    fake = Fake([reply, "[]"])
    out = tmp_path / "b6.jsonl"
    summary = b6.run(target(tmp_path), fake, out)
    assert summary["status"] == "partial"
    assert any(e["type"] == "error" and e["raw_reply"] == reply for e in events(out))


def test_provider_error_preserves_partial_and_existing_output_refused(tmp_path):
    fake = Fake(["[]", ProviderError("synthetic unavailable")])
    out = tmp_path / "b6.jsonl"
    summary = b6.run(target(tmp_path), fake, out)
    assert summary["status"] == "partial" and summary["completed_files"] == 1
    before = out.read_bytes()
    with pytest.raises(FileExistsError):
        b6.run(tmp_path / "target", fake, out)
    assert out.read_bytes() == before
