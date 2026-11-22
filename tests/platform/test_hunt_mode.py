"""Task 6: --mode hunt wires model-hunt -> Laya verify -> compare into ScanService."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulnscan.contracts import (
    CoverageRecord,
    CoverageUnitStatus,
    CWECategory,
    Observation,
    RunStatus,
    ScannerResult,
    Severity,
    SourceCoordinate,
    ToolName,
)
from vulnscan.contracts.enums import ProviderProtocol
from vulnscan.contracts.provider import ProviderProfile
from vulnscan.core.config import ScanConfig
from vulnscan.core.scan_service import ScanService
from vulnscan.scanners.base import AdapterCapability, AdapterRegistry, ScannerAdapter

HUNT_STAGES = {"model_hunt", "laya_verification", "model_scanner_compare"}


@pytest.fixture
def checkout(tmp_path):
    path = tmp_path / "checkout"
    path.mkdir()
    (path / "Example.java").write_text("class Example {}\n")
    for args in [
        ["init"],
        ["add", "."],
        [
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "fixture",
        ],
    ]:
        subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)
    return path


class FixtureAdapter(ScannerAdapter):
    tool = ToolName.NATIVE_HUNT
    binary_name = "fixture"

    def capabilities(self):
        return AdapterCapability(self.tool, available=True)

    def run(self, spec, *, workdir):
        now = datetime.now(UTC)
        return ScannerResult(
            run_id=spec.run_id,
            tool=self.tool,
            tool_version="test",
            adapter_version="test",
            status=RunStatus.COMPLETED,
            started_at=now,
            observations=[
                Observation(
                    observation_id=self.tool.value + "-test",
                    run_id=spec.run_id,
                    tool=self.tool,
                    tool_version="test",
                    rule_id="test-low",
                    severity=Severity.LOW,
                    cwe_category=CWECategory.SQL_INJECTION,
                    message="Fixture evidence",
                    detected_at=now,
                    location=SourceCoordinate(file_path="Example.java", line_start=1),
                )
            ],
            coverage_records=[
                CoverageRecord(
                    run_id=spec.run_id,
                    tool=self.tool,
                    tool_version="test",
                    source_snapshot=spec.target_commit_sha,
                    unit_path="Example.java",
                    eligible=True,
                    status=CoverageUnitStatus.ANALYZED,
                    analyzed_at=now,
                )
            ],
        )


@pytest.fixture
def service(tmp_path):
    registry = AdapterRegistry()
    registry.register(FixtureAdapter())
    leaks = FixtureAdapter()
    leaks.tool = ToolName.GITLEAKS
    registry.register(leaks)
    return ScanService(str(tmp_path / "runs.db"), registry)


def settings(tmp_path, **kwargs):
    kwargs.setdefault("tools", ["native-hunt"])
    return ScanConfig(output_dir=str(tmp_path / "reports"), **kwargs)


def _profile():
    return ProviderProfile(
        id="test",
        label="Test",
        protocol=ProviderProtocol.OPENAI_CHAT_COMPLETIONS,
        base_url="https://api.test.invalid/v1",
        api_key_env="TEST_KEY",
        models=["m"],
        default_model="m",
    )


def test_default_mode_runs_hunt_path_skipped_without_key(service, checkout, tmp_path, monkeypatch):
    import vulnscan.providers.profile_store as store_mod

    monkeypatch.setattr(store_mod, "default_profile", lambda base=None: None)
    result = service.run(str(checkout), settings(tmp_path))
    assert "model_candidates" not in result
    stages = {e["stage"]: e["status"] for e in result["stages"]}
    assert stages.get("model_hunt") == "skipped"
    for core in (
        "intake",
        "targeted_deep_analysis",
        "independent_validation",
        "final_report",
    ):
        assert core in stages


def test_hunt_mode_persists_three_stages_and_artifact(service, checkout, tmp_path, monkeypatch):
    import vulnscan.ai.hunt as hunt_mod
    import vulnscan.ai.laya_verify as verify_mod
    import vulnscan.providers.profile_store as store_mod

    candidate = {
        "title": "SQL concatenation in Example",
        "file": "Example.java",
        "line": 2,
        "cwe": "CWE-89",
        "severity": "high",
        "rationale": "tainted string reaches query",
        "evidence": "executeQuery(",
    }

    def _fake_hunt(*, snapshot_root, client, model, max_rounds=8, max_findings=20):
        assert Path(snapshot_root, "Example.java").is_file()
        return {"candidates": [dict(candidate)], "rounds": 2, "usage": {}, "status": "completed"}

    def _fake_hunt_all(
        *,
        snapshot_root,
        client,
        model,
        families=None,
        logic_pass=True,
        max_rounds=12,
        max_findings=20,
        **_kwargs,
    ):
        assert Path(snapshot_root, "Example.java").is_file()
        return {
            "candidates": [dict(candidate)],
            "passes": [
                {"family": f, "status": "completed", "candidates": 1}
                for f in (families or ["java"])
            ],
            "rounds": 2,
            "usage": {},
            "status": "completed",
            "detail": "fake multi-pass hunt",
            "trace": [],
        }

    def _fake_verify(candidates, *, snapshot_root, laya_config=None):
        return [
            {**c, "laya_route": "deep", "laya_confidence": 0.9, "laya_status": "completed"}
            for c in candidates
        ]

    monkeypatch.setattr(hunt_mod, "hunt_vulns", _fake_hunt)
    monkeypatch.setattr(hunt_mod, "hunt_all", _fake_hunt_all)
    monkeypatch.setattr(verify_mod, "laya_verify_candidates", _fake_verify)
    monkeypatch.setattr(store_mod, "load_profile", lambda _pid: _profile())

    result = service.run(str(checkout), settings(tmp_path, mode="hunt", provider_profile="test"))
    assert result["model_candidates"]
    assert result["comparison"]["counts"]["agreed"] >= 1
    stages = {e["stage"]: e["status"] for e in result["stages"]}
    for name in HUNT_STAGES:
        assert stages.get(name) == "completed", stages
    hunt_path = Path(result["reports"]["hunt"])
    assert hunt_path.is_file()
    payload = json.loads(hunt_path.read_text(encoding="utf-8"))
    assert payload["candidates"][0]["file"] == "Example.java"
    assert payload["comparison"]["counts"]["agreed"] >= 1


def test_hunt_mode_without_provider_falls_back_to_deterministic(service, checkout, tmp_path):
    result = service.run(str(checkout), settings(tmp_path, mode="hunt"))
    stages = {e["stage"]: e["status"] for e in result["stages"]}
    assert stages.get("model_hunt") == "skipped"
    assert "laya_verification" not in stages
    assert "model_scanner_compare" not in stages
    assert "hunt" not in result["reports"]
    assert result["orchestration"]["mode"] == "deterministic_fallback"


def test_hunt_mode_ai_orchestrates_scanners_without_duplicate_runs(checkout, tmp_path, monkeypatch):
    """Unified Phase 1 + Phase 2: AI invokes scanners directly; Phase 2 does NOT re-run them."""
    import vulnscan.ai.laya_verify as verify_mod
    import vulnscan.providers.client as client_mod
    import vulnscan.providers.profile_store as store_mod
    from vulnscan.providers.client import ChatResponse

    class CountingAdapter(FixtureAdapter):
        def __init__(self, tool_name: ToolName) -> None:
            self.tool = tool_name
            self.calls = 0

        def run(self, spec, *, workdir):
            self.calls += 1
            result = super().run(spec, workdir=workdir)
            original = result.observations[0]
            result.observations.append(
                original.model_copy(
                    update={
                        "observation_id": "unmatched-scan-observation",
                        "rule_id": "scanner-only",
                        "cwe_category": CWECategory.XSS,
                        "severity": Severity.HIGH,
                    }
                )
            )
            return result

    semgrep_adapter = CountingAdapter(ToolName.SEMGREP)
    gitleaks_adapter = CountingAdapter(ToolName.GITLEAKS)
    registry = AdapterRegistry()
    registry.register(semgrep_adapter)
    registry.register(gitleaks_adapter)
    svc = ScanService(str(tmp_path / "runs.db"), registry)

    calls_seen: list[dict] = []

    def _fake_chat(
        self,
        messages,
        *,
        model=None,
        temperature=0.0,
        max_tokens=4096,
        tools=None,
        tool_choice="auto",
    ):
        calls_seen.append({"has_tools": bool(tools), "n_messages": len(messages)})
        # First turn of the java pass: AI invokes run_semgrep_scan directly
        if tools and semgrep_adapter.calls == 0:
            return ChatResponse(
                content="",
                tool_calls=[
                    {
                        "id": "tc-semgrep-1",
                        "type": "function",
                        "function": {
                            "name": "run_semgrep_scan",
                            "arguments": json.dumps({"target_path": ".", "language": "java"}),
                        },
                    }
                ],
                finish_reason="tool_calls",
                model="v0-pro",
            )
        # After receiving extracted scanner output, AI returns analyzed JSON findings
        return ChatResponse(
            content=json.dumps(
                [
                    {
                        "title": "SQL injection confirmed via Semgrep",
                        "file": "Example.java",
                        "line": 1,
                        "cwe": "CWE-89",
                        "severity": "low",
                        "rationale": "Verified from Semgrep finding test-low",
                        "evidence": "class Example {}",
                    }
                ]
            ),
            finish_reason="stop",
            model="v0-pro",
        )

    monkeypatch.setattr(client_mod.ProviderClient, "chat", _fake_chat)
    monkeypatch.setattr(store_mod, "load_profile", lambda _pid: _profile())
    monkeypatch.setattr(
        verify_mod,
        "laya_verify_candidates",
        lambda candidates, *, snapshot_root, laya_config=None: [
            {**c, "laya_route": "deep", "laya_confidence": 0.9, "laya_status": "completed"}
            for c in candidates
        ],
    )

    result = svc.run(str(checkout), settings(tmp_path, mode="hunt", provider_profile="test"))

    # Tool-first orchestration: Turn 1 received tools immediately (no no-tools fast path)
    assert calls_seen and calls_seen[0]["has_tools"] is True
    # AI invoked Semgrep once and Phase 2 reused it without re-running Semgrep or Gitleaks
    assert semgrep_adapter.calls == 1
    assert gitleaks_adapter.calls == 0
    assert result["orchestration"] == {
        "mode": "ai_orchestrated",
        "ai_invoked_tools": ["semgrep"],
    }
    assert result["status"] == "completed"
    assert result["exit_code"] == 1
    assert result["findings"] == 2
    assert result["comparison"]["counts"]["agreed"] >= 1
    assert (tmp_path / "reports" / result["run_id"] / "scanner-semgrep.json").is_file()


def test_hunt_mode_falls_back_to_static_scanners_on_ai_error(checkout, tmp_path, monkeypatch):
    """If the AI provider errors (e.g. HTTP 429), ScanService falls back to static scanners."""
    import vulnscan.providers.client as client_mod
    import vulnscan.providers.profile_store as store_mod
    from vulnscan.providers.client import ProviderError

    class CountingAdapter(FixtureAdapter):
        def __init__(self, tool_name: ToolName) -> None:
            self.tool = tool_name
            self.calls = 0

        def run(self, spec, *, workdir):
            self.calls += 1
            return super().run(spec, workdir=workdir)

    native_adapter = CountingAdapter(ToolName.NATIVE_HUNT)
    semgrep_adapter = CountingAdapter(ToolName.SEMGREP)
    gitleaks_adapter = CountingAdapter(ToolName.GITLEAKS)
    registry = AdapterRegistry()
    registry.register(native_adapter)
    registry.register(semgrep_adapter)
    registry.register(gitleaks_adapter)
    svc = ScanService(str(tmp_path / "runs.db"), registry)

    def _failing_chat(self, *args, **kwargs):
        raise ProviderError("HTTP 429: daily message limit")

    monkeypatch.setattr(client_mod.ProviderClient, "chat", _failing_chat)
    monkeypatch.setattr(store_mod, "load_profile", lambda _pid: _profile())

    result = svc.run(
        str(checkout),
        settings(tmp_path, mode="hunt", provider_profile="test", tools=None),
    )

    assert result["orchestration"]["mode"] == "deterministic_fallback"
    assert native_adapter.calls == 1
    assert result["status"] == "completed"
    assert semgrep_adapter.calls == 1, result["errors"]
    assert gitleaks_adapter.calls == 1, result["errors"]
    assert result["exit_code"] == 0
