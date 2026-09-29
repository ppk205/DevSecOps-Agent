"""QR-22 / FR-72: full-profile containment and incomplete execution reporting."""

from datetime import UTC, datetime
from pathlib import Path

from vulnscan.contracts import RunStatus, ScannerResult, ScanSpecification, ToolName
from vulnscan.infra.full_scan import run_isolated_tool
from vulnscan.scanners.process import CommandResult


def test_full_profile_scopes_mounts_and_cleans_container(monkeypatch, tmp_path):
    calls = []
    spec = ScanSpecification(
        run_id="test",
        target_repository_url="local",
        target_commit_sha="abcd",
        repository_checkout_path=str(tmp_path),
    )

    def invoke(argv, **kwargs):
        calls.append(argv)
        if argv[1] == "run":
            mounts = [argv[i + 1] for i, arg in enumerate(argv) if arg == "--mount"]
            assert len(mounts) == 2
            assert mounts[0].endswith("target=/input,readonly")
            assert "--cap-drop=ALL" in argv and "--read-only" in argv and "--user" in argv
            assert not any("docker.sock" in arg for arg in argv)
            output = Path(mounts[1].split("source=", 1)[1].split(",target=", 1)[0])
            result = ScannerResult(
                run_id="test",
                tool=ToolName.SPOTBUGS,
                tool_version="4.10.4",
                adapter_version="test",
                status=RunStatus.COMPLETED,
                started_at=datetime.now(UTC),
            )
            (output / "result.json").write_text(result.model_dump_json())
        return CommandResult(0)

    monkeypatch.setattr("vulnscan.infra.full_scan.run_command", invoke)
    result = run_isolated_tool(ToolName.SPOTBUGS, spec, 10)
    assert result.is_complete
    assert calls[-1][:3] == ["docker", "rm", "-f"]


def test_full_profile_missing_image_or_build_output_fails(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "vulnscan.infra.full_scan.run_command",
        lambda *a, **k: CommandResult(125, stderr="image not found"),
    )
    spec = ScanSpecification(
        run_id="test",
        target_repository_url="local",
        target_commit_sha="abcd",
        repository_checkout_path=str(tmp_path),
    )
    result = run_isolated_tool(ToolName.SPOTBUGS, spec, 10)
    assert result.status == RunStatus.FAILED
    assert "image not found" in result.errors[0]


def test_advisory_updater_has_no_target_and_build_gets_readonly_cache(monkeypatch, tmp_path):
    calls = []
    spec = ScanSpecification(
        run_id="cache-test",
        target_repository_url="local",
        target_commit_sha="abcd",
        repository_checkout_path=str(tmp_path / "checkout"),
        metadata={"configuration": {"output_dir": str(tmp_path / "artifacts")}},
    )

    def invoke(argv, **kwargs):
        if argv[1] != "run":
            return CommandResult(0)
        calls.append(argv)
        mounts = [argv[i + 1] for i, arg in enumerate(argv) if arg == "--mount"]
        if "--updateonly" in argv:
            assert len(mounts) == 1 and mounts[0].endswith("target=/data")
            assert not any("/input" in item for item in argv)
            cache = Path(mounts[0].split("source=", 1)[1].split(",target=", 1)[0])
            (cache / "odc.mv.db").write_bytes(b"fixture-advisory-database")
        else:
            assert mounts[-1].endswith("target=/advisories,readonly")
            output = Path(mounts[1].split("source=", 1)[1].split(",target=", 1)[0])
            result = ScannerResult(
                run_id="cache-test",
                tool=ToolName.OWASP_DEPENDENCY_CHECK,
                tool_version="13.0.0",
                adapter_version="test",
                status=RunStatus.COMPLETED,
                started_at=datetime.now(UTC),
            )
            (output / "result.json").write_text(result.model_dump_json())
        return CommandResult(0)

    monkeypatch.setattr("vulnscan.infra.full_scan.run_command", invoke)
    result = run_isolated_tool(ToolName.OWASP_DEPENDENCY_CHECK, spec, 10)
    assert result.is_complete and len(calls) == 2
    assert len(result.metadata["advisory_database_sha256"]) == 64
