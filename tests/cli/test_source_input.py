"""FR-01/70: real local scanning and reports without Git or a provider."""

import json

import pytest
from typer.testing import CliRunner

from vulnscan.cli.main import app


@pytest.mark.parametrize("without_git", [False, True])
def test_fr01_python_cli_scans_unversioned_sources(tmp_path, monkeypatch, without_git):
    folder = tmp_path / "plain folder"
    folder.mkdir()
    (folder / "Example.java").write_text("class Example {}", encoding="utf-8")
    monkeypatch.setenv("DEVSECOPS_NATIVE", "python")
    if without_git:
        empty = tmp_path / "empty path"
        empty.mkdir()
        monkeypatch.setenv("PATH", str(empty))
    config = tmp_path / "scan.json"
    config.write_text(
        json.dumps(
            {"schema_version": 1, "tools": ["native-hunt"], "mode": "deterministic", "laya": False}
        ),
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        app,
        [
            "scan-run",
            "--checkout",
            f'"{folder}"',
            "--config",
            str(config),
            "--db-path",
            str(tmp_path / "scan.db"),
            "--out",
            str(tmp_path / "reports"),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    summary = json.loads(result.stdout)
    assert summary["commit"] == "no-revision"
    assert summary["manifest"]["dirty"] is None
    assert summary["manifest"]["inventory"] == ["Example.java"]
    assert summary["reports"]["json"]
