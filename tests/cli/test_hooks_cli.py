"""The documented hooks command reaches Python with an explicit target."""

from pathlib import Path

from typer.testing import CliRunner

from vulnscan.cli.main import app
from vulnscan.harness import hooks


def test_hooks_accepts_target_flag(monkeypatch, tmp_path):
    seen = []

    def install(repo, python):
        seen.append(repo)
        return ["post-commit", "post-merge"]

    monkeypatch.setattr(hooks, "install", install)
    result = CliRunner().invoke(app, ["hooks", "install", "--target", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert seen == [Path(tmp_path)]
    assert "post-commit" in result.output and "post-merge" in result.output
