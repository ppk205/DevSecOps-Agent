"""TDD tests for CLI ``env`` commands and TUI onboarding tab."""

from __future__ import annotations

from typer.testing import CliRunner

from vulnscan.cli.main import app
from vulnscan.infra.envfile import EnvFile

runner = CliRunner()


def test_env_list_empty(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["env", "list"])
    assert result.exit_code == 0
    assert "No keys" in result.output or "no keys" in result.output.lower()


def test_env_set_and_list(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["env", "set", "TEST_SECRET_KEY", "--value", "abc123"])
    assert result.exit_code == 0, result.output
    assert "saved" in result.output.lower() or "TEST_SECRET_KEY" in result.output

    result = runner.invoke(app, ["env", "list"])
    assert result.exit_code == 0
    assert "TEST_SECRET_KEY" in result.output
    assert "abc123" not in result.output  # never leak actual value


def test_env_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["env", "path"])
    assert result.exit_code == 0
    assert ".env" in result.output


def test_env_unset(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["env", "set", "TEMPREMOVE", "--value", "x"])
    result = runner.invoke(app, ["env", "unset", "TEMPREMOVE"])
    assert result.exit_code == 0
    assert EnvFile(tmp_path / ".env").get("TEMPREMOVE") is None


def test_env_set_rejects_empty_value(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["env", "set", "BADKEY", "--value", ""])
    assert result.exit_code != 0 or "empty" in result.output.lower() or "invalid" in result.output.lower()


def test_env_set_rejects_bad_name(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["env", "set", "123-BAD!", "--value", "x"])
    assert result.exit_code != 0 or "invalid" in result.output.lower()


def test_cli_env_show_help():
    result = runner.invoke(app, ["env", "--help"])
    assert result.exit_code == 0
    assert "set" in result.output.lower() or "manage" in result.output.lower()
