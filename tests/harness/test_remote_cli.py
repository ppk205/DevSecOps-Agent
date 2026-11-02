"""The headless remote command validates binding before starting a host."""

from typer.testing import CliRunner

from vulnscan.cli.main import app


def test_non_loopback_bind_requires_flag() -> None:
    result = CliRunner().invoke(app, ["remote", "--remote-host", "0.0.0.0"])
    assert result.exit_code == 2
    assert "--remote-allow-lan" in result.output


def test_remote_help_includes_chat_and_listener_options() -> None:
    result = CliRunner().invoke(app, ["remote", "--help"])
    assert result.exit_code == 0
    for flag in ("--target", "--model", "--provider", "--mode", "--budget", "--resume", "--port"):
        assert flag in result.output
