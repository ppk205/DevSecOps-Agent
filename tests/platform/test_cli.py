"""Platform tests: CLI smoke tests (T01 gate)."""

from typer.testing import CliRunner

from vulnscan.cli.main import app

runner = CliRunner()


def test_db_init():
    """db-init must succeed."""
    result = runner.invoke(app, ["db-init", "--db-path", ":memory:"])
    assert result.exit_code == 0
    assert "Initialized" in result.output


def test_target_add_and_list():
    result = runner.invoke(app, ["db-init", "--db-path", ":memory:"])
    assert result.exit_code == 0
    result = runner.invoke(
        app,
        [
            "target-add",
            "https://github.com/test/repo",
            "deadbeef",
            "--db-path",
            ":memory:",
        ],
    )
    assert result.exit_code == 0
    assert "Added target" in result.output
