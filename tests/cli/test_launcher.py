"""C-04/FR-71: default launches retain URL/credential surfaces and explicit native UI."""

import subprocess
import sys

import pytest
from typer import Exit

from vulnscan.cli import main as cli
from vulnscan.core import native
from vulnscan.tui import app as tui


@pytest.mark.parametrize("command", ["tui", "scan-run"])
def test_fr71_default_source_commands_use_python(monkeypatch, command):
    called = []
    monkeypatch.setenv("DEVSECOPS_NATIVE", "auto")
    monkeypatch.setattr(native, "binary_path", lambda: "native-binary")
    monkeypatch.setattr(sys, "argv", ["devsec", command])
    monkeypatch.setattr(cli, "app", lambda: called.append("python"))
    cli.main()
    assert called == ["python"]


def test_fr71_explicit_native_tui_is_retained(monkeypatch):
    called = []
    monkeypatch.setenv("DEVSECOPS_NATIVE", "go")
    monkeypatch.delenv("DEVSECOPS_PYTHON_ONLY", raising=False)
    monkeypatch.setattr(native, "binary_path", lambda: "native-binary")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda args, **kwargs: called.append(args) or subprocess.CompletedProcess(args, 0),
    )
    with pytest.raises(Exit) as result:
        cli.launch_tui("fixture.db")
    assert result.value.exit_code == 0
    assert called[0] == ["native-binary", "tui", "--db-path", "fixture.db"]


def test_fr71_auto_tui_uses_full_workspace(monkeypatch):
    called = []

    class Workspace:
        def __init__(self, db_path):
            called.append(db_path)

        def run(self):
            called.append("workspace")

    monkeypatch.setenv("DEVSECOPS_NATIVE", "auto")
    monkeypatch.setattr(native, "binary_path", lambda: "native-binary")
    monkeypatch.setattr(tui, "ScanApp", Workspace)
    cli.launch_tui("fixture.db")
    assert called == ["fixture.db", "workspace"]
