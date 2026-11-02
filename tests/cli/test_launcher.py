"""C-04/FR-71: the Python launcher opens the native chat client."""

import subprocess
import sys
from types import SimpleNamespace

import pytest
from typer import Exit

from vulnscan.cli import main as cli
from vulnscan.core import native


@pytest.fixture(autouse=True)
def no_legacy_tui(monkeypatch):
    monkeypatch.setitem(
        sys.modules,
        "vulnscan.tui.app",
        SimpleNamespace(
            ScanApp=lambda *args, **kwargs: pytest.fail("legacy Python TUI was launched")
        ),
    )
    monkeypatch.setattr("vulnscan.infra.envfile.EnvFile.load_into_environ", lambda self: [])


@pytest.mark.parametrize("command", ["tui", "scan-run"])
def test_fr71_default_source_commands_use_python(monkeypatch, command):
    called = []
    monkeypatch.setenv("DEVSECOPS_NATIVE", "auto")
    monkeypatch.setattr(native, "binary_path", lambda **kwargs: "native-binary")
    monkeypatch.setattr(sys, "argv", ["devsec", command])
    monkeypatch.setattr(cli, "app", lambda: called.append("python"))
    cli.main()
    assert called == ["python"]


def test_fr71_explicit_native_tui_is_retained(monkeypatch):
    called = []
    monkeypatch.setenv("DEVSECOPS_NATIVE", "go")
    monkeypatch.delenv("DEVSECOPS_PYTHON_ONLY", raising=False)
    monkeypatch.setattr(native, "binary_path", lambda **kwargs: "native-binary")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda args, **kwargs: called.append(args) or subprocess.CompletedProcess(args, 0),
    )
    with pytest.raises(Exit) as result:
        cli.launch_tui("fixture.db")
    assert result.value.exit_code == 0
    assert called[0] == ["native-binary", "tui", "--db-path", "fixture.db"]


def test_fr71_auto_tui_opens_native_chat(monkeypatch):
    called = []
    monkeypatch.setenv("DEVSECOPS_NATIVE", "auto")
    monkeypatch.setattr(native, "binary_path", lambda **kwargs: "native-binary")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda args, **kwargs: called.append(args) or subprocess.CompletedProcess(args, 0),
    )
    with pytest.raises(Exit) as result:
        cli.launch_tui("fixture.db")
    assert result.value.exit_code == 0
    assert called == [["native-binary", "tui", "--db-path", "fixture.db"]]


def test_tui_without_binary_exits_2_with_build_hint(monkeypatch, capsys):
    monkeypatch.setenv("DEVSECOPS_NATIVE", "python")
    monkeypatch.setattr(native, "binary_path", lambda **kwargs: None)
    with pytest.raises(Exit) as result:
        cli.launch_tui("fixture.db")
    assert result.value.exit_code == 2
    assert "chat needs the native binary: run ci/build_native.py" in capsys.readouterr().out


@pytest.mark.parametrize("command", ["chat", "model", "hooks", "remote"])
def test_harness_commands_stay_python_with_go_preference(monkeypatch, command):
    called = []
    monkeypatch.setenv("DEVSECOPS_NATIVE", "go")
    monkeypatch.delenv("DEVSECOPS_PYTHON_ONLY", raising=False)
    monkeypatch.setattr(native, "binary_path", lambda **kwargs: "native-binary")
    monkeypatch.setattr(sys, "argv", ["devsec", command])
    monkeypatch.setattr(cli, "app", lambda: called.append("python"))
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: pytest.fail("native dispatch"))
    cli.main()
    assert called == ["python"]
