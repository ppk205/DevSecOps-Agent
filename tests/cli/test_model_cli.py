"""The CLI and console share a masked add-model wizard."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.harness.conftest import make_ctx, scripted
from tests.harness.fakes import ScriptedTransport
from vulnscan.cli.main import app
from vulnscan.harness import models
from vulnscan.harness.console import ChatConsole, console_asker
from vulnscan.harness.gates import Gate, GateRequest
from vulnscan.harness.session import Session
from vulnscan.infra.envfile import EnvFile


@pytest.fixture
def isolated_models(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> EnvFile:
    env = EnvFile(tmp_path / "synthetic.keys")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(models, "EnvFile", lambda: env)
    monkeypatch.setattr("vulnscan.infra.envfile.EnvFile", lambda: env)
    monkeypatch.delenv("DEVSEC_KEY_MY_CLOUD", raising=False)
    monkeypatch.delenv("DEVSEC_KEY_LOCAL", raising=False)
    return env


def test_model_add_wizard_masks_key(
    isolated_models: EnvFile, monkeypatch: pytest.MonkeyPatch
) -> None:
    prompts: list[str] = []

    def hidden(prompt: str) -> str:
        prompts.append(prompt)
        return "synthetic-wizard-credential"

    monkeypatch.setattr("getpass.getpass", hidden)
    result = CliRunner().invoke(
        app, ["model", "add", "--template", "deepseek"], input="my-cloud\n\n\nmodel-one,model-two\n"
    )
    assert result.exit_code == 0, result.output
    assert prompts and "synthetic-wizard-credential" not in result.output
    assert "DEVSEC_KEY_" not in result.output and "key set" in result.output
    assert isolated_models.get("DEVSEC_KEY_MY_CLOUD") == "synthetic-wizard-credential"


def test_model_list_key_and_remove(
    isolated_models: EnvFile, monkeypatch: pytest.MonkeyPatch
) -> None:
    models.add_model("local", "ollama", "", "", ["m"], None)
    runner = CliRunner()
    listed = runner.invoke(app, ["model", "list"])
    assert listed.exit_code == 0 and "local:m" in listed.output and "local" in listed.output
    monkeypatch.setattr("getpass.getpass", lambda prompt: "synthetic-updated-key")
    keyed = runner.invoke(app, ["model", "key", "local"])
    assert keyed.exit_code == 0 and "synthetic-updated-key" not in keyed.output
    assert "DEVSEC_KEY_" not in keyed.output
    assert runner.invoke(app, ["model", "remove", "local"]).exit_code == 0
    assert models.list_models() == []


def test_legacy_provider_flag_still_works(isolated_models: EnvFile, tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "chat",
            "--target",
            str(tmp_path),
            "--provider",
            "ollama",
            "--model",
            "m",
            "--sessions-dir",
            str(tmp_path / "sessions"),
            "-p",
            "hi",
        ],
    )
    assert result.exit_code == 2 and "G0 needs a human" in result.output


@pytest.mark.parametrize("spec,expected", [("local", "m"), ("local:family:large", "family:large")])
def test_chat_resolves_added_model_default(
    isolated_models: EnvFile,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    spec: str,
    expected: str,
) -> None:
    models.add_model("local", "ollama", "", "", ["m", "family:large"], None)
    seen: list[tuple[str, str]] = []

    def refused(session: Session) -> bool:
        seen.append((session.transport.profile.id, session.transport.model))
        return False

    monkeypatch.setattr(Session, "start", refused)
    result = CliRunner().invoke(
        app,
        [
            "chat",
            "--model",
            spec,
            "--target",
            str(tmp_path),
            "--sessions-dir",
            str(tmp_path / "sessions"),
        ],
    )
    assert result.exit_code == 2 and seen == [("local", expected)]


def test_model_command_stays_in_python(
    isolated_models: EnvFile, monkeypatch: pytest.MonkeyPatch
) -> None:
    main = importlib.import_module("vulnscan.cli.main")
    called: list[bool] = []
    monkeypatch.setattr("sys.argv", ["devsec", "model", "list"])
    monkeypatch.setattr("vulnscan.core.native.binary_path", lambda: "native-present")
    monkeypatch.setenv("DEVSECOPS_NATIVE", "go")
    monkeypatch.setattr(main, "app", lambda: called.append(True))
    monkeypatch.setattr(
        "subprocess.run", lambda *args, **kwargs: pytest.fail("model reached native CLI")
    )
    main.main()
    assert called == [True]


def test_console_lists_adds_and_switches_models(
    isolated_models: EnvFile, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx, _ = make_ctx(tmp_path, [])
    out: list[str] = []
    monkeypatch.setattr("getpass.getpass", lambda prompt: "")
    con = ChatConsole(
        Session(ScriptedTransport([]), ctx),
        read=scripted(["local", "ollama", "", "", "m"]),
        write=out.append,
    )
    con.handle("/model add")
    con.handle("/model")
    con.handle("/keys")
    con.handle("/model local")
    assert con.session.transport.profile.id == "local" and con.session.transport.model == "m"
    assert "local:m" in "\n".join(out) and "DEVSEC_KEY_" not in "\n".join(out)


@pytest.mark.parametrize("reply", ["", "yes", "n", "y"])
def test_console_auto_requires_explicit_y(
    isolated_models: EnvFile, tmp_path: Path, reply: str
) -> None:
    ctx, _ = make_ctx(tmp_path, [])
    con = ChatConsole(
        Session(ScriptedTransport([]), ctx), read=scripted([reply]), write=lambda text: None
    )
    con.handle("/mode auto")
    assert ctx.gates.mode == ("auto" if reply == "y" else "ask")
    mode_events = [event for event in ctx.log.events() if event["type"] == "mode"]
    assert len(mode_events) == (1 if reply == "y" else 0)


def test_console_closed_auto_confirmation_preserves_mode(
    isolated_models: EnvFile, tmp_path: Path
) -> None:
    ctx, _ = make_ctx(tmp_path, [])

    def closed(prompt: str) -> str:
        raise EOFError

    con = ChatConsole(Session(ScriptedTransport([]), ctx), read=closed, write=lambda text: None)
    con.handle("/mode auto")
    assert ctx.gates.mode == "ask"


def test_console_gate_shows_mode_dangerous_and_g7_edit() -> None:
    out: list[str] = []
    decision = console_asker(scripted(["e", '{"paths":["A.java"]}']), out.append, mode="auto")(
        GateRequest(Gate.G7_RESCAN, "Re-scan", "Read the fix")
    )
    assert decision.edits == {"paths": ["A.java"]} and "mode: auto" in "\n".join(out)
    console_asker(scripted(["n", "declined"]), out.append)(
        GateRequest(Gate.G0_SESSION, "Start", "Send code")
    )
    assert "DANGEROUS" in "\n".join(out)


def test_model_key_never_falls_back_to_echoed_input(
    isolated_models: EnvFile,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import getpass
    import warnings

    models.add_model("local", "ollama", "", "", ["m"], None)

    def unmasked(prompt: str) -> str:
        warnings.warn("Password input may be echoed.", getpass.GetPassWarning, stacklevel=2)
        pytest.fail("unmasked credential input was permitted")

    monkeypatch.setattr(getpass, "getpass", unmasked)
    result = CliRunner().invoke(app, ["model", "key", "local"])
    assert result.exit_code == 2
    assert isolated_models.names() == []


def test_console_cloud_switch_still_needs_g0(
    isolated_models: EnvFile,
    tmp_path: Path,
) -> None:
    models.add_model(
        "my-cloud",
        None,
        "openai_compatible",
        "https://models.example/v1",
        ["m"],
        "synthetic-cloud-key",
    )
    ctx, asked = make_ctx(tmp_path, ["reject"])
    con = ChatConsole(Session(ScriptedTransport([]), ctx), write=lambda text: None)
    con.handle("/model my-cloud")
    assert asked == ["G0"] and con.session.transport.profile.id == "ollama"
