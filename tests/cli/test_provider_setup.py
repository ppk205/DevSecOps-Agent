from typer.testing import CliRunner

from vulnscan.cli.main import app
from vulnscan.providers.profile_store import load_profile


def test_ir11_guided_provider_setup(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        ["provider-setup"],
        input="my-provider\nhttps://example.test/v1\nexample-model\nMY_TEST_KEY\nsynthetic-secret\n",
    )
    assert result.exit_code == 0, result.output
    profile = load_profile("my-provider", tmp_path / ".providers")
    assert profile.default_model == "example-model"
    assert profile.api_key_env == "MY_TEST_KEY"
    assert "synthetic-secret" not in result.output
    assert "synthetic-secret" not in (tmp_path / ".providers" / "my-provider.json").read_text()


def test_ir11_guided_setup_rejects_invalid_profile_before_saving(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        ["provider-setup"],
        input="../bad\nhttps://example.test/v1\nexample-model\nMY_TEST_KEY\nsynthetic-secret\n",
    )
    assert result.exit_code != 0
    assert not (tmp_path / ".env").exists()


def test_ir11_guided_setup_reuses_existing_environment_key(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MY_TEST_KEY", "synthetic-secret")
    result = CliRunner().invoke(
        app,
        ["provider-setup"],
        input="my-provider\nhttps://example.test/v1\nexample-model\nMY_TEST_KEY\n",
    )
    assert result.exit_code == 0, result.output
    assert "existing key" in result.output
    assert "synthetic-secret" not in result.output
    assert not (tmp_path / ".env").exists()
