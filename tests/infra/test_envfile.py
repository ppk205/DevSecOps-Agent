"""TDD: friendly first-run experience + API key management.

User story: user opens TUI/CLI with no prior knowledge and should know
what to do next, and be able to save an API key without touching the shell.
"""

import os

from vulnscan.infra.envfile import EnvFile, find_project_root, mask_secret


def test_mask_secret_never_leaks_value():
    masked = mask_secret("sk-abcdef123456")
    assert "abcdef" not in masked
    assert "123456" not in masked
    assert masked != ""


def test_mask_secret_empty_stays_empty():
    assert mask_secret("") == ""


def test_envfile_roundtrip(tmp_path, monkeypatch):
    env = EnvFile(tmp_path / ".env")
    env.set("TEST_API_KEY", "super-secret-123")
    assert (tmp_path / ".env").exists()
    # value persisted and re-readable
    assert EnvFile(tmp_path / ".env").get("TEST_API_KEY") == "super-secret-123"
    # raw file contains the value (expected — file is gitignored + chmod 600)
    raw = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "TEST_API_KEY=super-secret-123" in raw


def test_envfile_preserves_other_lines(tmp_path):
    target = tmp_path / ".env"
    target.write_text("KEEP_ME=yes\nTEST_API_KEY=old\n", encoding="utf-8")
    EnvFile(target).set("TEST_API_KEY", "new-value-456")
    text = target.read_text(encoding="utf-8")
    assert "KEEP_ME=yes" in text
    assert "TEST_API_KEY=new-value-456" in text
    assert "old" not in text


def test_envfile_missing_key_returns_none(tmp_path):
    assert EnvFile(tmp_path / ".env").get("MISSING") is None


def test_envfile_names_lists_stored_keys_unmasked_values_never(tmp_path):
    env = EnvFile(tmp_path / ".env")
    env.set("OPENAI_API_KEY", "sk-secret")
    env.set("OTHER", "plain")
    names = env.names()
    assert "OPENAI_API_KEY" in names
    assert "OTHER" in names
    # no stored values exposed via names()
    assert "sk-secret" not in " ".join(names)


def test_find_project_root_from_nested_dir(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert find_project_root(nested) == tmp_path


def test_find_project_root_falls_back_to_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert find_project_root(tmp_path) == tmp_path


def test_envfile_applies_to_process_env(tmp_path, monkeypatch):
    env = EnvFile(tmp_path / ".env")
    env.set("TUI_TEST_KEY", "abc-123")
    monkeypatch.delenv("TUI_TEST_KEY", raising=False)
    loaded = env.load_into_environ()
    assert "TUI_TEST_KEY" in loaded
    assert os.environ["TUI_TEST_KEY"] == "abc-123"


def test_envfile_does_not_override_existing_environ(tmp_path, monkeypatch):
    env = EnvFile(tmp_path / ".env")
    env.set("TUI_TEST_KEY", "from-file")
    monkeypatch.setenv("TUI_TEST_KEY", "from-shell")
    env.load_into_environ()
    assert os.environ["TUI_TEST_KEY"] == "from-shell"


def test_envfile_restrictive_permissions(tmp_path):
    env = EnvFile(tmp_path / ".env")
    env.set("K", "v")
    if os.name == "posix":
        mode = (tmp_path / ".env").stat().st_mode & 0o777
        assert mode == 0o600
