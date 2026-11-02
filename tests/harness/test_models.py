"""Added models own their keys; storage and display never expose credentials."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from vulnscan.harness import models
from vulnscan.infra.envfile import EnvFile


@pytest.fixture
def model_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, EnvFile]:
    monkeypatch.chdir(tmp_path)
    env = EnvFile(tmp_path / "synthetic.keys")
    monkeypatch.setattr(models, "EnvFile", lambda: env)
    for alias in ("MY_CLOUD", "LOCAL", "OTHER", "A", "1", "MY_CLOUD_OTHER"):
        monkeypatch.delenv("DEVSEC_KEY_" + alias, raising=False)
    monkeypatch.delenv("OTHER", raising=False)
    return tmp_path / ".providers", env


def cloud(store: Path, env: EnvFile, **overrides: object) -> models.ModelEntry:
    args = {
        "alias": "my-cloud",
        "template": "deepseek",
        "protocol": "openai_compatible",
        "base_url": "https://models.example/v1",
        "models": ["model-one", "model-two"],
        "key": "synthetic-model-credential",
        "store": store,
        "env": env,
    }
    args.update(overrides)
    return models.add_model(**args)  # type: ignore[arg-type]


def test_add_cloud_model_stores_key_in_env_not_profile(model_store: tuple[Path, EnvFile]) -> None:
    store, env = model_store
    entry = cloud(store, env)
    saved = (store / "my-cloud.json").read_text()
    assert "synthetic-model-credential" not in saved
    assert json.loads(saved)["api_key_env"] == "DEVSEC_KEY_MY_CLOUD"
    assert env.get("DEVSEC_KEY_MY_CLOUD") == "synthetic-model-credential"
    assert entry.key_set and entry.default_model == "model-one" and not entry.local


@pytest.mark.parametrize("key", [None, "", "  "])
def test_cloud_model_without_key_is_refused(
    model_store: tuple[Path, EnvFile], key: str | None
) -> None:
    store, env = model_store
    with pytest.raises(ValueError, match="key"):
        cloud(store, env, key=key)
    assert not (store / "my-cloud.json").exists()
    assert env.names() == []


@pytest.mark.parametrize(
    "url", ["http://127.0.0.1:11434/v1", "http://localhost:1234/v1", "http://[::1]:8000/v1"]
)
def test_local_model_needs_no_key(model_store: tuple[Path, EnvFile], url: str) -> None:
    store, env = model_store
    entry = cloud(store, env, alias="local", base_url=url, key=None)
    assert entry.local and not entry.key_set
    assert models.resolve_model("local")[1] == "model-one"


def test_models_event_has_no_key_values_or_env_names(model_store: tuple[Path, EnvFile]) -> None:
    store, env = model_store
    cloud(store, env)
    event = models.models_event(models.list_models(store=store))
    assert event["type"] == "models" and len(event["items"]) == 1
    assert set(event["items"][0]) == {
        "alias",
        "protocol",
        "base_url",
        "models",
        "default_model",
        "local",
        "key_set",
    }
    text = json.dumps(event)
    assert "synthetic-model-credential" not in text and "DEVSEC_KEY_" not in text


def test_models_event_templates_match_builtins_without_reading_stores(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("models event must not read profile or credential storage")

    monkeypatch.setattr(models, "_profiles", forbidden)
    monkeypatch.setattr(models, "EnvFile", forbidden)
    event = models.models_event([])
    templates = {item["id"]: item for item in event["templates"]}
    assert event["items"] == []
    assert len(event["templates"]) == len(models.BUILTIN_PROFILES)
    assert set(templates) == set(models.BUILTIN_PROFILES)
    public = {"id", "label", "protocol", "base_url", "models", "default_model"}
    text = json.dumps(event)
    for name, profile in models.BUILTIN_PROFILES.items():
        assert templates[name] == profile.model_dump(mode="json", include=public)
        if profile.api_key_env:
            assert profile.api_key_env not in text
    assert "api_key_env" not in text and "DEVSEC_KEY_" not in text


def test_models_event_templates_exclude_private_profile_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    template = next(iter(models.BUILTIN_PROFILES.values()))
    private = template.model_copy(
        update={
            "api_key_env": "SYNTHETIC_TEMPLATE_API_KEY",
            "headers": {"Authorization": "synthetic-template-credential"},
            "metadata": {"private": "synthetic-template-metadata"},
        }
    )
    monkeypatch.setattr(models, "BUILTIN_PROFILES", {private.id: private})
    event = models.models_event([])
    assert event["templates"][0]["id"] == private.id
    text = json.dumps(event)
    for excluded in (
        "api_key_env",
        "headers",
        "metadata",
        "SYNTHETIC_TEMPLATE_API_KEY",
        "synthetic-template-credential",
        "synthetic-template-metadata",
    ):
        assert excluded not in text


def test_resolve_alias_and_alias_colon_model(model_store: tuple[Path, EnvFile]) -> None:
    store, env = model_store
    cloud(store, env, models=["model-one", "family:large"])
    profile, model = models.resolve_model("my-cloud")
    assert profile.id == "my-cloud" and model == "model-one"
    assert models.resolve_model("my-cloud:family:large")[1] == "family:large"
    with pytest.raises(ValueError):
        models.resolve_model("my-cloud:")
    with pytest.raises(ValueError):
        models.resolve_model("../outside")


def test_template_only_prefills(model_store: tuple[Path, EnvFile]) -> None:
    store, env = model_store
    entry = cloud(store, env, template="anthropic", protocol="openai_compatible")
    assert entry.protocol == "openai_compatible" and entry.base_url == "https://models.example/v1"
    saved = json.loads((store / "my-cloud.json").read_text())
    assert saved["headers"] == {} and saved["metadata"] == {}


def test_remove_deletes_profile_and_env_entry(model_store: tuple[Path, EnvFile]) -> None:
    store, env = model_store
    env.path.write_text("# keep comment\nOTHER=keep\n\n", encoding="utf-8")
    cloud(store, env)
    models.remove_model("my-cloud", store=store, env=env)
    assert not (store / "my-cloud.json").exists()
    assert env.path.read_text() == "# keep comment\nOTHER=keep\n\n"
    assert "DEVSEC_KEY_MY_CLOUD" not in os.environ
    assert models.list_models(store=store) == []


@pytest.mark.parametrize(
    "alias", ["../escape", "../a", "my_cloud", "UPPER", "", "a" * 33, "C:bad", "a/b"]
)
def test_bad_alias_rejected(model_store: tuple[Path, EnvFile], alias: str) -> None:
    store, env = model_store
    for action in (
        lambda: cloud(store, env, alias=alias),
        lambda: models.remove_model(alias, store=store, env=env),
        lambda: models.set_key(alias, "synthetic-new-key", store=store, env=env),
    ):
        with pytest.raises(ValueError):
            action()
    assert env.names() == []


@pytest.mark.parametrize("alias", ["a", "1"])
def test_plan_aliases_round_trip(model_store: tuple[Path, EnvFile], alias: str) -> None:
    store, env = model_store
    assert cloud(store, env, alias=alias).alias == alias
    assert models.resolve_model(alias)[0].id == alias


def test_set_key_replaces_live_key_preserving_other_lines(
    model_store: tuple[Path, EnvFile],
) -> None:
    store, env = model_store
    cloud(store, env)
    with env.path.open("a", encoding="utf-8") as stream:
        stream.write("# keep\nOTHER=unchanged\n")
    models.set_key("my-cloud", "synthetic-replacement", store=store, env=env)
    assert env.get("DEVSEC_KEY_MY_CLOUD") == "synthetic-replacement"
    assert os.environ["DEVSEC_KEY_MY_CLOUD"] == "synthetic-replacement"
    assert env.path.read_text().endswith("\n# keep\nOTHER=unchanged\n")


def test_duplicate_alias_does_not_replace_key(model_store: tuple[Path, EnvFile]) -> None:
    store, env = model_store
    cloud(store, env)
    with pytest.raises(ValueError):
        cloud(store, env, key="synthetic-replacement")
    assert env.get("DEVSEC_KEY_MY_CLOUD") == "synthetic-model-credential"


def test_key_namespace_collision_is_refused(model_store: tuple[Path, EnvFile]) -> None:
    store, env = model_store
    cloud(store, env, alias="other")
    path = store / "other.json"
    raw = json.loads(path.read_text())
    raw["api_key_env"] = "DEVSEC_KEY_MY_CLOUD"
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError):
        cloud(store, env)
    assert not (store / "my-cloud.json").exists()


def test_cannot_mutate_another_profiles_key(model_store: tuple[Path, EnvFile]) -> None:
    store, env = model_store
    cloud(store, env)
    path = store / "my-cloud.json"
    raw = json.loads(path.read_text())
    raw["api_key_env"] = "OTHER"
    path.write_text(json.dumps(raw))
    env.set("OTHER", "synthetic-other-key")
    with pytest.raises(ValueError):
        models.remove_model("my-cloud", store=store, env=env)
    with pytest.raises(ValueError):
        models.set_key("my-cloud", "synthetic-new-key", store=store, env=env)
    assert env.get("OTHER") == "synthetic-other-key" and path.exists()


def test_symlink_profile_is_not_followed(model_store: tuple[Path, EnvFile], tmp_path: Path) -> None:
    store, env = model_store
    store.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("untouched")
    try:
        (store / "my-cloud.json").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks not permitted")
    with pytest.raises(ValueError):
        cloud(store, env)
    with pytest.raises(ValueError):
        models.remove_model("my-cloud", store=store, env=env)
    assert outside.read_text() == "untouched"


@pytest.mark.parametrize("url", ["http://localhost.example/v1", "https://cloud.example/v1"])
def test_template_metadata_cannot_make_cloud_local(
    model_store: tuple[Path, EnvFile], url: str
) -> None:
    store, env = model_store
    with pytest.raises(ValueError, match="key"):
        cloud(store, env, template="ollama", base_url=url, key=None)


@pytest.mark.parametrize("key", ["one\nOTHER=injected", "one\rOTHER=injected", "one\x00two"])
def test_key_control_characters_are_refused(model_store: tuple[Path, EnvFile], key: str) -> None:
    store, env = model_store
    with pytest.raises(ValueError) as caught:
        cloud(store, env, key=key)
    assert key not in str(caught.value) and "DEVSEC_KEY_" not in str(caught.value)
    assert env.names() == []


def test_key_storage_errors_are_generic(
    model_store: tuple[Path, EnvFile], monkeypatch: pytest.MonkeyPatch
) -> None:
    store, env = model_store

    def broken(*args: object, **kwargs: object) -> None:
        raise OSError("DEVSEC_KEY_MY_CLOUD synthetic-model-credential")

    monkeypatch.setattr(env, "set", broken)
    with pytest.raises(ValueError) as caught:
        cloud(store, env)
    assert "synthetic-model-credential" not in str(caught.value)
    assert "DEVSEC_KEY_" not in str(caught.value)


def test_missing_key_is_listed_but_cloud_resolution_is_refused(
    model_store: tuple[Path, EnvFile],
) -> None:
    store, env = model_store
    cloud(store, env)
    env.remove("DEVSEC_KEY_MY_CLOUD")
    assert models.list_models(store=store)[0].key_set is False
    with pytest.raises(ValueError, match="key missing"):
        models.resolve_model("my-cloud")


def test_orphan_key_is_not_overwritten(model_store: tuple[Path, EnvFile]) -> None:
    store, env = model_store
    env.set("DEVSEC_KEY_MY_CLOUD", "synthetic-existing")
    with pytest.raises(ValueError):
        cloud(store, env)
    assert env.get("DEVSEC_KEY_MY_CLOUD") == "synthetic-existing"


def test_malformed_profile_never_logs_its_contents(
    model_store: tuple[Path, EnvFile],
    caplog: pytest.LogCaptureFixture,
) -> None:
    store, _env = model_store
    store.mkdir()
    (store / "other.json").write_text('{"key":"synthetic-bad-profile"}')
    with pytest.raises(ValueError) as caught:
        models.list_models(store=store)
    assert "synthetic-bad-profile" not in str(caught.value) + caplog.text


@pytest.mark.parametrize("operation", ["add", "list", "remove", "key", "resolve"])
def test_env_failures_never_echo_values_or_names(
    model_store: tuple[Path, EnvFile],
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    store, env = model_store
    if operation != "add":
        cloud(store, env)

    def broken(*args: object, **kwargs: object) -> None:
        raise ValueError("DEVSEC_KEY_MY_CLOUD synthetic-storage-failure")

    monkeypatch.setattr(env, "_read_lines", broken)
    monkeypatch.setattr(env, "is_configured", broken)
    actions = {
        "add": lambda: cloud(store, env),
        "list": lambda: models.list_models(store=store),
        "remove": lambda: models.remove_model("my-cloud", store=store, env=env),
        "key": lambda: models.set_key("my-cloud", "synthetic-next", store=store, env=env),
        "resolve": lambda: models.resolve_model("my-cloud"),
    }
    with pytest.raises(ValueError) as caught:
        actions[operation]()
    assert "synthetic-storage-failure" not in str(caught.value)
    assert "DEVSEC_KEY_" not in str(caught.value)


def test_env_remove_preserves_unrelated_lines_and_duplicate_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DELETE", raising=False)
    env = EnvFile(tmp_path / "synthetic.keys")
    env.path.write_text("# keep\nDELETE=one\nOTHER=two\nDELETE = three\n\n", encoding="utf-8")
    assert env.remove("DELETE")
    assert env.path.read_text() == "# keep\nOTHER=two\n\n"
    assert not env.remove("DELETE")
