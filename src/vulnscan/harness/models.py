"""Human-managed model aliases; credentials are stored only through EnvFile."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from vulnscan.contracts.enums import ProviderProtocol
from vulnscan.contracts.provider import ProviderProfile
from vulnscan.core.model_consent import is_local_base_url
from vulnscan.infra.envfile import EnvFile
from vulnscan.providers.credentials import redact_value
from vulnscan.providers.profile_store import delete_profile, load_profile, save_profile

from .providers import BUILTIN_PROFILES

_ALIAS = re.compile(r"[a-z0-9-]{1,32}")
_PROTOCOLS = {
    ProviderProtocol.OPENAI_COMPATIBLE,
    ProviderProtocol.OPENAI_CHAT_COMPLETIONS,
    ProviderProtocol.ANTHROPIC_MESSAGES,
}


@dataclass(frozen=True)
class ModelEntry:
    """Public model information: only a boolean describes the credential."""

    alias: str
    protocol: str
    base_url: str
    models: list[str]
    default_model: str
    local: bool
    key_set: bool


def _alias(alias: str) -> None:
    if not isinstance(alias, str) or _ALIAS.fullmatch(alias) is None:
        raise ValueError("Invalid model alias; use 1–32 lowercase letters, digits or dashes")


def _key_name(alias: str) -> str:
    _alias(alias)
    return "DEVSEC_KEY_" + alias.upper().replace("-", "_")


def _profile_path(alias: str, store: Path) -> Path:
    """Constrain profile-store calls before they can read, write or unlink."""
    try:
        if store.is_symlink():
            raise ValueError("Unsafe model store")
        path = store / f"{alias}.json"
        if path.is_symlink() or path.resolve().parent != store.resolve():
            raise ValueError("Unsafe model profile path")
    except OSError:
        raise ValueError("Cannot access model profile") from None
    return path


def _profiles(store: Path) -> list[ProviderProfile]:
    try:
        result = []
        for path in sorted(store.glob("*.json")):
            _profile_path(path.stem, store)
            profile = load_profile(path.stem, store)
            if profile.id != path.stem:
                raise ValueError("Model alias does not match its profile")
            result.append(profile)
        return result
    except (OSError, ValueError):
        # Validation errors can contain the entire source profile, including keys.
        raise ValueError("Cannot read model profiles") from None


def _owned(alias: str, store: Path) -> ProviderProfile:
    name = _key_name(alias)
    _profile_path(alias, store)
    profiles = _profiles(store)
    profile = next((item for item in profiles if item.id == alias), None)
    if profile is None:
        raise ValueError("Unknown added model; use model add first")
    if profile.api_key_env != name:
        raise ValueError("Model credential ownership is invalid")
    _check_collision(alias, name, profiles)
    return profile


def _check_collision(alias: str, name: str, profiles: list[ProviderProfile]) -> None:
    if any(item.id != alias and item.api_key_env.upper() == name for item in profiles):
        raise ValueError("Model credential ownership conflicts with another profile")


def _public_text(value: str) -> bool:
    return (
        bool(value)
        and all(ord(char) >= 32 and ord(char) != 127 for char in value)
        and "DEVSEC_KEY_" not in value.upper()
    )


def _endpoint(base_url: str) -> str:
    if (
        not isinstance(base_url, str)
        or not _public_text(base_url)
        or any(char.isspace() for char in base_url)
    ):
        raise ValueError("Invalid model base URL")
    try:
        url = urlsplit(base_url)
        if (
            url.scheme not in {"http", "https"}
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.query
            or url.fragment
        ):
            raise ValueError
        _ = url.port
    except ValueError:
        raise ValueError(
            "Use an HTTP or HTTPS base URL without credentials, query or fragment"
        ) from None
    return base_url


def _model_ids(values: list[str]) -> list[str]:
    if not isinstance(values, list) or not values:
        raise ValueError("At least one model id is required")
    if any(
        not isinstance(item, str) or not _public_text(item) or any(char.isspace() for char in item)
        for item in values
    ):
        raise ValueError("Invalid model id")
    return list(dict.fromkeys(values))


def _key(key: str | None, *, required: bool) -> str:
    if key is not None and (
        not isinstance(key, str) or any(ord(char) < 32 or ord(char) == 127 for char in key)
    ):
        raise ValueError("Invalid model key")
    value = key.strip() if key else ""
    if required and not value:
        raise ValueError("A key is required for this model")
    return value


def _entry(profile: ProviderProfile, env: EnvFile) -> ModelEntry:
    base_url = _endpoint(profile.base_url)
    ids = _model_ids(profile.models)
    default = profile.default_model
    if default is None or default not in ids or profile.protocol not in _PROTOCOLS:
        raise ValueError("Invalid added model profile")
    try:
        key_set = env.is_configured(_key_name(profile.id))
    except (OSError, ValueError):
        raise ValueError("Cannot read model key status") from None
    return ModelEntry(
        profile.id,
        profile.protocol.value,
        base_url,
        ids,
        default,
        is_local_base_url(base_url),
        key_set,
    )


def add_model(
    alias: str,
    template: str | None,
    protocol: str,
    base_url: str,
    models: list[str],
    key: str | None,
    *,
    store: Path = Path(".providers"),
    env: EnvFile | None = None,
) -> ModelEntry:
    """Add an alias; templates prefill only protocol and endpoint."""
    name = _key_name(alias)
    try:
        path = _profile_path(alias, store)
        if path.exists():
            raise ValueError("Model alias already exists")
        profiles = _profiles(store)
        _check_collision(alias, name, profiles)
        source = BUILTIN_PROFILES.get(template) if template else None
        if template and source is None:
            raise ValueError("Unknown model template")
        try:
            wire = ProviderProtocol(protocol or (source.protocol.value if source else ""))
        except ValueError:
            raise ValueError("Unsupported model protocol") from None
        if wire not in _PROTOCOLS:
            raise ValueError("Unsupported model protocol")
        url = _endpoint(base_url or (source.base_url if source else ""))
        ids = _model_ids(models)
        value = _key(key, required=not is_local_base_url(url))
        if value and any(value in field for field in [alias, url, *ids]):
            raise ValueError("Credentials cannot be part of model details")
        try:
            credentials = env if env is not None else EnvFile()
            assigned = name in {
                item.upper() for item in credentials.names()
            } or credentials.is_configured(name)
        except (OSError, ValueError):
            raise ValueError("Cannot read model key status") from None
        if assigned:
            raise ValueError("Model credential is already assigned")
        try:
            profile = ProviderProfile(
                id=alias,
                label=alias,
                protocol=wire,
                base_url=url,
                api_key_env=name,
                models=ids,
                default_model=ids[0],
            )
        except ValueError:
            raise ValueError("Invalid added model profile") from None
        if value:
            try:
                credentials.set(name, value, update_environ=True)
            except (OSError, ValueError):
                raise ValueError("Cannot save model key") from None
        try:
            save_profile(profile, store)
        except (OSError, ValueError):
            if value:
                try:
                    credentials.remove(name)
                except (OSError, ValueError):
                    raise ValueError("Cannot save model profile or undo key storage") from None
            raise ValueError("Cannot save model profile") from None
        return _entry(profile, credentials)
    except OSError:
        raise ValueError("Cannot save added model") from None


def remove_model(
    alias: str, *, store: Path = Path(".providers"), env: EnvFile | None = None
) -> None:
    """Remove only the alias's profile and its generated credential."""
    profile = _owned(alias, store)
    try:
        credentials = env if env is not None else EnvFile()
        credentials.remove(profile.api_key_env)
        delete_profile(alias, store)
    except (OSError, ValueError):
        raise ValueError("Cannot remove added model") from None


def set_key(
    alias: str,
    key: str,
    *,
    store: Path = Path(".providers"),
    env: EnvFile | None = None,
) -> None:
    """Replace the saved and live key for one added model."""
    profile = _owned(alias, store)
    value = _key(key, required=True)
    if any(value in field for field in [alias, profile.base_url, *profile.models]):
        raise ValueError("Credentials cannot be part of model details")
    try:
        credentials = env if env is not None else EnvFile()
        credentials.set(profile.api_key_env, value, update_environ=True)
    except (OSError, ValueError):
        raise ValueError("Cannot save model key") from None


def list_models(*, store: Path = Path(".providers")) -> list[ModelEntry]:
    """List added models, excluding built-in templates and legacy profiles."""
    try:
        env = EnvFile()
        profiles = _profiles(store)
        entries = []
        for profile in profiles:
            if not profile.api_key_env.upper().startswith("DEVSEC_KEY_"):
                continue
            name = _key_name(profile.id)
            if profile.api_key_env != name:
                raise ValueError("Model credential ownership is invalid")
            _check_collision(profile.id, name, profiles)
            entries.append(_entry(profile, env))
        return entries
    except (OSError, ValueError):
        raise ValueError("Cannot list added models") from None


def resolve_model(spec: str) -> tuple[ProviderProfile, str]:
    """Resolve alias[:model-id]; an alias alone selects its saved default."""
    alias, separator, model = spec.partition(":")
    profile = _owned(alias, Path(".providers"))
    try:
        env = EnvFile()
        env.load_into_environ()
        entry = _entry(profile, env)
    except (OSError, ValueError):
        raise ValueError("Cannot load added model") from None
    if not entry.local and not entry.key_set:
        raise ValueError("Model key missing; use model key to set it")
    if separator:
        return profile, _model_ids([model])[0]
    return profile, entry.default_model


def models_event(entries: list[ModelEntry]) -> dict[str, Any]:
    """Build model items and public template prefills; the host adds the envelope."""
    templates = [
        {
            "id": profile.id,
            "label": profile.label,
            "protocol": profile.protocol.value,
            "base_url": profile.base_url,
            "models": list(profile.models),
            "default_model": profile.default_model,
        }
        for profile in BUILTIN_PROFILES.values()
    ]
    return cast(
        dict[str, Any],
        redact_value(
            {
                "type": "models",
                "items": [asdict(entry) for entry in entries],
                "templates": templates,
            }
        ),
    )
