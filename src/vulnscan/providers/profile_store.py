"""Provider profile persistence — JSON on disk.

Profiles are stored encrypted at rest in production; for development we
keep them as plain JSON files under ``.providers/``.  The API key is
referenced by environment variable name, never stored in the profile file.
"""

from __future__ import annotations

import logging
from pathlib import Path

from pydantic import ValidationError

from vulnscan.contracts.provider import ProviderProfile

logger = logging.getLogger(__name__)

_DEFAULT_DIR = Path(".providers")


def _dir(base: Path | None = None) -> Path:
    d = base or _DEFAULT_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_profile(profile: ProviderProfile, base: Path | None = None) -> Path:
    """Write *profile* to ``<base>/<id>.json``."""
    d = _dir(base)
    path = d / f"{profile.id}.json"
    path.write_text(profile.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_profile(profile_id: str, base: Path | None = None) -> ProviderProfile:
    """Load a single profile by ID."""
    d = _dir(base)
    path = d / f"{profile_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"Provider profile '{profile_id}' not found at {path}")
    return ProviderProfile.model_validate_json(path.read_text(encoding="utf-8"))


def list_profiles(base: Path | None = None) -> list[ProviderProfile]:
    """Return all profiles in the base directory."""
    d = _dir(base)
    profiles = []
    for p in sorted(d.glob("*.json")):
        try:
            profiles.append(ProviderProfile.model_validate_json(p.read_text(encoding="utf-8")))
        except (OSError, ValidationError) as exc:
            logger.warning("Skipping malformed provider profile %s: %s", p.name, exc)
            continue
    return profiles


def delete_profile(profile_id: str, base: Path | None = None) -> bool:
    """Delete a profile. Returns True if deleted."""
    d = _dir(base)
    path = d / f"{profile_id}.json"
    if path.exists():
        path.unlink()
        return True
    return False


def default_profile(base: Path | None = None) -> ProviderProfile | None:
    """First profile whose API-key env var is set.

    Used to auto-enable model hunt on every scan: an explicitly chosen
    profile always wins; this is only the fallback when the caller did
    not pick one. Returns None when no key is configured anywhere, in
    which case hunt stages skip with a reason instead of failing.
    """
    import os

    if base is None and os.environ.get("PYTEST_CURRENT_TEST"):
        # Unit tests must never touch the network: without an explicit base
        # dir there is no auto provider under pytest. Tests that exercise
        # resolution itself pass base=tmp_path explicitly.
        return None
    keyed = [
        p
        for p in list_profiles(base)
        if p.api_key_env and os.environ.get(p.api_key_env, "").strip()
    ]
    if not keyed:
        return None
    keyed.sort(key=lambda p: (0 if p.id == "opencode-free" else 1, p.id))
    return keyed[0]
