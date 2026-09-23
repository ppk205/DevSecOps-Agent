"""Provider profile persistence — JSON on disk.

Profiles are stored encrypted at rest in production; for development we
keep them as plain JSON files under ``.providers/``.  The API key is
referenced by environment variable name, never stored in the profile file.
"""

from __future__ import annotations

import json
from pathlib import Path

from vulnscan.contracts.provider import ProviderProfile


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
        except Exception:
            continue  # skip malformed
    return profiles


def delete_profile(profile_id: str, base: Path | None = None) -> bool:
    """Delete a profile. Returns True if deleted."""
    d = _dir(base)
    path = d / f"{profile_id}.json"
    if path.exists():
        path.unlink()
        return True
    return False
