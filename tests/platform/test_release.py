"""FR-74: version agreement and immutable rerun identities."""

import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "release", Path(__file__).parents[2] / "ci/release.py"
)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def test_fr74_version_must_match_exactly():
    release.validate_version("0.2.0", "0.2.0")
    for requested in ["v0.2.0", "0.2", "0.2.1", "0.2.0;echo"]:
        with pytest.raises(ValueError):
            release.validate_version(requested, "0.2.0")


def test_fr74_reruns_only_accept_identical_existing_assets():
    release.compare_assets({"wheel": "abc", "source": "def"}, {"wheel": "abc"})
    with pytest.raises(ValueError, match="immutable"):
        release.compare_assets({"wheel": "abc"}, {"wheel": "changed"})
