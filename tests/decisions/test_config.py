from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnscan.decisions.config import LayaConfig, load_config

REPO_CONFIG = Path(__file__).resolve().parents[2] / "config" / "laya.json"


def test_defaults_are_disabled_and_advisory() -> None:
    config = LayaConfig()

    config.validate()

    assert config.enabled is False
    assert config.mode == "shadow"
    assert config.affects_finding_status is False


def test_repo_config_is_shipped_disabled() -> None:
    config = load_config(REPO_CONFIG)

    assert config.enabled is False
    assert config.affects_finding_status is False
    assert config.revision


def test_missing_file_returns_defaults() -> None:
    assert load_config(Path("does-not-exist.json")) == LayaConfig()


def test_status_authority_is_rejected() -> None:
    with pytest.raises(ValueError, match="never own finding status"):
        LayaConfig(affects_finding_status=True).validate()


def test_invalid_thresholds_are_rejected() -> None:
    with pytest.raises(ValueError, match="thresholds"):
        LayaConfig(high_confidence_threshold=0.2, review_threshold=0.9).validate()


def test_loaded_config_round_trips(tmp_path: Path) -> None:
    file = tmp_path / "laya.json"
    file.write_text(
        json.dumps(
            {
                "enabled": True,
                "mode": "advisory",
                "batch_size": 8,
                "max_input_tokens": 256,
                "review_threshold": 0.5,
                "high_confidence_threshold": 0.7,
            }
        ),
        encoding="utf-8",
    )

    config = load_config(file)

    assert config.enabled is True
    assert config.mode == "advisory"
    assert config.batch_size == 8
    assert config.max_input_tokens == 256
    assert config.review_threshold == 0.5
