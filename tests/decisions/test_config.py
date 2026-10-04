from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnscan.decisions import config as config_module
from vulnscan.decisions.config import LayaConfig, load_config

REPO_CONFIG = Path(__file__).resolve().parents[2] / "config" / "laya.json"


def test_defaults_are_disabled_and_advisory() -> None:
    config = LayaConfig()

    config.validate()

    assert config.enabled is False
    assert config.mode == "shadow"
    assert config.affects_finding_status is False


def test_qr18_optional_torch_is_not_required_for_default_configuration(mocker) -> None:
    load = mocker.patch.object(config_module.importlib, "import_module", side_effect=ImportError)
    LayaConfig().validate()
    load.assert_not_called()
    assert config_module._import_torch() is False
    assert config_module._torch_cuda_ok() is False
    with pytest.raises(ValueError, match="CUDA|cuda"):
        LayaConfig(device="cuda").validate()


def test_qr18_cuda_configuration_uses_optional_module_loading(mocker) -> None:
    torch = mocker.Mock()
    torch.cuda.is_available.return_value = True
    load = mocker.patch.object(config_module.importlib, "import_module", return_value=torch)
    LayaConfig(device="cuda").validate()
    assert all(call.args == ("torch",) for call in load.call_args_list)


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
