import importlib.util
import io
import os
import zipfile
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("launch", Path(__file__).parents[2] / "ci/launch.py")
assert spec is not None and spec.loader is not None
launch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launch)


def test_stale_when_target_missing_or_older(tmp_path):
    source = tmp_path / "src" / "a.ts"
    source.parent.mkdir()
    source.write_text("x")
    target = tmp_path / "dist" / "index.html"
    assert launch.stale(target, source.parent)

    target.parent.mkdir()
    target.write_text("built")
    os.utime(source, (1, 1))
    assert not launch.stale(target, source.parent)

    os.utime(target, (0, 0))
    assert launch.stale(target, source.parent)


@pytest.mark.parametrize(
    ("platform", "machine", "asset"),
    [
        ("win32", "AMD64", "gitleaks_8.24.2_windows_x64.zip"),
        ("linux", "x86_64", "gitleaks_8.24.2_linux_x64.tar.gz"),
        ("linux", "aarch64", "gitleaks_8.24.2_linux_arm64.tar.gz"),
        ("darwin", "arm64", "gitleaks_8.24.2_darwin_arm64.tar.gz"),
        ("freebsd", "x86_64", None),
    ],
)
def test_gitleaks_asset_is_pinned_per_platform(platform, machine, asset):
    assert launch.gitleaks_asset(platform, machine) == asset
    if asset:
        assert len(launch.GITLEAKS_SHA256[asset]) == 64


def _fake_download(payload: bytes):
    def retrieve(url, path):
        Path(path).write_bytes(payload)

    return retrieve


def test_gitleaks_checksum_mismatch_installs_nothing(tmp_path, monkeypatch):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("gitleaks.exe", b"tampered")
    monkeypatch.setattr(launch.urllib.request, "urlretrieve", _fake_download(archive.getvalue()))

    with pytest.raises(ValueError, match="checksum"):
        launch.install_gitleaks(tmp_path, "gitleaks_8.24.2_windows_x64.zip")
    assert list(tmp_path.iterdir()) == []


def test_gitleaks_installs_verified_binary(tmp_path, monkeypatch):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("gitleaks.exe", b"binary")
    payload = archive.getvalue()
    asset = "gitleaks_8.24.2_windows_x64.zip"
    monkeypatch.setattr(launch.urllib.request, "urlretrieve", _fake_download(payload))
    monkeypatch.setitem(launch.GITLEAKS_SHA256, asset, launch.hashlib.sha256(payload).hexdigest())

    installed = launch.install_gitleaks(tmp_path, asset)

    assert installed == tmp_path / "gitleaks.exe"
    assert installed.read_bytes() == b"binary"
