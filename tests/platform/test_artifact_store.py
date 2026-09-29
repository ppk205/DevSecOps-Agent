"""Platform tests: content-addressed artifact store (T01 gate)."""

import hashlib
from pathlib import Path

import pytest

from vulnscan.core.artifact_store import ArtifactStore


def test_save_and_retrieve(tmp_path: Path):
    store = ArtifactStore(tmp_path / "artifacts")
    art = store.save_bytes(run_id=1, attempt=1, name="out.json", data=b'{"a":1}', kind="json")
    assert art.checksum == hashlib.sha256(b'{"a":1}').hexdigest()

    data = store.retrieve(run_id=1, attempt=1, checksum=art.checksum, name="out.json")
    assert data == b'{"a":1}'


def test_artifacts_identifiable_by_run_and_attempt(tmp_path: Path):
    store = ArtifactStore(tmp_path / "artifacts")
    a1 = store.save_bytes(run_id=10, attempt=1, name="a.txt", data=b"run10-attempt1")
    store.save_bytes(run_id=10, attempt=2, name="a.txt", data=b"run10-attempt2")
    store.save_bytes(run_id=11, attempt=1, name="a.txt", data=b"run11-attempt1")

    items_10 = store.list_by_run(10)
    assert len(items_10) == 2

    items_10_att1 = store.list_by_run(10, attempt=1)
    assert len(items_10_att1) == 1
    assert items_10_att1[0].checksum == a1.checksum


def test_different_content_not_overwritten(tmp_path: Path):
    """Same name, different content: stored under distinct checksums, original intact."""
    store = ArtifactStore(tmp_path / "artifacts")
    a1 = store.save_bytes(run_id=1, attempt=1, name="x.bin", data=b"aaa")
    a2 = store.save_bytes(run_id=1, attempt=1, name="x.bin", data=b"bbb")
    assert a1.checksum != a2.checksum

    # Original content is retrievable and unchanged.
    assert store.retrieve(1, 1, a1.checksum, "x.bin") == b"aaa"
    assert store.retrieve(1, 1, a2.checksum, "x.bin") == b"bbb"


def test_missing_artifact_raises(tmp_path: Path):
    store = ArtifactStore(tmp_path / "artifacts")
    with pytest.raises(FileNotFoundError):
        store.retrieve(run_id=999, attempt=1, checksum="a" * 64, name="nope.txt")
