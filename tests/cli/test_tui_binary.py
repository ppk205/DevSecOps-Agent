"""Chat needs the native binary even when baseline compute selects Python."""

from vulnscan.core import native


def test_required_tui_binary_ignores_compute_preference(monkeypatch):
    monkeypatch.setenv("DEVSECOPS_NATIVE", "python")
    monkeypatch.setenv("DEVSECOPS_GO_BINARY", "chat-binary")
    monkeypatch.setattr(native.shutil, "which", lambda name: "/native/" + name)
    assert native.binary_path() is None
    assert native.binary_path(required=True) == "/native/chat-binary"
