"""Pending reviews only auto-start after consent, on an idle local session."""

import threading

import pytest

from tests.harness.conftest import make_ctx
from tests.harness.fakes import ScriptedTransport
from tests.harness.test_host import reply
from vulnscan.harness.host import SessionHost
from vulnscan.harness.pending import record_watch, store_path
from vulnscan.harness.providers import BUILTIN_PROFILES
from vulnscan.harness.session import Session


@pytest.mark.parametrize(
    "mode,cloud,attached,expected",
    [
        ("auto", False, True, True),
        ("ask", False, True, False),
        ("auto", True, True, False),
        ("auto", False, False, False),
    ],
)
def test_pending_autostart_requires_local_auto_and_client(
    tmp_path, mode, cloud, attached, expected
):
    ctx, _ = make_ctx(tmp_path, [], mode)
    transport = ScriptedTransport(
        [reply("done")], profile=BUILTIN_PROFILES["deepseek" if cloud else "ollama"]
    )
    host = SessionHost(Session(transport, ctx), lambda e: None)
    if attached:
        host.attach("tui", "tui")
    host.started = True
    record_watch(store_path(tmp_path, ctx.ws.target), ["A.java"])
    host.enable_pending(tmp_path)
    assert host.wait_idle(5)
    assert bool(transport.calls) is expected
    if expected:
        assert "propose_scan_plan limited to these files" in host.session.messages[0].content
    host.close()


def test_pending_waits_for_idle(tmp_path):
    entered, release = threading.Event(), threading.Event()

    class Blocking(ScriptedTransport):
        def complete(self, system, messages, tools):
            if not self.calls:
                entered.set()
                assert release.wait(5)
            return super().complete(system, messages, tools)

    ctx, _ = make_ctx(tmp_path, [], "auto")
    transport = Blocking([reply("first"), reply("review")])
    host = SessionHost(Session(transport, ctx), lambda e: None)
    host.attach("tui", "tui")
    host.started = True
    host.submit("first")
    assert entered.wait(5)
    record_watch(store_path(tmp_path, ctx.ws.target), ["A.java"])
    host.enable_pending(tmp_path)
    assert host.state()["pending_reviews"]
    release.set()
    assert host.wait_idle(5)
    # wait_idle means all auto-started work is idle as well.
    assert len(transport.calls) == 2
    host.close()
