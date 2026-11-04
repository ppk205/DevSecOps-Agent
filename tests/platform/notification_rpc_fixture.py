"""Exercise native completion with real delivery code and synthetic HTTP only."""

import sys
from pathlib import Path

from tests.platform import rpc_fixture
from vulnscan.notifications import service, transports
from vulnscan.notifications.settings import NotificationSettings, load_settings


def main():
    # A dedicated settings directory prevents reading the owner's preferences.
    db = Path(sys.argv[sys.argv.index("--db-path") + 1])
    service.load_settings = lambda: load_settings(base=db.parent)
    service.EnvFile.load_into_environ = lambda self: []

    def post(url, payload, timeout):
        if "api.telegram.org" in url:
            assert "chat_id" in payload and payload["text"].startswith("DevSecOps-Agent")
            return 200, {"ok": True, "result": {"message_id": 1}}
        assert payload["allowed_mentions"] == {"parse": []}
        assert "wait=true" in url
        return 200, {"id": "fixture-message"}

    transports._post_json = post
    # Ensure defaults remain off when this fixture is used without a saved file.
    assert isinstance(service.load_settings(), NotificationSettings)
    rpc_fixture.main(notification_settings=service.load_settings())


if __name__ == "__main__":
    main()
