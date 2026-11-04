"""FR-75: native EXE completion reaches shared Telegram/Discord delivery."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.platform.test_scan_service import checkout
from vulnscan.notifications.service import deliveries
from vulnscan.notifications.settings import save_settings

__all__ = ["checkout"]
ROOT = Path(__file__).parents[2]
BINARY = ROOT / "bin" / ("devsecops-agent-go.exe" if os.name == "nt" else "devsecops-agent-go")


@pytest.mark.skipif(not BINARY.is_file(), reason="Build the native binary first")
def test_native_completion_sends_selected_events_with_real_channel_payloads(checkout, tmp_path):
    db = tmp_path / "notifications.db"
    save_settings(
        {
            "mode": "automatic",
            "telegram": {"enabled": True, "events": ["scan_completed"]},
            "discord": {"enabled": True, "events": ["report_ready"]},
        },
        base=tmp_path,
    )
    result = subprocess.run(
        [
            str(BINARY),
            "scan-run",
            "--checkout",
            str(checkout),
            "--db-path",
            str(db),
            "--out",
            str(tmp_path / "out"),
            "--json",
        ],
        cwd=ROOT,
        env={
            **os.environ,
            "DEVSECOPS_PYTHON": sys.executable,
            "DEVSECOPS_RPC_MODULE": "tests.platform.notification_rpc_fixture",
            "DEVSECOPS_FIXTURE_NATIVE_HUNT": "1",
            "DEVSEC_TELEGRAM_BOT_TOKEN": "123456:synthetic-token",
            "DEVSEC_TELEGRAM_CHAT_ID": "-100123456",
            "DEVSEC_DISCORD_WEBHOOK_SECRET": "https://discord.com/api/webhooks/123456/synthetic-token",
        },
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout[-2000:]
    summary = json.loads(result.stdout)
    rows = deliveries(str(db), summary["id"])["deliveries"]
    assert len(rows) == 2 and all(row["status"] == "sent" for row in rows)
    assert {row["channel"]: row["selected_events"] for row in rows} == {
        "telegram": ["scan_completed"],
        "discord": ["report_ready"],
    }
    assert "synthetic-token" not in result.stdout + result.stderr
