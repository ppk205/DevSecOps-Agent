# Telegram and Discord notifications

SRS FR-75 adds outbound scan digests. New installations disable both destinations
and select no events. Configuration is local to the project found from the
current directory, including its `bin` subdirectory. Outside a project, settings
and EnvFile use the caller's current directory.

## Setup

Use the existing masked secret prompt. Do not put real tokens or webhook URLs
in shell arguments, screenshots, reports or repository documents.

```powershell
bin/devsecops-agent-go.exe env set DEVSEC_TELEGRAM_BOT_TOKEN
bin/devsecops-agent-go.exe env set DEVSEC_TELEGRAM_CHAT_ID
bin/devsecops-agent-go.exe env set DEVSEC_DISCORD_WEBHOOK_SECRET
bin/devsecops-agent-go.exe notifications configure
```

The Python console command supports the same `env` and `notifications` commands.
On Linux/macOS omit `.exe`. Telegram requires a bot token and a chat the bot can
message. Store the entire Discord incoming-webhook URL in the third variable.
Process-injected values retain precedence over the project `.env` file.

`notifications configure` asks which destinations and events to enable, and
whether to send automatically or ask after each scan. Native and Python Textual
TUIs expose preferences with F6 and retained deliveries with F7. In the React
dashboard, open the bell and choose **Telegram / Discord**. The masked Keys page
stores credentials; the notification form stores event rules only.

Settings are saved atomically to the gitignored `.devsec-notifications.json`.
It contains event rules and variable references, never destination credentials.
Saving preferences sends nothing and does not flush historical drafts.

## Events and messages

| Event ID | Sent when selected and observed |
| --- | --- |
| `scan_completed` | The scan reaches completed status |
| `scan_failed` | The scan finishes failed, or an interrupted result is offered |
| `scan_cancelled` | The scan finishes cancelled |
| `gate_failed` | The retained policy gate is failed |
| `high_critical_findings` | Non-rejected findings have effective High/Critical severity |
| `ai_failed` | Requested model stages are unavailable/failed, or all recorded calls fail |
| `report_ready` | At least one report artifact was exported; message includes scan status |

One digest per destination contains only selected events that actually occurred.
It includes run identity, outcome, finding counts or available report formats.
It excludes repository paths, code, secret matches, diffs and model transcripts.
High/Critical findings still require evidence and status review.

Automatic mode sends saved event selections at completion. Manual mode retains
pending drafts and offers explicit selection in the TUI or interactive Python
CLI. Noninteractive/JSON CLI runs retain drafts without prompting. To review:

```powershell
bin/devsecops-agent-go.exe notifications review RUN_ID --db-path vulnscan.db
```

CLI automation can explicitly select a retained draft:

```powershell
bin/devsecops-agent-go.exe notifications send RUN_ID --events scan_completed,report_ready --channels telegram,discord --db-path vulnscan.db
```

The requested events must have been offered and still be allowed in settings.
The native CLI returns retained drafts in manual mode; use `notifications review`
or TUI F7 to choose them. Loading a web feed or delivery receipt sends nothing.

## Delivery status and recovery

The `notification_deliveries` table records one digest per run/channel. Reads and
concurrent sends cannot produce another copy after a claim. `sent` requires a
provider message acknowledgement. `failed` means an HTTP/API rejection;
`unconfigured` means missing or invalid destination configuration. `unknown`
means no acknowledgement, and the remote service may already have accepted it.
`sending` may remain after a process stops during delivery; inspect the remote
channel before taking further action. Pending drafts are available through F7,
CLI review or the web dialog's run-ID lookup.

No automatic retries are performed, including rate limits. After correcting a
failed or unconfigured destination, repeat the explicit `notifications send`
command with `--retry`. Retrying `unknown` can duplicate a remotely accepted
message. A `sending` record is deliberately not reclaimable automatically.
Delivery failures do not change findings, the policy gate or scan exit codes.
Receipts are stored separately from scan artifacts; read their current status
through the delivery interfaces rather than an old `summary.json` snapshot.

Messages are bounded to 1,800 characters. Each HTTP request uses a five-second
socket timeout. Redirects are disabled and destination credentials are omitted
from errors. Discord delivery suppresses mention parsing and requests a message
acknowledgement. Telegram sends plain text without link previews.

Telegram delivery uses the outgoing [Bot API sendMessage endpoint](https://core.telegram.org/bots/api#sendmessage),
which returns a Message on success. It does not register an inbound Telegram
webhook or require a public listener. Discord uses the
[Execute Webhook endpoint](https://docs.discord.com/developers/resources/webhook#execute-webhook)
with `wait=true`. The existing generic `WEBHOOK_URL` gate-failure integration
remains separate and keeps its legacy web-feed behavior.

## Interfaces and verification

- `GET/POST /api/outbound/settings`: read/save event preferences.
- `GET /api/scans/{run_id}/outbound`: retained receipts, with no delivery side effect.
- `POST /api/scans/{run_id}/outbound`: explicit `events` and `channels` arrays;
  optional `retry: true`. Existing localhost and CSRF restrictions apply.
- Owned JSONL `notification` method: `settings`, `save`, `deliveries`, `send` and
  trusted completion action `complete`. This is not a model tool.

Offline tests use synthetic credentials and HTTP responses. They cover actual
native EXE completion, persistence and channel payload construction. No live
Telegram/Discord delivery or remote bot/webhook permissions are established by
those tests. See [NOTIFICATION-VERIFICATION-2026-11-04.md](NOTIFICATION-VERIFICATION-2026-11-04.md)
for this checkout's executed checks and remaining baseline failures.
