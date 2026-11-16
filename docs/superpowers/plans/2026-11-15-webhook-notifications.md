# Outbound Webhook Notifications Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one opt-in, signed, summary-only generic HTTP webhook destination to the existing shared scan notification service.

**Architecture:** Extend the current settings/event/claim/receipt flow with channel `webhook`; retain Telegram/Discord behavior and the existing notification RPC/HTTP actions. A focused standard-library HTTPS transport validates and pins the destination before sending signed retained bytes. Retire the separate legacy webhook-on-feed-read path through an explicit documented migration.

**Tech Stack:** Existing Python 3.11+, Pydantic, SQLAlchemy/SQLite, `json`, `hmac`, `hashlib`, `ssl`, `socket`, `http.client`, Typer, Textual, React/TypeScript and Go/Bubble Tea; version-1 owned JSONL. No new dependency and no inbound webhook listener.

**Spec:** [Proposed remediation and webhook design](../specs/2026-11-15-remediation-webhook-design.md), outbound webhook sections and `P-WEB-01`/`P-WEB-02` only. This plan can ship independently of the remediation plan.

## Global Constraints

- Python requires 3.11 or later. Preserve the existing locked dependencies; add no dependencies, provider SDKs or agent frameworks.
- Keep the hand-written agent loop, provider profiles and `src/vulnscan/providers/client.py`; no model-callable write, shell, network, notification or publication tools.
- Preserve `IndependentValidator`, human review, finding status, CVSS, coverage and policy-gate ownership.
- Preserve pristine targets, source-path confinement, credential exclusions and sanitized persistence/display boundaries.
- Provider use, patch application and external PR publication are separate explicit operator actions; none follows from saving credentials or reading a page.
- Offline verification uses fakes, synthetic HTTP and explicit `mode="deterministic"`, `laya=False`, `ai_review=False`, `ai_report=False`; no paid calls, source uploads, model downloads or live notifications.
- Preserve Python CLI/Textual, Go CLI/Bubble Tea and local dashboards; retain localhost, CSRF, cancellation, bounded layouts and version-1 JSONL with its 8 MiB limit.
- Go remains on the locked modules in `go.mod`/`go.sum`; use `-mod=readonly` and do not fetch modules or install dependencies silently.
- This is planning only. Do not implement, commit, push, tag, open a PR or change history under this authorization.
- Do not modify essays, existing evidence or unrelated working-tree changes.

There are no repository commit steps in this plan. A later implementation approval does not authorize commits or live webhook sends unless the owner includes them explicitly. Normal product use may select automatic delivery only after reviewing an enabled destination and its event rules.

## Review Focus

- Existing `WEBHOOK_URL` plus a feed refresh currently sends: the new release must remove that network side effect without losing local feed entries; Task 4 pins it.
- Host validation passes, then DNS changes or contains mixed private/public answers: every answer must pass policy and the actual socket must use the validated IP with original TLS hostname; Task 2 pins it.
- Environment proxies, 307/308 redirects or URL errors expose destination credentials: bypass proxies, follow no redirects, keep URLs out of diagnostics; Task 2 pins it.
- Concurrent completion/send, restart or a lost HTTP acknowledgement causes duplicate delivery: one persistent claim, retained exact bytes/ID and no automatic retry; Task 3 pins it.
- Version-1 settings or typed Go/React round trips erase the new channel: explicitly migrate settings and preserve every field/client default; Tasks 1 and 5 pin it.

---

## Baseline and file structure

`NotificationSettings` currently has schema version 1 with Telegram/Discord, both disabled and no events by default. `offer_run`, `send_selected`, `deliveries`, `notify_finished` and `handle` in `notifications/service.py` own delivery. `NotificationDeliveryORM` has unique `(run_id, channel)` and `pending/sending/sent/failed/unknown/unconfigured` states; conditional SQL claims already prevent duplicate concurrent sends. Preserve that boundary rather than building a second queue, scheduler or generalized integration framework.

The separate `web/app.py::_maybe_dispatch_webhook` is currently invoked during local gate-failure feed insertion, including lazy insertion from `GET /api/notifications`. Its retirement is an intentional compatibility proposal. FR-75 currently names Telegram/Discord, so generic webhook support needs an accepted FR-75 update; it is not already specified as shipped.

| File | Responsibility |
| --- | --- |
| Modify `src/vulnscan/notifications/settings.py`, `events.py` | Version-2 settings/reference validation and strict summary envelope builder. |
| Create `src/vulnscan/notifications/webhook.py` | HTTPS destination validation, DNS pinning, HMAC and bounded transmission returning existing `DeliveryResult`. |
| Modify `src/vulnscan/notifications/service.py` | Add webhook channel to offering, selection, persistent claims, frozen body and retries. |
| Modify `src/vulnscan/storage/models.py`, `database.py` | Add nullable delivery metadata through additive migration 9. |
| Modify `src/vulnscan/web/app.py`, `src/vulnscan/core/rpc.py`, `src/vulnscan/cli/notifications.py`, `src/vulnscan/tui/notifications.py` | Remove legacy sends; expose normal webhook settings/selection and retain read-only GET behavior; allow only the named outbound template. |
| Modify `internal/service/notifications.go`, `internal/tui/notifications.go`, `internal/dashboard/server.go`, `src/vulnscan/web/templates/base.html`; create `src/vulnscan/web/templates/outbound.html` | Typed native round trips, F6/F7 controls and native dashboard settings/review forms through the same service. |
| Modify `web-ui/src/api/types.ts`, `web-ui/src/api/client.ts`, `web-ui/src/components/OutboundNotifications.tsx`, `web-ui/src/components/__tests__/outbound.test.tsx` | Webhook host/reference configuration, selected events, receipts and explicit retry consent through the existing endpoints. |
| Tests listed per task below | Settings migration, exact HMAC, actual connection parameters, atomic claims and real owned-child completion. |
| Modify `docs/SRS.md`, `docs/NOTIFICATIONS.md`, `docs/TEST-PLAN.md`, `docs/NATIVE-MIGRATION.md`, `docs/IMPLEMENTATION-PLAN.md`, `README.md`, `CHANGELOG.md`, `AGENTS.md` | Accepted generic webhook contract, legacy migration, limitations and offline verification scope. |

All implementation paths above are future work. Only the requested planning documents are written now.

### Task 1: Version settings and define the retained summary envelope

**Files:** Modify `src/vulnscan/notifications/settings.py`, `events.py`, `tests/notifications/test_settings_events.py`; create `tests/notifications/test_webhook_settings.py`, `test_webhook_payload.py`.

**Interfaces:** Add `WebhookSettings(_Channel)` with `url_env: str="DEVSEC_WEBHOOK_URL"`, `signing_key_env: str="DEVSEC_WEBHOOK_SIGNING_SECRET"`, `allowed_hosts: list[str]=[]`; inherit `enabled=False`, `events=[]`. Validate references using the existing environment-reference regex and sanitized generic errors. Version-2 `NotificationSettings` adds `webhook` and keeps existing `mode`/Telegram/Discord fields. `load_settings` accepts v1/v2; v1 is normalized to v2 in memory with webhook off; `save_settings` writes v2 atomically. A payload with no schema version retains existing partial-update/default acceptance through explicit normalization; reject unsupported versions.

Produce `build_webhook_body(run_id: str, scan_status: str, events: Sequence[Mapping[str, str]], delivery_id: str) -> bytes` in `events.py`. Allow only existing `NotificationKind` values, selected sanitized messages and the five envelope keys `schema_version`, `delivery_id`, `run_id`, `scan_status`, `events`. Serialize exact compact sorted JSON, UTF-8, `ensure_ascii=False`; reject output exceeding 16 KiB rather than truncating JSON. Run identity and messages retain current bounds; do not accept arbitrary scan result dictionaries as payloads.

- [ ] **Step 1: Add failing settings/payload tests.**

  ```python
  # test_v1_upgrades_without_enabling_webhook
  assert cfg.schema_version == 2
  assert cfg.webhook.enabled is False and cfg.webhook.events == []
  # test_default_references_and_no_host_are_off
  assert cfg.webhook.url_env == "DEVSEC_WEBHOOK_URL"
  assert cfg.webhook.signing_key_env == "DEVSEC_WEBHOOK_SIGNING_SECRET"
  assert cfg.webhook.allowed_hosts == []
  # test_envelope_has_only_selected_summary_fields
  assert set(json.loads(body)) == {
      "schema_version", "delivery_id", "run_id", "scan_status", "events"
  }
  assert json.loads(body)["schema_version"] == 1
  assert len(body) <= 16384
  ```

  Round-trip v1 enabled Telegram/Discord settings with identical references/events/mode. Reject enabled webhook without an exact host, raw URLs pasted into reference fields, wildcard/control-character hosts and schema version 3. Verify generic errors never echo pasted credentials. Use hostile messages containing HTML/script/control characters and synthetic secret markers; output uses existing sanitization and never copies source/path/diff/transcript fields from the input event mapping. Test Unicode deterministic bytes and the exact 16 KiB boundary.
- [ ] **Step 2: Run `.venv\Scripts\python.exe -m pytest -q tests/notifications/test_settings_events.py tests/notifications/test_webhook_settings.py tests/notifications/test_webhook_payload.py`.** Expect missing model/builder and version/envelope failures before implementation.
- [ ] **Step 3: Implement in-memory migration, strict settings and envelope construction.** Preserve atomic `os.replace` saving. Normalize hosts to lowercase IDNA with trailing dots removed, then validate exact DNS names; deduplicate events/hosts. Keep disabled/missing-host defaults usable. No setting load/save may load credentials, resolve DNS or send. Builder code takes only retained offered event records and copies whitelisted fields; use `sanitize`/`redact` before producing bytes.
- [ ] **Step 4: Run the same tests.** Confirm a plain existing settings save does not require a webhook and never alters Telegram/Discord configuration.

### Task 2: Implement signed HTTPS delivery with pinned destination validation

**Files:** Create `src/vulnscan/notifications/webhook.py`, `tests/notifications/test_webhook_transport.py`; preserve existing `notifications/transports.py` and its `DeliveryResult` contract.

**Interfaces:** Produce `send_webhook(body: bytes, *, delivery_id: str, url_env: str="DEVSEC_WEBHOOK_URL", signing_key_env: str="DEVSEC_WEBHOOK_SIGNING_SECRET", allowed_hosts: Sequence[str], timeout: float=5.0) -> DeliveryResult`. It reads effective environment values after the service's existing `EnvFile.load_into_environ`; it never writes credential storage. Use a private immutable destination structure for normalized hostname, pinned public IP, port and path/query; secret path/query must have `repr=False` and stay out of errors. `DeliveryResult.status` remains `sent/failed/unknown/unconfigured`.

- [ ] **Step 1: Add failing transport tests with fake DNS/sockets/TLS and no external network.** Verify HMAC against an independently computed test vector with frozen timestamp `1700000000`: exact bytes `b"1700000000." + body`, `sha256=<hexdigest>`, delivery ID header, JSON content type and user agent. A 31-byte signing secret is unconfigured and makes no socket; a 32-byte secret works. Capture actual socket target and TLS `server_hostname`; DNS returning an allowed public address once and a private address on a hypothetical second resolution must still produce exactly one lookup and a socket to the first validated IP.

  Parameterize blocked HTTP/non-443, userinfo/fragment/control characters, literal IPv4/IPv6, mismatched/wildcard host, loopback, RFC1918, metadata/link-local, IPv6 unique-local, multicast, reserved, IPv4-mapped private IPv6, empty DNS and mixed public/private results. Assert zero POST bytes for every policy rejection. Set synthetic environment proxy variables and assert they are unused. For 301/302/307/308, assert one request and no redirect. Test 200/202/204 as HTTP-acknowledged only, 400/401/429/500 as failed without retry, oversized response capped at 64 KiB, timeout/broken connection as unknown. Never echo raw URL, query, signing key or response body in captured logs/receipts.
- [ ] **Step 2: Run `.venv\Scripts\python.exe -m pytest -q tests/notifications/test_webhook_transport.py`.** Expect missing transport, then signature/network-policy assertions failing until implemented. Do not use fixtures that bypass the actual URL/DNS/connect code under test.
- [ ] **Step 3: Implement the focused transport.** Use stdlib `urllib.parse`, `ipaddress`, `socket.getaddrinfo`, `ssl.create_default_context` and `http.client.HTTPSConnection`. Require port 443 and exact allowed host; validate every returned address, including mapped IPv4. Connect the socket directly to one checked IP and wrap TLS with the original hostname/SNI; never hand the hostname to an HTTP layer that resolves it again. No environment proxy, redirect handler, shell or arbitrary custom headers. Sign the retained bytes with current timestamp and a secret of at least 32 UTF-8 bytes; do not persist the signature/key. Bound socket operations to five seconds and response reads to 65,537 bytes before rejecting over 65,536; close responses/connections on every path. A returned 2xx is an HTTP acknowledgement; socket/ack uncertainty is `unknown`. Document OS DNS resolution can exceed the socket timeout; no end-to-end deadline is promised.
- [ ] **Step 4: Run the new tests and `.venv\Scripts\python.exe -m pytest -q tests/notifications/test_transports.py`.** Telegram/Discord payload/acknowledgement semantics must remain unchanged. Do not replace their existing credential-safe `urllib` transport or add a new HTTP dependency.

### Task 3: Extend the existing ledger and claims without retrying uncertainty

**Files:** Modify `src/vulnscan/notifications/service.py`, `src/vulnscan/storage/models.py`, `database.py`, `tests/notifications/test_service.py`; create `tests/notifications/test_webhook_service.py`, `test_webhook_migration.py`.

**Interfaces:** Preserve `offer_run(db_path, run_id)`, `send_selected(db_path, run_id, event_kinds, channels, *, retry=False)`, `deliveries`, `notify_finished` and `handle` signatures/old response fields. Add recognized channel `webhook`; selection remains explicit event/channel arrays. Add nullable `NotificationDeliveryORM.delivery_key` (UUID), `payload_json` (canonical envelope text) and `destination_fingerprint` (digest) using additive migration 9; old Telegram/Discord rows stay unchanged. Unique `(run_id, channel)` remains sufficient because one generic webhook destination is supported. Migration 9 must apply with or without remediation migration 8.

`destination_fingerprint` hashes effective URL, URL/signing variable names and exact normalized allowed-host list; no secret value is stored. Record it when a configured draft is offered, then check it again on send/retry. An unconfigured draft with no effective URL may retain a null fingerprint; an explicit send/retry after configuration binds it before any network attempt. A configured draft's destination change blocks sending instead of silently redirecting that digest. Key rotation through the same signing-key reference is allowed; body/delivery ID remain stable.

- [ ] **Step 1: Add failing migration and service tests.** Upgrade a DB with old delivery rows and no remediation tables, retain counts/status/events and run migration twice. Assert disabled webhook does not load credentials or resolve DNS. A manual offer creates one pending webhook digest, zero requests and a retained UUID; automatic completion sends one configured selection. Race two actual SQL sessions and assert exactly one claimed POST. Test repeated completion/read/save/restart does not resend. Freeze exact body/selected events at first claim and assert a retry preserves them and the UUID while refreshing only signing timestamp. A changed event selection, full URL/ref/host fingerprint or foreign run is rejected before network. Missing credentials yield unconfigured; after explicit correction with initially null fingerprint, retry can bind the destination. A timeout is unknown, no automatic retry, explicit `retry=True` required; existing sending/sent rows are not claimable. Finding JSON, run status/gate/exit code are unchanged for every outcome.
- [ ] **Step 2: Run `.venv\Scripts\python.exe -m pytest -q tests/notifications/test_service.py tests/notifications/test_webhook_service.py tests/notifications/test_webhook_migration.py`.** Record failures proving the absent channel/metadata and unsafe retry behavior before implementation.
- [ ] **Step 3: Extend the existing offer/send branches and conditional SQL claims.** Reuse the current per-run/channel transaction pattern. Store UUID and destination fingerprint at offer where configured; construct/freeze the final selected body in the winning send transaction before making HTTP. Persist `selected_events_json` and `payload_json` together with the transition to `sending`; failed/unknown retries must use that retained selection/body. Keep the current public receipt fields and add only nonsecret `delivery_id` for webhook inspection. Do not include raw envelope bytes, full destination, signing headers or keys in general receipts. Redacted generic failure messages remain separate from scan results. Never create drafts from GET/settings actions; completion remains the sole offer entry.
- [ ] **Step 4: Run all notification service/migration tests with existing transports.** Check real concurrent sessions and reopened databases, not only a mocked `rowcount`. A stopped process leaves `sending` uncertain; no lease expiry reclaims it automatically.

### Task 4: Retire legacy feed sends and expose webhook through existing operator APIs

**Files:** Modify `src/vulnscan/web/app.py`, `src/vulnscan/cli/notifications.py`, `tests/web/test_notifications.py`, `tests/notifications/test_interfaces.py`; create `tests/notifications/test_webhook_interfaces.py`.

**Interfaces:** Reuse `GET/POST /api/outbound/settings`, `GET/POST /api/scans/{run_id}/outbound`, owned JSONL method `notification` (`settings/save/deliveries/send/complete`) and `notifications configure/settings/review/send`. `--channels webhook` adds a channel, not a new command. Existing native CLI forwarding already invokes the Python notification commands. `core/rpc.py` dispatch remains the same; test its actual `ServiceRPC.dispatch` path.

- [ ] **Step 1: Add the direct failing GET regression first.** Set a synthetic legacy `WEBHOOK_URL`, arrange a retained gate-failed run, capture `urllib.request.urlopen` and every new webhook sender, then call `GET /api/notifications` twice. Assert the same local feed entries/unread count are retained and network call count is exactly zero. The existing `test_webhook_called_on_gate_fail` currently expects the opposite; replace that compatibility expectation explicitly. Also test outbound/settings/receipt GET and settings POST never send/create old drafts, even with automatic mode configured. POST sends require CSRF, offered events and channel `webhook`. CLI configuration chooses hosts/events/references without asking for URL/secret values; `notifications send ... --channels webhook` delegates to the shared service. JSONL rejects raw URLs pasted in references without echoing them.
- [ ] **Step 2: Run `.venv\Scripts\python.exe -m pytest -q tests/web/test_notifications.py tests/notifications/test_interfaces.py tests/notifications/test_webhook_interfaces.py`.** Observe the old GET network side effect failing before removing it.
- [ ] **Step 3: Remove `_maybe_dispatch_webhook` and its invocation from `record_scan_notification`.** Preserve local feed creation/acknowledgement and diff download behavior. Update CLI channel choices/help and add exact-host/reference prompts to configuration; keep credentials in the existing masked `env set` mechanism. Validation errors expose neither raw input nor remote response bodies. A legacy env variable alone sends nothing. Settings may explicitly choose `url_env="WEBHOOK_URL"` only with signing reference, allowlist, events and enablement; saving that migration still sends nothing and never replays old runs.
- [ ] **Step 4: Run those checks and all existing notification interface tests.** Confirm raw legacy webhook requests are impossible from feed reads and old Telegram/Discord selection commands keep working.

### Task 5: Extend React, Textual and native controls with honest receipts

**Files:** Modify `web-ui/src/api/types.ts`, `web-ui/src/api/client.ts`, `web-ui/src/components/OutboundNotifications.tsx`, `web-ui/src/components/__tests__/outbound.test.tsx`, `src/vulnscan/tui/notifications.py`, `tests/notifications/test_textual.py`, `src/vulnscan/core/rpc.py`, `internal/service/notifications.go`, `internal/tui/notifications.go`, `internal/tui/notifications_test.go`, `internal/dashboard/server.go`, `src/vulnscan/web/templates/base.html`; create `src/vulnscan/web/templates/outbound.html`, `tests/notifications/test_webhook_clients.py`; extend `tests/platform/test_native_dashboard.py`.

**Interfaces:** Add `Webhook` to Go `NotificationSettings` and extend `NotificationChannel` with `URLEnv`, `SigningKeyEnv`, `AllowedHosts` JSON fields; preserve old fields. Add Go receipt `SelectedEvents []string` and optional `DeliveryID string` so explicit retries preserve selection. Add schema version 2/webhook reference/host fields to `OutboundSettings` and optional receipt delivery ID. Extend React `sendOutbound(runId: string, events: string[], channels: string[], retry: boolean=false)` to submit `retry: true` only after explicit retry consent; existing three-argument callers remain valid. F6/F7 clients enumerate three explicit channel configs; preserve webhook fields when saving unrelated Telegram/Discord toggles. Native dashboard adds `GET/POST /outbound/settings`, `GET /runs/{id}/outbound` and `POST /runs/{id}/outbound`, delegating through `Backend.Notification`; do not create a second transport in Go. The existing local CSRF middleware protects new POST forms and templates are escaped through the owned Python renderer's allowlist, so add only `outbound.html` to that explicit allowlist in `src/vulnscan/core/rpc.py`.

- [ ] **Step 1: Add failing client tests.** Round-trip a complete v2 config through React/Go typed structures, saving a different channel without losing webhook host/reference fields. New installations show all destinations disabled and no events selected. Enabling webhook without a host shows a reference/host error; no raw URL/signing-key input exists in these forms. Show signature requirement, summary-only scope, HTTP acknowledgement meaning, no automatic retry and duplicate risk for an explicit unknown retry. Open/close/save/load dialogs cause zero sends. Keyboard-only interaction must work at 80x24, 75x26 and minimum size; native Up/Down focus, Left/Right choices and reader scrolling remain usable. Native dashboard GET/form rendering does not send; POST without CSRF fails.
- [ ] **Step 2: Run `npm --prefix web-ui test -- src/components/__tests__/outbound.test.tsx`, `.venv\Scripts\python.exe -m pytest -q tests/notifications/test_textual.py tests/notifications/test_webhook_clients.py tests/platform/test_native_dashboard.py` and `go test -mod=readonly ./internal/tui ./internal/service ./internal/dashboard`.** Expect absent channel/UI/round-trip cases to fail.
- [ ] **Step 3: Implement thin controls and forms.** Rename the existing “Telegram / Discord” opening button to “Outbound notifications”; render Webhook next to the existing channels. Expose enabled/events, exact hosts and reference names only, directing actual secrets to masked Keys/`env set`. Use existing background workers for delivery; keep unknown/sending receipts visible on reload and require an explicit duplicate-risk acknowledgement before an unknown retry. Normal send buttons never set `retry=True`. Native forms and React/Textual show no URL or signature. Add the native dashboard template to `render_page`'s explicit allowlist without permitting arbitrary template paths.
- [ ] **Step 4: Run the same tests, then `npm --prefix web-ui run lint` and `npm --prefix web-ui run build`.** No package install or lockfile change is permitted. Report unavailable installed tools rather than fetching them.

### Task 6: Prove native completion parity and document the accepted contract

**Files:** Modify `tests/platform/notification_rpc_fixture.py`, `tests/notifications/test_native_completion.py`, documentation targets from the file map and `tests/notifications/test_webhook_clients.py` for the new allowed RPC template. Do not change scan modes/defaults or create live webhook evidence.

**Interfaces:** Preserve `Backend.Notification`, the existing native completion `complete` RPC action and normal Python `notify_finished` calls. Extend the dedicated child fixture so it patches DNS/socket/TLS at the webhook transport boundary inside the owned Python child, using synthetic credentials/settings under the temporary database directory. Leave real envelope/signature/claim code running. Neither this fixture nor parent-only monkeypatching establishes live delivery permissions.

- [ ] **Step 1: Add the failing real-native parity regression.** Build a model-free synthetic scan with automatic selected events for Telegram, Discord and Webhook. Assert the native executable/owned Python child persists exactly one webhook receipt and the expected frozen envelope/signature, with no source/path/secret payload fields. Rerun completion/GET/restart and assert no additional POST. Exercise a synthetic unknown webhook response and confirm completed scan/gate/exit code remain unchanged. Also verify Python completion uses the same envelope field/event contract. Keep all settings/EnvFile behavior isolated from the owner's files in both parent and child.
- [ ] **Step 2: Build `.venv\Scripts\python.exe ci/build_native.py --go .tools/go/bin/go.exe`, then run `.venv\Scripts\python.exe -m pytest -q tests/notifications/test_native_completion.py`.** A missing binary is a blocker to this task's proof, not a reason to count a skipped integration test as passed. Use PATH `go` when available; do not install/fetch modules.
- [ ] **Step 3: Extend the child fixture and native tests to exercise the actual shared completion path.** Persist real claims, body bytes and receipts through SQLite. Substitute only synthetic low-level network results; no live endpoint, DNS lookup or source upload occurs. Do not add test fixture behavior to application defaults or change native deterministic/Python Hunt defaults.
- [ ] **Step 4: Update accepted documentation.** Extend FR-75/C-01 as needed and trace `P-WEB-01/02` to that accepted change; reference FR-67/68/71/75 and QR-01/05/06/07/12/13/14/15/16/20/21 in tests/docstrings. Update `docs/NOTIFICATIONS.md` with exact env references, schema migration, seven existing events, HMAC bytes/headers/300-second receiver guidance, public HTTPS/port/host/DNS rules, socket-timeout limitation and HTTP-only acknowledgement. Explain `WEBHOOK_URL` opt-in migration and removal of GET sends. Update `docs/TEST-PLAN.md`, `docs/NATIVE-MIGRATION.md`, `docs/IMPLEMENTATION-PLAN.md`, `README.md`, `CHANGELOG.md` under `Unreleased`, and `AGENTS.md` where current descriptions changed. Do not describe an inbound listener, generic retry queue, private-network support or PR notification events as implemented.
- [ ] **Step 5: Run and read the mandatory Python checks.**

  ```powershell
  .venv\Scripts\python.exe -m ruff check src tests ci
  .venv\Scripts\python.exe -m ruff format --check src tests ci
  .venv\Scripts\python.exe -m mypy src/vulnscan
  .venv\Scripts\python.exe -m pytest -q
  ```

  On Linux/macOS use the configured `.venv/bin/python` or `.venv-linux/bin/python`. These are future implementation gates; runtime checks are not needed for the present plan-only change.
- [ ] **Step 6: Run and read changed native/frontend gates and real child tests.**

  ```powershell
  $env:GOFLAGS = '-mod=readonly'
  $env:GOPROXY = 'off'
  go vet ./...
  go test ./...
  .venv\Scripts\python.exe ci/build_native.py --go .tools/go/bin/go.exe
  .venv\Scripts\python.exe -m pytest -q tests/notifications/ tests/platform/test_native_dashboard.py
  npm --prefix web-ui test
  npm --prefix web-ui run lint
  npm --prefix web-ui run build
  ```

  Use `.tools/go/bin/go.exe` for vet/test if PATH lacks Go, then restore the test invocation's changed environment variables without printing the environment. Report locked modules/tooling unavailable rather than silently fetching them. Record OS actually run; cross-compilation does not prove another OS runtime.
- [ ] **Step 7: Review final diff and acceptance evidence.** Verify single shared outbound service, no model tool additions, disabled defaults, read-only GETs, retained atomic claims and uncertain states, no changes to finding/run/gate status, no secrets in settings/receipts, and no evidence/essay/unrelated edits. Live receiver delivery, private endpoints and inbound triggers remain untested/unsupported. A full target scan is unnecessary for this feature's offline gate; any live send needs separate owner authorization.

## Planning self-review

All planned integration points match inspected source: `notification` already dispatches to `handle`, native completion already uses it, Go settings are typed, React/Textual hardcode two channel names today, and the legacy feed send exists separately. Tasks 1–3 implement the settings/envelope/network/ledger design; Task 4 removes the conflicting legacy behavior; Tasks 5–6 cover all supported clients, docs and mandatory checks. The plan intentionally keeps one destination and the current seven events. No implementation, live send or commit occurred; runtime checks were not run.
