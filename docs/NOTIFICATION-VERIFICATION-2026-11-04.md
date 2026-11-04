# Notification verification — 2026-11-04

Scope: SRS section 3 FR-75, SQLite integrity under DR-01, credential boundaries
and keyboard/layout requirements under QR-21. This record describes the working
tree on `my_tool_call`; it is not a release certification.

## Implemented behavior

Python ScanService and native deterministic completion reach the shared outbound
service after scan results are retained. Telegram Bot API and Discord incoming
webhooks send one selected digest per destination. The ledger keeps delivery
status separate from scan/finding status, claims sends atomically, and requires
an explicit retry after failure or uncertain acknowledgement. Reading settings,
opening feeds and saving preferences do not send messages.

CLI configuration asks which events to send. Both terminal interfaces expose F6
settings and F7 retained delivery review. The dashboard bell exposes matching
preferences and run-ID delivery lookup. Manual drafts begin with no send choices
selected. Requested provider-unavailable stages are recognized even when a saved
profile exists; an unresolved assessment alone is not an AI failure.

The owner selected automatic delivery to both channels for completed/failed
scans, failed gates, High/Critical findings, AI failures/unavailability and
report-ready notices. These rules were saved to the local, gitignored
`.devsec-notifications.json`. Installation defaults remain disabled. No secret
values were requested or read for this setup, and no live message was sent.
Credentials still come from the configured EnvFile/process references.

## Executed checks

All logs are new files under
[`evidence/notifications-2026-11-04`](../evidence/notifications-2026-11-04/).

| Check | Result and evidence |
| --- | --- |
| Final focused Python regression set | 56 passed: `last-focused.log`; notification tests plus existing web notification, model RPC, native AI and migration boundaries |
| Whole Python suite | 760 passed, 15 failed, 191 setup errors, 1 skipped: `pytest-final.log` |
| Whole Ruff lint | Passed: `last-ruff.log` |
| Whole Ruff formatting | 13 existing files require formatting: `last-format.log` |
| Formatting for affected Python files | 25 files passed: `format-notification-files.log` |
| Whole mypy | Four existing errors in three files: `last-mypy.log` |
| Notification modules, CLI and Textual mypy | Seven files passed for each of linux/darwin/win32: `mypy-notifications-*.log` |
| `go vet ./...`, `go test ./...` | Failed on existing `artifacts/tui-verification/native_probe_test.go`: `go-vet.log`, `go-test.log` |
| Go application packages (`./cmd/... ./internal/...`) | Vet and tests passed: `go-vet-packages.log`, `go-test-packages.log` |
| Dashboard tests | 77 passed across 19 files: `web-test.log` |
| Dashboard type check and production build | Passed: `web-lint.log`, `web-build.log` |
| Native build | `ci/build_native.py` built Windows amd64, Linux amd64/arm64 and macOS amd64/arm64; default and versioned Windows EXEs match |
| Native runtime boundary | Actual Windows EXE → JSONL → ledger → real channel payload construction with synthetic HTTP acknowledgements |
| Native CLI forwarding | Both Windows EXEs returned reference-only notification settings from an isolated project path containing spaces |

Native asset names, hashes and forwarding results are in
`native-build-and-forwarding.json`. The full-suite failure-name comparison with
the earlier native-AI verification has no added or removed failures; see
`baseline-comparison.json`. Scanner startup errors still affect Java, JS/TS,
PHP and Python rule fixtures. Existing failures also include fix verification,
native report parity/dashboard rendering, incomplete adapter fixtures and
dependent UI workflows. These are not passing checks.

Mypy errors remain in `core/stdio_worker.py` (`CREATE_NO_WINDOW` twice),
`decisions/model_worker.py` (optional torch stubs) and `scanners/osv_adapter.py`
(Any return). The whole Go command also discovers an artifact probe with
undefined test helpers. Those unrelated files were preserved.

## Regression evidence and limits

Tests were added before implementation and failed on missing modules/commands,
unsupported JSONL dispatch and absent HTTP routes. The EXE completion test first
found zero deliveries against the previous binary and passed after rebuilding.
Additional failing controls established that ANSI sanitization, malformed
acknowledgements, pasted-URL validation and explicit-profile unavailability needed
correction; the final focused run passes those cases.

The last whole-suite run preceded the final provider-unavailable classifier
control. That small change was verified afterward in the final 56-test focused
set and whole lint/mypy checks. Full-suite results above are the actual retained
run, not an inferred clean result for every check.

Regression tests isolate operator preferences and replace HTTP responses, so
they cannot send to saved user destinations. Native fixture children explicitly
disable operator rules unless the dedicated notification test supplies them.
Tests verify missing credentials, API rejection, uncertain delivery, explicit
retry, concurrent sends, CSRF, safe error messages and status isolation. They
do not establish actual bot permissions, remote webhook validity, live service
availability or notification arrival in Telegram/Discord.

Native layout checks include 80x24, 75x26 and the minimum-size fallback.
Linux/macOS builds and type checks are not runtime verification on those OSes.
No live provider calls, source uploads, model downloads or full target scans were
performed for notification verification. No dependencies, essays, commits,
history or previous evidence were changed.
