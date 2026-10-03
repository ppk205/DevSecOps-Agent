# Native migration verification

Validated on Windows with Python 3.11.15 and the workspace Go 1.27.1 SDK.
Rechecked against the current source on 2026-10-02 before committing to GitHub.

## Responsiveness

| Scenario | Measurement | Target |
| --- | --- | --- |
| Navigation, state update and view construction with a 200-row page representing 10,000 findings | p95 1.006 ms | under 100 ms |
| SQLite filtering and fetching a 200-row page among 10,000 evidence-bearing findings | p95 62.663 ms | under 250 ms |

These headless measurements exclude terminal rendering. An earlier interactive
PTY smoke test verified startup, setup navigation, typing and clean quit; that
interactive check was not repeated in the current verification.
The old Python implementation rebuilt every row; its 10,000-row synthetic
rebuild took approximately 333 ms before database and terminal costs. The new
bound comes from pagination and moving I/O out of UI updates.

## Functional and compatibility checks

- The complete offline Python suite passed: 283 tests, 73% aggregate Python
  coverage and one dependency deprecation warning from Starlette's HTTPX test
  client. Python coverage does not include the separate native/worker processes.
- Go vet, formatting and an uncached `go test -count=1 -v ./...` run passed.
- After rebuilding the native binary from the current source, all 12 targeted
  native parity, cancellation, dashboard, model-runtime and training-data checks
  passed.
- Native fixture scans matched Python finding identities, severities, policy,
  coverage, stage order and retry history.
- Native cancellation stopped a deliberately slow scanner, retained partial
  findings/reports and rejected another process attempting the same database.
- Native HTTP tests passed existing routes, CSRF checks, status updates,
  projection refresh and JSON/SARIF/HTML/Markdown exports.
- Python navigation remained responsive during an intentionally blocked history
  read. Native tests covered stale responses, cursor preservation, empty
  filters, clipboard input and keyboard navigation.
- Laya tests verified genuine batch calls, exact bounded input hashes,
  redaction, process deadlines and cancellation without downloading a model.
- Dataset tests required independent review and kept projects/families in one
  split. Notebook Python cells were syntax-checked.
- Ruff checked all application, test and CI source; all 167 checked files were
  formatted. Strict mypy passed for 105 application source files.
- Offline dependency-lock validation and installed dependency compatibility
  checks passed. Wheel/source build and a fresh wheel installation with
  hash-pinned runtime dependencies passed, including entrypoint and asset checks.
- Native binaries cross-compiled for Linux amd64/arm64, macOS amd64/arm64 and
  Windows amd64. CI defines native runtime checks on all three operating systems.

## Repository hygiene

- `.gitignore` excludes the local `JVA-bookstore` checkout, compiler SDK,
  dependency/build caches, native binaries, SQLite sidecars, private environment
  files, credential files, model weights and notebook checkpoints. Environment
  examples, scanner test fixtures and the training notebook remain eligible for
  version control. No currently tracked files match the ignore rules.
- The local `essay/` thesis documents and diagrams are excluded from the commit
  and ignored at the user's request.
- A local pattern check of 250 text/document files found no matches for private
  keys or common GitHub, AWS, OpenAI and Hugging Face credential formats. This
  limited check is not a full security audit. No candidate file exceeded 10 MiB.
- All five notebook code cells parsed successfully and had no saved execution
  outputs. The remote `main` branch was fetched before preparing the commit.

## Execution limits

Real scanner binaries were unavailable in the local terminal smoke environment.
Scanner/container behavior uses the existing Python implementations, with the
existing real fast/full integration jobs retained in CI. Linux/macOS binaries
were cross-compiled here; their runtime checks are configured in CI.

Laya/PyTorch weights were not loaded and GPU training was not run. The training
notebook is ready for independently reviewed data and a GPU session. Historical
RTX 3050 results are not represented as measurements of the current GTX 1650.

SRS trace: FR-70/71, DR-09 and IR-15/16 drove parity and lifecycle checks;
QR-21 drove responsiveness/cancellation; QR-05/12/17 drove Laya provenance,
redaction and independent dataset checks.
