# Changelog

## Unreleased

- Keep aggregate token totals unavailable when a run with model calls omits
  usage, instead of displaying a partial sum as the complete total.

- Show model token usage (requests, prompt, completion and total tokens) in
  Markdown, text, HTML and Word reports. Counts a provider did not report
  appear as unavailable, not zero.
- Remove cost and USD budget displays. Providers are bring-your-own-key with
  their own per-token prices. The Keys page shows token totals instead, and
  run summaries, benchmarks and the native TUI no longer carry cost fields.

- Start the installed Laya worker automatically at routing and show batch
  progress, the scan scenario, and outputs on the live dashboard.

- Bound the final-report model prompt and render the full scanner comparison
  locally.

- Load saved provider credentials and model defaults before dashboard scans.

- Add an AI benchmark comparison to Reports, including scanner coverage,
  measured time, request activity, and savings against the review baseline.
- Allow an optional provider request cap shared across all model stages and
  retries. Preserve finding evidence and distinguish unavailable prices.

- Select the Laya worker device automatically in CUDA, Vulkan and CPU order.
  Retain the actual device in routing results and fall back on GPU failures.

- Cache completed scanner tool results within a Hunt session and fall back to
  bundled Semgrep packs when a registry scan fails. Resolve Maven properties
  in OSV dependency inputs and group dependency advisories in model output.

- Restore the FR-72 scanner lists for the fast and full profiles and run them
  deterministically in CI. Show the built-in native-hunt adapter in the web
  scanner health list. Update the React build plugin for Vite 8.
- Run exact-rule Semgrep fix verification on private copies of the baseline and
  patched files. This preserves byte-level checks with the locked Semgrep CLI.
- Include the deterministic final Markdown narrative in native scan exports.
- Serve the registration form when the React bundle has not been built.

- Use Trivy in the full scanner profile and keep SpotBugs available for
  explicit legacy scans. Show backend scanner presets in the web form and
  preserve scanner-only findings through model Hunt and validation.

- Direct the Python web root to the React application, show notification
  settings in its navigation, and expose webhook event switches in the Go TUI.
  The native dashboard still uses the older server-rendered pages.

- Remove the legacy `WEBHOOK_URL` send triggered by reading the notification
  feed. Local feed entries remain available. Add an opt-in signed generic webhook
  through the shared notification service, CLI and web settings; terminal and
  native controls are pending.

- Add a source-backed codebase map and an interactive scan pipeline with explicit
  inputs and outputs. Add proposed implementation plans for fix suggestions with
  draft pull requests and shared outbound webhooks; these plans do not implement
  the features.

- The web UI New Scan form has an "Allow cloud model" switch, off by default.
  Off sends a deterministic scan with no model stages; on shows separate
  Model hunt, AI review and AI report switches plus the provider and model.
  The form also offers Laya routing, the gate's fail-on level, and now sends
  the pinned commit, which it collected but never sent. `POST /api/scans`
  accepts `ai_report`, `laya`, `fail_on` and `allow_cloud_model`;
  `allow_cloud_model: false` turns every model stage off on the server. Requests
  without these fields keep the earlier behavior, where Hunt also enabled AI
  review and AI report. This is a web form control, not a scan-wide consent
  mechanism: the CLI is unchanged.
- The web UI tool list (`/api/tools`) shows SpotBugs and Dependency-Check as
  available when Docker has the `devsecops-agent-scanners:0.2.0` image, since
  full-profile scans run them in that container. It listed them as missing
  whenever the host had no binaries on PATH.
- Model hunt now detects language families from every file name in the
  snapshot. It used the `list_files` tool, which refused more than 2000 files,
  so on BenchmarkPython (2505 files) and BenchmarkJava (5570) the language pass
  never ran and only the generic and logic passes did. Over 2000 matches,
  `list_files` now returns the first 200 paths with the total and per-directory
  counts, and `grep_code` searches the first 2000 files and marks the result
  truncated, instead of returning an error the model kept retrying.
- Retry provider calls that fail with HTTP 499, 502, 503 or 504, in addition to
  429, up to the profile's `max_retries`. 429 and 499 wait 30 s (or the
  `Retry-After` value); 502-504 back off 5 s per attempt. Other HTTP errors
  still fail at once. A gateway that dropped long calls left most AI review
  targets unresolved.

- Reject web UI provider IDs that break the profile contract (for example
  `deepseek_test`) with a 422 that names the allowed characters. Saving such an
  ID previously stored the key in `.env` and then failed with a 500. The web UI
  now shows the server's error detail instead of only the status code.

- Add `ci/launch.py`, which installs missing Python packages, web UI packages,
  the web UI build, the Go binary and a checksum-verified Gitleaks before
  launching the web UI, Go CLI or Python CLI.

- Add `provider-setup` for guided local model provider and key configuration.

- Run the Go, Ruby and C# native-hunt packs through `scan-run`. These files now
  join the scan inventory and report their own language. A vulnerable target in
  these languages previously ended with no native-hunt findings and a passed gate.
  Semgrep records these files as `unsupported` instead of `analyzed` because its
  bundled rules do not cover them.

- Correct independent-validation logic: exclude model/raw-scanner proposals
  from decision authority, separate counterevidence from support, scope records
  by finding/run, deduplicate identities, and keep conflicts, blocked/failed
  procedures and fixed-variant results from falsely confirming findings.
- Replace the incorrect CVSS formula with FIRST v4.0 MacroVector scoring and
  bundled reference tables. Validate metric order/values and eleven Base metrics;
  leave incomplete vectors unscored. Record Base and contextual scores separately
  and compute assessment numbers from vectors in both AI review paths. Preserve
  assumptions, score errors and validation provenance. Keep metric assumptions
  unverified and scanner severity unchanged by arithmetic alone.

- Add an OWASP Top 10:2025 to CWE cross-reference to HTML, Markdown, text, Word
  and final narrative reports, with matching JSON/SARIF metadata. Use bundled
  official category-specific CWE lists, preserve primary/secondary labels and
  finding status, and show unmapped labels and empty categories explicitly.
  Keep the section application-generated when the narrative comes from a model.
  Correct the duplicate CWE prefix in the deterministic final narrative.

- Add opt-in Telegram Bot API and Discord incoming-webhook digests at scan
  completion. Choose events and automatic/manual mode through `notifications
  configure`, native/Textual F6 settings or the dashboard bell. Manual delivery
  retains drafts for explicit selection. Keep credentials in EnvFile/process
  variables, messages summary-only, and delivery receipts separate from scan
  status. Prevent duplicate concurrent sends and require explicit retries for
  failed or uncertain deliveries. Add offline channel, CLI/API, TUI and EXE tests.

- Connect native Hunt/review/report settings to the Python AI pipeline. Add
  provider/model selection, effective-settings review, call/tool progress,
  retained finding explanations and reported token usage. Preserve AI settings
  on retry and keep native defaults deterministic. Missing providers and failed
  calls remain explicit; unknown usage and monetary cost remain unavailable.
- Preserve provider-returned explanation fields, tool-call IDs and selected
  models in investigation requests. Resolve profiles from the project root and
  refresh locally loaded saved keys while preserving process-environment
  precedence. Add offline EXE-to-provider-parser regression tests.

- Use arrow keys for native TUI navigation: Up/Down moves between controls,
  Left/Right switches views or cycles choices, and text fields keep cursor
  movement. Preserve reader scrolling and keep Tab as an optional shortcut.

- Resolve local paths, repository URLs and shorthand consistently in terminal,
  CLI and web source input. Keep explicit missing paths local, normalize quoted
  inputs and URL slashes, and reject invalid clone URLs without invoking Git.
  Local folders work without Git and record `no-revision`, revision limits and
  file hashes; commit pins and CI still require a verified revision. Preserve
  reviewed source identity in native scans and isolate clone caches by URL and
  origin. Add native `--workdir` support and optional web commit input.

- Fix direct native launches from `bin` and other working directories by
  discovering the application's Python environment relative to the executable.
  Support Windows, Linux/macOS and `.venv-linux` layouts, active environments
  and `python3` on PATH. Apply the same import-path cleanup to the Python
  service bridge and CLI forwarding.

- Kill the four honest limitations: OSV.dev CVE lookup replaces flaky NVD
  downloads (auto-fallback when the ODC binary is missing); CodeQL promoted
  from experimental stub to an opt-in DEEP step with SARIF parsing;
  notifications feed (bell + ack + gate-fail webhook) plus fix `.diff`
  download; targeted HTTP verification probes (reflected-XSS canary,
  SQL-error signatures, allowlist + request caps) as opt-in DAST evidence.
- Narrow secret redaction to key formats + loaded env values
  (`token.isEmpty()`, diff lines and JSON pass through).
- Python configuration runs model hunt by default (deterministic + model in one
  pass); without a provider key the hunt stages skip with a reason instead
  of failing. Pass `--mode deterministic` to opt out. Native defaults keep model
  stages disabled until Hunt or an AI option is selected.

- Scan any web language, not just Java: new Semgrep rulesets `javascript.yml` (JS/TS), `python.yml`, `php.yml` (10 rules each, two-direction fixtures, batched tests), `LanguageKind` extended + `language_from_extension` hub, inventory covers `.js/.ts/.py/.php/...`, default Semgrep load is every bundled `rules/*.yml`. Live-verified: CWE-78 JS, CWE-89 PY, CWE-79 PHP, safe code silent.

- Add `--mode hunt`: model-first pipeline where the model explores the snapshot with read-only tools (`hunt_vulns`), scanners run unchanged, Laya verifies each candidate (`laya_verification`), and `model_scanner_compare` buckets agreed/model-only/scanner-only; the AI lane focuses on agreed findings and `hunt.json` lands next to `final-report.md`. Default `deterministic` mode is byte-for-byte unchanged; without `--provider` hunt stages skip and the run falls back to deterministic.
- Verify hunted vulnerabilities with Laya: each model candidate becomes a `DecisionRequest` with a code excerpt, attaching `laya_route`/`laya_confidence`/`laya_status` — Laya unavailable degrades to `skipped`, never fails a run.
- Compare model vs scanner findings with a pure `(path, line±3, CWE-digits)` matcher and surface it in the final report via a `## Đối chiếu model vs scanner` section (prompt counts + deterministic fallback table).

- Wire the AI stages end to end: `scan-run --ai-review` sends Laya-routed findings through the bounded model loop with read-only snapshot tools, `IndependentValidator` owns every status change, and `--ai-report` produces an AI-written `final-report.md` per run (deterministic template fallback without a provider).
- Add single-shot verdict fallback for reasoning-only gateways that emit no tool calls: one bounded call with embedded evidence, parsed by a shared verdict parser.
- Add `provider-add` (BYOK profiles, key in env only), 429 retry with `Retry-After`, txt/docx exports from the same report source, and TUI toggles for the AI stages.
- Verified live on KiosAPI `beam-free`: 2/2 routed, 1 confirmed at 0.99, AI report written.

## 0.3.0

- Expand the Java ruleset from 3 to 13 rules (SQL concatenation, command execution, XSS taint, XXE, weak cryptography, insecure deserialization, security misconfiguration) with fixtures and regression tests.
- Add API key management to both terminals: Ctrl+K saves project credentials on the Workspace screen, the action menu elsewhere.
- Consolidate terminal scan configuration in Workspace with expandable advanced options, typed choices, an action menu and directory completion.
- Fix highlighted-run retry/export targeting, scrollable configuration review, stale review handling, retained failure messages and per-run historical activity in both TUIs.
- Present readable finding/source summaries with optional raw details; bound native layouts and show an explicit minimum-size message.
- Add keyboard-only acceptance tests for scan review, execution, evidence, exports and history, including terminal resizing.
- Add the native Go terminal, scan lifecycle, storage queries and local HTTP handlers, with Python compatibility helpers.
- Keep navigation responsive through paginated findings, background reads and stable selections.
- Fix Laya checkpoint loading, real batching, cancellation, input hashes, redaction and routing policy.
- Run the Laya pipeline on CPU: 4 GB VRAM cannot serve the forward pass; routing completes on CPU with recorded batch latency.
- Add independently reviewed training exports, a Kaggle notebook and held-out evaluation tools.
- Add native parity checks and platform binaries to the release workflow.
- Fix zero-finding scans launched from a plain shell: scanner binaries now resolve against the application venv instead of the caller's PATH, and test sources at any path depth are excluded from the scan inventory.
- Sanitize PYTHONPATH when the native launcher spawns the Python CLI, and ignore late TUI worker updates during shutdown.

## 0.2.0

- Add persistent shared scan execution, cancellation, attempt history and security gates.
- Add a keyboard-accessible Textual terminal interface with evidence inspection and exports.
- Add fast/full Ubuntu composite scanning Action and versioned Java rules.
- Require platform tests, strict typing, formatting, packaging and scanner fixture checks.
- Add manually selected, immutable GitHub releases with checksums.

## 0.1.0

- Initial deterministic scanner, advisory routing, evidence contracts and local dashboard.
