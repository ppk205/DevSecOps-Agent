# Changelog

## Unreleased

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
