# Changelog

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
