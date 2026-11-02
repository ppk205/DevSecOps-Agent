# Changelog

## Unreleased

- Rebuild required CI checks around the current harness, locked dependency exports, full Python matrix, native platform suites, installed-package chat refusal and real baseline fixtures.
- Add a `CI required` aggregate check that rejects failed, skipped or cancelled prerequisite jobs, and retain harness/native JUnit and coverage on failure.
- Preserve installed extras with `uv run --no-sync`, test the wheel, Action and scanner image with the same offline chat smoke check, and select Python explicitly in release jobs.
- Select the exact current-version package archives and refresh official Action revisions to reviewed full commit SHAs across workflows, the composite Action and examples.

- Validate enumerated harness paths, including source-index inputs, and exclude credential files while preserving `.env.example`.
- Redact normal provider messages, tool output, console display, audit events and both report formats.
- Display the full fix diff before G6 and leave malformed JSON gate edits undecided.
- Require recorded Laya triage before opening investigation batches, including edited candidate lists.
- Resolve fix worktrees to absolute paths and re-scan the original candidate alongside changed files.
- Include applicable exact, path-prefix and extension filters and their authorization checks in route lookup.
- Refresh runtime, build and scanner requirements exports with the required `cvss==3.6` dependency.

- Add `devsec chat`, the hand-written AI harness: a provider layer with two transports (Anthropic Messages, OpenAI-compatible Chat Completions) and built-in profiles for Anthropic, OpenAI, OpenRouter, DeepSeek, Ollama and LM Studio, plus user profiles in `.providers/*.json`.
- Add a session loop with non-streaming tool calling, `/model` switching, budget checks, provider-error recovery and resume from the append-only `.devsec/sessions/*.jsonl` log.
- Add human permission gates G0–G7 with `ask` and `auto` modes: only G1–G4 and G7 may be approved automatically (logged as person `auto`), G0 and G6 always wait for a human, and G5 is never decided by code. No gate offers "always", and a closed or invalid prompt is `undecided`.
- Add the harness scan tools: file inventory, source–sink candidate extraction (14 rule families plus a missing-role-check route rule), route lookup, confined reads and grep. Third-party scanners stay as `scan-run` baselines.
- Run Laya triage on harness candidates before the model reads anything, with a new candidate-based input state; raise the shipped Laya timeout from 30 s to 300 s.
- Add the citation checker and CVSS v4.0 scoring through `cvss==3.6`; the harness verifies evidence and only a human sets a finding's status.
- Add fix proposals applied only to a `devsec/fix-<finding_id>` worktree branch after a human G6, and a G7 re-scan that reports whether the candidate is gone.
- Add finding-card reports (Markdown and JSON) with the gate decision log, and the console slash commands `/model`, `/mode`, `/cost`, `/review`, `/export`, `/resume`, `/clear`, `/quit`.

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
