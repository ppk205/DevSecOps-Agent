# Fix Suggestions and Draft Pull Requests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend existing fix suggestions into a source-pinned, human-reviewed overlay verification and separately approved GitHub draft PR workflow.

**Architecture:** Keep `ai/fix.py` as the provider/diff helper and move operator orchestration from web-only closures into one Python remediation service. Existing HTTP routes, CLI/Textual and the Go clients call that service; a dedicated trusted `httpx` transport publishes only the reviewed patched file through GitHub REST after approval. Finding status and independent validation remain separate.

**Tech Stack:** Existing Python 3.11+, Pydantic, SQLAlchemy/SQLite, `httpx`, Typer, Textual, React/TypeScript, Go/Bubble Tea and version-1 owned JSONL; installed Semgrep for supported mechanical verification. No new dependency.

**Spec:** [Proposed remediation and webhook design](../specs/2026-11-15-remediation-webhook-design.md), remediation sections and `P-REM-01` through `P-REM-03` only.

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

There are no repository commit steps in this plan. Implementation approval, if later granted, does not authorize a development commit or a real target PR unless the owner separately includes that action. The product's publication controls described here are future behavior, not permission to publish during development.

## Review Focus

- A valid rule moves to a different line after patching: verification must fail if it refires anywhere in the file; Task 1 pins this.
- Windows drive/UNC/alternate-stream paths and links escape naive `..` checks: reject them before reads/writes; Task 1 pins them.
- Source, diff or overlay changes after review, including legacy `verified` rows without provenance: block application/publication; Tasks 2 and 4 pin them.
- GitHub accepts a branch/PR but the response is lost: retain an uncertain receipt, never resend a write automatically, reconcile by read; Tasks 3 and 4 pin this.
- Cancel, double-click, concurrent clients or process restart occurs during a write: keep evidence, one publication claim and a visible incomplete outcome; Tasks 2, 4, 5 and 6 pin this.

---

## Baseline and file structure

The code already generates, lists, downloads and applies proposals through `src/vulnscan/web/app.py`; it has no PR transport or shared remediation RPC. `ai/fix.py::verify_fixed` is a narrow Semgrep helper, not an independent assessment validator. `FixProposalORM` stores latest state only. Do not import the absent chat harness or a `GateKeeper`.

| File | Responsibility |
| --- | --- |
| Modify `src/vulnscan/ai/fix.py` | Strict one-file parsing, source-safe overlay preparation, complete exact-rule verification and returned model usage metadata. |
| Create `src/vulnscan/contracts/remediation.py` | `ProposalProvenance`, `FixVerification`, `PRPreview` and `PublicationReceipt`; reference existing run/finding identities. |
| Create `src/vulnscan/remediation/__init__.py`, `service.py` | Shared operator actions, provenance, artifact attempts, atomic claims and public serialization. |
| Create `src/vulnscan/remediation/github.py` | Fixed-host REST transport and read-only reconciliation. |
| Modify `src/vulnscan/storage/models.py`, `database.py` | Add proposal provenance and append-only remediation attempt rows; additive migration 8. |
| Modify `src/vulnscan/web/app.py`, `src/vulnscan/core/rpc.py`, `src/vulnscan/cli/main.py`; create `src/vulnscan/cli/fixes.py` | Retain existing HTTP contracts; add preview/publish/receipt actions, JSONL and CLI group. |
| Modify `web-ui/src/components/FixProposals.tsx`, `web-ui/src/api/types.ts`, `web-ui/src/api/client.ts`, `web-ui/src/mock/mockClient.ts`, `web-ui/src/mock/mockPhase2.ts`, `web-ui/src/i18n/en.ts`, `web-ui/src/i18n/vi.ts` | Diff review, exact approval preview, honest result and receipt rendering with offline mocks. |
| Create `src/vulnscan/tui/remediation.py`, `internal/service/remediation.go`, `internal/tui/remediation.go`; modify `src/vulnscan/tui/app.py`, `internal/tui/app.go`, `internal/tui/view.go`, `internal/dashboard/server.go`, `src/vulnscan/web/templates/evidence.html` | Thin shared-service review controls for supported fallback/native clients. |
| Tests listed per task below | Offline regressions, real temporary files and real owned-child/native wiring. |
| Modify `README.md`, `CHANGELOG.md`, `docs/SRS.md`, `docs/IMPLEMENTATION-PLAN.md`, `docs/TEST-PLAN.md`, `docs/NATIVE-MIGRATION.md`, `AGENTS.md`; create `docs/REMEDIATION.md` | Accepted requirements, limits, settings, workflows and current feature status. |

Only these planning documents are written now. All paths in the table are future implementation targets. Keep each task scoped; no unrelated refactor of the large web/TUI files.

### Task 1: Make isolated application and its limited verification trustworthy

**Files:** Modify `src/vulnscan/ai/fix.py`; create `src/vulnscan/contracts/remediation.py`; modify `tests/ai/test_fix.py`; create `tests/ai/test_fix_boundaries.py` and `tests/ai/test_fix_verification.py`.

**Interfaces:** Preserve `propose_fix(finding, profile_id, model=None, max_tokens=2000, code_context="") -> FixProposal`, `apply_unified_diff(repo_root: Path, diff_text: str) -> list[str]`, `prepare_overlay(checkout: str, file_path: str, overlay_root: Path) -> Path` and `verify_fixed(overlay: Path, file_path: str, rule_id: str, line: int | None, semgrep_bin: str="semgrep") -> dict[str, Any]`. Add keyword-only `budget: BudgetManager | None=None` to `propose_fix`, `expected_sha256: str | None=None` to overlay preparation and `baseline: Path | None=None` to verification; the service must supply recorded source/baseline. Existing positional callers continue to work but a missing reproducible baseline returns `fixed=False`, `outcome="incomplete"`. Extend the existing `FixProposal` dataclass with optional returned `usage: dict[str, int]` and actual profile/returned model metadata. Reuse `providers/budget.py::BudgetManager` rather than adding a cost subsystem; missing pricing/cost stays unavailable per FR-49's recorded implementation limit.

`FixVerification` fields: `fixed: bool`, `detail: str`, `outcome: Literal["passed","failed","unavailable","cancelled","incomplete"]`, `rule_id: str`, `tool_version: str | None`, `baseline_artifact: str | None`, `patched_artifact: str | None`, `baseline_sha256: str | None`, `patched_sha256: str | None`, `attempt_id: int | None`. No independent-validator metadata or finding status belongs here. Exact rule matching preserves the bundled rule's identity; it must not use an arbitrary suffix match that collides with another rule.

- [ ] **Step 1: Add the smallest failing boundary and verification tests.** Use actual temporary files for patching and synthetic `CommandResult` data for process outcomes. Pin these cases by name/assertion:

  ```python
  # test_refire_after_line_shift_is_not_fixed
  assert result["fixed"] is False and result["outcome"] == "failed"
  # test_error_json_or_skipped_target_is_incomplete (exit codes 0, 1, 2, 7)
  assert result["fixed"] is False
  # test_baseline_must_reproduce_exact_rule
  assert result["outcome"] == "incomplete"
  # test_complete_baseline_and_clean_patch_pass
  assert result["fixed"] is True and result["outcome"] == "passed"
  # test_pristine_file_bytes_survive_apply_and_failure
  assert original.read_bytes() == before
  ```

  Parameterize rejected paths for `../`, absolute POSIX, drive-relative `C:foo`, drive-absolute, UNC, backslashes, alternate streams, symlink parents, same source/overlay root and credential files. Reject multiple headers, add/delete/rename/binary hunks, overlapping hunks, wrong hunk counts, malformed context, diffs over 256 KiB and files over 1 MiB before any write. Add CRLF/BOM preservation and fake-secret rejection controls. Unsupported rule, missing Semgrep, non-JSON, no analyzed file and cancellation never return `fixed=True`. Fake provider tests preserve returned usage/model identity and prove a supplied exhausted budget prevents HTTP without inventing a monetary estimate.
- [ ] **Step 2: Run `.venv\Scripts\python.exe -m pytest -q tests/ai/test_fix.py tests/ai/test_fix_boundaries.py tests/ai/test_fix_verification.py`.** Record assertion failures demonstrating the old unsafe success/path behavior. Missing fixtures/imports alone do not prove the behavior regression.
- [ ] **Step 3: Implement strict preflight and complete verification.** Reuse safe confinement and credential exclusion semantics from `core/scan_service.py::checkout_manifest`; do not weaken that function. Parse/validate the entire diff before writing. Resolve every source/destination component without following links, verify the recorded hash, write only under a newly created attempt root, and preserve byte encoding/newlines. Pass a supplied budget, or the existing default `BudgetManager`, into `ProviderClient` and retain actual returned usage/model metadata. Use `scanners/process.py::run_command` and its cooperative cancellation instead of raw `subprocess.run`. Retain the `line` parameter for compatibility but match exact-rule results across the complete file. Require baseline/patched completion and target coverage; keep old `fixed/detail` keys with richer outcomes. Sanitized tool artifacts remain append-only under the attempt root.
- [ ] **Step 4: Run the same targeted tests.** Require all positive/negative controls to pass. Update the existing real-Semgrep round-trip test to supply its baseline; retain that installed-tool integration check and report unavailable Semgrep honestly instead of substituting a fake for it.

### Task 2: Extract one source-pinned remediation service and retain attempts

**Files:** Create `src/vulnscan/remediation/__init__.py`, `service.py`, `tests/remediation/test_service.py`, `test_migrations.py`; modify `src/vulnscan/contracts/remediation.py`, `src/vulnscan/storage/models.py`, `database.py`.

**Interfaces:** Produce `handle(service: ScanService, params: dict[str, Any], *, cancel: threading.Event | None=None) -> dict[str, Any]` in `remediation/service.py`. Initial actions are `propose`, `list`, `download`, `apply`, `attempts`. Later tasks add PR actions without a second finding schema. Resolve numeric/public run IDs through `ScanService.resolve_id`; use `detail`'s `spec`/`result` and shared `Finding` contracts. Read effective configuration from `spec.metadata.configuration`, as `ScanConfig.specification` writes it, and derive artifacts from its `output_dir` (legacy fallback `artifacts`); reject an artifact root overlapping the pristine checkout. Never accept a client-provided arbitrary source/artifact path. The current web `_fix_provider` looks for top-level `configuration`; do not preserve that mistaken lookup when extracting it.

`ProposalProvenance` records run/finding identity, profile/model, revision, file path, source/diff SHA-256 and returned usage (missing usage stays unavailable). Add `FixProposalORM.provenance_json` default `{}`. Create `RemediationAttemptORM` with `id`, `proposal_id`, `kind` (`apply`/`publish`), `state`, `request_json`, `result_json`, `created_at`, `updated_at`. Completed attempts are immutable; retries append a new row. A partial unique index prevents two active `apply` attempts per proposal; publication exclusion is added in Task 4. Migration 8 adds only these fields/table/index and is idempotent on old databases. It must apply without webhook migration 9.

- [ ] **Step 1: Add failing shared-service and migration tests.** Assert a proposal records the original manifest hash, actual fake provider identity and an immutable diff; generation/list/download never apply or publish. Include a real `ScanConfig.specification` fixture whose provider/output settings exist only in `metadata.configuration`; the shared service must resolve them correctly. Missing manifest, foreign finding, changed checkout and secret-bearing output yield sanitized failures and zero model calls where preflight fails. `apply` requires a scoped immutable proposal; a provided `reviewed_diff_sha256` must match. Two concurrent apply calls stage at most one active attempt; a failed/cancelled retry creates a new directory and retains earlier artifacts. Snapshot hashes and finding JSON/status/gate are identical before/after. Upgrade a version-7 DB containing old `verified` proposals, preserve all old rows and require fresh complete verification for PR eligibility. Repeat migration without data loss.
- [ ] **Step 2: Run `.venv\Scripts\python.exe -m pytest -q tests/remediation/test_service.py tests/remediation/test_migrations.py`.** Expect missing service/columns first; after imports exist, retain the meaningful assertions proving source/claim behavior fails before its implementation.
- [ ] **Step 3: Implement the service and additive storage.** Move `_fix_provider`, `_fix_context`, `_execute_fixes` and apply/list serialization responsibilities out of `web/app.py` in the integration task; do not duplicate that logic. Read only bounded source from the recorded manifest and validate hashes before/after staging. Keep provider use explicit; reuse `propose_fix`, pass cancellation before each call and immediately after it returns, and never continue into apply/publish after cancellation. Model response time remains bounded by provider settings; do not promise token streaming. Bind process cancellation with the existing runner context. Atomic claims use conditional SQL and database indexes, never a process-local boolean. `provenance_json={}` is a visible legacy limitation until reverified against the retained manifest.
- [ ] **Step 4: Run the service and migration tests plus `tests/ai/test_fix_boundaries.py` and `test_fix_verification.py`.** Confirm no scan/finding mutation and no writes outside new artifact attempts.

### Task 3: Add a fixed-host GitHub transport with uncertain outcomes

**Files:** Create `src/vulnscan/remediation/github.py`, `tests/remediation/test_github.py`; extend `src/vulnscan/contracts/remediation.py`.

**Interfaces:** Define `PRPreview` with `proposal_id`, public `run_id`, `repository`, `base_branch`, `base_commit`, `source_path`, regular-file `mode`, `source_sha256`, `patched_sha256`, `diff_sha256`, `branch`, `title`, `body`, `preview_sha256`. Hash the canonical sorted compact JSON of all fields except `preview_sha256`. `PublicationReceipt` retains `attempt_id`, `status` (`prepared`/`publishing`/`published`/`failed`/`blocked`/`unknown`), `last_step`, `branch`, `commit_sha`, `pr_number`, `pr_url`, sanitized `detail` and `preview_sha256`.

Produce `publish_draft(preview: PRPreview, patched: bytes, *, token_env: str="DEVSEC_GITHUB_TOKEN", on_step: Callable[[str, dict[str, Any]], None], cancel: threading.Event | None=None) -> PublicationReceipt` and `reconcile(preview: PRPreview, receipt: PublicationReceipt, *, token_env: str="DEVSEC_GITHUB_TOKEN") -> PublicationReceipt`. The service supplies/persists attempt identity through `on_step`; returned receipts retain it. There is no arbitrary host, shell command or provider-tool interface.

- [ ] **Step 1: Add failing transport tests using `httpx.MockTransport`.** Capture the real serialized requests. Assert fixed `api.github.com`, Authorization header only, API version `2026-03-10`, original parent/tree, exactly one source entry with recorded mode, new ref only and `draft=True`. Assert wrong origin/repository, stale base tip, existing branch, oversize body/response and changed patched bytes block writes. Inject `401`, `403`, `404`, `409`, `422`, `429`, `5xx`, redirect, malformed success body and timeouts at each write step. A lost PR acknowledgement yields `unknown`, no automatic second POST, and a GET-only reconcile can recover the matching draft PR marker. Secret tokens/URLs/response bodies never appear in logs or receipts.
- [ ] **Step 2: Run `.venv\Scripts\python.exe -m pytest -q tests/remediation/test_github.py`.** Expect missing transport initially, then request/receipt contract failures until implemented.
- [ ] **Step 3: Implement the minimal REST sequence.** Use existing `httpx`, `trust_env=False`, redirects disabled, five-second connect and ten-second read/write timeouts, bounded response streaming and sanitized errors. Read repository/ref/commit metadata, then POST tree, commit, new ref and draft PR as specified. Validate every returned ID/draft flag/URL and report actual acknowledgements through `on_step`. Do not update existing refs, request merge, change target files, execute Git hooks or use `gh`. Never replay a POST automatically. Read-only reconciliation checks the expected branch, commit and PR marker; a branch without a PR remains incomplete for separate recovery authorization.
- [ ] **Step 4: Run the transport tests and `tests/remediation/test_service.py`.** All network traffic remains synthetic. Permission checks are simulated; no real token, upload, branch or PR is created.

### Task 4: Bind PR review, publication and receipts to exact verified content

**Files:** Modify `src/vulnscan/remediation/service.py`, `src/vulnscan/storage/database.py`; create `tests/remediation/test_publication.py`.

**Interfaces:** Extend `handle` with `prepare_pr`, `publish_pr`, `publication`, `reconcile_pr`. `prepare_pr` accepts `run_id`, `proposal_id`, `repository`, `base_branch`, reviewed `title` and `body`; it performs local checks only and returns `{preview, receipt}`. `publish_pr` requires `run_id`, `proposal_id`, `preview_sha256`, `approval="publish_draft_pr"`; it accepts no changed destination/body. `publication` reads only. `reconcile_pr` is an explicit read-only remote check that may update the local receipt. Use the Task 3 contracts and transport.

- [ ] **Step 1: Add failing publication tests.** Assert prepare/list/receipt cause zero HTTP; apply consent never counts as publish consent. Reject missing/incorrect approval or preview hash, no-revision/dirty scan, foreign proposal, changed source/diff/overlay, unsupported/partial verification and old `verified` state without new evidence. Publish a matching clean fixture through fake HTTP exactly once. Race two real SQL sessions and restart the service after an acknowledged ref/lost response: retain one claimed publication and no automatic resend. A `published`/`unknown`/`publishing` attempt blocks another publication claim. Cancellation before writes produces no write; cancellation after any uncertain write preserves its receipt and forbids automatic recovery. Finding status/validation/gate remain byte-identical.
- [ ] **Step 2: Run `.venv\Scripts\python.exe -m pytest -q tests/remediation/test_publication.py`.** Require behavioral failures before adding publication dispatch.
- [ ] **Step 3: Implement exact-content approval and claim.** Read Git origin/commit/mode only through fixed read-only Git argument vectors and the trusted runner; compare the actual origin with the explicitly chosen GitHub.com repository and recorded source. Refuse hidden source transformations; outbound source containing a known secret is blocked. Generate the deterministic branch name and preview digest, create a prepared attempt, then atomically claim only the exact reviewed attempt. Add a partial unique index over proposal publication states `publishing`, `unknown`, `published`. Acknowledge step checkpoints separately from remote execution. Retain stale active attempts on restart as uncertain; do not silently reclaim them or delete remote branches. Revalidate the remote base tip immediately before the first write and fail closed on drift.
- [ ] **Step 4: Run `tests/remediation/` together.** Confirm local temporary checkout refs/files and all earlier attempt files are unchanged after success, failure, reconciliation and cancellation.

### Task 5: Expose shared CLI, HTTP, JSONL and React review controls

**Files:** Modify `src/vulnscan/web/app.py`, `src/vulnscan/core/rpc.py`, `src/vulnscan/cli/main.py`, the React/mock/i18n files from the map; create `src/vulnscan/cli/fixes.py`, `tests/cli/test_fixes.py`, `tests/platform/test_rpc_remediation.py`; extend `tests/web/test_fix.py`, `tests/web/test_notifications.py`, `web-ui/src/components/__tests__/aiFix.test.tsx`.

**Interfaces:** Retain existing fix routes/status fields, integer backend proposal IDs and `POST /fix` response `{run_id, accepted: <count>, status:"queued"}`. Existing TypeScript declares `accepted: boolean` and proposal `id: string`, while the server returns a count/integer: correct client types to `number`/`string | number`, mocks and callers without changing server output. Add:

| Operation | HTTP | CLI / RPC action |
| --- | --- | --- |
| Suggest | Existing `POST /api/scans/{run_id}/fix` (202) | `fix suggest RUN --findings ID,... --provider-profile PROFILE`; `propose` |
| Inspect/list | Existing `GET .../fixes`, `GET .../download` | `fix list RUN`, `fix diff RUN PROPOSAL`; `list`, `download` |
| Overlay | Existing `POST .../fixes/{proposal_id}/apply` | `fix apply RUN PROPOSAL --approve-overlay`; `apply` |
| PR preview | `POST .../fixes/{proposal_id}/pr/preview` | `fix pr-preview RUN PROPOSAL --repository OWNER/REPO --base BRANCH`; `prepare_pr` |
| Publish | `POST .../fixes/{proposal_id}/pr` | `fix pr-publish RUN PROPOSAL --preview-sha256 HASH --approve-publish`; `publish_pr` |
| Receipt | `GET .../fixes/{proposal_id}/pr` | `fix pr-status RUN PROPOSAL`; `publication` |
| Reconcile | `POST .../fixes/{proposal_id}/pr/reconcile` | `fix pr-reconcile RUN PROPOSAL`; `reconcile_pr` |

All owned RPC operations use method `remediation` and an `action` field. RPC calls use the existing request ID, cancellation event and response-size guard. A browser's published request includes exact approval/hash; no credential value is accepted in these bodies. Existing native CLI forwarding already forwards unknown commands such as `fix` to Python; retain that behavior. For the shared Jinja evidence page, add `POST /runs/{run_id}/remediation` accepting only the actions `propose`, `apply`, `prepare_pr`, `publish_pr`, `reconcile_pr` and their documented fields; use the same service and CSRF middleware. Add `GET /runs/{run_id}/fixes/{proposal_id}/download` as a read-only alias to the existing download service. Evidence GET loads list/receipt data only.

- [ ] **Step 1: Add failing cross-interface tests.** Check unchanged old route responses, scoped 404/422 failures, CSRF on every new POST and no side effects from GET. Verify `fix suggest` uses an explicit profile, `fix apply` requires overlay approval and `pr-publish` rejects missing approval/hash without prompting noninteractive runs. JSONL honors cancellation and never exceeds 8 MiB. React must display the whole reviewed diff/verification limitation and destination/base/upload notice, render a distinct “Publish draft PR” confirmation, send the exact preview hash and keep `unknown` visible after refresh. Closing a preview sends nothing. Mock mode never sends real HTTP. Test the existing accepted-count and numeric-ID mismatches explicitly.
- [ ] **Step 2: Run `.venv\Scripts\python.exe -m pytest -q tests/cli/test_fixes.py tests/platform/test_rpc_remediation.py tests/web/test_fix.py tests/web/test_notifications.py` and `npm --prefix web-ui test -- src/components/__tests__/aiFix.test.tsx`.** Observe failures for missing actions/approval controls; existing route regression failures must also be fixed.
- [ ] **Step 3: Route every operation through the service.** Remove duplicated web-only orchestration after callers use `handle`; keep the existing background 202 generation response. Use bounded worker tasks for long apply/publish operations, preserve partial artifacts, and serialize sanitized service results. Add explicit review/confirm controls with keyboard focus and escaped diff text; never render model HTML. Use the existing masked `env set`/Keys mechanism for `DEVSEC_GITHUB_TOKEN`, not a new credential store. Fix TypeScript/mock numeric contracts to match the server.
- [ ] **Step 4: Run the same focused checks, then `npm --prefix web-ui run lint` and `npm --prefix web-ui run build`.** Require offline tests/type-check/build success; record absent installed frontend tooling without installing packages.

### Task 6: Add supported terminal and native dashboard parity

**Files:** Create `src/vulnscan/tui/remediation.py`, `internal/service/remediation.go`, `internal/tui/remediation.go`, `tests/tui/test_remediation.py`, `internal/tui/remediation_test.go`, `tests/platform/test_native_remediation.py`, `tests/platform/remediation_rpc_fixture.py`; modify `src/vulnscan/tui/app.py`, `internal/tui/app.go`, `internal/tui/view.go`, `internal/dashboard/server.go`, `src/vulnscan/web/templates/evidence.html`, `tests/platform/test_native_dashboard.py`.

**Interfaces:** Add `Backend.Remediation(ctx context.Context, params map[string]any) (map[string]any, error)` as a thin `Client.Call(ctx,"remediation",...)` wrapper. Extend the TUI API interface and its fakes. Add a **Fixes** action on the current finding evidence screen; Textual/Bubble Tea workers consume the same actions/preview hashes. Native dashboard implements the same `POST /runs/{id}/remediation` action whitelist and `GET /runs/{id}/fixes/{proposal_id}/download` alias defined in Task 5; its existing scoped evidence GET loads list/receipt data. Shared evidence forms offer suggest, apply, preview, publish, status and reconcile using the owned Python service; handlers render escaped results and retain existing CSRF middleware. No new Go provider, scanner or GitHub implementation.

- [ ] **Step 1: Write failing client/native tests.** Keyboard-only workflows at 80x24, 75x26 and minimum size must expose separate apply/publish confirmations, readable long diffs, retained unknown receipts and cancellation without blocking navigation. Up/Down focus and Left/Right choices must preserve reader/text-cursor keys. Closing a dialog or navigating to history causes no publish. A real native executable and its owned Python child must use synthetic provider/GitHub responses to complete a single draft workflow and expose its retained receipt; patching only the parent pytest process is not sufficient. Native dashboard POST without CSRF fails; GET and template rendering never publish.
- [ ] **Step 2: Run `.venv\Scripts\python.exe -m pytest -q tests/tui/test_remediation.py tests/platform/test_native_remediation.py tests/platform/test_native_dashboard.py` and `go test -mod=readonly ./internal/tui ./internal/service ./internal/dashboard`.** Expected initial failures name missing controls/methods; do not replace the real child boundary with an in-process fake.
- [ ] **Step 3: Implement the thin clients and responsive controls.** Use existing owned-child cancellation/lifecycle. Pass transport fixtures into the child using a fixture module consistent with `tests/platform/ai_rpc_fixture.py`; keep those test-only substitutions out of application defaults. Native CLI `fix` continues to use existing Python forwarding with interpreter/import cleanup unchanged. Public/native dashboards display the same verification limitation and explicit upload approval.
- [ ] **Step 4: Build with `.venv\Scripts\python.exe ci/build_native.py --go .tools/go/bin/go.exe` and rerun the client/native tests.** Use PATH `go` if available, otherwise the repository SDK. A cross-build is not Windows/Linux/macOS runtime proof; report the OS actually exercised.

### Task 7: Update accepted contracts and complete required verification

**Files:** Documentation targets from the file map and this plan's completion checkboxes only after authorized execution.

**Interfaces:** Trace `P-REM-01/02/03` to accepted new SRS IDs; retain FR-01/02/19/40/50/55/56/62/65/66/67/68/71 and QR-01/03/05/12/13/14/15/20/21 in tests/docstrings. Extend C-01 for separately approved GitHub publication. FR-75 remains notifications; do not describe PR publication as a model notification tool.

- [ ] **Step 1: Update `docs/SRS.md`, `docs/REMEDIATION.md`, `docs/TEST-PLAN.md`, `docs/NATIVE-MIGRATION.md`, `docs/IMPLEMENTATION-PLAN.md`, `README.md`, `CHANGELOG.md` under `Unreleased`, and `AGENTS.md` when feature descriptions become stale.** State single-file/GitHub.com/Semgrep-only PR eligibility, clean pinned base requirement, partial verification limits, credential reference, explicit approvals, HTTP permission needs and read-only reconciliation. Label unimplemented recovery writes and other hosts as unsupported. Document migration and legacy proposal behavior without inventing results.
- [ ] **Step 2: Run and read all required Python checks.**

  ```powershell
  .venv\Scripts\python.exe -m ruff check src tests ci
  .venv\Scripts\python.exe -m ruff format --check src tests ci
  .venv\Scripts\python.exe -m mypy src/vulnscan
  .venv\Scripts\python.exe -m pytest -q
  ```

  On Linux/macOS use the configured `.venv/bin/python` or `.venv-linux/bin/python`. These are mandatory implementation checks, not commands executed during this planning task.
- [ ] **Step 3: Run and read Go/frontend/native checks for the changed clients.**

  ```powershell
  $env:GOFLAGS = '-mod=readonly'
  $env:GOPROXY = 'off'
  go vet ./...
  go test ./...
  .venv\Scripts\python.exe ci/build_native.py --go .tools/go/bin/go.exe
  npm --prefix web-ui test
  npm --prefix web-ui run lint
  npm --prefix web-ui run build
  ```

  Use `.tools/go/bin/go.exe vet ./...` and `test ./...` if `go` is not on PATH; restore only environment variables changed by the test invocation afterward without dumping the environment. Do not install/fetch to hide a missing tool/module. Re-run affected real native boundary tests after rebuilding.
- [ ] **Step 4: Review requirement coverage, paths and final diff.** Confirm new artifacts stay outside pristine targets, no model tool gained permissions, no evidence/essay/unrelated edits occurred, and no real provider/GitHub action occurred. State failing checks, skipped live operations and untested OS runtimes plainly. No full target scan is needed for this feature's offline regression gate; a later live GitHub smoke test needs separate explicit authorization.

## Planning self-review

The inspected helper names, existing HTTP responses, JSONL version/limit, database migration baseline, CLI forwarding and native service wrapper pattern match this checkout. Tasks 1–4 cover every remediation design invariant; Tasks 5–6 provide client parity; Task 7 covers requirements/documentation and mandatory checks. Each review-focus item has a named negative test and positive control. No commit or implementation was performed while writing this plan; runtime checks were not run.
