# Fix suggestions, draft pull requests and outbound webhooks

**Status:** Proposed design for review. This document does not implement or authorize either feature.

**Date and baseline:** 2026-11-15, `feat/native-workflow-notifications`. Source inspection, rather than historical verification reports, establishes the baseline below. Other working-tree changes are outside this design.

**Planning assumptions:** “Gợi ý tự sửa - PR” means a suggested diff, human-approved isolated application and verification, followed by a separately approved GitHub draft pull request. “Webhook notification” means an outbound scan-summary HTTP delivery. It does not mean an inbound scan trigger. GitHub.com and one generic webhook destination per project are the initial scope. These choices remain proposals until the owner approves implementation.

## Current implementation and gaps

| Area | Existing implementation | Planned extension |
| --- | --- | --- |
| Fix generation | `src/vulnscan/ai/fix.py` exposes `propose_fix`, `prepare_overlay`, `apply_unified_diff` and `verify_fixed`. `ProviderClient` uses configured provider profiles; this helper currently discards returned usage and constructs the client without a budget tracker. | Share the existing flow with operator clients; pin proposals to recorded source hashes; retain actual usage and the existing budget interface; harden application and verification before using results to qualify a PR. |
| Fix interfaces | `src/vulnscan/web/app.py` has `POST /api/scans/{run_id}/fix`, `GET /api/scans/{run_id}/fixes`, explicit `POST .../fixes/{proposal_id}/apply` and `GET .../download`. React uses `web-ui/src/components/FixProposals.tsx`. | Retain those routes and response fields; add PR preview/publish/receipt operations and CLI, Textual, JSONL and Go clients using one service. |
| Verification | The helper runs a bundled Semgrep rule against one copied file. It filters matches by the old line and accepts exit codes `0`, `1`, `2`, `7` before inspecting output. The current code is not proof that an incomplete/error scan cannot report `fixed`. | Require a complete successful baseline and patched scan with the exact rule; inspect the whole file; preserve unsupported, failed and cancelled attempts. “Rule no longer fires” remains a limited mechanical observation. |
| Persistence | `FixProposalORM` in `src/vulnscan/storage/models.py` retains a diff, status, overlay and latest verification JSON. `storage/database.py` currently has migrations through version 7. | Add proposal provenance and append-only apply/publication attempts. Legacy `verified` rows do not qualify for PR publication without fresh complete verification. |
| Notifications | `notifications/settings.py`, `events.py`, `service.py` and `transports.py` provide opt-in Telegram/Discord digests, an atomic per-run/channel claim and retained receipts. Python/native completion uses this shared Python service. | Add channel `webhook` through the same offer, selection, claim and receipt path. |
| Legacy webhook | `web/app.py::_maybe_dispatch_webhook` reads `WEBHOOK_URL`. `record_scan_notification` calls it for gate failures; lazy notification creation on `GET /api/notifications` can invoke it. `docs/NOTIFICATIONS.md` documents this separate legacy behavior. | Explicitly propose retiring that send path. Preserve local feed entries, but make all feed/settings/receipt GET requests free of outbound delivery. `WEBHOOK_URL` alone will no longer send. |

The legacy GET side effect conflicts with the desired shared outbound service and repository T8. Its removal is a proposed compatibility change, not a claim about current behavior. Document the migration and replace the existing webhook-on-GET test instead of silently retaining two send paths.

## Requirements traceability

| Feature or boundary | Existing SRS requirements | Proposed contract addition |
| --- | --- | --- |
| Isolated, source-pinned remediation | FR-01, FR-02, FR-19, FR-40, FR-48, FR-49, FR-62, FR-65; QR-05, QR-14 | `P-REM-01`: immutable proposal provenance; separate operator actions for generation, overlay application and external PR publication. |
| Honest verification and status ownership | FR-50, FR-55, FR-56; QR-01, QR-03 | `P-REM-02`: complete baseline/patched mechanical results and append-only attempts; no automatic finding-status, validator-decision, CVSS or policy-gate changes. |
| Shared operator interfaces | FR-66, FR-67, FR-68, FR-71; QR-12, QR-13, QR-15, QR-20, QR-21 | `P-REM-03`: preview and explicitly publish a GitHub draft PR through the trusted service, with retained remote outcomes. |
| Generic outbound delivery | FR-75, C-01; QR-01, QR-05, QR-12, QR-15, QR-16 | `P-WEB-01`: extend FR-75 to a generic signed summary webhook with disabled defaults and the existing selected events. |
| Network and recovery behavior | FR-75; QR-06, QR-07, QR-14 | `P-WEB-02`: exact-host public HTTPS policy, pinned DNS destination, bounded signed envelopes, atomic claims and explicit uncertain outcomes. |

`P-*` labels identify proposals in these planning files only. They are not existing SRS FR IDs. Implementation must amend `docs/SRS.md`: add the accepted remediation requirements, extend FR-75 and C-01 for approved GitHub publication, and update the interface/secret-storage contracts. Existing FR-50 specifies assessment validation; a repair rescan does not satisfy it or confer independent validator authority.

## Shared constraints

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

## Remediation behavior

### Scope and provenance

One proposal changes exactly one existing regular UTF-8 source file. Reject multiple file headers, renames, adds/deletes, binary patches, links, submodules, absolute/drive/UNC paths, traversal, credential paths and malformed hunks before writing. Preserve original line endings and UTF-8 BOM; reject unsupported encodings. Diff limit is 256 KiB; source-file limit is 1 MiB. These limits apply before model parsing, persistence and application. Do not run a repository's hooks, build scripts or model-provided commands.

Resolve the checkout from the persisted `ScanSpecification.repository_checkout_path` and its recorded manifest, not from `TargetORM.repository_url` as though every URL were a local folder. `ScanService.detail` exposes `spec` and `result`; source hashes are recorded in `spec.metadata.manifest` and the result's `manifest`. Require a matching recorded file hash before generation and application. Recheck hashes before and after copying. Missing provenance is a visible blocker, not an invented revision. An operator may explicitly reverify a legacy proposal against a matching retained run manifest; do not trust its old status alone.

Record proposal run/finding identity, actual provider profile/model, scanned revision or `no-revision`, path, source SHA-256 and diff SHA-256. Keep proposals immutable after generation. Rejected secret-bearing output must not be stored as a usable diff; apply sanitization/redaction before persistence, and reject when transformation would change patch semantics. Source instructions remain untrusted prompt data.

Preserve the existing `providers/budget.py::BudgetManager` interface when generating suggestions and retain returned usage. As FR-49's current implementation note states, provider prices are not configured and monetary budget enforcement is incomplete; this plan does not invent a cost or claim to finish that separate requirement. Missing tokens/cost remain unavailable, and recorded budget exhaustion must stop a requested call.

### Human actions and mechanical verification

1. **Suggest fix:** an explicit request selects findings and a provider profile. Reuse `propose_fix`; retain the diff without applying it. Report unavailable profiles and returned usage honestly. A source upload to a provider occurs only under this explicit request and its displayed effective settings.
2. **Apply and verify in an overlay:** an explicit request identifies the immutable proposal. New clients also submit the reviewed diff SHA-256; existing empty-body apply requests remain valid for their immutable proposal ID. Stage under a new attempt directory inside the configured artifact root. Never reuse or overwrite an earlier overlay.
3. **Inspect the result:** run the exact bundled Semgrep rule once against the original copied file and once against the patched file. The baseline must completely analyze the file and reproduce that rule. The patched run must completely analyze the file and have no match for that exact rule anywhere in the file. Parser errors, missing scans, unsupported rules/languages, timeouts, skipped files, errors in JSON or tool failures are not success. Semgrep `0` or `1` alone is insufficient without those JSON/coverage checks. Use the existing cancellable trusted process runner; no shell.
4. **Prepare PR:** a local preview contains the complete diff, verification scope/limitations, destination `owner/repo`, base branch/commit, title/body, new branch name and hashes of uploaded content. It sends no HTTP request. No-revision and dirty scans may retain proposals/overlays but cannot publish in this initial release.
5. **Publish draft PR:** a separate explicit confirmation binds the exact preview SHA-256. Revalidate the immutable patch and current source/overlay hashes; allow only a clean verified Git revision and origin that matches the explicitly selected GitHub.com repository. The selected remote base branch tip must still equal that scanned commit. Reject drift before creating remote objects.

Verification retains `{fixed, detail}` for existing clients and adds `outcome`, exact rule/tool version, analyzed-file evidence, original/patched artifact hashes and attempt identity. `outcome` is `passed`, `failed`, `unavailable`, `cancelled` or `incomplete`; `fixed` is true only for `passed`. Display “Rule no longer fires; human review required.” Do not describe functional correctness, exploit prevention or complete vulnerability resolution as proven. Native-hunt-only, secret and dependency findings can receive suggestions but cannot qualify through unsupported Semgrep verification. Dedicated verification for those scanners is outside this release.

### GitHub publication

Use a small trusted `httpx` REST transport, separate from provider calls, fixed to `https://api.github.com`. Use an EnvFile/process variable reference `DEVSEC_GITHUB_TOKEN`; never persist or expose its value. Initial permissions are repository Contents write and Pull requests write. No GitHub SDK, `gh` dependency, local Git commit, local branch, target push or credentials in URLs.

After approval, read repository/ref/commit metadata; create a Git tree based on the scanned commit's tree with the one patched file and its existing regular-file mode; create a commit whose parent is the scanned commit; create a new branch `fix/devsecops-{public_run_id}-{proposal_id}-{diff_sha256_prefix12}`; create a PR with `draft: true`. Never update, force-push or delete any existing branch. The PR body contains sanitized finding identity/CWE, limited verification outcome and limitations, plus an opaque publication marker; it excludes absolute host paths, secret excerpts and model transcripts. Title/body and changed source are reviewed before sending; recheck known-secret redaction boundaries on outbound bytes and block rather than mutate source. Show that publishing uploads the patched file and may trigger repository workflows.

Use `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2026-03-10`, five-second connect and ten-second read/write timeouts, disabled redirects and `trust_env=False`. Bound JSON responses to 1 MiB, suppress HTTP request logging containing credentials and return sanitized error classes. A token is passed only as an Authorization header. No token/URL/raw response body is included in a receipt.

One atomic database claim per proposal prevents concurrent publication. Record acknowledged tree/commit/ref identifiers as each step returns. A timeout or process interruption leaves `unknown`/`publishing` with the last acknowledged step. Do not automatically resend a write or remove an acknowledged branch. An explicit **Reconcile** action uses GETs to inspect the expected branch and matching PR marker/hash. If the expected PR exists, retain its URL/number and mark `published`. If only a matching branch exists, report it as incomplete; if remote state conflicts or is absent, retain the uncertainty. The user must separately authorize any later recovery write; automatic resume and branch cleanup are outside this release.

GitHub's [pull-request API](https://docs.github.com/en/rest/pulls/pulls#create-a-pull-request), [tree API](https://docs.github.com/en/rest/git/trees#create-a-tree), [commit API](https://docs.github.com/en/rest/git/commits#create-a-commit) and [reference API](https://docs.github.com/en/rest/git/refs#create-a-reference) define these operations. Their returned IDs, draft flag and URLs require validation before acknowledging success.

## Outbound webhook behavior

### Settings and migration

Add `WebhookSettings` beside Telegram/Discord with `enabled=False`, `events=[]`, `url_env="DEVSEC_WEBHOOK_URL"`, `signing_key_env="DEVSEC_WEBHOOK_SIGNING_SECRET"`, `allowed_hosts=[]`. Require at least one explicit exact hostname before enabling. Store references and host rules only. New settings schema is version 2; reading version 1 upgrades in memory with webhook disabled, and saving writes version 2 atomically. Existing Telegram/Discord preferences survive.

Retire `_maybe_dispatch_webhook` and its invocation from local feed insertion. An existing `WEBHOOK_URL` variable is not an opt-in and causes no request. Migration instructions let an operator deliberately set `url_env="WEBHOOK_URL"`, select `gate_failed`, set a signing-key reference and exact host, and enable delivery through the normal settings form. Do not copy secret values, replay old gate failures or silently turn on automatic mode.

Use the existing seven event IDs in `notifications/events.py`; do not add fix or PR event types in this release. `offer_run` still offers one digest per `(run_id, channel)`; `webhook` is one additional channel. Manual mode retains a pending selection; automatic mode uses saved selections only at trusted scan completion. Saving settings or loading any GET never sends or offers old drafts. Python and native completion use the same `notify_finished`/JSONL notification path.

### Request contract

Send a JSON UTF-8 envelope of at most 16 KiB with precisely these fields:

```json
{
  "schema_version": 1,
  "delivery_id": "<retained UUID>",
  "run_id": "<public run ID or retained legacy ID>",
  "scan_status": "completed",
  "events": [{"kind": "scan_completed", "message": "Scan <run ID> completed."}]
}
```

Only selected offered event kinds and their existing sanitized summary messages appear. Do not copy a raw scan result, path, repository URL, source, diff, transcript or raw scanner match into the envelope. Preserve the existing bounded event messages. Serialize with `json.dumps(..., ensure_ascii=False, sort_keys=True, separators=(",", ":"))` and persist the resulting body before sending so retries have the same bytes and delivery ID. Unknown/unexpected fields are omitted, not forwarded.

Require a configured signing secret of at least 32 UTF-8 bytes. Set `Content-Type: application/json`, `User-Agent: DevSecOps-Agent`, `X-DevSecOps-Delivery: <delivery_id>`, `X-DevSecOps-Timestamp: <Unix seconds>` and `X-DevSecOps-Signature: sha256=<hex>`. The signature is HMAC-SHA256 over `timestamp_ascii + b"." + exact_body_bytes`. Timestamp and signature are refreshed on an explicitly authorized retry; body and delivery ID remain unchanged. Receiver guidance requires constant-time signature comparison, a 300-second replay window and delivery-ID deduplication. No receiver implementation or public listener is included.

### Destination and receipt policy

Require HTTPS on port 443; reject userinfo, fragments, IP literals, control characters, wildcards, malformed IDNA hostnames and unmatched hosts. Query/path may carry a destination credential, so the entire URL stays secret. Hostnames are normalized to lowercase ASCII IDNA without a trailing dot; matching is exact. No per-request arbitrary headers, custom CA bypass or private-address override.

Resolve A/AAAA records immediately before connecting. Reject the destination if any result is not a global unicast address, including IPv4-mapped private IPv6, loopback, link-local, RFC1918, unique-local, multicast, reserved and metadata addresses. Select one allowed resolved IP for that attempt and connect directly to it while verifying TLS/SNI for the original hostname. Do not re-resolve inside the connection, follow redirects, use environment proxies or retry another address after a send may have begun. A small `http.client.HTTPSConnection` subclass can pin the socket address and preserve certificate validation without a dependency or global socket monkeypatch. Validate policy before sending bytes. Blocking/invalid configuration returns sanitized `unconfigured` without a network POST.

Use five-second socket timeouts and a 64 KiB response-read limit. These are socket timeouts, not an end-to-end deadline; operating-system DNS resolution may take longer. Run delivery off the UI thread and state this limitation. A `2xx` response means `sent` with detail “Receiver acknowledged HTTP delivery”; it does not prove downstream processing. `3xx`, `4xx`, `5xx` are `failed`, with sanitized status only. Network timeouts, broken connections or missing acknowledgements are `unknown`, even if the receiver may have accepted the request. No automatic retries, including `429` and `5xx`. Existing `sending` claims are not automatically reclaimed. A user-selected retry preserves the envelope and warns about duplicate processing for `unknown`. Changing the selected events on a retry is rejected.

Persist the webhook body, delivery UUID and destination fingerprint on the existing delivery row. The fingerprint covers the effective URL, URL/signing-key references and normalized allowed-host list using a one-way digest; never store the URL or signing secret. Bind a configured draft at offer time; a draft with no effective URL may keep a null fingerprint until an explicit configured send/retry binds it. A configured draft/retry cannot silently switch destinations: reject a changed fingerprint and require a new future run after deliberate configuration review. Rotating a signing-key value through the same reference remains allowed. Keep receipts separate from immutable scan artifacts and preserve scan/finding status and exit codes on every failure.

## Client and storage boundaries

Remediation uses one shared Python remediation service, reused by existing HTTP handlers, a `fix` Typer command group and an owned JSONL `remediation` method. Go adds a thin `Backend.Remediation` client. Textual and Bubble Tea expose review/apply/PR-preview/publish/receipt controls using workers, preserving keyboard and resize behavior. Native and Python dashboards use the same service and CSRF boundaries; no orchestration is implemented in React or Go.

Webhook extends existing `notification` RPC actions, HTTP outbound routes, notification CLI and F6/F7 forms. Native dashboard currently has no outbound settings routes; the webhook plan includes shared-service routes/forms there for parity rather than claiming they exist now.

Reserve additive migration 8 for remediation provenance/attempts and migration 9 for webhook envelope metadata. Each migration must work if the other feature is not installed first; do not gate one feature's code on the other's tables. Before implementation, check that those numbers remain unused and renumber both references together if concurrent development has consumed them. Python remains the migration owner; native startup already opens its owned Python service before using the store.

## Acceptance and delivery boundaries

- Proposed diffs, overlays and draft PR outcomes remain separate, reviewable records. No source checkout changes; no automatic publication or finding-status transition.
- Moving a finding to another line, a scanner parse failure, missing rule, unchanged baseline, mismatched source or forged `verified` row cannot qualify a PR.
- Declined/cancelled approval produces no outbound publication request. Concurrent publish requests produce at most one claimed attempt; uncertain writes remain visible and are reconciled without repeating them.
- All webhook defaults are disabled. Legacy variables, settings saves, feed/receipt GETs and restarts produce no historical sends. Python/native completion produces the same offered webhook payload for the same retained result.
- HMAC uses retained exact bytes; destination policy survives redirects, mixed DNS responses, private IPv6 and DNS rebinding. Secret URLs/signatures/tokens do not appear in logs or receipts.
- Required regression tests fail before the implementation and pass afterward. The full repository checks and applicable frontend/native checks are read before claiming implementation completion; unavailable tools and untested OS runtime behavior remain explicit limitations.

Implementation is split into [fix suggestions and draft PRs](../plans/2026-11-15-fix-suggestions-pr.md) and [webhook notifications](../plans/2026-11-15-webhook-notifications.md). Neither plan depends on shipping the other feature. No runtime verification was performed for this design-only change.
