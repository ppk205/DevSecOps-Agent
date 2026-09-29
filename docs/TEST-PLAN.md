# Test Plan — DevSecOps-Agent

**Version:** 1.0
**Status:** Draft (T00)
**Related:** [SRS.md](SRS.md), [IMPLEMENTATION-PLAN.md](IMPLEMENTATION-PLAN.md)

---

## 1. Strategy

Test everything against real artifacts; never claim a pass without an executed check. Three test technologies map to three layers:

| Layer | Technology | Scope |
|-------|-----------|-------|
| Pipeline / API / contracts | **pytest** | Python modules, adapters, persistence, API, evaluator |
| Target function tests | **JUnit** | Java verification harness inside containers |
| Dashboard workflow | **Playwright** | Browser-driven scan submission → report export |

## 2. Test categories

### 2.1 Unit tests

Per module, using contract fixtures from `tests/fixtures/`:

- **Contracts** — model validation, rejection of invalid CWE values, malformed CVSS vectors, invented locations.
- **Normalization** — grouping, dedup, provenance preservation.
- **CVSS** — scoring matches reference examples, missing metrics → incomplete.
- **Providers** — fake-provider responses: malformed, unsupported capability, rate limit, timeout, budget exhaustion, prompt injection.

### 2.2 Integration tests

- **Job lifecycle** — fake adapter completes a run; restart preserves stage history; failed/partial runs cannot appear clean; artifacts identifiable by run and attempt.
- **Adapter smoke** — each scanner parses recorded fixtures and completes a real smoke scan or reports a documented unavailable condition.
- **Validation** — source-coordinate/checksum mismatch rejected; counterevidence required for rejection.
- **Reporting** — report totals reproduce from archived artifacts; exports preserve accuracy references and denominators.

### 2.3 End-to-end tests

- **Scan-to-report** — pinned revision produces traceable raw findings and reports (Playwright + API).
- **Browser workflow** — a browser user starts a scan, inspects evidence, exports a report.
- **Baseline without AI** — provider unavailable → visible incomplete AI assessment, scanner findings intact.

### 2.4 Accuracy tests (ACC-01 – ACC-07)

| ID | Test cases |
|----|-----------|
| ACC-01 | Direct, cross-method, cross-file vulnerable flows + sanitized controls. Per-scanner detection/miss records. CodeQL extraction mode + query versions recorded. |
| ACC-02 | Helper wrappers, valid sanitization, ineffective sanitization, wrong-context sanitization. Ambiguous calls stay explicit. |
| ACC-03 | Unauthenticated caller, incorrect role, another user's resource, permitted owner. Missing/disputed policy → unresolved. |
| ACC-04 | Unsafe, correctly encoded, incorrectly encoded per context (HTML text, attribute, URL, embedded JS). Unknown context / failed compilation = gap. |
| ACC-05 | Variable renaming, equivalent expressions, helper extraction, cross-file movement. |
| ACC-06 | Vulnerable/fixed variant pairs, functionality checks, harness failure vs security observation separation. |
| ACC-07 | Coverage reconciliation: eligible vs analyzed vs skipped vs failed; missed-finding classification with multi-cause support. |

### 2.5 Security tests

- Provider keys redacted in API and reports.
- Repository prompt injection cannot expand tool permissions.
- Verification containers cannot access host credentials or external services.
- CSRF protection on state-changing requests.
- Untrusted snippets escaped in reports and UI rendering.

---

## 3. Fixture management

| Fixture type | Location | Owner |
|--------------|----------|-------|
| Contract fixtures | `tests/fixtures/contracts/` | Coordinator |
| Scanner fixtures (recorded native output) | `tests/fixtures/scanners/` | Analysis |
| Detection regression fixtures (ACC-05) | `tests/analysis/fixtures/` | Analysis |
| Verification failure-injection fixtures | `tests/sandbox/fixtures/` | Sandbox |
| Evaluator fixtures | `tests/evaluation/fixtures/` | Evaluation |
| **Development case families** | `evaluation/fixtures/development/` | Evaluation (label-visible) |
| **Held-out case families** | `evaluation/fixtures/held_out/` | Evaluation (label-isolated) |

**Ground-truth isolation rule:** development fixtures may be used for model/rule tuning; held-out fixtures are analyzed with labels hidden and paired only in the evaluator. Test code under `tests/analysis/`, `tests/ai/`, `tests/sandbox/` must never read held-out labels.

---

## 4. Ground truth protocol

1. Case families: 3 per CWE group (1 development + 2 held-out) → planned 72 variants, plus a separate dependency track.
2. Both students independently review labels; disagreements resolved before evaluation.
3. Unresolved label disputes excluded from scored ground truth, counted separately.
4. Related variants stay in the same split (regression variants are correlated, not independent cases).
5. Natural findings outside controlled cases receive separate review and a separate reported track.
6. Model-generated tests are evidence candidates — they never define ground truth.
7. Freeze matching, uncertainty treatment, labels, and development-only model tuning before held-out testing.

---

## 5. Per-task test mapping

| Task | Test targets | Key acceptance checks |
|------|-------------|----------------------|
| T00 | `tests/contracts/` | Contract fixtures exist; build feasibility logged or blocked. |
| T01 | `tests/platform/` | Fake adapter run; restart history; failed/partial visibility; artifact identity; CLI coverage. |
| T02 | `tests/analysis/` | Fixture parsing per adapter; real smoke scan or documented unavailable; grouping provenance; same-CWE distinct sites; ACC-01–05, ACC-07 cases. |
| T03 | `tests/sandbox/` | Timeouts, cleanup, denied external access, credential separation, disposable DB state, failure-injection distinction. |
| T04 | `tests/ai/` | Malformed/rate-limit/timeout/budget/injection fake-provider tests; ambiguous calls; unknown JSP context; absent policy. |
| T05 | `tests/validation/` | Scoring vs reference; invented evidence rejected; missing metrics incomplete; counterevidence for rejection; wrong-context encoding cannot justify rejection. |
| T06 | `tests/web/`, `tests/reporting/` | Playwright scan→export; CSRF; counts reconcile; unresolved vs unprocessed distinguishable; JSP links to original positions. |
| T07 | `tests/evaluation/` | Fixture metrics hand-checkable; split membership enforced; labels hidden from inference; matching rules documented; dataset size actual. |
| T08 | `tests/integration/` | Requirement tests pass; baseline survives provider failure; budget accounting; second-person reproduction. |
| T09 | `tests/evaluation/` (frozen) | Tables regenerate from archived artifacts; recall loss vs 5-point tolerance; undefined metrics disclosed. |
| T10 | — | Independent reproduction of baseline + proposed-system runs; application acceptance tests. |

---

## 6. CI considerations

- Run pytest on every commit; full suite before merge to protected branches.
- Separate slow/integration marks (`@pytest.mark.integration`, `@pytest.mark.sandbox`) from unit tests.
- Container-based tests require Docker; skip gracefully when unavailable (documented, not silent).
- Playwright tests run against a seeded local instance.
- Coverage report per module; no minimum threshold enforced over unowned areas.

---

## 7. Evaluation metrics (T07/T09)

Measured per CWE and aggregate:

- Precision, recall, F1 — with numerators, denominators, and undefined values shown.
- FPR — only where labeled negative cases exist.
- Unresolved rate.
- Verification coverage — completed applicable verification / eligible for that level; ineligible/unsupported reported separately.
- CVSS metric/vector agreement, score error.
- Runtime, AI cost.
- Java and JSP file coverage — separate.
- Dependency findings and natural findings — separate tracks.
- CWE-862 and CWE-639 — reported separately and combined.

**Interpretation rules:**

- The 24 planned held-out vulnerable cases imply ~4.17 percentage points per miss; the 5-point criterion is descriptive, not a statistical guarantee.
- Correlated regression variants do not add independent examples.
- Do not treat every unlabelled code line as a true negative.
- Report known-issue coverage rather than complete recall on the natural application.
- Measure discarded true findings explicitly (pre-triage vs post-validation counts preserved).

---

## 8. Acceptance — application level

The application is acceptance-complete when:

- A pinned revision produces traceable raw findings and reports.
- Java/JSP locations survive normalization and dedup.
- Incorrect locations, invented evidence, invalid CWE, malformed CVSS are rejected.
- Scanner errors and unavailable AI produce visibly incomplete results.
- Provider keys redacted; budget limits stop further requests.
- Prompt injection cannot expand tool permissions.
- Verification containers cannot access host credentials or external services.
- Report totals and evaluation metrics reproduce from archived artifacts.
- A browser user can start a scan, inspect evidence, export a report.
- All ACC-01–07 cases run with traceable fixtures.
- Shared records retain model/policy/procedure versions through normalization, validation, persistence, export.
- Scanner and agent input inspection confirms evaluator-only fields are absent.


## v0.2.0 platform acceptance (SRS 1.1)

| Requirement | Automated evidence |
| --- | --- |
| FR-70, DR-09 | `tests/platform/test_scan_service.py`: persisted attempts, restart, retry, OS lock, recovery and partial cancellation |
| FR-71, IR-14, QR-21 | `tests/tui/test_app.py`: configure/scan/export/reopen, keyboard navigation, resizing, modal quit and responsive cancellation |
| FR-72, IR-15 | `test_fr72_policy_outcomes`, missing-scanner/coverage tests and CLI parity tests: high/critical, unresolved/unprocessed, rejected, unknown; execution failures precede thresholds |
| FR-73, DR-10, QR-22 | checkout commit/dirty manifest, configuration precedence, path traversal and subprocess credential tests; immutable snapshots and redacted outputs |
| FR-74 | `tests/platform/test_release.py`: exact version/tag selection and immutable rerun assets; `ci/release.py` validates wheel/sdist before publishing |
| QR-23 | `.github/workflows/checks.yml`: all test areas, Linux 3.11?3.13, Windows/macOS 3.11, Ruff, strict mypy and clean wheel install |
| FR-72, FR-73, QR-22 | `ci/fixture_scan.py`: real safe/vulnerable Java fixtures; fast on PR/main, full/container scheduled/manual and before release |
| DR-03, FR-60, IR-16 | Incremental scanner envelopes with SHA-256 references; typed UTC progress; same normalized report source for all exports |

Run `uv sync --frozen --extra dev` before testing. No paid providers or live model
weights are required by ordinary tests. JUnit and module coverage are uploaded
with `always()`; integrations retain sanitized reports. Real scanner integration
is a separate required check, not simulated by adapter fixtures. Repository branch
protection must select required jobs in GitHub settings.
