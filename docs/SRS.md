# Software Requirements Specification

**Project**: DevSecOps-Agent — Automated Vulnerability Scanning and Assessment for Java Servlet/JSP Applications

**Document ID**: SRS-001  
**Version**: 1.0  
**Status**: Approved baseline — awaiting implementation  
**Authors**: Tran Doan Hoa (23162026), Nguyen Minh Khoi (23162046)  
**Supervisor**: Nguyen Thi Thanh Van

---

## 1. Introduction

### 1.1 Purpose

This document specifies the functional and non-functional requirements for a local software application that scans Java Servlet/JSP source code, consolidates security findings from multiple conventional static analysis tools, proposes evidence-backed CVSS v4.0 severity assessments with AI assistance, and independently verifies every AI-generated conclusion before accepting it.

This is a requirements specification, not a report of completed work. All requirements herein are planned and traceable to the project plan's accuracy gates (ACC-01 through ACC-07).

### 1.2 Scope

The application performs static analysis of Java Servlet/JSP source code. It does not run the target application (except for optional, targeted sandbox verification), does not deploy to a hosted environment, and does not automatically remediate findings.

**In scope (first release)**:

- Local scanning of Java Servlet/JSP source trees
- Integration of four conventional scanners plus one experimental cross-file analyzer
- Source-context modeling: call graphs, sanitizers, authentication checks, dangerous operations
- AI-assisted CVSS v4.0 assessment with independent mechanical verification
- Authorization policy declaration and mapping for four user roles
- JSP output-context analysis (HTML text, attributes, URLs, embedded JavaScript)
- Reporting in multiple formats with per-CWE and per-scanner breakdowns
- Experiment comparison for accuracy evaluation
- CLI and local web dashboard sharing the same application services

**Out of scope (first release)**:

- Hosted or multi-tenant deployment
- Multi-user accounts and authentication for the scanner itself
- Push or email notifications
- Automatic code remediation
- Dynamic application security testing (DAST)
- Continuous integration/continuous deployment (CI/CD) integration
- Scanning of non-Java source code (except JSP)

### 1.3 Definitions, Acronyms, and Abbreviations

| Term | Definition |
| --- | --- |
| ACC-01..07 | Accuracy gates defined in the project plan; each maps to requirements, tests, and an owner |
| CWE | Common Weakness Enumeration, a community-developed list of software weakness types |
| CVSS v4.0 | Common Vulnerability Scoring System version 4.0, the standard for assessing software vulnerability severity |
| DAO | Data Access Object, a Java design pattern for database access |
| Finding | A normalized security issue reported by a scanner, enriched with context and assessment |
| JSP | JavaServer Pages, a server-side view technology |
| LLM | Large Language Model, the AI backend used for assessment |
| ODG | OWASP Dependency-Check, a Software Composition Analysis tool |
| SAST | Static Application Security Testing |
| Servlet | A Java class handling HTTP requests under `javax.servlet` |
| Sink | A code location where untrusted data reaches a dangerous operation |
| Source | A code location where untrusted data enters the application |
| Sanitizer | Code that neutralizes untrusted data, making it safe for a specific context |
| Verification | Mechanical, independent checking of AI-generated conclusions |

### 1.4 References

| ID | Reference |
| --- | --- |
| REF-01 | Project plan: `.planning/PROJECT-PLAN.md` (accuracy table, scope, testing protocol) |
| REF-02 | Handoff guide: `.planning/AGENT-HANDOFF.md` (task order, ownership, acceptance gates) |
| REF-03 | JVA-bookstore, commit `dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5`, https://github.com/Moseyuh333/JVA-bookstore |
| REF-04 | CVSS v4.0 specification, https://www.first.org/cvss/v4.0/specification-document |
| REF-05 | CWE list, https://cwe.mitre.org |
| REF-06 | Semgrep documentation, https://semgrep.dev/docs |
| REF-07 | SpotBugs and FindSecBugs documentation |
| REF-08 | OWASP Dependency-Check, https://owasp.org/www-project-dependency-check |
| REF-09 | Gitleaks, https://github.com/gitleaks/gitleaks |
| REF-10 | CodeQL, https://codeql.github.com |

### 1.5 Overview

Section 2 defines the target environment and constraints. Section 3 specifies functional requirements with traceable feature IDs. Section 4 specifies data, storage, and reporting requirements. Section 5 specifies external interfaces. Section 6 specifies quality attributes. Section 7 specifies language, time, and formatting conventions.

Every requirement carries an ID of the form `FR-nn` (functional), `QR-nn` (quality), or `DR-nn` (data), and is linked to its acceptance tests and accuracy gates.

---

## 2. Target Environment and Constraints

### 2.1 Experimental Target

The sole experimental target is JVA-bookstore at the pinned commit `dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5`. Application behavior must not assume a different revision without recording a deliberate dataset revision.

| Property | Value |
| --- | --- |
| Repository | https://github.com/Moseyuh333/JVA-bookstore |
| Commit | `dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5` |
| Java source files | 97 |
| JSP files | 38 |
| Test suite | None (`src/test` absent) |
| Java version | 11 |
| Build system | Maven, WAR packaging |
| Servlet API | `javax.servlet` |
| Database | PostgreSQL |

**FR-01**: The application shall accept a local filesystem path to a Java Servlet/JSP project and register it as a scan target, recording the source revision (git commit hash) or an explicit "no-revision" marker.

**FR-02**: The application shall maintain the pristine target revision separate from build overlays, generated test fixtures, and seeded vulnerable variants. Overlay and variant content shall be versioned and recorded separately in the scan manifest.

**FR-03**: The application shall inventory every `.java` and `.jsp` file in the target tree at intake time and record the inventory as the coverage baseline. Files skipped by any later stage must remain visible as skipped, never as successfully analyzed.

### 2.2 Target Application Roles

The target application has four user roles. The application declares an authorization policy for each and maps sensitive operations to routes and enforcement points.

| Role | Description |
| --- | --- |
| Customer | Browses and purchases books; manages own profile and orders |
| Seller | Manages own book listings, inventory, and fulfillment of own orders |
| Administrator | Manages users, catalog, and platform-wide configuration |
| Shipper | Views assigned orders and updates delivery status |

**FR-04**: The application shall maintain a declared authorization policy document covering customers, sellers, administrators, and shippers, specifying permitted resource operations and ownership conditions for each role.

**FR-05**: The application shall map each sensitive operation (database writes, cross-user resource access, administrative functions, order status changes) to its route and enforcement point, and flag operations with missing or disputed enforcement.

### 2.3 Constraints

**C-01**: The application must run entirely locally. No component requires network access except scanner rule updates and LLM API calls.

**C-02**: Total AI-usage budget is USD 50 for the project lifetime. The application must track cumulative spend and refuse to exceed the budget without explicit override.

**C-03**: Timeline is 17 weeks with two developers.

**C-04**: The application is written in Python 3.11+ with a Python orchestration service; the analyzed application is Java-only.

**C-05**: Scanning is static. Function tests and optional targeted sandbox execution strengthen evidence but are not required for every finding.

**C-06**: The target application's pristine source must not be modified by any scan stage.

---

## 3. Functional Requirements

Feature IDs below are stable and carried unchanged into the test plan and evidence manifest. Each feature lists its accuracy-gate mapping and required acceptance evidence.

### 3.1 Source Intake and Inventory (FR-10..FR-19)

**FR-10 — Target registration.** The application shall register a target by local path, record its git revision, and store a manifest of project metadata (build system, Java version, dependency file locations).

*Evidence*: registration record with revision hash and file inventory; test `T-INTAKE-01`.

**FR-11 — File inventory.** The application shall enumerate all `.java` and `.jsp` files, classify each as Java source, JSP page, or resource, and record byte size and character encoding detection.

*Evidence*: inventory table reconciling with the filesystem; test `T-INTAKE-02`.

**FR-12 — Parsing and compilation status.** The application shall attempt to parse each Java file (AST) and each JSP file (syntax + tag structure) and record parse success or failure per file with the error class (syntax error, unsupported construct, missing dependency, encoding problem).

*Evidence*: per-file parse status; failures recorded with error class, never silently dropped; tests `T-INTAKE-03`, `T-INTAKE-04`.

**FR-13 — Unsupported constructs registry.** The application shall record every construct it cannot analyze (e.g., reflection-based dispatch, dynamic JSP includes resolved at runtime, custom tag handlers without source) in a limitations log with file and line.

*Evidence*: limitations log entries with positions; test `T-INTAKE-05`.

**FR-14 — Java security model construction.** The application shall build security models for: request input sources, dangerous operations (sinks), helper methods, sanitizers, and authentication checks. Each model entry shall record provenance (file, line, rule version) and applicability conditions.

*Evidence*: model tables with provenance and regression tests for helper wrappers, valid sanitization, ineffective sanitization, and sanitization in the wrong context; accuracy gate ACC-02; tests `T-INTAKE-06`..`T-INTAKE-09`.

**FR-15 — Call-graph construction.** The application shall build a call graph covering Servlet-to-helper-to-DAO flows, record unresolved calls explicitly as ambiguous, and expose per-finding reachable callers and callees.

*Evidence*: call-graph export with unresolved-call list; accuracy gate ACC-01; test `T-INTAKE-10`.

**FR-16 — Route and filter mapping.** The application shall extract URL patterns from `web.xml` and servlet annotations, map filters to routes, and associate each finding with its route and filter chain.

*Evidence*: route table reconciled with `web.xml` and annotations; test `T-INTAKE-11`.

**FR-17 — JSP position preservation.** The application shall analyze JSP files while preserving original JSP source positions (line and column in the `.jsp` file) in every finding and evidence excerpt derived from JSP analysis.

*Evidence*: findings with JSP positions matching original `.jsp` lines; accuracy gate ACC-04; test `T-INTAKE-12`.

**FR-18 — Build feasibility probing.** The application shall attempt an isolated Maven build and JSP precompilation of the target using an explicit toolchain version, and record actual logs or an explicit environmental blocker. A feasibility failure does not count as successful target analysis.

*Evidence*: build log file or documented blocker; test `T-INTAKE-13`.

**FR-19 — Overlay versioning.** The application shall version any build overlay separately from the pristine target and record the overlay's hash in the scan manifest.

*Evidence*: overlay directory with recorded hash, separate from pristine; test `T-INTAKE-14`.

### 3.2 Scanning (FR-20..FR-29)

**FR-20 — Scanner integration.** The application shall integrate the following scanners as adapters behind a common interface:

| Scanner | Responsibility | Status |
| --- | --- | --- |
| Semgrep Community Edition | Java source rules and targeted checks | Baseline |
| SpotBugs with FindSecBugs | Compiled Java security analysis | Baseline |
| OWASP Dependency-Check | Dependency vulnerability identification | Baseline |
| Gitleaks | Secrets in the selected source snapshot | Baseline |
| CodeQL | Cross-function/cross-file detection evaluation | Experimental |

*Evidence*: adapter implementations with per-scanner detection and miss records; accuracy gates ACC-01, ACC-07; tests `T-SCAN-01`..`T-SCAN-05`.

**FR-21 — Scanner isolation.** Each scanner shall run in an isolated working directory with its own copy of the target snapshot. Scanner failures shall be recorded as tool-status entries and must not abort the overall scan.

*Evidence*: per-scan tool-status table; test `T-SCAN-06`.

**FR-22 — Raw output retention.** The application shall retain each scanner's raw output (JSON, XML, or text) as an artifact with the scanner version and rule/query versions recorded.

*Evidence*: artifact files with version metadata; test `T-SCAN-07`.

**FR-23 — Custom rule support.** The application shall load custom Semgrep rules from the `rules/` directory and record which rules fired for which findings.

*Evidence*: rule-firing log; test `T-SCAN-08`.

**FR-24 — Dependency scan separation.** Dependency-Check findings shall be stored and reported separately from source-code findings. Dependency findings do not count toward the twelve source-code CWE groups.

*Evidence*: separate finding table and report section; test `T-SCAN-09`.

**FR-25 — Secret scan scoping.** Gitleaks shall scan only the selected source snapshot, not the entire git history, unless the operator explicitly requests history mode.

*Evidence*: scan configuration record showing scope; test `T-SCAN-10`.

**FR-26 — CodeQL provenance.** The experimental CodeQL adapter shall record extraction mode, database build command, query pack versions, and per-query detection and miss results.

*Evidence*: CodeQL provenance record; accuracy gate ACC-01; test `T-SCAN-11`.

**FR-27 — Scanner selection.** The operator shall be able to enable or disable individual scanners per scan, and the scan record shall reflect the active set.

*Evidence*: scan configuration echo; test `T-SCAN-12`.

**FR-28 — One scan at a time.** The application shall serialize scan execution: one scan runs at a time, with queued work persisted in SQLite.

*Evidence*: queue state inspection; test `T-SCAN-13`.

**FR-29 — Interrupted-stage recovery.** The application shall record interrupted stages explicitly and retry them as new attempts while retaining all previous artifacts.

*Evidence*: retry record referencing prior attempt artifacts; test `T-SCAN-14`.

### 3.3 Normalization and Deduplication (FR-30..FR-34)

**FR-30 — Common finding schema.** The application shall normalize all scanner output into a common finding schema with fields: finding ID, scanner, rule ID, CWE, file, start/end position, severity (scanner-native), confidence, message, and raw excerpt.

*Evidence*: schema definition and normalized records; test `T-NORM-01`.

**FR-31 — CWE mapping.** Each normalized finding shall carry at least one CWE ID from the supported group list, or an explicit "unmapped" marker with the original rule text retained.

*Evidence*: mapping table with unmapped entries visible; test `T-NORM-02`.

**FR-32 — Deduplication.** The application shall deduplicate findings from multiple scanners that point to the same code location and CWE, preserving each contributing scanner's record in the finding's provenance chain.

*Evidence*: deduplication log showing merged records and retained provenance; test `T-NORM-03`.

**FR-33 — Grouping integrity.** The application shall group findings by CWE and by affected feature/route, and shall report grouping failures (e.g., findings that cannot be attributed to a route) explicitly rather than dropping them.

*Evidence*: grouping report with unattributed findings listed; accuracy gate ACC-07; test `T-NORM-04`.

**FR-34 — Coverage reconciliation.** The application shall reconcile normalized findings against the intake inventory, separately for Java and JSP, and report per-CWE coverage: eligible files, analyzed files, parse failures, and unsupported constructs.

*Evidence*: coverage table reconciling with FR-11 inventory; accuracy gate ACC-07; tests `T-NORM-05`, `T-NORM-06`.

### 3.4 Contextual Assessment (FR-40..FR-49)

**FR-40 — Finding context assembly.** For each normalized finding, the application shall assemble the finding-specific context: the source (input entry), the route and filter chain, callers along the path, the sink, and any sanitizer or authentication check present on the path.

*Evidence*: context assembly records; accuracy gate ACC-02; test `T-CTX-01`.

**FR-41 — Sanitizer applicability.** The application shall evaluate each sanitizer against the output context of the sink, distinguishing valid sanitization, ineffective sanitization, and sanitization in the wrong context.

*Evidence*: per-finding sanitizer classification with the applicable context; accuracy gate ACC-02; tests `T-CTX-02`..`T-CTX-04`.

**FR-42 — JSP output-context analysis.** The application shall analyze server-generated JSP output in four contexts — HTML text, HTML attributes, URLs, and embedded JavaScript — evaluating encoding against the actual context and preserving original JSP positions.

*Evidence*: per-context examples covering unsafe, correctly encoded, and incorrectly encoded cases; accuracy gate ACC-04; tests `T-CTX-05`..`T-CTX-08`.

**FR-43 — Unknown-context handling.** JSP constructs whose output context cannot be determined shall be recorded as unknown-context with the reason, not classified as safe.

*Evidence*: unknown-context log; accuracy gate ACC-04; test `T-CTX-09`.

**FR-44 — Cross-function and cross-file flows.** The application shall trace vulnerable flows across method and file boundaries (Servlet → helper → DAO), including sanitized controls, and record the full path with positions.

*Evidence*: flow records with complete paths; accuracy gate ACC-01; tests `T-CTX-10`, `T-CTX-11`.

**FR-45 — Ambiguous call resolution.** Where the call graph cannot resolve a target uniquely (interface dispatch, reflection, dynamic dispatch), the application shall record the ambiguity explicitly and enumerate candidate targets.

*Evidence*: ambiguity records with candidate lists; accuracy gate ACC-02; test `T-CTX-12`.

**FR-46 — Authorization mapping.** The application shall map each finding to the declared authorization policy (FR-04), identifying the required role and ownership condition, and flagging findings whose route lacks enforcement.

*Evidence*: policy mapping table; accuracy gate ACC-03; test `T-CTX-13`.

**FR-47 — Authorization test cases.** The declared policy shall be exercised by test cases covering: unauthenticated callers, incorrect roles, another user's resource, and permitted owner access.

*Evidence*: policy test matrix with pass/fail per case; accuracy gate ACC-03; tests `T-CTX-14`..`T-CTX-17`.

**FR-48 — AI assessment request.** For each finding requiring assessment, the application shall send the finding with its assembled context to the configured LLM and request a CVSS v4.0 assessment with a stated rationale.

*Evidence*: LLM request/response artifacts retained per finding; test `T-CTX-18`.

**FR-49 — AI cost accounting.** The application shall record token counts and estimated cost per LLM call and accumulate them against the USD 50 budget, refusing further calls when the budget is exhausted unless explicitly overridden.

*Evidence*: usage ledger; test `T-CTX-19`.

### 3.5 Independent Verification (FR-50..FR-56)

**FR-50 — Mandatory verification.** No AI-generated assessment shall be accepted without passing mechanical verification. The verification engine is independent of the assessment agent and checks claims against source evidence.

*Evidence*: acceptance flags on every finding showing verification status; test `T-VERIF-01`.

**FR-51 — Sanitization verification.** The engine shall verify AI claims that a sanitizer is present, effective, and applicable by re-deriving the sanitizer's effect on the data path independently of the LLM.

*Evidence*: verification records with sanitizer re-derivation; test `T-VERIF-02`.

**FR-52 — Context verification.** The engine shall verify AI claims about JSP output context by re-deriving the context from the JSP structure and comparing.

*Evidence*: context re-derivation records; test `T-VERIF-03`.

**FR-53 — CVSS vector validation.** The engine shall validate each proposed CVSS v4.0 vector: well-formedness, consistency between vector components and the evidence excerpt, and plausibility of scope/impact claims against the finding context.

*Evidence*: validation records with per-component verdicts; test `T-VERIF-04`.

**FR-54 — Authorization verification.** The engine shall verify AI claims about required roles and enforcement by checking the declared policy mapping independently.

*Evidence*: policy verification records; test `T-VERIF-05`.

**FR-55 — Rejection handling.** When verification fails, the application shall retain the scanner-native finding with the AI assessment marked rejected, record the rejection reason, and exclude the AI assessment from the accepted result set.

*Evidence*: rejection records with reasons; test `T-VERIF-06`.

**FR-56 — Verification limitation reporting.** The engine shall report cases it could not verify due to missing models, broken extraction, unsupported flows, or incomplete context, separately from successful verifications.

*Evidence*: limitation report section; accuracy gate ACC-07; test `T-VERIF-07`.

### 3.6 Reporting and Experiments (FR-60..FR-68)

**FR-60 — Report formats.** The application shall produce reports in HTML, CSV, and JSON, all three generated from the same result set.

*Evidence*: report files with matching content across formats; test `T-REP-01`.

**FR-61 — Report content.** Each report shall include: scan metadata and tool versions, coverage tables (Java and JSP separately), findings with source evidence excerpts, CVSS v4.0 vectors and assumptions, verification results and rejections, dependency findings separately, and limitations.

*Evidence*: report section checklist verified by test; test `T-REP-02`.

**FR-62 — Source evidence.** Each finding in a report shall include the relevant source excerpt with file, line range, and highlighting of the source, sanitizer, and sink where applicable.

*Evidence*: rendered excerpts with correct positions; test `T-REP-03`.

**FR-63 — Experiment comparison.** The application shall compare two or more scans (e.g., baseline toolset vs. with CodeQL) and report per-CWE and per-finding differences in detections, misses, and assessment changes.

*Evidence*: comparison report; test `T-REP-04`.

**FR-64 — Missed-finding analysis.** The application shall accept a ground-truth or seeded-vulnerability set and report which findings each scanner detected, missed, or falsely reported.

*Evidence*: detection/miss matrix per scanner; accuracy gates ACC-01, ACC-07; test `T-REP-05`.

**FR-65 — Report export and retention.** Reports and raw artifacts shall be stored under a versioned artifacts directory keyed by scan ID, retained for later re-analysis without re-running scanners.

*Evidence*: artifact directory listing; test `T-REP-06`.

**FR-66 — Web dashboard.** The application shall provide a local web dashboard with four screens: target registration and scan configuration; run progress, tool status, and coverage limitations; findings with source evidence, CVSS assumptions, and verification results; and provider settings, usage, reports, and experiment comparisons.

*Evidence*: dashboard screens accessible and functional; test `T-WEB-01`..`T-WEB-04`.

**FR-67 — Local session and CSRF protection.** The web service shall bind to localhost only, protect state-changing requests with a local session and CSRF tokens, and reject requests without a valid token.

*Evidence*: CSRF enforcement test showing rejection; test `T-WEB-05`.

**FR-68 — Shared services.** The CLI and web interface shall invoke the same application services; no scan logic may exist only in one interface.

*Evidence*: service-layer test asserting both interfaces route through the same service; test `T-WEB-06`.

---

## 4. Data, Storage, and Reporting Requirements

**DR-01 — Database.** The application shall persist all scan state in SQLite via SQLAlchemy, accessed asynchronously through aiosqlite.

**DR-02 — Persisted queue.** Queued work, scan configuration, stage status, and retry history shall be persisted so that a process restart resumes the queue without losing queued work.

**DR-03 — Artifact storage.** Scanner raw output, LLM request/response pairs, generated reports, and comparison outputs shall be stored as files under a scan-keyed artifacts directory, with paths recorded in the database.

**DR-04 — Timestamps.** All timestamps shall be stored in UTC. Display shall default to Asia/Saigon with an explicit timezone indicator. No naive timestamps shall be stored.

**DR-05 — Idempotency.** Re-running a scan with identical configuration and target revision shall produce a scan record linked to the prior attempt's artifacts rather than silently duplicating them.

**DR-06 — Report data model.** The reporting layer shall consume a single normalized result set (findings, coverage, tool status, limitations) and render all formats from it, so that HTML, CSV, and JSON cannot diverge.

**DR-07 — Retained provenance.** Every finding shall carry a provenance chain: originating scanner, rule/query ID, rule/query version, normalization decisions, context assembly inputs, LLM model and prompt version, and verification verdict.

**DR-08 — Coverage ledger.** The application shall maintain a per-CWE coverage ledger recording eligible files, analyzed files, parse failures, unsupported constructs, and findings, reconcilable against the intake inventory for Java and JSP independently.

---

## 5. External Interface Requirements

### 5.1 Command-Line Interface

**IR-01**: The CLI shall expose commands for target registration, scan execution, result querying, report generation, experiment comparison, and server startup, using Typer with help text and shell completion.

**IR-02**: The CLI shall accept scan configuration (scanners enabled, rule sets, budget override) as flags and/or a configuration file, and shall echo the effective configuration before starting a scan.

**IR-03**: The CLI shall exit with non-zero status when a scan fails or coverage reconciliation fails, and shall print a machine-readable summary (JSON when `--json` is passed).

### 5.2 Web Interface

**IR-04**: The web service shall bind to `127.0.0.1` only and shall not bind to a public interface by default.

**IR-05**: The four dashboard screens (FR-66) shall be reachable within two clicks from the landing page.

**IR-06**: All state-changing endpoints shall require a session cookie and a valid CSRF token; GET endpoints shall not mutate state.

**IR-07**: The findings screen shall render source evidence with syntax highlighting and shall link each finding to its verification record and raw scanner artifact.

### 5.3 Scanner Interfaces

**IR-08**: Each scanner adapter shall expose a uniform interface: `name`, `version`, `run(target_snapshot, config) -> raw_artifact`, and `parse(raw_artifact) -> normalized_findings`.

**IR-09**: Scanner adapters shall be invoked through a subprocess or library boundary that isolates failures; a scanner crash shall be captured as a tool-status failure, not propagated.

**IR-10**: SpotBugs shall be invoked against compiled classes; where compilation fails, the adapter shall record a blocker and the scan shall continue with the remaining tools.

### 5.4 LLM Provider Interface

**IR-11**: The LLM provider shall be configured by base URL, API key, and model name, with per-request timeout and retry policy.

**IR-12**: Every LLM request and response shall be persisted with the prompt template version so that assessments are reproducible.

**IR-13**: The provider abstraction shall support any OpenAI-compatible endpoint, and the dashboard shall allow switching providers and models between scans.

---

## 6. Quality Attributes

### 6.1 Accuracy and Honesty

**QR-01 — No fabricated results.** The application shall never present a finding, assessment, or verification result that it did not actually produce. Where a stage could not run, the output shall say so.

**QR-02 — Coverage honesty.** Skipped, failed, and unsupported files shall appear as such in every report and shall never be counted as successfully analyzed.

**QR-03 — Verification is binding.** An AI assessment that fails verification shall never appear as an accepted result. The report shall show it as rejected with the reason.

**QR-04 — Ambiguity preserved.** Unresolved calls, unknown contexts, and disputed policy entries shall be reported as such, never resolved silently to a convenient verdict.

**QR-05 — Provenance completeness.** Every accepted finding shall have a complete provenance chain (DR-07) retrievable from the report.

### 6.2 Reliability

**QR-06 — Crash isolation.** A failure in any scanner, the LLM call, or the verification engine shall not lose prior stage results. Partial scan results shall be persistable and inspectable.

**QR-07 — Retry semantics.** Retried stages shall be recorded as new attempts; previous attempt artifacts shall be retained and linked.

**QR-08 — Deterministic output.** Given identical input, scanner versions, and LLM responses, the normalized result set and report content shall be byte-identical apart from timestamps.

### 6.3 Performance

**QR-09 — Target-scale capacity.** The application shall complete a full four-scanner scan of the JVA-bookstore target (97 Java files, 38 JSP files) on a developer laptop within a bounded wall-clock time, with progress visible per stage.

**QR-10 — Incremental reporting.** Findings shall be queryable as they are produced; the dashboard shall not require scan completion to show partial results.

### 6.4 Security

**QR-11 — Local-only binding.** The web service shall bind to localhost; a misconfiguration that binds to a public interface shall be a failing test.

**QR-12 — Secret handling.** LLM API keys and session secrets shall be read from environment variables or a local configuration file with restrictive permissions, never logged, and never included in artifacts.

**QR-13 — CSRF and session.** State-changing web requests shall require session and CSRF tokens (IR-06).

**QR-14 — Sandbox containment.** Optional targeted sandbox execution shall run in an isolated environment that cannot reach the host filesystem or network except as explicitly configured.

### 6.5 Usability

**QR-15 — Interface parity.** CLI and web shall offer the same operations; an operation available in one shall be available in the other.

**QR-16 — Actionable failure messages.** Failures shall name the stage, the underlying cause, and the next corrective action where one exists.

### 6.6 Maintainability

**QR-17 — Test coverage.** The test suite shall cover all functional requirements listed in Section 3, with requirement IDs referenced from test names or docstrings.

**QR-18 — Type safety.** The codebase shall pass `mypy --strict` with no errors under the configured Python version.

**QR-19 — Lint compliance.** The codebase shall pass `ruff check` and `ruff format --check` with the configured line length.

### 6.7 Portability

**QR-20 — Platform support.** The Python application shall run on Linux, macOS, and Windows with Python 3.11 or later. Scanner availability may differ by platform; missing scanners shall degrade gracefully per FR-21.

---

## 7. Language, Time, and Formatting Conventions

**CR-01 — Documentation and UI language.** All application documentation, UI text, reports, and error messages shall be in English.

**CR-02 — Timestamp storage.** All timestamps shall be stored in UTC with timezone awareness (DR-04).

**CR-03 — Timestamp display.** Display shall default to Asia/Saigon with an explicit UTC offset shown; the timezone shall be configurable per session.

**CR-04 — Position notation.** Source positions shall use one-based line and zero-based column, reported as `file:line:column`, matching common editor conventions.

**CR-05 — CVSS notation.** Severity shall be reported as a CVSS v4.0 vector string with the qualitative rating (None, Low, Medium, High, Critical) alongside the numeric score.

**CR-06 — Identifier stability.** Requirement IDs (FR, QR, DR, IR, CR, ACC) and test IDs (T-*) shall remain stable across documents; changes require a revision entry.

**CR-07 — Report naming.** Reports and artifacts shall be named with the pattern `scan-{id}-{stage}-{format}-{timestamp}.{ext}`, sorted lexicographically by timestamp.

**CR-08 — Currency.** All cost figures shall be in USD with two decimal places.

---

## Appendix A. Requirement-to-Accuracy-Gate Traceability

| Requirement | Accuracy gate | Required evidence summary |
| --- | --- | --- |
| FR-15, FR-44, FR-26 | ACC-01 | Development fixtures for direct, cross-method, cross-file flows and sanitized controls; per-scanner detection/miss records; extraction mode and query versions; dataflow paths; limitations |
| FR-14, FR-40, FR-41, FR-45 | ACC-02 | Model provenance; regression tests for helper wrappers, valid/ineffective/wrong-context sanitization; explicit ambiguous-call resolution |
| FR-04, FR-05, FR-46, FR-47 | ACC-03 | Policy declaration reviewed independently by both students; test matrix for unauthenticated, wrong-role, other-user, and owner access |
| FR-17, FR-42, FR-43 | ACC-04 | Per-context unsafe / correctly encoded / incorrectly encoded examples; unknown-context and missing-mapping records |
| FR-30..FR-34, FR-56, FR-64 | ACC-07 | Coverage ledger reconciling Java and JSP against intake; missed findings classified by cause; limitations separated by category |
| FR-50..FR-56 | (verification) | Per-finding verification verdict with re-derivation records |
| FR-60..FR-65 | (reporting) | Reports in three formats with identical content source |

## Appendix B. Supported CWE Groups

| CWE | Name | Primary scanners |
| --- | --- | --- |
| CWE-89 | SQL Injection | Semgrep, SpotBugs/FindSecBugs, CodeQL |
| CWE-78 | OS Command Injection | Semgrep, SpotBugs/FindSecBugs |
| CWE-79 | Cross-Site Scripting (XSS) | Semgrep, CodeQL (JSP contexts) |
| CWE-22 | Path Traversal | Semgrep, SpotBugs/FindSecBugs |
| CWE-434 | Unrestricted File Upload | Semgrep |
| CWE-918 | Server-Side Request Forgery | Semgrep, SpotBugs/FindSecBugs |
| CWE-611 | XML External Entity (XXE) | SpotBugs/FindSecBugs |
| CWE-502 | Deserialization of Untrusted Data | SpotBugs/FindSecBugs |
| CWE-798 | Hard-coded Credentials | Gitleaks, Semgrep |
| CWE-327 | Broken Cryptographic Algorithm | Semgrep, SpotBugs/FindSecBugs |
| CWE-330 | Insufficient Randomness | Semgrep, SpotBugs/FindSecBugs |
| CWE-862 / CWE-639 | Missing Authorization / IDOR | Semgrep, CodeQL |

Dependency vulnerabilities (CWE-1035 class and related) are identified by OWASP Dependency-Check and reported separately per FR-24.
