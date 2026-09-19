# Application Implementation and Testing Plan

Status: implementation plan, not a report of completed work. This document preserves the plan agreed in the planning conversation. Implementation coordination is described in [AGENT-HANDOFF.md](AGENT-HANDOFF.md).

## 1. Objective and confirmed baseline

Build a local application that scans Java Servlet/JSP source code, consolidates security findings, proposes evidence-backed CVSS v4.0 assessments, and independently verifies AI-generated conclusions.

The application will provide a simple web dashboard and a CLI for reproducible experiments. Planning and application documentation will be in English; the existing thesis files remain unchanged.

Use JVA-bookstore at commit `dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5` as the experimental baseline. Inspection found 97 main-source Java files, 38 JSP files, and no `src/test` suite. Its configuration specifies Java 11, Maven WAR packaging, `javax.servlet`, and PostgreSQL. Build success has not yet been tested. [Pinned repository](https://github.com/Moseyuh333/JVA-bookstore/tree/dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5)

Planning defaults:

- Two students, 17 weeks, provisional USD 50 total AI-usage budget.
- Twelve source-code vulnerability groups, with dependency vulnerabilities evaluated separately.
- Static scanning requires no running target application. Function tests and optional targeted sandbox execution strengthen evidence.
- Hosted deployment, multi-user accounts, notifications, automatic remediation, and DAST scanners are outside the first release.

## 2. Application architecture and implementation

### Requirements and documentation

Create `docs/SRS.md`, `docs/IMPLEMENTATION-PLAN.md`, and `docs/TEST-PLAN.md`. Assign requirement IDs and connect each feature to its acceptance tests and relevant thesis section.

The SRS will cover source intake, scanning, normalization, contextual assessment, verification, reporting, provider configuration, and reproducibility.

### Accuracy requirements and acceptance gates

Carry the following IDs unchanged into the SRS, test plan, and evidence manifest. These are planned requirements, not measured improvements. Task ownership and downstream gates are defined in [AGENT-HANDOFF.md](AGENT-HANDOFF.md).

| ID | Planned requirement | Required acceptance evidence |
| --- | --- | --- |
| ACC-01 | Cross-function and cross-file analysis, including an experimental CodeQL adapter and an early comparison with the existing scanner combination. Cover Servlet-to-helper-to-DAO flows. | Development fixtures cover direct, cross-method, and cross-file vulnerable flows and sanitized controls. Record each scanner's detections and misses, extraction mode, query versions, dataflow paths, and limitations. Failed extraction means incomplete coverage. |
| ACC-02 | Version Java security models for request inputs, dangerous operations, helpers, sanitizers, authentication checks, and their applicability. Assemble finding-specific routes, filters, callers, and sinks. | Each model has provenance and regression tests for helper wrappers, valid sanitization, ineffective sanitization, and sanitization in the wrong context. Ambiguous call resolution remains explicit. |
| ACC-03 | Declare authorization policy for customers, sellers, administrators, and shippers, including permitted resource operations and ownership conditions. Map sensitive operations to routes and enforcement points. | Test unauthenticated callers, incorrect roles, another user's resource, and permitted owner access. Both students review intended permissions independently of implementation; missing or disputed policy leaves affected findings unresolved. |
| ACC-04 | Analyze server-generated JSP output in HTML text, attributes, URLs, and embedded JavaScript, preserving original JSP positions and evaluating encoding against the actual context. | Each supported context has unsafe, correctly encoded, and incorrectly encoded examples. Unknown contexts, missing source mappings, and failed JSP compilation are explicit coverage gaps. |
| ACC-05 | Maintain regression fixtures for every custom detection rule: vulnerable examples, suspicious-looking safe examples, and meaning-preserving variations. | Test variable renaming, equivalent expressions, helper extraction, and applicable cross-file movement. Unexpected detection changes fail regression checks or require an explicit, reviewed limitation; record non-applicability rather than silently skipping a variation. |
| ACC-06 | Apply the same reviewed verification procedure to vulnerable and fixed variants, including legitimate-functionality checks and a defined security property for each applicable CWE. | Execution observations distinguish demonstrated vulnerability, blocked behavior, harness failure, and inconclusive results. Use independently checked structural evidence where execution cannot establish the property. Preserve procedure versions and artifacts for both variants. |
| ACC-07 | Record eligible and analyzed files, parsing/compilation failures, unsupported constructs, unresolved calls, and capability by CWE; classify missed findings. | Reports separate missing rules, broken extraction, missing models, unsupported flows, incorrect grouping, AI rejection, and verification limitations. Skipped files cannot appear successfully analyzed. Java and JSP coverage reconcile separately with the input inventory. |

### Local application

Use Python, FastAPI, Jinja templates, SQLite through SQLAlchemy, and a separate worker process. The CLI and web interface share the same application services.

Persist queued work in SQLite and run one scan at a time. Record interrupted stages explicitly; retry them as new attempts while retaining previous artifacts.

Provide four screens:

1. Target registration and scan configuration.
2. Run progress, tool status, and coverage limitations.
3. Findings, source evidence, CVSS assumptions, and verification results.
4. Provider settings, usage, reports, and experiment comparisons.

Bind the service to localhost and protect state-changing requests with a local session and CSRF checks.

### Scanning and source context

Integrate these tools:

| Tool | Responsibility |
| --- | --- |
| Semgrep Community Edition | Java source rules and targeted checks |
| SpotBugs with FindSecBugs | Compiled Java security analysis |
| OWASP Dependency-Check | Dependency vulnerability identification |
| Gitleaks | Secrets in the selected source snapshot |
| CodeQL (experimental) | Evaluate additional cross-function/cross-file detection under ACC-01; preserve extraction and query provenance |

The existing four-tool combination remains the baseline. CodeQL is an experimental addition evaluated alongside it; inclusion does not imply complete cross-file or JSP coverage. Establish its extraction, toolchain, resource, and usage feasibility in weeks 1–2, including development-only flow and JSP probes. Record unsupported cases and schedule impact without silently dropping accuracy requirements.

Pin tool versions, rules, configuration, and advisory data for experiments. Preserve raw output before normalization. Distinguish execution failures, unsupported files, and successful scans with no findings.

Precompile JSP with Jasper and retain mappings back to original JSP locations. Test JSP coverage explicitly; precompiled JSP analysis is documented by FindSecBugs. Failed compilation must remain visible as incomplete coverage. [JSP analysis guidance](https://github.com/find-sec-bugs/find-sec-bugs/wiki/JSP-precompilation)

Build a Java syntax index and read Servlet annotations, deployment mappings, filters, and authentication helpers. Use scanner traces for dataflow evidence; syntax references alone must not be presented as proven reachability.

Implement ACC-02 models and ACC-03 policy references as versioned inputs, and attach their applicability and provenance to finding-specific context. Develop application-specific models only on development cases. For ACC-04, preserve output context alongside the original JSP coordinates; an encoder's name alone is insufficient evidence of correct sanitization. Record tool-specific coverage under ACC-07 even when a tool emits no findings.

### AI assistance and BYOK

Implement a bounded investigation loop supporting code inspection, route lookup, evidence retrieval, approved targeted checks, and verification-test proposals.

Retrieve structured route/filter/caller/sink evidence, model and policy references, JSP context, and relevant coverage gaps. Missing analysis must remain missing evidence, never a safety conclusion. Expected labels, fixed-variant references, and evaluation judgments are excluded from scanner and agent inputs.

Provider profiles contain endpoint, protocol, model ID, credential reference, generation settings, and budget limits. Initially support Chat Completions-compatible APIs, including compatible OpenCode Zen models. Other protocols require separate adapters and must not be treated as interchangeable. [Zen endpoint documentation](https://opencode.ai/docs/zen/)

Keep keys server-side in environment variables or an OS credential store. Never include them in target containers, reports, or model transcripts.

Default to five follow-up tool calls per finding. Enforce token, time, and cost limits before requests. Freeze one provider/model configuration for each experiment; do not silently switch models. Provider failure or budget exhaustion preserves scanner findings and produces an unresolved AI assessment.

### Severity and verification

Preserve each scanner's original severity. Calculate CVSS v4.0 scores deterministically from validated vectors using a tested scoring library.

Each metric must reference either source evidence or an explicit, versioned assumption. Missing required metrics produce an incomplete assessment, not an invented score. Preserve published dependency scores with their original CVSS version. [CVSS specification](https://www.first.org/cvss/v4.0/specification-document)

Implement three verification levels:

- Static route, dataflow, and configuration evidence.
- Isolated JUnit function tests.
- Optional targeted checks against an isolated application instance.

Store outcome—confirmed, rejected with evidence, or unresolved—separately from evidence strength. Static support is not proof of successful exploitation; a failed test is not proof that a vulnerability is absent.

Under ACC-06, both students must review the security observation used by reference tests before evaluation. Model-generated tests are evidence candidates and cannot define ground truth. Define an observable security condition and legitimate-functionality checks per applicable CWE, with execution or structural verification selected explicitly. For example, unsafe randomness and hardcoded secrets may require independently checked structural evidence. A fixed variant passing one test does not establish general safety. Blocked behavior supports only the tested condition; harness failure and inconclusive observations remain unresolved. Pair observations only in the evaluator after independent analysis of each variant.

## 3. Interfaces, data, and execution boundaries

Expose CLI commands for target registration, scanning, status, report export, and experiment evaluation. Provide equivalent API operations for runs, findings, evidence, provider profiles, and exports.

Use versioned records for:

- **Scan specification:** source revision, file scope, tools, rules, context profile, and limits.
- **Scanner observation:** original rule, severity, location or dependency identity, and raw artifact.
- **Finding:** grouped observations, CWE labels, and stable fingerprint.
- **Assessment:** proposed conclusion, CVSS vector, assumptions, validation outcome, and evidence references.
- **Run manifest:** input hashes, tool/container versions, model settings, timings, usage, failures, and artifact checksums.
- **Coverage record (ACC-01, ACC-04, ACC-07):** tool/version, source snapshot, file or analysis unit, eligibility, analysis status, limitation reason, extraction mode, and applicable CWE capabilities. Distinguish analyzed, partial, failed, unsupported, and skipped units; preserve parsing/compilation diagnostics and unresolved calls.
- **Security-model reference (ACC-02, ACC-05):** model identifier, version, applicability, provenance, and regression fixture references.
- **Authorization-policy reference (ACC-03):** role, resource, operation, ownership condition, policy version, assumption/review status, and mapped routes/enforcement points.
- **Context evidence (ACC-01–04):** route, filters, callers, source/sink references, dataflow paths and query versions, ambiguous resolutions, and JSP output context with original source mappings where applicable.
- **Verification observation (ACC-06):** procedure version, expected security property, observed behavior, execution status, legitimate-functionality result, evidence kind, and artifact references. Keep this separate from the final finding decision.
- **Evaluation case (ACC-05–07, evaluator only):** case family, variant relationship, development/held-out split, expected finding identity, matching criteria, expected labels, fixed-variant references, and review judgments.

The coordinator owns these shared-contract extensions and their consumer fixtures. Separate evaluator-only fields and storage from inference contracts and mounts; hiding them only in prompts is insufficient. The runner receives one opaque variant and its approved procedure at a time, without pair identity or expected finding labels. The evaluator joins independently produced observations afterward. Reports expose coverage limitations, output context, policy assumptions, and verification strength through these same contracts.

Deduplicate conservatively using location, weakness, and source/sink evidence. Preserve all contributing observations; never merge solely because CWE labels match.

Export SARIF 2.1.0, JSON, and human-readable HTML/Markdown. Keep confirmed, rejected, unresolved, and unprocessed counts distinct.

Run target builds and tests in Linux containers with resource limits. Target containers receive no provider credentials or Docker socket. Permit dependency downloads during controlled preparation; verification uses cached dependencies and isolated services.

Use synthetic PostgreSQL records and a local mail substitute. The repository initializes database state from application code, so tests must never use an existing database. Do not execute its tunnel startup scripts or restore its bundled database backups.

## 4. Testing and experimental design

### Application acceptance tests

Verify:

- A pinned revision produces traceable raw findings and reports.
- Java/JSP locations survive normalization and deduplication.
- Incorrect locations, invented evidence, invalid CWE values, and malformed CVSS vectors are rejected.
- Scanner errors and unavailable AI produce visibly incomplete results.
- Provider keys are redacted; budget limits stop further requests.
- Repository prompt injection cannot expand tool permissions.
- Verification containers cannot access host credentials or external services.
- Report totals and evaluation metrics reproduce from archived artifacts.
- A browser user can start a scan, inspect evidence, and export its report.
- All ACC-01–07 acceptance cases above run with traceable fixtures; unknown output context, failed extraction, skipped files, and missing policy cannot become clean analysis or unsupported rejection decisions.
- Shared records retain model/policy/procedure versions through normalization, validation, persistence, and export; scanner and agent input inspection confirms evaluator-only fields are absent.

Use pytest for pipeline/API tests, JUnit for target-function tests, and Playwright for the essential dashboard workflow.

### Ground truth

Build vulnerable/fixed pairs within isolated copies of JVA-bookstore. Start with three independent case families per source-code group: one for development and two held out for evaluation. This yields a planned 72 case variants, plus a separate dependency track.

Both students independently review labels and resolve disagreements before evaluation. Keep related variants in the same split. Hide labels, explanatory patch names, fixed-variant references, and reviewer decisions from scanners and agents; analyze each variant independently and pair only in the evaluator. Exclude unresolved label disputes from scored ground truth and report them separately.

Document intended authorization permissions independently of observed enforcement and have both students review them. Mark policy assumptions explicitly and provide the same declared policy to all comparable configurations; observed implementation cannot define its own correctness. Missing or disputed policy remains unresolved. Review reference security observations independently of model-generated tests.

Include difficult negative cases and ACC-05 regression variants. Renaming or relocating a flow creates a correlated regression variant, not a new independent research example. Split and analyze by case family. Freeze application-specific models using development cases only; inspect held-out failures after the primary evaluation, and label any resulting tuning as a new experiment.

Use existing application behavior where supported by evidence. Seed missing classes explicitly and record their origin. Natural findings outside the controlled cases receive separate review.

### Comparison configurations

Evaluate:

1. Each scanner independently.
2. The combined deterministic pipeline.
3. The combined pipeline with one non-agentic model assessment.
4. The combined pipeline with bounded agent investigation.
5. Verification ablations: static only, static plus function tests, and optional sandbox checks.
6. The existing scanner combination versus that same combination plus experimental CodeQL (ACC-01), first on development fixtures in weeks 1–2 and later under the frozen protocol.
7. Generic rules/models versus application-specific models (ACC-02), using identical source revisions, scanner configurations, and declared authorization policy while changing only the model/rule treatment.

Use identical frozen findings for the main assessment comparison. Evaluate adaptive rescanning separately against a deterministic configuration with equivalent checks or budget.

Keep detection comparisons separate from assessment comparisons: freeze scanner observations across deterministic, non-agentic, and agent-assisted assessment conditions. Attribute changes only to the controlled factor, rather than crediting all additional detection to AI. Archive per-scanner detections and misses, including extraction failures, for the CodeQL comparison.

Repeat AI configurations three times. Freeze rules, prompts, model settings, labels, and context assumptions before held-out testing.

### Metrics and interpretation

Measure precision, recall, F1, FPR, unresolved rate, CVSS metric/vector agreement, score error, verification yield, runtime, and AI cost.

Report precision, recall, F1, unresolved rate, and verification coverage per CWE alongside aggregate results, showing numerators, denominators, and undefined values. Report CWE-862 and CWE-639 separately as well as their combined authorization group. Define verification coverage as findings with completed applicable verification divided by findings eligible for that level, and report ineligible/unsupported counts separately. Separate Java and JSP file coverage, dependency findings, and natural findings from the controlled source-code track.

For ACC-07, classify each missed finding by stage using archived evidence: missing rule, broken extraction, missing model, unsupported flow, incorrect grouping, AI rejection, or verification limitation. Permit multiple contributing reasons and an explicit undetermined reason pending review; do not force an unsupported causal explanation. Preserve pre-triage and post-validation counts so discarded true findings remain visible.

- Calculate FPR only where labeled negative cases exist.
- Report known-issue coverage rather than claiming complete recall on the natural application.
- Measure discarded true findings explicitly.
- Test the agreed hypothesis: improved precision with no more than five percentage points of observed recall loss.
- Compare native scanner severity with reference severity categories; do not invent numeric CVSS equivalents.
- Report uncertainty and case-family dependence. Three repeats and one application do not establish broad generalizability.

The original split targets 24 held-out vulnerable cases (two per source-code group). One additional miss changes overall recall by 1/24, approximately 4.17 percentage points; per-CWE resolution is even coarser. Report actual counts and uncertainty using a predeclared method that respects case-family grouping, rather than treating regression variants or repeated AI runs as independent cases. The five-percentage-point criterion remains a descriptive acceptance threshold, not a statistically established guarantee. Limited sample size, correlated variants, application-model overfitting, disputed policy, incomplete extraction/JSP coverage, and the limits of differential execution must be discussed in the final evaluation.

Research hypotheses may fail without making the implementation unsuccessful.

## 5. Delivery schedule and completion criteria

| Weeks | Deliverable and completion gate |
| --- | --- |
| 1–2 | SRS with ACC-01–07, shared contracts, pinned source, container prerequisites, reproducible build attempt, CodeQL cross-file and JSP feasibility/comparison probes, and independent policy assumptions |
| 3–4 | CLI, durable worker, Semgrep adapter, immutable artifacts, coverage records, and initial detection-rule regression fixtures |
| 5–6 | Remaining and experimental CodeQL adapters, JSP output contexts/mappings, normalization, security models, and baseline reports |
| 7–8 | Complete detection/model improvements, policy-aware context extraction, CVSS validation, minimal dashboard, and BYOK configuration |
| 9–10 | Bounded agent, independent validation, reviewed differential function-test procedures, structural checks, and optional sandbox checks |
| 11–12 | Complete verification/regression gates, reviewed case-family dataset, evaluator tests, cost pilot, and frozen experimental protocol |
| 13–14 | Held-out comparisons, repeated AI runs, and verification ablations |
| 15–16 | Reproducible tables, limitations, requirement traceability, and demonstration preparation |
| 17 | Independent reproduction, regression fixes, and final handover |

Reserve USD 10 for provider/pilot work, USD 30 for frozen experiments, and USD 10 for reruns. Record prices and usage; unknown pricing requires configuration before paid requests.

Completion requires a working scan-to-report workflow, honest coverage and failure reporting, machine-validated AI assessments, and experimental tables reproducible from archived evidence. All measured results must come from executed experiments; planned values remain clearly labeled.

Keep the dashboard minimal to protect the accuracy work within 17 weeks. If early feasibility threatens delivery, record the affected ACC IDs, evidence, schedule/budget impact, and proposed revision for review; do not silently remove requirements or mark a blocked gate complete. Completion also requires ACC-01–07 traceability, frozen model/policy/procedure versions, accuracy regression checks, controlled comparative results, and independently reproducible evidence or explicitly incomplete experiments.
