# Agent and Collaborator Handoff

Status: ready for implementation planning and task assignment. All tasks below are pending. This guide organizes the agreed [project plan](PROJECT-PLAN.md); it does not claim the application, datasets, contracts, or tests already exist.

This revised package is staged in `planning-accuracy-revision/`. Future application implementation must use a new directory. Copy these three reviewed documents together into that workspace's `.planning/` before using the startup prompt below; preserve the original workspace's planning and thesis files.

## 1. Startup and authority

Read [README.md](README.md), [PROJECT-PLAN.md](PROJECT-PLAN.md), and the root `AGENTS.md` when available. The English planning package captures the user's current application decisions. The older architecture guide and historical thesis plans are background only where consistent with this scope.

The target is `https://github.com/Moseyuh333/JVA-bookstore`, commit `dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5`. Do not replace this with the current branch tip without recording a deliberate dataset revision. Keep the pristine revision separate from build overlays, generated tests, and seeded variants; record their hashes too.

The first coordinator establishes the SRS and shared contracts before delegating dependent implementation. A missing SRS is a documentation task, not permission to invent product behavior. Keep requirement-to-test links in all handoffs.

The original thesis and `.document-work/` are outside implementation ownership. Do not rebuild Word files or revise thesis headings as part of application tasks. The Java-only limit concerns the analyzed application; a Python orchestration service is already agreed.

## 2. Proposed workspace ownership

These paths are reserved for future implementation; they are not created by this planning package. Use `src/vulnscan/` as the Python package root. The coordinator owns shared files and dependency changes.

| Area | Exclusive owner | Proposed paths |
| --- | --- | --- |
| Requirements, shared contracts, dependencies, integration | Coordinator | `docs/`, `src/vulnscan/contracts/`, `pyproject.toml`, dependency lockfile, CI configuration |
| Intake, database, job lifecycle, CLI | Platform worker | `src/vulnscan/core/`, `src/vulnscan/storage/`, `src/vulnscan/cli/`, `tests/platform/` |
| Tool adapters, normalization, source index | Analysis worker | `src/vulnscan/scanners/`, `src/vulnscan/normalization/`, `src/vulnscan/context/`, `rules/`, `tests/analysis/` |
| Providers and bounded agent | AI worker | `src/vulnscan/providers/`, `src/vulnscan/agent/`, `prompts/`, `tests/ai/` |
| CVSS and independent evidence validation | Validation worker | `src/vulnscan/assessment/`, `src/vulnscan/verification/`, `tests/validation/` |
| Container execution and target harness | Sandbox worker | `infra/`, `harness/`, `tests/sandbox/` |
| Dashboard and reports | Presentation worker | `src/vulnscan/web/`, `src/vulnscan/reporting/`, `tests/web/`, `tests/reporting/` |
| Dataset protocol and evaluator | Evaluation worker | `evaluation/`, `tests/evaluation/` |

Workers are roles, not a requirement to launch seven agents. Reuse agents across successive tasks. With four slots, reserve one for the coordinator and at most three for independent workers. Never run two writers against the same ownership area concurrently.

Runtime artifacts, source checkouts, credentials, and hidden labels are not source-code modules. The coordinator defines their configured storage roots, ignore rules, retention, and access boundaries during T00. Keep ground-truth labels outside all scanner and agent input mounts.

## 3. Shared contract gate

T00 must publish the following before downstream integration:

- Versioned scan specification, scanner-result envelope, observations, grouped findings, evidence, assessment proposals, validation decisions, and run manifests.
- Source and dependency identities, Java/JSP source-map representation, and artifact references with checksums.
- Run/stage statuses, interruptions, retry attempts, partial coverage, and distinctions between unresolved and not processed.
- Adapter input/output contracts, provider request/response contract, and typed agent tool interfaces.
- Independent validation ownership: an AI proposal cannot directly mutate a finding into confirmed or rejected status.
- CLI/API operations and report contracts shared by backend, UI, and evaluator.
- Context-policy versioning, CVSS assumptions, and cost/token/time accounting.
- ACC-01–07 extensions defined in project-plan section 3: coverage records, security-model references, authorization-policy references, context evidence, verification observations, and evaluator-only case records. Include field-level access boundaries and fixtures for every consumer.

Expected labels, fixed-variant references, split membership, and evaluation judgments belong only to the evaluator. Scanners and agents analyze each variant independently; the runner receives an opaque variant and reviewed procedure, and the evaluator pairs observations afterward. Shared schema changes remain coordinator-owned.

Required invariant: syntactically valid JSON and existing source coordinates do not establish semantic correctness. Preserve uncertainty when evidence cannot support a conclusion.

Contract changes after T00 go through the coordinator, who updates consumers and fixtures together. Do not create competing finding schemas inside separate adapters.

## 4. Task queue and acceptance gates

### T00 — Requirements, source intake feasibility, and contracts

Owner: coordinator, with bounded read-only research delegated if useful. Dependencies: none.

Create the SRS, detailed implementation/test documents, project skeleton, shared contracts, and dependency policy. Map SRS sections 1–2 to scope and constraints, 3 to features, 4 to data/reports, 5 to interfaces, 6 to quality attributes, and 7 to language/time formatting. Use English UI/documentation, UTC stored timestamps, and Asia/Saigon display by default.

Inspect the pinned target and attempt an isolated Maven build and JSP precompilation. Establish compatible toolchain versions rather than relying on the host's Java installation. Document missing prerequisites, build errors, file exclusions, and coverage gaps. Do not silently repair the pristine target; version any build overlay separately.

Acceptance: source revision is verified; SRS feature IDs and contract fixtures exist; build/JSP feasibility has actual logs or an explicit environmental blocker; dependent tasks have agreed interfaces. Feasibility failure does not count as successful target analysis.

Accuracy responsibility: define ACC-01–07 and publish the extended contracts. During weeks 1–2, begin CodeQL extraction and cross-file feasibility, compare development flow probes with the existing scanner combination, and probe JSP output contexts. Record extraction mode, query/tool versions, detections, misses, and limitations. Establish an independent authorization-policy draft for customers, sellers, administrators, and shippers with both students; distinguish intended permissions and assumptions from observed implementation. The coordinator writes shared policy documentation in `docs/`; the analysis worker later implements mappings.

Additional gate: each ACC ID maps to planned tests and an owner; feasibility logs or explicit blockers exist; policy review/dispute status and schedule impact are recorded. A blocker can be handed off but cannot satisfy the affected accuracy gate. Early probes are feasibility work, not completion of T02 or a held-out experiment.

### T01 — Platform, persistence, and CLI

Owner: platform worker. Dependencies: T00.

Implement target registration, immutable snapshot identity, artifact storage, SQLite job persistence, single-scan execution, CLI operations, and interrupted-stage handling. Keep baseline scanning independent of provider availability.

Acceptance: a fake adapter can complete a run; restart preserves stage history; failed/partial runs cannot appear clean; artifacts are identifiable by run and attempt; CLI behavior is covered by platform tests.

### T02 — Scanner adapters and finding normalization

Owner: analysis worker. Dependencies: T00; end-to-end acceptance also requires T01 and T03.

Implement Semgrep CE first, then SpotBugs/FindSecBugs, Dependency-Check, and Gitleaks. Preserve native output, logs, versions, coverage, and exit semantics. Add conservative grouping and source indexing for Servlet mappings, filters, and caller references. Preserve JSP mappings and dependency identities.

Acceptance: each adapter parses recorded fixtures and completes a real smoke scan or reports a documented unavailable condition; grouping retains provenance; same-CWE findings at different sites stay distinct; compile or advisory-data failures stay visible. A fixture-only adapter is not production-complete.

Accuracy responsibility: own ACC-01 experimental CodeQL integration, ACC-02 security models, ACC-03 route/enforcement mappings, ACC-04 JSP context analysis, ACC-05 custom-rule fixtures, and ACC-07 coverage extraction within the existing analysis paths. Version models under `src/vulnscan/context/` and keep development fixtures in `tests/analysis/`; evaluator labels remain outside this area. Record model applicability/provenance and unresolved calls. Preserve HTML-text, attribute, URL, and embedded-JavaScript context and original JSP coordinates. Complete detection improvements during weeks 3–8.

Additional gate: direct, cross-method, and cross-file flows plus sanitized controls report per-scanner detections/misses. Wrapper, ineffective/wrong-context sanitization, and every custom rule's safe/vulnerable/meaning-preserving fixtures pass or expose reviewed limitations. Parsing, extraction, JSP compilation, unsupported constructs, and skipped files reconcile with eligible/analyzed inventories and CWE capability records. CodeQL remains experimental; no complete cross-file/JSP coverage claim is permitted.

### T03 — Isolated build and verification runner

Owner: sandbox worker. Dependencies: T00.

Implement restricted Linux-container execution, preparation-time dependency caching, resource/time limits, JUnit harness support, synthetic PostgreSQL fixtures, and a local mail substitute. Use a trusted runner boundary; do not give target code a host Docker socket or provider credentials. Avoid bundled tunnel scripts and database dumps.

Acceptance: tests exercise timeouts and cleanup, denied external access during verification, credential separation, disposable database state, and artifact collection after failures. Optional whole-application execution is separately enabled and remains local to the sandbox.

Accuracy responsibility (ACC-06): support repeatable execution of independent vulnerable and fixed variants using the same reviewed procedure, clean state, and legitimate-functionality checks. Separate demonstrated vulnerability, blocked behavior, harness failure, and inconclusive observations. T03 owns execution mechanics; T05 owns interpretation, and T07 owns reference procedures and pairing. Procedure integration requires T05/T07 artifacts, without changing T03's infrastructure dependency on T00.

Additional gate: failure-injection fixtures distinguish harness errors from security observations; artifacts identify procedure version and input hash without exposing expected labels to inference. Full differential acceptance requires integration with T05 and T07 during weeks 9–12.

### T04 — BYOK providers and bounded agent

Owner: AI worker. Dependencies: T00; full integration requires T01, T02, and T03.

Implement Chat Completions-compatible provider profiles, credential references, capability/error handling, usage accounting, and the bounded investigation loop. Limit the loop to registered tools; preserve the five-follow-up-call default. Emit proposals and evidence references for T05 rather than final authoritative decisions.

Acceptance: fake-provider tests cover malformed responses, unsupported capabilities, rate limits, timeouts, budget exhaustion, and prompt injection; these preserve baseline observations. Live smoke tests use an explicitly configured model and recorded cost. No silent model/provider substitution is allowed in evaluation.

Accuracy responsibility (ACC-01–04, ACC-07): retrieve structured routes, filters, callers, sinks, dataflow paths, model/policy references, JSP output context, and coverage gaps. Expose missing evidence rather than interpreting absent analysis as safety.

Additional gate: tests cover ambiguous calls, unknown JSP context, absent/disputed policy, and failed extraction; proposals retain uncertainty and baseline observations. Scanner/agent inputs contain no evaluation labels or fixed-variant references.

### T05 — CVSS and independent validation

Owner: validation worker. Dependencies: T00; full integration requires T02 and T03.

Implement vector validation and deterministic scoring, source-coordinate/checksum checks, context assumptions, and verification outcomes with evidence strength. Consume scanner evidence and isolated test results. Reference CVSS vectors and reviewer decisions must remain outside agent-visible inputs.

Acceptance: scoring matches reference examples; invented locations and evidence are rejected; missing metrics remain incomplete; rejected findings need counterevidence; failed tests and unavailable verification remain unresolved. Source-only evidence must not claim demonstrated exploitation.

Accuracy responsibility (ACC-02–04, ACC-06): validate model applicability, context-specific sanitization, policy provenance, and differential observations. Consume independently reviewed reference procedures from T07 for final integration, while implementation can proceed on contract fixtures. Select structural verification where execution cannot establish a property, including applicable unsafe-randomness and hardcoded-secret cases.

Additional gate: wrong-context encoding and invented permission expectations cannot justify rejection; missing/disputed policy remains unresolved. Harness failures and inconclusive checks remain unresolved, and blocked behavior supports only the tested condition. A passing fixed-variant test cannot become a general safety claim. Both students' review of reference observations is required for T07/T08 completion; model-generated tests never define ground truth.

### T06 — Dashboard and reporting

Owner: presentation worker. Dependencies: T00; full integration requires T01, T02, T04, and T05.

Implement the four agreed screens and SARIF/JSON/HTML/Markdown exports through shared services. Show scope, original severity, proposed CVSS, assumptions, verification strength, and failures clearly. Escape untrusted snippets and model output. Provider settings show credential references and masked status, never keys.

Acceptance: Playwright verifies scan submission through report export; CSRF and source-rendering tests pass; report counts reconcile with stored records; unresolved and unprocessed items are distinguishable; JSP findings link to original source positions.

Accuracy responsibility (ACC-01–07): keep the four-screen dashboard minimal while showing Java/JSP coverage separately, limitation reasons, output context, model/policy assumptions, verification strength, and comparative results. Evaluation display integration additionally requires T07 output contracts and fixtures; measured results arrive from T09.

Additional gate: exports preserve all accuracy references and denominators, skipped files never appear analyzed, and dependency findings remain a separate track. Reports distinguish pending experiments from measured results.

### T07 — Dataset, labels, and evaluator

Owner: evaluation worker; the two students supply independent human review. Dependencies: T00; pilot integration requires T02, T03, and T05.

Define case identities and finding-matching rules before measuring results. Prepare a target of three vulnerable/fixed case families per source-code group, with one development family and two held out. Cover both CWE-862 and CWE-639 within the authorization group. Keep dependency cases and naturally occurring findings in separate reported tracks.

Implement metrics and evaluator fixtures, including duplicate observations, zero denominators, unresolved outcomes, scanner failures, and partially labeled natural findings. Do not treat every unlabelled code line as a true negative. Agent-produced labels are proposals only; they cannot substitute for independent reference review.

Acceptance: fixture metrics are hand-checkable; related variants cannot leak across splits; labels are hidden from inference; matching rules and uncertainty treatment are documented; dataset size is recorded as actual rather than assumed to equal the planned target.

Accuracy responsibility (ACC-01–07): own evaluator cases, difficult negatives, matching criteria, family-level splits, per-CWE metrics, and missed-finding analysis. Write reference procedures and security-property definitions in `evaluation/` for both students to review; the coordinator publishes shared policy documents and contracts. Define each applicable CWE's observable condition, legitimate-functionality checks, and execution/structural method. Keep expected labels and pair relationships isolated from scanner/agent inputs.

Additional gate: evaluator fixtures distinguish missing rules, broken extraction, missing models, unsupported flows, incorrect grouping, AI rejection, and verification limitations, allowing multiple contributors or an undetermined cause. Precision, recall, F1, unresolved rate, and verification coverage expose per-CWE and aggregate counts; Java/JSP coverage and dependencies remain separate. Report CWE-862 and CWE-639 separately and as a group. Related regression variants cannot inflate independent sample counts. The planned 24 held-out vulnerable cases imply about 4.17 percentage points per miss; document uncertainty and the descriptive nature of the five-point criterion. Freeze matching, uncertainty treatment, labels, and development-only model tuning before held-out testing; unresolved label disputes remain outside scored ground truth and are counted separately.

### T08 — Integration and protocol freeze

Owner: coordinator. Dependencies: T01–T07.

Run the complete local workflow and a development-only cost/coverage pilot. Resolve integration defects. Freeze tools, rules, model configuration, prompts, input hashes, context policy, labels, evaluator, and comparison definitions before held-out runs. Give deterministic and AI configurations the same declared context for the main comparison.

Acceptance: requirement tests pass; baseline survives provider failure; budget accounting is operational; a second person can reproduce one run; the protocol identifies all excluded or unsupported cases. No pilot tuning may use held-out labels.

Accuracy gate (ACC-01–07): complete detection regression and differential/structural verification checks by weeks 9–12. Freeze extraction/query versions, security models, authorization policy and review status, JSP context support, procedures, case-family splits, matching criteria, uncertainty method, and all comparison configurations. Verify both students reviewed intended permissions and reference security observations independently of model output. Comparable configurations receive the same declared policy/context. Unmet accuracy requirements remain blockers with recorded schedule/budget impact; they cannot be silently waived.

### T09 — Experiments and analysis

Owner: evaluation worker; coordinator schedules runs. Dependencies: T08.

Run standalone tools, the deterministic combination, non-agentic model assessment, bounded agent assessment, and verification ablations. Repeat AI conditions three times within budget. Separate frozen-finding experiments from adaptive rescanning with matched checks/budget. Preserve failed and interrupted run records.

Acceptance: tables regenerate from archived artifacts; recall loss is compared with the five-percentage-point tolerance; undefined metrics and uncertainty are disclosed; the result can reject any research hypothesis. If cost prevents the frozen protocol, report incomplete execution and version any revised protocol rather than silently dropping difficult cases.

Accuracy responsibility (ACC-01–07): run the existing scanner combination versus the same combination plus CodeQL, and generic versus application-specific models on identical revisions with other settings controlled. Evaluate AI assessment using frozen scanner observations, separately from additional detection. Preserve per-scanner detections/misses and perform missed-finding analysis only after the primary held-out evaluation; subsequent tuning is a new experiment.

Additional gate: per-CWE and aggregate tables include counts, unresolved rate, verification coverage, Java/JSP coverage, and uncertainty respecting case-family dependence. Do not attribute all improvement to AI or describe the five-point recall threshold as a statistical guarantee. Record incomplete extraction and experimental CodeQL/JSP limitations alongside comparison results.

### T10 — Reproduction and handover

Owner: coordinator with an independent reviewer. Dependencies: T09.

Deliver setup instructions, the CLI/dashboard demo, manifests, tool configurations, test results, dataset documentation, and generated comparison reports. Connect requirement IDs to evidence. Describe one-application generalization limits and optional-verification coverage.

Acceptance: a collaborator reproduces a baseline and a proposed-system result from documented inputs; application acceptance tests pass; no unsupported completed-result claims remain. Thesis prose updates are a separate task.

Accuracy gate (ACC-01–07): connect every requirement to frozen configurations, regression outcomes, comparative artifacts, and independently reproducible evidence. Document policy uncertainty, reference-test limits, model overfitting, correlated variants, small-sample resolution, and unsupported coverage. A fixed variant passing one test is not general safety evidence; an incomplete experiment remains explicitly incomplete.

## 5. Parallel execution order

| Wave | Tasks | Constraint |
| --- | --- | --- |
| 0 | T00 | Coordinator establishes contracts before implementation branches diverge. |
| 1 | T01, T02, T03 | Independent ownership; use shared fixtures until integration is available. |
| 2 | T04, T05, T07 | Distinct owners; dataset labels stay isolated from inference inputs. |
| 3 | T06; unfinished integration checks from prior tasks | No second writer in an already-owned module. |
| 4 | T08 | Coordinator runs the integration and freeze gate. |
| 5 | T09, then T10 | Serialize measured scans to avoid hardware contention. |

Scheduling waves describe dependency order, not additional weeks beyond the 17-week plan. Early work with mocks is allowed, but completion requires the real acceptance checks stated above.

Within these waves, run T00 cross-file/CodeQL and JSP probes in weeks 1–2, T02 detection improvements in weeks 3–8, and T03/T05/T07 verification/regression integration in weeks 9–12. T05 and T07 may exchange contract fixtures concurrently; T08 requires their real joint acceptance evidence. This avoids a circular implementation dependency while preserving review gates. Keep the dashboard minimal; report feasibility-driven schedule impact instead of dropping ACC requirements. One writer remains assigned to each area, and only the coordinator changes shared contracts.

## 6. Collaboration rules

- You are not alone in the codebase. Do not revert another worker's edits; accommodate them or report a contract conflict.
- Assign one writer per area. The coordinator alone changes shared contracts, dependency manifests/locks, migrations affecting shared data, and root configuration.
- Use isolated branches/worktrees when available. In a shared filesystem, preserve the same ownership boundaries. Do not perform broad formatting or cleanup outside your assignment.
- Send dependency requests to the coordinator instead of independently selecting incompatible library versions.
- Keep changes bounded and reviewable. Commit when the workspace has a Git repository and the coordinator's workflow uses commits; never claim an uncreated commit exists.
- Do not modify the pristine target. Keep experimental mutations and generated tests in dedicated overlays or variant copies with recorded provenance.
- A successful tool call is not a passed acceptance gate. Report actual checks, results, and limitations.
- Archive visible tool actions, evidence, and concise rationales; do not require private model reasoning traces for reproducibility.
- Never mark a task complete while its required integration check remains mocked, skipped, or blocked.

## 7. Copyable coordinator startup prompt

```text
Read .planning/README.md, .planning/PROJECT-PLAN.md, and
.planning/AGENT-HANDOFF.md, plus root AGENTS.md if present.

Implement this project according to the agreed scope. Start with T00.
Do not change the thesis, broaden the target-language scope, or claim
experimental results before running the experiments.

Establish the SRS, shared contracts, source revision, and build feasibility
first. Then assign bounded tasks using the ownership table and dependency
waves. If parallel agents are available, reserve one coordinator slot and
use at most three independent workers at once. Do not delegate dependent
implementation before its contracts exist.

Maintain task status with evidence and unresolved blockers. Preserve
baseline scanning when AI is unavailable. Keep hidden evaluation labels
out of all scanner and model inputs. Enforce budgets and independent
validation. Complete integration, protocol freeze, experiments, and
reproduction gates in order.
```

## 8. Copyable worker assignment

```text
Task: <Txx and title>
Owner: <agent or collaborator>
Dependencies completed: <task IDs and evidence>
Owned paths: <exclusive paths from the ownership table>
Required contracts: <schema versions and relevant SRS requirements>
Acceptance criteria: <copy the task's criteria>

Read the planning package and applicable AGENTS.md instructions first.
You are not alone in the codebase. Do not revert others' edits or write
outside your ownership. Request shared-contract/dependency changes from
the coordinator. Use existing contracts and preserve source provenance.

Return: changed files, requirement IDs satisfied, exact checks and their
outcomes, integration requirements, remaining limitations, and commit ID
if a commit was actually created. Do not call the task complete unless its
acceptance criteria pass.
```

## 9. Handoff record template

```text
Task ID:
Status: pending | in_progress | blocked | ready_for_review | complete
Owner:
Dependencies:
Changed files:
SRS requirement IDs:
Contract versions:
Checks run and outcomes:
Artifacts / commit reference:
Known limitations:
Next consumer and required integration:
```

Planning package creation does not mark any T00–T10 task complete.
