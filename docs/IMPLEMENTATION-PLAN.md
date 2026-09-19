# Implementation Plan — DevSecOps-Agent

**Version:** 1.0
**Status:** Draft (T00)
**Related:** [SRS.md](SRS.md), [TEST-PLAN.md](TEST-PLAN.md), [../.planning/AGENT-HANDOFF.md](../.planning/AGENT-HANDOFF.md)

---

## 1. Ownership

| Area | Owner | Exclusive paths |
|------|-------|-----------------|
| Requirements, shared contracts, dependencies, integration | Coordinator | `docs/`, `src/vulnscan/contracts/`, `pyproject.toml`, lockfile, CI |
| Intake, database, job lifecycle, CLI | Platform | `src/vulnscan/core/`, `src/vulnscan/storage/`, `src/vulnscan/cli/`, `tests/platform/` |
| Tool adapters, normalization, source index | Analysis | `src/vulnscan/scanners/`, `src/vulnscan/normalization/`, `src/vulnscan/context/`, `rules/`, `tests/analysis/` |
| Providers and bounded agent | AI | `src/vulnscan/providers/`, `src/vulnscan/agent/`, `prompts/`, `tests/ai/` |
| CVSS and independent evidence validation | Validation | `src/vulnscan/assessment/`, `src/vulnscan/verification/`, `tests/validation/` |
| Container execution and target harness | Sandbox | `infra/`, `harness/`, `tests/sandbox/` |
| Dashboard and reports | Presentation | `src/vulnscan/web/`, `src/vulnscan/reporting/`, `tests/web/`, `tests/reporting/` |
| Dataset protocol and evaluator | Evaluation | `evaluation/`, `tests/evaluation/` |

Workers are roles, not a requirement to launch seven agents. With four agent slots: 1 coordinator + at most 3 independent workers. Never two writers in the same ownership area concurrently.

## 2. Dependency graph

```
T00 ──┬──> T01 ──┐
      ├──> T02 ──┼──> T04 ──┐
      └──> T03 ──┘    T05 ──┼──> T06 ──> T08 ──> T09 ──> T10
                       T07 ──┘
```

- T01/T02/T03 start on T00 contracts (Wave 1).
- T04/T05/T07 start on T00 contracts; full integration needs Wave 1 outputs (Wave 2).
- T06 needs T01/T02/T04/T05 (Wave 3).
- T08 needs T01–T07 (Wave 4). T09 needs T08 (Wave 5). T10 needs T09.
- T05 and T07 may exchange contract fixtures concurrently; T08 requires their real joint acceptance evidence.

## 3. Wave execution

| Wave | Tasks | Constraint |
|------|-------|-----------|
| 0 | T00 | Coordinator establishes contracts before implementation branches diverge. |
| 1 | T01, T02, T03 | Independent ownership; shared fixtures until integration exists. |
| 2 | T04, T05, T07 | Distinct owners; dataset labels isolated from inference inputs. |
| 3 | T06; unfinished integration checks | No second writer in an owned module. |
| 4 | T08 | Coordinator runs integration and freeze gate. |
| 5 | T09, then T10 | Serialize measured scans to avoid hardware contention. |

## 4. 17-week schedule

| Weeks | Deliverable and gate |
|-------|---------------------|
| 1–2 | SRS with ACC-01–07, shared contracts, pinned source, container prerequisites, reproducible build attempt, CodeQL cross-file and JSP feasibility probes, independent policy assumptions. |
| 3–4 | CLI, durable worker, Semgrep adapter, immutable artifacts, coverage records, initial detection-rule regression fixtures. |
| 5–6 | Remaining + experimental CodeQL adapters, JSP output contexts/mappings, normalization, security models, baseline reports. |
| 7–8 | Complete detection/model improvements, policy-aware context extraction, CVSS validation, minimal dashboard, BYOK configuration. |
| 9–10 | Bounded agent, independent validation, reviewed differential function-test procedures, structural checks, optional sandbox checks. |
| 11–12 | Complete verification/regression gates, reviewed case-family dataset, evaluator tests, cost pilot, frozen experimental protocol. |
| 13–14 | Held-out comparisons, repeated AI runs, verification ablations. |
| 15–16 | Reproducible tables, limitations, requirement traceability, demonstration preparation. |
| 17 | Independent reproduction, regression fixes, final handover. |

In-wave timing: T00 cross-file/CodeQL + JSP probes in weeks 1–2; T02 detection improvements weeks 3–8; T03/T05/T07 verification/regression integration weeks 9–12.

## 5. Task summary

| ID | Task | Owner | Deps | Key acceptance |
|----|------|-------|------|---------------|
| T00 | Requirements, feasibility, contracts | Coordinator | — | SRS + contract fixtures; build feasibility logged; ACC-01–07 mapped to tests/owners. |
| T01 | Platform, persistence, CLI | Platform | T00 | Fake adapter run; restart history; failed/partial visible; artifact identity; CLI tests. |
| T02 | Scanner adapters, normalization | Analysis | T00 (+T01, T03 for E2E) | Fixture parse + real smoke scan or documented unavailable; grouping provenance; same-CWE distinct; ACC-01–05, ACC-07. |
| T03 | Isolated build, verification runner | Sandbox | T00 (+T05, T07 for differential) | Timeouts/cleanup; denied external access; credential separation; disposable DB; failure-injection distinction. |
| T04 | BYOK providers, bounded agent | AI | T00 (+T01–T03) | Fake-provider edge cases; budget enforcement; injection resistance; proposals retain uncertainty. |
| T05 | CVSS, independent validation | Validation | T00 (+T02, T03) | Scoring vs reference; invented evidence rejected; missing metrics incomplete; counterevidence required. |
| T06 | Dashboard, reporting | Presentation | T00 (+T01, T02, T04, T05) | Playwright scan→export; CSRF; counts reconcile; JSP position links; masked keys. |
| T07 | Dataset, labels, evaluator | Evaluation | T00 (+T02, T03, T05 pilot) | Hand-checkable metrics; split enforcement; labels hidden; matching documented; actual dataset size. |
| T08 | Integration, protocol freeze | Coordinator | T01–T07 | Requirement tests; baseline survives provider failure; budget operational; reproduction by second person. |
| T09 | Experiments, analysis | Evaluation | T08 | Tables regenerate; recall loss vs 5-point tolerance; undefined metrics disclosed; hypothesis may fail. |
| T10 | Reproduction, handover | Coordinator + reviewer | T09 | Collaborator reproduces baseline + proposed-system runs; no unsupported claims. |

## 6. Budget allocation

| Reserve | USD | Purpose |
|---------|-----|---------|
| Pilot / provider setup | 10 | Feasibility probes, provider configuration, development-only runs. |
| Frozen experiments | 30 | Held-out comparisons, 3× AI repeats, ablations. |
| Reruns | 10 | Failure recovery, disputed-case re-evaluation. |
| **Total** | **50** | Record prices and usage; unknown pricing requires configuration before paid requests. |

## 7. Risk register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| JVA-bookstore build fails on host toolchain | Medium | High | Establish pinned toolchain versions in T00; version any build overlay separately; record environmental blocker explicitly. |
| CodeQL extraction infeasible locally | Medium | Medium | Remains experimental; ACC-01 does not require it — baseline cross-file work covers the gate. |
| JSP precompilation fails for some files | Medium | Medium | Failed compilation stays visible as incomplete coverage (ACC-04); no silent skip. |
| Docker unavailable on host | High (observed) | High | T03 must support a documented unavailable condition; sandbox-level verification becomes opt-in; ACC-06 structural evidence path used where execution unsuitable. |
| Provider budget exceeded | Low | Medium | Enforce token/time/cost limits before requests; provider failure → unresolved assessment, findings preserved. |
| Label disputes unresolved | Medium | Medium | Excluded from scored ground truth; counted and reported separately. |
| Small-sample metrics over-interpreted | Medium | Medium | Predeclared uncertainty method; case-family grouping; 5-point criterion labeled descriptive. |
| Schedule slip in accuracy work | Medium | Medium | Report affected ACC IDs + schedule/budget impact; never silently drop requirements. |
| Context extraction ambiguous calls | High | Low | Ambiguous resolution stays explicit in context evidence. |

## 8. Collaboration rules

- Do not revert another worker's edits; accommodate or report a contract conflict.
- One writer per area; coordinator alone changes shared contracts, dependency manifests/locks, shared migrations, root config.
- Send dependency requests to the coordinator.
- Commit when the workspace uses commits; never claim an uncreated commit exists.
- Do not modify the pristine target; mutations live in overlays/variants with recorded provenance.
- A successful tool call is not a passed acceptance gate.
- Archive visible tool actions, evidence, and rationale; private model reasoning is not required for reproducibility.
- Never mark a task complete while its required integration check is mocked, skipped, or blocked.

## 9. Completion criteria

Completion requires:

1. Working scan-to-report workflow.
2. Honest coverage and failure reporting.
3. Machine-validated AI assessments.
4. Experimental tables reproducible from archived evidence.
5. ACC-01–07 traceability.
6. Frozen model/policy/procedure versions.
7. Accuracy regression checks passed.
8. Controlled comparative results.
9. Independently reproducible evidence or explicitly incomplete experiments.

All measured results come from executed experiments; planned values remain clearly labeled. Unmet accuracy requirements are blockers with recorded schedule/budget impact — they cannot be silently waived.
