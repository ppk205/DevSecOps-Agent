# Implementation Plan — DevSecOps-Agent

**Version:** 1.2
**Status:** In progress — T00–T10 implemented; T09 evaluated on JVA-bookstore
**Related:** [SRS.md](SRS.md), [TEST-PLAN.md](TEST-PLAN.md), [../.planning/AGENT-HANDOFF.md](../.planning/AGENT-HANDOFF.md), [Laya decision-routing plan](../.hermes/plans/2026-09-23_000000-laya-decision-routing.md)

---

## 1. Ownership

Remote integration (2026-11-05): combine `my_tool_call` at `d082435` and
`lane-hunt-recall` at `1cab83d` with the local workflow/CVSS/report commits and
pending native-language coverage fixes. Both remote tips are retained in merge
history. The original dirty checkout is preserved in place; work uses a separate
integration worktree and branch. No dependency or model installation is needed.
See [REMOTE-INTEGRATION-2026-11-05.md](REMOTE-INTEGRATION-2026-11-05.md) for
executed checks, source/environment isolation and remaining limits.

Validation/scoring correction (2026-11-04, FR-50/53/56): the validator now
requires scoped independent evidence with explicit polarity and provenance for
terminal status. Model confidence, raw detections, duplicate identities,
conflicting evidence and incomplete/fixed-variant procedures cannot provide
confirmation. The current evidence adapter labels scanner/model records as
non-independent; a general semantic source verifier is still not implemented.

CVSS uses pinned FIRST v4.0 MacroVector tables/interpolation, strict syntax and
eleven Base metrics. Base and contextual scores are separate; incomplete input
remains unscored. Assessment construction recomputes numbers, and both review
paths preserve vector assumptions and score errors. Finding metadata retains
the assessment/decision. A parsed explicit verdict no longer triggers a second
model call merely because its extracted rationale omitted the JSON wrapper.
These changes add no dependency or automatic source-verification capability.
See [VALIDATOR-CVSS.md](VALIDATOR-CVSS.md).

Report update (2026-11-04, FR-61/68): `reporting/owasp.py` bundles OWASP Top
10:2025 category-specific mapped-CWE lists. The shared report generator adds
the same cross-reference to human formats and JSON/SARIF metadata. Primary and
secondary normalized labels participate; each category counts a finding once.
Per-CWE rows preserve finding IDs and status counts. Exact unmapped labels stay
unmapped, and empty categories do not establish coverage. The final narrative
appends the deterministic section after any model response or fallback. This
adds no scanners, dependency, provider call or finding-status decision. Reference
sources and regeneration instructions are in [OWASP-REPORTING.md](OWASP-REPORTING.md).

Notification implementation update (2026-11-04, SRS FR-75): shared Python
delivery creates one digest per run/destination. ScanService invokes it after
terminal persistence; native deterministic completion invokes the same service
over version-1 JSONL. SQLite migration 7 adds a delivery ledger with a unique
run/channel key and atomic send claims. Pending, sending, sent, failed, unknown
and unconfigured outcomes remain separate from scan/finding status. Preferences
store environment references only. CLI, native/Textual F6/F7 and the dashboard
offer event selection. Defaults disable delivery; no old drafts are flushed on
settings saves or reads. Offline tests replace only HTTP transport, while native
integration exercises the actual EXE, bridge, digest creation and payloads.

Current implementation update (2026-11-04): the native EXE now routes Hunt,
AI-review and AI-report scans through the existing Python ScanService. Native
deterministic execution remains available. Both paths use the shared database,
run identity, history, reports and cancellation boundaries. AI retries preserve
the saved configuration and use the Python retry path.

Workspace exposes scan mode, provider/model choices and bounded review settings.
Effective review shows provider readiness. Activity records call/tool progress
and returned explanations; finding details retrieve assessments for the matching
run and finding. Provider message serialization now includes tool-call IDs and
the selected model. Profiles resolve from the same project root as EnvFile.

Verification uses synthetic HTTP responses through the real EXE/bridge/parser
and investigation loop. This establishes execution and display behavior. Live
provider health, model accuracy, monetary price estimates, full prompt transcripts
and token-by-token streaming remain outside the verified implementation. Actual
checks and remaining failures are recorded in
[NATIVE-AI-VERIFICATION-2026-11-04.md](NATIVE-AI-VERIFICATION-2026-11-04.md).

These additions trace to SRS FR-48/49/71, IR-11/12/13 and QR-21. The historical
task results below retain their original evidence and limitations.

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

```text
Deterministic evidence
        ↓
Laya batch routing
        ↓
Targeted deep analysis
        ↓
Independent validation
        ↓
Human decision support
```

The pipeline stages are: scanner adapters → normalization/deduplication/source context → deterministic evidence envelope → optional Laya GPU decision router → targeted deep-analysis worker → `IndependentValidator` → final status and human decision workspace.

Laya is an optional advisory backend, not a scanner, provider replacement, ground-truth source, final-status owner, or CVSS generator. See [the detailed Laya plan](../.hermes/plans/2026-09-23_000000-laya-decision-routing.md).

### T09 result — Laya advisory routing on JVA-bookstore

29 findings from `dd48d12`, 25 false positives and 4 true positives (missing
subresource-integrity on third-party CDN scripts).

```text
route_accuracy        0.724   (21/29)
false_escalation_rate 0.000
ECE                   0.339
Brier                 0.245
```

```text
expected -> actual                n  verdict
low_priority     -> low_priority  21  false_positive
low_priority     -> human_review   4  false_positive
dependency_analysis -> low_priority 4  true_positive
```

Labels are lane names (one of the eight Laya lanes), derived by reading the
source at each reported line. They were produced by the agent that built the
pipeline, so these figures are **not independent validation of Laya** and must
not be cited as such; `evidence/t09/eval_agentlabels.json` records that caveat
alongside the numbers.

What this run does and does not show:

- **Every true positive was routed to `low_priority`.** Laya has no signal for
  third-party script provenance, so the one finding class that matters most is
  the one it misses. `false_escalation_rate = 0.0` measures only unwanted
  escalation and says nothing about this; false negatives are not measured.
- ECE 0.339 means self-reported confidence (mean 0.529) is poorly calibrated
  against the achieved accuracy.
- n=29 on one project. Not a general accuracy estimate.
- Router policy was corrected during T09: it previously escalated on Laya's
  self-reported confidence alone, which rewrote 18 of 29 routes and destroyed
  the model's own signal. It now decides on the probability distribution.

---

## 3. Wave execution

| Wave | Tasks | Constraint |
|------|-------|-----------|
| 0 | T00 | Coordinator establishes contracts before implementation branches diverge. |
| 1 | T01, T02, T03 | Independent ownership; shared fixtures until integration exists. |
| 2 | T04, T05, T07 | Distinct owners; dataset labels isolated from inference inputs. |
| 3 | T06; unfinished integration checks | No second writer in an owned module. |
| 4 | T08 — integration, Laya compatibility/adapter/protocol freeze | Coordinator + AI | Laya is optional and shadow/advisory by default; baseline remains operational without it. |
| 5 | T09, then T10 | Evaluate baseline, Laya routing, and full system; reproduce on a clean environment; no unsupported claims. |

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
| T08 | Integration, Laya compatibility/adapter, protocol freeze | Coordinator + AI | T01–T07 | Baseline survives provider/Laya failure; budget operational; redaction/routing contracts frozen; GPU/CPU behavior documented; full integration evidence present. |
| T09 | Experiments, analysis | Evaluation | T08 | Baseline/Laya/full-system tables regenerate; route quality and calibration measured; recall loss vs 5-point tolerance; undefined metrics disclosed; hypothesis may fail. |
| T10 | Reproduction, handover | Coordinator + reviewer | T09 | Clean reproduction of baseline, Laya routing, and proposed system; pinned model revision; no unsupported claims; final limitations and evidence manifest. |

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
