# Laya Decision-Routing Architecture Plan

**Date:** 2026-09-23
**Status:** In progress — compatibility verified against `laya==0.3.20`; adapter/router implemented; shadow pipeline, T09 experiments, and T10 reproduction pending
**Project:** DevSecOps-Agent
**Target:** JVA-bookstore at `dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5`
**Implementation checkpoint:** T06 committed as `6de8693`

## 1. Goal

Add Laya as an optional local GPU decision router to improve analysis speed, prioritization, uncertainty detection, and human decision support without weakening the project's evidence and validation guarantees.

The authoritative processing architecture is:

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

Laya must never replace scanners, ground-truth labels, `IndependentValidator`, or the final human decision. It may only produce advisory typed decisions and routing recommendations.

## 2. Current baseline

- T00–T07 have implementation-level coverage and the current local suite passes 117 tests.
- T06 dashboard/reporting is implemented at unit/API level; browser E2E and integration gates remain pending.
- T08 integration/protocol freeze, T09 experiments, and T10 reproduction/handover remain incomplete.
- Existing AI uses a bounded OpenAI-compatible `ProviderClient` for text/tool investigation. Laya uses a separate decision-backend interface because it is a non-autoregressive typed-decision model, not a chat endpoint.
- Current final finding status ownership belongs to `IndependentValidator`; this boundary must remain unchanged.

## 3. Architecture principles

1. **Deterministic first:** scanners, normalization, source coordinates, sanitizer/policy/output-context extraction remain authoritative inputs.
2. **Laya second:** Laya receives a redacted, normalized evidence envelope and returns typed probabilities.
3. **Targeted analysis third:** routing selects only the relevant deep-analysis path, reducing unnecessary LLM calls and latency.
4. **Independent validation fourth:** mechanical evidence, not Laya confidence, owns `confirmed`, `rejected`, and `unresolved` transitions.
5. **Human support last:** the UI presents probabilities, route, evidence completeness, counterevidence, and uncertainty so an analyst can make an informed decision.
6. **Fail safe:** model load failure, GPU OOM, timeout, malformed output, or missing package falls back to the baseline scanner result; the scan must not be lost or silently downgraded.
7. **No label leakage:** Laya never receives ground truth, split membership, fixed-variant references, or hidden evaluation metadata.
8. **No unsafe automation in the first release:** Laya starts in shadow/advisory mode and cannot change final status.

## 4. Processing flow

```text
Scanner adapters
  Semgrep / SpotBugs / Dependency-Check / Gitleaks / CodeQL-experimental
        ↓
Normalization, deduplication, grouping
        ↓
Source index, Java/JSP context, deterministic evidence gate
        ↓
Redacted normalized evidence envelope
        ↓
Laya GPU worker
  choice / score / noul questions
  batched, lazy-loaded, cached
        ↓
Decision route
  fast verification | cross-file | authorization | JSP | dependency | human review
        ↓
Targeted deep analysis
  source graph | sanitizer/policy extraction | JUnit/security harness | bounded AI
        ↓
IndependentValidator
  mechanical evidence and counterevidence
        ↓
Final finding status
  confirmed | rejected | unresolved | unprocessed
        ↓
Dashboard, reports, experiment evaluator
        ↓
Human decision support
  priority, uncertainty, rationale from deterministic evidence, user override
```

## 5. Laya responsibility and prohibitions

### Laya is responsible for

- `likely_true_positive` advisory probability.
- `recommended_action`/`route` classification.
- `review_priority` ordinal score.
- `needs_human_review` uncertainty probability.
- Optional `cross_file_review_needed` or `jsp_context_review_needed` triage signal.
- Batch-level latency and availability metrics.

### Laya is prohibited from

- Creating scanner findings from scratch.
- Confirming or rejecting a finding.
- Creating or selecting a CVSS vector.
- Replacing source-to-sink, authorization, encoding, or harness evidence.
- Reading ground truth, labels, split membership, fixed-variant references, or secrets.
- Making autonomous remediation changes.
- Running inside the isolated verification sandbox or receiving network access there.
- Replacing the evaluator or generating ground-truth labels.

## 6. New module boundaries

Create the following modules during T08:

```text
src/vulnscan/decisions/
├── __init__.py
├── base.py          # DecisionBackend protocol
├── contracts.py     # typed request/answer/result contracts
├── router.py        # route policy and baseline fallback
├── laya.py          # local Hugging Face adapter
└── state.py         # redaction and normalized evidence envelope

src/vulnscan/pipeline/
├── __init__.py
├── scan_pipeline.py
├── laya_triage.py   # stage orchestration
└── verification_dispatch.py

tests/decisions/
├── test_decision_contracts.py
├── test_laya_backend.py
├── test_laya_routing.py
├── test_laya_failure_modes.py
└── test_laya_redaction.py
```

Do not put Laya in `ProviderClient`; its protocol and output are not OpenAI Chat Completions compatible.

## 7. Contract design

Add a small decision contract with the following conceptual fields:

```text
DecisionQuestion:
  name, type(choice|score|noul), instructions, criteria

DecisionRequest:
  questions, normalized_state, model_policy, state_hash

DecisionAnswer:
  name, type, choice/score/noul, probabilities, confidence

DecisionResult:
  backend, model_id, model_revision, device, status,
  answers, latency_ms, input_truncated, state_hash,
  question_set_version, error_code, created_at
```

Status values must distinguish:

```text
completed
unavailable
incomplete
failed
```

A malformed or unavailable Laya result must not be serialized as a successful decision.

## 8. Laya state envelope

The state sent to Laya must be deterministic, English-oriented where possible, redacted, and bounded to 512 tokens per question. Initial fields:

```json
{
  "finding_id": "stable-id",
  "cwe_category": "CWE-89",
  "scanner": "semgrep",
  "rule_id": "java.sql.injection",
  "severity": "HIGH",
  "source_path": "src/main/java/...",
  "source_line": 42,
  "sink_type": "sql_execute",
  "source_type": "http_parameter",
  "sanitizer_detected": false,
  "authorization_context": "unknown",
  "output_context": "html_text",
  "evidence_count": 1
}
```

Never send credentials, environment secrets, full unnecessary repository content, ground truth, fixed-variant references, or evaluation labels. Record `input_truncated=true` when the 512-token limit is reached.

## 9. Routing policy

Initial routes:

```text
fast_verification
cross_file_analysis
authorization_analysis
jsp_context_analysis
dependency_analysis
secret_review
human_review
baseline_fallback
```

Initial advisory thresholds are configuration, not validated project claims:

- `>= 0.85`: high-confidence route signal; targeted analysis may be scheduled.
- `0.60–0.85`: additional analysis or human review.
- `< 0.60`: do not automate; retain finding as unresolved.
- `unavailable/failed/malformed`: baseline fallback; no automated decision.

Thresholds must be recalibrated on JVA-bookstore in T09 before they can affect workflow decisions.

## 10. GPU and performance plan for RTX 3050 4 GB

- Run Laya in a dedicated worker process; keep Maven, scanners, parsing, hashing, and API work in the main process.
- Lazy-load the model once, warm it with a small fixed input, then measure steady-state latency separately from model load time.
- Batch findings sharing the same question-set version; do not issue one model call per finding.
- Benchmark FP32, FP16, and any supported quantized mode. Select a mode only after comparing latency, memory, output validity, ECE, Brier score, and route quality.
- Cache by canonical normalized state hash plus model revision and question-set version.
- Pre-filter only deterministic cases that are provably not eligible for Laya; do not discard findings merely because Laya is uncertain.
- Record p50/p95 latency, model load time, throughput, GPU memory, CPU fallback rate, OOM rate, and malformed-output rate.
- Keep `enabled=false` by default. Enable only in an explicit experiment profile.

## 11. Configuration and security

Proposed file:

```text
config/laya.json
```

Initial fields:

```json
{
  "enabled": false,
  "mode": "shadow",
  "model_id": "convaiinnovations/laya",
  "revision": null,
  "device": "auto",
  "batch_size": 4,
  "max_input_tokens": 512,
  "timeout_seconds": 30,
  "cache_enabled": true,
  "high_confidence_threshold": 0.85,
  "review_threshold": 0.60,
  "affects_finding_status": false
}
```

Model weights and HF snapshots stay outside Git, under a user-local cache. Pin the model revision before experiments. Keep Laya an optional dependency until the compatibility spike proves package/API/Python/CUDA compatibility.

## 12. Implementation phases

### Phase 1 — Compatibility spike (T08 preparation)

- Verify the actual `laya` package and API on the current environment.
- Pin the Hugging Face model revision and inspect license/config files.
- Load the model on RTX 3050 4 GB.
- Run one `choice`, one `score`, and one `noul` prompt.
- Measure cold load, warm inference, batch throughput, peak memory, and output shape.
- Confirm CPU fallback and timeout behavior.
- Do not change the production pipeline in this phase.

### Phase 2 — Adapter and router (T08)

- Add decision contracts and fake backend.
- Implement lazy-loaded `LayaDecisionBackend`.
- Implement redaction and canonical state hashing.
- Implement route policy and baseline fallback.
- Add structured error handling for missing package, OOM, timeout, and malformed output.
- Add unit tests with mocked `laya.load()` and `agent.predict()`.

### Phase 3 — Shadow integration

- Add the Laya stage after deterministic evidence preparation.
- Run it in advisory mode only.
- Preserve scanner findings and final status behavior.
- Persist result metadata and evidence references.
- Add dashboard/report fields for route, confidence, model revision, truncation, and availability.
- Add a visible fallback/unavailable state.

### Phase 4 — Protocol freeze (T08 gate)

Freeze:

- Decision contracts and versioning.
- Model revision and dependency versions.
- Question-set version.
- Redaction rules.
- Timeout and fallback behavior.
- Threshold semantics.
- Artifact and evidence schema.
- Human override semantics.
- ACC-01–07 traceability updates.

### Phase 5 — Experiments (T09)

Compare:

```text
Baseline scanner pipeline
Laya advisory routing
Laya routing + targeted deep analysis + existing AI + IndependentValidator
```

Measure:

- Precision, recall, F1, macro F1.
- ECE, Brier score, reliability diagrams.
- Route accuracy and false escalation rate.
- Human-review workload and review time.
- P50/P95 latency and throughput.
- GPU memory and model-unavailable rate.
- Recall loss versus the five-point tolerance.
- Calibration by CWE, scanner, Java/JSP, dependency, authorization, and cross-file groups.

### Phase 6 — Reproduction and handover (T10)

- Lock optional dependencies and model revision.
- Record model/config checksums.
- Provide exact local commands for RTX 3050 4 GB.
- Reproduce baseline, Laya, and full-system results on a clean environment.
- Document CPU fallback, model limitations, threshold rationale, and unresolved cases.
- Update final report and evidence manifest.

## 13. Acceptance criteria

### Architecture

- Laya is a separate optional decision backend, not a chat provider.
- Laya receives only redacted normalized evidence.
- Laya output is advisory and cannot mutate final finding status.
- Baseline works when Laya is disabled, unavailable, malformed, or out of memory.
- Final status is owned only by `IndependentValidator` and mechanical evidence.

### Performance

- Model loads once and supports warm/batch inference.
- GPU worker does not block scanner/API processing.
- Cache and pre-filter reduce unnecessary calls.
- Latency and memory are measured on RTX 3050 4 GB.

### Quality

- Accuracy and calibration are measured on project-specific held-out data.
- No claim relies solely on Laya's published benchmark.
- Human review receives probabilities, route, evidence completeness, and uncertainty.
- ACC-01–07 are updated with Laya-specific test/evidence mappings without changing their original ownership.

### Security

- No credentials or labels enter Laya state.
- No model output is treated as executable instruction.
- No network is enabled in the verification sandbox.
- Model/cache files are excluded from Git.

## 14. First implementation slice

After confirmation, begin with the compatibility spike only. Deliverables:

1. A reproducible local smoke script outside the production pipeline.
2. Verified model revision and dependency/API findings.
3. A measured RTX 3050 compatibility report.
4. No changes to final statuses, reports, or production routing until the spike passes.

## 15. Open decisions

- Exact Hugging Face model commit to pin.
- Whether the published package supports a stable Python 3.11 installation.
- Whether the implementation supports batched states directly or requires an adapter-side batch loop.
- Whether FP16 or another quantization is safe for calibration.
- Whether Laya can accept a compact code-context state without reducing route quality.
- Whether human feedback can later be used for calibration without contaminating held-out evaluation.

## 16. Definition of done

The Laya integration is complete only when the compatibility spike, adapter tests, shadow integration, protocol freeze, project-specific experiments, and clean reproduction all pass. A successful model load or a passing unit-test suite alone is not sufficient.
