# Reproduction — DevSecOps-Agent + Laya advisory routing

Reference machine: **Windows 11, RTX 3050 Laptop GPU (4 GB), Python 3.11.15**.
Every number quoted below was measured on that machine; none are projected.

## 1. Environment

```bash
cd "D:/New folder/DevSecOps-Agent"
python -m venv .venv
.venv/Scripts/python.exe -m pip install -U pip
.venv/Scripts/python.exe -m pip install -r requirements.lock.txt
.venv/Scripts/python.exe -m pip install -e ".[dev]"
```

`requirements.lock.txt` is a `pip freeze` of the verified environment. It pins
`torch==2.6.0+cu124`, so the file carries
`--extra-index-url https://download.pytorch.org/whl/cu124` — the local version
tag is not on PyPI. If you want CPU-only, install plain `torch` instead and
record the substitution; the pipeline still runs, slower.

To capture the environment again:

```bash
PYTHONPATH=src bash scripts/record_environment.sh
```

Writes `evidence/environment/pip-freeze.txt` plus the model revision, the
device name, and the `config/laya.json` checksum.

## 2. Frozen decisions

`src/vulnscan/decisions/protocol.py` is the single source of truth:

| Item | Value |
|---|---|
| Contract version | `decision-contract-1` |
| Question set version | `laya-questions-1` |
| Model | `convaiinnovations/laya` |
| Model revision | `aa8c91ca088ec597df95a0d1c76b3063cb2ae5e8` |
| License | Apache-2.0 |
| Status owner | `IndependentValidator` |

## 3. Three runs

`config/laya.json` ships **disabled**; a test enforces that. Enable advisory
routing with the CLI flag, never by editing the file.

### Baseline — no model

```bash
PYTHONPATH=src .venv/Scripts/python.exe -m vulnscan.cli.main scan-run \
  --repo https://github.com/juicesecurity/JVA-bookstore \
  --commit dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5 \
  --checkout "D:/New folder/DevSecOps-Agent/harness/JVA-bookstore" \
  --out artifacts/baseline
```

### Laya advisory routing

```bash
PYTHONPATH=src .venv/Scripts/python.exe -m vulnscan.cli.main scan-run \
  --repo https://github.com/juicesecurity/JVA-bookstore \
  --commit dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5 \
  --checkout "D:/New folder/DevSecOps-Agent/harness/JVA-bookstore" \
  --out artifacts/t09 --laya
```

### Grading — requires ground truth

```bash
PYTHONPATH=src .venv/Scripts/python.exe -m vulnscan.cli.main laya-evaluate \
  --scan artifacts/t09/export-<id>.json \
  --truth evidence/t09/ground_truth.json \
  --out evidence/t09/experiment_record.json
```

**Currently blocked.** `evidence/t09/ground_truth.json` has an empty `rows`
array and `"adjudicated": false`. Until an independent adjudicator labels
which findings deserve escalation, every graded metric serialises as
`null` — not `0`. That is deliberate: a zero would read as a measured
0% result.

## 4. Measured results

### GPU (Phase 1 spike)

```text
python 3.11.15 · torch 2.6.0+cu124 · laya 0.3.20
cuda_available: true · NVIDIA GeForce RTX 3050 Laptop GPU · 4096 MiB
model load        9196 ms
single state      p50 73.6 ms · p95 80.6 ms · mean 74.5 ms (20 iterations)
peak GPU          2336 MiB
batch 1           74.2 ms/state
batch 4           196.5 ms total → 49.1 ms/state, 2401 MiB
```

GPU is ~93× faster than the CPU path (6868 ms → 73.6 ms per state). Peak
memory is 2336 of 4096 MiB, so batch 4 fits; larger batches will not.

### CPU fallback (measured, not projected)

```text
requested_device: cpu · resolved_device: cpu · peak_gpu_mib: 0
model load        49 769 ms
single state      p50 6868 ms · p95 7248 ms · mean 6818 ms (3 iterations)
batch 4           24 892 ms total → 6223 ms/state
```

**Operational consequence:** at the default `batch_size: 4`, a CPU chunk takes
~25 s against a `timeout_seconds: 30` budget. That is inside the limit but
with almost no margin — one slow chunk, or a larger batch, will trip the
timeout and route those findings to `baseline_fallback`. On CPU, either lower
`batch_size` to 2–3 or raise `timeout_seconds`. GPU is unaffected.

### Scan + routing

```text
29 findings · CWE-89 ×11, CWE-79 ×13, UNCLASSIFIED ×5
laya routed        29/29 · unavailable 0
affects_finding_status  false
routes              human_review 18 · low_priority 11
```

## 5. Failure modes and what happens

| Condition | Behaviour |
|---|---|
| `laya` not installed | stage skipped, `error_code: package_missing`, baseline intact |
| model load fails | `error_code: model_unavailable`, baseline intact |
| inference timeout | `error_code: timeout`, per-finding fallback |
| GPU OOM | `error_code: out_of_memory`, baseline intact |
| unparseable output | `error_code: malformed_output`, finding gets `baseline_fallback` |
| CPU-only torch | runs, ~93× slower per state; raise `timeout_seconds` or lower `batch_size` |

Every path above leaves the finding set and all statuses unchanged. The
pipeline never depends on the model being present or correct.

## 6. Model limitations — read before quoting any number

Laya prints this at load, and it matters:

```text
RuntimeWarning: laya: this checkpoint ships invalid temperatures or values
outside [0.5, 5]; using choice:11+=0.1005... -> 0.5. Treat confidence from
the affected entries as uncalibrated.
```

The checkpoint's temperature is below the valid floor and gets clamped.
Consequences:

- **Reported confidence is not a probability.** Do not present it as one.
- T09's ECE/Brier exist precisely to measure that gap on project data.
- The clamp is a property of the pinned revision, not of this integration.
  Changing the revision invalidates every calibration number recorded so far.

## 7. Threshold rationale

`HIGH_CONFIDENCE_THRESHOLD 0.85`, `REVIEW_THRESHOLD 0.60`,
`ESCALATION_FLOOR 0.50` in `protocol.py` are **starting configuration, not
validated claims**. They were chosen before any project-specific data
existed. §9 of the plan requires them to be recalibrated on JVA-bookstore in
T09 before they can influence workflow decisions — that has not happened yet,
because T09 has no ground truth.

The conservative default is to leave them alone and keep routing advisory.

## 8. Unresolved cases

- 5 of 29 findings have no CWE label in the semgrep output. They are
  reported as `CWE-UNCLASSIFIED`, which is a real value, not a missing field.
- Route distribution shifted from `low_priority 21 / human_review 8` to
  `human_review 18 / low_priority 11` when CWE extraction was fixed. Ten
  findings changed decision because of one field-parsing bug, which is
  direct evidence that routing quality is sensitive to evidence quality.
- Laya warns that it cannot run a "targeted deep analysis" stage yet
  (`targeted_deep_analysis: skipped — no AI agent configured`), so the
  third comparison in Phase 5 is not yet measurable.
