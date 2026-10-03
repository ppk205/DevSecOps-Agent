# Laya triage review and training

The application uses optional `laya==0.3.20` and the English
`convaiinnovations/laya` checkpoint. The approved base revision is
`aa8c91ca088ec597df95a0d1c76b3063cb2ae5e8`. Upstream describes a
421-million-parameter ModernBERT encoder with a typed decision head. It scores
choices, ordinal evidence levels, and a yes/no question; it does not generate
CVSS vectors or own finding status.

Routing policy 2 requires a top probability of at least 0.55 with a 0.20 margin.
The human-review answer takes precedence at `review_threshold` (default 0.60),
which also gates specialized routes. `high_confidence_threshold` remains a
legacy configuration field; policy 2 uses the documented dominance and review
conditions. Evidence sufficiency is recorded as advisory information.

The checkpoint weights are downloaded separately. The normal scan works with
Laya disabled. The loader now resolves the requested revision, or hashes a
local checkpoint, and records the actual device. Inference uses a persistent
Python child, real batches, bounded inputs and enforceable cancellation.

## What the existing experiment shows

`evidence/t09/eval_agentlabels.json` contains 29 findings from one project. Its
72.4% route agreement used labels proposed by the same agent that implemented
the pipeline. Four expected dependency-analysis cases went to `low_priority`.
These are review candidates, not independent training or test ground truth.
The old escalation counter also conflated missed and unnecessary escalation;
new evaluation reports these separately and evaluates raw model decisions
separately from policy decisions.

The current machine has a GTX 1650 with 4 GB. Earlier repository timings came
from an RTX 3050 and are historical observations, not measurements of this
machine. Use the Kaggle notebook for training. No training or model publication
is performed by application tests.

## Collect labels

Start with approximately 100 independently reviewed findings per route across
multiple projects. This is a collection target, not a guarantee of accuracy.
Keep ambiguous labels out of the scored dataset until reviewers agree.

Each JSON label row needs the following fields:

```json
{
  "run_id": "run-example",
  "finding_id": "existing-finding-id",
  "project_id": "bookstore-family-a",
  "case_family": "original-and-related-variants-a",
  "expected_route": "cross_file_analysis",
  "evidence_sufficiency": 1,
  "needs_human_review": false,
  "adjudicated": true,
  "independently_adjudicated": true,
  "reviewers": ["reviewer-one", "reviewer-two"]
}
```

The eight routes are `fast_verification`, `cross_file_analysis`,
`authorization_analysis`, `jsp_context_analysis`, `dependency_analysis`,
`secret_review`, `human_review`, and `low_priority`. Evidence labels are
0 insufficient, 1 partial, and 2 sufficient. Reviewers should apply the exact
rubrics in `build_triage_questions()` and make the route label consistent with
the required human-review answer.

The model sees canonical CWE/severity values, scanner and rule identifiers,
coordinates, evidence strength and available evidence flags. Missing dataflow
or dependency context stays missing. Training cannot recover information that
is absent from the input. Operational IDs, final finding status, secrets,
reviewer identity and expected answers stay outside inference inputs.

## Export four independent splits

```powershell
.venv/Scripts/python.exe -m vulnscan.training.dataset `
  --scan artifacts/run-example/export-example.json `
  --scan artifacts/run-another/export-another.json `
  --labels reviewed-labels.json --out artifacts/laya-dataset
.venv/Scripts/python.exe -m vulnscan.training.finetune `
  --data artifacts/laya-dataset --mode validate
```

Projects, related case families and identical model inputs form connected
groups. A group stays in one split. The exporter aims for 70/10/10/10 by group,
with at least one group in each split; sample counts may differ. At least four
independent groups are required. The manifest records actual counts, labels'
provenance, seed 42, input/question versions and file checksums.

Upload only `train.jsonl`, `validation.jsonl`, `calibration.jsonl` and
`manifest.json` to the training session. Retain `test.jsonl` separately. The
training script never opens the test file.

## Train in Kaggle

Open `notebooks/laya_triage_kaggle.ipynb`, select T4 GPUs and provide the current
source distribution plus the training dataset as notebook inputs. The notebook
validates the dataset, checks GPU availability, installs the optional training
dependencies and invokes the project training command.

Defaults: 512 tokens, FP16, encoder and head gradient checkpointing,
microbatch 2 per GPU, accumulation 16, at most four epochs, encoder learning
rate `2.5e-5`, head learning rate `1e-4`, and seed 42. Training uses proper-score
policy-gradient rewards with cross-entropy guidance. It selects the checkpoint
by validation loss and stops after two epochs without improvement. Two GPUs
give an effective batch of 64 decision sequences; a single GPU gives 32.

Temperature calibration uses the separate calibration split. The export
removes inherited option-bucket temperature overrides so they cannot hide the
new fit. Checkpoint output includes weights, tokenizer, encoder configuration,
training provenance and checksums. It is saved locally and not uploaded to a
model hub.

## Evaluate and promote

Freeze the checkpoint and routing settings before opening the retained test
split. Run the same evaluator for the base and trained checkpoint:

```powershell
.venv/Scripts/python.exe -m vulnscan.training.evaluate `
  --test artifacts/laya-dataset/test.jsonl --model convaiinnovations/laya `
  --out artifacts/laya-base-test.json
.venv/Scripts/python.exe -m vulnscan.training.evaluate `
  --test artifacts/laya-dataset/test.jsonl --model artifacts/laya-trained `
  --out artifacts/laya-trained-test.json
```

Compare macro-F1, per-route support/recall, raw and policy route accuracy,
dangerous downgrades, human-review precision/recall, evidence-score error,
ECE/Brier and latency. A missing class or unavailable prediction is reported
explicitly. Compare with deterministic routing and a majority-route baseline.
Improve validation-selected behavior without increasing held-out dangerous
downgrades before promotion; retain the original checkpoint for rollback.

To use a local trained checkpoint, copy `config/laya.json` to a separate file,
set `model_id` to its directory and `revision` to null, and pass
`--laya --laya-config path/to/the/copied-config.json`. Keep advisory routing
disabled in the shipped default configuration.

SRS trace: FR-40/41 and QR-05 govern evidence and provenance; QR-12 governs
redaction; QR-17 governs independent evaluation; QR-21 governs inference
cancellation. Input format `laya-state-2` and routing policy `laya-policy-2`
identify the new behavior without rewriting historical evidence.

References: [Laya 0.3.20](https://github.com/NandhaKishorM/laya/tree/v0.3.20),
[upstream training notebook](https://github.com/NandhaKishorM/laya/blob/v0.3.20/notebooks/laya_finetune_typed_decisions_2xT4_kaggle.ipynb).
