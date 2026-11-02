# Experiment runbook

This runbook covers the experiment tooling in
`docs/superpowers/plans/2026-11-02-experiment.md`. The pilot and full trial have
not been run. They require two owner-appointed labellers, live added models,
and the owner's consent for cloud calls and source uploads. Unit tests under
`tests/experiment/` use synthetic inputs; they are not experiment results.

The configurations are B1–B7, S1–S3, F1–F4 and optional R1. Detection in the
harness comes from its static tools. The model provides AI support. Evaluate
proposals before G5 separately from findings accepted by a human after G5.

## 1. Prerequisites and versions

Locked versions below were read from repository files, not inferred from tool
names. Save actual installed version output with each live trial.

| Component | Pin and source |
|---|---|
| Python | 3.11 or later, `pyproject.toml`; record the exact runtime |
| httpx / pydantic / typer | 0.28.1 / 2.13.5 / 0.27.2, `uv.lock` |
| CVSS | 3.6, `uv.lock`; both scores use `harness.evidence.score_cvss4` |
| Semgrep | 1.178.0, `uv.lock` |
| Laya | 0.3.20, `uv.lock`; CPU only |
| Laya checkpoint | `convaiinnovations/laya` at `aa8c91ca088ec597df95a0d1c76b3063cb2ae5e8`, `config/laya.json` |
| Test tools | pytest 9.1.1, ruff 0.16.9, mypy 2.3.1, `uv.lock` |
| Maven / Java | Maven 3.9.9, Eclipse Temurin 17 base image, `ci/scanners.Dockerfile` |
| SpotBugs / FindSecBugs | 4.10.4 / 1.14.0, `ci/scanners.Dockerfile` |
| Dependency-Check | 13.0.0, `ci/scanners.Dockerfile` |
| Gitleaks | 8.24.2, `ci/install_action.py` |
| Go | Minimum 1.26.0, `go.mod`; unnecessary for the Python experiment CLIs |

The Dockerfile pins its base image digest. `ci/build_image.py` builds
`devsecops-agent-scanners:0.2.0`; this image tag is distinct from the Python
package version. Record the resulting image digest.

Provider aliases, exact model ids, local model tags/digests, quantization,
server versions and prices are **not selected yet**. The operator records
them in the trial README after selection. A local model id must be an
actually installed Ollama/LM Studio model, not an illustrative tag copied
from documentation. Preserve the model alias, protocol, base URL and model
id, never key values or credential files. Add models with `devsec model add`.

## 2. Environment

Run full scans inside WSL Kali with Docker, outside `/mnt/<drive>`. The shell
examples below are Bash, executed from a clean agent checkout in WSL.

```bash
wsl -d kali-linux
```

Inside WSL, set paths to the operator's actual checkouts and new dated output
directory. These variables are parameters, not measured results.

```bash
export AGENT="$HOME/DevSecOps-Agent"
export TARGET="$HOME/scan-targets/JVA-bookstore"
export PIN=dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5
export RUN="$AGENT/evidence/jva-bookstore-experiment-$(date -u +%F)"
cd "$AGENT"
test ! -e "$RUN"
mkdir -p "$RUN/config" "$RUN/raw" "$RUN/runs"
export UV_PROJECT_ENVIRONMENT=.venv-linux
uv sync --frozen --extra dev --extra scanners --python 3.11
export PY="$AGENT/.venv-linux/bin/python"
export PATH="$AGENT/.venv-linux/bin:$PATH"
export DEVSECOPS_NATIVE=python
docker version
"$PY" ci/build_image.py
docker image inspect devsecops-agent-scanners:0.2.0 --format '{{.Id}}'
"$PY" --version
semgrep --version
gitleaks version
```

Install/warm the optional Laya environment and checkpoint before S2, following
`docs/LAYA-TRAINING.md`. Keep the CPU device and timeout of at least 300 seconds.
An unavailable Laya backend is recorded as unavailable; it is not a successful
S2 triage measurement. Warm Maven dependencies on a disposable preparation
clone before fix evaluation; fixeval's compiler command is offline.

Copy an existing `.scanner-data` cache into the **new** baseline output root
before scanning. Select `PREVIOUS_CACHE` to the actual directory containing
the warmed data. Do not move it or modify the previous run.

```bash
mkdir -p "$RUN/raw/baselines"
cp -a "$PREVIOUS_CACHE/.scanner-data" "$RUN/raw/baselines/.scanner-data"
```

## 3. Target preparation

The owner supplies `TARGET_ORIGIN`, the actual local source or approved clone
URL. Prepare the clean target outside the Windows-mounted filesystem:

```bash
git clone --no-hardlinks "$TARGET_ORIGIN" "$TARGET"
git -C "$TARGET" checkout --detach "$PIN"
git -C "$TARGET" rev-parse HEAD
git -C "$TARGET" status --porcelain
```

HEAD must equal `PIN`; status must be empty. Record these outputs and the agent
commit in the trial README. All configurations use this commit. Fix evaluation
creates its own temporary scratch clone and detached worktree automatically.
It never registers a worktree or applies a patch in this target.

For the pilot, prepare **separate** scratch repositories from
`tests/fixtures/java/vulnerable` and `tests/fixtures/java/safe`. Follow the copy,
minimal Maven descriptor and initial-commit procedure in `ci/fixture_scan.py`.
Keep those scratch repositories and their pinned commits for all pilot
configurations. Use a new `evidence/fixtures-experiment-YYYY-MM-DD/` root and
evaluate the two targets separately. Do not treat directory names as labels.

## 4. Ground truth and run layout

Follow `experiment/ground-truth/README.md`. Two labellers work independently,
record disagreement resolution, assign CVSS vectors, and freeze the agreed
CSV before model trials. The owner supplies `fixtures.csv` and
`jva-bookstore.csv`; the tooling does not create labels.

Copy the frozen CSV and `cwe-equivalence.csv` into the new trial's `config/`
directory. Record their hashes. CWE equivalence is explicit and symmetric,
not an automatic parent/child expansion.

The evaluator reads this exact layout:

```text
RUN/runs/<alias>/B1/1/scanner-semgrep.json
RUN/runs/<alias>/B2/1/scanner-spotbugs.json
RUN/runs/<alias>/B3/1/codeql.sarif
RUN/runs/<alias>/B4/1/scanner-owasp-dependency-check.json
RUN/runs/<alias>/B5/1/scanner-gitleaks.json
RUN/runs/<alias>/B6/1/b6.jsonl
RUN/runs/<alias>/B7/1/hunt.json                 # also copy summary.json
RUN/runs/<alias>/S1/1/report.json
RUN/runs/<alias>/S1/1/session.jsonl
RUN/runs/<alias>/S2/1/report.json
RUN/runs/<alias>/S2/1/session.jsonl
RUN/runs/<alias>/S3/1/report.json
RUN/runs/<alias>/S3/1/session.jsonl
```

Numeric folders are repetitions. Use a separate root for each model alias so
different providers are never averaged together. Copy the same frozen baseline
artifacts into each alias root. The normalizer selects only that configuration's
scanner, even when other scanner envelopes share the directory.

Each slot may contain `status.json` with `status` (`completed`, `partial`,
`failed`, `skipped`, `unavailable`) and `reason`. Record the real outcome;
never declare completion simply because an artifact exists. For B4/B5 include
`gt_ids`, the independently frozen list of dependency/secret labels for that
separate comparison cohort. Without it those configurations are partial.
Optional `gt_ids` also bounds a declared source-code cohort.

Keep unavailable optional configurations visible using a numeric slot with a
status marker and the actual reason. Do not fabricate empty scanner output.
Malformed observations, missing artifacts and error records make a run partial.

## 5. Detection configurations, in order

### B1, B2, B4, B5: scanners

Run the full baseline runner once; a policy exit of 1 can mean alerts, so read
`summary.json` and scanner statuses rather than assuming process success or
failure from alert count.

```bash
"$PY" -m vulnscan.cli.main scan-run --checkout "$TARGET" --commit "$PIN" \
  --profile full --no-laya --no-ai-review --no-ai-report \
  --out "$RUN/raw/baselines" --db-path "$RUN/raw/baselines.db"
```

Copy each completed scanner envelope from its generated run directory into
the corresponding numeric slot. Preserve errors and timestamps. The full
runner uses the project's Semgrep rules only. The plan's B1 additionally
requires `p/java`; use the adapter with **both** rule paths:

```bash
export B1_OUT="$RUN/raw/b1-both-rules-1.json"
"$PY" - "$TARGET" "$PIN" "$B1_OUT" <<'PY'
import sys
from pathlib import Path
from vulnscan.contracts import ScanSpecification, ToolConfig, ToolName
from vulnscan.scanners.semgrep_adapter import SemgrepAdapter
from vulnscan.providers.credentials import redact_json
target, commit, output = sys.argv[1:]
rules = Path('src/vulnscan/scanners/rules/java.yml').resolve()
spec = ScanSpecification(target_repository_url=target, target_commit_sha=commit,
    repository_checkout_path=target,
    tools=[ToolConfig(tool=ToolName.SEMGREP, rule_paths=[str(rules), 'p/java'])])
result = SemgrepAdapter().run(spec, workdir=target)
with Path(output).open('x', encoding='utf-8') as f:
    f.write(redact_json(result.model_dump(mode='json'), indent=2))
PY
```

Use this envelope as `B1/1/scanner-semgrep.json`. Repeat to a new output and
`RUN/determinism/B1/2/` for the determinism check. Preserve the resolved registry rules/version
from the actual run; for later reruns substitute the frozen local rules file
for `p/java` in both B1 and F4. If that rules snapshot is unavailable, record
the reproducibility limit instead of claiming a pinned ruleset.

### B3: CodeQL

Follow section 6. Use the Java `security-extended` suite, the same commit and
the recorded CodeQL/query versions. Save the analysis metadata and the SARIF
as `B3/1/codeql.sarif`. CodeQL alerts are a separate baseline, never input to
the harness.

### B6: one model request per file

Set `ALIAS` to an added model. Repeat with numeric folders 1, 2 and 3 for each
model used in S2. The local command is:

```bash
export ALIAS=the-added-alias
export N=1
mkdir -p "$RUN/runs/$ALIAS/B6/$N"
"$PY" -m vulnscan.experiment.b6 --target "$TARGET" --model "$ALIAS" \
  --out "$RUN/runs/$ALIAS/B6/$N/b6.jsonl"
```

For an owner-approved cloud run add `--i-consent-code-leaves-machine`. This is
B6 baseline consent, not harness G0. Without it a cloud run exits 2 before a
transport is created. The JSONL stores file hashes, prompt hash, usage,
proposals, invalid replies, and the final status. No tools are supplied.
Each Java/JSP file is path-confined, credential-excluded, numbered and wrapped
as untrusted code. Files over 128 KiB cause partial coverage rather than a
silently truncated review.

To enforce a USD budget, pass `--budget` and `--prices`. The prices JSON maps
the exact model id to `[input_USD_per_million, output_USD_per_million]`. Populate
it only from a recorded price source and date; zero is valid only when
documented. Unknown prices produce `null` cost and prevent a budgeted run
from calling the model. Budgets stop between calls; the last in-flight call
can exceed the remainder. Exit 1 means partial; 0 means completed; existing
output files are refused. Keep invalid JSON/provider failures in the dataset.

### B7: baseline hunt

Use the same added profile and exact model id (`MODEL_ID`), retaining the raw
hunt output and summary. This CLI takes a profile id and model id separately.

```bash
"$PY" -m vulnscan.cli.main scan-run --checkout "$TARGET" --commit "$PIN" \
  --profile full --mode hunt --provider "$ALIAS" --model "$MODEL_ID" \
  --out "$RUN/raw/b7-$ALIAS" --db-path "$RUN/raw/b7-$ALIAS.db"
```

Cloud B7 additionally requires `--allow-cloud-model` and the owner's consent.
Copy `hunt.json` and `summary.json` to `B7/1/`. Score only hunt proposals as B7;
do not mix scanner observations into them. Legacy artifacts may lack complete
model cost/time telemetry; those values remain unknown.

### S1, S2 and S3: interactive harness sessions

Create a separate S1 config. **Only `mode: "off"` disables harness triage**;
the `enabled` field belongs to the baseline runner. S2 keeps the shipped
shadow configuration even though its baseline `enabled` flag is false.

```bash
"$PY" - "$RUN/config/laya-s1.json" <<'PY'
import json, sys
from pathlib import Path
config = json.loads(Path('config/laya.json').read_text())
config['mode'] = 'off'
with Path(sys.argv[1]).open('x') as f:
    json.dump(config, f, indent=2)
PY
cp config/laya.json "$RUN/config/laya-s2.json"
```

Run the following in an actual interactive terminal. Choose `S=S1` and the
off config for S1; choose `S=S2` and the shadow config for S2. Repeat each
configuration three times per model, keeping the same target and prompt.

```bash
export S=S2
export N=1
export SLOT="$RUN/runs/$ALIAS/$S/$N"
mkdir -p "$SLOT/sessions"
"$PY" -m vulnscan.cli.main chat --target "$TARGET" --model "$ALIAS" \
  --mode auto --laya-config "$RUN/config/laya-s2.json" \
  --sessions-dir "$SLOT/sessions"
```

Exact session prompt:

> Run a full review of this repository for the CWE classes in scope. Follow the tool order. Propose findings with CVSS v4.0 vectors.

The operator must define the same CWE scope in the run manifest and inspect
G1's plan. Cloud G0 asks for consent: answer `y` only after reviewing target,
provider, model and data disclosure. Local G0 may auto-approve only in auto
mode with an interactive human attached; it is logged as person `auto` with
reason `local provider, auto mode`. G1–G4 and G7 may auto-approve. G5 stays
proposed until `/review`. G6 always requires the human. Closing a prompt or
pressing Enter alone never approves.

S1 must show `DecisionStatus.SKIPPED`, route `human_review`, and reason
`Laya disabled for S1`, without a Laya backend call. S2 must show an actual
backend outcome. Both retain G3 selection and G4 investigation checks.
An exhausted budget, model failure, unreviewed scope or unavailable backend
must be described in the run's status/reason rather than hidden.

At the end, type `/export` followed by the **expanded absolute path** of the
slot (the chat prompt does not expand Bash variables). Copy the one actual
session JSONL from `sessions/` to `session.jsonl` after closing the session.
Preserve the original file. Do not export again over a frozen report.

S3 uses the S2 protocol on at least three added models, including local and
cloud. Use one alias root per provider and keep provider-specific tables;
S3 is not a pool of incomparable model repetitions. Exact model identities
and all completion failures belong in the trial README.

For after-G5 and F1, freeze the proposed report before review, then have the
designated reviewer use `/review` in the **same live session** and export to
a new after-review slot. The console's history-only `/resume` must not be
assumed to restore finding/worktree state. A copied JSONL by itself is not a
reconstructed session. Use `c`, `r`, or `m` based on the review, with reasons;
the experiment operator must not supply labels on the reviewer's behalf.
Compare after-review metrics separately; no recorded human G5 means that
stage is unavailable, and a partially reviewed set is partial.

## 6. GitHub and Semgrep platform steps

These steps are pending owner authorization and account availability. Before
upload, the owner records the destination repository/account, permitted data,
purpose, date and consent in the new trial's `CONSENT.md`. Re-run the secret
baseline and inspect its result; an old clean result does not authorize a
new upload. Any upload/push is a separate operator action, not an experiment
tool side effect.

### B3 and F2: CodeQL and Copilot Autofix

1. The owner selects the GitHub repository and uploads the pinned clean code.
2. Configure Java code scanning with the `security-extended` query suite.
   Save the actual setup, CodeQL version, query pack versions and build mode.
3. Wait for successful analysis. Select the analysis whose `commit_sha`
   equals `PIN`; save the complete analysis metadata, including errors.
4. Export the SARIF and alert list using the authenticated GitHub CLI. `GH_REPO`
   is the owner-selected `owner/repository`; `ANALYSIS_ID` is the actual id.

```bash
gh api --paginate "repos/$GH_REPO/code-scanning/analyses" > "$RUN/raw/codeql-analyses.json"
gh api -H 'Accept: application/sarif+json' \
  "repos/$GH_REPO/code-scanning/analyses/$ANALYSIS_ID" > "$RUN/raw/codeql.sarif"
gh api --paginate "repos/$GH_REPO/code-scanning/alerts?tool_name=CodeQL" \
  > "$RUN/raw/codeql-alerts.json"
```

5. For **every eligible alert**, retain its number and status, including those
   with no suggestion. On the frozen default branch request F2, then save the
   actual eventual status to a new file:

```bash
gh api --method POST "repos/$GH_REPO/code-scanning/alerts/$ALERT/autofix" \
  > "$RUN/raw/f2-$ALERT-request.json"
gh api "repos/$GH_REPO/code-scanning/alerts/$ALERT/autofix" \
  > "$RUN/raw/f2-$ALERT-status.json"
```

The [official REST reference](https://docs.github.com/en/rest/code-scanning/code-scanning#get-the-status-of-an-autofix-for-a-code-scanning-alert)
was opened while writing this runbook. GET returns `status`, `description`
and `started_at`; it does **not** promise a unified patch. Capture the
displayed suggestion from the alert page without changing it, retain its
provenance, and save the exact diff where available. Record an inaccessible
suggestion or unsupported alert as unavailable/no suggestion. The separate
Autofix commit endpoint writes a commit and is not part of this runbook.

### F3 and F4: Semgrep suggestions

F3 is optional. With the owner's account and explicit upload consent, enable
Semgrep Assistant for the same pinned project and rules, export each actual
suggestion and its alert identity, and record unsuccessful/no-suggestion
responses. Otherwise record the real skipped reason (for example, no account).
No Semgrep Platform integration is implemented by the experiment Python code.

F4 uses only rule-defined fixes, with the same two rule sources as B1. Run
the dry run in a disposable scratch checkout, save stdout/stderr and the
actual Semgrep version, and retain missing fixes as coverage misses:

```bash
semgrep --config "$AGENT/src/vulnscan/scanners/rules/java.yml" --config p/java \
  --metrics off --disable-version-check --autofix --dryrun --json "$F4_SCRATCH" \
  > "$RUN/raw/f4-dryrun.json" 2> "$RUN/raw/f4-dryrun.stderr"
```

Dry-run output is not guaranteed to be a ready-to-apply unified diff. Preserve
it intact; export the actual per-alert patch from the tool output. If a patch
cannot be reconstructed without inventing code, mark it unavailable. Replace
`p/java` with the same frozen local rules snapshot when one was captured.

## 7. Fix evaluation, F1–F4

For F1, ask the model to propose a fix only after the human confirms at G5.
Review the full diff at G6; `a` applies in the harness worktree, `r` rejects,
`d` defers. Preserve the G6 event and exact diff. G7's static rescan result is
not a human assertion that the vulnerability is fixed.

Score one unmodified suggestion with:

```bash
"$PY" -m vulnscan.experiment.fixeval --repo "$TARGET" --commit "$PIN" \
  --gt "$RUN/config/ground-truth.csv" --finding "$GT_ID" \
  --diff "$PATCH_FILE" --detector harness --out "$SCORE_FILE"
```

`SCORE_FILE` must be new. The CLI uses `git clone --no-hardlinks --no-checkout`,
a detached worktree of that scratch clone, `git apply --check`, `git apply`,
and `mvn -q -o compile`. It runs the same detector before and after. Commands
have fixed argv and no shell; the target has no worktree registration, file
changes or branch changes. The temporary scratch directory is cleaned after
its redacted command results and detector rows have been captured in the score.

Output fields include `applies`, `compiles`, `vuln_removed_by_detector`,
`files_changed`, `lines_changed`, `in_scope`, `new_alerts`, `human_verdict`,
`human_reason`, `errors`, `commands`, `before_alerts` and `after_alerts`.
Unsupported/malformed diffs are scored with an error before commands run;
unknown counts remain null. A nonapplying patch does not crash evaluation.
Compilation and detector failures are recorded as failed/unavailable stages.

F1's built-in detector is `extract_candidates`, with no model. F2 must use
the **same pinned CodeQL detector** as B3; F3/F4 must use the same Semgrep
rules as their original alerts. For these, pass
`--detector owner_module:function`. This is a trusted, operator-provided
Python callable `(Path) -> list[Row]`, run only on the scratch worktree; it
must actually rescan and raise on incomplete analysis. It must not return
an empty list for scanner failure or replay unchanged original rows.
External detector wrappers are not shipped: F2–F4 rescans remain unavailable
until the owner supplies and validates them. Do not substitute the harness
detector for CodeQL to manufacture a comparison.

Removal is unknown if the original site was not detected before the patch.
Line shifts are mapped from before/after text, so moving an alert does not
make it a removed or new alert. `in_scope` uses the GT item's file and cited
line region, expanded by the same 15-line window and 80-changed-line ceiling
as the harness; the GT schema contains only one region. This is static scope,
not a semantic correctness claim.

Later, the labellers provide a CSV with header:

```text
finding_id,human_verdict,human_reason,labeller_a,labeller_b,agreed
```

Values are supplied by the humans, never generated by this tooling. Agreed
verdicts are `accept`, `reject`, or `need_more`, with both labellers and a
reason. Pass `--verdicts path.csv` to attach them to a new evaluation output.
Report detector removal **and** labeller agreement for the removal criterion;
an absent verdict stays null.

Compute coverage with `coverage(alert_ids, suggestions_by_alert_id)` from
`vulnscan.experiment.fixeval`. Include all eligible alerts; missing/empty
suggestions count as misses. An empty denominator yields null. Compute one
table on each tool's own matched true-positive ids and another on the
intersection of B3 and harness `matched_gt_ids` in `metrics.json`. Keep the
mapping from original alert id to GT id; do not identify overlap by title.

## 8. Evaluate and verify a rerun

Run the evaluator on one target and one alias root:

```bash
"$PY" -m vulnscan.experiment.evaluate \
  --gt "$RUN/config/ground-truth.csv" --eq "$RUN/config/cwe-equivalence.csv" \
  --runs "$RUN/runs/$ALIAS" --out "$RUN/evaluation/$ALIAS"
```

It writes:

- `metrics.json`: per-run, per-CWE and per-stage TP/FP/FN/TN, precision,
  recall, F1, FPR, duplicate counts and matched GT ids; completed-run mean,
  minimum and maximum; separately listed partial/skipped/failed runs.
- `cvss.json`: vector-pair availability, invalid vectors, score error and
  exact-vector share; scores are computed, not copied from a model.
- `cost.json`: known tokens, USD, seconds and their per-TP ratios, retaining
  each run; ratios use total known cost divided by total TP, not mean cost
  divided by a sum of TP. Any missing cost prevents the total-cost ratio.
- `human.json`: human decisions, automatic decisions, undecided gates and
  timed counts. Gate durations need request and decision timestamps; older
  logs with only decisions have null durations.
- `laya.json`: S2–S1 recall, precision, tokens, cost and elapsed-time deltas.
  These compare the same model and declared scope only.
- `tables.md` and `charts/precision_recall.csv`, `charts/cost_per_tp.csv`,
  `charts/cvss_error.csv`.

`evaluate(...)` and the module CLI write the same outputs. They refuse a
nonempty output directory. Metrics with no denominator are null. Safe labels
are required for FPR. Missing prices are not known zero costs: historical
usage records with `cost_usd: 0` and no `price_known: true` remain unknown.
An optional per-run `cost.json` with `tokens`, `usd`, `seconds` may be supplied
only when computed from retained telemetry; never estimate missing fields.
Session elapsed time is the first-to-last recorded timestamp, not isolated
inference latency, and includes operator waiting where recorded.

For a deterministic evaluator rerun, use another new directory and compare
every output against the first evaluation:

```bash
"$PY" -m vulnscan.experiment.evaluate \
  --gt "$RUN/config/ground-truth.csv" --eq "$RUN/config/cwe-equivalence.csv" \
  --runs "$RUN/runs/$ALIAS" --out "$RUN/evaluation-rerun/$ALIAS"
diff -r "$RUN/evaluation/$ALIAS" "$RUN/evaluation-rerun/$ALIAS"
```

For B1, compare normalized row **sets**, excluding run ids/timestamps, rather
than byte-comparing scanner envelopes. This checks the actual two runs:

```bash
"$PY" - "$RUN/runs/$ALIAS/B1/1" "$RUN/determinism/B1/2" <<'PY'
import sys
from pathlib import Path
from vulnscan.experiment.normalize import from_scan_run
def keys(path):
    return {(r.file, r.line, r.cwe, r.severity, r.source_id)
            for r in from_scan_run(Path(path), 'B1')}
assert keys(sys.argv[1]) == keys(sys.argv[2]), 'B1 row sets differ'
print('B1 normalized row sets match')
PY
```

Use only one of those deterministic repetitions in the main comparison;
retain the second as the reproducibility check. For B6/S1/S2 model runs,
compare observed ranges, not exact output equality. Keep all partial runs
visible and excluded from means. Preserve every failed attempt in its own
dated folder before any repeat.

At completion, create `SHA256SUMS` once, covering the frozen input/output
files while excluding mutable caches and the manifest itself:

```bash
"$PY" - "$RUN" <<'PY'
import hashlib, sys
from pathlib import Path
root = Path(sys.argv[1])
paths = sorted(p for p in root.rglob('*') if p.is_file()
               and '.scanner-data' not in p.parts and p.name != 'SHA256SUMS')
with (root / 'SHA256SUMS').open('x', encoding='utf-8', newline='\n') as f:
    for p in paths:
        f.write(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(root).as_posix()}\n')
PY
```

Store no credential files, databases or model weights in the frozen evidence
set. The trial README lists target and agent commits, dates, aliases/model ids,
rules/checkpoint revisions, source paths, consent records, exclusions and the
commands that produced each folder. All future changes go into a new dated
trial folder rather than rewriting this one.

## 9. Observed time, cost and optional literature comparison

No pilot/full timing, USD, accuracy, acceptance rate or improvement claim is
available from this tooling implementation. Populate the trial results only
from its generated `cost.json`, `metrics.json`, logs and fix scores. A passing
synthetic unit test is not a real provider/scanner measurement.

Task 9's IRIS literature comparison and optional R1 replication are not run.
Before R1, the owner must pin a CWE-Bench-Java revision and selected projects,
read and record the paper's actual detection criterion, and prepare the
project-specific builds and agreed labels. Then run B3 and S2 in separate
per-project roots with the same contracts above. Report this subset separately
from JVA and from published IRIS results. No paper measurements or unverified
plan claims are copied into this runbook.

## 10. Another target or provider

Change the target origin, pinned commit, agreed labels and declared cohorts
together. Confirm Java/JSP scope and Maven build prerequisites before the
pilot. Add the new model alias interactively and record its exact id, local
tag/digest, protocol, endpoint and price source. Cloud consent is per actual
provider/session; a prior local run grants none.

Run the small-program pilot first with the selected model and owner labels.
Only then repeat the same configuration order on the full target. Target
state, baseline rules, prompt text, model parameters and scoring definitions
must remain fixed within a comparison. Re-evaluate into a new output directory
whenever any input changes.
