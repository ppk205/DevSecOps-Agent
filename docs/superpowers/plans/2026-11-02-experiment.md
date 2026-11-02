# Experiment: harness vs baselines, fix suggestions vs Copilot Autofix and Semgrep, and IRIS — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce the measured data for Chương 3 §3.8.5 and Chương 4 of the essay:
- detection quality of the harness (S1–S3) against bounded baselines (B1–B7);
- fix suggestions from the harness against GitHub Copilot Autofix and Semgrep;
- a positioning against IRIS (ICLR 2025).

It also leaves a runbook that lets anyone re-run everything.

**Architecture:** Every source of findings is normalised into one row format and matched against a hand-labelled ground truth by one tested evaluator.
- **Harness runs** are interactive sessions: an operator answers G0, `auto` mode handles G1–G4 and G7, and G5 is deferred. Detection is therefore measured on the system's **proposals** before any human decision. The human decision is measured separately.
- **Fix suggestions** from every tool are scored on the same criteria.
- **IRIS** is compared from its published results, with an optional small replication on its public benchmark.

**Tech Stack:**
- Python 3.11, with new code under `src/vulnscan/experiment/` (covered by ruff, mypy and pytest);
- the existing `scan-run` and harness;
- WSL Kali with Docker for the baselines;
- GitHub code scanning (CodeQL) for B3 and Copilot Autofix;
- Semgrep CLI (B1), plus Semgrep AppSec Platform Assistant if an account exists.

**Spec:**
- `docs/ARCHITECTURE-MODIFICATION.md` §8 (configurations and metrics), D7 and D10;
- `docs/superpowers/plans/2026-11-01-essay-correction.md` §0 (lecturer requirements 7, 15 and 22);
- `special_requirements.txt`.

**Preconditions:**
- **Project 1** (`2026-11-01-stabilize-and-merge-main.md`) has merged. Its redaction fix is required: without it, code quotes such as `token.isEmpty()` reach the model as `[REDACTED]` and corrupt the results. Project 1 also delivers the B7 consent flag.
- **The add-model flow** (Task 2b of `2026-11-01-go-chat-tui.md`, shippable alone as `feat/add-model`) has merged. Every model in the experiment is an **added model**: an alias with a base URL, a protocol and its own key, entered through `devsec model add`. It is not tied to a provider-named key. The runbook lists the alias, template, base URL and model id used, never the key.
- **The rest of projects 2–4 is not required.** The console `devsec chat` is enough.
- Branch: `feat/experiment`.

## Global Constraints

- **AGENTS E2:** every number in the results comes from files under `evidence/jva-bookstore-experiment-YYYY-MM-DD/` (and `evidence/fixtures-experiment-YYYY-MM-DD/`), produced by the evaluator. Nothing is typed in.
- **AGENTS E5:** results say "đề xuất" (proposed) or "cảnh báo" (alert), never "lỗ hổng đã xác nhận" (confirmed vulnerability), except for ground-truth rows the two labellers agreed on.
- **AGENTS E7:** each run writes a new dated folder. Nothing under `evidence/` is edited after it is written. Append a `SHA256SUMS` file at the end of each run.
- **AGENTS A4 and D10:** the harness never sees baseline results. AI is described as a supporting tool.
- **Code leaving the machine:**
  - S-runs with a cloud provider need G0 consent.
  - B3 and F2 (GitHub) and F3 (Semgrep Platform) upload source code to third parties. Each needs the owner's written consent recorded in `evidence/.../CONSENT.md`. The JVA-bookstore repository must contain no real secrets: Gitleaks reported 0 on 2026-11-01, and this is re-checked before upload.
- **Bounded comparison (requirement 15):** the configurations are exactly B1–B7, S1–S3, F1–F4 and R1 below. No others.
- **Fix suggestions are suggestions** (spec D7 as updated by Task 1): limited to the vulnerability's cited code, never applied to the target, and applied only in a worktree after G6 for measurement.

## Configurations

| ID | What runs | Detects | Fixes | Source of rows |
|---|---|---|---|---|
| B1 | Semgrep CLI (project rules + `p/java`) | yes | rule `fix:` only (F4) | `scanner-semgrep.json` |
| B2 | SpotBugs + FindSecBugs | yes | — | `scanner-spotbugs.json` |
| B3 | GitHub CodeQL `security-extended`, Java | yes | Copilot Autofix (F2) | SARIF from the code-scanning API |
| B4 | OWASP Dependency-Check | dependencies only (separate table) | — | `scanner-owasp-dependency-check.json` |
| B5 | Gitleaks | secrets only (separate table) | — | `scanner-gitleaks.json` |
| B6 | The same model as S2, one prompt per file, no tools | yes | yes (as text) | `b6.jsonl` (Task 5) |
| B7 | `scan-run --mode hunt` / `--ai-review` (the teammate's ungated model path) | yes | — | the hunt output in the run folder |
| S1 | Harness without Laya | yes (proposals) | F1 | `.devsec/reports/<id>/report.json` and the session JSONL |
| S2 | Harness with Laya | yes (proposals) | F1 | same |
| S3 | S2 on ≥ 3 added models: at least one local (loopback base URL) and one cloud | yes | F1 | same |
| F1 | Harness `propose_fix` for findings confirmed at G5 | — | yes | the G6 diff in the session JSONL |
| F2 | GitHub Copilot Autofix on CodeQL alerts | — | yes | autofix suggestions exported per alert (Task 8) |
| F3 | Semgrep Assistant autofix (**optional**, only if the owner has a Semgrep AppSec Platform account; the free tier has limited AI credits) | — | yes | exported suggestions |
| F4 | Semgrep rule `fix:` autofixes (`semgrep --autofix --dryrun`) | — | yes, where a rule defines one | the dry-run diff |
| R1 | **Optional** replication on a CWE-Bench-Java subset: B3 (CodeQL) and S2, on the projects whose CWE is in {22, 78, 79} | yes | — | per-project rows |

Repetitions: S1, S2 and B6 run 3 times per provider, because model output is nondeterministic. Baselines run once and are checked as deterministic by a second run of B1 that must produce an identical row set.

## Metrics

All metrics are computed by `vulnscan.experiment.evaluate`.

**Detection**, per CWE and overall:
- TP, FP and FN;
- Precision, Recall and F1;
- FPR = FP / (FP + TN). TN comes from the labelled **safe sites** in the ground truth;
- for S-configs, the **proposed** level (before the human) and the **after-G5** level.

**Severity:** the CVSS v4.0 score error, |score(proposed vector) − score(ground-truth vector)|. Both scores come from `score_cvss4`. Also the share of exactly matching vectors.

**Cost and effort:**
- tokens, USD and wall time per configuration and per true-positive finding (from `usage` events and timestamps);
- the Laya effect, S2 against S1: tokens, time and recall lost;
- human decisions per scan and the time per gate (the decision timestamp minus the request event timestamp).

**Fix suggestions** (F1–F4), each scored on the same fixes:
- **coverage:** the share of alerts with a suggestion;
- **compiles:** `mvn -q compile` in the worktree;
- **removes the vulnerability:** the same detector no longer reports it **and** a labeller agrees;
- **scope:** files and lines changed, and whether the change stays within the cited code (the Task 1 rule);
- **new alerts introduced:** the detector's alert set on the patched tree minus the alert set before;
- **human acceptance:** a labeller accepts or rejects, with a reason.

**Comparison sets** for fixes:
- each tool on its own true positives;
- all tools on the **overlap set** (ground-truth vulnerabilities detected by both CodeQL and the harness), which is the fair head-to-head for F1 against F2.

## Review Focus

1. **The same vulnerability is reported at different lines by different tools.** For example, SpotBugs reports the bytecode method line and the harness reports the sink line. Matching uses the file, the CWE equivalence and a line window, so one ground-truth item is never counted twice. Pinned in Task 2 by `test_one_gt_item_matched_once_per_config`.
2. **A tool reports a CWE that is a parent or child of the ground-truth CWE** (CWE-639 against CWE-862). It matches only through the documented equivalence table, which is printed in the results. Pinned in Task 2 by `test_cwe_equivalence_is_explicit`.
3. **A model run fails halfway** (budget, provider error). The run is recorded as `partial`, with what completed. It is never silently dropped or averaged as zero. Pinned in Task 4 by `test_partial_runs_reported_not_averaged`.
4. **Copilot Autofix returns no suggestion for an alert.** That counts against F2 coverage. It is not excluded. Pinned in Task 6 by `test_missing_suggestion_counts_in_coverage`.
5. **A fix suggestion edits code outside the vulnerability**, for example a whole-file reformat. The harness rejects it before G6 (Task 1). For other tools it is scored as out of scope. Pinned in Task 1 by `test_fix_outside_cited_code_is_refused` and in Task 6 by `test_scope_metric_flags_out_of_region_hunks`.

---

### Task 1: Fix proposals limited to the vulnerability

**Files:**
- Modify: `src/vulnscan/harness/tools.py` (`_propose_fix`)
- Modify: `src/vulnscan/harness/fixes.py` (add `diff_hunks(diff: str) -> list[tuple[str, int, int]]` returning (file, start line, end line) in the old file)
- Test: `tests/harness/test_tools.py`, `tests/harness/test_fixes.py`
- Docs: spec D7, AGENTS S3 (wording below), CHANGELOG

**Interfaces:**
- Produces:
  - `FIX_WINDOW = 15`: the number of lines around a cited hop that a hunk may touch.
  - `MAX_FIX_LINES = 80`: the maximum number of changed lines.
  - A proposal is refused with a `ValueError` naming the offending file and lines when any of these holds:
    - a hunk touches a file that is not among the finding's hop files;
    - a hunk lies more than `FIX_WINDOW` lines from every cited hop in that file;
    - the total number of added and removed lines exceeds `MAX_FIX_LINES`.
  - `test_hint` stays free text.
- Spec D7 gets: "A fix is a suggestion limited to the vulnerability's cited code (hop files, ±15 lines, ≤ 80 changed lines); it is shown at G6 and applied only to a worktree; the target is never modified."
- AGENTS S3 gets: "`propose_fix` refuses diffs outside the finding's cited code."

- [ ] **Step 1: Write the failing tests.**
  - `test_fix_outside_cited_code_is_refused`: a diff edits another file. The error names the file, and no G6 request is logged.
  - `test_fix_far_from_hop_is_refused`: a hunk 40 lines away from the hop is refused.
  - `test_large_fix_is_refused`: 81 changed lines are refused.
  - `test_fix_near_hop_reaches_g6`: the existing happy path still reaches G6.
- [ ] **Step 2: Run the tests to confirm they fail.**
  Run: `.venv\Scripts\python.exe -m pytest tests/harness/test_tools.py -q -k fix`
  Expected: the new tests FAIL.
- [ ] **Step 3: Implement** the check in `_propose_fix`, before `_ask`. Then run the G3 commands. Expected: all pass.
- [ ] **Step 4: Update the docs.** Update spec D7, AGENTS S3 and the CHANGELOG. Commit:
  ```bash
  git commit -m "Limit fix suggestions to the vulnerability's cited code"
  ```

### Task 2: Ground truth format and matching

**Files:**
- Create: `src/vulnscan/experiment/__init__.py`, `src/vulnscan/experiment/groundtruth.py`
- Create: `experiment/ground-truth/README.md` (labelling protocol), `experiment/ground-truth/cwe-equivalence.csv`
- Test: `tests/experiment/test_groundtruth.py`

**Interfaces:**
- Produces:
  ```python
  @dataclass(frozen=True)
  class GTItem: id: str; file: str; line_start: int; line_end: int; cwe: str; kind: Literal["vuln","safe"]
                 origin: Literal["builtin","injected"]; cvss_vector: str | None; labeller_a: str; labeller_b: str; agreed: bool
  @dataclass(frozen=True)
  class Row: config: str; run: int; file: str; line: int; cwe: str; severity: str | None
             cvss_vector: str | None; stage: Literal["proposed","after_g5","baseline"]; source_id: str
  def load_gt(path: Path) -> list[GTItem]          # CSV with exactly the GTItem fields as header
  def load_equivalence(path: Path) -> dict[str, frozenset[str]]
  def match(rows: list[Row], gt: list[GTItem], eq: dict[str, frozenset[str]], window: int = 3) -> MatchResult
  ```
  - `MatchResult` holds `tp: list[tuple[Row, GTItem]]`, `fp: list[Row]`, `fn: list[GTItem]` and `tn: list[GTItem]`, where `tn` is the safe sites with no row.
  - A row matches a vulnerable item when all three hold:
    - the paths are equal after normalisation (posix, relative to the repo root);
    - the CWEs are equal or listed as equivalent;
    - the line is within `[line_start − window, line_end + window]`.
  - Each GT item is matched at most once per config and run. Extra matching rows count as duplicates, which are reported but are not FP.
  - A row that hits a `safe` item is an FP.
- Labelling protocol (README): two labellers work independently (essay Hình 3.6–3.7). Disagreements are settled in a recorded discussion, and only `agreed=True` items are scored. Safe sites are sampled from harness candidates and baseline alerts that both labellers judge safe. The CVSS vector is set by the labellers, and the score is computed.

- [ ] **Step 1: Write the failing tests.**
  - `test_exact_match_is_tp`.
  - `test_line_window`: a row 3 lines off matches; one 4 lines off does not.
  - `test_cwe_equivalence_is_explicit`: CWE-639 against CWE-862 matches only when the pair is listed.
  - `test_one_gt_item_matched_once_per_config`.
  - `test_safe_site_hit_is_fp_and_unhit_is_tn`.
  - `test_unagreed_items_ignored`.
- [ ] **Step 2: Run the tests to confirm they fail.**
  Run: `.venv\Scripts\python.exe -m pytest tests/experiment -q`
  Expected: FAIL.
- [ ] **Step 3: Implement.** Then run the tests to confirm they pass. Commit:
  ```bash
  git commit -m "Add ground truth format and finding matching for the experiment"
  ```

### Task 3: Normalisers for every source

**Files:**
- Create: `src/vulnscan/experiment/normalize.py`
- Test: `tests/experiment/test_normalize.py`, with tiny fixtures under `tests/experiment/fixtures/`. The fixtures are trimmed copies of real shapes, with no evidence files copied.

**Interfaces:**
- Produces one function per source. Each returns `list[Row]` and never raises on an unknown CWE; it maps the CWE to `"CWE-unknown"` and keeps the row:
  ```python
  def from_scan_run(run_dir: Path, config: str) -> list[Row]            # scanner-*.json (B1, B2, B4, B5) and hunt output (B7)
  def from_sarif(path: Path, config: str) -> list[Row]                  # CodeQL (B3), CWE from rule tags "external/cwe/cwe-NNN"
  def from_harness(report_json: Path, session_jsonl: Path, config: str, run: int) -> list[Row]  # stages proposed + after_g5
  def from_b6(jsonl: Path, config: str, run: int) -> list[Row]
  ```

- [ ] **Step 1: Write the failing tests.** One per function, each on a two-finding fixture, plus `test_unknown_cwe_kept`.
- [ ] **Step 2: Run them to confirm they fail.** Then implement, and run them to confirm they pass. Commit:
  ```bash
  git commit -m "Normalise baseline, SARIF, harness and model-only findings to one row format"
  ```

### Task 4: Metrics, tables and chart data

**Files:**
- Create: `src/vulnscan/experiment/evaluate.py` (entry point `python -m vulnscan.experiment.evaluate --gt … --eq … --runs <evidence dir> --out <dir>`)
- Test: `tests/experiment/test_evaluate.py`

**Interfaces:**
- Writes to `<out>`:
  - `metrics.json`, with configs, then CWEs, then stages, then TP, FP, FN, TN, P, R, F1 and FPR;
  - `cvss.json`;
  - `cost.json`, with tokens, USD and seconds per config and per TP;
  - `human.json`, with gate decisions and seconds per gate;
  - `laya.json`, S2 against S1;
  - `tables.md`, the Markdown tables used for the essay's Chương 4;
  - `charts/*.csv`, the chart inputs for the essay plan's §5.5 style.
- Repeated runs are reported as mean, min and max. Runs marked `partial` are listed separately and excluded from the means (Review Focus 3).

- [ ] **Step 1: Write the failing tests.**
  - `test_precision_recall_f1_fpr_on_toy_set`, with hand-computed expected values in the test.
  - `test_cvss_error_uses_score_cvss4`.
  - `test_partial_runs_reported_not_averaged`.
  - `test_cost_per_tp`.
  - `test_tables_md_contains_every_config`.
- [ ] **Step 2: Run them to confirm they fail.** Then implement, and run them to confirm they pass. Commit:
  ```bash
  git commit -m "Compute experiment metrics, tables and chart data"
  ```

### Task 5: B6 runner (the model alone, no tools)

**Files:**
- Create: `src/vulnscan/experiment/b6.py` (`python -m vulnscan.experiment.b6 --target … --model <alias>[:<id>] --out b6.jsonl`; the model is resolved with `resolve_model` from Task 2b)
- Test: `tests/experiment/test_b6.py`

**Interfaces:**
- Uses the harness transports from `harness/providers.py` (A2: no SDK). Every file goes through `Workspace.files(["**/*.java", "**/*.jsp"])`, is wrapped in `<untrusted_code>`, and is sent with one fixed prompt, `B6_PROMPT`. The prompt asks for JSON rows `{file, line, cwe, cvss_vector, explanation, fix}`.
- **G0:** a cloud provider requires `--i-consent-code-leaves-machine`; without it the script exits 2. A local provider needs no flag.
- Budget: `--budget` in USD. When it is exhausted, the run stops and is marked `partial`.

- [ ] **Step 1: Write the failing tests** (fake transport):
  - `test_rows_written_per_file`;
  - `test_cloud_without_consent_exits_2`;
  - `test_budget_exhaustion_marks_partial`;
  - `test_invalid_json_reply_recorded_not_dropped`.
- [ ] **Step 2: Run them to confirm they fail.** Then implement, and run them to confirm they pass. Commit:
  ```bash
  git commit -m "Add the model-only baseline runner"
  ```

### Task 6: Fix-suggestion evaluation (F1–F4)

**Files:**
- Create: `src/vulnscan/experiment/fixeval.py`
- Test: `tests/experiment/test_fixeval.py`

**Interfaces:**
- `evaluate_fix(repo: Path, commit: str, diff: str, finding: GTItem, detector: Callable[[Path], list[Row]]) -> FixScore`.
- `FixScore` has the fields `applies`, `compiles`, `vuln_removed_by_detector`, `files_changed`, `lines_changed`, `in_scope` (the Task 1 rule) and `new_alerts`, plus `human_verdict` and `human_reason`, which are filled from a CSV later.
- It works in a temporary `git worktree` of a **scratch clone**, never the target checkout. It runs `git apply --check` and then `git apply`, followed by `mvn -q -o compile` (offline, using the warmed `.m2`), then the detector.
- `coverage(alerts, suggestions)` counts alerts without a suggestion as misses.

- [ ] **Step 1: Write the failing tests** (on `tests/fixtures/java/vulnerable`, with a stub detector, and with `mvn` replaced by an injected command runner in unit tests):
  - `test_missing_suggestion_counts_in_coverage`;
  - `test_scope_metric_flags_out_of_region_hunks`;
  - `test_non_applying_diff_scored_not_crashed`;
  - `test_new_alerts_diffed`.
- [ ] **Step 2: Run them to confirm they fail.** Then implement, and run them to confirm they pass. Commit:
  ```bash
  git commit -m "Score fix suggestions on applies, compiles, removal, scope and new alerts"
  ```

### Task 7: Pilot, a basic trial on the small programs (requirement 22)

Target: `tests/fixtures/java/vulnerable` and `tests/fixtures/java/safe`, copied to a scratch clone with a `git init` and one commit, the same way as `ci/fixture_scan.py`.

- [ ] **Step 1: Label the ground truth.** Two labellers mark every vulnerable site and 5 safe sites in `experiment/ground-truth/fixtures.csv`.
- [ ] **Step 2: Run B1, B2, B4 and B5** with `scan-run --profile full --no-laya` in WSL. Run S2 once with a **local** provider (no consent needed). Run B6 once with the same provider. Run F1 on the confirmed findings.
- [ ] **Step 3: Evaluate.** Run `python -m vulnscan.experiment.evaluate`, with output to `evidence/fixtures-experiment-YYYY-MM-DD/`.
  Expected: the safe fixture produces 0 TP and its safe sites as TN. Every pipeline stage produces rows. No crashes.
- [ ] **Step 4: Fix any problems.** If anything in Tasks 2–6 breaks on real data, fix it with a failing test first, then rerun the pilot.
- [ ] **Step 5: Commit** the evidence folder, its `SHA256SUMS` and the code fixes.
  ```bash
  git commit -m "Record the pilot experiment on the fixture programs"
  ```

### Task 8: Full run on JVA-bookstore

Target: a clean clone of JVA-bookstore at `dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5` in `~/scan-targets/` (WSL), per AGENTS G7.

- [ ] **Step 1: Ground truth.** Write `experiment/ground-truth/jva-bookstore.csv` per the README protocol. Include the five manual cases from `HARNESS-TUI-PLAN.md` §10, the injected flaws (essay 3.7.1) and the safe sites. Freeze it with a commit **before** running any S-config.
- [ ] **Step 2: Baselines B1, B2, B4, B5.** Run `scan-run --profile full --no-laya --out evidence/jva-bookstore-experiment-YYYY-MM-DD/baselines`. Reuse the `.scanner-data` copied from `evidence/jva-fullscan-2026-11-01/` into the new folder (a copy, never moved; E7). Run B1 a second time as the determinism check.
- [ ] **Step 3: B3 and F2 (GitHub).** These need the owner's consent first (`CONSENT.md`).
  1. Push the clean clone to a GitHub repository chosen by the owner. Code scanning is free for public repositories; a private repository needs GitHub Code Security.
  2. Enable CodeQL default setup with the `security-extended` suite for Java.
  3. Wait for the analysis to finish.
  4. Export the SARIF with `gh api -H "Accept: application/sarif+json" /repos/<o>/<r>/code-scanning/analyses/<id>`.
  5. For every CodeQL alert, request and download the Copilot Autofix suggestion through the code-scanning autofix REST endpoints for the alert. If an endpoint is unavailable for the plan, **record that and capture the suggestion from the alert page with the Playwright MCP**, storing the diff text as it appears, unedited.
  6. Store everything in `…/b3-codeql/` and `…/f2-autofix/`.
- [ ] **Step 4: F3 and F4 (Semgrep).**
  - F4: run `semgrep --config <same rules> --autofix --dryrun --json` and store the diffs in `…/f4-semgrep-rulefix/`.
  - F3 (only with an owner account and consent): run Semgrep AppSec Platform Assistant on the same repository and export the autofix suggestions to `…/f3-semgrep-assistant/`. If skipped, `tables.md` shows "skipped: no account", not zero.
- [ ] **Step 5: B6 and B7.**
  - B6: three runs per provider, local first.
  - B7: `scan-run --mode hunt` with the same local profile, plus a cloud profile only with `--allow-cloud-model` and consent.
- [ ] **Step 6: S1 and S2, three runs each, and S3 on at least three providers.** Each run is one console session:
  ```
  devsec model add            # once per model: template or Custom, base URL, model id, key (masked)
  devsec chat --target <clone> --model <alias>[:<id>] --mode auto --sessions-dir evidence/…/s2/<alias>/run-<n>/sessions
  > Run a full review of this repository for the CWE classes in scope. Follow the tool order. Propose findings with CVSS v4.0 vectors.
  ```
   - S1 uses a separate Laya config with `mode: "off"` (owner-approved correction, 2026-11-02). The baseline-only `enabled` flag does not disable harness triage. S1 records skipped triage and still requires G3/G4. S2 uses `config/laya.json` (timeout ≥ 300).
  - The operator answers G0 only. G5 is deferred, as `auto` mode does. Then `/export`.
- [ ] **Step 7: The after-G5 stage and F1.**
  - Copy one S2 run per provider. In the copy, a labeller who has **not** seen the ground truth answers G5 through `/review`.
  - For the confirmed findings, the operator asks for fixes, and the model calls `propose_fix`. G6 is answered with `apply` so the fix can be measured in the worktree. The diff is exported.
- [ ] **Step 8: Evaluate and score the fixes.**
  - Run `evaluate`.
  - Run `fixeval` over F1, F2, F4 and, if present, F3. The detector for each tool is its own scanner: F2 uses CodeQL and F1 uses the harness `extract_candidates`.
  - Fill in the human verdicts in `fix-verdicts.csv` (two labellers).
  - Write `SHA256SUMS`.
- [ ] **Step 9: Commit** the evidence and the ground truth.
  ```bash
  git commit -m "Record the JVA-bookstore experiment"
  ```

### Task 9: Comparison with IRIS (and related research)

**Files:**
- Create: `experiment/related-work.md`, the source of the essay's §4.7 table

- [ ] **Step 1: Write the literature table.** It holds only facts read from the papers, each with a citation. The columns are:
  - LLM role;
  - static analyser;
  - benchmark;
  - vulnerability classes;
  - human in the loop;
  - fix generation;
  - reported results (quoted with section and version).

  IRIS row:
  - *IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities*, Li, Dutta and Naik, ICLR 2025 (arXiv 2405.17238, **v3**).
  - Role: the LLM infers taint specifications for CodeQL and filters alarms.
  - Benchmark: CWE-Bench-Java, 120 validated vulnerabilities in 4 classes.
  - Reported results: CodeQL detects 27 and IRIS with GPT-4 detects 55; the false discovery rate is about 5 points lower than CodeQL's.
  - **Cite v3.** The v1 draft reported different numbers.

  Add rows for GitHub Copilot Autofix and Semgrep Assistant from their official documentation (industry tools, not peer-reviewed). Add more research rows only if the paper is opened and read.
- [ ] **Step 2 (optional, R1): replicate on CWE-Bench-Java.**
  1. Clone `cwe-bench-java` at a pinned commit.
  2. Select the projects whose CWE is in {22, 78, 79}, where the harness has rules.
  3. Build them with the provided scripts.
  4. Run B3 (CodeQL CLI, used under its academic-research terms) and S2 with a local model.
  5. Use **IRIS's own detection criterion**, copied verbatim from the paper into `related-work.md`.

  Report R1 as a small, separate table labelled "không so sánh trực tiếp được với số liệu IRIS nếu điều kiện khác nhau" (not directly comparable with IRIS's numbers if the conditions differ).
- [ ] **Step 3: Commit.**
  ```bash
  git commit -m "Add related-work comparison and optional IRIS benchmark replication"
  ```

### Task 10: Runbook and results docs

**Files:**
- Create: `docs/EXPERIMENT-RUNBOOK.md`, `evidence/jva-bookstore-experiment-YYYY-MM-DD/README.md`
- Modify: `README.md` (link), `CHANGELOG.md`, spec §8 and §13

- [ ] **Step 1: Write `docs/EXPERIMENT-RUNBOOK.md`.** It must let someone re-run everything. Its sections:
  1. **Prerequisites:** the exact versions, read from `uv.lock`, `ci/scanners.Dockerfile`, `go.mod`, the Ollama or LM Studio model tags, and the provider model ids.
  2. **Environment:** WSL Kali, Docker, `.venv-linux`, building the scanner image, and the `.scanner-data` reuse.
  3. **Target preparation:** the clean clone at the pinned commit, and the scratch clone for fixes.
  4. **Ground truth:** the protocol and the files.
  5. **Every configuration in order**, B1–B7, S1–S3, F1–F4 and R1, with the exact commands, the exact session prompt, the gate answers expected from the operator, and the output paths.
  6. **The GitHub CodeQL and Copilot Autofix steps**, and the Semgrep Platform steps, including the consent steps.
  7. **The evaluation commands** and the expected files.
  8. **Verifying a re-run:** `SHA256SUMS`, the B1 determinism check, and model nondeterminism (compare ranges, not exact values).
  9. **Time and cost observed in this run**, copied from `cost.json`, not estimated.
  10. **Re-running on another target or provider:** what to change.
- [ ] **Step 2: Write the evidence README.** It lists the folders, what produced each, the commit, the dates, the providers and the consent records.
- [ ] **Step 3: Rerun the evaluator** from a fresh clone, following only the runbook. `metrics.json` must be byte-identical: the evaluation is deterministic for a fixed evidence folder.
- [ ] **Step 4: Update the docs.** Spec §8 gets the final configuration table, and §13 gets a pointer. Add the CHANGELOG entry. Commit, push `feat/experiment`, and open a PR. Do not merge it.
