# DevSecOps-Agent

Source analysis for **Java/Servlet/JSP, JavaScript/TypeScript, Python and PHP**.
The application combines the native-hunt analyzer, scanner baselines, AI support
for investigation, independent validation, reports and fix proposals. It runs
as a single-user local application. Enabled AI stages can send source excerpts
to the configured provider. Keys use masked entry and local environment storage;
profiles contain credential variable references.

```text
CLI / Textual TUI / web UI / Go TUI
  intake
    -> model hunt (only with --mode hunt, the Python default)
    -> scanners (native-hunt alone, or a profile that adds Semgrep and Gitleaks)
    -> normalize and dedup -> Laya routing (advisory)
    -> only when the hunt returned candidates:
         Laya candidate check -> compare -> promote model-only candidates
    -> targeted AI review -> independent validation -> AI narrative report
    -> policy gate -> report exports -> optional notifications

Separate action: fix proposal -> isolated overlay -> rescan
```

## Quickstart

Prerequisites: Python 3.11+, Node 18+ (web UI only). Git is needed for URLs,
commit verification and CI; plain local folders work without it. Java 11+ only if
you want the DEEP profile (SpotBugs). Semgrep and Gitleaks resolve via `PATH`
with a `sys.prefix` fallback (`pip install semgrep`, Gitleaks binary next to
the venv).

```bash
git clone https://github.com/ppk205/DevSecOps-Agent.git
cd DevSecOps-Agent

# Isolated venv (uv recommended; plain venv works too)
uv sync --frozen --extra dev --extra scanners --extra laya
# Windows: .venv\Scripts\activate

# 1) Scan from the terminal (deterministic, no key needed)
devsecops-agent scan-run --checkout /path/to/repo --out artifacts/demo \
  --profile fast --db-path scans.db --allow-dirty --mode deterministic --no-laya

# 2) Or use the web UI
devsecops-agent serve --host 127.0.0.1 --port 8000   # backend
cd web-ui && npm install && npm run dev               # http://localhost:5173/app/
```

Open `http://localhost:5173/app/scans/new`, pick a repo, press **Start scan**,
watch the **Live** rail turn green.

The terminal opens in **Workspace**. Choose a checkout and profile, expand
Advanced options when needed, then press **Ctrl+E** to review and **Ctrl+S** to
start. **Ctrl+K** opens the action menu. Review and finding details scroll with
arrow/page keys; **V** shows raw details. See the
[TUI review and remediation](docs/TUI-REVIEW.md) for the implemented fixes.

The default Textual workspace retains repository URL input, pinned commits,
clone-cache settings and the API Keys tab. Set `DEVSECOPS_NATIVE=go` to use the
native TUI for repository URLs and local source folders; `DEVSECOPS_NATIVE=python` selects Python for
all commands. The `devsec` alias is also available.

The native executable in `bin` discovers the project's virtual environment from
its own location, including when launched from another directory. Set
`DEVSECOPS_PYTHON` to select a different Python environment with the application
installed. See [native build and launch](docs/NATIVE-MIGRATION.md#build-and-launch)
for platform layouts and fallback behavior.

Repository input accepts local paths (including quoted paths with spaces),
HTTPS/SSH/Git URLs and `owner/repo` shorthand. Existing local folders take
precedence over shorthand; prefix a path with `./` or `../` to keep it local.
Plain source folders also work without Git: reports record `no-revision`, the
reason, and file hashes. Git is required to clone URLs, verify commit pins or
pass CI source checks. See [source input](docs/NATIVE-MIGRATION.md#source-input).

## Overview

DevSecOps-Agent is a local application that detects and reports vulnerabilities
in web projects. Its own analyzer is native-hunt. Semgrep, SpotBugs/FindSecBugs,
OWASP Dependency-Check, Gitleaks and CodeQL are integrated adapters and comparison
baselines. A model can hunt for candidates and propose assessments; those proposals
go through `IndependentValidator` and human review. The validator requires scoped
independent evidence for terminal decisions. CVSS proposals use the corrected
deterministic v4.0 scorer; metric assumptions still require independent checks.

The experimental target is [JVA-bookstore](https://github.com/Moseyuh333/JVA-bookstore) (commit `dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5`): 101 Java files, 38 JSP files, Java 11, Maven WAR packaging, PostgreSQL, `javax.servlet`.

## Architecture

```text
Clients:  Python CLI, Textual TUI, FastAPI + React web UI, Go CLI/TUI, native dashboard
Service:  ScanService (scan lifecycle, snapshots, SQLite, retry, cancellation)
          Go runs hunt and AI stages through the Python service over a JSONL bridge

Stages in execution order (ScanService._run):
  1. intake                  checkout manifest and source snapshot
  2. model_hunt              only in hunt mode; skipped without a provider
  3. scanners                selected tools, each with raw results and coverage
  4. normalization           grouped findings
  5. laya_batch_routing      advisory; routes scanner findings only
  6. laya_verification       hunt with candidates only
  7. model_scanner_compare   hunt with candidates only; file, line +/-3, CWE
  8. promotion               hunt with candidates only; model-only candidates
                             whose source excerpt can be re-read
  9. targeted_deep_analysis  AI review of at most max_ai_findings findings
 10. independent_validation  skipped when no assessment exists
 11. final_report            AI narrative; the gate is still pending here
 12. policy gate             fail_on, default high
 13. exports and notifications
```

## Vulnerability Groups (CWE)

Native-hunt has 102 rules: Java 30, JavaScript/TypeScript 25, PHP 23, Python 23 and
one generic rule (counted from `src/vulnscan/native_hunt/rules/` on 2026-11-04). A rule
existing does not mean it works well; see [Measured Results](#measured-results).

| CWE | Description | Native-hunt rule families |
|-----|-------------|---------------------------|
| CWE-89 | SQL injection | Java, JS/TS, PHP, Python |
| CWE-78 | OS command injection | Java, JS/TS, PHP, Python |
| CWE-79 | Cross-site scripting | Java, JS/TS, PHP, Python |
| CWE-90 | LDAP injection | Java, Python |
| CWE-643 | XPath injection | Java |
| CWE-94, CWE-95 | Code injection | 95: JS/TS, PHP, Python; 94: generic |
| CWE-22 | Path traversal | Java, JS/TS, PHP, Python |
| CWE-918 | Server-side request forgery | Java, JS/TS, PHP, Python |
| CWE-601 | Open redirect | Java, JS/TS, PHP, Python |
| CWE-611 | XML external entity | Java, JS/TS, PHP, Python |
| CWE-614 | Cookie without Secure | Java |
| CWE-502 | Unsafe deserialization | Java, JS/TS, PHP, Python |
| CWE-798 | Hard-coded credentials | Java, JS/TS, PHP, Python |
| CWE-327 | Weak cryptographic algorithm | Java, JS/TS |
| CWE-328 | Weak hash | JS/TS, PHP, Python |
| CWE-330 | Insufficiently random values | Java, JS/TS, PHP, Python |
| CWE-209, CWE-215 | Information exposure through errors or debug output | 209: Java; 215: Python |

Native-hunt has no rule for CWE-434, CWE-501, CWE-306, CWE-862 or CWE-639. Only the
model's logic pass can suggest those. Dependency findings (CWE-1395) come only from
OWASP Dependency-Check or OSV, and are evaluated separately from source findings.

## Measured Results

OWASP Benchmark, measured on 2026-11-04 with no model called. A case counts as flagged
when an accepted CWE is reported in the case's own file; every tool uses the same rule.
J is TPR minus FPR, in percent, so 0 equals random guessing. Scoring script, raw output
and limits are in `evidence/owasp-benchmark-tools-2026-11-04/`.

| Suite | Tool | TPR | FPR | Precision | J |
|-------|------|-----|-----|-----------|---|
| Java 1.2 (2,740 cases) | native-hunt | 50.04% | 30.11% | 63.96% | 19.92 |
| Java 1.2 | Semgrep CE, `p/java` + `p/security-audit` | 86.50% | 38.64% | 70.51% | 47.86 |
| Java 1.2 | CodeQL 2.27.4 `security-extended` | 100% | 40.08% | 72.71% | 59.92 |
| Python 0.1 (1,230 cases) | native-hunt | 26.55% | 3.98% | 79.47% | 22.56 |
| Python 0.1 | Semgrep CE, `p/python` + `p/security-audit` | 29.65% | 11.57% | 59.82% | 18.08 |
| Python 0.1 | CodeQL 2.27.4 `security-extended` | 25.22% | 19.28% | 43.18% | 5.94 |

On Java, native-hunt reports SQL injection, XSS, LDAP and XPath cases at about the same
rate whether or not they are vulnerable. AI review and model hunt have no measured
quality result yet: retained model runs use synthetic providers or found no candidates.

## Tech Stack

- **Language**: Python 3.11+
- **Web Framework**: FastAPI + Uvicorn
- **Templating**: Jinja2 (legacy server pages; the PIT WALL SPA is React)
- **Database**: SQLite via SQLAlchemy (sync sessions)
- **CLI**: Typer
- **HTTP Client**: httpx
- **Analyzer**: native-hunt (regex and intra-file taint, no external binary)
- **Other scanners**: Semgrep CE, SpotBugs + FindSecBugs, OWASP Dependency-Check, OSV fallback, Gitleaks, CodeQL (opt-in)
- **AI Provider**: Project-local profiles (`.providers/*.json`, OpenAI-compatible API) + BYOK env keys
- **Web UI**: React SPA (PIT WALL) served by FastAPI; mock mode for frontend-only work
- **Build**: Hatchling

## Project Structure

```text
DevSecOps-Agent/
├── src/vulnscan/
│   ├── agent/           # Agent loop and seven read-only model tools
│   ├── ai/              # Hunt, review, compare, promotion, fix proposals
│   ├── assessment/      # IndependentValidator and CVSS v4.0 scorer
│   ├── cli/             # CLI entry points (Typer)
│   ├── context/         # Source context
│   ├── contracts/       # Shared data contracts
│   ├── core/            # ScanService, config, policy gate, RPC, source intake
│   ├── decisions/       # Laya router, questions, calibration
│   ├── evaluation/      # Metrics and calibration
│   ├── infra/           # Credential file, isolated full-profile scans
│   ├── native_hunt/     # Native-hunt engine, taint logic and rule packs
│   ├── normalization/   # Finding normalization and deduplication
│   ├── notifications/   # Telegram and Discord delivery
│   ├── pipeline/        # Pipeline helpers
│   ├── providers/       # OpenAI-compatible client and profiles
│   ├── reporting/       # Report generation
│   ├── scanners/        # Scanner adapters and bundled Semgrep rules
│   ├── storage/         # SQLite models and repositories
│   ├── training/        # Laya dataset, fine-tune and evaluation
│   ├── tui/             # Textual interface
│   ├── verification/    # Opt-in HTTP probes
│   └── web/             # FastAPI backend and legacy Jinja pages
├── cmd/, internal/      # Go CLI, TUI, bridge and native dashboard
├── web-ui/              # React web UI
├── ci/                  # Native build, release and Action helpers
├── config/              # Shipped Laya and security configuration
├── docs/                # Requirements, plans and verification records
├── evidence/            # Retained measurements; never rewritten
├── tests/               # Tests, one directory per area
├── pyproject.toml
└── LICENSE
```

`src/vulnscan/harness/` has no tracked implementation on this branch.

## Scope — what it scans (and what it does not)

| Area | Status |
|------|--------|
| Java Servlet/JSP | Native-hunt 30 rules on `.java`, `.jsp`, `.jspx`; Semgrep 25 rules; SpotBugs and Dependency-Check on `full`. A retained 2026-11-01 run shows Semgrep analyzing 101 Java files and marking all 38 JSP files unsupported. Native-hunt reads JSP by pattern; JSP accuracy is not measured separately. |
| JavaScript/TypeScript | Native-hunt 25 rules; Semgrep 20 rules. No answer-key measurement yet. |
| Python | Native-hunt 23 rules; Semgrep 20 rules. Measured on OWASP BenchmarkPython. |
| PHP | Native-hunt 23 rules; Semgrep 20 rules. No answer-key measurement yet. |
| Secrets/credentials | Native-hunt CWE-798 rules; Gitleaks when selected. |
| Java dependencies | OWASP Dependency-Check on `full`, with OSV.dev fallback when the binary or NVD is unavailable. |
| Notifications | In-app bell plus selectable Telegram/Discord digests. Tested with synthetic HTTP responses, not delivered to the real services. |
| OWASP/CWE report cross-reference | OWASP Top 10:2025 section from primary and secondary CWE labels, with finding references, status counts and explicit unmapped cases; [report guide](docs/OWASP-REPORTING.md) |
| Targeted verification probes | Opt-in HTTP probes (reflected-XSS canary, SQL-error signatures) as extra evidence, never findings by themselves. |
| Model-first hunt (`--mode hunt`) | One pass per extension family present (java/js-ts/py/php), a generic pass for other text, and a logic pass (authZ/session/crypto). Findings carry a `provenance` of `model`, `scanner` or `both`. |
| DAST / runtime attacks | **Not supported.** |
| Auto-remediation | **Not supported.** Proposals only; you apply them. |
| Kotlin, Go, Ruby, C# and others | No dedicated rules. The generic hunt pass can read their text. |

Semgrep rules have `Vuln*` and `Safe*` fixtures (`tests/scanners/test_*_rules.py`). These
tests need a working Semgrep; in the last recorded Windows run they errored because Semgrep
crashed on that machine (see [Development](#development)).

## Installation

### Prerequisites

- Python 3.11 or later
- Java 11+ (only for SpotBugs and target builds)
- Maven 3.6+ (for target application builds)
- Git (repository URLs, commit verification and CI; optional for plain local folders)

### Setup

```bash
# Clone the repository
git clone https://github.com/ppk205/DevSecOps-Agent.git
cd DevSecOps-Agent

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install the project in development mode
pip install -e ".[dev,scanners]"

# Install scanner binaries (if not already available)
# Semgrep: pip install semgrep
# SpotBugs: download from https://spotbugs.github.io/
# FindSecBugs: download plugin from https://find-sec-bugs.github.io/
# OWASP Dependency-Check: download from https://owasp.org/www-project-dependency-check/
# Gitleaks: download from https://github.com/gitleaks/gitleaks
```

### Configuration

Register an OpenAI-compatible Chat Completions profile using your endpoint and
model name. The following endpoint and model are placeholders:

```bash
devsecops-agent provider-add --id my-provider \
  --base-url https://your-provider.example/v1 \
  --api-key-env MY_PROVIDER_API_KEY --models your-model --default-model your-model
devsecops-agent env set MY_PROVIDER_API_KEY
```

The key command prompts without echoing the value. Native Workspace also has
masked key entry. Profiles are local JSON under `.providers`; keys can be saved
through `EnvFile` in the local gitignored `.env`. Profiles and keys resolve from
the project root when launching inside `bin`. An externally injected process
value takes precedence. Updating a key loaded from the same local file refreshes
it for subsequent scans. The application does not encrypt these files.

In the native EXE, select **Hunt** in **Scan mode**, choose a provider profile,
and optionally enter a model override. Review with **Ctrl+E**, check the provider,
model and key status, then start with **Ctrl+S**. Hunt includes AI review and the
final narrative. For review or report support without hunting, keep deterministic
mode and enable the corresponding controls in Advanced. Saving a key alone does
not enable native model calls.

**Activity** shows model requests, returned explanations and tool steps as calls
finish. Open a finding with **Enter** to inspect its retained AI rationale and
proposed status. Reported token counts are retained; omitted usage and monetary
cost are shown as unavailable. This is call-level progress; token-by-token
streaming is not implemented. See [native AI support](docs/NATIVE-MIGRATION.md#ai-support)
and the [verification record](docs/NATIVE-AI-VERIFICATION-2026-11-04.md).

Scanner binaries resolve via `PATH` with a `sys.prefix` fallback; install them
once (Semgrep: `pip install semgrep`, Gitleaks/SpotBugs/ODC from their
upstream releases). Local dirty checkouts require `--allow-dirty`.

## Usage

### CLI

```bash
# Model-free scan with native-hunt only (no external binary)
# native.json: {"schema_version": 1, "tools": ["native-hunt"]}
devsecops-agent scan-run --checkout /path/to/repo --out artifacts/native \
  --config native.json --db-path scans.db --allow-dirty --mode deterministic --no-laya

# Model-free scan with the fast profile (native-hunt + Semgrep + Gitleaks)
devsecops-agent scan-run --checkout /path/to/repo --out artifacts/demo \
  --profile fast --db-path scans.db --allow-dirty --mode deterministic --no-laya

# + targeted AI review and AI-written final report (needs a provider profile)
devsecops-agent scan-run --checkout /path/to/repo --out artifacts/demo-ai \
  --mode deterministic --no-laya --ai-review --provider my-provider \
  --model your-model --max-ai-findings 2 --ai-report

# Model-first hunt: the model hunts with read-only tools, scanners run separately,
# results are compared, AI reviews, the validator decides, a report is written
devsecops-agent scan-run --checkout /path/to/repo --out artifacts/demo-hunt \
  --mode hunt --provider my-provider --model your-model \
  --max-ai-findings 5 --ai-report

# Export retained evidence without rerunning scanners
devsecops-agent scan-export 37 --fmt html --out artifacts/run37-new

# Start the local web backend (PIT WALL reads this DB)
devsecops-agent serve --host 127.0.0.1 --port 8000
```

### Web Dashboard

The legacy Jinja pages (`/`, `/runs/...`). The main interface is the
PIT WALL SPA below — the dashboard links there.

### Web UI (PIT WALL)

The React SPA at `/app/` (FastAPI serves `web-ui/dist`; legacy Jinja stays at `/`).

```bash
cd web-ui
npm install
VITE_MOCK=1 npm run dev        # mock mode: scripted run, no backend
npm run build                  # tsc + vite build -> web-ui/dist (offline-safe)
npm test                       # vitest run
npm run lint                   # tsc --noEmit
```

Live backend: `npm run build`, then serve via uvicorn — the SPA proxies
`/api` to `127.0.0.1:8000` under `npm run dev`. Contract version header:
`X-Contract-Version: 1`.

| Route | Page |
|---|---|
| `/app/` | Home (mission control, KPIs, charts, history) |
| `/app/scans/new` | New scan (FAST/DEEP profile, scanners, AI review, Hunt switch, CLI preview) |
| `/app/live` | Live pipeline (8 stages, AI panel, results, log dock) |
| `/app/findings` | Findings table, filters, drawer + detail, CSV export, **Fix all** |
| `/app/reports` | Report generate/preview/download + compare |
| `/app/logs` | Log stream, filter, copy, .log/.jsonl download |
| `/app/keys` | API keys (write-only), tools, usage, settings |
| `/app/styleguide` | Hidden token/component inventory (not in nav) |

Notes and decisions:

- **Reports CSV**: flat finding-rows export (`finding_id,title,severity,
  status,tools,file,line,cwe`), generated via the reports table
  (`text/csv` download) and mirrored client-side from Findings
  ("Export CSV"). Decision: CSV stays a flat rows dump, not a formatted report.
- **Keys are write-only**: the API never returns secrets (masked `••••8901`
  display only); covered by the secret-leak tests in `tests/web/`.
- **i18n**: EN/VI dictionaries in `web-ui/src/i18n/` (`vi.ts` mirrors `en.ts`
  key-for-key, enforced by test); EN/VI toggle in the topnav persists to
  `localStorage` and sets `document.documentElement.lang`. Brand headlines
  stay UPPERCASE in both languages.
- **Accessibility**: WCAG 2.2 AA contrast on black (muted `#909090`);
  2px white focus ring; full keyboard operation (J/K + arrows + Esc);
  `aria-live="polite"` on the AI feed and counters (never on log lines);
  44px+ touch targets on coarse pointers.
- **Verification limits (honest)**: layout widths 375/768/1024/1440/1920
  were verified by responsive-class audit + jsdom render — no real
  Chromium exists in this environment, so no rendered screenshots were
  captured (see `docs/screenshots/` for the textual page inventory).
  Lighthouse could not run headless here — performance/PWA/SEO scores
  are unverified.

## How It Works

### Scan Pipeline

This section follows `ScanService._run`. Both modes share one path:

1. **Intake**: checkout manifest and source snapshot.
2. **Model hunt** (`--mode hunt`, the Python default): the model explores the snapshot in
   sequential passes with `list_files`, `grep_code` and `inspect_code`. It is skipped with a
   reason when no provider is available. In `--mode deterministic` this stage is skipped.
3. **Scanners**: each selected tool scans the whole snapshot. Scanners do not receive the
   model's candidates. `fast` selects Semgrep, native-hunt and Gitleaks; `full` adds SpotBugs
   and Dependency-Check; a config file can select `tools: ["native-hunt"]`. For comparison
   work, the product scanners are baselines and native-hunt is the project's analyzer.
4. **Normalization and dedup**, then **Laya routing**. Laya is advisory and only sees scanner
   findings at this point. `ScanConfig` enables it by default, but the shipped
   `config/laya.json` is disabled.
5. **Only when the hunt returned candidates**: Laya checks the candidates, code compares them
   with scanner findings (file, line within 3, CWE), and model-only candidates whose excerpt
   can be re-read become findings. Provenance is `model`, `scanner` or `both`. Hunt detail is
   written to `hunt.json`.
6. **Targeted AI review** of at most `max_ai_findings` (default 10). With candidates, it covers
   only agreed and promoted findings, so scanner-only findings are not reviewed. Without
   candidates, it selects from all findings, deep-analysis routes first.
7. **Independent validation** of the review's assessments. It is skipped when none exist.
8. **Final AI narrative**. The gate is still pending when this text is written.
9. **Policy gate** (`fail_on`, default `high`), then **report exports** and
   **optional notifications**.

Exit code 1 from `scan-run` means vulnerabilities were found: `errors: []` with gate `failed`.
Exit code 2 means the scan itself did not complete cleanly, for example incomplete scanner
coverage or a failed export.

### Finding lifecycle and rail colors

`unprocessed` → (`unresolved` | `confirmed` | `rejected`). The contract also defines
`triaged`, `assessed` and `pending_validation`; the pipeline does not assign them. On the Live rail:
**green** = completed/verified, **yellow** = partial/unresolved (needs a
human), **red** = failed, gray = pending. The scanner lane aggregates all
scanners; per-tool detail lives in the feed and log dock.

### AI fix proposals (diff → overlay → rescan)

From any finding (drawer button) or the whole run (**Fix all**):

1. The model writes **only a unified diff** — it cannot touch source. The
   prompt carries ~60 numbered source lines around the finding so context
   matches the real file; the applier is strict and rejects drift.
2. You review the diff in the proposals panel.
3. **Apply** patches a **copy** under `artifacts/reports/fix-<run>/`
   (your checkout is never modified).
4. The app rescans the patched copy with the finding's bundled Semgrep rule:
   `verified` (rule silent) or `failed` with the reason. This needs Semgrep, and a rule
   that is not in the bundled set reports `failed`.
5. Statuses: `proposed` → `applied` → `verified` (yellow → green),
   `failed` is red with the error shown. Re-requesting skips already-proposed
   rows and retries failed ones.

API: `POST /api/scans/{id}/fix` (`finding_ids` or `null` = all),
`GET /api/scans/{id}/fixes`, `POST /api/scans/{id}/fixes/{pid}/apply`,
`GET /api/scans/{id}/fixes/{pid}/download` (raw `.diff` to take the patch
anywhere, e.g. targets without git).

### Validation

The model only proposes; `IndependentValidator` owns AI-driven finding-status
decisions, and human review remains available. Model confidence and raw scanner
observations do not count as independent proof. Terminal decisions require
scoped supporting/counterevidence from trusted independent checks. Conflicting
evidence stays unresolved. Blocked, failed, incomplete and fixed-variant checks
cannot confirm the original finding. Decisions retain policy version, used IDs,
ignored records and verification outcomes.

The previous counterevidence/counting defect is corrected. Its historical
records remain unchanged; earlier `confirmed` labels are not recertified by
this fix. Current scanner/model review does not run a general semantic source
verifier, so those proposals normally remain unresolved for human review.
FR-51/52/54 source checks and semantic verification of CVSS assumptions remain
implementation gaps.

The CVSS scorer now uses FIRST v4.0 MacroVectors and interpolation, strict metric
order/values and all eleven Base metrics. Valid vectors are scored in both
bounded-agent and single-shot review. Model numeric scores are ignored; missing
or invalid vectors stay unscored. Base and contextual scores are recorded
separately, with `metric_assumptions_verified=False`. See the
[validator and CVSS guide](docs/VALIDATOR-CVSS.md) and its verification record.

## Training Laya (teach it to route)

Laya is `convaiinnovations/laya` rev `aa8c91ca` (ModernBERT-large 0.4B +
typed decision heads, CPU inference). The repo ships a full offline training
loop in `src/vulnscan/training/` (`dataset.py` leakage-resistant export,
`finetune.py` full fine-tune with gradient checkpointing + fp16,
`evaluate.py` frozen-checkpoint scoring with calibration).

Why train: a local training run reported 31% route agreement for the frozen checkpoint and
93.75% after teaching on 94 labels (holdout 16). That run's scores are not retained as an
artifact in this repository, so treat them as unverified. The retained evaluation in
`evidence/t09/` measures the frozen checkpoint at 55.17% route accuracy on 29 agent-labelled
findings, with 9 dangerous downgrades.

End to end on the RTX 3050 4GB machine:

```bash
# 0) Isolated train env (never touch the main CPU-only venv)
uv venv D:/dev/laya-train/.venv --python 3.11
uv pip install --python D:/dev/laya-train/.venv/Scripts/python.exe \
  torch --index-url https://download.pytorch.org/whl/cu124
uv pip install --python D:/dev/laya-train/.venv/Scripts/python.exe \
  transformers peft datasets accelerate "laya==0.3.20" \
  huggingface_hub safetensors pydantic sqlalchemy

# 1) Scan repos to label (any completed runs do)
devsecops-agent scan-run --checkout ... --db-path D:/dev/laya-data/synth.db ...

# 2) Label each finding: expected_route + evidence_sufficiency (0-2) +
#    needs_human_review + project/case family + two reviewers.
#    Rule of thumb used here: single-statement sink -> fast_verification;
#    needs caller/source -> cross_file_analysis; prod secret -> secret_review;
#    test/docs secret -> low_priority; human=true only when the snippet
#    cannot decide. Fixtures auto-label: Vuln* -> route, Safe*/Silent* ->
#    low_priority. Needs >= 4 independent projects.

# 3) Build the leakage-checked dataset (train/validation/calibration/test)
PYTHONPATH=src python -m vulnscan.training.dataset \
  --scan scans-real.json --scan scans-synth.json \
  --labels labels-all.json --out D:/dev/laya-data/dataset
# -> 94 rows here: train 64 / validation 12 / calibration 2 / test 16

# 4) Baseline the frozen checkpoint
PYTHONPATH=src python -m vulnscan.training.evaluate \
  --test D:/dev/laya-data/dataset/test.jsonl \
  --model convaiinnovations/laya --out baseline.json

# 5) Validate shapes, then train (microbatch 1 fits 2.4GB free VRAM)
PYTHONPATH=src D:/dev/laya-train/.venv/Scripts/python.exe \
  -m vulnscan.training.finetune --data D:/dev/laya-data/dataset \
  --out D:/dev/laya-train/out --mode validate --microbatch 1
PYTHONPATH=src D:/dev/laya-train/.venv/Scripts/python.exe \
  -m vulnscan.training.finetune --data D:/dev/laya-data/dataset \
  --out D:/dev/laya-train/out --mode train --epochs 4 \
  --microbatch 1 --accumulation 16 --seed 42

# 6) Gate: holdout agreement >= 80% before wire-in
PYTHONPATH=src python -m vulnscan.training.evaluate \
  --test D:/dev/laya-data/dataset/test.jsonl \
  --model D:/dev/laya-train/out --out trained.json

# 7) Wire-in: point the backend at the trained dir (falls back to hub if unset)
export LAYA_MODEL_DIR='D:/dev/laya-train/out'
# Proven live: routing records model_id D:/dev/laya-train/out + sha256 identity.

# 8) GPU (optional, same host): the trained 842MB checkpoint fits a 4GB laptop
# GPU (0.9s/predict proven live; the 3.7GB base did not). Main venv is
# CPU torch, so point the worker at the CUDA venv + request cuda; any
# failure (OOM included) falls back to CPU and never kills a scan.
export LAYA_WORKER_PYTHON='D:/dev/laya-train/.venv/Scripts/python.exe'
export LAYA_DEVICE='cuda'
```

Notes: training data, datasets, and weights live **outside the repo**
(`D:/dev/laya-*`); only code is committed. Watch validation loss per epoch —
with ~60 train rows it overfits fast (here: 3.53 → 6.58); the saved
checkpoint is the best epoch. The holdout here is small (16), so treat the
score as encouraging rather than final — add hard labels
(`cross_file_analysis`, secrets) before trusting new lanes. The
`LAYA_MODEL_DIR` override is covered by unit tests and falls back safely.

## Development

```bash
.venv/Scripts/python.exe -m ruff check src tests ci
.venv/Scripts/python.exe -m ruff format --check src tests ci
.venv/Scripts/python.exe -m mypy src/vulnscan
.venv/Scripts/python.exe -m pytest -q
go vet ./internal/... ./cmd/...
go test ./internal/... ./cmd/...
cd web-ui && npm run lint && npm test && npm run build
```

The last recorded full run is not clean (`evidence/notifications-2026-11-04/`, Windows):

| Check | Result |
|-------|--------|
| pytest | 760 passed, 15 failed, 1 skipped, 191 errors. All 191 errors are Semgrep rule tests; the 15 failures match the list from before that change. |
| ruff check | 2 errors |
| ruff format | 13 files would be reformatted |
| mypy | 4 errors in 3 files |
| web-ui | 77 tests passed; lint and build passed |
| Go application packages | vet and test passed |
| `go test ./...` | Fails only because of the local `artifacts/tui-verification` probe |
| Native builds | Five cross-compiled binaries and the local Windows executable built; cross-compilation is not a run on those platforms |

```bash
# Run a specific test module
PYTHONPATH=src .venv/Scripts/python.exe -m pytest tests/scanners/ -q -p no:randomly
```

Conventions are in `AGENTS.md`: regression test first, no hook bypass, never
commit weights, datasets, keys, `.providers/`, or `artifacts/`. Findings and
labels created by agents record `labelled_by`; agents never self-assign
`expected_route` and grading. DB migrations are additive with
`schema_migrations` pins (covered by `test_dr09`).

### Adding a new scanner / language ruleset

1. Add a Semgrep ruleset in `src/vulnscan/scanners/rules/<lang>.yml`
   (id prefix `<lang>-`, `cwe` + `version` metadata, taint mode where
   dataflow matters).
2. Add `Vuln*`/`Safe*` fixtures under `tests/scanners/fixtures/<lang>/`
   plus SILENT boundary fixtures.
3. Add `tests/scanners/test_<lang>_rules.py` mirroring `test_java_rules.py`
   (single batched run, CASES + SILENT_FIXTURES).
4. Extend `LanguageKind` + `WEB_SOURCE_EXTENSIONS` in
   `src/vulnscan/contracts/enums.py` (the default Semgrep load picks up every
   `rules/*.yml` automatically).
5. Run `semgrep --validate`, the new test, and the full `tests/scanners/`
   suite (guards against cross-language false positives).

## Limitations

- Current scanner/model review does not independently re-derive sanitizer,
  authorization or CVSS metric assumptions from source. Proposals stay unresolved
  without trusted independent checks; historical validation labels are not
  automatically rewritten. See [Validation](#validation).
- AI review and hunt have no measured accuracy yet.
- Native-hunt analyzes one file at a time and scores below Semgrep and CodeQL on OWASP
  Benchmark Java. Its rule confidence is not reliable: on Java, 0.9 rules have 56.02% precision
  and 0.3 rules have 84.10%.
- Hunt and review prompts still describe the target as Java Servlet/JSP.
- No prompt-injection test exists, and prompts do not mark source as untrusted data.
- Local-only, single user; no hosted mode, no accounts. Optional Telegram Bot
  API and Discord incoming-webhook notifications send selected summary events.
  Configure event choices and credentials explicitly; see
  [notification setup](docs/NOTIFICATIONS.md). New installations disable both
  destinations. The legacy `WEBHOOK_URL` gate-failure integration remains separate.
- Static analysis only — no DAST, no runtime exploitation. Opt-in targeted
  HTTP probes (XSS canary, SQL-error signatures, allowlisted host only) can
  corroborate a finding as extra evidence.
- Laya is advisory and never sets a finding status.
- Free-tier providers rate-limit (stages slow down with backoff) and some
  reasoning-only models return empty content the pipeline must work around.
- Training on a 4GB laptop GPU fits only tiny datasets with microbatch 1;
  use the Kaggle notebook path from `docs/LAYA-TRAINING.md` for anything big.
- CodeQL is an opt-in DEEP step (needs the CodeQL CLI bundle); ODC needs NVD
  downloads (flaky offline — OSV.dev fallback covers manifests).

## Budget and Timeline

- **Total budget**: USD 50 for AI usage
- **Timeline**: 17 weeks (2 students)
- **Target**: JVA-bookstore (101 Java files, 38 JSP files)

## Team

- **Tran Doan Hoa** (23162026) — Student
- **Nguyen Minh Khoi** (23162046) — Student
- **Supervisor**: Nguyen Thi Thanh Van

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
## Terminal and CI

```sh
uv sync --frozen --extra dev
uv run devsecops-agent          # TUI in a terminal; help when redirected
uv run devsecops-agent tui
uv run devsecops-agent --version
uv run devsecops-agent scan-run --checkout /path/to/clean/repo --profile fast --json --db-path scans.db --out artifacts
```

The TUI offers saved history, configuration review, live progress, searchable
findings/evidence, cancellation, retries and JSON/SARIF/HTML/Markdown exports.
Use Ctrl+N for setup, Ctrl+R for history refresh, Ctrl+X to cancel and Ctrl+Q to
quit. A running scan must finish cancellation before quitting. In the native
TUI, Up/Down moves between controls; Left/Right switches views or cycles choices.
While editing text, Left/Right moves the cursor. Enter activates or edits, and
Esc returns. Tab remains optional. UTC timestamps display in Asia/Saigon by default.

Scanners must be installed separately. Fast scans require Semgrep and Gitleaks;
missing tools produce an actionable failure and partial reports. Local dirty
checkouts require `--allow-dirty` and retain a content-hash manifest. CI rejects
dirty checkouts. AI stages (Laya routing, review, validation, AI report) run
when Hunt or the corresponding AI option is selected and a provider profile/key
is available. Python configuration defaults to Hunt; native configuration
defaults to deterministic scanning with AI review/report disabled.
The existing `serve` command keeps the local web interface available.

See [consumer workflows, required checks and GitHub releases](docs/CI-INTEGRATION.md)
and [requirement-to-test traceability](docs/TEST-PLAN.md). Application version comes
from installed package metadata; contract schema versions remain independent.
