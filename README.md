# DevSecOps-Agent

Source analysis for **Java/Servlet/JSP, JavaScript/TypeScript, Python and PHP**.
The application combines the native-hunt analyzer, scanner baselines, AI support
for investigation, independent validation, reports and fix proposals. It runs
as a single-user local application. Enabled AI stages can send source excerpts
to the configured provider. Keys use masked entry and local environment storage;
profiles contain credential variable references.

```
CLI (Typer) ─┬─ deterministic lane ──────────────────────────────┐
             │                                                    ▼
             │   static scanners ─► normalize/dedup ─► Laya routing ─► AI review ─► validator ─► report
             │                                                    ▲                      │
             └─ hunt lane ───────────────────────────────────────┘                      ▼
                model multi-pass hunt (per language family + generic + logic)
                  ─► scanners verify ─► compare ─► model-only promotion      fix proposals
                                                                                 (diff → overlay → rescan)
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

DevSecOps-Agent is a local application that detects, classifies, and assesses
vulnerabilities in web projects. It combines conventional static analysis
tools (Semgrep, SpotBugs/FindSecBugs, OWASP Dependency-Check, Gitleaks) with
model-first hunting, AI-assisted contextual analysis and CVSS v4.0 severity
assessments. Every AI-generated conclusion is independently verified through
mechanical checks.

The experimental target is [JVA-bookstore](https://github.com/Moseyuh333/JVA-bookstore) (commit `dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5`): 97 Java source files, 38 JSP files, Java 11, Maven WAR packaging, PostgreSQL, `javax.servlet`.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              CLI / PIT WALL Web UI / Go TUI              │
│         (Typer + React SPA + FastAPI + native Go)        │
├─────────────────────────────────────────────────────────┤
│                   Orchestration Layer                    │
│            (scan lifecycle, queue, retry)                │
├─────────────────────────────────────────────────────────┤
│  Deterministic lane        │  Model-first lane (--hunt)  │
│  Semgrep, Gitleaks,        │  Model hunts (read-only     │
│  SpotBugs, ODC             │  tools) → scanners verify    │
├────────────────────────────┴────────────────────────────┤
│              Normalization & Deduplication               │
├─────────────────────────────────────────────────────────┤
│   Laya advisory routing + independent verification      │
├─────────────────────────────────────────────────────────┤
│   Targeted AI review (CVSS v4.0) + independent validation│
├─────────────────────────────────────────────────────────┤
│          Reporting & Experiment Comparison               │
│   (JSON, SARIF, HTML, Markdown, CSV, TXT, DOCX)          │
├─────────────────────────────────────────────────────────┤
│   Storage: SQLite (SQLAlchemy) + Artifact Files          │
└─────────────────────────────────────────────────────────┘
```

## Supported Vulnerability Groups (CWE)

| CWE ID | Description |
|--------|-------------|
| CWE-89 | SQL Injection |
| CWE-78 | OS Command Injection |
| CWE-79 | Cross-Site Scripting (XSS) |
| CWE-22 | Path Traversal |
| CWE-434 | Unrestricted File Upload |
| CWE-918 | Server-Side Request Forgery (SSRF) |
| CWE-611 | XML External Entity (XXE) |
| CWE-502 | Deserialization of Untrusted Data |
| CWE-798 | Hard-coded Credentials |
| CWE-327 | Broken or Risky Cryptographic Algorithm |
| CWE-330 | Use of Insufficiently Random Values |
| CWE-862/639 | Missing Authorization / Insecure Direct Object Reference |

Dependency vulnerabilities (OWASP Dependency-Check) are evaluated separately from source-code findings.

## Tech Stack

- **Language**: Python 3.11+
- **Web Framework**: FastAPI + Uvicorn
- **Templating**: Jinja2 (legacy server pages; the PIT WALL SPA is React)
- **Database**: SQLite via SQLAlchemy (sync sessions)
- **CLI**: Typer
- **HTTP Client**: httpx
- **Scanners**: Semgrep CE, SpotBugs + FindSecBugs, OWASP Dependency-Check, Gitleaks, CodeQL (experimental)
- **AI Provider**: Project-local profiles (`.providers/*.json`, OpenAI-compatible API) + BYOK env keys
- **Web UI**: React SPA (PIT WALL) served by FastAPI; mock mode for frontend-only work
- **Build**: Hatchling

## Project Structure

```
DevSecOps-Agent/
├── src/vulnscan/           # Application source code
│   ├── agent/              # Agentic loop + read-only code tools
│   ├── ai/                 # Hunt, review, compare, fix proposals
│   ├── assessment/         # CVSS v4.0 assessment logic
│   ├── cli/                # CLI entry points (Typer)
│   ├── contracts/          # Shared data contracts (findings, enums, providers)
│   ├── core/               # Scan service, config, manifests, policy gate
│   ├── decisions/          # Laya router, triage questions, calibration
│   ├── normalization/      # Finding normalization & deduplication
│   ├── providers/          # LLM provider abstraction (BYOK profiles)
│   ├── reporting/          # Report generation (JSON/SARIF/HTML/MD/CSV/TXT/DOCX)
│   ├── scanners/           # Scanner adapters + bundled rulesets (java/js/py/php)
│   ├── storage/            # Database models & repositories
│   ├── training/           # Laya dataset / finetune / evaluate pipeline
│   ├── verification/       # Independent verification engine
│   └── web/                # FastAPI backend + PIT WALL SPA contract
├── tests/                  # Test suite
│   ├── ai/                 # AI agent tests
│   ├── analysis/           # Analysis pipeline tests
│   ├── evaluation/         # Evaluation & accuracy tests
│   ├── platform/           # Platform integration tests
│   ├── reporting/          # Report generation tests
│   ├── sandbox/            # Sandbox execution tests
│   ├── validation/         # Verification engine tests
│   └── web/                # Web API tests
├── docs/                   # Documentation
├── rules/                  # Semgrep custom rules
├── prompts/                # AI prompt templates
├── evaluation/             # Evaluation datasets & benchmarks
├── harness/                # Test harness & fixtures
├── infra/                  # Infrastructure configuration
├── pyproject.toml          # Project metadata & dependencies
├── LICENSE                 # MIT License
└── .planning/              # Project planning documents
```

## Scope — what it scans (and what it does not)

| Area | Status |
|------|--------|
| Java Servlet/JSP | Full: 25 Semgrep rules (injection incl. LDAP/XPath/XXE/SSRF/log, crypto, cookie/session, open redirect, reflection, error exposure) + SpotBugs + ODC |
| JavaScript/TypeScript | 20 Semgrep rules (SQLi, NoSQLi, XSS, exec/spawn, eval/implied-eval, ReDoS, JWT, postMessage, CORS, timing compare, weak hash, debug leftover, path traversal) |
| Python | 20 Semgrep rules (SQLi, LDAPi, XXE, header injection, open redirect, command injection, eval, pickle/dill variants, JWT, TLS-verify-off, debug mode, weak hash, secrets) |
| PHP | 20 Semgrep rules (SQLi concat, reflected XSS, command injection, XXE, open redirect, create_function, dynamic callable, parse_str/extract pollution, preg /e, phar wrapper, session fixation, JWT, weak random, eval) |
| Secrets/credentials | Gitleaks, all languages and docs |
| Java dependencies | OWASP Dependency-Check (DEEP profile), with **OSV.dev fallback** when the binary/NVD is unavailable |
| Notifications | In-app bell plus selectable Telegram/Discord digests; automatic or manual delivery with retained status |
| Targeted verification probes | Opt-in HTTP probes (reflected-XSS canary, SQL-error signatures) as extra evidence — never auto-findings |
| Model-first hunt (`--mode hunt`) | Multi-pass, one per extension family present (java/js-ts/py/php) + generic fallback for other text + logic pass ON (authZ/session/crypto); findings carry an origin chip (model/scanner/both), model-only candidates land in hunt.json + final report for human review |
| DAST / runtime attacks | **Not supported** — static analysis only |
| Auto-remediation | **Not supported** — proposals only, you apply |
| Other languages (Go, Ruby, C#…) | Generic hunt fallback pass covers any text, but no dedicated rules yet |

Every rule is tested both directions: it must fire on its `Vuln*` fixture
and stay silent on its `Safe*` fixture (`tests/scanners/test_*_rules.py`,
single batched Semgrep run per language, no cross-language false positives).

## Installation

### Prerequisites

- Python 3.11 or later
- Java 11+ (for Semgrep, SpotBugs, and target application analysis)
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
# Model-free scan (native-hunt + Semgrep + Gitleaks)
devsecops-agent scan-run --checkout /path/to/repo --out artifacts/demo \
  --profile fast --db-path scans.db --allow-dirty --mode deterministic --no-laya

# + targeted AI review and AI-written final report (needs a provider profile)
devsecops-agent scan-run --checkout /path/to/repo --out artifacts/demo-ai \
  --mode deterministic --no-laya --ai-review --provider my-provider \
  --model your-model --max-ai-findings 2 --ai-report

# Model-first hunt: the model hunts with read-only tools, scanners verify,
# Laya routes, AI reviews, validator confirms, report is written for humans
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

Two lanes, one gate:

- **Deterministic lane** (`--profile fast|full`): intake → static scanners
  (native-hunt, Semgrep, Gitleaks, + SpotBugs/ODC on full) → normalization
  & dedup. `native-hunt` is the in-house engine (regex + intra-file taint,
  90 rules across java/js-ts/py/php, no external binary); Semgrep/SpotBugs
  stay as baseline oracles for evaluation, not the primary evidence.
- **Model-first lane** (`--mode hunt`, Python default): the model hunts the snapshot
  in sequential passes — one per extension family present (java/js-ts/py/php,
  plus a generic pass for any other web-hostable text) + a logic pass
  (authZ/IDOR/session/crypto, ON by default) — with read-only tools
  (`list_files`, `grep_code`, `inspect_code`). Scanners verify each candidate
  → model/scanner comparison → model-only candidates are promoted to findings
  with a `provenance` chip (`model`/`scanner`/`both`) and get full AI review +
  validator verdicts. Hunt detail (per-pass counts, trace) lands in `hunt.json`.

Then, for both lanes: Laya routing → targeted AI review with CVSS v4.0 →
independent validation (conservative: only decisive evidence flips a status)
→ final AI-written report (TXT/MD/DOCX) + machine exports
(JSON/SARIF/HTML/Markdown/CSV).

The policy gate fails when high-severity findings remain (`fail_on`,
default `high`). Exit code 1 from `scan-run` means "vulnerabilities found",
not "scan broken" — `errors: []` plus gate `failed` is the healthy
vulnerable-repo signal.

### Finding lifecycle and rail colors

`unprocessed` → (`unresolved` | `confirmed` | `rejected`). On the Live rail:
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
4. The app rescans the patched copy with the finding's rule:
   `verified` (rule silent) or `failed` with the reason.
5. Statuses: `proposed` → `applied` → `verified` (yellow → green),
   `failed` is red with the error shown. Re-requesting skips already-proposed
   rows and retries failed ones.

API: `POST /api/scans/{id}/fix` (`finding_ids` or `null` = all),
`GET /api/scans/{id}/fixes`, `POST /api/scans/{id}/fixes/{pid}/apply`,
`GET /api/scans/{id}/fixes/{pid}/download` (raw `.diff` to take the patch
anywhere, e.g. targets without git).

### Verification Philosophy

AI is a **supporting tool**, not the final authority. Every AI-generated assessment is subject to mechanical verification:

- **Sanitization claims** are checked against actual encoding/context
- **Authorization assumptions** are verified against the declared policy
- **CVSS vector components** are validated against source evidence
- **Scope and impact estimates** are cross-referenced with application architecture

Failed verifications are flagged and reported — findings with unverifiable AI conclusions remain in their scanner-original state.

## Training Laya (teach it to route)

Laya is `convaiinnovations/laya` rev `aa8c91ca` (ModernBERT-large 0.4B +
typed decision heads, CPU inference). The repo ships a full offline training
loop in `src/vulnscan/training/` (`dataset.py` leakage-resistant export,
`finetune.py` full fine-tune with gradient checkpointing + fp16,
`evaluate.py` frozen-checkpoint scoring with calibration).

Why train: the frozen checkpoint scored **31% route agreement** on real
findings (over-cautious, mean confidence 0.43, 8× `fast_verification` dumped
to `low_priority`). After teaching on 94 hand-checked labels it scores
**93.75%** (ECE 0.06, confidence ~1.0).

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
PYTHONPATH=src .venv/Scripts/python.exe -m pytest -q -p no:randomly \
  --ignore=tests/e2e --timeout=90 --timeout-method=thread   # full suite (~6 min, 790 passed)
.venv/Scripts/python.exe -m ruff check src tests
.venv/Scripts/python.exe -m ruff format --check src tests
.venv/Scripts/python.exe -m mypy --platform win32 src/vulnscan
cd web-ui && npx tsc -p tsconfig.json && npx vitest run && npm run build
```

```bash
# Run a specific test module
PYTHONPATH=src .venv/Scripts/python.exe -m pytest tests/scanners/ -q -p no:randomly
```

Conventions: TDD per task, frequent commits (`git -c core.hooksPath=/dev/null`
when hooks misbehave), plan/design docs stay local under `.hermes/`, never
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

## Limitations (honest)

- Local-only, single user; no hosted mode, no accounts. Optional Telegram Bot
  API and Discord incoming-webhook notifications send selected summary events.
  Configure event choices and credentials explicitly; see
  [notification setup](docs/NOTIFICATIONS.md). New installations disable both
  destinations. The legacy `WEBHOOK_URL` gate-failure integration remains separate.
- Static analysis only — no DAST, no runtime exploitation. Opt-in targeted
  HTTP probes (XSS canary, SQL-error signatures, allowlisted host only) can
  corroborate a finding as extra evidence.
- Laya is advisory; the validator is conservative, so ambiguous findings stay
  `unresolved` rather than guessed.
- Free-tier providers rate-limit (stages slow down with backoff) and some
  reasoning-only models return empty content the pipeline must work around.
- Training on a 4GB laptop GPU fits only tiny datasets with microbatch 1;
  use the Kaggle notebook path from `docs/LAYA-TRAINING.md` for anything big.
- CodeQL is an opt-in DEEP step (needs the CodeQL CLI bundle); ODC needs NVD
  downloads (flaky offline — OSV.dev fallback covers manifests).

## Budget and Timeline

- **Total budget**: USD 50 for AI usage
- **Timeline**: 17 weeks (2 students)
- **Target**: JVA-bookstore (97 Java files, 38 JSP files)

## Team

- **Tran Doan Hoa** (23162026) — Student
- **Nguyen Minh Khoi** (23162046) — Student
- **Supervisor**: Nguyen Thi Thanh Van

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
# v0.2.0 terminal and CI platform

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
