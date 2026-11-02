# DevSecOps-Agent

Automated vulnerability scanning and severity assessment for **web projects**
— **Java/Servlet/JSP, JavaScript/TypeScript, Python, and PHP** — powered by a
multi-scanner pipeline with model-first hunting, Agentic AI analysis,
independent mechanical verification, an AI-written final report, and
AI-generated fix proposals. Single-user, local-only: everything runs on your
machine, API keys stay in your shell and never in the repo.

```
CLI (Typer) ─┬─ deterministic lane ──────────────────────────────┐
             │                                                    ▼
             │   static scanners ─► normalize/dedup ─► Laya routing ─► AI review ─► validator ─► report
             │                                                    ▲                      │
             └─ hunt lane ───────────────────────────────────────┘                      ▼
                model hunts (read-only tools) ─► scanners verify ─► compare      fix proposals
                                                                                 (diff → overlay → rescan)
```

## Quickstart

Prerequisites: Python 3.11+, Git, Node 18+ (web UI only). Java 11+ only if
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
  --profile fast --db-path scans.db --allow-dirty

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
native TUI for local checkouts; `DEVSECOPS_NATIVE=python` selects Python for
all commands. The `devsec` alias is also available.

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
| Java Servlet/JSP | Full: 13 Semgrep rules + SpotBugs + ODC |
| JavaScript/TypeScript | 10 Semgrep rules (SQLi, XSS, exec, path traversal, SSRF, open redirect, eval, weak random, secrets, prototype pollution) |
| Python | 10 Semgrep rules (SQLi, XSS bypass, command injection, eval, path traversal, SSRF, SSTI, pickle/YAML, secrets, weak random) |
| PHP | 10 Semgrep rules (SQLi concat, reflected XSS, command injection, path traversal, SSRF, unserialize, weak hashing, loose comparison, extract, eval) |
| Secrets/credentials | Gitleaks, all languages and docs |
| Java dependencies | OWASP Dependency-Check (DEEP profile), with **OSV.dev fallback** when the binary/NVD is unavailable |
| Notifications | In-app bell + read/unread feed, optional gate-fail webhook |
| Targeted verification probes | Opt-in HTTP probes (reflected-XSS canary, SQL-error signatures) as extra evidence — never auto-findings |
| DAST / runtime attacks | **Not supported** — static analysis only |
| Auto-remediation | **Not supported** — proposals only, you apply |
| Other languages (Go, Ruby, C#…) | Hunt mode reads any text, but no dedicated rules yet |

Every rule is tested both directions: it must fire on its `Vuln*` fixture
and stay silent on its `Safe*` fixture (`tests/scanners/test_*_rules.py`,
single batched Semgrep run per language, no cross-language false positives).

## Installation

### Prerequisites

- Python 3.11 or later
- Java 11+ (for Semgrep, SpotBugs, and target application analysis)
- Maven 3.6+ (for target application builds)
- Git

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

AI keys are **bring-your-own** and never stored in the repo. Register a
provider profile once, then export the key in your shell:

```bash
# Register a profile (writes .providers/kios-free.json; gitignored)
devsecops-agent provider-add --id kios-free --base-url https://kiosapi.com/v1 \
  --api-key-env KIOS_API_KEY --models beam-free --default-model beam-free

# Export the key for this shell only (never commit it)
export KIOS_API_KEY='<paste-key-here>'        # git-bash / Linux
# setx KIOS_API_KEY "<paste-key-here>"         # Windows cmd (new shells)

# Models that must route through a session header (opencode go gateway)
# declare it in the profile's "headers", e.g. {"x-opencode-session": "..."}

Known-good setups: **KiosAPI free** (3 req/min; reasoning-only models often
return empty content — prefer instruct models) and **opencode go gateway**
(`https://opencode.ai/zen/go/v1`, model `iceman-contributor-free` follows
hunt JSON reliably, no call limit). Free-tier rate limits surface as slow
stages with backoff, never silent corruption. The Keys page never shows
secrets back — only the env var name and a masked fingerprint.
```

Scanner binaries resolve via `PATH` with a `sys.prefix` fallback; install them
once (Semgrep: `pip install semgrep`, Gitleaks/SpotBugs/ODC from their
upstream releases). Local dirty checkouts require `--allow-dirty`.

## Usage

### CLI

```bash
# Deterministic scan (Semgrep + Gitleaks)
devsecops-agent scan-run --checkout /path/to/repo --out artifacts/demo \
  --profile fast --db-path scans.db --allow-dirty

# + targeted AI review and AI-written final report (needs a provider profile)
devsecops-agent scan-run --checkout /path/to/repo --out artifacts/demo-ai \
  --ai-review --provider kios-free --model beam-free --max-ai-findings 2 --ai-report

# Model-first hunt: the model hunts with read-only tools, scanners verify,
# Laya routes, AI reviews, validator confirms, report is written for humans
devsecops-agent scan-run --checkout /path/to/repo --out artifacts/demo-hunt \
  --mode hunt --provider opencode-free --model iceman-contributor-free \
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
  (Semgrep, Gitleaks, + SpotBugs/ODC on full) → normalization & dedup.
- **Model-first lane** (`--mode hunt`): the model hunts the snapshot with
  read-only tools (`list_files`, `grep_code`) → scanners verify each
  candidate → model/scanner comparison → Laya advisory routing.

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
  --ignore=tests/e2e --timeout=90 --timeout-method=thread   # full suite (~6 min, 580 passed)
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

- Local-only, single user; no hosted mode, no accounts. In-app notification
  feed + optional webhook cover alerts (nothing leaves the machine unless you
  configure a webhook URL).
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
quit. A running scan must finish cancellation before quitting. Tab and arrow keys
navigate controls. UTC timestamps display in Asia/Saigon by default.

Scanners must be installed separately. Fast scans require Semgrep and Gitleaks;
missing tools produce an actionable failure and partial reports. Local dirty
checkouts require `--allow-dirty` and retain a content-hash manifest. CI rejects
dirty checkouts. AI stages (Laya routing, review, validation, AI report) run
when a provider profile + key is configured; hunt mode requires one.
The existing `serve` command keeps the local web interface available.

See [consumer workflows, required checks and GitHub releases](docs/CI-INTEGRATION.md)
and [requirement-to-test traceability](docs/TEST-PLAN.md). Application version comes
from installed package metadata; contract schema versions remain independent.
