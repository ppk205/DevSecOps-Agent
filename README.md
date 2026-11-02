# DevSecOps-Agent

The application now supports a native Go TUI and service implementation with a
Python compatibility backend. See [build and keyboard instructions](docs/NATIVE-MIGRATION.md)
and [the Laya review and training guide](docs/LAYA-TRAINING.md).

The terminal opens in **Workspace**. Choose a checkout and profile, expand
Advanced options when needed, then press **Ctrl+E** to review and **Ctrl+S** to
start. **Ctrl+K** opens the action menu. Review and finding details scroll with
arrow/page keys; **V** shows raw details. See the
[TUI review and remediation](docs/TUI-REVIEW.md) for the implemented fixes.

The default Textual workspace retains repository URL input, pinned commits,
clone-cache settings and the API Keys tab. Set `DEVSECOPS_NATIVE=go` to use the
native TUI for local checkouts; `DEVSECOPS_NATIVE=python` selects Python for
all commands. The `devsec` alias is also available.

Automated vulnerability scanning and severity assessment for web projects in **Java/Servlet/JSP, JavaScript/TypeScript, Python, and PHP**, powered by a multi-scanner pipeline with Agentic AI analysis and independent mechanical verification.

## Overview

DevSecOps-Agent is a local application that detects, classifies, and assesses vulnerabilities in Java Servlet/JSP projects. It combines conventional static analysis tools (Semgrep, SpotBugs/FindSecBugs, OWASP Dependency-Check, Gitleaks) with AI-assisted contextual analysis to produce CVSS v4.0 severity assessments. Every AI-generated conclusion is independently verified through mechanical checks.

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
- **Templating**: Jinja2
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
│   ├── agent/              # AI assessment agent
│   ├── assessment/         # CVSS v4.0 assessment logic
│   ├── cli/                # CLI entry points (Typer)
│   ├── context/            # Source context & call-graph analysis
│   ├── core/               # Core domain models & configuration
│   ├── normalization/      # Finding normalization & deduplication
│   ├── providers/          # LLM provider abstraction
│   ├── reporting/          # Report generation (HTML, CSV, JSON)
│   ├── scanners/           # Scanner adapters (Semgrep, SpotBugs, ODG, etc.)
│   ├── storage/            # Database models & repositories
│   ├── verification/       # Independent verification engine
│   └── web/                # FastAPI web dashboard & routes
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

```bash
# Start the web server
devsecops-agent serve --host 127.0.0.1 --port 8000

# Open http://127.0.0.1:8000 in your browser
```

The web dashboard provides four screens:

1. **Target Registration & Scan Configuration** — register projects and configure scan parameters
2. **Run Progress & Tool Status** — monitor active scans, view coverage limitations
3. **Findings & Evidence** — browse findings with source evidence, CVSS assumptions, and verification results
4. **Settings & Reports** — configure AI providers, view usage, export reports, compare experiments

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
| `/app/findings` | Findings table, filters, drawer, detail, CSV export |
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

### Verification Philosophy

AI is a **supporting tool**, not the final authority. Every AI-generated assessment is subject to mechanical verification:

- **Sanitization claims** are checked against actual encoding/context
- **Authorization assumptions** are verified against the declared policy
- **CVSS vector components** are validated against source evidence
- **Scope and impact estimates** are cross-referenced with application architecture

Failed verifications are flagged and reported — findings with unverifiable AI conclusions remain in their scanner-original state.

## Development

### Running Tests

```bash
# Run the full test suite
pytest

# Run with coverage
pytest --cov=vulnscan --cov-report=html

# Run a specific test module
pytest tests/analysis/
```

### Code Quality

```bash
# Lint
ruff check src/ tests/

# Format
ruff format src/ tests/

# Type check
mypy src/
```

### Adding a New Scanner

1. Create a new adapter in `src/vulnscan/scanners/`
2. Implement the `ScannerAdapter` protocol
3. Register the adapter in the scanner registry
4. Add normalization rules for its output format
5. Write tests in `tests/`

### Custom Semgrep Rules

Place custom Semgrep rules in the `rules/` directory. The scanner adapter loads rules from this path automatically.

## Limitations

- **No hosted deployment**: The application runs locally only
- **No multi-user accounts**: Single-user local mode
- **No DAST**: Only static analysis is supported
- **No automatic remediation**: The system reports findings but does not fix them
- **No notifications**: Results are viewed on-demand via CLI or web
- **CodeQL is experimental**: Cross-function/cross-file analysis is evaluated but not guaranteed

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
