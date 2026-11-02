# DevSecOps-Agent

The application now supports a native Go TUI and service implementation with a
Python compatibility backend. Start with [compile, build, and run instructions](docs/BUILD-AND-RUN.md),
then see [native architecture and keyboard instructions](docs/NATIVE-MIGRATION.md)
and [the Laya review and training guide](docs/LAYA-TRAINING.md).

The terminal opens in **Workspace**. Choose a checkout and profile, expand
Advanced options when needed, then press **Ctrl+E** to review and **Ctrl+S** to
start. **Ctrl+K** opens the action menu in Python; in the native Workspace it
enters or saves an API key. Review and finding details scroll with
arrow/page keys; **V** shows raw details. See the
[TUI review and remediation](docs/TUI-REVIEW.md) for the implemented fixes.

The default Textual workspace retains repository URL input, pinned commits,
clone-cache settings and the API Keys tab. Set `DEVSECOPS_NATIVE=go` to use the
native TUI for local checkouts; `DEVSECOPS_NATIVE=python` selects Python for
all commands. The `devsec` alias is also available.

Automated vulnerability scanning and severity assessment for Java Servlet/JSP source code, powered by a multi-scanner pipeline with Agentic AI analysis and independent mechanical verification.

## Overview

DevSecOps-Agent finds, explains and helps fix security vulnerabilities in Java
Servlet/JSP source code. The main path is `devsec chat`: a hand-written AI
harness that scans with its own source–sink tools, triages candidates with the
local Laya model, investigates only what a human approved, writes finding cards
with code evidence, and proposes fixes. A human decides at every gate; the model
proposes and never decides.

The harness is provider-agnostic: `anthropic`, `openai`, `openrouter`,
`deepseek`, `ollama`, `lmstudio`, plus user profiles in `.providers/*.json`.
Keys are read from environment variables only, never from a profile file.

Gate modes are `ask` (default) and `auto`. `auto` approves the routine scanning
gates (G1–G4) and the re-scan gate (G7) and logs each approval as person `auto`.
G0 (session start: code leaves the machine, cost) and G6 (writing code) always
wait for a human in every mode, and G5 (a finding's final status) is never
decided by code or by auto mode.

Investigation batches require a recorded Laya route, including `human_review`
when Laya is unavailable. Reads, inventory, extraction and route indexing
validate enumerated paths and exclude credential files (`.env`, `.env.*` and
`.secrets`, with `.env.example` allowed). Normal provider messages, console
output, session logs and reports pass through secret redaction.

The console shows the full fix diff before asking for G6. Invalid JSON edits
leave a gate undecided. Fix worktree paths are resolved from the caller's
directory before invoking git. Re-scans check the original candidate file as
well as changed files. Route lookup includes applicable exact, path-prefix
and extension filters and checks their source for authorization guards.

Third-party scanners — Semgrep, SpotBugs/FindSecBugs, OWASP Dependency-Check,
Gitleaks and GitHub CodeQL — are **baselines** for comparison. They run through
`scan-run` and are not part of the harness pipeline.

The experimental target is [JVA-bookstore](https://github.com/Moseyuh333/JVA-bookstore) (commit `dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5`): 97 Java source files, 38 JSP files, Java 11, Maven WAR packaging, PostgreSQL, `javax.servlet`.

## Architecture

CI checks the current harness with fake providers and Laya backends on Linux,
Windows and macOS. The full Python matrix, native Go checks, dependency-export
consistency, installed chat smoke tests and real baseline fixtures feed the
`CI required` job. Full baseline integration also runs before releases. See
[CI integration](docs/CI-INTEGRATION.md) for the jobs and local commands.

```
Human ⇄ harness (src/vulnscan/harness: session loop, gates, audit log)
           │ provider layer: profile → protocol → transport (httpx)
           ▼
   Anthropic Messages · OpenAI-compatible Chat Completions
   (Anthropic, OpenAI, OpenRouter, DeepSeek, Ollama, LM Studio, custom)
           │ tool calls, each checked by the gate keeper
           ▼
   harness tools: plan → inventory → extract_candidates → Laya triage
   → select → investigate (read_file, grep, lookup_route)
   → propose_finding (G5) → propose_fix (G6) → rescan (G7)
           │
           ▼
   human decision → finding cards, decision log, report export
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
- **Database**: SQLite via SQLAlchemy (async with aiosqlite)
- **CLI**: Typer
- **HTTP Client**: httpx
- **Scanners**: Semgrep CE, SpotBugs + FindSecBugs, OWASP Dependency-Check, Gitleaks, CodeQL (experimental)
- **AI Provider**: Configurable LLM backend (OpenAI-compatible API)
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

- Python 3.11 or later and Git
- Go 1.27.1 to compile the native interface (matching CI)
- Semgrep 1.178.0 and Gitleaks 8.24.2 for Fast scans
- Docker and the project scanner image for Full scans, including Java/Maven,
  SpotBugs/FindSecBugs, and Dependency-Check

### Setup

Follow [Compile, build, and run](docs/BUILD-AND-RUN.md) for copyable Windows
PowerShell and Linux/macOS commands. It covers locked Python installation,
native compilation, Python wheel/source builds, scanner setup, and verification.
The Go executable still requires the Python application environment.

### Configuration

No API key or `.env` file is required to open the TUI. Use Workspace to choose
the checkout, profile, output directory, and advanced options, then review the
effective settings. Optional secrets can be entered through the Python API Keys
tab, native Workspace controls, or `devsecops-agent env set VARIABLE_NAME`, which
prompts for a hidden value. Put scanner executables on `PATH` or in the
application virtual environment. Scan history defaults to `vulnscan.db` in the
working directory; select another file with `--db-path`.

## Usage

### AI harness: `devsec chat`

```bash
# Store a key for a cloud provider (value is prompted, never printed)
devsec env set DEEPSEEK_API_KEY

# Start a review session; ask the human at every gate
devsec chat --target /path/to/JVA-bookstore --provider deepseek --model deepseek-chat --mode ask

# Same session, routine gates auto-approved and logged as person "auto"
devsec chat --target /path/to/JVA-bookstore --provider ollama --model llama3 --mode auto

# Send one prompt and exit
devsec chat --target JVA-bookstore --provider deepseek -p "scan the admin servlets for missing authorization"
```

Slash commands inside the session: `/help`, `/model <provider> [model]`,
`/mode ask|auto`, `/cost`, `/review`, `/export [dir]`, `/resume <file>`,
`/clear`, `/quit`.

Sessions are written to `.devsec/sessions/<id>.jsonl`, approved fixes to
`.devsec/worktrees/<finding_id>` on branch `devsec/fix-<finding_id>`, and
reports to `.devsec/reports/<id>/report.md` with a matching `report.json`.
The harness never commits, pushes or merges.

### Baseline scans (`scan-run`)

```bash
# Run a Fast baseline scan without advisory model routing
devsecops-agent scan-run --checkout /path/to/JVA-bookstore --profile fast --no-laya

# View saved scans and inspect a run
devsecops-agent scan-list
devsecops-agent scan-status RUN_ID

# Export retained evidence without rescanning
devsecops-agent scan-export RUN_ID --fmt html --out artifacts/reports
```

These commands assume the virtual environment is active and the Python launcher
is selected (`DEVSECOPS_NATIVE=python`). Replace `RUN_ID` with an ID from
`scan-list`. See the build guide for commands that work without activation.

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
| `/app/scans/new` | New scan (profile, scanners, AI review, CLI preview) |
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

### Harness review pipeline

1. **G0 session start**: target, commit, provider, model and whether code leaves the machine. Consent is asked again after `/model` switches to a different cloud provider.
2. **G1 plan**: the model states modules, file globs and vulnerability classes; the human approves, edits or rejects.
3. **G2 scan**: each scan tool call (inventory, candidate extraction, Laya triage) is approved before it runs.
4. **Laya triage**: the local model routes every candidate (`authorization_analysis`, `cross_file_analysis`, `jsp_context_analysis`, `fast_verification`, `dependency_analysis`, `secret_review`, `human_review`, `low_priority`); it never sets a status.
5. **G3 selection**: the human accepts or changes the routes and chooses what to investigate.
6. **G4 investigation**: the model reads the chosen code with `read_file`, `grep` and `lookup_route`. Every read is logged and wrapped as `<untrusted_code>`.
7. **G5 finding**: the model proposes a card with a source→sink path, an explanation and a CVSS v4.0 vector; the harness checks every citation and computes the score. Only a human confirms, rejects or asks for more evidence.
8. **G6 fix / G7 re-scan**: for a confirmed finding the model may propose a diff. Applying it writes only inside `.devsec/worktrees/<finding_id>` on branch `devsec/fix-<finding_id>`, and a re-scan reports whether the candidate is gone.

When the model is unavailable the error is shown and logged, the history is
kept and `/resume` continues the session. A rejected step is not retried until
the human sends a new message.

### Baseline scanner pipeline (`scan-run`)

1. **Intake**: Register a Java Servlet/JSP project; the system catalogs all `.java` and `.jsp` files
2. **Source Parsing**: Java and JSP files are parsed; AST and call-graph analysis extracts security-relevant context
3. **Static Scanning**: Each enabled scanner analyzes the source and produces findings
4. **Normalization**: Findings from all scanners are normalized into a common schema, deduplicated, and tagged with CWE IDs
5. **Context Enrichment**: For each finding, the system assembles the finding-specific route, filter, callers, sanitizers, and sinks
6. **Optional Laya triage**: advisory routing, off by default in `config/laya.json`
7. **Reporting**: Results are persisted in SQLite and available via CLI, web dashboard, or exported reports

Baseline results are the comparison arm of the experiment, not part of the
harness.

### Decision ownership

The harness never decides a finding. It checks evidence and records what the
human said:

- **Citations** are checked against the target: file exists, line is in range, the quoted code is within two lines of it
- **CVSS vectors** must be valid `CVSS:4.0/…`; the score is computed by `cvss` 3.6, never typed
- **Missing evidence** is reported as "unknown", never as "safe"
- **Status** (`confirmed`, `rejected`, `need_more`, `proposed`) is set only by a human answer at G5 or `/review`

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
dirty checkouts. AI/Laya default off. Deep analysis remains explicitly unavailable.
The existing `serve` command keeps the local web interface available.

See [consumer workflows, required checks and GitHub releases](docs/CI-INTEGRATION.md)
and [requirement-to-test traceability](docs/TEST-PLAN.md). Application version comes
from installed package metadata; contract schema versions remain independent.
