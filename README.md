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

DevSecOps-Agent is a local application that detects, classifies, and assesses vulnerabilities in Java Servlet/JSP projects. It combines conventional static analysis tools (Semgrep, SpotBugs/FindSecBugs, OWASP Dependency-Check, Gitleaks) with AI-assisted contextual analysis to produce CVSS v4.0 severity assessments. Every AI-generated conclusion is independently verified through mechanical checks.

The experimental target is [JVA-bookstore](https://github.com/Moseyuh333/JVA-bookstore) (commit `dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5`): 97 Java source files, 38 JSP files, Java 11, Maven WAR packaging, PostgreSQL, `javax.servlet`.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CLI / Web Dashboard                   │
│                  (Typer + FastAPI + Jinja)                │
├─────────────────────────────────────────────────────────┤
│                   Orchestration Layer                    │
│            (scan lifecycle, queue, retry)                │
├─────────┬──────────┬──────────┬──────────┬──────────────┤
│ Semgrep │ SpotBugs │   ODG    │ Gitleaks │ CodeQL (exp) │
│  (CE)   │+FindSec  │          │          │              │
├─────────┴──────────┴──────────┴──────────┴──────────────┤
│              Normalization & Deduplication               │
├─────────────────────────────────────────────────────────┤
│          Source Context & Java Security Models           │
│   (call-graph, sanitizers, auth checks, sinks, routes)  │
├─────────────────────────────────────────────────────────┤
│            AI Assessment Agent (LLM-backed)              │
│      (CVSS v4.0 estimation, contextual reasoning)       │
├─────────────────────────────────────────────────────────┤
│         Independent Verification Engine                 │
│   (mechanical checks on AI claims before acceptance)     │
├─────────────────────────────────────────────────────────┤
│          Reporting & Experiment Comparison               │
│       (HTML, CSV, JSON; per-scanner, per-CWE)           │
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

### CLI

```bash
# Run a Fast scan without advisory model routing
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

## How It Works

### Scan Pipeline

1. **Intake**: Register a Java Servlet/JSP project; the system catalogs all `.java` and `.jsp` files
2. **Source Parsing**: Java and JSP files are parsed; AST and call-graph analysis extracts security-relevant context
3. **Static Scanning**: Each enabled scanner analyzes the source and produces findings
4. **Normalization**: Findings from all scanners are normalized into a common schema, deduplicated, and tagged with CWE IDs
5. **Context Enrichment**: For each finding, the system assembles the finding-specific route, filter, callers, sanitizers, and sinks
6. **AI Assessment**: The AI agent evaluates each normalized finding with contextual information and proposes a CVSS v4.0 assessment
7. **Verification**: The independent verification engine mechanically checks every AI claim against source evidence before acceptance
8. **Reporting**: Results are persisted in SQLite and available via CLI, web dashboard, or exported reports

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
dirty checkouts. AI/Laya default off. Deep analysis remains explicitly unavailable.
The existing `serve` command keeps the local web interface available.

See [consumer workflows, required checks and GitHub releases](docs/CI-INTEGRATION.md)
and [requirement-to-test traceability](docs/TEST-PLAN.md). Application version comes
from installed package metadata; contract schema versions remain independent.
