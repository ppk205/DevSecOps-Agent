# DevSecOps-Agent

Review Java Servlet/JSP source with the Go chat client (`devsec tui`), the
Python console (`devsec chat`), or a browser attached to the session host.
The harness's static tools find candidates. AI supports investigation and
explanation; a human decides finding status and whether to apply a fix.

Start with [compile, build, and run](docs/BUILD-AND-RUN.md),
[native architecture and keys](docs/NATIVE-MIGRATION.md), and the
[Laya guide](docs/LAYA-TRAINING.md). Baseline scanners are available behind
the **Baseline** tab and through `scan-run` for testing and comparison.

The baseline runner also supports JavaScript/TypeScript, Python and PHP
through bundled Semgrep rules. The human-gated harness's detection tools
remain focused on Java Servlet/JSP.

## Quickstart

Install Python, Git and uv as described in the build guide. Add a model using
its masked-key wizard, then start a console review:

```bash
uv sync --locked --extra dev --extra scanners
uv run --no-sync devsec model add
uv run --no-sync devsec chat --target /path/to/java-project --model my-model --mode ask
```

Replace `my-model` with the alias you added. To use the Go chat UI, build the
native binary with `ci/build_native.py`, then run `devsec tui`.

For a baseline scan, provision Gitleaks alongside the locked Semgrep package:

```bash
uv run --no-sync devsec scan-run --checkout /path/to/repo --profile fast --no-laya --out artifacts/demo
```

The PIT WALL baseline dashboard uses the same stored runs. Build the web UI
with Node and the committed npm lock, then serve it:

```bash
npm --prefix web-ui ci
npm --prefix web-ui run build
uv run --no-sync devsec serve --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/app/`. Configure a target under **New scan** and
inspect progress and any failures in the **Live** view.

## Overview

DevSecOps-Agent finds, explains and helps fix security vulnerabilities in Java
Servlet/JSP source code. The main path is `devsec chat`: a hand-written AI
harness that scans with its own source–sink tools, triages candidates with the
local Laya model, investigates only what a human approved, writes finding cards
with code evidence, and proposes fixes. A human decides at every gate; the model
proposes and never decides.

Add a model with `devsec model add`: choose a template or Custom, an alias,
base URL, model ids and a masked key. Built-ins are templates for Anthropic,
OpenAI, OpenRouter, DeepSeek, Ollama and LM Studio. Profiles in `.providers/`
store only the key's environment-variable reference; the UI shows set/missing.

Gate modes are `ask` (default) and `auto`. `auto` approves the routine scanning
gates (G1–G4) and the re-scan gate (G7) and logs each approval as person `auto`.
G0 (session start: code leaves the machine, cost) waits for a human except in
local `auto` sessions with an interactive human client attached. Locality comes
from the loopback base URL. Unattended runs cannot pass G0. G6 (writing code)
always waits for a human, and G5 (a finding's final status) is human-only.

Investigation batches require a recorded Laya route, including `human_review`
when Laya is unavailable. Reads, inventory, extraction and route indexing
validate enumerated paths and exclude credential files (`.env`, `.env.*` and
`.secrets`, with `.env.example` allowed). Normal provider messages, console
output, session logs and reports pass through secret redaction.

For experiment S1, a separate Laya config with `mode: "off"` records skipped
triage without loading the backend; G3/G4 still apply. See the
[experiment runbook](docs/EXPERIMENT-RUNBOOK.md) for configuration and evaluation.

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

SonarCloud also scans the repository's supported languages through the
standard scan action on `main`, `dev` and same-repository pull requests.
Set `SONAR_ORGANIZATION`, `SONAR_PROJECT_KEY` and the `SONAR_TOKEN` secret as documented in
[CI integration](docs/CI-INTEGRATION.md#sonarcloud-testing-on-dev).

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
| Java Servlet | Harness candidate rules and baseline Semgrep/SpotBugs checks; coverage limits are reported |
| JSP | Harness expression checks; baseline Semgrep reports JSP as unsupported |
| JavaScript/TypeScript | Baseline rules for SQLi, XSS, exec, path traversal, SSRF, redirect, eval, weak random, secrets and prototype pollution |
| Python | Baseline rules for SQLi, XSS bypass, command injection, eval, path traversal, SSRF, SSTI, deserialization, secrets and weak random |
| PHP | Baseline rules for SQLi, reflected XSS, command injection, path traversal, SSRF, unserialize, weak hashing, loose comparison, extract and eval |
| Secrets/credentials | Gitleaks, all languages and docs |
| Java dependencies | OWASP Dependency-Check (DEEP profile) |
| DAST / runtime attacks | **Not supported** — static analysis only |
| Auto-remediation | **Not supported** — proposals only, you apply |
| Other languages (Go, Ruby, C#…) | Hunt mode reads any text, but no dedicated rules yet |

Every rule is tested both directions: it must fire on its `Vuln*` fixture
and stay silent on its `Safe*` fixture (`tests/scanners/test_*_rules.py`,
single batched Semgrep run per language, no cross-language false positives).

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

No key is needed to open the TUI. Add a model on the start screen or with
`devsec model add`, then choose the target and mode. A loopback model needs
no key. Put baseline scanner executables on `PATH` or in the application
environment. Baseline history defaults to `vulnscan.db`; harness sessions
use append-only JSONL logs under `.devsec/sessions/`.

Baseline model stages also accept existing `provider-add` profiles. They
reference a key by environment-variable name and can supply non-secret extra
headers. Store keys with the masked `devsec env set VARIABLE_NAME` prompt.

Scanner binaries resolve via `PATH` with a `sys.prefix` fallback; install them
once (Semgrep: `pip install semgrep`, Gitleaks/SpotBugs/ODC from their
upstream releases). Local dirty checkouts require `--allow-dirty`.

## Usage

### AI harness: `devsec chat`

```bash
# Add a model; the wizard asks for its alias and a masked key
devsec model add --template deepseek
devsec model list

# Start a review session; ask the human at every gate
devsec chat --target /path/to/JVA-bookstore --model my-model --mode ask

# Same session, routine gates auto-approved and logged as person "auto"
devsec chat --target /path/to/JVA-bookstore --model local-model --mode auto

# Send one prompt and exit
devsec chat --target JVA-bookstore --model my-model -p "scan the admin servlets for missing authorization"
```

Replace `my-model` and `local-model` with aliases you added. Use
`alias:model-id` to select another model id in a profile. The legacy
`--provider` form remains supported for one release.

Slash commands inside the session: `/help`, `/model <alias>[:model-id]`,
`/mode ask|auto`, `/cost`, `/review`, `/export [dir]`, `/resume <file>`,
`/clear`, `/quit`.

Sessions are written to `.devsec/sessions/<id>.jsonl`, approved fixes to
`.devsec/worktrees/<finding_id>` on branch `devsec/fix-<finding_id>`, and
reports to `.devsec/reports/<id>/report.md` with a matching `report.json`.
The harness never commits, pushes or merges.

### Chat TUI and browser remote

`devsec tui` starts the native chat client. Build it with `python
ci/build_native.py`; without the binary, the launcher prints that build hint
and exits. The Python Textual TUI has been replaced by this client. The
console `devsec chat` remains available without a native binary.

Use the start screen to add/select a model and target. The hint bar shows
available keys. Gate buttons support letters, mouse clicks, or arrows and
Enter with no initial selection. G6 requires viewing the full diff.

In the TUI, `/remote on` prints a one-time browser link; `/remote off` stops
the listener. Start a standalone host with:

```bash
devsec remote --target /path/to/project --model my-model --mode ask
```

Open the printed link to attach to the same session. The browser and TUI
share the transcript and pending gate; the first reply wins. Web approvals
at G0/G6 require `send`/`apply`. Loopback is the default; LAN binding requires
`--remote-allow-lan`. Build `web-ui/dist` to serve the remote page from a
source checkout. SPA assets are not bundled into the Python wheel.

### Automatic local reviews

```bash
devsec hooks install --target /path/to/project
devsec hooks status --target /path/to/project
devsec hooks uninstall --target /path/to/project
```

Hooks queue reviews after commits/merges and preserve foreign hooks. A
session on a non-git target watches for settled file changes. The clients
show pending reviews with Review now and Dismiss actions. Auto-start requires
a local model, auto mode, an attached human client, and an idle host. Cloud
reviews wait for the user. G5/G6 still require a human.

Root commits and linked worktrees are supported. A configured
`core.hooksPath` is refused rather than silently installing an unused hook.

For a non-git target, approved G6 exports `.devsec/patches/<finding_id>.patch`;
it does not apply the patch. Re-scan is reported unavailable for that target.

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

1. **Intake**: Register a web project; the baseline inventory includes Java/JSP, JavaScript/TypeScript, Python and PHP source files
2. **Source Parsing**: Java and JSP files are parsed; AST and call-graph analysis extracts security-relevant context
3. **Static Scanning**: Each enabled scanner analyzes the source and produces findings
4. **Normalization**: Findings from all scanners are normalized into a common schema, deduplicated, and tagged with CWE IDs
5. **Context Enrichment**: For each finding, the system assembles the finding-specific route, filter, callers, sanitizers, and sinks
6. **Optional Laya triage**: advisory routing, off by default in `config/laya.json`
7. **Reporting**: Results are persisted in SQLite and available via CLI, web dashboard, or exported reports

Optional B7 model paths include `--mode hunt`, `--ai-review` and `--ai-report`.
They add read-only model investigation, model/scanner comparison, targeted
review and an AI-written final report to the baseline workflow. Cloud model
use requires `--allow-cloud-model`. Baseline HTML exports use the PIT WALL
theme and summarized coverage; the other export formats remain available.

Baseline results are the comparison arm of the experiment, not part of the
harness.

```text
Baseline deterministic lane: scanners → normalize/deduplicate → report
Baseline B7 lane: model hunt → scanners → compare → optional AI review → report
Baseline fix utility: proposed diff → human apply → overlay → rule re-scan
```

The policy gate uses the configured severity threshold (`high` by default).
Exit code 1 means findings exceed that threshold; exit code 2 reports a
configuration or execution failure. The Live rail shows completed stages in
green, partial stages in yellow, failed stages in red, and pending stages in
gray. Per-tool details and errors remain in the feed and log dock.

### Baseline fix proposals

The PIT WALL Findings drawer offers **Propose fix**, and the Findings page
offers **Fix all** for the run. Proposals contain reviewable diffs. Applying
one patches a separate overlay under the export directory and re-runs the
matching Semgrep rule. The original checkout is preserved. A verified proposal
means the rule no longer reports the issue in that file; it does not change a
finding's status or establish runtime correctness.

Cloud proposals require consent for the selected profile. The same profile
can reuse the run's explicit cloud consent; a different cloud profile needs
explicit request consent. The UI's one-request checkbox resets after use.
Missing scanners, malformed output and missing scan coverage remain failures.

API: `POST /api/scans/{id}/fix` (`finding_ids` or `null` for all),
`GET /api/scans/{id}/fixes`, and `POST /api/scans/{id}/fixes/{pid}/apply`.
Requests can supply `provider_profile`, `provider_model` and explicit
`allow_cloud_model`. Already-proposed rows are retained; failed proposals can
be requested again.

Set `LAYA_MODEL_DIR` to an existing trained-checkpoint directory to override
the default Laya checkpoint. Explicitly selected model IDs remain unchanged,
and the runtime continues to use the CPU.

### Decision ownership

The harness never decides a finding. It checks evidence and records what the
human said:

- **Citations** are checked against the target: file exists, line is in range, the quoted code is within two lines of it
- **CVSS vectors** must be valid `CVSS:4.0/…`; the score is computed by `cvss` 3.6, never typed
- **Missing evidence** is reported as "unknown", never as "safe"
- **Status** (`confirmed`, `rejected`, `need_more`, `proposed`) is set only by a human answer at G5 or `/review`

## Training Laya (teach it to route)

The training tools live in `src/vulnscan/training/`: dataset export with
leakage checks, fine-tuning and held-out evaluation/calibration. Follow
[LAYA-TRAINING.md](docs/LAYA-TRAINING.md) for the locked environment and
supported training setup. The application continues to run inference on CPU.

The workflow is to export completed scans, obtain independent human route
labels, build a leakage-checked dataset, compare the frozen checkpoint with a
trained checkpoint, and retain the actual evaluation artifacts. Example
commands, using your own scan and label files in that environment:

```bash
python -m vulnscan.training.dataset \
  --scan scans-real.json --scan scans-synth.json \
  --labels labels-all.json --out /path/to/dataset

python -m vulnscan.training.evaluate \
  --test /path/to/dataset/test.jsonl \
  --model convaiinnovations/laya --out baseline.json

python -m vulnscan.training.finetune --data /path/to/dataset \
  --out /path/to/trained-model --mode validate

python -m vulnscan.training.finetune --data /path/to/dataset \
  --out /path/to/trained-model --mode train

python -m vulnscan.training.evaluate --test /path/to/dataset/test.jsonl \
  --model /path/to/trained-model --out trained.json
```

Keep datasets and weights outside the repository. Set `LAYA_MODEL_DIR` to the
trained directory only after reviewing its held-out results. No training
accuracy is claimed from a code merge or from fixture tests.

## Development

```bash
uv run --no-sync python -m pytest -q
.venv/Scripts/python.exe -m ruff check src tests
.venv/Scripts/python.exe -m ruff format --check src tests
.venv/Scripts/python.exe -m mypy --platform win32 src/vulnscan
npm --prefix web-ui run lint
npm --prefix web-ui test
npm --prefix web-ui run build
```

```bash
# Run a specific test module
uv run --no-sync python -m pytest tests/scanners/ -q
```

Follow [AGENTS.md](AGENTS.md) for development rules. Keep keys, model weights,
local datasets and generated artifacts out of commits. Design and execution
plans are tracked under `docs/superpowers/`. Human-reviewed labels are the
answer key for evaluation; models do not grade themselves. Database migrations
are additive and covered by the retained-history tests.

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

- **No hosted deployment**: The application runs locally only
- **No multi-user accounts**: Single-user local mode
- **No DAST**: Only static analysis is supported
- **No automatic target edits**: approved harness fixes use separate worktrees; baseline fixes use overlay copies
- **No notifications**: Results are viewed on-demand via CLI or web
- **CodeQL is experimental**: Cross-function/cross-file analysis is evaluated but not guaranteed
- Providers can rate-limit requests or omit usable responses; the app reports
  failures and retains session history.
- Dependency-Check needs an available advisory database. Full scans require
  the documented WSL/Docker setup.

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
