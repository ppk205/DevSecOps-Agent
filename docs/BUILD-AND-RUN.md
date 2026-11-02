# Compile, build, and run

Run the commands from the repository root. The application has a native Go
interface and a Python application. The Go executable still uses Python for
scanner adapters, reports, and other compatibility services, so install the
Python environment even when using the native TUI.

## 1. Prerequisites

| Tool | Requirement |
| --- | --- |
| Git | Clone the source and inspect the target checkout. |
| Python | 3.11 or later; the commands below select 3.11. |
| Go | 1.27.1 matches CI and the local SDK; `go.mod` declares a minimum of 1.26.0. Needed to compile Go. |
| uv | 0.12.17, as pinned in CI, to install the locked Python environment. |
| Terminal | Use Windows Terminal, PowerShell, or a terminal on Linux/macOS. The workflow supports 80x24 and 75x26; below 60x18, resize to continue. |

The initial dependency installation and first Go build need internet access
unless the relevant packages and Go modules are already cached. Scanner tools
are additional dependencies described in step 5. Opening the TUI does not
automatically install missing scanners.

## 2. Install the Python environment

### Windows PowerShell

For a new checkout:

```powershell
git clone https://github.com/ppk205/DevSecOps-Agent.git
Set-Location DevSecOps-Agent
```

For this existing workspace, use this directory instead:

```powershell
Set-Location 'D:\phuc\Code Project\DevSecOps-Agent'
```

Install uv using your base Python, then create or update `.venv` from `uv.lock`:

```powershell
py -3.11 -m pip install --user uv==0.12.17
py -3.11 -m uv sync --frozen --extra dev --extra scanners --python 3.11
```

If the Windows `py` launcher is unavailable, replace `py -3.11` with the path to
your Python 3.11+ executable. The commands below call `.venv` directly, so
virtual-environment activation and PowerShell execution-policy changes are
unnecessary. The `dev` extra includes tests and Python build tools; `scanners`
installs the pinned Semgrep package. Gitleaks is installed separately.

### Linux/macOS

```sh
git clone https://github.com/ppk205/DevSecOps-Agent.git
cd DevSecOps-Agent
python3 -m venv .tools/uv
.tools/uv/bin/python -m pip install uv==0.12.17
.tools/uv/bin/python -m uv sync --frozen --extra dev --extra scanners --python 3.11
```

The separate `.tools/uv` environment holds uv; `.venv` holds the application.
For subsequent steps, replace `.venv\Scripts\python.exe` with `.venv/bin/python`
and use forward slashes in paths. The native executable has no `.exe` suffix.

## 3. Compile the native Go executable

With Go on `PATH`:

```powershell
go version
.\.venv\Scripts\python.exe ci/build_native.py
.\bin\devsecops-agent-go.exe --version
```

This existing workspace also contains a Go SDK under `.tools/go` and populated
offline module/build caches. If `go` is not on `PATH`, use:

```powershell
$env:GOCACHE = Join-Path (Get-Location) '.tools\review-go-cache'
$env:GOMODCACHE = Join-Path (Get-Location) '.tools\review-go-mod'
$env:GOPROXY = 'off'
$env:GOTOOLCHAIN = 'local'
.\.tools\go\bin\go.exe version
.\.venv\Scripts\python.exe ci/build_native.py --go .tools/go/bin/go.exe
.\bin\devsecops-agent-go.exe --version
```

The build helper reads the package version from `pyproject.toml`, embeds it in
the binary, disables CGO, and uses the existing module versions without editing
`go.mod` or `go.sum`. It creates `bin/devsecops-agent-go.exe` on Windows and
`bin/devsecops-agent-go` on Linux/macOS. The current source version is 0.3.0.
Rebuild after changing Go source; the existing executable is not rebuilt by
launching the application or installing Python dependencies.

Linux/macOS example:

```sh
.venv/bin/python ci/build_native.py
./bin/devsecops-agent-go --version
```

To compile all release targets (Linux amd64/arm64, macOS amd64/arm64, Windows
amd64), run `ci/build_native.py --all --out dist` with the same Python
interpreter and optional `--go` argument. These outputs have platform suffixes;
the ordinary local build uses the filename that the launcher discovers.

## 4. Run the application

### Chat-first Go TUI

Launch the freshly compiled executable directly:

```powershell
$env:DEVSECOPS_PYTHON = (Resolve-Path .\.venv\Scripts\python.exe).Path
.\bin\devsecops-agent-go.exe tui
```

Or use the Python launcher, which sets the bridge interpreter automatically:

```powershell
.\.venv\Scripts\python.exe -m vulnscan.cli.main tui
```

For Linux/macOS:

```sh
.venv/bin/python -m vulnscan.cli.main tui
```

`tui` requires the native binary, including when `DEVSECOPS_NATIVE=python`
selects Python for baseline computation. A missing binary produces
`chat needs the native binary: run ci/build_native.py` and exit code 2.
The Python Textual TUI is removed; `devsec chat` is the Python console.
The installed `devsecops-agent` and `devsec` console scripts are aliases for
this launcher; on Windows they are in `.venv\Scripts`.

### First terminal workflow

1. Add a model or choose an existing alias on the start screen. Key entry is masked.
2. Enter a local target path and choose `ask` or `auto` mode.
3. Start the session and answer G0 when requested.
4. Type a review request. `/` opens the command menu; the hint bar shows
   available keys. Esc interrupts the running turn.
5. Use **Baseline** for comparison scans and **Keys** to manage added models.

Permission dialogs start with no selected button. Use the displayed letter,
a mouse click, or arrows then Enter. Enter alone does not approve. Rejection
asks for a reason; G6 buttons unlock only after the entire diff has been shown.
The status line identifies provider/model, mode, tokens and recorded cost.

### Baseline scanners (testing and comparison only)

These examples explicitly select Python so URL handling and the `--no-laya`
option are available:

```powershell
$env:DEVSECOPS_NATIVE = 'python'
.\.venv\Scripts\python.exe -m vulnscan.cli.main --help
.\.venv\Scripts\python.exe -m vulnscan.cli.main scan-run --checkout 'C:\path\to\java-project' --profile fast --no-laya --out artifacts/first-scan
.\.venv\Scripts\python.exe -m vulnscan.cli.main scan-list
.\.venv\Scripts\python.exe -m vulnscan.cli.main serve --host 127.0.0.1 --port 8000
```

Replace the example checkout with your target repository. `--no-laya` disables
advisory model routing for this scan. A dirty checkout requires explicit local
consent with `--allow-dirty`. Scan exit codes are 0 for a passing scan, 1 for
findings meeting the severity threshold, 2 for configuration/execution failure,
and 130 for cancellation. Open <http://127.0.0.1:8000> for the dashboard and use
Ctrl+C to stop its server. The default SQLite file is `vulnscan.db` in the
working directory; use the same `--db-path` when sharing history across commands.

`scan-run --mode hunt`, `--ai-review` and `--ai-report` are baseline B7: they
call a model outside the harness gates. When the provider's base URL is not
loopback (`localhost`, `127.0.0.1`, `::1`), they stay skipped unless you pass
`--allow-cloud-model`; the refusal is recorded on the run's stages, not raised
as an error.

The baseline inventory and bundled Semgrep rules also cover
JavaScript/TypeScript, Python and PHP. Java-specific scanners keep their own
coverage limits; the harness's detection tools remain Java Servlet/JSP-focused.

In the PIT WALL Findings view, **Propose fix** requests a diff for one finding,
and **Fix all** requests proposals for the run. The run needs a provider profile
or the request must supply one. A cloud profile needs consent: either the run's
existing consent for that same profile or explicit `allow_cloud_model: true`
on the request. The UI checkbox grants consent to one request and resets.

Applying a baseline proposal changes an overlay copy under the export directory,
then checks for the same Semgrep rule. It never edits the target checkout.
The check catches rule matches even if the patch shifted their line numbers;
scanner failures or missing coverage do not count as a verified fix. Semgrep
is resolved from PATH or the application virtual environment.

To use an existing trained Laya checkpoint, set `LAYA_MODEL_DIR` to its directory
before launching. The override applies only to the default model selection;
Laya remains on the CPU.

## 4a. Run the AI harness

The runtime, build and scanner dependency exports include `cvss==3.6`, so
installing from a shipped requirements lock supports `chat` with `--no-deps`.

Investigation requires both G3 selection and a recorded Laya route. A Laya
failure records `human_review` and still allows the human to select a batch.
The S1 experiment uses `--laya-config` with an explicit `mode: "off"` config;
this records skipped triage and does not load Laya. The baseline `enabled`
flag alone does not disable harness triage.
Direct reads and enumerated files pass through the same path confinement and
credential exclusion; `.env.example` remains readable. Provider messages,
console output, JSONL events and exported reports pass through redaction.

The G6 console prompt displays the full diff before accepting a decision.
Malformed JSON edits leave the gate undecided; retry with a JSON object.
Relative worktree paths are resolved from the directory running `chat`, even
when `--target` points elsewhere. Re-scans include the original candidate file
alongside the changed files. Route lookup checks applicable exact, prefix and
extension filter mappings and includes authorization checks in filter source.

`devsec chat` is the harness: it talks to a model, calls the gated tools and
pauses for a human at every gate. It needs Python 3.11 and, for a cloud
provider, one API key.

```powershell
# Add a model alias; the wizard prompts for a masked key when needed
.\.venv\Scripts\python.exe -m vulnscan.cli.main model add --template deepseek
.\.venv\Scripts\python.exe -m vulnscan.cli.main model list

# Start a session. --mode ask (default) asks at every gate; --mode auto
# approves G1-G4 and G7 automatically. Local G0 may auto-approve only
# with an interactive human client attached. G5 and G6 remain human-only.
.\.venv\Scripts\python.exe -m vulnscan.cli.main chat --target 'C:\path\to\JVA-bookstore' --model my-model --mode ask

# Local model, no key and no code leaving the machine
.\.venv\Scripts\python.exe -m vulnscan.cli.main chat --target JVA-bookstore --model local-model

# One prompt, then exit
.\.venv\Scripts\python.exe -m vulnscan.cli.main chat --target JVA-bookstore --model my-model -p "scan the admin servlets for missing authorization"
```

Replace the example aliases with names you added. Templates are `anthropic`,
`openai`, `openrouter`, `deepseek`, `ollama` and `lmstudio`, or choose Custom.
Each `.providers/<alias>.json` stores a key reference, never its value. Use
`model key <alias>` to change the key and `model remove <alias>` to remove it.
`--model alias:model-id` overrides the default id; legacy `--provider` remains
supported for one release. Other chat options: `--mode ask|auto`, `--budget 50`
(USD), `--sessions-dir`, `--laya-config`, `--resume <session.jsonl>`.

Slash commands: `/help`, `/model <alias>[:model-id]` (a move to a cloud provider
asks G0 consent again), `/mode ask|auto`, `/cost`, `/review` (settles findings
awaiting a human), `/export [dir]`, `/resume <file>`, `/clear`, `/quit`.

What it writes, all under the working directory:

| Path | Contents |
| --- | --- |
| `.devsec/sessions/<stamp>-<hex>.jsonl` | every message, tool call, gate decision and usage record |
| `.devsec/worktrees/<finding_id>` | the worktree for an approved fix, on branch `devsec/fix-<finding_id>` |
| `.devsec/reports/<id>/report.md`, `report.json` | finding cards with the decision log |

The harness never commits, pushes or merges in the target repository. Only an
approved G6 writes a fix, inside that worktree or as a patch for a non-git
target. `scan-run` stays the
baseline runner for Semgrep, SpotBugs/FindSecBugs, Dependency-Check and Gitleaks;
its results are the comparison arm, not part of the harness.

### Remote control from a browser

In the Go TUI, `/remote on` prints a single-use browser link. `/remote off`
stops the listener. For a standalone session:

```powershell
.\.venv\Scripts\python.exe -m vulnscan.cli.main remote --target 'C:\path\to\project' --model my-model --mode ask
```

Open the printed link. Login establishes an HttpOnly, SameSite=Strict cookie;
mutations need the CSRF token. A disconnected browser reconnects from its last
event sequence. The first valid client response settles a pending gate. Web
G0/G6 approvals also need the typed word `send`/`apply`, checked by the host.
With no attached human client, the host cannot auto-approve local G0.

Loopback is the default. Prefer an SSH tunnel to a remote machine:

```sh
ssh -L 8765:127.0.0.1:<port> user@host
```

Binding another address requires `--remote-host <address> --remote-allow-lan`
and prints a warning. Build the SPA with the web commands below before opening
`/app/remote`; the wheel does not yet bundle SPA assets.

### Automatic local reviews

```powershell
.\.venv\Scripts\python.exe -m vulnscan.cli.main hooks install --target 'C:\path\to\project'
.\.venv\Scripts\python.exe -m vulnscan.cli.main hooks status --target 'C:\path\to\project'
.\.venv\Scripts\python.exe -m vulnscan.cli.main hooks uninstall --target 'C:\path\to\project'
```

Hooks append pending reviews and exit; they do not run a model or block git.
Foreign hooks are preserved. A session host watches non-git folders and queues
a review after changes settle. Review now and Dismiss are available in both
clients. Auto-start requires an idle host, an attached client, auto mode and a
local model. G5/G6 remain human-only. Pipes, hooks and CI cannot approve G0.

The initial commit is included, and filenames are read from NUL-delimited Git
output. Hook operations support linked worktrees but refuse a configured
`core.hooksPath`; integrate the printed command into your own hook manager.

For non-git targets, G6 exports `.devsec/patches/<finding_id>.patch` without
changing the target. Re-scan reports `unavailable: target is not a git repository`.
The [experiment runbook](EXPERIMENT-RUNBOOK.md) covers S1/S2 configuration,
baseline normalisation, metrics and scratch-clone fix evaluation.

## 5. Install tools before an actual scan

| Profile | Additional tools |
| --- | --- |
| fast | Semgrep 1.178.0 (installed by the `scanners` extra) and Gitleaks 8.24.2. |
| full | Fast tools plus Docker with Linux containers and the scanner image containing Maven/Java, SpotBugs 4.10.4, FindSecBugs 1.14.0, and Dependency-Check 13.0.0. |

Install the Gitleaks binary from the [v8.24.2 release](https://github.com/gitleaks/gitleaks/releases/tag/v8.24.2)
for your operating system and architecture
and add its directory to `PATH`. The Windows executable must be named
`gitleaks.exe`. Check the tools from the repository root:

```powershell
.\.venv\Scripts\semgrep.exe --version
gitleaks version
```

On Linux/macOS, use `.venv/bin/semgrep --version`. For full scans, start Docker,
then build the project's scanner image:

```powershell
docker version
.\.venv\Scripts\python.exe ci/build_image.py
```

The image build downloads its pinned tools; dependency database initialization
also needs network access. See [CI integration](CI-INTEGRATION.md) for full-scan
containment and fixture checks. Missing scanners prevent a successful scan;
they do not prevent compiling the Go executable or opening the TUI.

## 6. Build Python distribution packages

Python source runs from the installed environment. To produce a wheel and a
source archive for distribution, use the build tools from the `dev` extra:

```powershell
.\.venv\Scripts\python.exe -m build --no-isolation
```

The outputs are `dist/devsecops_agent-0.3.0-py3-none-any.whl` and
`dist/devsecops_agent-0.3.0.tar.gz` for the current package version. The native
Go executable is a separate artifact. Install the matching Python package when
moving the Go binary to another machine.

## 7. Verify a development build

Pushes to `main`/`dev`, same-repository pull requests and manual dispatch run
the standard SonarCloud scan action for all supported first-party languages.
The workflow needs repository variables `SONAR_ORGANIZATION` and
`SONAR_PROJECT_KEY`, plus the `SONAR_TOKEN` Actions secret. It waits for the
quality gate; it is separate from the local checks below. See
[the setup and analysis scope](CI-INTEGRATION.md#sonarcloud-testing-on-dev).

### Web UI

The PIT WALL SPA lives in `web-ui/` and is built with Node 24 and the
committed `package-lock.json`. From `web-ui/`:

```bash
npm ci
npm run lint    # tsc --noEmit
npm test        # vitest run
npm run build   # tsc --noEmit && vite build -> web-ui/dist
```

The built `web-ui/dist` is served by the Python app at `/app/` in a source
checkout. Copying it into the wheel under `src/vulnscan/web/static/app` is
**not implemented**, so a pip install serves the JSON API and the legacy Jinja
pages but not the SPA.

Required CI checks use uv 0.12.17 and `uv sync --locked`. Commands after the
sync use `uv run --no-sync` so installed dev and scanner extras remain present.
The quality job includes `ci/`, checks dependency exports and runs strict mypy
for Linux, macOS and Windows. Run the same local checks after installing the
`dev` and `scanners` extras:

```powershell
.\.venv\Scripts\python.exe -m ruff check src tests ci
.\.venv\Scripts\python.exe -m ruff format --check src tests ci
.\.venv\Scripts\python.exe -m mypy src/vulnscan
.\.venv\Scripts\python.exe ci/check_lock_exports.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe ci/package_smoke.py
```

The package smoke test builds a wheel and source archive, installs the wheel
with hash-locked runtime dependencies into a fresh environment, checks assets
and CVSS, then checks both CLI aliases. Non-interactive chat must refuse G0;
the installed gatekeeper must also refuse unattended G6. It makes no provider
calls. The Action installer and scanner image use the same installed smoke
check. Dependency installation requires network access or a populated cache.
Archive selection uses the exact current project version, so older local
`dist/` files cannot replace the current wheel. Official Actions are pinned to
reviewed stable releases listed in `docs/CI-INTEGRATION.md`.

The `CI required` job depends on quality, harness, native, full Python tests,
package smoke and real fast baseline fixtures. Harness tests use fakes on all
supported operating systems. Native jobs build the binary before running the
platform and CLI suites. Full baseline integration remains scheduled,
manual and a release prerequisite. See [CI integration](CI-INTEGRATION.md).

```powershell
go vet ./...
go test ./...
.\.venv\Scripts\python.exe -m pytest tests/cli tests/harness
```

Use `.\.tools\go\bin\go.exe` instead of `go` when using the workspace SDK.
Run `.\.venv\Scripts\python.exe -m pytest` for the full Python suite. Build the
native executable first so native parity tests can find it.

The offline Go settings in step 3 also apply to tests. They require the caches
and SDK to be populated already; omit those settings for a normal first build
with network access.

SRS trace: section 2 C-01/C-04 defines local execution and Python/Go support;
section 3 FR-71 and section 5 IR-01/IR-14 define launch and CLI behavior;
section 6 QR-12/QR-21/QR-22 defines secret entry, terminal bounds, and locked
dependencies.
