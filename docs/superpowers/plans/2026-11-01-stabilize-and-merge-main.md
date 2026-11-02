# Stabilize the harness branch and merge `main` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the reviewed harness fixes on `feat/human-gated-harness`, fix the over-broad redaction, merge the teammate's `origin/main` (PIT WALL web UI and the `hunt` pipeline), make every scan-run model path consent-gated as a baseline, put the web UI under CI, and open one PR to `main` with all checks green.

**Architecture:** Work stays on `feat/human-gated-harness` (AGENTS R2). Current uncommitted work is committed first so every later task is a clean diff. Redaction moves from "regex over serialized text" to "redact string values, then serialize". `origin/main` is merged in, not rebased. Its model paths in `ScanService` (`--mode hunt`, `--ai-review`, `--ai-report`) become baseline B7 and refuse cloud providers without explicit consent. A `web-ui` CI job joins the `CI required` gate.

**Tech Stack:** Python 3.11+, uv 0.12.17, pytest, ruff, mypy (strict), Go 1.27.1, Node 24 with npm (`web-ui/package-lock.json`, lockfile v3), Vite 5, Vitest 2, GitHub Actions pinned by SHA.

**Spec:** `docs/ARCHITECTURE-MODIFICATION.md` (sections 3, 8, 13) and `AGENTS.md`. Decisions taken in the 2026-11-01 conversation that this plan carries:
- The owner approved the dependencies `sse-starlette>=3.0.0` and `python-docx>=1.1.0` from `origin/main` (AGENTS G1).
- `hunt`, `ai_review` and `ai_report` in `scan-run` are kept as baseline **B7 "model without harness gates"**. B6 keeps its existing definition.
- The project order is 1) this plan, 2) the chat bridge and Go chat TUI, 3) the web as a remote control, 4) local triggers. Projects 2–4 are out of scope here.

## Global Constraints

- AGENTS A1/A2: no agent framework, no provider SDK. Model calls use `httpx`.
- AGENTS A4: the harness never calls `ScanService` or scanners. The output of B7 never reaches the harness.
- AGENTS K1/K3: never read or print `.env` values. Text leaving the provider boundary, logs and reports passes through `vulnscan.providers.credentials` redaction.
- AGENTS E2/E6: every number in docs comes from a command run in this plan. Failures are reported with their output.
- AGENTS E7: do not modify or delete anything under `evidence/`. Do not commit `evidence/**/.scanner-data/` or `*.db` (R5).
- AGENTS R1/R2/R4: commit only on `feat/human-gated-harness`. Never push to `main`, never force-push, never use `--no-verify`. The owner merges the PR.
- AGENTS R3: commit subjects are imperative and sentence case, with no `feat:`-style prefix. Every commit message ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Pin every action by full SHA:
  - `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1`
  - `actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0`
  - the other pins are those already in `checks.yml`.
- G3 checks, which every task's final verification runs on Windows:
  ```
  .venv\Scripts\python.exe -m ruff check src tests ci
  .venv\Scripts\python.exe -m ruff format --check src tests ci
  .venv\Scripts\python.exe -m mypy src/vulnscan
  .venv\Scripts\python.exe -m pytest -q
  ```
  - On this machine, `tests/platform/test_artifact_store.py` fails with `WinError 206` when the pytest base temp path is long (more than about 100 characters). Run pytest with the default temp directory, or pass `--basetemp` with a short path **outside** the checkout. A path inside the checkout breaks root-discovery tests (spec 13.7).

## Review Focus

1. **Real Java identifiers stay intact after redaction.** `token.isEmpty()`, `io.jsonwebtoken.Claims` and `tokenService.verify(jwt)` must survive both directions of the provider boundary. Pinned in Task 2 by `test_redact_keeps_java_identifiers` and `test_provider_round_trip_keeps_code`.
2. **JSON stays valid when code contains a tab before `ok…`.** JSONL logs and request bodies must remain parseable, and no gate decision may disappear from the log. Pinned in Task 2 by `test_redact_json_never_breaks_json` and `test_gate_event_with_tab_code_survives_log`.
3. **A cloud profile used from the web New Scan form without consent.** The scan must run without any model stage, and the model client must never be constructed. Pinned in Task 5 by `test_web_scan_without_consent_skips_model_stages`.
4. **A profile whose `base_url` is `http://localhost:11434/v1`.** It counts as local and needs no consent flag. `127.0.0.1` and `[::1]` count as local; `localhost.example.com` does not. Pinned in Task 5 by `test_locality`.
5. **The merged `uv.lock` matches `pyproject.toml` and the three requirements exports.** A stale lock fails CI. Pinned in Task 4 by `uv lock --check` and `ci/check_lock_exports.py`.

---

### Task 1: Commit the reviewed work already in the tree

**Files:**
- Modify: `.gitignore` (add `.scanner-data/`)
- Commit, without editing: the files listed in each step.

**Interfaces:**
- Produces: a clean working tree, apart from untracked `evidence/` run folders and `docs/TUI-VERIFICATION-2026-10-17.md`, which stay uncommitted. They are listed as open items in Task 7.

- [ ] **Step 1: Ignore scanner caches.** Append `.scanner-data/` to `.gitignore`.
  Run: `git check-ignore -v evidence/jva-fullscan-2026-11-01/.scanner-data/ready.json`
  Expected: one line naming `.gitignore` and `.scanner-data/`.
- [ ] **Step 2: Run the G3 checks.** Expected: ruff and format pass, mypy reports no issues, and pytest passes. The only allowed failures are the two `test_artifact_store.py` `WinError 206` cases, and only when they are caused by a long temp path; in that case, rerun them with a short `--basetemp` and they must pass.
- [ ] **Step 3: Commit the harness fixes.**
  ```bash
  git add .gitignore src/vulnscan tests/harness requirements.lock requirements-build.lock requirements-scanners.lock
  git commit -m "Confine harness file access, redact boundary traffic and gate investigation on triage"
  ```
- [ ] **Step 4: Commit CI.**
  ```bash
  git add .github action.yml ci go.mod docs/examples tests/platform/test_ci_contract.py
  git commit -m "Rebuild required CI around the harness with an aggregate gate"
  ```
- [ ] **Step 5: Commit the rules and docs.**
  ```bash
  git add AGENTS.md CLAUDE.md CHANGELOG.md README.md docs/ARCHITECTURE-MODIFICATION.md docs/BUILD-AND-RUN.md docs/CI-INTEGRATION.md docs/superpowers/plans/2026-11-01-stabilize-and-merge-main.md
  git commit -m "Add agent rules and document the review corrections and CI"
  ```
  Run: `git status --short`
  Expected: only `?? evidence/...` and `?? docs/TUI-VERIFICATION-2026-10-17.md`.

### Task 2: Redact key-shaped values, not identifiers, and never break JSON

**Files:**
- Modify: `src/vulnscan/providers/credentials.py` (`redact`, plus the new `redact_value` and `redact_json`)
- Modify: `src/vulnscan/harness/providers.py` (`_HttpTransport._post`)
- Modify: `src/vulnscan/harness/audit.py` (`SessionLog.append`)
- Modify: `src/vulnscan/harness/tools.py` (`run_tool` return)
- Modify: `src/vulnscan/harness/report.py` (`export` JSON write)
- Modify: `tests/harness/test_review_regressions.py` (sentinel only, see Step 6)
- Create: `tests/harness/test_redaction.py`

**Interfaces:**
- Produces:
  - `redact(text: str) -> str`. Same name and signature as today; the patterns become narrower.
  - `redact_value(value: Any) -> Any`. Returns a deep copy in which every `str` (dict values and list items, recursively) has passed through `redact`. Dict keys and non-`str` scalars are unchanged.
  - `redact_json(value: Any, *, indent: int | None = None) -> str`. Implemented as `json.dumps(redact_value(json.loads(json.dumps(value, default=str))), indent=indent)`, so objects serialized via `default=str` are redacted too.

- [ ] **Step 1: Write the failing tests** in `tests/harness/test_redaction.py`.
  ```python
  KEY = "sk-ant-" + "a1B2c3D4e5F6g7H8i9J0k1L2"

  def test_redact_keeps_java_identifiers():
      for s in ["token.isEmpty()", "import io.jsonwebtoken.Claims;", "apiEndpointUrl",
                "+    if (tokenService.verify(jwt)) {", "task_candidates", "tokenizer.json"]:
          assert redact(s) == s

  @pytest.mark.parametrize("secret", [KEY, "sk-" + "Z" * 32, "ghp_" + "a" * 36,
                                      "github_pat_" + "b" * 30, "AKIA" + "ABCDEFGHIJKLMNOP",
                                      "xoxb-" + "1" * 20])
  def test_redact_masks_key_shapes(secret):
      assert secret not in redact(f"x={secret};") and "[REDACTED]" in redact(f"x={secret};")

  def test_redact_masks_bearer_header():
      assert "abcdefghijklmnopqrstuv" not in redact("Authorization: Bearer abcdefghijklmnopqrstuv")

  def test_redact_masks_loaded_env_key_values(monkeypatch):
      monkeypatch.setenv("FIXTURE_API_KEY", "plain-value-without-prefix")
      assert "plain-value-without-prefix" not in redact("echo plain-value-without-prefix")

  def test_redact_json_never_breaks_json():
      value = {"code": "\tokHttpClientBuilderInstance x;", "k": KEY, "n": [1, None, "\tok"]}
      out = json.loads(redact_json(value))
      assert out["code"] == value["code"] and out["n"] == value["n"] and KEY not in out["k"]

  def test_gate_event_with_tab_code_survives_log(tmp_path):
      log = SessionLog(tmp_path / "s.jsonl")
      log.append({"type": "gate", "payload": {"code": "\tokHttpClientBuilderInstance"}})
      assert log.events()[0]["payload"]["code"] == "\tokHttpClientBuilderInstance"

  def test_provider_round_trip_keeps_code():
      # MockTransport (pattern from test_review_regressions.test_provider_redacts_normal_request_and_response):
      # the request contains "token.isEmpty()"; the reply is a tool call whose "diff" argument
      # contains "+    if (tokenService.verify(jwt)) {".
      # Assert both strings arrive unchanged: the request body still contains "token.isEmpty()",
      # and reply.message.tool_calls[0].arguments["diff"] still contains the tokenService line.
  ```
- [ ] **Step 2: Run the tests to confirm they fail.**
  Run: `.venv\Scripts\python.exe -m pytest tests/harness/test_redaction.py -q`
  Expected: FAIL in `test_redact_keeps_java_identifiers`, `test_redact_json_never_breaks_json`, `test_gate_event_with_tab_code_survives_log`, `test_provider_round_trip_keeps_code` and `test_redact_masks_loaded_env_key_values`, plus an ImportError for `redact_json`/`redact_value` until they exist.
- [ ] **Step 3: Implement the redaction in `credentials.py`.**
  - `redact` replaces the current single regex with this ordered alternation, each match becoming `[REDACTED]`:
    ```
    \bsk-ant-[A-Za-z0-9_-]{20,}
    \b(?:sk|pk|rk)-[A-Za-z0-9_-]{20,}
    \bghp_[A-Za-z0-9]{36}\b
    \bgithub_pat_[A-Za-z0-9_]{22,}
    \bAKIA[0-9A-Z]{16}\b
    \bxox[abprs]-[A-Za-z0-9-]{10,}
    (?<=Bearer )[A-Za-z0-9._~+/-]{20,}=*
    ```
  - It then replaces the literal value of every environment variable whose name ends in `_API_KEY`, `_TOKEN` or `_SECRET` and whose value is at least 8 characters long. Read `os.environ` at call time; never print or log the names or values.
  - Add `redact_value` and `redact_json` with the signatures above.
- [ ] **Step 4: Switch the call sites to structured redaction.**
  - `harness/providers.py` `_post`:
    - Before sending: `payload = redact_value(payload)`, which replaces the `json.loads(redact(json.dumps(...)))` line.
    - After receiving: `raw = redact_value(response.json())`, which replaces `json.loads(redact(response.text))`. Keep the existing `ValueError` → `ProviderError` handling around `response.json()`.
  - `harness/audit.py` `append`: `handle.write(redact_json(payload) + "\n")`.
  - `harness/tools.py` `run_tool`: `return redact_json(result)`.
  - `harness/report.py` `export`: `json_path.write_text(redact_json(payload, indent=2), ...)`.
  - `render_markdown` and `console.py` keep `redact(text)`, since that output is display text, not JSON.
- [ ] **Step 5: Run the new tests.** Run: `.venv\Scripts\python.exe -m pytest tests/harness/test_redaction.py -q`. Expected: PASS.
- [ ] **Step 6: Update sentinels that were never key-shaped.**
  - In `test_review_regressions.py`, `test_logs_reports_and_display_redact_normal_content` uses `"tok_" + "syntheticfixture123456"`. Change it to `"sk-ant-" + "syntheticfixture123456"`. The test still asserts the sentinel is absent from the log, the reports and the console.
  - Run: `git grep -n "redact\|REDACTED" tests`. Apply the same change to any other test whose sentinel no longer matches a key shape. Do not delete assertions.
- [ ] **Step 7: Run the full suite.** Run the G3 checks. Expected: all pass, except the documented `WinError 206` caveat.
- [ ] **Step 8: Update the docs.**
  - Spec 13.6, redaction bullet: add "Redaction matches key formats and loaded key values only, and is applied to string values before JSON serialization."
  - CHANGELOG Unreleased: "Narrow redaction to key formats and loaded key values; redact structured values before serializing so code identifiers and JSON logs stay intact."
- [ ] **Step 9: Commit.**
  ```bash
  git add src/vulnscan/providers/credentials.py src/vulnscan/harness tests/harness CHANGELOG.md docs/ARCHITECTURE-MODIFICATION.md
  git commit -m "Redact key-shaped values only and redact before serializing JSON"
  ```

### Task 3: Review cleanups

**Files:**
- Create: `tests/harness/conftest.py`
- Modify: `tests/harness/test_console.py`, `test_tools.py`, `test_fixes.py`, `test_gates.py`, `test_review_regressions.py` (imports only)
- Modify: `src/vulnscan/harness/scanning.py` (`lookup_route`)
- Modify: `tests/harness/test_scanning.py`, `CHANGELOG.md`

**Interfaces:**
- Produces:
  - `tests/harness/conftest.py` exports `scripted(lines: list[str]) -> Callable[[str], str]`, `make_ctx(...)`, `call(ctx, name, **args)`, `DIFF: str` and the `ws` fixture. They move verbatim from their current modules.
  - `lookup_route` adds the key `"filter_match"` to its result: `"request_url"` when the query starts with `/`, otherwise `"servlet_pattern"`.

- [ ] **Step 1: Write the failing test** in `test_scanning.py`.
  ```python
  def test_lookup_route_reports_filter_match_basis(tmp_path):
      (tmp_path / "Users.java").write_text('@WebServlet("/admin/users")\nclass Users {}', encoding="utf-8")
      ws = Workspace(tmp_path, "unversioned")
      assert lookup_route(ws, "Users")["filter_match"] == "servlet_pattern"
      assert lookup_route(ws, "/admin/users")["filter_match"] == "request_url"
  ```
- [ ] **Step 2: Run it to confirm it fails** (KeyError). Then add the key in `lookup_route` and run it to confirm it passes.
- [ ] **Step 3: Move the helpers.** Move the shared helpers into `conftest.py` unchanged. Remove `pytest_plugins = [...]` from `test_review_regressions.py`. Replace the cross-test-module imports, such as `from tests.harness.test_console import scripted`, with imports from `tests.harness.conftest`, or rely on the `ws` fixture.
  Run: `.venv\Scripts\python.exe -m pytest tests/harness -q`
  Expected: the same pass count as before this step.
- [ ] **Step 4: CHANGELOG.** Add under Unreleased: "Shared source index: annotation URL patterns now include extension mappings (`*.do`). This also changes `scan-run` route context."
- [ ] **Step 5: Commit.**
  ```bash
  git add tests/harness src/vulnscan/harness/scanning.py CHANGELOG.md
  git commit -m "Share harness test helpers and report the filter match basis in route lookup"
  ```

### Task 4: Merge `origin/main`

**Files:**
- Conflicts to resolve: `CHANGELOG.md`, `pyproject.toml`.
- Regenerate: `uv.lock`, `requirements.lock`, `requirements-build.lock`, `requirements-scanners.lock`.
- Modify as needed: any merged file that fails a G3 check.

**Interfaces:**
- Consumes: `origin/main` at `7f88d99` or later. Run `git fetch origin` first and record the SHA you merge in the commit body.

- [ ] **Step 1: Start the merge.** Run `git fetch origin`, then `git merge --no-ff origin/main`.
  Expected: conflicts in exactly `CHANGELOG.md` and `pyproject.toml`. If any other file conflicts, stop and report it.
- [ ] **Step 2: Resolve the conflicts.**
  - `pyproject.toml`: the `dependencies` list keeps `cvss==3.6`, `sse-starlette>=3.0.0` and `python-docx>=1.1.0`, plus every other entry from both sides.
  - `CHANGELOG.md`: one `Unreleased` section that holds both sides' entries, branch entries first.
- [ ] **Step 3: Relock and re-export.**
  ```powershell
  uv lock
  uv lock --check
  uv sync --locked --extra dev --extra scanners
  uv export --frozen --no-dev --no-emit-project --no-header -o requirements.lock
  uv export --frozen --no-dev --no-emit-project --no-header --group build -o requirements-build.lock
  uv export --frozen --no-dev --no-emit-project --no-header --extra scanners --group build -o requirements-scanners.lock
  .venv\Scripts\python.exe ci/check_lock_exports.py
  ```
  Expected: `uv lock --check` exits 0, and `check_lock_exports.py` prints `matches uv.lock` three times.
  - If `uv lock` needs the network and none is available, stop and report it. Do not hand-edit the lock.
- [ ] **Step 4: Run the G3 checks plus Go.** Also run `go vet ./...` and `go test ./...`, with the offline settings from `docs/BUILD-AND-RUN.md` §3.
  - Fix every failure, including failures in merged code.
  - Keep each fix minimal and record it as one line for the commit body, for example: `ruff F401 in web/phase2.py`.
  - Do not delete or skip tests. If a merged test is wrong rather than the code, state why in the commit body.
- [ ] **Step 5: Check that the web build still works.** Run `npm ci`, `npm run lint`, `npm test` and `npm run build` in `web-ui/`, with Node 24 or the local Node.
  Expected: all exit 0.
  - If `npm run lint` (`tsc --noEmit`) fails because `@types/react@^19` doesn't match `react@^18`, change only the `@types/react` and `@types/react-dom` ranges to `^18.3.x`, then rerun `npm install` to update `package-lock.json`.
- [ ] **Step 6: Commit the merge.**
  ```bash
  git add -A -- . ':!evidence' ':!docs/TUI-VERIFICATION-2026-10-17.md'
  git commit -m "Merge main: PIT WALL web UI and the model hunt pipeline" -m "<origin/main SHA; one line per fix from Step 4/5>"
  ```

### Task 5: Make scan-run model paths a consent-gated baseline (B7)

**Files:**
- Create: `src/vulnscan/core/model_consent.py`
- Modify: `src/vulnscan/core/config.py` (`ScanConfig`)
- Modify: `src/vulnscan/core/scan_service.py` (the hunt block near `if config.mode == "hunt":`, the AI-review client setup near `config.provider_profile if (config.ai_review or config.mode == "hunt")`, and the AI-report call near `profile_id=config.provider_profile if config.ai_report`)
- Modify: `src/vulnscan/cli/main.py` (`scan-run` options)
- Modify: `src/vulnscan/web/phase2_routes.py` (scan-create body model and the `ScanConfig` mapping near `"ai_review": body.ai_review`)
- Modify: `web-ui/src/api/client.ts` (request type), `web-ui/src/pages/NewScanPage.tsx` (checkbox)
- Test:
  - `tests/core/test_model_consent.py` (new)
  - `tests/platform/test_hunt_mode.py`
  - the web scan-create test module, found with `git grep -ln "ai_review" tests/web`
  - `web-ui/src/pages/NewScanPage.test.tsx`: extend it if it exists, otherwise create it beside the page.

**Interfaces:**
- Produces:
  - `ScanConfig.allow_cloud_model: bool = False`.
  - `is_local_base_url(base_url: str) -> bool`. True only when the `urlparse` hostname is `localhost`, `127.0.0.1` or `::1`.
  - `model_use_allowed(profile: ProviderProfile, allow_cloud_model: bool) -> tuple[bool, str]`. It returns one of:
    - `(True, "local provider")`
    - `(True, "cloud provider allowed by --allow-cloud-model")`
    - `(False, f"cloud provider {profile.id} needs --allow-cloud-model; code excerpts would leave this machine")`
  - CLI: `scan-run --allow-cloud-model/--no-allow-cloud-model`, default off.
  - Web: the scan-create body field `allow_cloud_model: bool = False`. In the UI it is a checkbox labelled "Allow code excerpts to leave this machine (cloud provider)", unchecked by default, and shown when AI review or hunt is selected.

- [ ] **Step 1: Write the failing unit tests** in `tests/core/test_model_consent.py`.
  ```python
  @pytest.mark.parametrize("url,local", [("http://localhost:11434/v1", True), ("http://127.0.0.1:1234/v1", True),
      ("http://[::1]:8080/v1", True), ("https://api.deepseek.com", False), ("http://localhost.example.com", False)])
  def test_locality(url, local): assert is_local_base_url(url) is local

  def test_cloud_refused_without_flag(cloud_profile):
      ok, reason = model_use_allowed(cloud_profile, False)
      assert not ok and "--allow-cloud-model" in reason

  def test_cloud_allowed_with_flag(cloud_profile): assert model_use_allowed(cloud_profile, True)[0]
  def test_local_needs_no_flag(local_profile): assert model_use_allowed(local_profile, False) == (True, "local provider")
  ```
  `cloud_profile` and `local_profile` are fixtures built from `ProviderProfile` with base URLs `https://api.deepseek.com` and `http://127.0.0.1:11434/v1`.
- [ ] **Step 2: Write the failing ScanService test** in `tests/platform/test_hunt_mode.py`. Follow that module's existing setup for a hunt run.
  ```python
  def test_cloud_hunt_without_consent_skips_model_stages(monkeypatch, ...):
      # The profile has a cloud base_url and the config has mode="hunt", ai_review=True, ai_report=True.
      # Monkeypatch vulnscan.providers.client.ProviderClient.__init__ to raise AssertionError("model called").
      # Assert: the run completes; the stages model_hunt, ai_review and ai_report are "skipped" with a
      # reason containing "--allow-cloud-model"; the deterministic scanner findings are present.
  ```
- [ ] **Step 3: Write the failing web test** in the web scan-create test module.
  ```python
  def test_web_scan_without_consent_skips_model_stages(...):
      # POST a scan with ai_review=True and a cloud provider_profile, without allow_cloud_model.
      # Assert the stored run configuration has allow_cloud_model == False and that, with
      # ProviderClient patched to raise, the run does not call the model.
  ```
- [ ] **Step 4: Run the tests to confirm they fail.**
  Run: `.venv\Scripts\python.exe -m pytest tests/core/test_model_consent.py tests/platform/test_hunt_mode.py tests/web -q`
  Expected: the new tests FAIL; the existing ones pass.
- [ ] **Step 5: Implement the consent check.**
  - Create `model_consent.py` and add the `ScanConfig` field.
  - In `ScanService`, call `model_use_allowed` once, right after `load_profile(...)`, before any `ProviderClient(...)` is built. When it returns `False`, call `persist(<stage>, "skipped", reason)` for each requested model stage (`model_hunt`, `ai_review`, `ai_report`) and build no client.
  - Add the CLI option and pass it into `resolve_config`.
  - Add the web body field and map it into `ScanConfig`.
- [ ] **Step 6: Add the web-ui checkbox.**
  - In `NewScanPage.tsx`, add the checkbox. Add `allow_cloud_model?: boolean` to the request type in `client.ts` and always send it.
  - Vitest:
    ```tsx
    it("sends allow_cloud_model false unless the box is ticked", ...)
    it("shows the consent box only when AI review or hunt is selected", ...)
    ```
  - Run: `npm test` in `web-ui/`. Expected: PASS.
- [ ] **Step 7: Run the Python tests.** Run the Step 4 command. Expected: PASS.
- [ ] **Step 8: Update the docs.**
  - Spec §8 table: add the row `| B7 | scan-run model paths without harness gates: --mode hunt, --ai-review, --ai-report (teammate's pipeline); cloud providers need --allow-cloud-model |`.
  - AGENTS.md A4: add the sentence "`scan-run` model paths (`--mode hunt`, `--ai-review`, `--ai-report`) are baseline B7: off by default, cloud providers need `--allow-cloud-model`, and their output never reaches the harness."
  - BUILD-AND-RUN §4 command-line scan: document the flag.
  - CHANGELOG Unreleased: one line.
- [ ] **Step 9: Run the G3 checks**, then commit.
  ```bash
  git add src/vulnscan/core src/vulnscan/cli/main.py src/vulnscan/web tests web-ui/src AGENTS.md docs CHANGELOG.md
  git commit -m "Require consent before scan-run sends code to a cloud model and mark it baseline B7"
  ```

### Task 6: Put the web UI under required CI

**Files:**
- Modify: `.github/workflows/checks.yml` (new `web-ui` job; add it to `required.needs`)
- Modify: `tests/platform/test_ci_contract.py`
- Modify: `docs/CI-INTEGRATION.md`, `docs/BUILD-AND-RUN.md`

**Interfaces:**
- Produces: a job with the id `web-ui`.

- [ ] **Step 1: Write the failing contract test** in `test_ci_contract.py`.
  - Add `"actions/setup-node": "949feb2413d6458794dcd2491c4babbbce0c15c1"` to `ACTION_PINS`.
  - Add the test:
  ```python
  def test_web_ui_job_installs_locked_and_runs_typecheck_tests_build():
      job = workflow("checks.yml")["jobs"]["web-ui"]
      run = commands(job)
      for cmd in ("npm ci", "npm run lint", "npm test", "npm run build"):
          assert cmd in run
      assert "web-ui" in workflow("checks.yml")["jobs"]["required"]["needs"]
  ```
  - Run: `.venv\Scripts\python.exe -m pytest tests/platform/test_ci_contract.py -q`. Expected: FAIL with `KeyError: 'web-ui'`.
- [ ] **Step 2: Add the job.** The job:
  - runs on `ubuntu-latest` with `timeout-minutes: 15`, and `defaults.run.working-directory: web-ui`;
  - checks out with `persist-credentials: false` and `ref: ${{ inputs.ref || github.sha }}`;
  - uses `setup-node` (pinned) with `node-version: '24'`, `cache: npm` and `cache-dependency-path: web-ui/package-lock.json`;
  - runs `npm ci`, `npm run lint`, `npm test` and `npm run build`, as four separate steps.

  Add `web-ui` to `required.needs`.
- [ ] **Step 3: Run the contract tests.** Run the Step 1 command. Expected: PASS, including the existing `test_qr23_required_gate_covers_every_job...`.
- [ ] **Step 4: Update the docs.**
  - `CI-INTEGRATION.md`: add the job to the workflow map.
  - `BUILD-AND-RUN.md`: add a "Web UI" subsection with the four npm commands.
  - State honestly what the code does: the SPA is served from `web-ui/dist` in a source checkout, and copying it into the wheel at `src/vulnscan/web/static/app` is **not implemented**. Confirm this first: if a build step does copy it, describe that step instead.
- [ ] **Step 5: Commit.**
  ```bash
  git add .github/workflows/checks.yml tests/platform/test_ci_contract.py docs/CI-INTEGRATION.md docs/BUILD-AND-RUN.md
  git commit -m "Add the web UI typecheck, tests and build to required CI"
  ```

### Task 7: Full verification, docs record, push and PR

**Files:**
- Modify: `docs/ARCHITECTURE-MODIFICATION.md` (a new §13.9 "Merge and stabilization (2026-11-01)"), `CHANGELOG.md`

- [ ] **Step 1: Run everything and save the output.** Run the G3 checks, plus:
  ```
  go vet ./...
  go test ./...
  ci/check_lock_exports.py
  uv lock --check
  npm ci, npm run lint, npm test and npm run build in web-ui/
  .venv\Scripts\python.exe ci/package_smoke.py
  ```
  Save the outputs to `.tools/ci-logs/stabilize-2026-11-01/`.
  Expected: every command exits 0.
- [ ] **Step 2: Write spec §13.9.** It records:
  - the merged `origin/main` SHA;
  - the dependency approvals;
  - B7;
  - the redaction change;
  - each check with its exact pass/fail counts copied from Step 1;
  - what remains not implemented: projects 2–4, SPA packaging, live-provider smoke and the SonarCloud workflow on `dev`;
  - open items: the untracked `evidence/` run folders and `docs/TUI-VERIFICATION-2026-10-17.md`, which the owner decides on.

  Commit:
  ```bash
  git add docs/ARCHITECTURE-MODIFICATION.md CHANGELOG.md
  git commit -m "Record the merge and stabilization verification"
  ```
- [ ] **Step 3: Push the branch.** Run `git push -u origin feat/human-gated-harness`, without `--force`.
  - If the push is rejected because the remote has moved, stop and report it. Do not force-push.
- [ ] **Step 4: Open the PR** to `main`, with the title `Human-gated harness, review fixes and merge of the PIT WALL web UI`.
  - The body lists:
    - the harness summary;
    - the review fixes;
    - B7 consent;
    - the web-ui CI;
    - the verification table from §13.9;
    - not implemented;
    - the owner decisions (dependencies, B7).
  - It ends with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
  - Do not merge the PR.
- [ ] **Step 5: Wait for CI.** Watch the PR's CI. If `CI required` fails, report the failing job and its log excerpt, fix the problem in a new commit, and push again. Done means CI is green, or each remaining failure is reported with its cause.
