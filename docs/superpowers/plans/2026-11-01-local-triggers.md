# Local triggers and local G0 auto-approval — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Queue a review automatically after a local git commit or merge, or after file changes in a folder without git. Show queued reviews in the TUI and the web. Run them unattended up to G5/G6 when a local model runs in auto mode with a human client attached.

**Architecture:**
- Git hooks only append to `.git/devsec/pending.jsonl` and exit.
- For non-git targets, a polling watcher inside the session host writes to `.devsec/pending/`.
- The host reads both queues and emits `pending` events.
- `GateKeeper` gains a narrow, interactive-only automatic approval of G0 for local providers.
- Non-git targets export fixes as `.patch` files.

**Tech Stack:** Python stdlib (`subprocess` limited to fixed git argument lists, `hashlib`, `time`), plus the existing Go chat client and web page.

**Spec:** `docs/superpowers/specs/2026-11-01-chat-client-remote-triggers-design.md` Part C, §5, §6 and §7.

**Precondition:** projects 2 and 3 have merged. Branch: `feat/local-triggers`.

## Global Constraints

- AGENTS H9 applies, and the owner approved the H3 change on 2026-11-01. The same change must update `docs/ARCHITECTURE-MODIFICATION.md` §3, `AGENTS.md` H3 and S1, and `tests/harness/test_gates.py`.
- H6 stays: a non-interactive keeper (`refuse_all`, pipes, CI, hooks) never passes G0, even for local providers.
- G5 and G6 are never automatic.
- S1: git subprocesses use only fixed argument lists, in `workspace.py`, `fixes.py` and `pending.py`.
- Hooks never block git: every failure path exits 0 and prints at most one line to stderr.
- `install` never overwrites a hook without the `# devsec-hook v1` marker, and `uninstall` removes only hooks that carry it.
- The watcher never writes inside the target.
- No new dependencies.

## Review Focus

1. **The user already has a husky or pre-commit `post-commit` hook.** Install refuses and prints the exact line to add. The existing hook is untouched. Pinned in Task 3 by `test_install_refuses_foreign_hook`.
2. **A commit is made from an IDE whose git has no `python` on PATH.** The hook uses the absolute interpreter path recorded at install. If that path is gone, the hook prints one line and exits 0. Pinned in Task 3 by `test_hook_with_missing_python_exits_zero`.
3. **`devsec chat -p ... --mode auto --provider ollama` is run from a pipe.** G0 is still refused (H6). Pinned in Task 1 by the 8-case `test_local_g0_auto_matrix`.
4. **An editor saves 30 files over 8 seconds in a non-git folder.** Exactly one pending review is queued after 10 s of quiet. Pinned in Task 4 by `test_debounce_queues_once`.
5. **A pending review arrives while a turn is running.** It is never auto-submitted mid-turn. The banner waits, and the review starts after `done` only in auto+local mode. Pinned in Task 5 by `test_pending_waits_for_idle`.

---

### Task 1: Local G0 auto-approval (H3 change)

**Files:**
- Modify: `src/vulnscan/harness/gates.py` (`GateKeeper.__init__` gains `interactive: bool = False`; `ask`)
- Modify: `src/vulnscan/harness/console.py`, `rpc.py`, `remote.py` and `cli/main.py` (pass `interactive=True` only where a human-facing asker is used)
- Test: `tests/harness/test_gates.py`
- Modify: `AGENTS.md` (H3), `docs/ARCHITECTURE-MODIFICATION.md` §3 (gate-by-mode table)

**Interfaces:**
- Produces:
  - the rule `_auto_local_g0(request, mode, interactive) -> bool`. It is true only when all of these hold: the gate is G0, the mode is `auto`, `interactive` is true, `request.payload.get("local") is True` and `request.payload.get("code_leaves_machine") is False`.
  - The decision is logged with the person `auto` and the reason `local provider, auto mode`.

- [ ] **Step 1: Write the failing test.**
  ```python
  @pytest.mark.parametrize("mode", ["ask", "auto"])
  @pytest.mark.parametrize("local", [True, False])
  @pytest.mark.parametrize("interactive", [True, False])
  def test_local_g0_auto_matrix(mode, local, interactive):
      log = []
      k = GateKeeper(refuse_all, log.append, mode=mode, interactive=interactive)
      d = k.ask(GateRequest(Gate.G0_SESSION, "s", "", {"local": local, "code_leaves_machine": not local}))
      expected = mode == "auto" and local and interactive
      assert d.approved is expected
      assert (log[0]["person"] == "auto") is expected
  ```
  Also add `test_g6_never_auto_even_local_interactive`.
- [ ] **Step 2: Run the tests to confirm they fail.**
  Run: `.venv\Scripts\python.exe -m pytest tests/harness/test_gates.py -q`
  Expected: the new cases FAIL.
- [ ] **Step 3: Implement.** Then run the tests to confirm they pass. Also run `ci/smoke_installed.py`, which must still print that it refused G0.
- [ ] **Step 4: Update AGENTS H3 and spec §3 in the same commit.**
  ```bash
  git commit -m "Approve G0 automatically for local providers in interactive auto mode"
  ```

### Task 2: Pending review queue

**Files:**
- Create: `src/vulnscan/harness/pending.py` (also runnable as `python -m vulnscan.harness.pending record --hook <name>`)
- Test: `tests/harness/test_pending.py`

**Interfaces:**
- Produces:
  ```python
  @dataclass(frozen=True)
  class PendingReview: id: str; source: str; ref: str | None; files: list[str]; at: str
  def record_hook(repo: Path, hook: Literal["post-commit", "post-merge"]) -> PendingReview
  def record_watch(store: Path, files: list[str]) -> PendingReview
  def read_pending(repo: Path | None, store: Path) -> list[PendingReview]   # minus dismissed/started ids
  def mark(store: Path, review_id: str, state: Literal["started", "dismissed"]) -> None
  ```
- Where things are stored:
  - The git queue is `<repo>/.git/devsec/pending.jsonl`.
  - The watch queue and the state marks go to `<harness cwd>/.devsec/pending/<sha1(str(target.resolve()))[:12]>.jsonl`.
- The git commands have fixed argument lists:
   - `git diff-tree --root --no-commit-id --name-only -z -r HEAD` for a commit;
   - `git diff --name-only -z ORIG_HEAD HEAD` for a merge;
   - `git rev-parse HEAD` and `git rev-parse --abbrev-ref HEAD`.

Owner-approved correction (2026-11-02): include root commits and use NUL
delimiters to preserve filenames. Hook operations query
`git config -z --get core.hooksPath` and refuse a configured override rather
than claim installation in a directory Git will ignore. Fixed `rev-parse`
commands resolve Git/common directories for linked worktrees.

- [ ] **Step 1: Write the failing tests** on a temporary git repo, using the `ws` fixture pattern from `tests/harness/conftest.py`.
  - `test_record_commit_lists_changed_files`.
  - `test_record_merge_uses_orig_head`.
  - `test_read_skips_dismissed`.
  - `test_credential_files_never_listed`: a commit touching `.env` does not list it, because names go through `Workspace._excluded`.
- [ ] **Step 2: Run the tests to confirm they fail.** Then implement, and run them to confirm they pass.
- [ ] **Step 3: Update AGENTS S1** to list `pending.py`. Commit.
  ```bash
  git commit -m "Add a pending review queue fed by git hooks and the watcher"
  ```

### Task 3: `devsec hooks install|uninstall|status`

**Files:**
- Modify: `src/vulnscan/cli/main.py` (Python-handled command `hooks`; add it to the Python-only set next to `chat`)
- Create: `src/vulnscan/harness/hooks.py`
- Test: `tests/harness/test_hooks.py`

**Interfaces:**
- Produces:
  - `install(repo: Path, python: Path) -> list[str]`, which returns the hooks it wrote;
  - `uninstall(repo: Path) -> list[str]`;
  - `status(repo: Path) -> dict[str, str]`, where each value is `installed`, `foreign` or `absent`.
- The hook body, with the exact text:
  ```sh
  #!/bin/sh
  # devsec-hook v1
  "<python>" -m vulnscan.harness.pending record --hook <name> >/dev/null 2>&1 || echo "devsec: could not queue review" >&2
  exit 0
  ```

- [ ] **Step 1: Write the failing tests.**
  - `test_install_writes_both_hooks_executable`.
  - `test_install_refuses_foreign_hook`: the exit code is 1, the output contains the line to add, and the file is unchanged.
  - `test_uninstall_removes_only_marked`.
  - `test_hook_with_missing_python_exits_zero`: point the recorded python at a missing path and run `git commit`; it exits 0 and stderr has one line.
  - `test_commit_queues_review`: an end-to-end real `git commit` in `tmp_path`.
- [ ] **Step 2: Run the tests to confirm they fail.** Then implement, and run them to confirm they pass.
- [ ] **Step 3: Commit.**
  ```bash
  git commit -m "Add opt-in git hooks that queue a review after commit or merge"
  ```

### Task 4: Folder watcher for non-git targets

**Files:**
- Create: `src/vulnscan/harness/watcher.py`
- Test: `tests/harness/test_watcher.py`

**Interfaces:**
- Produces:
  - `Watcher(ws: Workspace, store: Path, clock: Callable[[], float] = time.monotonic, interval: float = 5.0, quiet: float = 10.0)`;
  - `tick() -> PendingReview | None`. The host calls it on a daemon thread every `interval` seconds; tests call it directly.
  - The ignored top-level directories are `.devsec`, `.git`, `target`, `build`, `out` and `node_modules`.

- [ ] **Step 1: Write the failing tests** (with a fake clock).
  - `test_debounce_queues_once`.
  - `test_no_change_no_review`.
  - `test_ignored_dirs_do_not_trigger`.
  - `test_watcher_never_writes_in_target`: the target's file set is identical before and after.
- [ ] **Step 2: Run the tests to confirm they fail.** Then implement, and run them to confirm they pass.
- [ ] **Step 3: Commit.**
  ```bash
  git commit -m "Watch folders without git and queue a review after changes settle"
  ```

### Task 5: Pending reviews in the host, TUI and web

**Files:**
- Modify: `src/vulnscan/harness/host.py` (a `pending` event; auto-submit only in auto mode with a local provider, with a client attached and the host idle; `PENDING_PROMPT` copied verbatim from spec §4.4)
- Modify: `internal/chat/start.go` and `internal/chat/model.go` (a pending list and a banner with `[r] Review now` and `[x] Dismiss` buttons)
- Modify: `web-ui/src/pages/RemoteSessionPage.tsx` (the same banner)
- Test: `tests/harness/test_host_pending.py`, `internal/chat/pending_test.go`, `web-ui/.../RemoteSessionPage.test.tsx`

- [ ] **Step 1: Write the failing tests.**
  - `test_pending_waits_for_idle`.
  - `test_auto_local_submits_prompt`.
  - `test_ask_mode_never_auto_submits`.
  - `test_cloud_never_auto_submits`.
  - Go `TestBannerButtons`.
  - Vitest `shows pending banner`.
- [ ] **Step 2: Run the tests to confirm they fail.** Then implement, and run them to confirm they pass.
- [ ] **Step 3: Update AGENTS T2** with the `pending` event. Commit.
  ```bash
  git commit -m "Show queued reviews and auto-start them for local models in auto mode"
  ```

### Task 6: Fix export for targets without git

**Files:**
- Modify: `src/vulnscan/harness/fixes.py` (`apply_fix` writes `.devsec/patches/<finding_id>.patch` when `ws.commit == "unversioned"`; `rescan_fix` returns `"unavailable: target is not a git repository"`)
- Modify: `src/vulnscan/harness/tools.py` (the G6 title for unversioned targets: `Export patch (target is not a git repository)`)
- Test: `tests/harness/test_fixes.py`

- [ ] **Step 1: Write the failing tests.**
  - `test_unversioned_apply_exports_patch_only`: the target tree is unchanged, and the patch file equals the proposal diff.
  - `test_unversioned_rescan_unavailable`.
- [ ] **Step 2: Run the tests to confirm they fail.** Then implement, and run them to confirm they pass.
- [ ] **Step 3: Commit.**
  ```bash
  git commit -m "Export fixes as patch files for targets without git"
  ```

### Task 7: Docs, verification and PR

- [ ] **Step 1: Update the docs.**
  - README and BUILD-AND-RUN get a section "Automatic local reviews": hooks install and uninstall, the watcher, which gates still need you, and the H6 explanation.
  - CHANGELOG.
  - Spec §13.
- [ ] **Step 2: Run all checks.** Run the G3 commands, the Go tests, all the web-ui checks and `ci/smoke_installed.py`. Save the logs to `.tools/ci-logs/local-triggers/`.
- [ ] **Step 3: Push and open the PR.** Push `feat/local-triggers` and open a PR to `main`. Do not merge it.
