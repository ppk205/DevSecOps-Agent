# Model-hunt recall vs native baseline (WebGoat)

Lane `lane-hunt-recall` — target: model-hunt reaches **>= 50% recall** of the
deterministic `native-hunt` baseline on WebGoat, matching on **file + line ±3**
(CWE ignored: the question is whether the model looked at the right place).

## Harness

- `scripts/hunt_recall.py` — runs the native baseline (`scan_snapshot` over
  `["java", "javascript", "python", "php"]`) and matches hunt candidates from
  `--hunt-json` (static) or `--live` (runs `hunt_all` against the configured
  provider; key from env, never logged). Fail-soft: provider/upstream errors
  are recorded with zero live candidates, never raise.
- `src/vulnscan/ai/recall.py` — pure matcher `(norm path, line ± tol)`.
- `tests/ai/test_hunt_recall.py` — offline matcher tests.
- Snapshot fidelity: `--git-archive harness/WebGoat` materializes tracked
  files only (`git archive HEAD`), mirroring the pipeline snapshot
  (WebGoat @ `3284a8e`, same revision as run #55). Reports land in
  `artifacts/hunt-recall/`.

## What changed in the hunt loop

1. **More passes**: `hunt_all(..., broad_pass=True)` adds a second-chance
   `broad` pass over all source globs for pattern-visible weaknesses
   (default-charset, secrets, weak crypto/random, debug leftovers,
   stack traces, log sinks). Pipeline (`scan_service`) enables it with
   `max_rounds=16`, `max_findings=200` (was 12/60 — the old 60-cap made
   50% of ~140 native findings arithmetically unreachable).
2. **Open excerpts**: `_sweep_excerpts()` attaches numbered ±12-line windows
   (same jailed reader as review/promote) for the top sweep hits in the
   fast-path and closing prompts — the model cites exact file+line instead
   of guessing from one-liners.
3. **Bigger caps**: sweep `per_seed_hits` 8→12, cap 40→150, prompt shows
   60 lines (was 20), tree lists 200 files, final JSON calls `max_tokens`
   8000 (was 4000).
4. **Family-specific prompts**: `_FAMILY_BRIEF` per family (CWE focus + "also
   check" list mirroring the native rule surface: secrets, weak crypto,
   default-encoding, stack traces, debug leftovers...), appended to the
   system prompt; deep-loop nudge lists pattern seeds explicitly.
5. **Seed expansion**: java +34 and javascript +30 grep seeds mirroring
   native rule patterns (the old 12-seed sink list covered only a minority
   of native findings).
6. **Blind-pass fix**: generic/logic/broad globs `["*"]` → bounded
   `_SOURCE_GLOBS` — on trees with >2000 files (`-git`, build output) the
   jailed tools refuse `*` and the pass hunted blind.

## Results

| round | code | passes | hunt candidates | matched / native | recall |
|-------|------|--------|-----------------|------------------|--------|
| static (old model output, `live-mega` hunt.json) | pre-change | 1 (java) | 10 | 8 / 148 | 5.4% |
| live round 1 | new code, dirty tree (inventory bug: generic only) | 3 | 0 | 0 / 148 | 0.0% |
| live round 2 | new code, clean snapshot, generic/logic/broad | 3 | 62 | 18 / 133 | 13.5% |
| live round 3 | + java/javascript passes (5 total) | 5 | 88 | 27 / 133 | 20.3% |
| live round 4 | + app-first evidence ranking, coverage nudge | 5 | 98 | 12 / 133 | 9.0% |
| live round 5 | + 3 fast-only micro-passes (8 total), prompt trim, pacing | 8 | 152 | 28 / 133* | 21.1% |
| live round 6 | micro briefs cover-all + demo-creds in-scope | 8 | 147 | 29 / 130 | 22.3% |

\* Rounds 1–5 ran while the shared tree carried the sibling
`native-hunt` extension (taint tweaks), hence native=133. The final
rematch on this branch's own engine gives native=130; round-6 candidates
re-matched offline: **29/130 = 22.3%**. Direction is identical either way.

Upstream notes: `opencode-free/iceman-contributor-free` rejects
tools-attached calls intermittently (HTTP 422 "Endpoint is unavailable") and
once hit a 120s read timeout; the fail-soft fallback (closing no-tools
verdict) is what salvages every pass. The model also emits placeholder junk
(`[{"id":1,"name":"Item 1"}...]`) on low-context prompts — fixed by feeding
real sweep/excerpt evidence.

## Verdict: ceiling hit at ~22% — target 50% NOT reached

Best measured recall is **round 6: 29/130 = 22.3%** (147 hunt candidates,
precision 19.7%). Rounds 3–6 plateau at 20–22% across four code variants,
so this is a model/upstream ceiling, not a prompt bug with an obvious fix.

Why the hunt stalls (all measured, not guessed):

1. **The model samples instead of covering.** Micro-passes emit 5–9 items
   while the evidence window holds 30–50 confirmed lines; "cover all"
   instructions move output by ±1. The missing 100+ native lines are
   visible to the sweep but never transcribed into candidates.
2. **Zero-classes need judgment the small model fumbles.** Hardcoded
   secrets (0/13: demo creds read as "intentional"), `console.log`
   debug leftovers (0/12: chased vendored libs before app-first ranking,
   then sampled), path traversal (0/8) and log injection (1/8: need taint
   confirmation), JWT fixtures (0/8: dismissed as test data).
3. **Upstream flakiness eats passes.** Every round loses 3–6 calls to
   HTTP 422 "Endpoint is unavailable" (all tools-attached loop calls) and
   1–2 fast/closing calls to 120s read timeouts. Fail-soft keeps the
   pipeline green, but degraded passes contribute ~0 matches.
4. **Breadth costs precision, not recall.** 147 candidates at 19.7%
   precision: the model already over-reports (vendored libs, test files);
   more candidates add noise faster than matches.

What would actually move recall (out of scope for this lane): a stronger
model (the loop is model-bound, not evidence-bound), per-class deterministic
prefill (would inflate the metric without model judgment — rejected as
gaming), or grading the model on CWE-aware agreement instead of pure
coverage.

## Reproduce

```
python scripts/hunt_recall.py --git-archive harness/WebGoat --live \
    --out artifacts/hunt-recall/live.json
```

Key comes from the environment (`OPENCODE_GO_API_KEY`), never from the
repo. Expect ~15–25 min (8 passes, free-tier latency + retries) and
±3 pts of run-to-run variance from upstream flakiness.
