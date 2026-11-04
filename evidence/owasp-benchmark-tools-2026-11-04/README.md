# OWASP Benchmark tool comparison, 2026-11-04

No model was called. Scoring rule and normalization are in `score_owasp.py`; results are in `score.json`.
A case counts as flagged when an accepted CWE is reported in the case's own file.

Limits:
- native-hunt results come from `scanner-native-hunt.json`. `scan-run` exited 1 in `.venv-linux` while writing DOCX because `python-docx` is missing there, so no `summary.json` exists. See `raw/*-native.stderr`.
- `native-engine-timing.txt` and `native-engine-timing-corrected.txt` are invalid: `scan_snapshot` was called with wrong arguments and returned 0 findings. Use `native-engine-timing-v3.txt`.
- `manifest.txt` reports 409 dirty lines from Linux git over a Windows checkout (line endings). Windows git reported 0 changed files in `src` and `tests`.
- SonarQube was not run: the container run was denied in the session.
- The first run of native-hunt on these suites was unseen by its rules. Results after any later tuning must be reported separately.

native-hunt engine time is in native-engine-timing-v3.txt: 253.97 s Java, 25.21 s Python.
test_fix failed because semgrep was not on PATH in the test run, not because of the fix logic.
