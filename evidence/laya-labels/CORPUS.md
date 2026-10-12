# Laya training corpus: proposed labels for five additional Java web apps

Status: **proposed by an AI agent (claude-sonnet-agent) from reading source. Not human adjudication.**
Every row has `adjudicated=false`, `independently_adjudicated=false`, `reviewers=[]`; `prepare()` rejects such rows
until two distinct human reviewers confirm them (QR-17). The `jva-bookstore/` folder here is written by a different
agent and is not counted below.

## Projects

Clones live outside the repo in `D:/phuc/laya-corpus/` (shallow, never built or executed). Scans ran with
`devsec scan-run --profile fast --no-laya --ci`: semgrep 1.178.0 (shipped `java.yml`, 13 rules) and gitleaks 8.30.1
completed. spotbugs and owasp-dependency-check did not run (no Docker; building untrusted code was out of scope).
Semgrep skips `src/test` paths, so each export carries "missing coverage" errors and a failed gate; findings are unaffected.

| slug | URL | SHA | kind | findings | labelled | fast_verification | cross_file_analysis | authorization_analysis | jsp_context_analysis | dependency_analysis | secret_review | human_review | low_priority |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| shepherd | https://github.com/OWASP/SecurityShepherd | `cff3958abf7a18cfc84fe6bed9dd6698631b2cee` | vulnerable (GPL-3.0) | 25 | 25 | 6 | 4 | 0 | 0 | 1 | 4 | 0 | 10 |
| webgoat | https://github.com/WebGoat/WebGoat | `7e198f39189f33e1912f7cbb60e24e42635ca06a` | vulnerable (GPL-2.0) | 42 | 36 | 6 | 3 | 0 | 0 | 0 | 4 | 1 | 22 |
| java-sec-code | https://github.com/JoyChou93/java-sec-code | `4711f4e186258c6e0dd5c3863e7c9592e7e9026a` | vulnerable (no licence file) | 12 | 12 | 2 | 2 | 2 | 0 | 1 | 2 | 0 | 3 |
| xxl-job | https://github.com/xuxueli/xxl-job | `693d27640be76d02ed7214ede57ce75f7f9ebb71` | real-world (GPL-3.0) | 7 | 7 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 6 |
| ruoyi | https://github.com/yangzongzhuan/RuoYi | `9cd770d2ac839999d6a425f70f3bd2cf3a0ee5cd` | real-world (MIT) | 5 | 5 | 0 | 3 | 0 | 0 | 0 | 0 | 1 | 1 |
| **total** | | | | **91** | **85** | 14 | 12 | 3 | 0 | 2 | 10 | 2 | 42 |

The 6 unlabelled rows (all WebGoat JWT sample tokens in docs/tests) are listed with reasons in
`webgoat/proposed-labels.json` under `unlabelled`; unlabelled is not a negative.
Verdicts across the 85 rows: 33 true_positive, 47 false_positive, 5 uncertain.

java-sec-code has no LICENSE file; only scanner metadata and short snippets from it are kept here, no source.

## Gap versus the ~100 reviewed findings per route target

Counts are these five projects only (add the JVA-bookstore rows for the full picture).

| route | proposed | gap to 100 |
|---|---|---|
| fast_verification | 14 | 86 |
| cross_file_analysis | 12 | 88 |
| authorization_analysis | 3 | 97 |
| jsp_context_analysis | 0 | 100 |
| dependency_analysis | 2 | 98 |
| secret_review | 10 | 90 |
| human_review | 2 | 98 |
| low_priority | 42 | 58 |

Why the thin spots: the shipped Semgrep pack is 13 Java-only rules and does not parse JSP, and gitleaks is the only
non-Java source. Even JSP-heavy Shepherd (122 JSP files), DVJA (63) and jpetstore-6 (20) produce no JSP findings;
DVJA and jpetstore-6 produced zero findings at all and were dropped. Closing the gap needs a JSP-aware scanner or rule
pack, spotbugs/Find Security Bugs and dependency-check runs (which need Docker or compiled classes), and more projects.
`authorization_analysis` rows come only from findings whose reachability turns on login or permission rules
(java-sec-code websocket endpoint, xxl-job GLUE execution).

## Self-check

All five exports and 85 rows were loaded, flags set true and `reviewers=["a","b"]` in memory only, then
`vulnscan.training.dataset.prepare()` was called. It succeeded with 5 independent groups and split counts
train 41, validation 25, calibration 7, test 12. Note the group-level split puts all of shepherd in validation,
java-sec-code in test, xxl-job in calibration, and webgoat plus ruoyi in train; route coverage per split is therefore
uneven until more projects are added. Nothing flipped was written to disk.

## Row conventions

- `expected_route` is the cheapest next analysis step given what the finding shows in place; `verdict` is the proposer's
  reading of the truth. A false positive that can only be ruled out from another file is routed `cross_file_analysis`.
- `evidence_sufficiency`: 2 = the finding's own lines settle it, 1 = needs other files, config or library behaviour.
- `needs_human_review` is true only on `human_review` rows.
- Lesson variants share one `case_family` (for example all Shepherd SQL-injection challenge levels, and both Deserialize
  variants in java-sec-code).
- Evidence strings quote the deciding source line; secret values are masked in them and in `scan-export.json`
  (gitleaks output is already redacted).

## Reviewer steps

1. Two reviewers, working independently, open each `proposed-labels.json` next to the clone at the commit in `source.json`
   (re-clone with `git clone` then `git checkout <sha>`; do not build or run it).
2. For every row read `file:line` and the callers/config named in `evidence`, apply the rubrics in
   `build_triage_questions()` literally, and confirm or change `expected_route`, `evidence_sufficiency`,
   `needs_human_review` (true only for `human_review`) and `verdict`.
3. Start with the lowest-confidence rows (see the list below) and the `uncertain` verdicts.
4. Resolve disagreements; keep still-ambiguous rows out of the scored set (move them to `unlabelled`).
5. Only then, on the final rows, set `adjudicated` and `independently_adjudicated` to true and add two distinct real
   reviewer names to `reviewers`. Never edit them for rows nobody reviewed.
6. Concatenate the `rows` arrays (drop the extra fields if the exporter later rejects them; it ignores unknown keys today)
   and run:

   ```powershell
   .venv/Scripts/python.exe -m vulnscan.training.dataset `
     --scan evidence/laya-labels/shepherd/scan-export.json `
     --scan evidence/laya-labels/webgoat/scan-export.json `
     --scan evidence/laya-labels/java-sec-code/scan-export.json `
     --scan evidence/laya-labels/xxl-job/scan-export.json `
     --scan evidence/laya-labels/ruoyi/scan-export.json `
     --labels reviewed-labels.json --out artifacts/laya-dataset
   ```

Lowest-confidence rows overall (0.50 to 0.55): shepherd SqlInjectionEmail.java:92, webgoat VulnerableTaskHolder.java:67,
ruoyi OnlineSessionFactory.java:38, webgoat ActuatorExposureTask.java:28, java-sec-code Cors.java:36.

## Reproduce a scan

`devsec scan-run --checkout D:/phuc/laya-corpus/<dir> --profile fast --no-laya --ci --out <dir> --db-path <db> --workdir <dir>`
with `gitleaks.exe` on PATH (downloaded release 8.30.1 in `D:/phuc/laya-tools`). Directory map: shep=shepherd, wg=webgoat,
jc=java-sec-code, xxl=xxl-job, ruoyi=ruoyi.
