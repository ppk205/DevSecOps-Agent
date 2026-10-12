# JVA-bookstore proposed Laya labels - reviewer guide

These labels are **AI-proposed** (claude-sonnet-agent, from reading the source). They are NOT independent human adjudication. Every row ships with `adjudicated=false`, `independently_adjudicated=false`, `reviewers=[]`; the training gate stays closed until two distinct humans confirm.

- Target: `JVA-bookstore` @ `dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5`
- Run: `run-59b60105a2064402aedde32bc5967ce7` (`scan-export.json`, 7 findings; `proposed-labels.json` labels all 7)
- Scanners: Semgrep ran. Gitleaks (binary missing), SpotBugs and OWASP Dependency-Check (no Docker) FAILED, so this is Semgrep-only coverage and much smaller than the 29-finding T09 sheet. Laya was off.

## Counts

| Route | Rows | | Verdict | Rows | | CWE | Rows |
|---|---|---|---|---|---|---|---|
| low_priority | 6 | | false_positive | 6 | | CWE-89 | 5 |
| fast_verification | 1 | | true_positive | 1 | | CWE-330 | 2 |

Evidence sufficiency: 2 on all rows. `needs_human_review` false on all rows (no conflicting/incomplete deterministic evidence), so no `human_review` route. Case families (3): `jva-bookstore/ddl-bootstrap-literal-sql` (5), `jva-bookstore/weak-prng-otp` (1), `jva-bookstore/weak-prng-seeded-demo-data` (1).

## Least sure first (confidence < 0.7)

None. Lowest-confidence rows to look at anyway:

1. `62eda14f6fdfdef3` OTPUtil.java:18 CWE-330, 0.78, true_positive / fast_verification. Real weak PRNG guarding registration OTP, but exploitability is limited (10 min expiry, 5 attempts); decide whether you treat it as a true positive for training and whether `fast_verification` is the right lane.
2. `65df56a4b593c9d8` DBUtil.java:800 CWE-330, 0.92, false_positive: constant-seeded Random for synthetic book metrics.
3. The five CWE-89 rows (0.93): only string literals are concatenated in `ensureSchema()` DDL. Reviewers may prefer `fast_verification` over `low_priority` if they think a harness is the better lane; the rubric text for low_priority is "very unlikely to be a true positive", which fits.

Also note: the export's `metadata.code_excerpt` is the odd string "requires login" for every finding (scanner/enrichment artifact, not part of the labels).

## Confirm a row

1. Open the cited `file:line` in `JVA-bookstore` (checkout the pinned commit) and read the code in the `evidence` field plus its callers.
2. Apply `triage.py` rubrics literally: pick the route (`_ROUTE_CRITERIA`), evidence 0/1/2, and `needs_human_review` (true only for conflicting/incomplete evidence; route `human_review` pairs with true).
3. If you agree, leave the fields; if not, edit `expected_route`, `evidence_sufficiency`, `needs_human_review`, `verdict`, `rationale` as needed.
4. Set `adjudicated: true`, `independently_adjudicated: true` and `reviewers: ["<name1>", "<name2>"]` (two distinct real reviewers, each reviewing independently). Never copy names you did not review under.
5. Run `python -m vulnscan.training.dataset --scan evidence/laya-labels/jva-bookstore/scan-export.json --labels <reviewed file> --out artifacts/laya-dataset` together with the other projects' scans; one project alone fails with "At least four independent project/family groups".
