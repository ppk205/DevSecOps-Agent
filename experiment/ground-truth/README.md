# Ground truth for the DevSecOps-Agent experiment

`jva-bookstore.csv` and `fixtures.csv` follow the same header: `id, file,
line_start, line_end, cwe, kind, origin, cvss_vector, labeller_a, labeller_b,
agreed`. Paths are relative to the repository root and use forward slashes.

Labelling protocol
------------------
1. Two labellers (A and B) work independently on the same checkout. Neither
   sees the other's list before both are finished.
2. A labeller records every vulnerable site, its CWE and the line range of the
   vulnerable statement. `origin` is `builtin` for flaws already in the target
   and `injected` for a flaw added for the experiment.
3. Safe sites are sampled from harness candidates and baseline alerts that
   both labellers judge not vulnerable. They are recorded with `kind=safe` and
   no CVSS vector.
4. Each labeller sets a CVSS v4.0 vector for every vulnerable item. The score
   in the results is computed by `score_cvss4`, never typed in.
5. Disagreements are settled in a recorded discussion. Only items with
   `agreed=true` are scored; the rest stay in the file as history.
6. Freeze the file with a commit before any model configuration runs.

`cwe-equivalence.csv`
---------------------
Two columns, `cwe,equivalent`. A pair is symmetric: listing `CWE-639,CWE-862`
also lets a CWE-862 row match a CWE-639 item. Only documented pairs belong
here; every pair in the file is printed with the results.

## Data status and format

No human-labelled target data is supplied by the unit tests. Values in
`tests/experiment/` are synthetic test inputs, never measured evidence.
The owner supplies the two independent labellers and freezes their agreed
CSV before the live pilot or full experiment. Do not infer agreement from a
scanner result, model reply or test fixture directory name.

The header must exactly match the field order above. Item ids are unique;
line ranges start at one; `kind` is `vuln` or `safe`; `origin` is `builtin` or
`injected`. Agreed rows require both labeller names. Unagreed rows remain in
the input but do not contribute ground-truth positives or negatives.

Matching uses repository-relative paths, explicit CWE pairs, and a three-line
window. Each item is credited once per configuration, repetition and stage;
duplicate alerts are reported separately. Unmatched alerts count as FP.
Safe-site sampling bounds interpretation of FPR; absent safe labels make FPR
unknown. Dependencies (B4) and secrets (B5) require explicit `gt_ids` cohorts
in their run's `status.json`, as described in the runbook.
