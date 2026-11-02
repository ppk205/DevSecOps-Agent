# Related work and bounded industry comparison

Source review: 2026-11-02. These are published descriptions, not measurements
of DevSecOps-Agent. The experiment uses the configurations in
`docs/EXPERIMENT-RUNBOOK.md`; the optional benchmark replication has not run.

| System | LLM role | Static analyser | Benchmark or input | Vulnerability classes | Human involvement | Fix generation | Reported results and source |
| --- | --- | --- | --- | --- | --- | --- | --- |
| IRIS, Li, Dutta and Naik, ICLR 2025, arXiv v3 | Infer project-specific source/sink specifications; filter paths using contextual reasoning | CodeQL, with inferred specifications and CWE-specific queries | CWE-Bench-Java: 120 manually validated vulnerabilities in buildable Java projects | CWE-22, CWE-78, CWE-79, CWE-94 | Dataset labels are manually validated; the described detection/triage pipeline automatically filters alerts, rather than requiring per-step human gates | No fix-generation stage is described in the evaluated pipeline | CodeQL detects 27 and IRIS with GPT-4 detects 55; average FDR is 90.03% and 84.82%, respectively. These are v3 Table 1 results, not this project's results. [IRIS §§3–5, Tables 1–2](https://arxiv.org/html/2405.17238v3) |
| GitHub Copilot Autofix (F2) | Generate a proposed patch and explanation from a CodeQL alert, query help and surrounding source | CodeQL | Supported CodeQL alerts in repositories; product documentation describes internal evaluation, not the JVA-bookstore experiment | Subset of supported default/security-extended queries; Java/Kotlin is supported | Developer reviews and accepts the suggestion; documentation warns that no suggestion may be available and that tests/review remain necessary | LLM-generated code changes | No comparable JVA-bookstore detection or acceptance result is published on the reviewed page. [GitHub application card, Overview, Key features, Limitations and Custom evaluations](https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/about-autofix-for-codeql-code-scanning) |
| Semgrep platform AI Autofix (F3; plan name: Assistant) | Generate remediation guidance and code changes from findings/context | Semgrep Code | Findings in a connected Semgrep AppSec Platform repository | Coverage depends on the finding and product support; record actual eligible alerts in the run | User chooses Open Autofix PR; the product creates a draft PR/MR for review and merge | AI-generated patch, separate from textual Suggested fix | No comparable JVA-bookstore outcome on the reviewed pages. The current documentation calls the AI layer Multimodal. [Overview](https://docs.semgrep.dev/semgrep-multimodal/overview), [Autofix](https://docs.semgrep.dev/semgrep-code/triage-remediation/autofix.md) |
| Semgrep rule-defined fix (F4) | None | Semgrep rules | Matches from rules containing `fix:` or `fix-regex` | Limited to rules that actually define a replacement | Developer authors/reviews the rule and decides whether to apply its replacement | Deterministic replacement; `--autofix --dryrun` previews it | No accuracy or fix-success metric is inferred from the feature description. [Rule-defined fix](https://docs.semgrep.dev/writing-rules/rule-defined-fix.md) |

## Interpretation of the IRIS results

The exact detection criterion in v3 §3.6 is:

> If at least one detected vulnerable path passes through a fixed location for
> the given vulnerability, then we consider the vulnerability detected.

IRIS counts path intersections with known fixed locations and averages
per-project measures. Its average false discovery rate is not the safe-site
false positive rate computed by this repository's evaluator. The paper also
notes in §5.2 that alerts for previously unknown true vulnerabilities can count
as false positives under its known-location criterion, making the reported
FDR an upper bound. Do not place these values beside this project's site-based
precision/recall/FPR as though the labels and denominators were identical.

The values above were checked against the v3 HTML abstract and Tables 1–2.
A Python/httpx/lxml command also extracted the abstract, §3.6 and both tables
during this implementation. Earlier paper versions are not used.

## Position of this project

The harness uses its own source–sink and route rules to surface candidates.
AI supports investigation inside approved batches, explains evidence, and
proposes CVSS vectors and fixes. Laya is advisory. Humans own finding status
and fix application. CodeQL and Semgrep results remain outside the harness.

This control model differs from IRIS's specification-inference/automatic
filtering pipeline. The distinction does not establish better detection.
Detection, workload and fix quality require the separate measured runs.

For F3, keep the plan's configuration identifier but record the actual product
feature used. Multimodal's **Suggested fix** is text guidance, while **Autofix**
creates code changes. Do not score text guidance as an exported patch. Account,
source-upload and repository-write permissions must be established by the
operator before that optional run.

## Optional R1 replication

Not run. A future replication must pin CWE-Bench-Java and CodeQL revisions,
record the selected projects and model, and use IRIS's criterion above in a
separate result table. Limit the planned subset to CWE-22, CWE-78 and CWE-79.
Different projects, models, queries or detection criteria prevent a direct
numerical comparison with the published IRIS experiment.
