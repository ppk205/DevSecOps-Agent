# OWASP Top 10 and CWE report cross-reference

SRS FR-61 adds an **OWASP Top 10:2025 and CWE mapping** section. It maps the
run's normalized primary and secondary CWE labels to OWASP's published 2025
category-specific lists. The mapping is bundled, dated and deterministic. Report
generation makes no network request to look up a category and adds no model call.

HTML, Markdown, plain text and Word reports use the same data. The final
narrative includes it when model support is available, disabled, empty or failed.
If the model writes its own OWASP Markdown section, the application replaces
that section with the computed table. Report generation leaves finding status,
independent validation decisions, scores, evidence and scan gates intact.

## Reading the section

Every category appears. Rows show its reported CWE, corresponding finding IDs
and confirmed/rejected/unresolved/pending counts. Pending combines unprocessed,
triaged, assessed and pending-validation states; JSON/SARIF retain each state
separately. A category counts each finding once even when several CWE labels
match it. Per-CWE rows and categories can overlap, so their counts must not be
added to obtain the run's unique finding total.

An empty category means **No mapped findings reported**. It is not a coverage,
compliance or security-test result. A matching CWE does not confirm a finding.
Rejected and unresolved findings retain those statuses in the cross-reference.

Only exact listed CWE IDs are mapped. No classification is guessed from a rule
name, title, CVE, source excerpt or CWE parent. Unclassified or unlisted labels
appear as unmapped rows with their finding references and status counts. Missing
scanner CWEs retain the existing `CWE-UNCLASSIFIED` normalization; a normalized
Finding still requires its primary CWE field. For example, this snapshot does
not directly list CWE-943, so a CWE-943 label remains unmapped despite its
conceptual relationship to injection.

## Reference examples

These are taxonomy examples, not detections or claims that every CWE below is
supported by a scanner or by the current Finding enum.

| OWASP Top 10:2025 category | Example listed CWEs |
| --- | --- |
| A01 Broken Access Control | CWE-22, CWE-862, CWE-918 |
| A02 Security Misconfiguration | CWE-16, CWE-611, CWE-942 |
| A03 Software Supply Chain Failures | CWE-1035, CWE-1104 |
| A04 Cryptographic Failures | CWE-327, CWE-328 |
| A05 Injection | CWE-78, CWE-79, CWE-89 |
| A06 Insecure Design | CWE-434, CWE-841 |
| A07 Authentication Failures | CWE-287, CWE-295, CWE-798 |
| A08 Software or Data Integrity Failures | CWE-502, CWE-915 |
| A09 Security Logging and Alerting Failures | CWE-117, CWE-778 |
| A10 Mishandling of Exceptional Conditions | CWE-209, CWE-215, CWE-754 |

The edition matters: the 2025 taxonomy puts injection in A05 and SSRF in A01.
Do not read those labels as the differently numbered 2021 categories.
See [OWASP's 2025 list](https://top10.owasp.org/2025/), the
[A01 mapped CWEs](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/#list-of-mapped-cwes)
and [A05 mapped CWEs](https://top10.owasp.org/2025/A05_2025-Injection/#list-of-mapped-cwes).

## Structured output and source provenance

JSON adds `owasp_top10` at its root. SARIF adds the identical structure under
`runs[0].properties.owasp_top10`. It contains the edition, snapshot date, source
URL, classification-only flag, total finding count, ten category records and
unmapped rows. Each category includes finding IDs, exact status counts, per-CWE
details and the source URL/hash. User-supplied scan metadata cannot override the
computed SARIF cross-reference. Existing finding records and CSV columns keep
their contracts.

The snapshot was retrieved on 2026-11-04 from the category pages' **List of Mapped
CWEs** sections. Category-page lists are the source of membership; overview
statistics can lag those lists. The retained extraction records the category
URLs and SHA-256 hashes of the fetched pages. OWASP publishes the source under
[CC BY 3.0](https://creativecommons.org/licenses/by/3.0/).
The application includes the CWE IDs and source references, without reproducing
the category narratives. Updating the snapshot is a reviewed code/data change;
reports do not silently follow future website edits.

## Existing runs

Generate a new export from a retained run through the Reports screen or the
existing `scan-export` command. No scanner rerun is required. Archived exports
and the old `final-report.md` are retained as originally produced; they are not
rewritten when the application changes. New scans and newly requested exports
include this section. The native bridge uses the same report generator.

Execution evidence and a synthetic preview are recorded in
[OWASP-REPORT-VERIFICATION-2026-11-04.md](OWASP-REPORT-VERIFICATION-2026-11-04.md).
