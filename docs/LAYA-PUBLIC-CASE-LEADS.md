# Public security cases beyond CVE datasets

Research date: 2026-11-09. This document catalogs external, publicly disclosed
security cases and source links. It is not a downloaded training dataset and
contains no generated vulnerability examples or Laya training labels.

The cases include reports without a CVE, audit observations, and disclosed
bug-bounty reports. A case can later receive a CVE or appear in an existing
dataset. Dataset membership has not been checked against every release, so none
is claimed to be absent from all datasets. GitHub's "No known CVE" is the
advisory page's status as observed in this research, not a permanent guarantee.
See [LAYA-REAL-CASE-SOURCES.md](LAYA-REAL-CASE-SOURCES.md) for existing datasets.

An advisory, audit or maintainer fix is evidence of a report, not independent
proof that every interpretation, line location or claimed impact is correct.
The links are starting points for finding the exact pre-fix source, deployment
conditions and independently reviewed scan findings. Treat severity and
remediation status as the sources' statements at their publication dates.

## Disclosures listed without a known CVE

| Project and case | Public record | Source and review notes |
| --- | --- | --- |
| OWASP ESAPI, Java: HTML validation can accept unsafe input | [GHSA-r68h-jhhj-9jvm](https://github.com/advisories/GHSA-r68h-jhhj-9jvm) | Maintainers explain why they did not file a CVE. Removed in 2.6.0.0; use of the return value and output context determine impact. |
| scikit-learn, Python: benchmark configuration evaluates an environment variable | [GHSA-475q-v6j3-mjr4](https://github.com/google/security-research/security/advisories/GHSA-475q-v6j3-mjr4) | Researcher describes a benchmarking script, required control of an environment variable and [fix PR 28504](https://github.com/scikit-learn/scikit-learn/pull/28504). Check the actual affected revision; do not infer arbitrary remote access. |
| PyPI and WebOb, Python: chained verified-URL open redirect | [GHSA-6hc9-758f-7r98](https://github.com/google/security-research/security/advisories/GHSA-6hc9-758f-7r98) | Researcher describes three interacting behaviors, mitigations and disclosure timeline. The report separately references a previous CVE; this chain itself was listed without a known CVE. Recover exact project revisions. |
| UTCP HTTP plugin, Python: redirect bypass of destination validation | [GHSA-9qhg-99ww-9mqc](https://github.com/advisories/GHSA-9qhg-99ww-9mqc) | The advisory links a specific vulnerable revision and fix reference and describes the conditions for SSRF. Review redirect handling and call context. |
| Legacy chatgpt-on-wechat, Python: unauthorized access to tool execution | [GHSA-qwjc-xv6c-mqfx](https://github.com/zhayujie/CowAgent/security/advisories/GHSA-qwjc-xv6c-mqfx) | Advisory identifies legacy 1.x scope, configuration conditions and fix commit `ab88e3a`. It explicitly excludes the refactored CowAgent 2.0+ branch. |
| Jaeger UI, TypeScript: stored XSS through trace attributes | [GHSA-2w8w-qhg4-f78j](https://github.com/advisories/GHSA-2w8w-qhg4-f78j) | Provides affected versions and a source path. Its related UI advisory describes the same case; deduplicate. Resolve the floating source link to an affected commit. |
| Nuxt, JavaScript/TypeScript: unsafe rendering in a NoScript component | [GHSA-m3q2-p4fw-w38m](https://github.com/nuxt/nuxt/security/advisories/GHSA-m3q2-p4fw-w38m) | Maintainer advisory names fix commits `4b054e9d` and `7fea9fd6`. It credits both an AI-assisted report and an independent human report. Use original project code and verify the fix, not generated judgments. |
| cdxgen, JavaScript: command injection from a scanned Maven project | [GHSA-5vwr-qchf-q4pf](https://github.com/cdxgen/cdxgen/security/advisories/GHSA-5vwr-qchf-q4pf) | Affected scanner execution used repository-controlled paths; [PR 4059](https://github.com/cdxgen/cdxgen/pull/4059) is cited as the fix. This concerns the scanner's own code, not a Java finding in the target. |
| n8n, JavaScript/TypeScript: stored XSS and open redirect in form node | [GHSA-w673-8fjw-457c](https://github.com/n8n-io/n8n/security/advisories/GHSA-w673-8fjw-457c) | Maintainers describe necessary workflow-editing permission and fixed release lines. Determine exact vulnerable source and fix commits. |
| TinyMCE, JavaScript: XSS in editor parsing | [GHSA-vrv8-v4w8-f95h](https://github.com/tinymce/tinymce/security/advisories/GHSA-vrv8-v4w8-f95h) | Maintainer disclosure gives affected and fixed versions and describes clipboard/API conditions. Locate the exact parser change and original source. |
| Ibexa User, PHP: anonymous user settings exposed | [GHSA-r3fg-3r88-6x3f](https://github.com/advisories/GHSA-r3fg-3r88-6x3f) | Advisory links upstream commit `77d1a09` and describes limited impact. Check the affected configuration and exact parent revision. |
| Pimcore admin bundle, PHP/JavaScript: embedded vulnerable jQuery | [GHSA-jmh9-6rjq-gjh9](https://github.com/advisories/GHSA-jmh9-6rjq-gjh9) | A dependency exposure, not proof that every consuming page is exploitable. The upstream dependency also has its own advisories; preserve that relationship. |

## Public audit findings with remediation links

### PyPI Warehouse, 2026

The [PyPI maintainer's audit summary](https://blog.pypi.org/posts/2026-04-16-pypi-completes-second-audit/)
lists 14 findings by Trail of Bits and links the full report and remediation
work. These are Python web-application observations from the same project, not
14 independent projects. The summary calls some findings informational and
accepts two; do not silently turn those into confirmed vulnerabilities or
assume they have no CVE. The statuses below are from the April 2026 summary.

| Audit ID | Reported finding | Public remediation or status |
| --- | --- | --- |
| TOB-PYPI26-1 | Token replay window from mismatched expiration and leeway | [PR 19627](https://github.com/pypi/warehouse/pull/19627) |
| TOB-PYPI26-2 | Race in token replay prevention | [PR 19625](https://github.com/pypi/warehouse/pull/19625) |
| TOB-PYPI26-3 | Verification badge bypass | [PR 19628](https://github.com/pypi/warehouse/pull/19628) |
| TOB-PYPI26-4 | Project token-deletion audit events dropped | [PR 19652](https://github.com/pypi/warehouse/pull/19652) |
| TOB-PYPI26-5 | Privileged account status exposed during password reset | [PR 19653](https://github.com/pypi/warehouse/pull/19653) |
| TOB-PYPI26-6 | IP ban not enforced by token authentication | Accepted in the audit summary; no fix link there. |
| TOB-PYPI26-7 | Organization application modification missing write-permission check | [PR 19619](https://github.com/pypi/warehouse/pull/19619) |
| TOB-PYPI26-8 | Organization members able to invite owners | [PR 19610](https://github.com/pypi/warehouse/pull/19610) |
| TOB-PYPI26-9 | TOTP replay prevention bypass through whitespace normalization | [PR 19668](https://github.com/pypi/warehouse/pull/19668) |
| TOB-PYPI26-10 | Wheel metadata not compared with upload metadata | Accepted in the audit summary; no fix link there. |
| TOB-PYPI26-11 | Token deletion missing ownership check | [PR 19669](https://github.com/pypi/warehouse/pull/19669) |
| TOB-PYPI26-12 | OIDC publisher lookup missing issuer isolation | [PR 19661](https://github.com/pypi/warehouse/pull/19661); summary links an additional change. |
| TOB-PYPI26-13 | Stale organization-scoped project associations | [PR 19749](https://github.com/pypi/warehouse/pull/19749) |
| TOB-PYPI26-14 | Administrative flag changes lack audit logging | [PR 19751](https://github.com/pypi/warehouse/pull/19751) |

PyPI's [first audit announcement](https://blog.pypi.org/posts/2023-11-14-1-pypi-completes-first-security-audit/)
links an earlier report covering Warehouse and cabotage. It reports 29
advisories; inspect the individual report before counting actionable cases.

### Apache Commons, 2024

The [Ada Logics audit report](https://ostif.org/wp-content/uploads/2024/07/apache-security-audit-report-12th-june-2024.pdf)
covers Java Commons IO, Lang and Codec and provides individual observations and
source context. For example, `ADA-APACHE-LANG-2023-5` discusses potential unsafe
deserialization when a caller supplies untrusted data and links
[SerializationUtils at a specific revision](https://github.com/apache/commons-lang/blob/f04b12b9cef909b079984fa4ab51c2ff8bb323f8/src/main/java/org/apache/commons/lang3/SerializationUtils.java#L203).
The audit marks the observation reported. A deserialization API alone does not
prove a deployed application is vulnerable; establish attacker-controlled input
and surrounding conditions. Do not infer the current status or a CVE alias.

## Public issue and bounty reports

These are reports on real projects; the report text and any reproduced inputs
are evidence about those projects, not necessarily independently validated
labels for a Laya scan. CVE and dataset membership are unknown here.

| Case | Public report | Evidence and limits |
| --- | --- | --- |
| GitLab Markdown stored XSS | [GitLab issue 52392](https://gitlab.com/gitlab-org/gitlab-foss/-/issues/52392) | Security team notes verification and links HackerOne report 418764. Find the actual fix and affected revision. |
| GitLab Markdown XSS | [GitLab issue 64033](https://gitlab.com/gitlab-org/gitlab-foss/-/issues/64033) | Links HackerOne report 633942 and names tested GitLab version 12.0.2. Verify fix and whether related to other GitLab cases. |
| GitLab go-get middleware output encoding | [GitLab issue 31508](https://gitlab.com/gitlab-org/gitlab-foss/-/issues/31508) | Links HackerOne report 224188 and source revision `6c65b63ca5fb60ae26c900b4615054d2ff66eeb9`. The issue confirms limited redirect impact; do not promote the broader XSS claim without additional evidence. |

## Where to find more original reports

| Source | What to look for | Availability and cautions |
| --- | --- | --- |
| [Trail of Bits public reports](https://trailofbits.com/reports/) | Audit reports on real projects, often with source revisions, findings, severity and fix status. | Select open-source application reports and inspect each finding. Reports can include hardening advice or unresolved hypotheses. |
| [OSTIF audit publications](https://ostif.org/apachec-audit-complete/) | Open-source security audits, including the Apache Commons report above. | Follow the individual report and source revision; do not assume all audit observations are confirmed exploitable flaws. |
| [GitHub Security Lab advisories](https://github.com/github/securitylab/security/advisories) and [Google security research advisories](https://github.com/google/security-research/security/advisories) | Public researcher disclosures with maintainer references, versions and sometimes fix commits. | Some involve proprietary software, have no source, lack fixes or contain related CVE aliases. Check each record. |
| [GitLab public issues](https://gitlab.com/gitlab-org/gitlab/-/issues) | Previously disclosed security issues, linked HackerOne reports and merge requests. | Search public items only; verify project/revision and avoid treating an issue title as a confirmed impact. |
| [HackerOne Hacktivity](https://hackerone.com/hacktivity) | Publicly disclosed bug-bounty reports and triage history. | Many reports concern proprietary services or lack code; filter to real public source and immutable revisions. |
| [Huntr Hacktivity](https://huntr.com/hacktivity) | Publicly disclosed reports associated with open-source projects. | Some older report pages were unavailable or displayed a sunset notice during this research. Follow public project advisories and commits where available. |
| [OSS-Fuzz vulnerability records](https://github.com/google/oss-fuzz-vulns) | Published fuzz-discovered project issues with OSV identifiers and affected-commit information. | Choose source projects and languages this application can analyze; a crash is not automatically a confirmed security vulnerability. Some projects are C/C++ or other unsupported languages. |
| [Drupal core security advisories](https://www.drupal.org/security/core/all) and [contributed-project advisories](https://www.drupal.org/security/contrib) | PHP project disclosures, including access control and XSS cases. | Some have CVEs, some may not. Resolve advisory version to original project code and check dates. |
| [FriendsOfPHP security advisories](https://github.com/FriendsOfPHP/security-advisories) | Maintainer-sourced PHP dependency advisories and affected version ranges. | Dependency metadata is not an application-level vulnerability or Laya route label. Verify reachability and upstream source. |

One [empirical study](https://arxiv.org/abs/2501.17748) reports examining
3,798 reviewed advisories and 4,033 disclosed OSS bounty reports, including
reports without CVEs. These are the researchers' study counts, not the number
of new cases collected here, and some sources overlap.

## Collection rules

1. Record public report URL, source project, original revision, affected code,
   report date, fix or accepted-risk status, license and available aliases.
   Record missing fields as unknown. Do not download or preserve real secrets.
2. Check whether the project is a supported source language and whether the
   scanner actually covered the relevant file. Missing detection is not a safe
   label. The existence of a public report does not guarantee scan coverage.
3. Keep related reports, revisions and projects grouped for splitting. Check
   existing datasets for overlap before describing any case as new.
4. Real scanner findings need two independent reviewers to adjudicate the Laya
   route, evidence sufficiency and human-review decision. Keep held-out labels
   outside inputs as required by [TEST-PLAN.md](TEST-PLAN.md) and follow
   [LAYA-TRAINING.md](LAYA-TRAINING.md) before any future training.

No source archives were downloaded, no scan was run, no Laya labels were
created, and no training was performed for this research.
