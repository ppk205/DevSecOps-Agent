# Public real-case sources for Laya

Research date: 2026-11-09.

For individual public audit, bounty and non-CVE case leads, see
[LAYA-PUBLIC-CASE-LEADS.md](LAYA-PUBLIC-CASE-LEADS.md).

This is a source catalog, not a downloaded dataset or a set of Laya labels.
The sources below describe real reported vulnerabilities or real security fixes.
Their inclusion does not establish that every individual record is correct.
Select records traceable to an upstream advisory, project and revision. Exclude
artificially seeded vulnerabilities, generated examples and generated labels.
Do not assume an unchanged or patched function is necessarily safe.

Dataset sizes below are reported by the source authors, not locally measured.
Sources overlap, so their counts cannot be added to obtain unique cases. Releases
and links may change. Check each dataset's terms and each upstream project's
license before copying, redistributing or using source code for training.

## Cross-language sources

| Source | Public access | Reported scope and use | Limits |
| --- | --- | --- | --- |
| MoreFixes v4 | [Zenodo record and downloads](https://zenodo.org/records/20776007) | 43,357 CVEs, 9,972 GitHub projects and 47,616 unique fix commits in the SQL release; CVEs through 2026-06-02. Multilingual CVE, CWE, commit, file and method metadata. | Fix links use heuristics and need checking. The authors describe a 16 GB PostgreSQL database; archives and storage requirements vary. |
| CVEfixes v1.0.8 | [Zenodo record and download](https://zenodo.org/records/13118970) | 11,873 CVEs, 4,249 projects and 12,107 fix commits; includes before/after source for changed files and functions. | Automatically collected; link and function labels need review. The zip is 12.7 GB. |
| CrossVul v2 | [Zenodo record and download](https://zenodo.org/records/4734050) | Cross-language vulnerability records with file changes and commit messages. The linked archive is 367 MB. | Review original advisory and fix links; compare with other sources for duplicates. |
| ReposVul | [Authors' repository](https://github.com/Eshe0922/ReposVul) and [paper](https://arxiv.org/abs/2401.13169) | The paper reports 6,134 CVEs in 1,491 projects across C, C++, Java and Python, with repository and call context. | Uses LLMs and static analysis to identify security-related patch files. Use only independently verified real upstream cases and evidence; do not use model-generated judgments as ground truth. |
| SecBench | [Authors' repository](https://github.com/TQRG/secbench) | Multilingual database of naturally occurring security fixes. | Inspect source records and original repositories. This is distinct from SecBench.js and unrelated cybersecurity question datasets. |
| Project KB | [Project and vulnerability-data link](https://sap.github.io/project-kb/) | Vulnerability statements for Java and Python components; includes work based on manually curated fixes. | Inspect individual statement provenance and upstream revisions; the project documents known limitations. |

## Java sources

| Source | Public access | Reported scope and use | Limits |
| --- | --- | --- | --- |
| Vul4J | [Authors' repository](https://github.com/tuhh-softsec/vul4j) | Real Java vulnerabilities with human patches and proof-of-vulnerability tests. | Reproduction support varies by case. Tests are supporting evidence, not Laya labels. |
| CWE-Bench-Java | [Authors' dataset](https://github.com/iris-sast/cwe-bench-java) | 120 CVEs across path traversal, command injection, XSS and code injection; includes project identities, revisions, advisory and fix information. | Narrow CWE coverage. Some versions of the same repository are related and must remain in one split. |
| JavaVFC | [Authors' paper and dataset link](https://arxiv.org/abs/2409.05576) | The paper reports 784 manually verified Java vulnerability-fixing commits and 16,837 heuristic candidates in an extended set. | Prefer the manually verified set. Independently verify extended candidates; the paper reports a precision of 0.7 for the final keyword-labeling round. |
| VJBench | [Authors' repository](https://github.com/lin-tan/llm-vul) | Original Java vulnerability cases and project metadata. | Select original VJBench cases only. Exclude VJBench-trans, which contains transformed variants. The repository also contains unrelated model outputs. |
| MegaVul Java | [Authors' repository and download](https://github.com/Icyrockton/MegaVul) | The April 2024 Java statistics report 775 CVEs and 902 commits from 362 repositories, plus vulnerable and other functions. | Select Java records linked to original CVEs and commits; do not treat automatic labels or fixed functions as independently verified. Data also includes C/C++, outside the current source-analyzer language scope. |

## Python and JavaScript/TypeScript sources

| Source | Public access | Reported scope and use | Limits |
| --- | --- | --- | --- |
| PyVul | [Authors' repository](https://github.com/billquan/PyVul) | Python security benchmark with commit-level and function-level records; vulnerable snapshots can be reconstructed from referenced repositories. | The paper describes LLM-assisted data cleansing. Use original upstream vulnerability cases and independently verify labels; do not import model-generated judgments. |
| PySecDB | [Authors' repository and request policy](https://github.com/SunLab-GMU/PySecDB) | About 1,200 real Python security commits and 2,800 non-security commits, as reported by the authors. | Download is available only after submitting the authors' request form and obtaining approval. A non-security commit is not proof that its project has no vulnerability. |
| SecBench.js | [Authors' repository](https://github.com/MartinDetloff/AttackStrings) | 600 publicly reported server-side JavaScript vulnerabilities collected from advisory sources. | Verify the original package, advisory and affected revision. Do not execute supplied exploits as part of collection. |
| JsVul | [Authors' repository](https://github.com/jsvul/jsvul) and [dataset DOI](https://doi.org/10.5281/zenodo.18195838) | JavaScript and TypeScript functions derived from security fixes across seven sources. | Code is normalized and labels are heuristic; retrieve the original revision when exact source provenance matters. Overlaps CVEfixes, CrossVul and SecBench.js. |

## Advisory databases for additional cases

These are discovery and corroboration sources. An advisory alone is not a
scanner finding, a triage label, or proof that a particular source line is
vulnerable. Some advisories have no available source or fixing commit.

- [GitHub Advisory Database](https://github.com/github/advisory-database):
  open-source vulnerability advisories, including GitHub-reviewed records.
- [OSV](https://osv.dev/): open-source package advisories and affected-version
  information. Cross-reference advisory aliases before counting cases.
- [CVE List](https://github.com/CVEProject/cvelistV5): official CVE records in
  JSON format, including rejected records that should not be treated as cases.
- [NVD data feeds](https://nvd.nist.gov/vuln/data-feeds): CVE enrichment and
  references; follow references to original advisories and commits.

## From real cases to a Laya dataset

1. Establish project, original advisory, affected revision, fix revision,
   language, license and case family for each chosen real case. Preserve the
   original source and provenance; do not fabricate missing evidence.
2. Keep benchmark ground truth out of scanner and model inputs. Reserve
   held-out project and case families before tuning, and follow
   [TEST-PLAN.md](TEST-PLAN.md). A real vulnerability may produce no finding;
   record missing or partial coverage rather than inventing a finding.
3. For each actual exported scan finding, two independent reviewers apply the
   Laya route, evidence-sufficiency and human-review rubrics and adjudicate
   disagreements. The public datasets above do not establish these decisions.
4. Use the existing exporter and four-way grouping described in
   [LAYA-TRAINING.md](LAYA-TRAINING.md). Projects, related families and identical
   model inputs are kept together; at least four independent groups are needed.
   Retain the test split separately and do not use it for tuning.

No examples have been labeled, no scan or model training was run, and no source
archives were downloaded during this research. The web source pages were
accessible, but a direct download request from this workspace could not connect.
