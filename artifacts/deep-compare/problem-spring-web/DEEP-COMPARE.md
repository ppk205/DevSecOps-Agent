# Deep-scan: problem-spring-web

Nguon: https://github.com/zalando/problem-spring-web @ `236613007ccc` (Java)
App tui: scan-run --profile full, mine_exit=2, gate=failed (co finding la dung).
Exports day du: sarif/json/html/md/txt/docx/final-report trong mine/run-*/

## Mine: 1 dong co finding
Top CWE: scanner [CWE-209] x1

| Doi thu | Trong scope source | Giao voi mine | Ngoai scope |
|---|---|---|---|
| semgrep-auto | 0 | 0 | 6 (yaml/CI/test) |

Giao tinh tren scope source chung. Semgrep-auto quet rong hon (yaml/CI) la dung vai tro, khong phai loi.
Chi tiet tung finding: mine/run-*/export-*.json|html|docx, external/*.json (raw).