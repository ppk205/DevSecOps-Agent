# Deep-scan: vue-mdc

Nguon: https://github.com/posva/vue-mdc @ `bf4795cefe22` (TypeScript)
App tui: scan-run --profile full, mine_exit=2, gate=failed (co finding la dung).
Exports day du: sarif/json/html/md/txt/docx/final-report trong mine/run-*/

## Mine: 2 dong co finding
Top CWE: scanner [CWE-489] x2

| Doi thu | Trong scope source | Giao voi mine | Ngoai scope |
|---|---|---|---|
| semgrep-auto | 0 | 0 | 0 (yaml/CI/test) |
| njsscan | 0 | 0 |  |

Giao tinh tren scope source chung. Semgrep-auto quet rong hon (yaml/CI) la dung vai tro, khong phai loi.
Chi tiet tung finding: mine/run-*/export-*.json|html|docx, external/*.json (raw).