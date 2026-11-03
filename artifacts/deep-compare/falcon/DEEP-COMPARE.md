# Deep-scan: falcon

Nguon: https://github.com/falconry/falcon @ `8d3aa53a6ac6` (Python)
App tui: scan-run --profile full, mine_exit=2, gate=failed (co finding la dung).
Exports day du: sarif/json/html/md/txt/docx/final-report trong mine/run-*/

## Mine: 21 dong co finding
Top CWE: scanner [CWE-330] x10, scanner [CWE-328] x6, scanner [CWE-113] x3, scanner [CWE-215] x2

| Doi thu | Trong scope source | Giao voi mine | Ngoai scope |
|---|---|---|---|
| semgrep-auto | 7 | 0 | 5 (yaml/CI/test) |
| bandit-med+ | 29 | 6 |  |

Giao tinh tren scope source chung. Semgrep-auto quet rong hon (yaml/CI) la dung vai tro, khong phai loi.
Chi tiet tung finding: mine/run-*/export-*.json|html|docx, external/*.json (raw).