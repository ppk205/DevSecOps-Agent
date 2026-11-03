# Deep-scan: pikachu

Nguon: https://github.com/zhuifengshaonianhanlu/pikachu @ `5e1e8d9d14a3` (PHP)
App tui: scan-run --profile full, mine_exit=2, gate=failed (co finding la dung).
Exports day du: sarif/json/html/md/txt/docx/final-report trong mine/run-*/

## Mine: 136 dong co finding
Top CWE: scanner [CWE-328] x45, scanner [CWE-79] x33, scanner [CWE-697] x17, scanner [CWE-330] x14, scanner [CWE-22] x11, scanner [CWE-89] x6, scanner [CWE-95] x3, scanner [CWE-918] x3

| Doi thu | Trong scope source | Giao voi mine | Ngoai scope |
|---|---|---|---|
| semgrep-auto | 103 | 20 | 1 (yaml/CI/test) |

Giao tinh tren scope source chung. Semgrep-auto quet rong hon (yaml/CI) la dung vai tro, khong phai loi.
Chi tiet tung finding: mine/run-*/export-*.json|html|docx, external/*.json (raw).