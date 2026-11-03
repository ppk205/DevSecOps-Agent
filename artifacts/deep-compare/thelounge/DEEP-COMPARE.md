# Deep-scan: thelounge

Nguon: https://github.com/thelounge/thelounge @ `70db8bcb6faf` (JavaScript)
App tui: scan-run --profile full, mine_exit=2, gate=failed (co finding la dung).
Exports day du: sarif/json/html/md/txt/docx/final-report trong mine/run-*/

## Mine: 42 dong co finding
Top CWE: scanner [CWE-208] x15, scanner [CWE-489] x11, scanner [CWE-798] x6, scanner [CWE-330] x5, scanner [CWE-22] x2, scanner [CWE-95] x1, scanner [CWE-502] x1, scanner [CWE-327] x1

| Doi thu | Trong scope source | Giao voi mine | Ngoai scope |
|---|---|---|---|
| semgrep-auto | 24 | 1 | 8 (yaml/CI/test) |
| njsscan | 2 | 0 |  |

Giao tinh tren scope source chung. Semgrep-auto quet rong hon (yaml/CI) la dung vai tro, khong phai loi.
Chi tiet tung finding: mine/run-*/export-*.json|html|docx, external/*.json (raw).