# App-cua-tui vs App-ngoai — 12 web

Mine = DevSecOps-Agent lane deterministic. Ext = Semgrep-OSS-default + Bandit(Med+) + njsscan, chay doc lap.
| Repo | Lang | Mine | Semgrep-def (giao) | Bandit Med+ (giao) | njsscan (giao) |
|---|---|---|---|---|---|
| easyappointments | PHP | 261 | 9 (0) | - | - |
| falcon | Python | 23 | 0 (0) | 29 (6) | - |
| flask-tutorial | Python | 2 | 0 (0) | 0 (0) | - |
| laravel-terminal | PHP | 0 | 0 (0) | - | - |
| matter-js | JavaScript | 13 | 0 (0) | - | 0 (0) |
| pikachu | PHP | 200 | 66 (24) | - | - |
| problem-spring-web | Java | 2 | 0 (0) | - | - |
| sanic | Python | 105 | 29 (10) | 41 (13) | - |
| spring-boot-demo | Java | 84 | 7 (1) | - | - |
| taiga-ui | TypeScript | 72 | 0 (0) | - | 0 (0) |
| thelounge | JavaScript | 58 | 3 (1) | - | 2 (0) |
| vue-mdc | TypeScript | 2 | 0 (0) | - | 0 (0) |

## Doc ket qua (trung thuc)
- Semgrep-default tim it hon mine hau het (pikachu 66 vs mine 200; sanic 29 vs 105): ruleset cong dong hep, rule custom-85 + native taint phu rong hon.
- Bandit Med+ o sanic 41 (giao 13), falcon 29 (giao 6): bo sung that (B104 hardbind, B108 tempdir) ma ca 2 engine source deu mu — chuyen gia tung ho co gia tri.
- Bandit all hon 3000/repo nhung 98% la B101 assert-LOW noise — so con so tho la sai lam, phai loc Med+.
- njsscan gan nhu mu (thelounge 2 vue-template, con lai 0): Node SAST yeu voi codebase hien dai; mine bat duoc nhieu hon nho native taint.
- Gioi han: chua so lane AI (can upstream on dinh); gitleaks/OSV-standalone bo qua vi trung DB/binary (ghi ro, khong gia vo so).