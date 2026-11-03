# Deep-scan app-tui vs 3 app-ngoai, 5 web (moi ngon ngu 1)

Mine = scan-run --profile full (deterministic + Laya, khong AI).
Ext = semgrep --config auto + bandit + njsscan. Giao tinh tren scope source chung.

| Repo | Lang | Mine | Semgrep-auto (giao / ngoai-scope) | Bandit Med+ (giao) | njsscan (giao) |
|---|---|---|---|---|---|
| problem-spring-web | Java | 1 | 0 (0 / 6) | - | - |
| thelounge | JavaScript | 42 | 24 (1 / 8) | - | 2 (0) |
| vue-mdc | TypeScript | 2 | 0 (0 / 0) | - | 0 (0) |
| falcon | Python | 21 | 7 (0 / 5) | 29 (6) | - |
| pikachu | PHP | 136 | 103 (20 / 1) | - | - |