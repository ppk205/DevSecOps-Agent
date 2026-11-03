# App-vs-App: falcon

Nguon: https://github.com/falconry/falcon @ `8d3aa53a6ac6`
Ngon ngu: Python

"Mine" = app DevSecOps-Agent lane deterministic (union native-hunt + semgrep-85-rules + gitleaks, da normalize/dedup).
"Ext" = app ngoai chay doc lap, default vendor:

| Doi thu | Tim thay | Giao voi mine | Nhan xet |
|---|---|---|---|
| Semgrep OSS (ruleset mac dinh p/python) | 0 | 0 | cung binary, khac rule: rule cong dong hep hon custom-85 |
| Bandit (Med+) | 29 (all: 3164, B101-LOW loai) | 6 | chuyen gia Python; B101 assert noise da loai |
