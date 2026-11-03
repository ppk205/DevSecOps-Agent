# App-vs-App: sanic

Nguon: https://github.com/sanic-org/sanic @ `5ffc7b371083`
Ngon ngu: Python

"Mine" = app DevSecOps-Agent lane deterministic (union native-hunt + semgrep-85-rules + gitleaks, da normalize/dedup).
"Ext" = app ngoai chay doc lap, default vendor:

| Doi thu | Tim thay | Giao voi mine | Nhan xet |
|---|---|---|---|
| Semgrep OSS (ruleset mac dinh p/python) | 29 | 10 | cung binary, khac rule: rule cong dong hep hon custom-85 |
| Bandit (Med+) | 41 (all: 2856, B101-LOW loai) | 13 | chuyen gia Python; B101 assert noise da loai |
