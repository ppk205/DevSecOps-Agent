# Bao cao scan chi tiet: taiga-ui

Nguon: https://github.com/taiga-family/taiga-ui @ `8281ae4d3a0b`
Ngon ngu chinh: TypeScript
Tool chay: native-hunt fixed (heredoc/append/entry-mark) | semgrep 1.178.0 + rules 85 | gitleaks 8.28.0 | OSV.dev

## Tong quan (dem theo dong file+line)

| Tool | Dong co finding |
|---|---|
| native-hunt | 35 |
| semgrep | 36 |
| gitleaks | 1 |
| OSV (CVE phu thuoc) | 0 |
| native & semgrep | 26 |
| chi native | 9 |
| chi semgrep | 10 |

## Native-hunt chi tiet (35 findings)
Top rule: js-insecure-random [Weak] x23, js-jwt-weak-secret [Weak] x4, js-debug-leftover [Weak] x3, js-hardcoded-secret [Weak] x3, js-generic-api-key [Weak] x1, js-timing-unsafe-compare [High] x1

## Semgrep chi tiet (37 findings)
Top rule: js-insecure-random x24, js-sql-concatenation x10, js-hardcoded-secret x3

## Gitleaks chi tiet (1 findings)
Top rule: generic-api-key x1

## OSV chi tiet (0 CVE)
Top: (khong co)
