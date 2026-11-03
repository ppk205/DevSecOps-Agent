# Bao cao scan chi tiet: matter-js

Nguon: https://github.com/liabru/matter-js @ `b8ee71cd7f9b`
Ngon ngu chinh: JavaScript
Tool chay: native-hunt fixed (heredoc/append/entry-mark) | semgrep 1.178.0 + rules 85 | gitleaks 8.28.0 | OSV.dev

## Tong quan (dem theo dong file+line)

| Tool | Dong co finding |
|---|---|
| native-hunt | 9 |
| semgrep | 4 |
| gitleaks | 0 |
| OSV (CVE phu thuoc) | 0 |
| native & semgrep | 4 |
| chi native | 5 |
| chi semgrep | 0 |

## Native-hunt chi tiet (10 findings)
Top rule: js-debug-leftover [Weak] x6, js-nosql-injection [Weak] x1, js-timing-unsafe-compare [Weak] x1, js-timing-unsafe-compare [Medium] x1, js-jwt-weak-secret [Weak] x1

## Semgrep chi tiet (4 findings)
Top rule: js-debug-leftover x4

## Gitleaks chi tiet (0 findings)
Top rule: (khong co)

## OSV chi tiet (0 CVE)
Top: (khong co)
