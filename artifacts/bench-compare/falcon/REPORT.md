# Bao cao scan chi tiet: falcon

Nguon: https://github.com/falconry/falcon @ `8d3aa53a6ac6`
Ngon ngu chinh: Python
Tool chay: native-hunt fixed (heredoc/append/entry-mark) | semgrep 1.178.0 + rules 85 | gitleaks 8.28.0 | OSV.dev

## Tong quan (dem theo dong file+line)

| Tool | Dong co finding |
|---|---|
| native-hunt | 21 |
| semgrep | 2 |
| gitleaks | 0 |
| OSV (CVE phu thuoc) | 0 |
| native & semgrep | 2 |
| chi native | 19 |
| chi semgrep | 0 |

## Native-hunt chi tiet (21 findings)
Top rule: py-weak-random-token [Weak] x10, py-weak-hash [Weak] x6, py-header-injection [High] x3, py-debug-mode-enabled [Weak] x2

## Semgrep chi tiet (2 findings)
Top rule: py-debug-mode-enabled x1, py-weak-random-token x1

## Gitleaks chi tiet (0 findings)
Top rule: (khong co)

## OSV chi tiet (0 CVE)
Top: (khong co)
