# Bao cao scan chi tiet: thelounge

Nguon: https://github.com/thelounge/thelounge @ `70db8bcb6faf`
Ngon ngu chinh: JavaScript
Tool chay: native-hunt fixed (heredoc/append/entry-mark) | semgrep 1.178.0 + rules 85 | gitleaks 8.28.0 | OSV.dev

## Tong quan (dem theo dong file+line)

| Tool | Dong co finding |
|---|---|
| native-hunt | 35 |
| semgrep | 22 |
| gitleaks | 1 |
| OSV (CVE phu thuoc) | 0 |
| native & semgrep | 16 |
| chi native | 19 |
| chi semgrep | 6 |

## Native-hunt chi tiet (35 findings)
Top rule: js-debug-leftover [Weak] x11, js-timing-unsafe-compare [High] x5, js-insecure-random [Weak] x5, js-hardcoded-secret [Weak] x4, js-timing-unsafe-compare [Medium] x2, js-timing-unsafe-compare [Weak] x2, js-implied-eval [Weak] x1, js-unsafe-deserialization [Weak] x1

## Semgrep chi tiet (23 findings)
Top rule: js-debug-leftover x10, js-timing-unsafe-compare x7, js-insecure-random x5, js-hardcoded-secret x1

## Gitleaks chi tiet (1 findings)
Top rule: generic-api-key x1

## OSV chi tiet (0 CVE)
Top: (khong co)
