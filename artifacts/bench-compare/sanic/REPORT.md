# Bao cao scan chi tiet: sanic

Nguon: https://github.com/sanic-org/sanic @ `5ffc7b371083`
Ngon ngu chinh: Python
Tool chay: native-hunt fixed (heredoc/append/entry-mark) | semgrep 1.178.0 + rules 85 | gitleaks 8.28.0 | OSV.dev

## Tong quan (dem theo dong file+line)

| Tool | Dong co finding |
|---|---|
| native-hunt | 69 |
| semgrep | 20 |
| gitleaks | 16 |
| OSV (CVE phu thuoc) | 0 |
| native & semgrep | 17 |
| chi native | 52 |
| chi semgrep | 3 |

## Native-hunt chi tiet (69 findings)
Top rule: py-debug-mode-enabled [Weak] x25, js-debug-leftover [Weak] x14, py-weak-random-token [Weak] x11, py-hardcoded-secret [High] x4, py-unsafe-deserialization [Weak] x3, py-header-injection [High] x2, py-hardcoded-secret [Medium] x2, py-debug-mode-enabled [Medium] x2

## Semgrep chi tiet (20 findings)
Top rule: py-debug-mode-enabled x10, js-debug-leftover x4, py-weak-random-token x3, py-ldap-injection x1, js-insecure-random x1, py-subprocess-shell-true x1

## Gitleaks chi tiet (16 findings)
Top rule: curl-auth-header x6, generic-api-key x4, private-key x4, jwt x2

## OSV chi tiet (0 CVE)
Top: (khong co)
