# Bao cao scan chi tiet: spring-boot-demo

Nguon: https://github.com/xkcoding/spring-boot-demo @ `87a142f9604c`
Ngon ngu chinh: Java
Tool chay: native-hunt fixed (heredoc/append/entry-mark) | semgrep 1.178.0 + rules 85 | gitleaks 8.28.0 | OSV.dev

## Tong quan (dem theo dong file+line)

| Tool | Dong co finding |
|---|---|
| native-hunt | 59 |
| semgrep | 16 |
| gitleaks | 9 |
| OSV (CVE phu thuoc) | 19 |
| native & semgrep | 14 |
| chi native | 45 |
| chi semgrep | 2 |

## Native-hunt chi tiet (60 findings)
Top rule: java-log-injection [High] x26, java-stack-trace-exposure [Weak] x8, java-unsafe-reflection [High] x3, java-log-injection [Medium] x3, java-log-injection [Weak] x3, java-unclosed-resource [Weak] x2, java-hardcoded-credentials [Weak] x2, java-default-encoding [Weak] x2

## Semgrep chi tiet (16 findings)
Top rule: java-stack-trace-exposure x8, java-permissive-cors x2, java-insecure-cookie x1, java-weak-digest x1, java-log-injection x1, java-open-redirect x1, java-hardcoded-credentials x1, js-insecure-random x1

## Gitleaks chi tiet (9 findings)
Top rule: curl-auth-header x5, jwt x3, generic-api-key x1

## OSV chi tiet (19 CVE)
Top: osv-GHSA-599f-7c49-w659 x1, osv-GHSA-v98j-7crc-wvrj x1, osv-GHSA-285m-vhfq-xx4h x1, osv-GHSA-2cqf-6xv9-f22w x1, osv-GHSA-2hjr-vmf3-xwvp x1, osv-GHSA-3393-hvrj-w7v3 x1, osv-GHSA-5v8f-xx9m-wj44 x1, osv-GHSA-62ww-4p3p-7fhj x1
