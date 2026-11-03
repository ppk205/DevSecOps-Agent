# Bao cao scan chi tiet: pikachu

Nguon: https://github.com/zhuifengshaonianhanlu/pikachu @ `5e1e8d9d14a3`
Ngon ngu chinh: PHP
Tool chay: native-hunt fixed (heredoc/append/entry-mark) | semgrep 1.178.0 + rules 85 | gitleaks 8.28.0 | OSV.dev

## Tong quan (dem theo dong file+line)

| Tool | Dong co finding |
|---|---|
| native-hunt | 122 |
| semgrep | 78 |
| gitleaks | 0 |
| OSV (CVE phu thuoc) | 0 |
| native & semgrep | 64 |
| chi native | 58 |
| chi semgrep | 14 |

## Native-hunt chi tiet (123 findings)
Top rule: php-weak-password-hash [High] x35, php-loose-comparison [High] x17, php-insecure-random [Weak] x14, php-weak-password-hash [Weak] x10, php-reflected-xss [Medium] x9, php-reflected-xss [Weak] x8, php-sql-concatenation [Medium] x6, php-path-traversal [High] x6

## Semgrep chi tiet (118 findings)
Top rule: php-insecure-random x42, php-weak-password-hash x23, php-reflected-xss x20, php-loose-comparison x17, php-sql-concatenation x6, php-path-traversal x5, php-command-injection x2, php-dynamic-eval x1

## Gitleaks chi tiet (0 findings)
Top rule: (khong co)

## OSV chi tiet (0 CVE)
Top: (khong co)
