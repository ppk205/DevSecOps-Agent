# Bao cao scan chi tiet: easyappointments

Nguon: https://github.com/alextselegidis/easyappointments @ `f6c8a4c2f364`
Ngon ngu chinh: PHP
Tool chay: native-hunt fixed (heredoc/append/entry-mark) | semgrep 1.178.0 + rules 85 | gitleaks 8.28.0 | OSV.dev

## Tong quan (dem theo dong file+line)

| Tool | Dong co finding |
|---|---|
| native-hunt | 156 |
| semgrep | 105 |
| gitleaks | 1 |
| OSV (CVE phu thuoc) | 6 |
| native & semgrep | 54 |
| chi native | 102 |
| chi semgrep | 51 |

## Native-hunt chi tiet (164 findings)
Top rule: php-preg-replace-eval [Weak] x94, php-weak-password-hash [Weak] x31, php-insecure-random [Weak] x29, php-loose-comparison [High] x5, php-parse-str-pollution [High] x2, js-debug-leftover [Weak] x1, php-reflected-xss [Weak] x1, php-session-fixation [High] x1

## Semgrep chi tiet (120 findings)
Top rule: php-xxe-external-entity x49, php-insecure-random x35, php-weak-password-hash x31, php-path-traversal x2, php-parse-str-pollution x2, js-debug-leftover x1

## Gitleaks chi tiet (1 findings)
Top rule: generic-api-key x1

## OSV chi tiet (6 CVE)
Top: osv-GHSA-6j4f-fj2g-mc7p x1, osv-GHSA-q2hr-2g5m-vwhr x1, osv-GHSA-qhr7-859c-m2p7 x1, osv-GHSA-g3hv-75wg-m249 x1, osv-GHSA-4p3w-j4w9-5jqw x1, osv-GHSA-68fv-2mgg-jv7q x1
