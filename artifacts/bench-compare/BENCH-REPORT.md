# So sánh native-hunt vs 3 tool khác — 12 web (Nov-2026)

Engine native bản fixed (heredoc/append/entry-mark + 51 taint_sinks).
Đối chứng: **semgrep 1.178.0** (85 rules) + **gitleaks 8.28.0** + **OSV.dev**.
Mỗi repo 1 folder `artifacts/bench-compare/<slug>/` gồm `manifest.json`
(url + commit SHA — note nguồn), `native.json`, `semgrep.json`,
`gitleaks.json`, `osv.json` (chi tiết từng finding), `comparison.json`,
`REPORT.md` (đọc cho người).

## Bảng tổng (đếm theo dòng file+line)

| Repo | Ngôn ngữ | native | semgrep | gitleaks | OSV | giao N/S |
|---|---|---|---|---|---|---|
| spring-boot-demo | Java | 59 | 16 | 9 | 19 | 14 |
| problem-spring-web | Java | 1 | 1 | 0 | 0 | 1 |
| thelounge | JavaScript | 35 | 22 | 1 | 0 | 16 |
| matter-js | JavaScript | 9 | 4 | 0 | 0 | 4 |
| vue-mdc | TypeScript | 2 | 0 | 0 | 0 | 0 |
| taiga-ui | TypeScript | 35 | 36 | 1 | 0 | 26 |
| flask-tutorial | Python | 0 | 0 | 2 | 28 | 0 |
| falcon | Python | 21 | 2 | 0 | 0 | 2 |
| sanic | Python | 69 | 20 | 16 | 0 | 17 |
| laravel-terminal | PHP | 0 | 0 | 0 | 230 | 0 |
| pikachu | PHP | 122 | 78 | 0 | 0 | 64 |
| easyappointments | PHP | 156 | 105 | 1 | 6 | 54 |
| **Tổng** | 5 họ | **509** | **284** | **30** | **283** | **198** |

## Đọc kết quả

- Native bao phủ trùng 198/284 semgrep (~70% toàn bench; WebGoat riêng
  43/49 = 88%). Phần native-only High/Medium đã spot-check: SQLi
  Lesson2/3/4, XSS heredoc PHP, log-injection, default-charset — semgrep mù.
- Native-only Weak (search-mode) ồn hơn: dùng làm lane verify, không đếm
  trong báo cáo chính.
- flask-tutorial / laravel-terminal / vue-mdc gần như sạch ở cả 2 engine —
  repo nhỏ/sạch thật, không phải scan hỏng (OSV vẫn thấy CVE phụ thuộc).
- OSV bổ sung chiều khác hẳn: 230 CVE trong laravel-terminal lockfile mà
  cả 2 engine source đều mù — đúng vai trò tool phụ thuộc.
- Gitleaks ít hit vì bench repos đã qua dọn secret công khai; chiều này
  WebGoat mạnh hơn (23 hit).

Tái hiện: `PYTHONPATH=src .venv/Scripts/python.exe scripts/bench_compare.py`
(clone shallow + semgrep/gitleaks/OSV), rồi re-scan native bằng
`scan_snapshot` (xem `docs/CONTRIBUTION-native.md`).
