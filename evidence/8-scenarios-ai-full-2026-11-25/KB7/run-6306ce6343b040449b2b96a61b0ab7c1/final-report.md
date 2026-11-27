# Tóm tắt điều hành

Bản quét trên target `local` tại commit `ef7646855751464552bda13b150e5d3acff76376` ghi nhận 10 phát hiện, tất cả đều ở trạng thái `unresolved`. Toàn bộ 10 phát hiện là đề xuất của model (`model_only`), không có phát hiện nào từ scanner và không có phát hiện nào được cả hai bên đồng thuận. Validator kết luận "Insufficient independent evidence" cho từng phát hiện, nên chưa có cơ sở để xác nhận cũng như bác bỏ bất kỳ mục nào. Gate đang ở trạng thái `pending`.

# Phạm vi và phương pháp

- Phạm vi: target `local`, commit `ef7646855751464552bda13b150e5d3acff76376`.
- Số liệu trạng thái: `{"unresolved": 10}`.
- Đối chiếu model và scanner: `agreed: 0`, `model_only: 10`, `scanner_only: 0`.
- Nguồn phát hiện: chỉ từ model. Không có phát hiện độc lập từ scanner.
- Đánh giá của validator cho cả 10 mục: "Insufficient independent evidence. Scanner detections, model proposals and incomplete procedures do not establish confirmation or rejection."
- Các mục không có trong dữ liệu cung cấp được coi là chưa biết.

# Phát hiện ưu tiên

**Mức critical (6 phát hiện, tất cả `unresolved`)**

- `model-1cb16bbe2d7e132d` | CWE-78 | `app/vuln_cmd.rb:3` | OS command injection qua `params[:dir]` không được làm sạch trong `system()`.
- `model-1eae62911d192eb8` | CWE-78 | `app/vuln_cmd.rb:1` | OS command injection khi tham số do người dùng kiểm soát đi vào `system()`.
- `model-ac40b4bbf031c98f` | CWE-95 | `app/vuln_eval.rb:3` | Remote code execution do `eval()` trên tham số của request.
- `model-1a49f19ddea57d2b` | CWE-95 | `app/vuln_eval.rb:1` | Code injection do `eval` trên dữ liệu không đáng tin cậy.
- `model-ccb26c19b27f8e36` | CWE-89 | `app/vuln_sql.rb:3` | SQL injection do nội suy chuỗi trong `where()` của ActiveRecord.
- `model-c2b6b14f556a90d7` | CWE-89 | `app/vuln_sql.rb:1` | SQL injection qua nội suy chuỗi trong câu truy vấn.

**Mức high (4 phát hiện, tất cả `unresolved`)**

- `model-86c0885f0cec1daf` | CWE-79 | `app/vuln_view.erb:1` | Cross-site scripting qua `raw()` trên tiểu sử người dùng trong template ERB.
- `model-501079420c3a0aaf` | CWE-639 | `app/vuln_sql.rb:2` | Broken access control: tra cứu bản ghi người dùng không có xác thực hay giới hạn theo chủ sở hữu (IDOR).
- `model-466f136d5b9cefd2` | CWE-862 | `app/vuln_cmd.rb:2` | Broken access control: hành động liệt kê thư mục không yêu cầu xác thực hay phân quyền.
- `model-133c74cbc2a4d259` | CWE-862 | `app/vuln_eval.rb:2` | Broken access control: endpoint đánh giá biểu thức tùy ý không yêu cầu xác thực.

Mức độ khai thác thực tế của từng mục là chưa biết, vì chưa có bằng chứng độc lập.

# Kết luận và bước tiếp theo

Cả 10 phát hiện vẫn `unresolved` và chỉ là đề xuất của model; không mục nào được xác nhận là lỗ hổng thực. Gate đang `pending`. Bước tiếp theo là thu thập bằng chứng độc lập để xác nhận hoặc bác bỏ từng mục, ưu tiên 6 phát hiện mức critical tại `app/vuln_cmd.rb:1`, `app/vuln_cmd.rb:3`, `app/vuln_eval.rb:1`, `app/vuln_eval.rb:3`, `app/vuln_sql.rb:1`, `app/vuln_sql.rb:3`.

## Đối chiếu model vs scanner

- Nhất trí (cả model và scanner đều thấy): 0
- Chỉ model thấy (scanner bỏ sót, cần người xem lại): 10
  - OS command injection via unsanitized params[:dir] in system() @ app/vuln_cmd.rb:3
  - Remote code execution via eval() of request parameter @ app/vuln_eval.rb:3
  - SQL injection in ActiveRecord where() string interpolation @ app/vuln_sql.rb:3
  - Cross-site scripting via raw() on user bio in ERB template @ app/vuln_view.erb:1
  - Broken access control: user record lookup has no authentication or ownership scoping (IDOR) @ app/vuln_sql.rb:2
  - Broken access control: directory listing action requires no authentication or authorization @ app/vuln_cmd.rb:2
  - Broken access control: arbitrary expression evaluation endpoint unauthenticated @ app/vuln_eval.rb:2
  - OS command injection via user-controlled params reaching system() @ app/vuln_cmd.rb:1
  - Code injection via eval on untrusted input @ app/vuln_eval.rb:1
  - SQL injection through string interpolation in query @ app/vuln_sql.rb:1
- Chỉ scanner thấy (model không liệt kê): 0

Luồng model-only: nhất trí 0, chỉ model thấy 10 (chờ người xem lại trong hunt.json, chưa thành finding chính thức khi thiếu evidence), chỉ scanner thấy 0.

## OWASP Top 10:2025 and CWE mapping

This is a CWE classification of reported findings, not a coverage or compliance assessment. An empty category means No mapped findings reported; it does not mean tested, safe or passed. Counts retain finding status; pending includes unprocessed, triaged, assessed and pending validation. A finding with multiple labels may appear in several rows/categories; do not add those row counts.

| OWASP category | Reported CWE | Finding IDs | Finding status counts |
|---|---|---|---|
| A01:2025 Broken Access Control | CWE-639 | model-501079420c3a0aaf | Confirmed: 0; Rejected: 0; Unresolved: 1; Pending: 0 |
| A01:2025 Broken Access Control | CWE-862 | model-133c74cbc2a4d259, model-466f136d5b9cefd2 | Confirmed: 0; Rejected: 0; Unresolved: 2; Pending: 0 |
| A02:2025 Security Misconfiguration | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A03:2025 Software Supply Chain Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A04:2025 Cryptographic Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A05:2025 Injection | CWE-78 | model-1cb16bbe2d7e132d, model-1eae62911d192eb8 | Confirmed: 0; Rejected: 0; Unresolved: 2; Pending: 0 |
| A05:2025 Injection | CWE-79 | model-86c0885f0cec1daf | Confirmed: 0; Rejected: 0; Unresolved: 1; Pending: 0 |
| A05:2025 Injection | CWE-89 | model-c2b6b14f556a90d7, model-ccb26c19b27f8e36 | Confirmed: 0; Rejected: 0; Unresolved: 2; Pending: 0 |
| A05:2025 Injection | CWE-95 | model-1a49f19ddea57d2b, model-ac40b4bbf031c98f | Confirmed: 0; Rejected: 0; Unresolved: 2; Pending: 0 |
| A06:2025 Insecure Design | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A07:2025 Authentication Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A08:2025 Software or Data Integrity Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A09:2025 Security Logging &amp; Alerting Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A10:2025 Mishandling of Exceptional Conditions | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |

Mapping source: [OWASP Top 10:2025](https://top10.owasp.org/2025/); offline snapshot 2026-11-04.
