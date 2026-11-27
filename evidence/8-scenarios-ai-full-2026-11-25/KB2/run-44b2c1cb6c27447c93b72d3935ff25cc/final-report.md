# Tóm tắt điều hành

Bản quét trên target `local`, commit `768a41fe4a304393cb02cb839a2688f58b41763e`, ghi nhận 4 phát hiện, tất cả đều ở trạng thái `unresolved`. Gate hiện ở trạng thái `pending`.

Số lượng theo trạng thái: `{"unresolved": 4}`. Không có phát hiện nào được xác nhận hay bác bỏ. Lý do validator đưa ra cho cả 4 phát hiện là "Insufficient independent evidence": các phát hiện từ scanner, đề xuất của model và các quy trình chưa hoàn tất đều không đủ để khẳng định hoặc phủ nhận lỗ hổng.

# Phạm vi và phương pháp

Phạm vi là mã nguồn tại commit `768a41fe4a304393cb02cb839a2688f58b41763e` trên target `local`. Kết quả gồm 4 phát hiện do model đề xuất, không có mục nào bị lược khỏi đầu vào của model (0 omitted from the model input). Chi tiết đầy đủ được lưu trong các file export của bản quét.

Mỗi phát hiện đã qua bước kiểm tra của validator. Với cả 4 phát hiện, validator kết luận chưa đủ bằng chứng độc lập, nên không thể xác nhận hay bác bỏ. Đây là giới hạn của bằng chứng hiện có, không phải kết luận rằng lỗ hổng đã được chứng minh khai thác.

# Phát hiện ưu tiên

| ID | Mô tả | CWE | Mức độ / Trạng thái | Vị trí |
|---|---|---|---|---|
| model-8cbb6a02d746527a | Remote code execution via eval on request body | CWE-95 | critical / unresolved | `src/vuln_eval.js:3` |
| model-5815bd155816b9c5 | SQL injection via string concatenation in db.query | CWE-89 | critical / unresolved | `src/vuln_sql.js:3` |
| model-79dfa5098d7f3e9d | OS command injection via exec with concatenated host | CWE-78 | critical / unresolved | `src/vuln_cmd.ts:5` |
| model-aa907b4b5caf7f0f | Reflected XSS via unescaped innerHTML sink | CWE-79 | high / unresolved | `src/vuln_dom.js:3` |

Ba phát hiện mức critical nằm ở `src/vuln_eval.js:3` (CWE-95), `src/vuln_sql.js:3` (CWE-89) và `src/vuln_cmd.ts:5` (CWE-78). Phát hiện mức high nằm ở `src/vuln_dom.js:3` (CWE-79). Cả 4 đều là `unresolved`.

# Kết luận và bước tiếp theo

Chưa có phát hiện nào được xác nhận hoặc bác bỏ, và gate vẫn `pending`. Không thể kết luận commit này an toàn hay có lỗ hổng dựa trên dữ kiện hiện có.

Bước tiếp theo: thu thập bằng chứng độc lập cho từng phát hiện tại đúng các vị trí trên, đủ để validator chuyển trạng thái khỏi `unresolved`. Chi tiết đầy đủ cần đối chiếu trong các file export của bản quét.

## Đối chiếu model vs scanner

- Nhất trí (cả model và scanner đều thấy): 0
- Chỉ model thấy (scanner bỏ sót, cần người xem lại): 4
  - Reflected XSS via unescaped innerHTML sink @ src/vuln_dom.js:3
  - Remote code execution via eval on request body @ src/vuln_eval.js:3
  - SQL injection via string concatenation in db.query @ src/vuln_sql.js:3
  - OS command injection via exec with concatenated host @ src/vuln_cmd.ts:5
- Chỉ scanner thấy (model không liệt kê): 0

Luồng model-only: nhất trí 0, chỉ model thấy 4 (chờ người xem lại trong hunt.json, chưa thành finding chính thức khi thiếu evidence), chỉ scanner thấy 0.

## OWASP Top 10:2025 and CWE mapping

This is a CWE classification of reported findings, not a coverage or compliance assessment. An empty category means No mapped findings reported; it does not mean tested, safe or passed. Counts retain finding status; pending includes unprocessed, triaged, assessed and pending validation. A finding with multiple labels may appear in several rows/categories; do not add those row counts.

| OWASP category | Reported CWE | Finding IDs | Finding status counts |
|---|---|---|---|
| A01:2025 Broken Access Control | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A02:2025 Security Misconfiguration | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A03:2025 Software Supply Chain Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A04:2025 Cryptographic Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A05:2025 Injection | CWE-78 | model-79dfa5098d7f3e9d | Confirmed: 0; Rejected: 0; Unresolved: 1; Pending: 0 |
| A05:2025 Injection | CWE-79 | model-aa907b4b5caf7f0f | Confirmed: 0; Rejected: 0; Unresolved: 1; Pending: 0 |
| A05:2025 Injection | CWE-89 | model-5815bd155816b9c5 | Confirmed: 0; Rejected: 0; Unresolved: 1; Pending: 0 |
| A05:2025 Injection | CWE-95 | model-8cbb6a02d746527a | Confirmed: 0; Rejected: 0; Unresolved: 1; Pending: 0 |
| A06:2025 Insecure Design | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A07:2025 Authentication Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A08:2025 Software or Data Integrity Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A09:2025 Security Logging &amp; Alerting Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A10:2025 Mishandling of Exceptional Conditions | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |

Mapping source: [OWASP Top 10:2025](https://top10.owasp.org/2025/); offline snapshot 2026-11-04.
