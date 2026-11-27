# Tóm tắt điều hành

Bản quét trên target `local`, commit `37f2458c4ec90f9d2fe19a9b49d114cbec8b5af0`, ghi nhận **9 phát hiện, tất cả ở trạng thái `unresolved`**. Gate đang `pending`.

Đối chiếu model với scanner: `agreed: 0`, `model_only: 9`, `scanner_only: 0`. Toàn bộ 9 phát hiện đến từ model, không có phát hiện nào từ scanner độc lập. `model_only` không đồng nghĩa với đã xác thực.

Mức độ theo dữ kiện: 6 phát hiện `critical`, 3 phát hiện `high`. Validator kết luận cho cả 9 phát hiện: "Insufficient independent evidence. Scanner detections, model proposals and incomplete procedures do not establish confirmation or rejection." Nghĩa là chưa xác nhận và cũng chưa bác bỏ.

# Phạm vi và phương pháp

- **Mục tiêu:** target `local`, commit `37f2458c4ec90f9d2fe19a9b49d114cbec8b5af0`.
- **Trạng thái gate:** `pending`.
- **Số lượng:** 9 phát hiện trong tổng số 9, không có phát hiện nào bị lược khỏi đầu vào của model. Chi tiết đầy đủ nằm trong các tệp xuất của bản quét.
- **Đối chiếu:** 0 `agreed`, 9 `model_only`, 0 `scanner_only`.
- **Kết quả kiểm định:** cả 9 phát hiện được validator ghi nhận là thiếu bằng chứng độc lập; các phát hiện của scanner, đề xuất của model và thủ tục chưa hoàn tất không đủ để xác nhận hay bác bỏ.
- **Chưa biết (unknown):** không có bằng chứng scanner độc lập; chưa rõ khả năng khai thác thực tế, điều kiện tiên quyết và tác động thực tế; không có thông tin CVE hay dữ liệu động học khác trong dữ kiện được cung cấp.
- Chi tiết đối chiếu và OWASP do ứng dụng hiển thị, không được tái tạo ở đây.

# Phát hiện ưu tiên

Cả 9 phát hiện giữ nguyên trạng thái `unresolved` và vị trí chính xác.

| ID | Mô tả | CWE | Mức độ / trạng thái | Vị trí |
|---|---|---|---|---|
| model-579e2ee9320c00ff | OS command injection via unsanitized request parameter in shell=True Popen | CWE-78 | critical / unresolved | app/vuln_cmd.py:6 |
| model-46073067cb2040c4 | OS command injection via os.system with user-controlled input | CWE-78 | critical / unresolved | app/vuln_cmd.py:1 |
| model-1c9c9f297b2bb1a8 | Unsafe deserialization of raw request body with pickle.loads | CWE-502 | critical / unresolved | app/vuln_pickle.py:6 |
| model-a47246365b979b90 | Arbitrary code execution via pickle.loads on untrusted data | CWE-502 | critical / unresolved | app/vuln_pickle.py:1 |
| model-c5e393381934a763 | Unsafe YAML deserialization using yaml.Loader on request body | CWE-502 | critical / unresolved | app/vuln_yaml.py:6 |
| model-fb6d571b9cbd0737 | Unsafe YAML deserialization via yaml.load without SafeLoader | CWE-502 | high / unresolved | app/vuln_yaml.py:1 |
| model-d892dbb509e17195 | SQL injection via string-built query | CWE-89 | critical / unresolved | app/vuln_sql.py:1 |
| model-54d4ad9ceed276c5 | SQL injection through string concatenation in cursor.execute | CWE-89 | high / unresolved | app/vuln_sql.py:5 |
| model-51eebd1bfa11dcb5 | SQL injection via string concatenation in user lookup | CWE-89 | high / unresolved | app/vuln_sql.py:6 |

Phân bố theo CWE: CWE-78 có 2 phát hiện (`app/vuln_cmd.py:1`, `app/vuln_cmd.py:6`); CWE-502 có 4 phát hiện (`app/vuln_pickle.py:1`, `app/vuln_pickle.py:6`, `app/vuln_yaml.py:1`, `app/vuln_yaml.py:6`); CWE-89 có 3 phát hiện (`app/vuln_sql.py:1`, `app/vuln_sql.py:5`, `app/vuln_sql.py:6`).

Lý do kiểm định áp dụng cho tất cả các dòng trên: "Insufficient independent evidence. Scanner detections, model proposals and incomplete procedures do not establish confirmation or rejection."

# Kết luận và bước tiếp theo

Chưa có kết luận nào về việc các lỗ hổng có tồn tại thật hay không. Toàn bộ 9 phát hiện là `model_only`, thiếu bằng chứng scanner độc lập, và gate vẫn `pending`.

Bước tiếp theo hợp lý dựa trên dữ kiện hiện có:

1. Thu thập bằng chứng độc lập cho từng phát hiện (quét lại bằng scanner, kiểm tra thủ công tại đúng vị trí `file:line` đã nêu) để chuyển trạng thái từ `unresolved` sang xác nhận hoặc bác bỏ.
2. Kiểm tra 4 phát hiện CWE-502 tại `app/vuln_pickle.py` và `app/vuln_yaml.py` trước, vì đây là nhóm có nhiều phát hiện `critical` nhất.
3. Hoàn tất quy trình kiểm định còn dang dở, sau đó xem lại gate `pending` để có quyết định.
4. Phần chưa biết vẫn để là **unknown**: khả năng khai thác thực tế, điều kiện tiên quyết, tác động thực tế và thông tin CVE. Không nên suy đoán cho tới khi có bằng chứng độc lập.

## Đối chiếu model vs scanner

- Nhất trí (cả model và scanner đều thấy): 0
- Chỉ model thấy (scanner bỏ sót, cần người xem lại): 9
  - OS command injection via unsanitized request parameter in shell=True Popen @ app/vuln_cmd.py:6
  - Unsafe deserialization of raw request body with pickle.loads @ app/vuln_pickle.py:6
  - SQL injection through string concatenation in cursor.execute @ app/vuln_sql.py:5
  - Unsafe YAML deserialization using yaml.Loader on request body @ app/vuln_yaml.py:6
  - SQL injection via string concatenation in user lookup @ app/vuln_sql.py:6
  - OS command injection via os.system with user-controlled input @ app/vuln_cmd.py:1
  - Arbitrary code execution via pickle.loads on untrusted data @ app/vuln_pickle.py:1
  - SQL injection via string-built query @ app/vuln_sql.py:1
  - Unsafe YAML deserialization via yaml.load without SafeLoader @ app/vuln_yaml.py:1
- Chỉ scanner thấy (model không liệt kê): 0

Luồng model-only: nhất trí 0, chỉ model thấy 9 (chờ người xem lại trong hunt.json, chưa thành finding chính thức khi thiếu evidence), chỉ scanner thấy 0.

## OWASP Top 10:2025 and CWE mapping

This is a CWE classification of reported findings, not a coverage or compliance assessment. An empty category means No mapped findings reported; it does not mean tested, safe or passed. Counts retain finding status; pending includes unprocessed, triaged, assessed and pending validation. A finding with multiple labels may appear in several rows/categories; do not add those row counts.

| OWASP category | Reported CWE | Finding IDs | Finding status counts |
|---|---|---|---|
| A01:2025 Broken Access Control | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A02:2025 Security Misconfiguration | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A03:2025 Software Supply Chain Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A04:2025 Cryptographic Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A05:2025 Injection | CWE-78 | model-46073067cb2040c4, model-579e2ee9320c00ff | Confirmed: 0; Rejected: 0; Unresolved: 2; Pending: 0 |
| A05:2025 Injection | CWE-89 | model-51eebd1bfa11dcb5, model-54d4ad9ceed276c5, model-d892dbb509e17195 | Confirmed: 0; Rejected: 0; Unresolved: 3; Pending: 0 |
| A06:2025 Insecure Design | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A07:2025 Authentication Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A08:2025 Software or Data Integrity Failures | CWE-502 | model-1c9c9f297b2bb1a8, model-a47246365b979b90, model-c5e393381934a763, model-fb6d571b9cbd0737 | Confirmed: 0; Rejected: 0; Unresolved: 4; Pending: 0 |
| A09:2025 Security Logging &amp; Alerting Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A10:2025 Mishandling of Exceptional Conditions | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |

Mapping source: [OWASP Top 10:2025](https://top10.owasp.org/2025/); offline snapshot 2026-11-04.
