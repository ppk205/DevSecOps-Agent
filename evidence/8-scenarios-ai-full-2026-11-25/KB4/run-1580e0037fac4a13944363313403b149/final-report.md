# Tóm tắt điều hành

Bản quét trên target `local`, commit `3beee0f6219cd49e29a3d9e27e3a5dceb21245fe`, ghi nhận **9 phát hiện**, tất cả đều ở trạng thái `unresolved` (status counts: `{"unresolved": 9}`). Gate hiện đang `pending`.

Đối chiếu model vs scanner: `agreed: 0`, `model_only: 9`, `scanner_only: 0`. Không có phát hiện nào được scanner xác nhận độc lập; toàn bộ 9 phát hiện chỉ đến từ model.

Lý do validator áp dụng cho cả 9 phát hiện: "Insufficient independent evidence. Scanner detections, model proposals and incomplete procedures do not establish confirmation or rejection." Vì vậy chưa có phát hiện nào được xác nhận hay bác bỏ.

Phân bố theo mức độ: 5 `critical`, 3 `high`, 1 `info`. Phân bố theo CWE: CWE-89 (2), CWE-78 (2), CWE-502 (2), CWE-79 (2), CWE-798 (1).

# Phạm vi và phương pháp

- Phạm vi: target `local`, commit `3beee0f6219cd49e29a3d9e27e3a5dceb21245fe`. Các phát hiện nằm trong bốn tệp thuộc thư mục `web/`: `vuln_sql.php`, `vuln_cmd.php`, `vuln_deser.php`, `vuln_xss.php`.
- Phương pháp: đối chiếu phát hiện của model với kết quả scanner. Kết quả: không có phát hiện nào trùng khớp giữa hai nguồn (`agreed: 0`), 9 phát hiện chỉ từ model (`model_only: 9`), không có phát hiện chỉ từ scanner (`scanner_only: 0`).
- Kiểm định: mỗi phát hiện đều qua validator với kết luận "Insufficient independent evidence. Scanner detections, model proposals and incomplete procedures do not establish confirmation or rejection."
- Dữ liệu không có trong đầu vào (như nội dung mã nguồn, bằng chứng khai thác, kết quả quét secret) được coi là **không xác định**; báo cáo này không suy diễn thêm.
- 0 phát hiện bị lược bỏ khỏi đầu vào của model; chi tiết đầy đủ nằm trong các tệp export của lần quét.

# Phát hiện ưu tiên

Tất cả 9 phát hiện đều `unresolved`.

**Mức critical (5)**

| ID | Mô tả | CWE | Vị trí |
|---|---|---|---|
| model-8abfaa82d10be0db | SQL injection qua tham số GET không được làm sạch, nối vào `mysqli_query` | CWE-89 | `web/vuln_sql.php:3` |
| model-8dba793fe2e803f6 | OS command injection qua tham số GET truyền vào `shell_exec` | CWE-78 | `web/vuln_cmd.php:3` |
| model-cfe59861d98f28c2 | OS command injection qua dữ liệu người dùng không được làm sạch, truyền vào thực thi shell | CWE-78 | `web/vuln_cmd.php:1` |
| model-85029b008e0bf398 | Deserialization không an toàn trên dữ liệu do kẻ tấn công kiểm soát | CWE-502 | `web/vuln_deser.php:1` |
| model-a2fd9086db8a6354 | SQL injection qua dữ liệu không được làm sạch trong truy vấn cơ sở dữ liệu | CWE-89 | `web/vuln_sql.php:1` |

**Mức high (3)**

| ID | Mô tả | CWE | Vị trí |
|---|---|---|---|
| model-ed0a142e6393612e | Reflected XSS: tham số GET thô được echo vào phản hồi HTML | CWE-79 | `web/vuln_xss.php:2` |
| model-26bbeb61ecc17524 | PHP object injection: `unserialize()` trên cookie do kẻ tấn công kiểm soát | CWE-502 | `web/vuln_deser.php:2` |
| model-a48bdbb0ebc0c939 | Reflected XSS qua xuất dữ liệu người dùng không được escape | CWE-79 | `web/vuln_xss.php:1` |

**Mức info (1)**

| ID | Mô tả | CWE | Vị trí |
|---|---|---|---|
| model-7230607c40e80064 | Secret scan chưa được thực thi; không thể xác nhận phát hiện credential cứng, API key, private key hay JWT | CWE-798 | `web/vuln_cmd.php:1` |

Lưu ý: phát hiện `model-7230607c40e80064` là ghi nhận về việc quy trình quét secret **chưa chạy**, không phải bằng chứng tìm thấy credential. Không có credential nào được xác nhận trong dữ liệu quét.

# Kết luận và bước tiếp theo

Chín phát hiện tiềm năng, trong đó 5 mức critical và 3 mức high, đều chưa được xác nhận: không có phát hiện nào trùng khớp với scanner, và validator kết luận thiếu bằng chứng độc lập. Gate đang `pending`, do đó trạng thái của mọi phát hiện vẫn là `unresolved`.

Các bước tiếp theo dựa trên dữ liệu hiện có:

1. Cung cấp bằng chứng độc lập cho các vị trí đã nêu, đặc biệt các phát hiện critical tại `web/vuln_sql.php:3`, `web/vuln_sql.php:1`, `web/vuln_cmd.php:3`, `web/vuln_cmd.php:1`, `web/vuln_deser.php:1`, để validator có thể xác nhận hoặc bác bỏ.
2. Thực thi quy trình secret scan còn thiếu (liên quan `model-7230607c40e80064`), vì hiện tại không thể xác nhận hay loại trừ credential cứng, API key, private key hoặc JWT.
3. Hoàn tất gate `pending` sau khi các phát hiện được xác nhận hoặc bác bỏ; các chi tiết đối chiếu và OWASP do ứng dụng hiển thị.

## Đối chiếu model vs scanner

- Nhất trí (cả model và scanner đều thấy): 0
- Chỉ model thấy (scanner bỏ sót, cần người xem lại): 9
  - SQL injection via unsanitized GET parameter concatenated into mysqli_query @ web/vuln_sql.php:3
  - Reflected XSS: raw GET parameter echoed into HTML response @ web/vuln_xss.php:2
  - OS command injection via GET parameter passed to shell_exec @ web/vuln_cmd.php:3
  - PHP object injection: unserialize() on attacker-controlled cookie @ web/vuln_deser.php:2
  - OS command injection via unsanitized user input passed to shell execution @ web/vuln_cmd.php:1
  - Insecure deserialization of attacker-controlled data @ web/vuln_deser.php:1
  - SQL injection via unsanitized input in database query @ web/vuln_sql.php:1
  - Reflected cross-site scripting via unescaped output of user input @ web/vuln_xss.php:1
  - Secret scan not executed; no hardcoded credential, API key, private key or JWT finding is confirmable @ web/vuln_cmd.php:1
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
| A05:2025 Injection | CWE-78 | model-8dba793fe2e803f6, model-cfe59861d98f28c2 | Confirmed: 0; Rejected: 0; Unresolved: 2; Pending: 0 |
| A05:2025 Injection | CWE-79 | model-a48bdbb0ebc0c939, model-ed0a142e6393612e | Confirmed: 0; Rejected: 0; Unresolved: 2; Pending: 0 |
| A05:2025 Injection | CWE-89 | model-8abfaa82d10be0db, model-a2fd9086db8a6354 | Confirmed: 0; Rejected: 0; Unresolved: 2; Pending: 0 |
| A06:2025 Insecure Design | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A07:2025 Authentication Failures | CWE-798 | model-7230607c40e80064 | Confirmed: 0; Rejected: 0; Unresolved: 1; Pending: 0 |
| A08:2025 Software or Data Integrity Failures | CWE-502 | model-26bbeb61ecc17524, model-85029b008e0bf398 | Confirmed: 0; Rejected: 0; Unresolved: 2; Pending: 0 |
| A09:2025 Security Logging &amp; Alerting Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A10:2025 Mishandling of Exceptional Conditions | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |

Mapping source: [OWASP Top 10:2025](https://top10.owasp.org/2025/); offline snapshot 2026-11-04.
