## Tóm tắt điều hành

Bản quét trên mục tiêu `local`, commit `9a25ac9c8c782420a9ac766c77872dfd9b1bb5a2`, đang ở trạng thái gate `pending`, ghi nhận **8 phát hiện**, tất cả đều ở trạng thái **unresolved** (`{"unresolved": 8}`). Không có phát hiện nào được xác nhận (confirmed) hay bị bác bỏ (rejected).

Sáu phát hiện ở mức **critical** thuộc ba nhóm lỗi: OS command injection (CWE-78), insecure deserialization (CWE-502) và SQL injection (CWE-89). Hai phát hiện ở mức **high** thuộc nhóm XSS (CWE-79).

Điểm cần lưu ý: cả 8 phát hiện đều là **model_only** (đối chiếu `{"agreed": 0, "model_only": 8, "scanner_only": 0}`), tức không có phát hiện nào trùng khớp với scanner và không có bằng chứng độc lập từ scanner. Validator kết luận cho từng phát hiện: "Insufficient independent evidence. Scanner detections, model proposals and incomplete procedures do not establish confirmation or rejection."

## Phạm vi và phương pháp

- **Mục tiêu:** `local`
- **Commit:** `9a25ac9c8c782420a9ac766c77872dfd9b1bb5a2`
- **Gate:** `pending`
- **Số liệu trạng thái:** `{"unresolved": 8}`
- **Đối chiếu model vs scanner:** `{"agreed": 0, "model_only": 8, "scanner_only": 0}`
- **Nguồn dữ liệu:** phần "Finding samples (8 of 8)"; ghi chú "0 omitted from the model input"; chi tiết đầy đủ nằm trong scan exports.
- **Phương pháp:** các phát hiện được model đề xuất, sau đó đi qua bước validator. Với mọi phát hiện, validator nêu rằng không đủ bằng chứng độc lập để xác nhận hoặc bác bỏ.

**Giới hạn dữ liệu (unknown/không xác định):** không có bằng chứng khai thác, PoC, lịch sử quét hay cấu hình scanner trong dữ liệu được cung cấp. Các nội dung này được coi là không xác định. Phần đối chiếu và chi tiết OWASP do ứng dụng hiển thị.

## Phát hiện ưu tiên

Tất cả 8 phát hiện giữ nguyên trạng thái **unresolved**; mức độ và vị trí giữ nguyên như dữ liệu quét.

| ID | Mô tả | CWE | Mức độ | Trạng thái | Vị trí |
|---|---|---|---|---|---|
| model-46f74f672f3ca92d | OS command injection via unsanitized query parameter passed to Process.Start | CWE-78 | critical | unresolved | `app/VulnCmd.cs:5` |
| model-0517a5309b100b66 | OS command injection via unsanitized argument in VulnCmd | CWE-78 | critical | unresolved | `app/VulnCmd.cs:1` |
| model-525828ab780cbffc | Insecure BinaryFormatter deserialization of untrusted stream (RCE gadget chain) | CWE-502 | critical | unresolved | `app/VulnDeser.cs:6` |
| model-0751364fb2aedb13 | Insecure deserialization of untrusted data in VulnDeser | CWE-502 | critical | unresolved | `app/VulnDeser.cs:1` |
| model-06edaa0b0d7332b3 | SQL injection via string concatenation into SqlCommand query | CWE-89 | critical | unresolved | `app/VulnSql.cs:5` |
| model-a7fe4ff58de7deb3 | SQL injection via string-concatenated query in VulnSql | CWE-89 | critical | unresolved | `app/VulnSql.cs:1` |
| model-66c182ab5062dcae | Stored/reflected XSS via @Html.Raw on unencoded model data | CWE-79 | high | unresolved | `app/VulnView.cshtml:2` |
| model-dd53621b21663226 | Reflected/stored XSS via unencoded output in VulnView | CWE-79 | high | unresolved | `app/VulnView.cshtml:1` |

**Nhận định validator (áp dụng cho cả 8):** "Insufficient independent evidence. Scanner detections, model proposals and incomplete procedures do not establish confirmation or rejection."

Ghi chú về tính chất bằng chứng: vì tất cả là **model_only**, không có bằng chứng độc lập từ scanner, và không có phát hiện nào bị scanner bác bỏ. Các phát hiện này cũng không được mô tả là đã được scanner xác nhận.

## Kết luận và bước tiếp theo

Có 8 phát hiện chưa được giải quyết (unresolved), trong đó 6 critical và 2 high, tập trung ở ba tệp mã nguồn (`app/VulnCmd.cs`, `app/VulnDeser.cs`, `app/VulnSql.cs`) và một tệp view (`app/VulnView.cshtml`). Do không có bằng chứng độc lập từ scanner và validator chưa xác nhận hay bác bỏ, mức độ và tính đúng đắn của từng phát hiện vẫn là chưa xác định.

Bước tiếp theo (dựa trên dữ liệu hiện có):

1. Mở scan exports để lấy chi tiết đầy đủ của 8 phát hiện, vì phần tóm tắt chỉ gồm "Finding samples (8 of 8)".
2. Kiểm tra thủ công từng vị trí được nêu để bổ sung bằng chứng độc lập, từ đó chuyển các phát hiện khỏi trạng thái unresolved hoặc bác bỏ chúng.
3. Giữ gate ở trạng thái `pending` cho đến khi có kết luận cho cả 8 phát hiện.

## Đối chiếu model vs scanner

- Nhất trí (cả model và scanner đều thấy): 0
- Chỉ model thấy (scanner bỏ sót, cần người xem lại): 8
  - OS command injection via unsanitized query parameter passed to Process.Start @ app/VulnCmd.cs:5
  - Insecure BinaryFormatter deserialization of untrusted stream (RCE gadget chain) @ app/VulnDeser.cs:6
  - SQL injection via string concatenation into SqlCommand query @ app/VulnSql.cs:5
  - Stored/reflected XSS via @Html.Raw on unencoded model data @ app/VulnView.cshtml:2
  - OS command injection via unsanitized argument in VulnCmd @ app/VulnCmd.cs:1
  - Insecure deserialization of untrusted data in VulnDeser @ app/VulnDeser.cs:1
  - SQL injection via string-concatenated query in VulnSql @ app/VulnSql.cs:1
  - Reflected/stored XSS via unencoded output in VulnView @ app/VulnView.cshtml:1
- Chỉ scanner thấy (model không liệt kê): 0

Luồng model-only: nhất trí 0, chỉ model thấy 8 (chờ người xem lại trong hunt.json, chưa thành finding chính thức khi thiếu evidence), chỉ scanner thấy 0.

## OWASP Top 10:2025 and CWE mapping

This is a CWE classification of reported findings, not a coverage or compliance assessment. An empty category means No mapped findings reported; it does not mean tested, safe or passed. Counts retain finding status; pending includes unprocessed, triaged, assessed and pending validation. A finding with multiple labels may appear in several rows/categories; do not add those row counts.

| OWASP category | Reported CWE | Finding IDs | Finding status counts |
|---|---|---|---|
| A01:2025 Broken Access Control | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A02:2025 Security Misconfiguration | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A03:2025 Software Supply Chain Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A04:2025 Cryptographic Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A05:2025 Injection | CWE-78 | model-0517a5309b100b66, model-46f74f672f3ca92d | Confirmed: 0; Rejected: 0; Unresolved: 2; Pending: 0 |
| A05:2025 Injection | CWE-79 | model-66c182ab5062dcae, model-dd53621b21663226 | Confirmed: 0; Rejected: 0; Unresolved: 2; Pending: 0 |
| A05:2025 Injection | CWE-89 | model-06edaa0b0d7332b3, model-a7fe4ff58de7deb3 | Confirmed: 0; Rejected: 0; Unresolved: 2; Pending: 0 |
| A06:2025 Insecure Design | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A07:2025 Authentication Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A08:2025 Software or Data Integrity Failures | CWE-502 | model-0751364fb2aedb13, model-525828ab780cbffc | Confirmed: 0; Rejected: 0; Unresolved: 2; Pending: 0 |
| A09:2025 Security Logging &amp; Alerting Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A10:2025 Mishandling of Exceptional Conditions | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |

Mapping source: [OWASP Top 10:2025](https://top10.owasp.org/2025/); offline snapshot 2026-11-04.
