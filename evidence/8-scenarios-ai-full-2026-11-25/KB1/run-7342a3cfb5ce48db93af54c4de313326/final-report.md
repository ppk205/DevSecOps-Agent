# Tóm tắt điều hành

Bản quét trên mục tiêu `local`, commit `a894c298d1475658d63d66693b71e61f5b3c7804`, có cổng kiểm soát ở trạng thái **pending**. Kết quả ghi nhận 12 phát hiện: **10 unresolved** và **2 unprocessed**. Toàn bộ 12 phát hiện là đề xuất của model (`model_only`); không có phát hiện nào được scanner xác nhận độc lập (agreed 0, scanner_only 0), và **không phát hiện nào được xác nhận là lỗ hổng thực sự**.

Bốn nhóm rủi ro được model nêu, tất cả đều chưa được kiểm chứng: OS command injection (CWE-78), SQL injection (CWE-89), deserialization không an toàn (CWE-502) và reflected XSS (CWE-79). Ngoài ra có 4 mục medium ghi rõ "Unverified: no scanner or code evidence" và 2 mục medium về các tuyên bố an toàn trong `SafeCmd.java` và `SafeComment.java` chưa được kiểm tra. Cần lưu ý: thiếu bằng chứng không đồng nghĩa với an toàn.

# Phạm vi và phương pháp

- Mục tiêu: `local`
- Commit: `a894c298d1475658d63d66693b71e61f5b3c7804`
- Cổng kiểm soát (gate): `pending`
- Số lượng trạng thái: unresolved 10, unprocessed 2
- Đối chiếu model vs scanner: agreed 0, model_only 12, scanner_only 0

Các phát hiện được đánh giá bởi validator với nhận định chung: "Insufficient independent evidence. Scanner detections, model proposals and incomplete procedures do not establish confirmation or rejection." Hai mục `unprocessed` không có ghi chú của validator. Chi tiết đối chiếu và ánh xạ OWASP do ứng dụng hiển thị, không được lặp lại ở đây. Báo cáo này chỉ dùng dữ liệu được cung cấp; mọi thông tin ngoài phạm vi đó được coi là chưa biết.

# Phát hiện ưu tiên

**Critical / unresolved (model-only, chưa xác nhận)**

| ID | Mô tả | CWE | Vị trí |
|---|---|---|---|
| model-0f317fe9b851065f | OS command injection qua tham số request `host` không được kiểm tra | CWE-78 | `src/VulnCmd.java:6` |
| model-07d4d153f4e2f708 | OS command injection qua tham số `host` không được kiểm tra trong shell exec | CWE-78 | `src/VulnCmd.java:7` |
| model-7b249236a60ff666 | SQL injection trong `findUser` qua câu lệnh `Statement` nối chuỗi | CWE-89 | `src/VulnSql.java:7` |
| model-d3288b19518e0126 | Deserialization Java không xác thực trên raw request body | CWE-502 | `src/VulnDeser.java:6` |
| model-5a2783d79cd7fcec | Deserialization Java không an toàn trên dữ liệu request không tin cậy qua `ObjectInputStream` | CWE-502 | `src/VulnDeser.java:7` |

**High / unresolved (model-only, chưa xác nhận)**

| ID | Mô tả | CWE | Vị trí |
|---|---|---|---|
| model-2d459b6fcd9237d8 | Reflected XSS trong JSP qua phản hồi tham số request không được mã hóa | CWE-79 | `src/VulnXss.jsp:3` |

**Medium / unresolved (model-only, ghi chú "Unverified: no scanner or code evidence")**

| ID | Mô tả | CWE | Vị trí |
|---|---|---|---|
| model-79aecfa4ff54fd8e | Chưa xác minh: không có bằng chứng từ scanner hoặc mã nguồn cho command injection trong `VulnCmd.java` | CWE-78 | `src/VulnCmd.java:1` |
| model-e3c8265bdac0ffb6 | Chưa xác minh: không có bằng chứng từ scanner hoặc mã nguồn cho SQL injection trong `VulnSql.java` | CWE-89 | `src/VulnSql.java:1` |
| model-01ae96becc874bfc | Chưa xác minh: không có bằng chứng từ scanner hoặc mã nguồn cho reflected/stored XSS trong `VulnXss.jsp` | CWE-79 | `src/VulnXss.jsp:1` |
| model-6ec2502f32810dcb | Chưa xác minh: không có bằng chứng từ scanner hoặc mã nguồn cho deserialization không an toàn trong `VulnDeser.java` | CWE-502 | `src/VulnDeser.java:1` |

**Medium / unprocessed (không có ghi chú validator)**

| ID | Mô tả | CWE | Vị trí |
|---|---|---|---|
| model-a5aaacbd146469d1 | Chưa xác minh: tuyên bố an toàn của `SafeCmd.java` chưa được xác nhận qua kiểm tra mã | CWE-78 | `src/SafeCmd.java:1` |
| model-36886ce5a6d9ce8e | Chưa xác minh: tuyên bố làm sạch dữ liệu của `SafeComment.java` chưa được xác nhận qua kiểm tra mã | CWE-79 | `src/SafeComment.java:1` |

# Kết luận và bước tiếp theo

Không có phát hiện nào được xác nhận, tái hiện hay khắc phục trong bản quét này. Các mục critical/high chỉ là đề xuất của model tại các dòng cụ thể; các mục medium ghi nhận tình trạng thiếu bằng chứng độc lập, không phải kết luận rằng mã an toàn. Cả hai mục `unprocessed` chưa được validator đánh giá nên trạng thái rủi ro thực tế là chưa biết.

Bước tiếp theo (chưa được thực hiện, chưa có người phụ trách hay thời hạn trong dữ liệu):

1. Chạy kiểm tra độc lập để xác minh hoặc bác bỏ từng đề xuất model tại `src/VulnCmd.java:6`, `src/VulnCmd.java:7`, `src/VulnSql.java:7`, `src/VulnDeser.java:6`, `src/VulnDeser.java:7` và `src/VulnXss.jsp:3`.
2. Đưa hai mục `unprocessed` (`src/SafeCmd.java:1`, `src/SafeComment.java:1`) vào quy trình đánh giá.
3. Làm rõ các mục medium tại các dòng `:1` của `VulnCmd.java`, `VulnSql.java`, `VulnXss.jsp`, `VulnDeser.java`: xác định rõ là có lỗ hổng hay không thay vì để trạng thái thiếu bằng chứng.
4. Hoàn tất cổng kiểm soát đang `pending` sau khi có bằng chứng xác minh độc lập.

## Đối chiếu model vs scanner

- Nhất trí (cả model và scanner đều thấy): 0
- Chỉ model thấy (scanner bỏ sót, cần người xem lại): 12
  - OS command injection via unvalidated 'host' request parameter @ src/VulnCmd.java:6
  - SQL injection in findUser via string-concatenated Statement query @ src/VulnSql.java:7
  - Unauthenticated Java deserialization of raw request body @ src/VulnDeser.java:6
  - Reflected XSS in JSP via unencoded request parameter echo @ src/VulnXss.jsp:3
  - OS command injection via unvalidated 'host' request parameter in shell exec @ src/VulnCmd.java:7
  - Unsafe Java deserialization of untrusted request body via ObjectInputStream @ src/VulnDeser.java:7
  - Unverified: no scanner or code evidence for command injection in VulnCmd.java @ src/VulnCmd.java:1
  - Unverified: no scanner or code evidence for SQL injection in VulnSql.java @ src/VulnSql.java:1
  - Unverified: no scanner or code evidence for reflected/stored XSS in VulnXss.jsp @ src/VulnXss.jsp:1
  - Unverified: no scanner or code evidence for unsafe deserialization in VulnDeser.java @ src/VulnDeser.java:1
  - Unverified: SafeCmd.java safety claim not confirmed by inspection @ src/SafeCmd.java:1
  - Unverified: SafeComment.java sanitization claim not confirmed by inspection @ src/SafeComment.java:1
- Chỉ scanner thấy (model không liệt kê): 0

Luồng model-only: nhất trí 0, chỉ model thấy 12 (chờ người xem lại trong hunt.json, chưa thành finding chính thức khi thiếu evidence), chỉ scanner thấy 0.

## OWASP Top 10:2025 and CWE mapping

This is a CWE classification of reported findings, not a coverage or compliance assessment. An empty category means No mapped findings reported; it does not mean tested, safe or passed. Counts retain finding status; pending includes unprocessed, triaged, assessed and pending validation. A finding with multiple labels may appear in several rows/categories; do not add those row counts.

| OWASP category | Reported CWE | Finding IDs | Finding status counts |
|---|---|---|---|
| A01:2025 Broken Access Control | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A02:2025 Security Misconfiguration | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A03:2025 Software Supply Chain Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A04:2025 Cryptographic Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A05:2025 Injection | CWE-78 | model-07d4d153f4e2f708, model-0f317fe9b851065f, model-79aecfa4ff54fd8e, model-a5aaacbd146469d1 | Confirmed: 0; Rejected: 0; Unresolved: 3; Pending: 1 |
| A05:2025 Injection | CWE-79 | model-01ae96becc874bfc, model-2d459b6fcd9237d8, model-36886ce5a6d9ce8e | Confirmed: 0; Rejected: 0; Unresolved: 2; Pending: 1 |
| A05:2025 Injection | CWE-89 | model-7b249236a60ff666, model-e3c8265bdac0ffb6 | Confirmed: 0; Rejected: 0; Unresolved: 2; Pending: 0 |
| A06:2025 Insecure Design | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A07:2025 Authentication Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A08:2025 Software or Data Integrity Failures | CWE-502 | model-5a2783d79cd7fcec, model-6ec2502f32810dcb, model-d3288b19518e0126 | Confirmed: 0; Rejected: 0; Unresolved: 3; Pending: 0 |
| A09:2025 Security Logging &amp; Alerting Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A10:2025 Mishandling of Exceptional Conditions | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |

Mapping source: [OWASP Top 10:2025](https://top10.owasp.org/2025/); offline snapshot 2026-11-04.
